use std::{
    result::Result,
    sync::{Arc, Mutex, Weak, atomic::Ordering},
    time::Duration,
};

use anyhow::Error;
use async_trait::async_trait;
use atomic_shim::AtomicU64;
use dashmap::DashMap;
use tokio::{
    select,
    sync::Notify,
    task::{JoinHandle, JoinSet},
};
use tokio_util::task::AbortOnDropHandle;

pub(crate) async fn reap_joinset_background<T>(tasks: Weak<Mutex<JoinSet<T>>>, origin: &'static str)
where
    T: Send + 'static,
{
    loop {
        crate::foundation::time::sleep(Duration::from_secs(1)).await;
        let Some(tasks) = tasks.upgrade() else {
            break;
        };
        while tasks.lock().unwrap().try_join_next().is_some() {}
    }
    tracing::debug!(origin, "joinset task reaper exited");
}

pub struct ExternalTaskSignal {
    version: AtomicU64,
    notify: Notify,
}

impl Default for ExternalTaskSignal {
    fn default() -> Self {
        Self::new()
    }
}

impl ExternalTaskSignal {
    pub fn new() -> Self {
        Self {
            version: AtomicU64::new(0),
            notify: Notify::new(),
        }
    }

    pub fn notify(&self) {
        self.version.fetch_add(1, Ordering::Relaxed);
        self.notify.notify_waiters();
    }

    pub fn version(&self) -> u64 {
        self.version.load(Ordering::Relaxed)
    }

    pub fn notified(&self) -> impl std::future::Future<Output = ()> + '_ {
        self.notify.notified()
    }
}

#[async_trait]
pub trait PeerTaskLauncher: Send + Sync + Clone + 'static {
    type CollectPeerItem;
    type TaskRet;

    async fn collect_peers_need_task(&self) -> Vec<Self::CollectPeerItem>;
    async fn launch_task(
        &self,
        item: Self::CollectPeerItem,
    ) -> JoinHandle<Result<Self::TaskRet, Error>>;

    async fn all_task_done(&self) {}

    fn loop_interval_ms(&self) -> u64 {
        5000
    }
}

type PeerTaskMap<Launcher> = DashMap<
    <Launcher as PeerTaskLauncher>::CollectPeerItem,
    AbortOnDropHandle<Result<<Launcher as PeerTaskLauncher>::TaskRet, Error>>,
>;

pub struct PeerTaskManager<Launcher: PeerTaskLauncher> {
    launcher: Launcher,
    main_loop_task: Mutex<Option<AbortOnDropHandle<()>>>,
    peer_tasks: Arc<PeerTaskMap<Launcher>>,
    run_signal: Arc<Notify>,
    external_signal: Option<Arc<ExternalTaskSignal>>,
}

impl<C, T, L> PeerTaskManager<L>
where
    C: std::fmt::Debug + Send + Sync + Clone + core::hash::Hash + Eq + 'static,
    T: Send + 'static,
    L: PeerTaskLauncher<CollectPeerItem = C, TaskRet = T> + 'static,
{
    pub fn new_with_external_signal(
        launcher: L,
        external_signal: Option<Arc<ExternalTaskSignal>>,
    ) -> Self {
        Self {
            launcher,
            main_loop_task: Mutex::new(None),
            peer_tasks: Arc::new(DashMap::new()),
            run_signal: Arc::new(Notify::new()),
            external_signal,
        }
    }

    pub fn start(&self) {
        let mut task_slot = self.main_loop_task.lock().unwrap();
        if task_slot.as_ref().is_some_and(|task| !task.is_finished()) {
            return;
        }
        let task = AbortOnDropHandle::new(tokio::spawn(Self::main_loop(
            self.launcher.clone(),
            self.run_signal.clone(),
            self.external_signal.clone(),
            self.peer_tasks.clone(),
        )));
        task_slot.replace(task);
    }

    pub async fn stop(&self) {
        let task = self.main_loop_task.lock().unwrap().take();
        if let Some(task) = task {
            task.abort();
            let _ = task.await;
        }
        let keys = self
            .peer_tasks
            .iter()
            .map(|entry| entry.key().clone())
            .collect::<Vec<_>>();
        for key in keys {
            if let Some((_, task)) = self.peer_tasks.remove(&key) {
                task.abort();
                let _ = task.await;
            }
        }
        self.peer_tasks.shrink_to_fit();
        self.launcher.all_task_done().await;
    }

    async fn main_loop(
        launcher: L,
        signal: Arc<Notify>,
        external_signal: Option<Arc<ExternalTaskSignal>>,
        peer_task_map: Arc<DashMap<C, AbortOnDropHandle<Result<T, Error>>>>,
    ) {
        let mut external_signal_version = external_signal.as_ref().map(|signal| signal.version());

        loop {
            let peers_to_connect = launcher.collect_peers_need_task().await;

            let mut to_remove = vec![];
            for item in peer_task_map.iter() {
                if !peers_to_connect.contains(item.key()) || item.value().is_finished() {
                    to_remove.push(item.key().clone());
                }
            }

            for key in to_remove {
                if let Some((_, task)) = peer_task_map.remove(&key) {
                    task.abort();
                    match task.await {
                        Ok(Ok(_)) => {}
                        Ok(Err(task_ret)) => {
                            tracing::error!(
                                target: "easytier_core::peers::peer_task",
                                ?task_ret,
                                "hole punching task failed"
                            );
                        }
                        Err(e) => {
                            tracing::error!(
                                target: "easytier_core::peers::peer_task",
                                ?e,
                                "hole punching task aborted"
                            );
                        }
                    }
                }
                peer_task_map.shrink_to_fit();
            }

            if !peers_to_connect.is_empty() {
                for item in peers_to_connect {
                    if peer_task_map.contains_key(&item) {
                        continue;
                    }

                    tracing::debug!(
                        target: "easytier_core::peers::peer_task",
                        ?item,
                        "launch hole punching task"
                    );
                    peer_task_map.insert(
                        item.clone(),
                        AbortOnDropHandle::new(launcher.launch_task(item).await),
                    );
                }
            } else if peer_task_map.is_empty() {
                launcher.all_task_done().await;
            }

            if let Some(external_signal) = external_signal.as_ref() {
                // The `notified()` future must be created before the version is
                // re-read: a `Notified` future is guaranteed to observe every
                // `notify_waiters()` call made after its creation, so a notify
                // landing between the version read and the first poll below
                // cannot be lost. Reordering these two statements would degrade
                // wakeups back to `loop_interval_ms` polling.
                let notified = external_signal.notified();
                tokio::pin!(notified);
                let cur_version = external_signal.version();
                if external_signal_version != Some(cur_version) {
                    external_signal_version = Some(cur_version);
                    continue;
                }

                select! {
                    _ = crate::foundation::time::sleep(std::time::Duration::from_millis(
                        launcher.loop_interval_ms(),
                    )) => {},
                    _ = signal.notified() => {},
                    _ = &mut notified => {
                        external_signal_version = Some(external_signal.version());
                    }
                }
            } else {
                select! {
                    _ = crate::foundation::time::sleep(std::time::Duration::from_millis(
                        launcher.loop_interval_ms(),
                    )) => {},
                    _ = signal.notified() => {}
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    use super::*;

    #[derive(Clone)]
    struct TestLauncher {
        active_tasks: Arc<AtomicUsize>,
    }

    struct ActiveTaskGuard(Arc<AtomicUsize>);

    impl Drop for ActiveTaskGuard {
        fn drop(&mut self) {
            self.0.fetch_sub(1, Ordering::SeqCst);
        }
    }

    #[async_trait]
    impl PeerTaskLauncher for TestLauncher {
        type CollectPeerItem = u8;
        type TaskRet = ();

        async fn collect_peers_need_task(&self) -> Vec<u8> {
            vec![1]
        }

        async fn launch_task(&self, _item: u8) -> JoinHandle<Result<(), Error>> {
            let active_tasks = self.active_tasks.clone();
            tokio::spawn(async move {
                active_tasks.fetch_add(1, Ordering::SeqCst);
                let _guard = ActiveTaskGuard(active_tasks);
                std::future::pending::<()>().await;
                Ok(())
            })
        }
    }

    #[tokio::test]
    async fn joinset_reaper_does_not_keep_task_set_alive() {
        let tasks = Arc::new(Mutex::new(JoinSet::new()));
        let weak_tasks = Arc::downgrade(&tasks);
        tasks
            .lock()
            .unwrap()
            .spawn(reap_joinset_background(weak_tasks.clone(), "test"));

        drop(tasks);

        assert!(weak_tasks.upgrade().is_none());
    }

    #[tokio::test]
    async fn peer_task_manager_is_cold_and_joins_children_on_stop() {
        let active_tasks = Arc::new(AtomicUsize::new(0));
        let manager = PeerTaskManager::new_with_external_signal(
            TestLauncher {
                active_tasks: active_tasks.clone(),
            },
            None,
        );

        tokio::task::yield_now().await;
        assert_eq!(active_tasks.load(Ordering::SeqCst), 0);

        manager.start();
        crate::foundation::time::timeout(std::time::Duration::from_secs(1), async {
            while active_tasks.load(Ordering::SeqCst) == 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();

        manager.stop().await;
        assert_eq!(active_tasks.load(Ordering::SeqCst), 0);
    }

    #[tokio::test(start_paused = true)]
    async fn external_signal_notify_before_first_poll_wakes_immediately() {
        // Pins the ordering invariant of `PeerTaskManager::main_loop`: the
        // `notified()` future is created before the version is re-read, and a
        // `notify()` landing between that read and the future's first poll
        // (the classic lost-wakeup window) must still wake the waiter without
        // waiting for a polling timeout.
        let signal = ExternalTaskSignal::new();
        let observed_version = signal.version();

        let notified = signal.notified();
        tokio::pin!(notified);

        let cur_version = signal.version();
        assert_eq!(observed_version, cur_version);

        signal.notify();

        tokio::time::timeout(Duration::from_secs(1), &mut notified)
            .await
            .expect("notify() before the first poll must not be lost");
        assert_eq!(signal.version(), observed_version + 1);
    }

    #[derive(Clone)]
    struct ImmediateWakeLauncher {
        collect_count: Arc<AtomicUsize>,
        interval_ms: u64,
    }

    #[async_trait]
    impl PeerTaskLauncher for ImmediateWakeLauncher {
        type CollectPeerItem = u8;
        type TaskRet = ();

        async fn collect_peers_need_task(&self) -> Vec<u8> {
            self.collect_count.fetch_add(1, Ordering::SeqCst);
            Vec::new()
        }

        async fn launch_task(&self, _item: u8) -> JoinHandle<Result<(), Error>> {
            tokio::spawn(async { Ok(()) })
        }

        fn loop_interval_ms(&self) -> u64 {
            self.interval_ms
        }
    }

    #[tokio::test(start_paused = true)]
    async fn external_signal_wakes_manager_without_waiting_for_interval() {
        // With the clock paused, only the lost-wakeup path (falling back to the
        // interval timer) would advance time; a working demand-driven wakeup
        // re-collects at ~zero elapsed time.
        let collect_count = Arc::new(AtomicUsize::new(0));
        let signal = Arc::new(ExternalTaskSignal::new());
        let manager = PeerTaskManager::new_with_external_signal(
            ImmediateWakeLauncher {
                collect_count: collect_count.clone(),
                interval_ms: 60_000,
            },
            Some(signal.clone()),
        );

        manager.start();
        while collect_count.load(Ordering::SeqCst) < 1 {
            tokio::task::yield_now().await;
        }

        let started = tokio::time::Instant::now();
        signal.notify();

        tokio::time::timeout(Duration::from_secs(5), async {
            while collect_count.load(Ordering::SeqCst) < 2 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("external signal must wake the manager immediately");

        assert!(started.elapsed() < Duration::from_secs(5));
        manager.stop().await;
    }
}
