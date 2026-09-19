use std::{
    fs::{self, File, OpenOptions},
    io::{self, Write},
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
        mpsc::{Receiver, SyncSender, channel, sync_channel},
    },
    thread::{Builder, JoinHandle},
    time::{Duration, Instant},
};

use tracing_subscriber::fmt::MakeWriter;

pub(crate) const MAX_LOG_BYTES: u64 = 5 * 1024 * 1024;
pub(crate) const MAX_LOG_FILES: usize = 4;

/// Minimum spacing between two "rotation failed" warnings, so a persistently
/// broken sink cannot flood the log with its own failures.
const ROTATION_WARN_INTERVAL: Duration = Duration::from_secs(30);

/// Bounded capacity of the event queue between emitting threads and the
/// writer thread. When full, events are dropped and counted instead of
/// blocking the emitter (which runs on data-plane worker threads).
const CHANNEL_CAPACITY: usize = 1024;

/// Why not `tracing_appender::non_blocking`: it does move writes off the
/// emitting thread, but its rolling policy is time-based only (it cannot
/// reproduce this sink's size-triggered rename chain with a hard file-count
/// cap) and it offers no way to run control operations (directory switch,
/// clear, synchronous drain) on the worker thread. A minimal dedicated
/// writer over a bounded std mpsc channel keeps those semantics without
/// pulling in another dependency.
enum Message {
    Event(Vec<u8>),
    SetDirectory(PathBuf, Reply),
    Clear(Reply),
    Flush(Reply),
    Shutdown,
}

/// Completion channel for control operations; the caller blocks on it until
/// the writer thread has processed the command.
type Reply = std::sync::mpsc::Sender<io::Result<()>>;

struct WriterShared {
    tx: SyncSender<Message>,
    /// Events dropped because the channel was full; once the channel
    /// recovers, a single summary line is emitted so the gap stays visible.
    /// Best-effort counters (Relaxed); exact counts are not required.
    dropped: AtomicU64,
    worker: Mutex<Option<JoinHandle<()>>>,
}

impl Drop for WriterShared {
    fn drop(&mut self) {
        // Last writer clone gone: enqueue Shutdown behind the remaining
        // events (send blocks only until the worker drains space, which it
        // always does for a live worker) and join so the handle never leaks.
        let _ = self.tx.send(Message::Shutdown);
        if let Some(worker) = self
            .worker
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .take()
        {
            // The worker surfaces errors as values and must not panic; a
            // stray panic is already unreportable here, so just reap it.
            let _ = worker.join();
        }
    }
}

#[derive(Clone)]
pub(crate) struct DiagnosticMakeWriter {
    shared: Arc<WriterShared>,
}

impl DiagnosticMakeWriter {
    pub(crate) fn new(directory: &Path) -> io::Result<Self> {
        let log = RotatingLog::open(directory)?;
        let (tx, rx) = sync_channel(CHANNEL_CAPACITY);
        let worker = Builder::new()
            .name("easytier-diagnostic-log".to_owned())
            .spawn(move || run_writer(log, rx))?;
        Ok(Self {
            shared: Arc::new(WriterShared {
                tx,
                dropped: AtomicU64::new(0),
                worker: Mutex::new(Some(worker)),
            }),
        })
    }

    pub(crate) fn set_directory(&self, directory: &Path) -> io::Result<()> {
        self.call(|reply| Message::SetDirectory(directory.to_owned(), reply))
    }

    pub(crate) fn clear(&self) -> io::Result<()> {
        self.call(Message::Clear)
    }

    /// Drain every event enqueued so far, flush the file, and only return
    /// once both are done. `disable` relies on this so already-emitted
    /// events are never lost. The writer thread itself is intentionally kept
    /// alive afterwards: the tracing subscriber is process-global and cannot
    /// be uninstalled, so a later enable reuses the parked thread instead of
    /// respawn machinery.
    pub(crate) fn flush(&self) -> io::Result<()> {
        self.call(Message::Flush)
    }

    /// Run a control operation on the writer thread and wait for it to
    /// finish. Blocking is fine here: these are called from FFI lifecycle
    /// paths, never from event emission.
    fn call(&self, make: impl FnOnce(Reply) -> Message) -> io::Result<()> {
        let (reply, done) = channel();
        self.shared
            .tx
            .send(make(reply))
            .map_err(|_| io::Error::other("diagnostic log writer stopped"))?;
        done.recv()
            .map_err(|_| io::Error::other("diagnostic log writer stopped"))?
    }
}

/// Writer thread body: owns the rotating log exclusively, so the emitting
/// path never touches files or locks.
fn run_writer(mut log: RotatingLog, rx: Receiver<Message>) {
    while let Ok(message) = rx.recv() {
        match message {
            Message::Event(event) => {
                // Write errors have no observer here and must not be logged
                // back (an unthrottled loop of failing warn events would
                // spin this thread); only the rate-limited rotation warning
                // is re-emitted, bounded by ROTATION_WARN_INTERVAL.
                let _ = log.write_event(&event);
                if let Some(warning) = log.take_rotation_warning() {
                    tracing::warn!(target: "easytier_ios::diagnostics", "{warning}");
                }
            }
            Message::SetDirectory(directory, reply) => {
                let _ = reply.send(log.set_directory(&directory));
            }
            Message::Clear(reply) => {
                let _ = reply.send(log.clear());
            }
            Message::Flush(reply) => {
                let _ = reply.send(log.flush());
            }
            Message::Shutdown => break,
        }
    }
}

/// Enqueue one formatted event without ever blocking the caller: a full
/// channel drops the event and counts it; once the channel recovers, a
/// single "dropped N events" summary line is emitted first so the gap stays
/// visible in the log.
fn enqueue_event(tx: &SyncSender<Message>, dropped: &AtomicU64, event: Vec<u8>) {
    let missed = dropped.load(Ordering::Relaxed);
    if missed > 0
        && dropped
            .compare_exchange(missed, 0, Ordering::Relaxed, Ordering::Relaxed)
            .is_ok()
    {
        let summary =
            format!("easytier diagnostic log: dropped {missed} events while the queue was full\n");
        if tx.try_send(Message::Event(summary.into_bytes())).is_err() {
            // Still saturated (or the worker is gone); restore the count so
            // the summary is retried later.
            dropped.fetch_add(missed, Ordering::Relaxed);
        }
    }
    if tx.try_send(Message::Event(event)).is_err() {
        dropped.fetch_add(1, Ordering::Relaxed);
    }
}

impl<'a> MakeWriter<'a> for DiagnosticMakeWriter {
    type Writer = BufferedEventWriter;

    fn make_writer(&'a self) -> Self::Writer {
        BufferedEventWriter {
            target: self.clone(),
            buffer: Vec::new(),
        }
    }
}

pub(crate) struct BufferedEventWriter {
    target: DiagnosticMakeWriter,
    buffer: Vec<u8>,
}

impl BufferedEventWriter {
    fn commit(&mut self) {
        if self.buffer.is_empty() {
            return;
        }
        let buffer = std::mem::take(&mut self.buffer);
        enqueue_event(&self.target.shared.tx, &self.target.shared.dropped, buffer);
    }
}

impl Write for BufferedEventWriter {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        self.buffer.extend_from_slice(buffer);
        Ok(buffer.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.commit();
        Ok(())
    }
}

impl Drop for BufferedEventWriter {
    fn drop(&mut self) {
        self.commit();
    }
}

struct RotatingLog {
    directory: PathBuf,
    active: Option<File>,
    active_bytes: u64,
    /// Rate-limited rotation failure message, drained by the writer thread
    /// after `write_event` returns and emitted as a `warn!`; the rate limit
    /// bounds the re-entry when that warning is logged itself.
    pending_rotation_warn: Option<String>,
    last_rotation_warn: Option<Instant>,
}

impl RotatingLog {
    fn open(directory: &Path) -> io::Result<Self> {
        fs::create_dir_all(directory)?;
        let mut log = Self {
            directory: directory.to_owned(),
            active: None,
            active_bytes: 0,
            pending_rotation_warn: None,
            last_rotation_warn: None,
        };
        log.truncate_oversized_files()?;
        log.open_active()?;
        Ok(log)
    }

    fn set_directory(&mut self, directory: &Path) -> io::Result<()> {
        if self.directory == directory && self.active.is_some() {
            return Ok(());
        }
        self.flush()?;
        // Open the new location fully before replacing the current handle,
        // so a failure (e.g. unwritable directory) keeps events flowing into
        // the previous file instead of silently dropping them.
        let replacement = RotatingLog::open(directory)?;
        self.directory = replacement.directory;
        self.active = replacement.active;
        self.active_bytes = replacement.active_bytes;
        Ok(())
    }

    fn active_path(&self) -> PathBuf {
        self.directory.join("easytier.log")
    }

    fn rotated_path(&self, index: usize) -> PathBuf {
        self.directory.join(format!("easytier.{index}.log"))
    }

    fn truncate_oversized_files(&self) -> io::Result<()> {
        let paths = std::iter::once(self.active_path())
            .chain((1..MAX_LOG_FILES).map(|index| self.rotated_path(index)));
        for path in paths {
            if path
                .metadata()
                .is_ok_and(|metadata| metadata.len() > MAX_LOG_BYTES)
            {
                OpenOptions::new()
                    .write(true)
                    .open(path)?
                    .set_len(MAX_LOG_BYTES)?;
            }
        }
        Ok(())
    }

    fn open_active(&mut self) -> io::Result<()> {
        let path = self.active_path();
        let file = OpenOptions::new().create(true).append(true).open(&path)?;
        self.active_bytes = file.metadata()?.len();
        self.active = Some(file);
        if self.active_bytes >= MAX_LOG_BYTES {
            // Fail-open: with no events to lose here, a failed rotation still
            // leaves the (oversized) active file writable; later events retry.
            if let Err(error) = self.rotate() {
                self.note_rotation_failure(&error);
            }
        }
        Ok(())
    }

    fn append(&mut self, event: &[u8]) -> io::Result<()> {
        if let Some(active) = self.active.as_mut() {
            active.write_all(event)?;
            self.active_bytes += event.len() as u64;
        }
        Ok(())
    }

    fn write_event(&mut self, event: &[u8]) -> io::Result<()> {
        if event.is_empty() {
            return Ok(());
        }
        if self.active_bytes > 0
            && self.active_bytes.saturating_add(event.len() as u64) > MAX_LOG_BYTES
            && let Err(error) = self.rotate()
        {
            // Rotation failed but `rotate` kept the previous handle open,
            // so append the full event even past MAX_LOG_BYTES instead
            // of dropping it; the oversized file is truncated on the
            // next open.
            self.note_rotation_failure(&error);
            return self.append(event);
        }
        let remaining = MAX_LOG_BYTES.saturating_sub(self.active_bytes) as usize;
        self.append(&event[..event.len().min(remaining)])
    }

    /// All fallible steps run before the active handle is replaced: on any
    /// failure the old file stays open and writable (fail-open), while a
    /// later event retries the rotation.
    fn rotate(&mut self) -> io::Result<()> {
        self.flush()?;

        let oldest = self.rotated_path(MAX_LOG_FILES - 1);
        if oldest.exists() {
            fs::remove_file(oldest)?;
        }
        for index in (1..MAX_LOG_FILES - 1).rev() {
            let source = self.rotated_path(index);
            if source.exists() {
                fs::rename(source, self.rotated_path(index + 1))?;
            }
        }
        let active = self.active_path();
        if active.exists() {
            fs::rename(active, self.rotated_path(1))?;
        }
        let replacement = OpenOptions::new()
            .create(true)
            .append(true)
            .open(self.active_path())?;
        self.active = Some(replacement);
        self.active_bytes = 0;
        Ok(())
    }

    fn clear(&mut self) -> io::Result<()> {
        self.flush()?;
        let mut failure: Option<io::Error> = None;
        for index in 1..MAX_LOG_FILES {
            match fs::remove_file(self.rotated_path(index)) {
                Err(error) if error.kind() != io::ErrorKind::NotFound => {
                    failure.get_or_insert(error);
                }
                _ => {}
            }
        }
        // Truncate the active file through a write-mode handle first:
        // append-mode handles cannot truncate on Windows, and truncating
        // before the swap keeps the old handle writable if the reopen below
        // fails.
        OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(self.active_path())?;
        let replacement = OpenOptions::new()
            .create(true)
            .append(true)
            .open(self.active_path())?;
        self.active = Some(replacement);
        self.active_bytes = 0;
        match failure {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self.active.as_mut() {
            Some(active) => active.flush(),
            None => Ok(()),
        }
    }

    /// Record a rate-limited warning about a swallowed rotation failure; the
    /// writer thread drains it via `take_rotation_warning` after
    /// `write_event` returns.
    fn note_rotation_failure(&mut self, error: &io::Error) {
        let now = Instant::now();
        if self
            .last_rotation_warn
            .is_none_or(|at| now.duration_since(at) >= ROTATION_WARN_INTERVAL)
        {
            self.last_rotation_warn = Some(now);
            self.pending_rotation_warn = Some(format!(
                "diagnostic log rotation failed, appending to the active file past the size cap: {error}"
            ));
        }
    }

    fn take_rotation_warning(&mut self) -> Option<String> {
        self.pending_rotation_warn.take()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    struct TempDir(PathBuf);

    impl TempDir {
        fn new(name: &str) -> Self {
            let unique = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let path = std::env::temp_dir().join(format!("easytier-ios-{name}-{unique}"));
            fs::create_dir_all(&path).unwrap();
            Self(path)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn rotates_without_exceeding_file_limit() {
        let directory = TempDir::new("rotation");
        let mut log = RotatingLog::open(&directory.0).unwrap();
        let event = vec![b'x'; (MAX_LOG_BYTES / 2 + 1) as usize];

        for _ in 0..6 {
            log.write_event(&event).unwrap();
        }
        log.flush().unwrap();

        let files = fs::read_dir(&directory.0)
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(files.len(), MAX_LOG_FILES);
        assert!(
            files
                .iter()
                .all(|entry| entry.metadata().unwrap().len() <= MAX_LOG_BYTES)
        );
    }

    #[test]
    fn clear_removes_rotated_content_and_keeps_active_file_writable() {
        let directory = TempDir::new("clear");
        let mut log = RotatingLog::open(&directory.0).unwrap();
        let event = vec![b'x'; (MAX_LOG_BYTES / 2 + 1) as usize];
        log.write_event(&event).unwrap();
        log.write_event(&event).unwrap();

        log.clear().unwrap();
        log.write_event(b"after clear\n").unwrap();
        log.flush().unwrap();

        assert_eq!(fs::read(log.active_path()).unwrap(), b"after clear\n");
        assert!(!log.rotated_path(1).exists());
    }

    #[test]
    fn opening_truncates_oversized_known_files() {
        let directory = TempDir::new("oversized");
        for name in ["easytier.log", "easytier.1.log"] {
            let file = File::create(directory.0.join(name)).unwrap();
            file.set_len(MAX_LOG_BYTES + 1).unwrap();
        }

        let log = RotatingLog::open(&directory.0).unwrap();

        for index in 1..MAX_LOG_FILES {
            let path = log.rotated_path(index);
            if path.exists() {
                assert!(path.metadata().unwrap().len() <= MAX_LOG_BYTES);
            }
        }
        assert!(log.active_path().metadata().unwrap().len() <= MAX_LOG_BYTES);
    }

    #[test]
    fn rotation_failure_keeps_writing_events() {
        let directory = TempDir::new("rotation-failure");
        let mut log = RotatingLog::open(&directory.0).unwrap();
        // A directory in the oldest slot makes `remove_file` fail before any
        // rename runs, deterministically on every platform. (Blocking the
        // final rename instead does not work: the shift loop first moves
        // whatever occupies `easytier.1.log` out of the way.)
        fs::create_dir(log.rotated_path(MAX_LOG_FILES - 1)).unwrap();

        let event = vec![b'x'; (MAX_LOG_BYTES / 2 + 1) as usize];
        log.write_event(&event).unwrap();
        // Exceeds the cap, so this triggers the failing rotation.
        log.write_event(&event).unwrap();
        assert!(
            log.take_rotation_warning()
                .is_some_and(|warning| warning.contains("rotation failed")),
            "rotation failure must be reported through the rate-limited warning"
        );
        // Rate limiting: another failing rotation within the interval is not
        // reported again.
        log.write_event(&event).unwrap();
        assert!(log.take_rotation_warning().is_none());

        // Fail-open: the events above and everything after still land in the
        // still-open active file (past the size cap) instead of being
        // silently dropped.
        log.write_event(b"still writable\n").unwrap();
        log.flush().unwrap();
        let content = fs::read(log.active_path()).unwrap();
        assert!(content.ends_with(b"still writable\n"));
        assert!(content.len() > MAX_LOG_BYTES as usize);
    }

    #[test]
    fn set_directory_failure_keeps_writing_events() {
        let directory = TempDir::new("set-directory-failure");
        let mut log = RotatingLog::open(&directory.0).unwrap();
        log.write_event(b"first\n").unwrap();

        // `directory.0/file/sub` lives inside a regular file, so
        // create_dir_all must fail.
        fs::File::create(directory.0.join("file")).unwrap();
        let bad = directory.0.join("file").join("sub");
        log.set_directory(&bad).unwrap_err();

        log.write_event(b"second\n").unwrap();
        log.flush().unwrap();
        assert_eq!(fs::read(log.active_path()).unwrap(), b"first\nsecond\n");
    }

    fn wait_for(mut probe: impl FnMut() -> bool) {
        let deadline = Instant::now() + Duration::from_secs(5);
        while !probe() {
            assert!(
                Instant::now() < deadline,
                "condition not met within the timeout"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    #[test]
    fn events_reach_disk_through_the_writer_thread() {
        let directory = TempDir::new("writer");
        let writer = DiagnosticMakeWriter::new(&directory.0).unwrap();
        {
            let mut event = writer.make_writer();
            event
                .write_all(b"hello from the emitting thread\n")
                .unwrap();
            event.flush().unwrap();
        }
        // The Drop of the writer also commits.

        // The write happens on another thread; poll for its arrival.
        let log_path = directory.0.join("easytier.log");
        wait_for(|| fs::read_to_string(&log_path).is_ok_and(|content| content.contains("hello")));
        // Control flush is a barrier: everything enqueued before it is on
        // disk once it returns.
        writer.flush().unwrap();
        assert!(fs::read_to_string(&log_path).unwrap().contains("hello"));
        // Dropping the last clone shuts the worker down cleanly.
    }

    #[test]
    fn flush_drains_pending_events() {
        let directory = TempDir::new("drain");
        let writer = DiagnosticMakeWriter::new(&directory.0).unwrap();
        const EVENTS: usize = 200;
        for index in 0..EVENTS {
            let mut event = writer.make_writer();
            writeln!(event, "drain event {index}").unwrap();
        }
        // Every writer Drop only enqueues; the flush reply proves all 200
        // events were written and flushed before it returned.
        writer.flush().unwrap();
        let content = fs::read_to_string(directory.0.join("easytier.log")).unwrap();
        for index in 0..EVENTS {
            assert!(
                content.contains(&format!("drain event {index}\n")),
                "event {index} lost before the flush barrier"
            );
        }
    }

    #[test]
    fn full_channel_drops_events_without_blocking() {
        let (tx, rx) = sync_channel::<Message>(2);
        let dropped = AtomicU64::new(0);

        enqueue_event(&tx, &dropped, b"first\n".to_vec());
        enqueue_event(&tx, &dropped, b"second\n".to_vec());
        // The queue is full now: this must neither block nor panic, just
        // count the drop.
        let start = Instant::now();
        enqueue_event(&tx, &dropped, b"third\n".to_vec());
        assert!(start.elapsed() < Duration::from_secs(1));
        assert_eq!(dropped.load(Ordering::Relaxed), 1);

        // Free one slot; the next enqueue recovers and reports the earlier
        // drop through a summary line ahead of it.
        assert!(matches!(&rx.try_recv(), Ok(Message::Event(e)) if e == b"first\n"));
        enqueue_event(&tx, &dropped, b"fourth\n".to_vec());
        assert!(matches!(&rx.try_recv(), Ok(Message::Event(e)) if e == b"second\n"));
        assert!(
            matches!(&rx.try_recv(), Ok(Message::Event(e)) if String::from_utf8_lossy(e).contains("dropped 1 events"))
        );
    }
}
