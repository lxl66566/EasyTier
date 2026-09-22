use std::collections::HashSet;
use std::sync::{
    Arc, Weak,
    atomic::{AtomicBool, Ordering},
};

use async_trait::async_trait;
use easytier_proto::{
    rpc_types::controller::BaseController,
    web::{
        DeviceOsInfo, GetFeatureRequest, GetFeatureResponse, HeartbeatRequest, HeartbeatResponse,
        WebServerServiceClientFactory,
    },
};
use tokio::{sync::Mutex, task::JoinSet};
use tokio_util::task::AbortOnDropHandle;
use url::Url;

use crate::{
    connectivity::protocol::raw::TunnelDialer,
    foundation::time,
    instance::{CoreInstance, CoreInstanceHost, manager::InstanceFactory},
    rpc::{bidirect::BidirectRpcManager, service_registry::ServiceRegistry},
    tunnel::{Tunnel, web_security},
};

#[cfg(not(feature = "management"))]
use super::register_web_client_rpc;
use super::{ConfigFileStorage, DaemonGuard, InstanceManager, InstanceMutationHooks};
#[cfg(feature = "management")]
use super::{LoggerControl, register_management_rpc};

const RETRY_INTERVAL: std::time::Duration = std::time::Duration::from_secs(1);
// Keep retry ownership in this loop when transport or protocol handshakes stall.
const CONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(20);
const FEATURE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(3);
const DEFAULT_HEARTBEAT_INTERVAL_MS: u32 = 3_500;
const DEFAULT_HEARTBEAT_TIMEOUT_MS: u32 = 15_000;
const MIN_HEARTBEAT_INTERVAL_MS: u32 = 1_000;
const MAX_HEARTBEAT_INTERVAL_MS: u32 = 60_000;
const MIN_HEARTBEAT_TIMEOUT_MS: u32 = 5_000;
const MAX_HEARTBEAT_TIMEOUT_MS: u32 = 120_000;
const MIN_HEARTBEAT_TIMEOUT_MARGIN_MS: u32 = 5_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct HeartbeatPolicy {
    interval: std::time::Duration,
    timeout_ms: i32,
}

impl Default for HeartbeatPolicy {
    fn default() -> Self {
        Self {
            interval: std::time::Duration::from_millis(DEFAULT_HEARTBEAT_INTERVAL_MS.into()),
            timeout_ms: DEFAULT_HEARTBEAT_TIMEOUT_MS as i32,
        }
    }
}

impl HeartbeatPolicy {
    fn from_response(response: &HeartbeatResponse) -> (Self, bool) {
        let requested_interval = response
            .heartbeat_interval_ms
            .unwrap_or(DEFAULT_HEARTBEAT_INTERVAL_MS);
        let requested_timeout = response
            .heartbeat_timeout_ms
            .unwrap_or(DEFAULT_HEARTBEAT_TIMEOUT_MS);
        let interval_ms =
            requested_interval.clamp(MIN_HEARTBEAT_INTERVAL_MS, MAX_HEARTBEAT_INTERVAL_MS);
        let timeout_ms = requested_timeout
            .clamp(MIN_HEARTBEAT_TIMEOUT_MS, MAX_HEARTBEAT_TIMEOUT_MS)
            .max(interval_ms.saturating_add(MIN_HEARTBEAT_TIMEOUT_MARGIN_MS));
        (
            Self {
                interval: std::time::Duration::from_millis(interval_ms.into()),
                timeout_ms: timeout_ms as i32,
            },
            interval_ms != requested_interval || timeout_ms != requested_timeout,
        )
    }

    fn controller(self) -> BaseController {
        BaseController {
            timeout_ms: self.timeout_ms,
            ..Default::default()
        }
    }

    fn remaining_interval(self, elapsed: std::time::Duration) -> Option<std::time::Duration> {
        self.interval
            .checked_sub(elapsed)
            .filter(|delay| !delay.is_zero())
    }
}

async fn connect_config_server(
    connector: &dyn TunnelDialer,
    timeout: std::time::Duration,
) -> anyhow::Result<Box<dyn Tunnel>> {
    time::timeout(timeout, connector.connect())
        .await
        .map_err(|_| anyhow::anyhow!("config-server connection timed out after {timeout:?}"))?
}

/// Normalized config-server endpoint and authentication token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigServerEndpoint {
    connect_url: Url,
    token: String,
    server_noise_pin: Option<[u8; 32]>,
    allow_plain: bool,
}

/// Extracts a server static-key pin from the URL fragment
/// (`#fingerprint=sha256:<hex>`). A present but malformed pin is an error:
/// silently ignoring it would turn an intended fail-closed configuration
/// into an unauthenticated one.
fn parse_noise_pin_fragment(url: &Url) -> anyhow::Result<Option<[u8; 32]>> {
    let Some(fragment) = url.fragment() else {
        return Ok(None);
    };
    for pair in fragment.split('&') {
        let Some(value) = pair.strip_prefix("fingerprint=") else {
            continue;
        };
        return crate::tunnel::fingerprint::parse_sha256_fingerprint(value)
            .map(Some)
            .ok_or_else(|| {
                anyhow::anyhow!("invalid server fingerprint in config server URL: {value}")
            });
    }
    Ok(None)
}

/// Extracts the explicit plaintext opt-in from the URL fragment
/// (`#allow-plain=1`). Only `0` and `1` are accepted so a typo fails loudly
/// instead of silently keeping the encrypted default.
fn parse_allow_plain_fragment(url: &Url) -> anyhow::Result<bool> {
    let Some(fragment) = url.fragment() else {
        return Ok(false);
    };
    for pair in fragment.split('&') {
        let Some(value) = pair.strip_prefix("allow-plain=") else {
            continue;
        };
        return match value {
            "0" => Ok(false),
            "1" => Ok(true),
            _ => Err(anyhow::anyhow!(
                "invalid allow-plain value in config server URL: {value} (expected 0 or 1)"
            )),
        };
    }
    Ok(false)
}

impl ConfigServerEndpoint {
    pub fn parse(input: &str, supports_scheme: impl FnOnce(&Url) -> bool) -> anyhow::Result<Self> {
        let endpoint = Url::parse(input)
            .map_err(|error| anyhow::anyhow!("failed to parse config server URL: {error}"))?;
        if !supports_scheme(&endpoint) {
            anyhow::bail!("unsupported config server scheme: {}", endpoint.scheme());
        }
        let server_noise_pin = parse_noise_pin_fragment(&endpoint)?;
        let allow_plain = parse_allow_plain_fragment(&endpoint)?;

        let token = endpoint
            .path_segments()
            .and_then(|mut segments| segments.next_back())
            .map(|segment| percent_encoding::percent_decode_str(segment).decode_utf8())
            .transpose()
            .map_err(|error| anyhow::anyhow!("failed to decode config server token: {error}"))?
            .map(|token| token.to_string())
            .unwrap_or_default();
        if token.is_empty() {
            anyhow::bail!("empty token");
        }

        let mut connect_url = endpoint;
        connect_url.set_fragment(None);
        if !matches!(connect_url.scheme(), "ws" | "wss") {
            connect_url.set_path("");
        }
        Ok(Self {
            connect_url,
            token,
            server_noise_pin,
            allow_plain,
        })
    }

    pub fn connect_url(&self) -> &Url {
        &self.connect_url
    }

    pub fn token(&self) -> &str {
        &self.token
    }

    /// Pinned SHA-256 fingerprint of the server's noise v2 static public key.
    pub fn server_noise_pin(&self) -> Option<[u8; 32]> {
        self.server_noise_pin
    }

    /// Explicit `#allow-plain=1` opt-in for unencrypted sessions.
    pub fn allow_plain(&self) -> bool {
        self.allow_plain
    }
}

pub struct WebClientConfig {
    pub token: String,
    pub machine_id: uuid::Uuid,
    pub hostname: String,
    pub device_os: DeviceOsInfo,
    pub easytier_version: String,
    pub secure_mode: bool,
    /// Pinned SHA-256 fingerprint of the config server's noise v2 static
    /// key. When set, only authenticated Noise_XX connections are allowed.
    pub server_noise_pin: Option<[u8; 32]>,
    /// Explicit `#allow-plain=1` opt-in from the config server URL. Without
    /// it, a session that cannot be encrypted is refused instead of silently
    /// downgraded to plaintext.
    pub allow_plain: bool,
}

#[async_trait]
pub(crate) trait WebClientBackend: Send + Sync + 'static {
    fn register(&self, registry: &ServiceRegistry);

    async fn instance_ids(&self) -> anyhow::Result<Vec<uuid::Uuid>>;

    fn failed_instance_ids(&self) -> Vec<uuid::Uuid>;

    fn instance_state_generation(&self) -> usize {
        0
    }

    async fn wait_for_instance_state_change(&self, _generation: usize) -> usize {
        std::future::pending().await
    }
}

struct NativeWebClientBackend<F>
where
    F: InstanceFactory,
{
    instances: Arc<InstanceManager<F>>,
    hooks: Arc<dyn InstanceMutationHooks>,
    storage: Arc<dyn ConfigFileStorage>,
    #[cfg(feature = "management")]
    logger: Arc<dyn LoggerControl>,
}

#[async_trait]
impl<F, H> WebClientBackend for NativeWebClientBackend<F>
where
    F: InstanceFactory<Instance = CoreInstance<H>, CreateContext = ()>,
    F::Error: std::fmt::Debug + std::fmt::Display + Send + Sync + 'static,
    H: CoreInstanceHost,
{
    fn register(&self, registry: &ServiceRegistry) {
        #[cfg(feature = "management")]
        register_management_rpc(
            self.instances.clone(),
            registry,
            self.hooks.clone(),
            self.storage.clone(),
            self.logger.clone(),
        );
        #[cfg(not(feature = "management"))]
        register_web_client_rpc(
            self.instances.clone(),
            registry,
            self.hooks.clone(),
            self.storage.clone(),
        );
    }

    async fn instance_ids(&self) -> anyhow::Result<Vec<uuid::Uuid>> {
        Ok(self.instances.instance_ids())
    }

    fn failed_instance_ids(&self) -> Vec<uuid::Uuid> {
        self.instances.failed_instance_ids()
    }

    fn instance_state_generation(&self) -> usize {
        self.instances.instance_state_generation()
    }

    async fn wait_for_instance_state_change(&self, generation: usize) -> usize {
        self.instances
            .wait_for_instance_state_change(generation)
            .await
    }
}

struct WebClientController {
    config: WebClientConfig,
    backend: Arc<dyn WebClientBackend>,
    runtime_id: uuid::Uuid,
}

/// Portable config-server client. Hosts only supply identity and adapters.
pub struct WebClient<F> {
    _controller: Arc<WebClientController>,
    _tasks: AbortOnDropHandle<()>,
    _manager_guard: Option<DaemonGuard>,
    connected: Arc<AtomicBool>,
    _factory: std::marker::PhantomData<F>,
}

impl<F, H> WebClient<F>
where
    F: InstanceFactory<Instance = CoreInstance<H>, CreateContext = ()>,
    F::Error: std::fmt::Debug + std::fmt::Display + Send + Sync + 'static,
    H: CoreInstanceHost,
{
    pub fn new<T: TunnelDialer + 'static>(
        connector: T,
        config: WebClientConfig,
        instances: Arc<InstanceManager<F>>,
        hooks: Arc<dyn InstanceMutationHooks>,
        storage: Arc<dyn ConfigFileStorage>,
        #[cfg(feature = "management")] logger: Arc<dyn LoggerControl>,
    ) -> Self {
        let manager_guard = instances.register_daemon();
        let backend = Arc::new(NativeWebClientBackend {
            instances,
            hooks,
            storage,
            #[cfg(feature = "management")]
            logger,
        });
        Self::start(connector, config, backend, Some(manager_guard))
    }
}

#[cfg(target_os = "wasi")]
impl WebClient<()> {
    pub(crate) fn with_backend<T: TunnelDialer + 'static>(
        connector: T,
        config: WebClientConfig,
        backend: Arc<dyn WebClientBackend>,
    ) -> Self {
        Self::start(connector, config, backend, None)
    }
}

impl<F> WebClient<F> {
    fn start<T: TunnelDialer + 'static>(
        connector: T,
        config: WebClientConfig,
        backend: Arc<dyn WebClientBackend>,
        manager_guard: Option<DaemonGuard>,
    ) -> Self {
        let controller = Arc::new(WebClientController {
            config,
            backend,
            runtime_id: uuid::Uuid::new_v4(),
        });
        let connected = Arc::new(AtomicBool::new(false));
        let tasks = AbortOnDropHandle::new(tokio::spawn(web_client_routine(
            controller.clone(),
            connected.clone(),
            Box::new(connector),
        )));

        Self {
            _controller: controller,
            _tasks: tasks,
            _manager_guard: manager_guard,
            connected,
            _factory: std::marker::PhantomData,
        }
    }

    pub fn is_connected(&self) -> bool {
        self.connected.load(Ordering::Acquire)
    }
}

/// Warn once per process that the config server only offers the
/// unauthenticated noise v1 web tunnel.
fn warn_once_noise_v1_fallback() {
    static WARNED: std::sync::OnceLock<()> = std::sync::OnceLock::new();
    WARNED.get_or_init(|| {
        tracing::warn!(
            "config server only supports the noise v1 (unauthenticated) web tunnel; \
             continuing without server verification. Upgrade easytier-web and pin \
             '#fingerprint=sha256:<hash>' in the config server URL once it supports \
             noise v2"
        );
    });
}

/// Warn once per process that the management session runs in plaintext by
/// explicit `#allow-plain=1` opt-in.
fn warn_once_plaintext_opt_in() {
    static WARNED: std::sync::OnceLock<()> = std::sync::OnceLock::new();
    WARNED.get_or_init(|| {
        tracing::warn!(
            "config server session runs unencrypted, allowed by '#allow-plain=1' in \
             the URL; a man-in-the-middle can read and modify all config-server traffic"
        );
    });
}

/// What to do with a freshly connected config-server session after the
/// GetFeature exchange.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SessionPlan {
    /// Reconnect and run the noise handshake; v1 still encrypts, v2 also
    /// authenticates the server (`noise_v2 == false` warns once).
    Secure { noise_v2: bool },
    /// Keep the already-open plaintext session (explicit opt-in).
    Plain,
    /// Refuse: a pinned endpoint must never lose server authentication.
    RefusePinned,
    /// Refuse: unencrypted session without the `#allow-plain=1` opt-in.
    RefusePlaintext,
    /// Refuse: secure mode forbids plaintext even with the opt-in.
    RefuseSecureMode,
}

/// Picks the session continuation from the negotiated feature flags.
///
/// Ordering is security-critical: the pin rule runs first (a pinned
/// endpoint may never end up on an unauthenticated path, not even with
/// `#allow-plain=1`), then the encrypted path, and only then the plaintext
/// decisions.
fn plan_session(
    support_encryption: bool,
    support_noise_v2: bool,
    local_secure_support: bool,
    pin: Option<[u8; 32]>,
    allow_plain: bool,
    secure_mode: bool,
) -> SessionPlan {
    if pin.is_some() && !(support_encryption && support_noise_v2 && local_secure_support) {
        return SessionPlan::RefusePinned;
    }
    if support_encryption && local_secure_support {
        // Noise v1 still encrypts the session; only dropping to plaintext
        // needs the explicit opt-in below.
        return SessionPlan::Secure {
            noise_v2: support_noise_v2,
        };
    }
    if secure_mode {
        return SessionPlan::RefuseSecureMode;
    }
    if !allow_plain {
        return SessionPlan::RefusePlaintext;
    }
    SessionPlan::Plain
}

async fn web_client_routine(
    controller: Arc<WebClientController>,
    connected: Arc<AtomicBool>,
    connector: Box<dyn TunnelDialer>,
) {
    loop {
        let connection = match connect_config_server(connector.as_ref(), CONNECT_TIMEOUT).await {
            Ok(connection) => connection,
            Err(error) => {
                tracing::warn!(%error, "failed to connect to config server; retrying");
                time::sleep(RETRY_INTERVAL).await;
                continue;
            }
        };

        connected.store(true, Ordering::Release);
        tracing::info!(?connection, "connected to config server");
        let mut session = WebClientSession::new(connection, controller.clone());
        let (support_encryption, support_noise_v2) =
            match time::timeout(FEATURE_TIMEOUT, session.get_feature()).await {
                Ok(Ok(feature)) => (feature.support_encryption, feature.support_noise_v2),
                Ok(Err(error)) => {
                    tracing::warn!(%error, "GetFeature RPC failed; assuming no encryption support");
                    (false, false)
                }
                Err(_) => {
                    tracing::warn!("GetFeature RPC timed out; assuming no encryption support");
                    (false, false)
                }
            };
        let local_secure_support = web_security::web_secure_tunnel_supported();
        let plan = plan_session(
            support_encryption,
            support_noise_v2,
            local_secure_support,
            controller.config.server_noise_pin,
            controller.config.allow_plain,
            controller.config.secure_mode,
        );

        match plan {
            SessionPlan::RefusePinned => {
                // Fail-closed rule for pinned endpoints: only a locally
                // supported, server-advertised Noise_XX handshake may carry
                // the management session. Never silently fall back to noise
                // v1 or plaintext.
                drop(session);
                connected.store(false, Ordering::Release);
                tracing::warn!(
                    support_encryption,
                    support_noise_v2,
                    local_secure_support,
                    "config server cannot perform the pinned noise v2 handshake; \
                     refusing an unauthenticated connection"
                );
                time::sleep(RETRY_INTERVAL).await;
                continue;
            }
            SessionPlan::Secure { noise_v2 } => {
                if !noise_v2 {
                    warn_once_noise_v1_fallback();
                }
                drop(session);
                let connection = match connect_config_server(connector.as_ref(), CONNECT_TIMEOUT)
                    .await
                {
                    Ok(connection) => connection,
                    Err(error) => {
                        connected.store(false, Ordering::Release);
                        tracing::warn!(%error, "failed to reconnect secure config-server tunnel");
                        time::sleep(RETRY_INTERVAL).await;
                        continue;
                    }
                };
                let mode = web_security::ClientHandshakeMode::negotiate(
                    controller.config.server_noise_pin,
                    noise_v2,
                );
                let connection = match web_security::upgrade_client_tunnel(connection, mode).await {
                    Ok(connection) => connection,
                    Err(error) => {
                        connected.store(false, Ordering::Release);
                        tracing::warn!(%error, "config-server secure handshake failed");
                        time::sleep(RETRY_INTERVAL).await;
                        continue;
                    }
                };
                let mut session = WebClientSession::new(connection, controller.clone());
                session.start_heartbeat().await;
                session.wait().await;
                connected.store(false, Ordering::Release);
                continue;
            }
            SessionPlan::RefusePlaintext => {
                // The GetFeature exchange is plaintext, so a
                // man-in-the-middle could have forged the "no encryption"
                // answer. Refuse unless the user opted in explicitly.
                drop(session);
                connected.store(false, Ordering::Release);
                tracing::warn!(
                    support_encryption,
                    local_secure_support,
                    "config server does not support encryption; refusing an unencrypted \
                     session. If this is intentional, append '#allow-plain=1' to the \
                     config server URL"
                );
                time::sleep(RETRY_INTERVAL).await;
                continue;
            }
            SessionPlan::RefuseSecureMode => {
                drop(session);
                connected.store(false, Ordering::Release);
                tracing::warn!("secure mode requires config-server encryption support");
                time::sleep(RETRY_INTERVAL).await;
                continue;
            }
            SessionPlan::Plain => {
                if support_encryption {
                    tracing::warn!(
                        "server supports encryption but the local build is using a legacy tunnel"
                    );
                }
                warn_once_plaintext_opt_in();
            }
        }

        session.start_heartbeat().await;
        session.wait().await;
        connected.store(false, Ordering::Release);
    }
}

struct WebClientSession {
    rpc: BidirectRpcManager,
    controller: Arc<WebClientController>,
    heartbeat_started: AtomicBool,
    tasks: Mutex<JoinSet<()>>,
}

fn running_instances_for_heartbeat(
    instance_ids: Vec<uuid::Uuid>,
    failed_instance_ids: &[uuid::Uuid],
) -> Vec<uuid::Uuid> {
    let failed_instance_ids: HashSet<_> = failed_instance_ids.iter().copied().collect();
    instance_ids
        .into_iter()
        .filter(|instance_id| !failed_instance_ids.contains(instance_id))
        .collect()
}

fn build_heartbeat_request(
    config: &WebClientConfig,
    runtime_id: uuid::Uuid,
    running_network_instances: Vec<uuid::Uuid>,
    failed_network_instances: Vec<uuid::Uuid>,
) -> HeartbeatRequest {
    HeartbeatRequest {
        machine_id: Some(config.machine_id.into()),
        inst_id: Some(runtime_id.into()),
        user_token: config.token.clone(),
        easytier_version: config.easytier_version.clone(),
        hostname: config.hostname.clone(),
        report_time: chrono::Local::now().to_rfc3339(),
        device_os: Some(config.device_os.clone()),
        support_config_source: true,
        running_network_instances: running_network_instances
            .into_iter()
            .map(Into::into)
            .collect(),
        failed_network_instances: failed_network_instances
            .into_iter()
            .map(Into::into)
            .collect(),
        support_heartbeat_policy: true,
    }
}

async fn wait_for_next_heartbeat(
    backend: &dyn WebClientBackend,
    observed_generation: usize,
    policy: HeartbeatPolicy,
    elapsed: std::time::Duration,
) {
    let Some(delay) = policy.remaining_interval(elapsed) else {
        return;
    };
    tokio::select! {
        _ = time::sleep(delay) => {}
        _ = backend.wait_for_instance_state_change(observed_generation) => {}
    }
}

impl WebClientSession {
    fn new(tunnel: Box<dyn Tunnel>, controller: Arc<WebClientController>) -> Self {
        let rpc = BidirectRpcManager::new();
        rpc.run_with_tunnel(tunnel);
        controller.backend.register(rpc.rpc_server().registry());
        Self {
            rpc,
            controller,
            heartbeat_started: AtomicBool::new(false),
            tasks: Mutex::new(JoinSet::new()),
        }
    }

    pub async fn start_heartbeat(&self) {
        if self.heartbeat_started.swap(true, Ordering::AcqRel) {
            return;
        }
        let mut tasks = self.tasks.lock().await;
        Self::heartbeat_routine(&self.rpc, Arc::downgrade(&self.controller), &mut tasks);
    }

    fn heartbeat_routine(
        rpc: &BidirectRpcManager,
        controller: Weak<WebClientController>,
        tasks: &mut JoinSet<()>,
    ) {
        let controller = controller.upgrade().expect("web client controller");
        let controller = Arc::downgrade(&controller);
        let client = rpc
            .rpc_client()
            .scoped_client::<WebServerServiceClientFactory<BaseController>>(1, 1, String::new());

        tasks.spawn(async move {
            let mut heartbeat_policy = HeartbeatPolicy::default();
            loop {
                let heartbeat_started_at = std::time::Instant::now();
                let Some(controller) = controller.upgrade() else {
                    break;
                };
                let observed_generation = controller.backend.instance_state_generation();
                let failed_network_instances = controller.backend.failed_instance_ids();
                let running_network_instances = match controller.backend.instance_ids().await {
                    Ok(instance_ids) => {
                        running_instances_for_heartbeat(instance_ids, &failed_network_instances)
                    }
                    Err(error) => {
                        tracing::error!(%error, "failed to list config-server instances");
                        break;
                    }
                };
                let request = build_heartbeat_request(
                    &controller.config,
                    controller.runtime_id,
                    running_network_instances,
                    failed_network_instances,
                );

                match client
                    .heartbeat(heartbeat_policy.controller(), request)
                    .await
                {
                    Ok(response) => {
                        tracing::debug!(?response, "config-server heartbeat response");
                        let (next_policy, adjusted) = HeartbeatPolicy::from_response(&response);
                        if adjusted {
                            tracing::warn!(
                                requested_interval_ms = ?response.heartbeat_interval_ms,
                                requested_timeout_ms = ?response.heartbeat_timeout_ms,
                                applied_interval_ms = next_policy.interval.as_millis(),
                                applied_timeout_ms = next_policy.timeout_ms,
                                "config-server heartbeat policy was outside safe bounds"
                            );
                        }
                        heartbeat_policy = next_policy;
                        wait_for_next_heartbeat(
                            controller.backend.as_ref(),
                            observed_generation,
                            heartbeat_policy,
                            heartbeat_started_at.elapsed(),
                        )
                        .await;
                    }
                    Err(error) => {
                        tracing::error!(?error, "config-server heartbeat failed");
                        break;
                    }
                }
            }
        });
    }

    async fn wait_routines(&self) {
        self.tasks.lock().await.join_next().await;
        self.tasks.lock().await.abort_all();
    }

    async fn wait(&mut self) {
        tokio::select! {
            _ = self.rpc.wait() => {}
            _ = self.wait_routines() => {}
        }
    }

    async fn get_feature(
        &self,
    ) -> Result<GetFeatureResponse, easytier_proto::rpc_types::error::Error> {
        let client = self
            .rpc
            .rpc_client()
            .scoped_client::<WebServerServiceClientFactory<BaseController>>(1, 1, String::new());
        client
            .get_feature(BaseController::default(), GetFeatureRequest {})
            .await
    }
}

#[cfg(test)]
mod tests {
    use std::{
        future::pending,
        sync::atomic::{AtomicUsize, Ordering},
    };

    use async_trait::async_trait;

    use super::*;
    use crate::tunnel::ring::create_ring_tunnel_pair;

    struct StalledThenReadyDialer {
        attempts: AtomicUsize,
    }

    struct ImmediateStateChangeBackend;

    #[async_trait]
    impl WebClientBackend for ImmediateStateChangeBackend {
        fn register(&self, _registry: &ServiceRegistry) {}

        async fn instance_ids(&self) -> anyhow::Result<Vec<uuid::Uuid>> {
            Ok(Vec::new())
        }

        fn failed_instance_ids(&self) -> Vec<uuid::Uuid> {
            Vec::new()
        }

        async fn wait_for_instance_state_change(&self, generation: usize) -> usize {
            generation.wrapping_add(1)
        }
    }

    #[async_trait]
    impl TunnelDialer for StalledThenReadyDialer {
        async fn connect(&self) -> anyhow::Result<Box<dyn Tunnel>> {
            if self.attempts.fetch_add(1, Ordering::Relaxed) == 0 {
                return pending().await;
            }

            let (tunnel, _peer) = create_ring_tunnel_pair();
            Ok(tunnel)
        }

        fn remote_url(&self) -> Url {
            "ring://config-server".parse().unwrap()
        }
    }

    #[test]
    fn heartbeat_hides_failed_instances_from_the_running_list() {
        let running = uuid::Uuid::new_v4();
        let failed = uuid::Uuid::new_v4();
        let stopped_clean = uuid::Uuid::new_v4();
        let instance_ids = vec![running, failed, stopped_clean];
        let failed_instance_ids = vec![failed];

        let reported = running_instances_for_heartbeat(instance_ids.clone(), &failed_instance_ids);

        assert_eq!(reported, vec![running, stopped_clean]);
        assert!(running_instances_for_heartbeat(instance_ids, &[]).len() == 3);
    }

    #[tokio::test]
    async fn stalled_connection_attempt_times_out_and_allows_redial() {
        let connector = StalledThenReadyDialer {
            attempts: AtomicUsize::new(0),
        };

        let error = connect_config_server(&connector, std::time::Duration::from_millis(10))
            .await
            .unwrap_err();
        assert!(error.to_string().contains("connection timed out"));

        connect_config_server(&connector, std::time::Duration::from_secs(1))
            .await
            .unwrap();
        assert_eq!(connector.attempts.load(Ordering::Relaxed), 2);
    }

    #[tokio::test]
    async fn instance_state_change_interrupts_a_long_heartbeat_interval() {
        let policy = HeartbeatPolicy {
            interval: std::time::Duration::from_secs(60),
            timeout_ms: 65_000,
        };

        tokio::time::timeout(
            std::time::Duration::from_secs(1),
            wait_for_next_heartbeat(
                &ImmediateStateChangeBackend,
                0,
                policy,
                std::time::Duration::ZERO,
            ),
        )
        .await
        .expect("instance state change must wake heartbeat before its interval");
    }

    #[test]
    fn endpoint_normalizes_non_websocket_paths() {
        let endpoint =
            ConfigServerEndpoint::parse("udp://example.com/team%2Ftoken", |_| true).unwrap();
        assert_eq!(endpoint.token(), "team/token");
        assert_eq!(endpoint.connect_url().as_str(), "udp://example.com");
    }

    #[test]
    fn endpoint_rejects_token_shorthand() {
        let error = ConfigServerEndpoint::parse("team%2Ftoken", |_| true).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("failed to parse config server URL")
        );
    }

    #[test]
    fn endpoint_preserves_websocket_path_and_validates_scheme() {
        let endpoint =
            ConfigServerEndpoint::parse("wss://example.com/team", |url| url.scheme() == "wss")
                .unwrap();
        assert_eq!(endpoint.token(), "team");
        assert_eq!(endpoint.connect_url().as_str(), "wss://example.com/team");

        let error =
            ConfigServerEndpoint::parse("unknown://example.com/team", |_| false).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("unsupported config server scheme")
        );
    }

    #[test]
    fn endpoint_rejects_an_empty_token() {
        assert!(ConfigServerEndpoint::parse("udp://example.com", |_| true).is_err());
    }

    #[test]
    fn endpoint_parses_and_strips_server_noise_pin() {
        let digest = [0x33u8; 32];
        let pin = crate::tunnel::fingerprint::format_sha256_fingerprint(&digest);
        let endpoint = ConfigServerEndpoint::parse(
            &format!("udp://example.com/team#fingerprint={pin}"),
            |_| true,
        )
        .unwrap();
        assert_eq!(endpoint.server_noise_pin(), Some(digest));
        // The fragment carries connection options only; it must not leak
        // into the URL actually dialed.
        assert_eq!(endpoint.connect_url().as_str(), "udp://example.com");

        // unrelated fragment pairs and absent fragments mean no pin
        let endpoint =
            ConfigServerEndpoint::parse("udp://example.com/team#other=1", |_| true).unwrap();
        assert_eq!(endpoint.server_noise_pin(), None);
        let endpoint = ConfigServerEndpoint::parse("udp://example.com/team", |_| true).unwrap();
        assert_eq!(endpoint.server_noise_pin(), None);
    }

    #[test]
    fn endpoint_rejects_malformed_server_noise_pin() {
        // Malformed pins fail closed instead of silently disabling pinning.
        let error = ConfigServerEndpoint::parse(
            "udp://example.com/team#fingerprint=sha256:not-hex",
            |_| true,
        )
        .unwrap_err();
        assert!(
            error.to_string().contains("invalid server fingerprint"),
            "{error}"
        );
    }

    #[test]
    fn endpoint_parses_allow_plain_fragment() {
        let endpoint =
            ConfigServerEndpoint::parse("udp://example.com/team#allow-plain=1", |_| true).unwrap();
        assert!(endpoint.allow_plain());
        // The fragment carries connection options only; it must not leak
        // into the URL actually dialed.
        assert_eq!(endpoint.connect_url().as_str(), "udp://example.com");

        // absent fragments, explicit opt-out and unrelated pairs mean no opt-in
        assert!(
            !ConfigServerEndpoint::parse("udp://example.com/team", |_| true)
                .unwrap()
                .allow_plain()
        );
        assert!(
            !ConfigServerEndpoint::parse("udp://example.com/team#allow-plain=0", |_| true)
                .unwrap()
                .allow_plain()
        );
        assert!(
            !ConfigServerEndpoint::parse("udp://example.com/team#other=1", |_| true)
                .unwrap()
                .allow_plain()
        );
        // coexists with the fingerprint pin
        let digest = [0x44u8; 32];
        let pin = crate::tunnel::fingerprint::format_sha256_fingerprint(&digest);
        let endpoint = ConfigServerEndpoint::parse(
            &format!("udp://example.com/team#fingerprint={pin}&allow-plain=1"),
            |_| true,
        )
        .unwrap();
        assert!(endpoint.allow_plain());
        assert_eq!(endpoint.server_noise_pin(), Some(digest));
    }

    #[test]
    fn endpoint_rejects_malformed_allow_plain() {
        let error = ConfigServerEndpoint::parse("udp://example.com/team#allow-plain=yes", |_| true)
            .unwrap_err();
        assert!(error.to_string().contains("invalid allow-plain"), "{error}");
    }

    #[test]
    fn plaintext_sessions_require_the_explicit_opt_in() {
        // Server (or a man-in-the-middle rewriting the plaintext GetFeature
        // exchange) claims no encryption: refused by default, allowed with
        // the '#allow-plain=1' opt-in.
        assert_eq!(
            plan_session(false, false, true, None, false, false),
            SessionPlan::RefusePlaintext
        );
        assert_eq!(
            plan_session(false, false, true, None, true, false),
            SessionPlan::Plain
        );

        // The opt-in never downgrades a pinned endpoint: fail closed stays
        // fail closed even when the server claims to lack v2 or encryption.
        assert_eq!(
            plan_session(false, false, true, Some([9; 32]), true, false),
            SessionPlan::RefusePinned
        );
        assert_eq!(
            plan_session(true, false, true, Some([9; 32]), true, false),
            SessionPlan::RefusePinned
        );

        // Secure mode outranks the opt-in.
        assert_eq!(
            plan_session(false, false, true, None, true, true),
            SessionPlan::RefuseSecureMode
        );
        assert_eq!(
            plan_session(false, false, true, None, false, true),
            SessionPlan::RefuseSecureMode
        );
    }

    #[test]
    fn encrypted_paths_are_preferred_when_available() {
        assert_eq!(
            plan_session(true, true, true, None, false, true),
            SessionPlan::Secure { noise_v2: true }
        );
        // Noise v1 still encrypts: allowed with a warn, no opt-in needed.
        assert_eq!(
            plan_session(true, false, true, None, false, false),
            SessionPlan::Secure { noise_v2: false }
        );
        // Server supports encryption but the local build cannot: plaintext
        // rules apply.
        assert_eq!(
            plan_session(true, true, false, None, false, false),
            SessionPlan::RefusePlaintext
        );
    }

    #[test]
    fn heartbeat_request_carries_registered_and_failed_instance_ids() {
        let runtime_id = uuid::Uuid::new_v4();
        let registered = uuid::Uuid::new_v4();
        let failed = uuid::Uuid::new_v4();
        let request = build_heartbeat_request(
            &WebClientConfig {
                token: "token".to_owned(),
                machine_id: uuid::Uuid::new_v4(),
                hostname: "host".to_owned(),
                device_os: DeviceOsInfo::default(),
                easytier_version: "test-version".to_owned(),
                secure_mode: false,
                server_noise_pin: None,
                allow_plain: false,
            },
            runtime_id,
            vec![registered],
            vec![failed],
        );

        assert_eq!(request.inst_id.map(uuid::Uuid::from), Some(runtime_id));
        assert_eq!(
            request
                .running_network_instances
                .into_iter()
                .map(uuid::Uuid::from)
                .collect::<Vec<_>>(),
            vec![registered]
        );
        assert_eq!(
            request
                .failed_network_instances
                .into_iter()
                .map(uuid::Uuid::from)
                .collect::<Vec<_>>(),
            vec![failed]
        );
        assert!(request.support_heartbeat_policy);
    }

    #[test]
    fn heartbeat_policy_uses_safe_defaults_for_legacy_servers() {
        let (policy, adjusted) = HeartbeatPolicy::from_response(&HeartbeatResponse::default());

        assert!(!adjusted);
        assert_eq!(
            policy.interval,
            std::time::Duration::from_millis(DEFAULT_HEARTBEAT_INTERVAL_MS.into())
        );
        assert_eq!(policy.timeout_ms, DEFAULT_HEARTBEAT_TIMEOUT_MS as i32);
    }

    #[test]
    fn heartbeat_policy_clamps_server_values_and_preserves_timeout_margin() {
        let (minimum, adjusted) = HeartbeatPolicy::from_response(&HeartbeatResponse {
            heartbeat_interval_ms: Some(1),
            heartbeat_timeout_ms: Some(1),
        });
        assert!(adjusted);
        assert_eq!(
            minimum.interval,
            std::time::Duration::from_millis(MIN_HEARTBEAT_INTERVAL_MS.into())
        );
        assert_eq!(minimum.timeout_ms, 6_000);

        let (maximum, adjusted) = HeartbeatPolicy::from_response(&HeartbeatResponse {
            heartbeat_interval_ms: Some(u32::MAX),
            heartbeat_timeout_ms: Some(u32::MAX),
        });
        assert!(adjusted);
        assert_eq!(
            maximum.interval,
            std::time::Duration::from_millis(MAX_HEARTBEAT_INTERVAL_MS.into())
        );
        assert_eq!(maximum.timeout_ms, MAX_HEARTBEAT_TIMEOUT_MS as i32);

        let (margin, adjusted) = HeartbeatPolicy::from_response(&HeartbeatResponse {
            heartbeat_interval_ms: Some(60_000),
            heartbeat_timeout_ms: Some(5_000),
        });
        assert!(adjusted);
        assert_eq!(margin.timeout_ms, 65_000);
    }
}
