use std::sync::{Arc, Mutex};

use futures::{SinkExt, StreamExt};
use sha2::{Digest, Sha256};
use snow::{Builder, params::NoiseParams};
use x25519_dalek::{PublicKey, StaticSecret};

use crate::{
    foundation::time::{Duration, timeout},
    packet::{PacketType, ZCPacket, ZCPacketType},
    proto::common::TunnelInfo,
    tunnel::{
        SplitTunnel, StreamItem, Tunnel, TunnelError, ZCPacketSink, ZCPacketStream,
        filter::{TunnelFilter, TunnelWithFilter},
        fingerprint::format_sha256_fingerprint,
        secure_datagram::{SecureDatagramDirection, SecureDatagramSession},
    },
};

const NOISE_V1_MAGIC: &[u8] = b"ET_WEB_NOISE_V1:";
const NOISE_V2_MAGIC: &[u8] = b"ET_WEB_NOISE_V2:";
const NOISE_V1_PROLOGUE: &[u8] = b"easytier-webclient-noise-v1";
const NOISE_V2_PROLOGUE: &[u8] = b"easytier-webclient-noise-v2";
const NOISE_NN_PATTERN: &str = "Noise_NN_25519_ChaChaPoly_SHA256";
const NOISE_XX_PATTERN: &str = "Noise_XX_25519_ChaChaPoly_SHA256";
const WEB_SECURE_CIPHER_ALGORITHM: &str = "aes-gcm";
const WEB_SESSION_GENERATION: u32 = 1;
const WEB_INITIAL_EPOCH: u32 = 0;
const WEB_SECURE_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(3);
const WEB_SECURE_ACCEPT_TIMEOUT: Duration = WEB_SECURE_HANDSHAKE_TIMEOUT;

/// Long-lived X25519 identity of a web config server for Noise_XX handshakes.
///
/// The key is generated (or loaded) by the server host; clients pin its
/// public-key SHA-256 fingerprint via the config-server URL fragment
/// `#fingerprint=sha256:<hex>` to authenticate the server.
#[derive(Clone)]
pub struct WebNoiseStaticKey {
    secret: StaticSecret,
}

impl WebNoiseStaticKey {
    pub fn random() -> Self {
        Self {
            secret: StaticSecret::random_from_rng(rand::rngs::OsRng),
        }
    }

    pub fn from_secret_bytes(bytes: [u8; 32]) -> Self {
        Self {
            secret: StaticSecret::from(bytes),
        }
    }

    pub fn secret_bytes(&self) -> [u8; 32] {
        self.secret.to_bytes()
    }

    pub fn public_key(&self) -> [u8; 32] {
        PublicKey::from(&self.secret).to_bytes()
    }

    /// SHA-256 fingerprint of the static public key, formatted for pinning.
    pub fn public_fingerprint(&self) -> String {
        let digest: [u8; 32] = Sha256::digest(self.public_key()).into();
        format_sha256_fingerprint(&digest)
    }
}

impl std::fmt::Debug for WebNoiseStaticKey {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never leak key material through Debug; identify by public fingerprint.
        formatter
            .debug_struct("WebNoiseStaticKey")
            .field("fingerprint", &self.public_fingerprint())
            .finish()
    }
}

/// Server handshake preference: V2 (Noise_XX with an authenticated static
/// key) when a key is configured, V1 (Noise_NN) otherwise.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientHandshakeMode {
    /// Noise_XX with server authentication; `pin` is verified fail-closed.
    V2 { pin: Option<[u8; 32]> },
    /// Legacy Noise_NN, kept for servers that never learned V2.
    V1,
}

impl ClientHandshakeMode {
    /// Picks the strongest mode the server supports. A configured pin
    /// requires V2: falling back to NN would silently drop the only server
    /// authentication the user asked for.
    pub fn negotiate(pin: Option<[u8; 32]>, server_supports_v2: bool) -> Self {
        match (server_supports_v2, pin) {
            (true, pin) => Self::V2 { pin },
            (false, Some(_)) => Self::V2 { pin },
            (false, None) => Self::V1,
        }
    }
}

struct RawSplitTunnel {
    info: Option<TunnelInfo>,
    split: Mutex<Option<SplitTunnel>>,
}

impl RawSplitTunnel {
    fn new(
        info: Option<TunnelInfo>,
        stream: std::pin::Pin<Box<dyn ZCPacketStream>>,
        sink: std::pin::Pin<Box<dyn ZCPacketSink>>,
    ) -> Self {
        Self {
            info,
            split: Mutex::new(Some((stream, sink))),
        }
    }
}

impl Tunnel for RawSplitTunnel {
    fn split(&self) -> SplitTunnel {
        self.split
            .lock()
            .unwrap()
            .take()
            .expect("split can only be called once")
    }

    fn info(&self) -> Option<TunnelInfo> {
        self.info.clone()
    }
}

#[derive(Clone, Copy)]
enum SecureTunnelRole {
    Initiator,
    Responder,
}

impl SecureTunnelRole {
    fn send_dir(self) -> SecureDatagramDirection {
        match self {
            Self::Initiator => SecureDatagramDirection::AToB,
            Self::Responder => SecureDatagramDirection::BToA,
        }
    }

    fn recv_dir(self) -> SecureDatagramDirection {
        match self {
            Self::Initiator => SecureDatagramDirection::BToA,
            Self::Responder => SecureDatagramDirection::AToB,
        }
    }
}

struct SecureDatagramTunnelFilter {
    session: Arc<SecureDatagramSession>,
    role: SecureTunnelRole,
}

impl TunnelFilter for SecureDatagramTunnelFilter {
    type FilterOutput = ();

    fn before_send(&self, data: ZCPacket) -> Option<ZCPacket> {
        let mut packet = ZCPacket::new_with_payload(data.tunnel_payload());
        packet.fill_peer_manager_hdr(0, 0, PacketType::Data as u8);
        self.session
            .encrypt_payload(self.role.send_dir(), &mut packet)
            .ok()?;
        Some(packet)
    }

    fn after_received(&self, data: StreamItem) -> Option<StreamItem> {
        let mut packet = match data {
            Ok(v) => v,
            Err(e) => return Some(Err(e)),
        };

        if let Err(e) = checked_payload(&packet, "secure packet") {
            return Some(Err(e));
        }
        // Decrypt in place on the received packet: the session binds the
        // canonical header into the AAD, so the marker and header bytes the
        // sender sealed with must survive to the receiver.
        if let Err(e) = self
            .session
            .decrypt_payload(self.role.recv_dir(), &mut packet)
        {
            return Some(Err(TunnelError::InvalidPacket(format!(
                "secure datagram decrypt failed: {e}"
            ))));
        }

        let packet = ZCPacket::new_from_buf(packet.payload_bytes(), ZCPacketType::DummyTunnel);
        if packet.peer_manager_header().is_none() {
            return Some(Err(TunnelError::InvalidPacket(
                "decrypted secure packet too short".to_string(),
            )));
        }

        Some(Ok(packet))
    }

    fn filter_output(&self) {}
}

fn checked_payload<'a>(packet: &'a ZCPacket, context: &str) -> Result<&'a [u8], TunnelError> {
    if packet.peer_manager_header().is_none() {
        return Err(TunnelError::InvalidPacket(format!("{context} too short")));
    }

    Ok(packet.payload())
}

fn pack_control_packet(payload: &[u8]) -> ZCPacket {
    let mut packet = ZCPacket::new_with_payload(payload);
    packet.fill_peer_manager_hdr(0, 0, PacketType::Data as u8);
    packet
}

fn encode_magic_payload(magic: &[u8], buf: &[u8]) -> Vec<u8> {
    let mut payload = Vec::with_capacity(magic.len() + buf.len());
    payload.extend_from_slice(magic);
    payload.extend_from_slice(buf);
    payload
}

/// Noise handshake versions recognizable in the first packet's magic prefix.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NoiseVersion {
    V1,
    V2,
}

fn split_noise_magic(payload: &[u8]) -> Option<(&[u8], NoiseVersion)> {
    // V2 must be checked first if one magic could prefix the other; they
    // differ in the version digit so order does not matter today.
    if let Some(body) = payload.strip_prefix(NOISE_V2_MAGIC) {
        return Some((body, NoiseVersion::V2));
    }
    payload
        .strip_prefix(NOISE_V1_MAGIC)
        .map(|body| (body, NoiseVersion::V1))
}

fn strip_noise_magic(payload: &[u8], version: NoiseVersion) -> Option<&[u8]> {
    let magic = match version {
        NoiseVersion::V1 => NOISE_V1_MAGIC,
        NoiseVersion::V2 => NOISE_V2_MAGIC,
    };
    payload.strip_prefix(magic)
}

pub fn web_secure_tunnel_supported() -> bool {
    crate::tunnel::encrypt::algorithm_is_available(crate::config::EncryptionAlgorithm::AesGcm)
}

fn web_secure_cipher_algorithm() -> Result<&'static str, TunnelError> {
    if !web_secure_tunnel_supported() {
        return Err(TunnelError::InternalError(format!(
            "web secure tunnel requires {WEB_SECURE_CIPHER_ALGORITHM} support"
        )));
    }
    Ok(WEB_SECURE_CIPHER_ALGORITHM)
}

fn new_web_secure_session(root_key: [u8; 32], algorithm: &str) -> Arc<SecureDatagramSession> {
    let algo = algorithm.to_string();
    Arc::new(SecureDatagramSession::new(
        root_key,
        WEB_SESSION_GENERATION,
        WEB_INITIAL_EPOCH,
        algo.clone(),
        algo,
    ))
}

fn wrap_secure_tunnel(
    info: Option<TunnelInfo>,
    stream: std::pin::Pin<Box<dyn ZCPacketStream>>,
    sink: std::pin::Pin<Box<dyn ZCPacketSink>>,
    session: Arc<SecureDatagramSession>,
    role: SecureTunnelRole,
) -> Box<dyn Tunnel> {
    let raw = RawSplitTunnel::new(info, stream, sink);
    Box::new(TunnelWithFilter::new(
        raw,
        SecureDatagramTunnelFilter { session, role },
    ))
}

type SplitStream = std::pin::Pin<Box<dyn ZCPacketStream>>;
type SplitSink = std::pin::Pin<Box<dyn ZCPacketSink>>;

fn build_noise_state(
    pattern: &str,
    prologue: &[u8],
    local_private_key: Option<&[u8]>,
    initiator: bool,
) -> Result<snow::HandshakeState, TunnelError> {
    let params: NoiseParams = pattern
        .parse()
        .map_err(|e| TunnelError::InternalError(format!("parse noise params failed: {e}")))?;
    let mut builder = Builder::new(params)
        .prologue(prologue)
        .map_err(|e| TunnelError::InternalError(format!("set prologue failed: {e}")))?;
    if let Some(key) = local_private_key {
        builder = builder
            .local_private_key(key)
            .map_err(|e| TunnelError::InternalError(format!("set local key failed: {e}")))?;
    }
    if initiator {
        builder.build_initiator()
    } else {
        builder.build_responder()
    }
    .map_err(|e| TunnelError::InternalError(format!("build noise handshake failed: {e}")))
}

/// Reads the next control packet with a deadline. Error kinds (timeout,
/// shutdown, transport) are preserved for callers that match on them.
async fn read_control_packet(
    stream: &mut SplitStream,
    limit: Duration,
) -> Result<ZCPacket, TunnelError> {
    match timeout(limit, stream.next()).await {
        Ok(Some(Ok(packet))) => Ok(packet),
        Ok(Some(Err(error))) => Err(error),
        Ok(None) => Err(TunnelError::Shutdown),
        Err(error) => Err(error.into()),
    }
}

pub async fn upgrade_client_tunnel(
    tunnel: Box<dyn Tunnel>,
    mode: ClientHandshakeMode,
) -> Result<Box<dyn Tunnel>, TunnelError> {
    let web_cipher_algorithm = web_secure_cipher_algorithm()?;
    let info = tunnel.info();
    let (mut stream, mut sink) = tunnel.split();

    let root_key = match mode {
        ClientHandshakeMode::V2 { pin } => upgrade_client_v2(&mut stream, &mut sink, pin).await?,
        ClientHandshakeMode::V1 => upgrade_client_v1(&mut stream, &mut sink).await?,
    };

    Ok(wrap_secure_tunnel(
        info,
        stream,
        sink,
        new_web_secure_session(root_key, web_cipher_algorithm),
        SecureTunnelRole::Initiator,
    ))
}

/// Legacy Noise_NN upgrade: msg1 (e) -> msg2 (e,ee + root_key payload).
async fn upgrade_client_v1(
    stream: &mut SplitStream,
    sink: &mut SplitSink,
) -> Result<[u8; 32], TunnelError> {
    let mut state = build_noise_state(NOISE_NN_PATTERN, NOISE_V1_PROLOGUE, None, true)?;

    let mut msg1 = vec![0u8; 1024];
    let msg1_len = state
        .write_message(&[], &mut msg1)
        .map_err(|e| TunnelError::InternalError(format!("write noise msg1 failed: {e}")))?;
    sink.send(pack_control_packet(&encode_magic_payload(
        NOISE_V1_MAGIC,
        &msg1[..msg1_len],
    )))
    .await?;

    let msg2_packet = read_control_packet(stream, WEB_SECURE_HANDSHAKE_TIMEOUT).await?;
    let msg2_payload = checked_payload(&msg2_packet, "noise msg2 packet")?;
    let msg2_cipher = strip_noise_magic(msg2_payload, NoiseVersion::V1)
        .ok_or_else(|| TunnelError::InvalidPacket("invalid noise msg2 magic".to_string()))?;
    read_root_key_message(&mut state, msg2_cipher)
}

/// Noise_XX upgrade: msg1 (e) -> msg2 (e,ee,s,es + root_key payload) ->
/// msg3 (s,se). The server static key learned from msg2 is checked against
/// `pin`; a mismatch (or a server that cannot speak V2) fails closed.
async fn upgrade_client_v2(
    stream: &mut SplitStream,
    sink: &mut SplitSink,
    pin: Option<[u8; 32]>,
) -> Result<[u8; 32], TunnelError> {
    // Per-connection client static: the server never authenticates clients
    // by static key (that stays at the application layer), so there is no
    // identity to preserve across connections.
    let client_static = WebNoiseStaticKey::random();
    let mut state = build_noise_state(
        NOISE_XX_PATTERN,
        NOISE_V2_PROLOGUE,
        Some(&client_static.secret_bytes()),
        true,
    )?;

    let mut msg1 = vec![0u8; 1024];
    let msg1_len = state
        .write_message(&[], &mut msg1)
        .map_err(|e| TunnelError::InternalError(format!("write noise msg1 failed: {e}")))?;
    sink.send(pack_control_packet(&encode_magic_payload(
        NOISE_V2_MAGIC,
        &msg1[..msg1_len],
    )))
    .await?;

    let msg2_packet = read_control_packet(stream, WEB_SECURE_HANDSHAKE_TIMEOUT).await?;
    let msg2_payload = checked_payload(&msg2_packet, "noise msg2 packet")?;
    let msg2_cipher = strip_noise_magic(msg2_payload, NoiseVersion::V2).ok_or_else(|| {
        TunnelError::InvalidPacket(
            "server did not answer with noise v2 magic; it may not support authenticated \
             web tunnels"
                .to_string(),
        )
    })?;
    let root_key = read_root_key_message(&mut state, msg2_cipher)?;

    // Verify the pin before sending msg3: msg2 is encrypted under DH with the
    // server static, so only the holder of the pinned key could produce it.
    let remote_static: Option<[u8; 32]> = state
        .get_remote_static()
        .map(|key| Sha256::digest(key).into());
    match (pin, remote_static) {
        (Some(expected), Some(digest)) if digest == expected => {}
        (Some(expected), Some(digest)) => {
            return Err(TunnelError::InvalidPacket(format!(
                "web server static key fingerprint mismatch: expected {}, got {}",
                format_sha256_fingerprint(&expected),
                format_sha256_fingerprint(&digest),
            )));
        }
        (Some(_), None) => {
            return Err(TunnelError::InvalidPacket(
                "noise v2 server did not present a static key".to_string(),
            ));
        }
        (None, _) => {}
    }

    // Complete XX so both sides bind the full transcript; the data plane
    // still derives from the root_key carried in msg2, snow transport mode
    // is not used (mirrors V1).
    let mut msg3 = vec![0u8; 1024];
    let msg3_len = state
        .write_message(&[], &mut msg3)
        .map_err(|e| TunnelError::InternalError(format!("write noise msg3 failed: {e}")))?;
    sink.send(pack_control_packet(&encode_magic_payload(
        NOISE_V2_MAGIC,
        &msg3[..msg3_len],
    )))
    .await?;

    Ok(root_key)
}

/// Reads a noise message whose payload is exactly the 32-byte root key.
fn read_root_key_message(
    state: &mut snow::HandshakeState,
    message: &[u8],
) -> Result<[u8; 32], TunnelError> {
    let mut root_key_buf = [0u8; 32];
    let root_key_len = state
        .read_message(message, &mut root_key_buf)
        .map_err(|e| TunnelError::InvalidPacket(format!("read noise message failed: {e}")))?;
    if root_key_len != root_key_buf.len() {
        return Err(TunnelError::InvalidPacket(format!(
            "invalid web secure root key len: {root_key_len}"
        )));
    }
    Ok(root_key_buf)
}

pub async fn accept_or_upgrade_server_tunnel(
    tunnel: Box<dyn Tunnel>,
    static_key: Option<&WebNoiseStaticKey>,
) -> Result<(Box<dyn Tunnel>, bool), TunnelError> {
    let info = tunnel.info();
    let (stream, sink) = tunnel.split();
    let mut stream = stream;
    let mut sink = sink;

    let first_packet = match timeout(WEB_SECURE_ACCEPT_TIMEOUT, stream.next()).await {
        Ok(Some(Ok(packet))) => packet,
        Ok(Some(Err(error))) => return Err(error),
        Ok(None) => return Err(TunnelError::Shutdown),
        Err(_) => {
            return Ok((
                Box::new(RawSplitTunnel::new(info, stream, sink)) as Box<dyn Tunnel>,
                false,
            ));
        }
    };
    let first_payload = checked_payload(&first_packet, "first packet")?;
    let Some((msg1_cipher, version)) = split_noise_magic(first_payload) else {
        let stream = Box::pin(futures::stream::once(async move { Ok(first_packet) }).chain(stream));
        return Ok((
            Box::new(RawSplitTunnel::new(info, stream, sink)) as Box<dyn Tunnel>,
            false,
        ));
    };
    let web_cipher_algorithm = web_secure_cipher_algorithm()?;

    let root_key = match version {
        NoiseVersion::V2 => {
            let static_key = static_key.ok_or_else(|| {
                TunnelError::InternalError(
                    "noise v2 handshake requires a configured server static key".to_string(),
                )
            })?;
            accept_server_v2(&mut stream, &mut sink, static_key, msg1_cipher).await?
        }
        NoiseVersion::V1 => accept_server_v1(&mut sink, msg1_cipher).await?,
    };

    Ok((
        wrap_secure_tunnel(
            info,
            stream,
            sink,
            new_web_secure_session(root_key, web_cipher_algorithm),
            SecureTunnelRole::Responder,
        ),
        true,
    ))
}

/// Legacy Noise_NN accept: msg1 (e) -> msg2 (e,ee + root_key payload).
async fn accept_server_v1(
    sink: &mut SplitSink,
    msg1_cipher: &[u8],
) -> Result<[u8; 32], TunnelError> {
    let mut state = build_noise_state(NOISE_NN_PATTERN, NOISE_V1_PROLOGUE, None, false)?;

    let mut msg1 = vec![0u8; 1024];
    state
        .read_message(msg1_cipher, &mut msg1)
        .map_err(|e| TunnelError::InvalidPacket(format!("read noise msg1 failed: {e}")))?;

    let root_key = SecureDatagramSession::new_root_key();
    let mut msg2 = vec![0u8; 1024];
    let msg2_len = state
        .write_message(&root_key, &mut msg2)
        .map_err(|e| TunnelError::InvalidPacket(format!("write noise msg2 failed: {e}")))?;
    sink.send(pack_control_packet(&encode_magic_payload(
        NOISE_V1_MAGIC,
        &msg2[..msg2_len],
    )))
    .await?;

    Ok(root_key)
}

/// Noise_XX accept: msg1 (e) -> msg2 (e,ee,s,es + root_key payload) ->
/// msg3 (s,se). msg2 presents the server static key the client may pin;
/// msg3 is read to validate the transcript MAC before any RPC traffic.
async fn accept_server_v2(
    stream: &mut SplitStream,
    sink: &mut SplitSink,
    static_key: &WebNoiseStaticKey,
    msg1_cipher: &[u8],
) -> Result<[u8; 32], TunnelError> {
    let mut state = build_noise_state(
        NOISE_XX_PATTERN,
        NOISE_V2_PROLOGUE,
        Some(&static_key.secret_bytes()),
        false,
    )?;

    let mut msg1 = vec![0u8; 1024];
    state
        .read_message(msg1_cipher, &mut msg1)
        .map_err(|e| TunnelError::InvalidPacket(format!("read noise msg1 failed: {e}")))?;

    let root_key = SecureDatagramSession::new_root_key();
    let mut msg2 = vec![0u8; 1024];
    let msg2_len = state
        .write_message(&root_key, &mut msg2)
        .map_err(|e| TunnelError::InvalidPacket(format!("write noise msg2 failed: {e}")))?;
    sink.send(pack_control_packet(&encode_magic_payload(
        NOISE_V2_MAGIC,
        &msg2[..msg2_len],
    )))
    .await?;

    let msg3_packet = read_control_packet(stream, WEB_SECURE_ACCEPT_TIMEOUT).await?;
    let msg3_payload = checked_payload(&msg3_packet, "noise msg3 packet")?;
    let msg3_cipher = strip_noise_magic(msg3_payload, NoiseVersion::V2)
        .ok_or_else(|| TunnelError::InvalidPacket("invalid noise msg3 magic".to_string()))?;
    let mut msg3 = vec![0u8; 1024];
    state
        .read_message(msg3_cipher, &mut msg3)
        .map_err(|e| TunnelError::InvalidPacket(format!("read noise msg3 failed: {e}")))?;

    Ok(root_key)
}

#[cfg(test)]
mod tests {
    use bytes::BytesMut;

    use crate::{foundation::time::sleep, tunnel::ring::create_ring_tunnel_pair};

    use super::*;

    #[test]
    fn web_secure_cipher_algorithm_matches_support_flag() {
        let result = web_secure_cipher_algorithm();
        if web_secure_tunnel_supported() {
            assert_eq!(result.unwrap(), WEB_SECURE_CIPHER_ALGORITHM);
        } else {
            assert!(matches!(result, Err(TunnelError::InternalError(_))));
        }
    }

    #[test]
    fn web_secure_session_uses_pinned_cipher_algorithm() {
        if !web_secure_tunnel_supported() {
            return;
        }

        let session = new_web_secure_session(
            SecureDatagramSession::new_root_key(),
            web_secure_cipher_algorithm().unwrap(),
        );
        session
            .check_encrypt_algo_same(WEB_SECURE_CIPHER_ALGORITHM, WEB_SECURE_CIPHER_ALGORITHM)
            .unwrap();
    }

    #[tokio::test]
    async fn upgrade_client_tunnel_times_out_when_server_never_replies() {
        if !web_secure_tunnel_supported() {
            return;
        }

        let (server_tunnel, client_tunnel) = create_ring_tunnel_pair();
        let _server_tunnel = server_tunnel;

        let err = upgrade_client_tunnel(client_tunnel, ClientHandshakeMode::V1)
            .await
            .unwrap_err();
        assert!(matches!(err, TunnelError::Timeout(_)));
    }

    #[tokio::test]
    async fn accept_secure_tunnel_rejects_short_first_packet() {
        let (server_tunnel, client_tunnel) = create_ring_tunnel_pair();

        let server_task =
            tokio::spawn(async move { accept_or_upgrade_server_tunnel(server_tunnel, None).await });

        let (_stream, mut sink) = client_tunnel.split();
        sink.send(ZCPacket::new_from_buf(
            BytesMut::from(&b"\x01"[..]),
            ZCPacketType::TCP,
        ))
        .await
        .unwrap();

        let err = server_task.await.unwrap().unwrap_err();
        assert!(matches!(
            err,
            TunnelError::InvalidPacket(msg) if msg == "first packet too short"
        ));
    }

    #[tokio::test]
    async fn accept_secure_tunnel_after_short_client_delay() {
        if !web_secure_tunnel_supported() {
            return;
        }

        let (server_tunnel, client_tunnel) = create_ring_tunnel_pair();

        let server_task =
            tokio::spawn(async move { accept_or_upgrade_server_tunnel(server_tunnel, None).await });

        sleep(Duration::from_millis(1500)).await;

        let client_task = tokio::spawn(async move {
            upgrade_client_tunnel(client_tunnel, ClientHandshakeMode::V1).await
        });

        let (server_res, client_res) = tokio::join!(server_task, client_task);
        let (_, secure) = server_res.unwrap().unwrap();
        assert!(secure);
        assert!(client_res.unwrap().is_ok());
    }

    fn pinned_public_fingerprint(key: &WebNoiseStaticKey) -> [u8; 32] {
        Sha256::digest(key.public_key()).into()
    }

    async fn assert_tunnel_carries_data(
        client: Box<dyn Tunnel>,
        server: Box<dyn Tunnel>,
        payload: &[u8],
    ) {
        let (_c_recv, mut c_send) = client.split();
        let (mut s_recv, _s_sink) = server.split();
        c_send
            .send(ZCPacket::new_with_payload(payload))
            .await
            .unwrap();
        let packet = tokio::time::timeout(Duration::from_secs(5), s_recv.next())
            .await
            .expect("data plane packet within timeout")
            .expect("stream alive")
            .expect("decrypted packet");
        assert_eq!(packet.payload(), payload);
    }

    #[test]
    fn handshake_mode_never_downgrades_a_pin_to_v1() {
        // No pin: follow the server's advertised version.
        assert_eq!(
            ClientHandshakeMode::negotiate(None, false),
            ClientHandshakeMode::V1
        );
        assert!(matches!(
            ClientHandshakeMode::negotiate(None, true),
            ClientHandshakeMode::V2 { pin: None }
        ));
        // A pin must never end up on the unauthenticated NN path, even when
        // the server claims (or appears) to lack V2 support.
        assert!(matches!(
            ClientHandshakeMode::negotiate(Some([7; 32]), false),
            ClientHandshakeMode::V2 { pin: Some(_) }
        ));
    }

    #[tokio::test]
    async fn v2_handshake_accepts_pinned_server_and_carries_data() {
        if !web_secure_tunnel_supported() {
            return;
        }

        let (server_tunnel, client_tunnel) = create_ring_tunnel_pair();
        let server_key = WebNoiseStaticKey::random();
        let pin = pinned_public_fingerprint(&server_key);

        let key = server_key.clone();
        let server_task = tokio::spawn(async move {
            accept_or_upgrade_server_tunnel(server_tunnel, Some(&key)).await
        });
        let client =
            upgrade_client_tunnel(client_tunnel, ClientHandshakeMode::V2 { pin: Some(pin) })
                .await
                .unwrap();

        let (server, secure) = server_task.await.unwrap().unwrap();
        assert!(secure);
        assert_tunnel_carries_data(client, server, b"v2 pinned web tunnel").await;
    }

    #[tokio::test]
    async fn v2_wrong_pin_fails_closed_on_both_sides() {
        if !web_secure_tunnel_supported() {
            return;
        }

        let (server_tunnel, client_tunnel) = create_ring_tunnel_pair();
        let server_key = WebNoiseStaticKey::random();
        let mut pin = pinned_public_fingerprint(&server_key);
        pin[0] ^= 0xff;

        let key = server_key.clone();
        let server_task = tokio::spawn(async move {
            accept_or_upgrade_server_tunnel(server_tunnel, Some(&key)).await
        });
        let err = upgrade_client_tunnel(client_tunnel, ClientHandshakeMode::V2 { pin: Some(pin) })
            .await
            .unwrap_err();
        assert!(err.to_string().contains("fingerprint mismatch"), "{err}");
        // The server must not hand out a session: the pinned client aborts
        // before msg3, so the handshake times out instead of completing.
        assert!(server_task.await.unwrap().is_err());
    }

    #[tokio::test]
    async fn v1_client_interoperates_with_v2_capable_server() {
        if !web_secure_tunnel_supported() {
            return;
        }

        let (server_tunnel, client_tunnel) = create_ring_tunnel_pair();
        let server_key = WebNoiseStaticKey::random();

        let key = server_key.clone();
        let server_task = tokio::spawn(async move {
            accept_or_upgrade_server_tunnel(server_tunnel, Some(&key)).await
        });
        let client = upgrade_client_tunnel(client_tunnel, ClientHandshakeMode::V1)
            .await
            .unwrap();

        let (server, secure) = server_task.await.unwrap().unwrap();
        assert!(secure);
        assert_tunnel_carries_data(client, server, b"v1 fallback web tunnel").await;
    }

    #[tokio::test]
    async fn pinned_client_never_falls_back_to_a_v1_only_server() {
        if !web_secure_tunnel_supported() {
            return;
        }

        // A server without a static key rejects the V2 handshake outright
        // instead of downgrading it, and the pinned client never retries
        // with V1/NN, so no session is ever established.
        let (server_tunnel, client_tunnel) = create_ring_tunnel_pair();
        let server_task =
            tokio::spawn(async move { accept_or_upgrade_server_tunnel(server_tunnel, None).await });

        let err = upgrade_client_tunnel(
            client_tunnel,
            ClientHandshakeMode::V2 { pin: Some([9; 32]) },
        )
        .await
        .unwrap_err();
        // The server drops the tunnel after rejecting msg1, so the client
        // sees the stream end rather than a usable msg2.
        assert!(
            matches!(err, TunnelError::Shutdown | TunnelError::Timeout(_)),
            "{err}"
        );
        assert!(server_task.await.unwrap().is_err());
    }
}
