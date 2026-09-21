use arc_swap::ArcSwapOption;
use crossbeam::atomic::AtomicCell;
use futures::{StreamExt, TryFutureExt};
use std::{
    any::Any,
    fmt::Debug,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicU32, Ordering},
    },
};

use tokio::sync::Mutex;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use guarden::guard;
use hmac::{Hmac, Mac};
use prost::Message;
use sha2::Sha256;

use tokio::{sync::broadcast, task::JoinSet};

use tracing::Instrument;
use zerocopy::AsBytes;

use snow::{HandshakeState, params::NoiseParams};

use crate::foundation::time::{Duration, timeout};

use super::{
    peer_conn_liveness::{FEATURE as LIVENESS_ECHO_FEATURE, PeerConnLiveness},
    peer_conn_ping::PeerConnPinger,
    peer_session::{PeerSession, PeerSessionAction},
};
use crate::peers::{
    PacketRecvChan, PeerConnectionOrigin, PeerPacketIngress,
    context::{ArcPeerContext, NetworkIdentity, NetworkSecretDigest},
    send_peer_packet_to_chan,
    traffic_metrics::data_packet_payload_len,
};
use crate::{
    config::PeerId,
    packet::{PacketType, ZCPacket},
    peers::conn::peer_session::{PeerSessionStore, SessionKey, UpsertResponderSessionReturn},
    peers::error::Error,
    proto::{
        common::{SecureModeConfig, TunnelInfo},
        core_peer::peer::{PeerConnInfo, PeerConnStats},
        peer_rpc::{
            HandshakeRequest, PeerConnNoiseMsg1Pb, PeerConnNoiseMsg2Pb, PeerConnNoiseMsg3Pb,
            PeerConnSessionActionPb, PeerIdentityType, SecureAuthLevel,
        },
    },
    tunnel::{
        Tunnel, TunnelError, ZCPacketStream,
        encrypt::derive_challenge_key_argon2id,
        filter::{StatsRecorderTunnelFilter, TunnelFilter, TunnelFilterChain, TunnelWithFilter},
        mpsc::{MpscTunnel, MpscTunnelSender},
        stats::{Throughput, WindowLatency},
    },
};

pub type PeerConnId = uuid::Uuid;

const MAGIC: u32 = 0xd1e1a5e1;
const VERSION: u32 = 1;

/// Handshake feature: this node binds the canonicalized PeerManagerHeader of
/// encrypted packets into the AEAD AAD. A peer that declared it can open
/// header-bound packets; peers that did not must only receive legacy
/// (empty-AAD) packets on their direct connections.
pub const HEADER_AAD_FEATURE: &str = "header-aad-v1";

/// Handshake feature: this node derives legacy data-plane keys from the
/// network secret with argon2id (crypto-review S1.1). Packets to a peer that
/// declared it are sealed under the argon2id keys and marked
/// [`crate::packet::KDF_V2_MARKER`]; other destinations keep the v1 SipHash
/// keys.
pub const KDF_V2_FEATURE: &str = "kdf-v2";

/// Handshake feature: this node authenticates the network secret with a
/// per-connection HMAC challenge-response instead of transmitting the static
/// digest (crypto-review S1.2). When both sides declare it, the legacy
/// handshake carries fresh nonces and transcript proofs and never puts the
/// digest on the wire, so a passive eavesdropper no longer obtains an
/// equivalent password.
///
/// Residual risk (documented): an active attacker can still relay a captured
/// proof between live endpoints, and can strip the feature to force a
/// featureless peer into the old static-digest flow. Fully authenticating
/// endpoints requires secure mode's noise transcript proof.
pub const SECRET_CHALLENGE_FEATURE: &str = "secret-challenge-v1";

/// Handshake feature: `secret-challenge-v2`, the stretched-proof upgrade of
/// [`SECRET_CHALLENGE_FEATURE`] (crypto-review N2).
///
/// When both sides declare it, challenge proofs are keyed with an
/// argon2id-stretched secret ([`derive_challenge_key_argon2id`]) instead of
/// the raw network secret, so a captured proof no longer permits offline
/// dictionary attacks at plain SHA-256 speed. Falls back to v1 (then to the
/// static-digest flow) with peers that do not declare it.
pub const SECRET_CHALLENGE_V2_FEATURE: &str = "secret-challenge-v2";

/// Size of the fresh per-connection nonces and proofs, matching
/// [`NetworkSecretDigest`] and HMAC-SHA256 output.
const CHALLENGE_FIELD_LEN: usize = 32;

/// Features declared in every handshake message of this build.
fn handshake_features() -> Vec<String> {
    vec![
        LIVENESS_ECHO_FEATURE.to_owned(),
        HEADER_AAD_FEATURE.to_owned(),
        KDF_V2_FEATURE.to_owned(),
        SECRET_CHALLENGE_FEATURE.to_owned(),
        SECRET_CHALLENGE_V2_FEATURE.to_owned(),
    ]
}

/// Challenge protocol version negotiated from the handshake features: the
/// newest `secret-challenge-*` feature both sides declare (crypto-review N2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ChallengeVersion {
    /// `secret-challenge-v1`: proofs are HMAC-SHA256 keyed with the raw
    /// network secret.
    V1,
    /// `secret-challenge-v2`: proofs are HMAC-SHA256 keyed with an
    /// argon2id-stretched secret ([`derive_challenge_key_argon2id`]) over a
    /// domain-separated transcript.
    V2,
}

/// Which side of a legacy handshake a challenge proof is computed for; the
/// role tag keeps initiator and responder proofs domain-separated over the
/// same transcript.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ChallengeRole {
    Initiator,
    Responder,
}

impl ChallengeRole {
    fn tag(self) -> &'static [u8] {
        match self {
            ChallengeRole::Initiator => b":initiator",
            ChallengeRole::Responder => b":responder",
        }
    }
}

/// Canonical transcript covered by legacy handshake challenge proofs
/// (crypto-review S1.2).
///
/// Variable-length fields are length-prefixed so the concatenation is
/// unambiguous. Both nonces are covered, which makes every proof valid for
/// exactly one handshake: replaying a captured message against a fresh
/// connection fails because the fresh side contributed a new nonce.
fn challenge_transcript(
    role: ChallengeRole,
    network_name: &str,
    initiator_peer_id: PeerId,
    responder_peer_id: PeerId,
    initiator_nonce: &[u8],
    responder_nonce: &[u8],
) -> Vec<u8> {
    fn put_len_prefixed(buf: &mut Vec<u8>, bytes: &[u8]) {
        buf.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
        buf.extend_from_slice(bytes);
    }

    let mut buf = Vec::new();
    buf.extend_from_slice(b"easytier-legacy-hs-challenge-v1");
    buf.extend_from_slice(role.tag());
    put_len_prefixed(&mut buf, network_name.as_bytes());
    buf.extend_from_slice(&initiator_peer_id.to_be_bytes());
    buf.extend_from_slice(&responder_peer_id.to_be_bytes());
    put_len_prefixed(&mut buf, initiator_nonce);
    put_len_prefixed(&mut buf, responder_nonce);
    buf
}

/// Canonical encoding of one side's declared handshake feature list for
/// `secret-challenge-v2` transcripts (crypto-review N3).
///
/// Sorted and length-prefixed so the encoding is unambiguous and
/// order-independent; both sides derive the identical bytes from the feature
/// lists they saw on the wire. Every proof covers both sides' lists, so a
/// relay stripping or forging any feature bit breaks the proof of whichever
/// side received the tampered list.
pub(crate) fn canonical_features(features: &[String]) -> Vec<u8> {
    let mut sorted: Vec<&str> = features.iter().map(String::as_str).collect();
    sorted.sort_unstable();
    let mut buf = Vec::with_capacity(4 + sorted.len() * 8);
    buf.extend_from_slice(&(sorted.len() as u32).to_be_bytes());
    for feature in sorted {
        buf.extend_from_slice(&(feature.len() as u32).to_be_bytes());
        buf.extend_from_slice(feature.as_bytes());
    }
    buf
}

/// Domain-separated transcript for `secret-challenge-v2` proofs. Extends the
/// v1 fields under a distinct prefix with both sides' canonically encoded
/// feature declarations, so v1 and v2 proofs over identical handshakes are
/// unrelated (version confusion fails closed) and feature stripping is
/// authenticated (downgrade fails closed).
fn challenge_v2_transcript(
    role: ChallengeRole,
    network_name: &str,
    initiator_peer_id: PeerId,
    responder_peer_id: PeerId,
    initiator_nonce: &[u8],
    responder_nonce: &[u8],
    initiator_features: &[String],
    responder_features: &[String],
) -> Vec<u8> {
    fn put_len_prefixed(buf: &mut Vec<u8>, bytes: &[u8]) {
        buf.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
        buf.extend_from_slice(bytes);
    }

    let mut buf = Vec::new();
    buf.extend_from_slice(b"easytier-legacy-hs-challenge-v2");
    buf.extend_from_slice(role.tag());
    put_len_prefixed(&mut buf, network_name.as_bytes());
    buf.extend_from_slice(&initiator_peer_id.to_be_bytes());
    buf.extend_from_slice(&responder_peer_id.to_be_bytes());
    put_len_prefixed(&mut buf, initiator_nonce);
    put_len_prefixed(&mut buf, responder_nonce);
    put_len_prefixed(&mut buf, &canonical_features(initiator_features));
    put_len_prefixed(&mut buf, &canonical_features(responder_features));
    buf
}

/// Secret material carried by one legacy handshake message.
#[derive(Debug)]
enum HandshakeSecret {
    /// Static digest comparison, the pre-challenge protocol. `send` is false
    /// when the remote identity is unknown or foreign; the field is zeroed.
    Static { send: bool },
    /// One round of the `secret-challenge-v1` flow; the digest field is
    /// zeroed so the equivalent-password never leaves the node.
    Challenge {
        nonce: [u8; CHALLENGE_FIELD_LEN],
        proof: Option<[u8; CHALLENGE_FIELD_LEN]>,
    },
}

/// The proof of client secret.
#[derive(Debug)]
struct SecretProof {
    challenge: Vec<u8>,
    proof: Vec<u8>,
}

/// The result of noise handshake.
#[derive(Debug)]
#[allow(dead_code)]
struct NoiseHandshakeResult {
    peer_id: PeerId,
    session: Arc<PeerSession>,
    local_static_pubkey: Vec<u8>,
    remote_static_pubkey: Vec<u8>,
    secure_auth_level: SecureAuthLevel,
    peer_identity_type: PeerIdentityType,
    remote_network_name: String,

    secret_digest: Vec<u8>,

    // foreign network manager use this to verify peer.
    // the challenge will be sent to authorized peer and compare the proof against it.
    client_secret_proof: Option<SecretProof>,
    remote_features: Vec<String>,
}

#[derive(Clone)]
struct PeerSessionTunnelFilter {
    enabled: bool,
    my_peer_id: Arc<AtomicCell<PeerId>>,
    peer_id: Arc<AtomicCell<Option<PeerId>>>,
    session: Arc<ArcSwapOption<PeerSession>>,
}

impl PeerSessionTunnelFilter {
    fn new_with_peer(my_peer_id: PeerId, enabled: bool) -> Self {
        Self {
            enabled,
            my_peer_id: Arc::new(AtomicCell::new(my_peer_id)),
            peer_id: Arc::new(AtomicCell::new(None)),
            session: Arc::new(ArcSwapOption::empty()),
        }
    }

    fn set_my_peer_id(&self, my_peer_id: PeerId) {
        self.my_peer_id.store(my_peer_id);
    }

    fn set_peer_id(&self, peer_id: PeerId) {
        self.peer_id.store(Some(peer_id));
    }

    fn set_session(&self, session: Arc<PeerSession>) {
        self.session.store(Some(session));
    }

    fn should_skip_encrypt(&self, hdr: &crate::packet::PeerManagerHeader) -> bool {
        hdr.packet_type == PacketType::NoiseHandshakeMsg1 as u8
            || hdr.packet_type == PacketType::NoiseHandshakeMsg2 as u8
            || hdr.packet_type == PacketType::NoiseHandshakeMsg3 as u8
            || hdr.packet_type == PacketType::RelayHandshake as u8
            || hdr.packet_type == PacketType::RelayHandshakeAck as u8
            || hdr.packet_type == PacketType::Ping as u8
            || hdr.packet_type == PacketType::Pong as u8
    }
}

impl TunnelFilter for PeerSessionTunnelFilter {
    type FilterOutput = ();

    fn before_send(&self, mut data: crate::tunnel::SinkItem) -> Option<crate::tunnel::SinkItem> {
        if !self.enabled {
            return Some(data);
        }

        let Some(hdr) = data.peer_manager_header() else {
            return Some(data);
        };

        if self.should_skip_encrypt(hdr) {
            return Some(data);
        }

        let Some(peer_id) = self.peer_id.load() else {
            return Some(data);
        };

        let my_peer_id = self.my_peer_id.load();
        if my_peer_id != hdr.from_peer_id.get() || hdr.to_peer_id.get() != peer_id {
            return Some(data);
        }

        let session_guard = self.session.load();
        let Some(session) = session_guard.as_deref() else {
            return Some(data);
        };
        if let Err(e) = session.encrypt_payload(my_peer_id, peer_id, &mut data) {
            tracing::warn!(
                ?my_peer_id,
                ?peer_id,
                ?e,
                "PeerSessionTunnelFilter: encrypt failed, dropping packet"
            );
            return None;
        }

        Some(data)
    }

    fn after_received(&self, data: crate::tunnel::StreamItem) -> Option<crate::tunnel::StreamItem> {
        if !self.enabled {
            return Some(data);
        }

        let mut data = match data {
            Ok(v) => v,
            Err(e) => return Some(Err(e)),
        };

        let Some(hdr) = data.peer_manager_header() else {
            return Some(Ok(data));
        };

        if self.should_skip_encrypt(hdr) {
            return Some(Ok(data));
        }

        let from_peer_id = hdr.from_peer_id.get();
        if from_peer_id == 0 {
            return Some(Ok(data));
        }

        let Some(peer_id) = self.peer_id.load() else {
            return Some(Ok(data));
        };

        if from_peer_id != peer_id {
            return Some(Ok(data));
        }

        let session_guard = self.session.load();
        let Some(session) = session_guard.as_deref() else {
            return Some(Ok(data));
        };

        let my_peer_id = self.my_peer_id.load();
        if hdr.to_peer_id.get() != my_peer_id {
            return Some(Ok(data));
        }

        if let Err(e) = session.decrypt_payload(from_peer_id, my_peer_id, &mut data) {
            if !session.is_valid() {
                // Session auto-invalidated after sustained decrypt failures.
                // Close the connection to trigger reconnection with a fresh handshake.
                tracing::error!(?e, "session invalidated, closing connection");
                return Some(Err(TunnelError::InternalError(
                    "session invalidated due to sustained decrypt failures".to_string(),
                )));
            }
            // Transient failure, drop this packet but keep the connection alive.
            return None;
        }

        Some(Ok(data))
    }

    fn filter_output(&self) {}
}

pub struct PeerConnCloseNotify {
    conn_id: PeerConnId,
    sender: Arc<std::sync::Mutex<Option<broadcast::Sender<()>>>>,
}

impl PeerConnCloseNotify {
    fn new(conn_id: PeerConnId) -> Self {
        let (sender, _) = broadcast::channel(1);
        Self {
            conn_id,
            sender: Arc::new(std::sync::Mutex::new(Some(sender))),
        }
    }

    fn notify_close(&self) {
        self.sender.lock().unwrap().take();
    }

    pub async fn get_waiter(&self) -> Option<broadcast::Receiver<()>> {
        if let Some(sender) = self.sender.lock().unwrap().as_mut() {
            let receiver = sender.subscribe();
            return Some(receiver);
        }
        None
    }

    pub fn get_conn_id(&self) -> PeerConnId {
        self.conn_id
    }

    pub fn is_closed(&self) -> bool {
        self.sender.lock().unwrap().is_none()
    }
}

pub struct PeerConn {
    conn_id: PeerConnId,
    origin: PeerConnectionOrigin,

    my_peer_id: PeerId,
    peer_id_hint: Option<PeerId>,
    context: ArcPeerContext,

    secure_mode_cfg: Option<SecureModeConfig>,
    session_filter: PeerSessionTunnelFilter,
    noise_handshake_result: Option<NoiseHandshakeResult>,

    #[allow(dead_code)]
    tunnel: Arc<Mutex<Box<dyn Any + Send + 'static>>>,
    sink: MpscTunnelSender,
    recv: Mutex<Option<Pin<Box<dyn ZCPacketStream>>>>,
    tunnel_info: Option<TunnelInfo>,

    tasks: JoinSet<Result<(), TunnelError>>,

    info: Option<HandshakeRequest>,
    is_client: Option<bool>,

    // remote or local
    is_hole_punched: bool,

    close_event_notifier: Arc<PeerConnCloseNotify>,

    ctrl_resp_sender: broadcast::Sender<ZCPacket>,

    latency_stats: Arc<WindowLatency>,
    throughput: Arc<Throughput>,
    loss_rate_stats: Arc<AtomicU32>,
    liveness: PeerConnLiveness,

    peer_session_store: Arc<PeerSessionStore>,
    my_encrypt_algo: String,
}

impl Debug for PeerConn {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PeerConn")
            .field("conn_id", &self.conn_id)
            .field("my_peer_id", &self.my_peer_id)
            .field("info", &self.info)
            .finish()
    }
}

impl PeerConn {
    #[cfg(test)]
    pub(crate) fn new(
        my_peer_id: PeerId,
        context: ArcPeerContext,
        tunnel: Box<dyn Tunnel>,
        peer_session_store: Arc<PeerSessionStore>,
    ) -> Self {
        Self::new_with_peer_id_hint_and_origin(
            my_peer_id,
            context,
            tunnel,
            None,
            peer_session_store,
            PeerConnectionOrigin::Network,
        )
    }

    pub(crate) fn new_with_peer_id_hint_and_origin(
        my_peer_id: PeerId,
        context: ArcPeerContext,
        tunnel: Box<dyn Tunnel>,
        peer_id_hint: Option<PeerId>,
        peer_session_store: Arc<PeerSessionStore>,
        origin: PeerConnectionOrigin,
    ) -> Self {
        let flags = context.flags();
        let tunnel_info = tunnel.info();
        let (ctrl_sender, _ctrl_receiver) = broadcast::channel(8);

        let secure_mode_cfg = context.secure_mode();
        let session_filter = PeerSessionTunnelFilter::new_with_peer(
            my_peer_id,
            secure_mode_cfg
                .as_ref()
                .map(|cfg| cfg.enabled)
                .unwrap_or(false),
        );

        let peer_conn_tunnel_filter = StatsRecorderTunnelFilter::new();
        let throughput = peer_conn_tunnel_filter.filter_output();
        let liveness = PeerConnLiveness::new();
        let filter_chain = TunnelFilterChain::new(session_filter.clone(), peer_conn_tunnel_filter)
            .chain(liveness.clone());
        let peer_conn_tunnel = TunnelWithFilter::new(tunnel, filter_chain);
        let mut mpsc_tunnel = MpscTunnel::new(peer_conn_tunnel, Some(Duration::from_secs(7)));

        let (recv, sink) = (mpsc_tunnel.get_stream(), mpsc_tunnel.get_sink());

        let conn_id = PeerConnId::new_v4();
        let my_encrypt_algo = flags.encryption_algorithm;

        PeerConn {
            conn_id,
            origin,

            my_peer_id,
            peer_id_hint,
            context,

            secure_mode_cfg,
            session_filter,
            noise_handshake_result: None,

            tunnel: Arc::new(Mutex::new(
                Box::new(guard!([mut mpsc_tunnel] mpsc_tunnel.close()))
                    as Box<dyn Any + Send + 'static>,
            )),
            sink,
            recv: Mutex::new(Some(recv)),
            tunnel_info,

            tasks: JoinSet::new(),

            info: None,
            is_client: None,

            is_hole_punched: true,

            close_event_notifier: Arc::new(PeerConnCloseNotify::new(conn_id)),

            ctrl_resp_sender: ctrl_sender,

            latency_stats: Arc::new(WindowLatency::new(15)),
            throughput,
            loss_rate_stats: Arc::new(AtomicU32::new(0)),
            liveness,

            peer_session_store,
            my_encrypt_algo,
        }
    }

    fn get_peer_session_store(&self) -> &Arc<PeerSessionStore> {
        &self.peer_session_store
    }

    pub fn is_secure_mode_enabled(&self) -> bool {
        self.secure_mode_cfg
            .as_ref()
            .map(|cfg| cfg.enabled)
            .unwrap_or(false)
    }

    // pri, pub
    fn get_keypair(&self) -> Result<(Vec<u8>, Vec<u8>), Error> {
        let cfg = self
            .secure_mode_cfg
            .as_ref()
            .ok_or_else(|| Error::WaitRespError("secure mode config not set".to_owned()))?;
        Ok((
            cfg.private_key()?.as_bytes().to_vec(),
            cfg.public_key()?.as_bytes().to_vec(),
        ))
    }

    pub fn get_conn_id(&self) -> PeerConnId {
        self.conn_id
    }

    pub(crate) fn is_attached(&self) -> bool {
        self.origin == PeerConnectionOrigin::Attached
    }

    pub fn set_is_hole_punched(&mut self, is_hole_punched: bool) {
        self.is_hole_punched = is_hole_punched;
    }

    pub fn is_hole_punched(&self) -> bool {
        self.is_hole_punched
    }

    pub fn is_closed(&self) -> bool {
        self.close_event_notifier.is_closed()
    }

    async fn wait_handshake(&self, need_retry: &mut bool) -> Result<HandshakeRequest, Error> {
        *need_retry = false;

        let mut locked = self.recv.lock().await;
        let recv = locked.as_mut().unwrap();
        let rsp = match recv.next().await {
            Some(Ok(rsp)) => rsp,
            Some(Err(e)) => {
                return Err(Error::WaitRespError(format!(
                    "conn recv error during wait handshake response, err: {:?}",
                    e
                )));
            }
            None => {
                return Err(Error::WaitRespError(
                    "conn closed during wait handshake response".to_owned(),
                ));
            }
        };

        *need_retry = true;
        let rsp_len = rsp.buf_len() as u64;

        let Some(peer_mgr_hdr) = rsp.peer_manager_header() else {
            return Err(Error::WaitRespError(format!(
                "unexpected packet: {:?}, cannot decode peer manager hdr",
                rsp
            )));
        };

        if peer_mgr_hdr.packet_type != PacketType::HandShake as u8 {
            return Err(Error::WaitRespError(format!(
                "unexpected packet type: {:?}, packet: {:?}",
                peer_mgr_hdr.packet_type, rsp
            )));
        }

        let rsp = HandshakeRequest::decode(rsp.payload()).map_err(|e| {
            Error::WaitRespError(format!("decode handshake response error: {:?}", e))
        })?;

        if rsp.network_secret_digest.len() != std::mem::size_of::<NetworkSecretDigest>() {
            return Err(Error::WaitRespError(
                "invalid network secret digest".to_owned(),
            ));
        }

        self.record_control_rx(&rsp.network_name, rsp_len);

        Ok(rsp)
    }

    async fn wait_handshake_loop(&self) -> Result<HandshakeRequest, Error> {
        timeout(Duration::from_secs(5), async move {
            loop {
                let mut need_retry = true;
                match self.wait_handshake(&mut need_retry).await {
                    Ok(rsp) => return Ok(rsp),
                    Err(e) => {
                        tracing::warn!("wait handshake error: {:?}", e);
                        if !need_retry {
                            return Err(e);
                        }
                    }
                }
            }
        })
        .map_err(|e| Error::WaitRespError(format!("wait handshake timeout: {:?}", e)))
        .await?
    }

    async fn send_handshake(
        &self,
        secret: HandshakeSecret,
        metric_network_name: &str,
    ) -> Result<(), Error> {
        let network = self.context.network_identity();
        let mut req = HandshakeRequest {
            magic: MAGIC,
            my_peer_id: self.my_peer_id,
            version: VERSION,
            features: handshake_features(),
            network_name: network.network_name.clone(),
            ..Default::default()
        };

        let mut digest = [0u8; std::mem::size_of::<NetworkSecretDigest>()];
        match secret {
            // only send network secret digest if the network is the same
            HandshakeSecret::Static { send } => {
                if send {
                    digest.copy_from_slice(&network.secret_digest().unwrap_or_default());
                }
            }
            HandshakeSecret::Challenge { nonce, proof } => {
                req.challenge_nonce = nonce.to_vec();
                if let Some(proof) = proof {
                    req.secret_proof = proof.to_vec();
                }
                // The digest stays zeroed: it is an equivalent password and
                // must not go on the wire (crypto-review S1.2).
            }
        }
        req.network_secret_digest = digest.to_vec();

        let hs_req = req.encode_to_vec();
        let mut zc_packet = ZCPacket::new_with_payload(hs_req.as_bytes());
        zc_packet.fill_peer_manager_hdr(
            self.my_peer_id,
            PeerId::default(),
            PacketType::HandShake as u8,
        );
        let pkt_len = zc_packet.buf_len() as u64;

        self.sink.send(zc_packet).await.map_err(|e| {
            tracing::warn!("send handshake request error: {:?}", e);
            Error::WaitRespError("send handshake request error".to_owned())
        })?;
        self.record_control_tx(metric_network_name, pkt_len);

        // yield to send the response packet
        tokio::task::yield_now().await;

        Ok(())
    }

    /// Whether the local network is actually gated by a secret. Open
    /// networks keep the static-digest flow: there is nothing to hide, and
    /// the digest equality is the only admission check both sides share.
    fn local_network_has_secret(&self) -> bool {
        self.context
            .network_identity()
            .network_secret
            .as_deref()
            .is_some_and(|secret| !secret.is_empty())
    }

    /// Which challenge protocol the initiator's handshake request selects:
    /// the newest `secret-challenge-*` feature both sides declare, requiring
    /// that the request targets our network and we hold the secret it must
    /// prove. `None` keeps the static-digest flow for featureless initiators.
    fn negotiated_challenge_version(&self) -> Option<ChallengeVersion> {
        let info = self.info.as_ref()?;
        if info.network_name != self.context.network_name() || !self.local_network_has_secret() {
            return None;
        }
        if info
            .features
            .iter()
            .any(|f| f == SECRET_CHALLENGE_V2_FEATURE)
        {
            Some(ChallengeVersion::V2)
        } else if info.features.iter().any(|f| f == SECRET_CHALLENGE_FEATURE) {
            Some(ChallengeVersion::V1)
        } else {
            None
        }
    }

    /// Transcript for one challenge round under the negotiated version. The
    /// feature lists are the ones each side saw on the wire (or its own for
    /// the local side); v1 transcripts ignore them, v2 binds them.
    #[allow(clippy::too_many_arguments)]
    fn challenge_transcript_for(
        version: ChallengeVersion,
        role: ChallengeRole,
        network_name: &str,
        initiator_peer_id: PeerId,
        responder_peer_id: PeerId,
        initiator_nonce: &[u8],
        responder_nonce: &[u8],
        initiator_features: &[String],
        responder_features: &[String],
    ) -> Vec<u8> {
        match version {
            ChallengeVersion::V1 => challenge_transcript(
                role,
                network_name,
                initiator_peer_id,
                responder_peer_id,
                initiator_nonce,
                responder_nonce,
            ),
            ChallengeVersion::V2 => challenge_v2_transcript(
                role,
                network_name,
                initiator_peer_id,
                responder_peer_id,
                initiator_nonce,
                responder_nonce,
                initiator_features,
                responder_features,
            ),
        }
    }

    /// Challenge-response rounds of the responder side (crypto-review S1.2).
    ///
    /// msg2 carries our fresh nonce plus a proof over both nonces; msg3 must
    /// answer with the initiator's proof over the same transcript. On
    /// success the initiator's digest is adopted as ours — it proved
    /// knowledge of the secret, which is what the digest comparison encodes.
    async fn respond_with_challenge(&mut self, version: ChallengeVersion) -> Result<(), Error> {
        let info = self.info.as_ref().expect("handshake request is decoded");
        let initiator_peer_id = info.my_peer_id;
        let network_name = info.network_name.clone();
        // Bind the feature lists exactly as they arrived: if a relay tampered
        // with the initiator's declaration, the initiator cannot verify our
        // proof against its own list (crypto-review N3).
        let initiator_features = info.features.clone();
        let responder_features = handshake_features();
        let initiator_nonce: [u8; CHALLENGE_FIELD_LEN] =
            info.challenge_nonce.clone().try_into().map_err(|_| {
                Error::WaitRespError("challenge nonce missing or malformed".to_owned())
            })?;
        let responder_nonce: [u8; CHALLENGE_FIELD_LEN] = rand::random();

        let transcript = |role| {
            Self::challenge_transcript_for(
                version,
                role,
                &network_name,
                initiator_peer_id,
                self.my_peer_id,
                &initiator_nonce,
                &responder_nonce,
                &initiator_features,
                &responder_features,
            )
        };
        let proof = self.network_secret_proof(version, &transcript(ChallengeRole::Responder))?;

        self.send_handshake(
            HandshakeSecret::Challenge {
                nonce: responder_nonce,
                proof: Some(proof),
            },
            &network_name,
        )
        .await?;

        let msg3 = timeout(
            Duration::from_secs(5),
            self.recv_next_peer_manager_packet(Some(PacketType::HandShake)),
        )
        .await
        .map_err(|e| {
            Error::WaitRespError(format!("wait initiator challenge proof timeout: {:?}", e))
        })??;
        self.record_control_rx(&network_name, msg3.buf_len() as u64);
        let msg3 = Self::decode_handshake_packet(&msg3)?;
        let initiator_proof: [u8; CHALLENGE_FIELD_LEN] = msg3
            .secret_proof
            .try_into()
            .map_err(|_| Error::WaitRespError("initiator proof missing or malformed".to_owned()))?;
        self.verify_challenge_proof(
            version,
            &initiator_proof,
            &transcript(ChallengeRole::Initiator),
        )?;

        let local_digest = self.context.secret_digest(&self.context.network_identity());
        self.info.as_mut().unwrap().network_secret_digest = local_digest;
        Ok(())
    }

    fn network_secret_proof(
        &self,
        version: ChallengeVersion,
        transcript: &[u8],
    ) -> Result<[u8; CHALLENGE_FIELD_LEN], Error> {
        let mac = match version {
            ChallengeVersion::V1 => self.context.secret_proof(transcript).ok_or_else(|| {
                Error::WaitRespError("no network secret for challenge response".to_owned())
            })?,
            ChallengeVersion::V2 => self.challenge_v2_mac(transcript)?,
        };
        let mut proof = [0u8; CHALLENGE_FIELD_LEN];
        proof.copy_from_slice(&mac.finalize().into_bytes());
        Ok(proof)
    }

    /// v2 proof MAC keyed with the argon2id-stretched secret (crypto-review
    /// N2): never the raw secret, and cached per secret so repeated
    /// handshakes pay one argon2id per secret per process.
    fn challenge_v2_mac(&self, transcript: &[u8]) -> Result<Hmac<Sha256>, Error> {
        let secret = self
            .context
            .network_identity()
            .network_secret
            .filter(|secret| !secret.is_empty())
            .ok_or_else(|| {
                Error::WaitRespError("no network secret for challenge response".to_owned())
            })?;
        let mut mac = Hmac::<Sha256>::new_from_slice(&derive_challenge_key_argon2id(&secret))
            .map_err(|_| Error::WaitRespError("failed to init challenge proof hmac".to_owned()))?;
        mac.update(transcript);
        Ok(mac)
    }

    fn verify_challenge_proof(
        &self,
        version: ChallengeVersion,
        proof: &[u8],
        transcript: &[u8],
    ) -> Result<(), Error> {
        let mac = match version {
            ChallengeVersion::V1 => self.context.secret_proof(transcript).ok_or_else(|| {
                Error::WaitRespError("no network secret for challenge verification".to_owned())
            })?,
            ChallengeVersion::V2 => self.challenge_v2_mac(transcript)?,
        };
        mac.verify_slice(proof)
            .map_err(|_| Error::SecretKeyError("handshake challenge proof mismatch".to_owned()))
    }

    /// Challenge-response rounds of the initiator side (crypto-review S1.2).
    ///
    /// msg1 (sent by the caller) carried only a fresh nonce. Here we verify
    /// the responder's proof over both nonces, answer with our own proof, and
    /// adopt the local digest for the remote identity: the peer proved
    /// knowledge of the secret, which is what the digest comparison encodes.
    async fn finish_challenge_as_client(
        &mut self,
        rsp: HandshakeRequest,
        initiator_nonce: [u8; CHALLENGE_FIELD_LEN],
    ) -> Result<(), Error> {
        let network = self.context.network_identity();
        if rsp.network_name != network.network_name {
            // Foreign network (e.g. a shared public server): the secret never
            // applied and identity is name-based downstream; no challenge is
            // expected even from a feature-declaring responder.
            self.info = Some(rsp);
            return Ok(());
        }

        if !rsp.features.iter().any(|f| f == SECRET_CHALLENGE_FEATURE) {
            // The initiator cannot authenticate a featureless responder
            // without revealing the digest, and old responders cannot echo a
            // digest they never received. Refuse rather than downgrade.
            return Err(Error::SecretKeyError(
                "peer does not support secret-challenge-v1; refusing unauthenticated handshake, upgrade the peer".to_owned(),
            ));
        }

        // We always declare v2; use it when the responder did too, otherwise
        // fall back to v1. A relay forging the v2 feature on either side only
        // desynchronizes the versions, and the differing proof keys make the
        // mismatched proof fail verification.
        let version = if rsp
            .features
            .iter()
            .any(|f| f == SECRET_CHALLENGE_V2_FEATURE)
        {
            ChallengeVersion::V2
        } else {
            ChallengeVersion::V1
        };

        let invalid = || Error::WaitRespError("malformed challenge response".to_owned());
        let responder_nonce: [u8; CHALLENGE_FIELD_LEN] = rsp
            .challenge_nonce
            .clone()
            .try_into()
            .map_err(|_| invalid())?;
        let responder_proof: [u8; CHALLENGE_FIELD_LEN] =
            rsp.secret_proof.clone().try_into().map_err(|_| invalid())?;

        // Bind our own declaration and the responder's declaration as it
        // arrived: a relay stripping or forging either list breaks the
        // responder's proof against our recomputation (crypto-review N3).
        let initiator_features = handshake_features();
        let responder_features = rsp.features.clone();
        let transcript = |role| {
            Self::challenge_transcript_for(
                version,
                role,
                &rsp.network_name,
                self.my_peer_id,
                rsp.my_peer_id,
                &initiator_nonce,
                &responder_nonce,
                &initiator_features,
                &responder_features,
            )
        };
        // Authenticate the responder; its proof covers our fresh nonce, so a
        // replayed captured response cannot pass.
        self.verify_challenge_proof(
            version,
            &responder_proof,
            &transcript(ChallengeRole::Responder),
        )?;

        // Prove ourselves over the same transcript.
        let proof = self.network_secret_proof(version, &transcript(ChallengeRole::Initiator))?;
        self.send_handshake(
            HandshakeSecret::Challenge {
                nonce: initiator_nonce,
                proof: Some(proof),
            },
            &network.network_name,
        )
        .await?;

        let mut rsp = rsp;
        rsp.network_secret_digest = self.context.secret_digest(&network);
        self.info = Some(rsp);
        Ok(())
    }

    fn decode_handshake_packet(pkt: &ZCPacket) -> Result<HandshakeRequest, Error> {
        let Some(peer_mgr_hdr) = pkt.peer_manager_header() else {
            return Err(Error::WaitRespError(
                "unexpected packet: cannot decode peer manager hdr".to_owned(),
            ));
        };

        if peer_mgr_hdr.packet_type != PacketType::HandShake as u8 {
            return Err(Error::WaitRespError(format!(
                "unexpected packet type: {:?}",
                peer_mgr_hdr.packet_type
            )));
        }

        let rsp = HandshakeRequest::decode(pkt.payload()).map_err(|e| {
            Error::WaitRespError(format!("decode handshake response error: {:?}", e))
        })?;

        if rsp.network_secret_digest.len() != std::mem::size_of::<NetworkSecretDigest>() {
            return Err(Error::WaitRespError(
                "invalid network secret digest".to_owned(),
            ));
        }

        Ok(rsp)
    }

    async fn recv_next_peer_manager_packet(
        &self,
        expected_pkt_type: Option<PacketType>,
    ) -> Result<ZCPacket, Error> {
        let mut locked = self.recv.lock().await;
        let recv = locked.as_mut().unwrap();

        loop {
            let Some(ret) = recv.next().await else {
                return Err(Error::WaitRespError(
                    "conn closed during wait handshake response".to_owned(),
                ));
            };
            let pkt = match ret {
                Ok(v) => v,
                Err(e) => {
                    return Err(Error::WaitRespError(format!(
                        "conn recv error during wait handshake response, err: {:?}",
                        e
                    )));
                }
            };

            let Some(peer_mgr_hdr) = pkt.peer_manager_header() else {
                continue;
            };

            if expected_pkt_type.is_none()
                || peer_mgr_hdr.packet_type == *expected_pkt_type.as_ref().unwrap() as u8
            {
                return Ok(pkt);
            }
        }
    }

    fn decode_b64_32(input: &str) -> Result<Vec<u8>, Error> {
        let decoded = BASE64_STANDARD
            .decode(input)
            .map_err(|e| Error::WaitRespError(format!("base64 decode failed: {e:?}")))?;
        if decoded.len() != 32 {
            return Err(Error::WaitRespError(format!(
                "invalid key length: {}",
                decoded.len()
            )));
        }
        Ok(decoded)
    }

    fn get_pinned_remote_static_pubkey_b64(&self) -> Option<String> {
        self.context
            .pinned_remote_static_pubkey(self.tunnel_info.as_ref())
    }

    async fn send_noise_msg<Msg: prost::Message + Debug>(
        &self,
        pb: Msg,
        packet_type: PacketType,
        remote_peer_id: PeerId,
        metric_network_name: &str,
        hs: &mut snow::HandshakeState,
    ) -> Result<(), Error> {
        tracing::info!(
            "send noise msg: {:?}, packet_type: {:?}, from: {:?}, to: {:?}",
            pb,
            packet_type,
            self.my_peer_id,
            remote_peer_id
        );
        let payload = pb.encode_to_vec();
        let mut msg = vec![0u8; 4096];
        let msg_len = hs
            .write_message(&payload, &mut msg)
            .map_err(|e| Error::WaitRespError(format!("noise write msg1 failed: {e:?}")))?;
        let mut pkt = ZCPacket::new_with_payload(&msg[..msg_len]);
        pkt.fill_peer_manager_hdr(self.my_peer_id, remote_peer_id, packet_type as u8);
        let pkt_len = pkt.buf_len() as u64;
        self.sink.send(pkt).await?;
        self.record_control_tx(metric_network_name, pkt_len);
        Ok(())
    }

    /// Unified remote peer authentication verification.
    ///
    /// Auth outcome matrix (current behavior):
    ///
    /// | Client role | Server role | Typical credential condition | Client auth level | Server auth level | Client sees server type | Server sees client type |
    /// | --- | --- | --- | --- | --- | --- | --- |
    /// | Admin | Admin | same network_secret, proof verified | NetworkSecretConfirmed | NetworkSecretConfirmed | Admin | Admin |
    /// | Credential | Admin | admin key is pinned and client key is trusted | PeerVerified | PeerVerified | Admin | Credential |
    /// | Credential | Admin | client pubkey is trusted, admin key is not pinned | EncryptedUnauthenticated | PeerVerified | Admin | Credential |
    /// | Credential | Admin | client pubkey is unknown | handshake may fail | handshake reject | unknown | unknown |
    /// | Admin | SharedNode | pinned key match | PeerVerified | EncryptedUnauthenticated | SharedNode | Admin |
    /// | Admin | SharedNode | local has no pinned key requirement | EncryptedUnauthenticated | EncryptedUnauthenticated | SharedNode | Admin |
    /// | Credential | SharedNode | no pin and not trusted | EncryptedUnauthenticated | EncryptedUnauthenticated | SharedNode | Credential |
    /// | Credential | Credential | should reject | handshake reject | handshake reject | unknown | unknown |
    ///
    /// Logic (in priority order):
    /// 1. **NetworkSecretConfirmed**: proof verification succeeds
    /// 2. **PeerVerified**: pinned_pubkey matches
    /// 3. **PeerVerified**: pubkey is in trusted list
    /// 4. **EncryptedUnauthenticated**: initiator without network_secret
    /// 5. **Reject**: none of the above
    #[allow(clippy::too_many_arguments)]
    fn verify_remote_auth(
        &self,
        proof: Option<&[u8]>,
        handshake_hash: &[u8],
        remote_pubkey: &[u8],
        pinned_pubkey: Option<&[u8]>,
        has_network_secret: bool,
        is_initiator: bool,
        remote_network_name: &str,
    ) -> Result<SecureAuthLevel, Error> {
        // 1. Verify proof
        if let Some(proof) = proof
            && let Some(mac) = self.context.secret_proof(handshake_hash)
            && mac.verify_slice(proof).is_ok()
        {
            return Ok(SecureAuthLevel::NetworkSecretConfirmed);
        }

        // 2. Check pinned pubkey
        if let Some(pinned) = pinned_pubkey {
            if pinned != remote_pubkey {
                return Err(Error::WaitRespError(
                    "pinned remote static pubkey mismatch".to_owned(),
                ));
            }
            return Ok(SecureAuthLevel::PeerVerified);
        }

        // 3. Check if pubkey is in trusted list
        if self
            .context
            .is_pubkey_trusted(remote_pubkey, remote_network_name)
        {
            return Ok(SecureAuthLevel::PeerVerified);
        }

        // 4. If we are the initiator without network_secret, keep encrypted channel only.
        if is_initiator && !has_network_secret {
            return Ok(SecureAuthLevel::EncryptedUnauthenticated);
        }

        // 5. Reject
        Err(Error::WaitRespError(
            "authentication failed: invalid proof and unknown credential".to_owned(),
        ))
    }

    fn classify_remote_identity(
        &self,
        remote_network_name: &str,
        secure_auth_level: SecureAuthLevel,
        remote_role_hint_is_same_network: bool,
        remote_sent_secret_proof: bool,
        is_client: bool,
    ) -> PeerIdentityType {
        if !remote_role_hint_is_same_network || remote_network_name != self.context.network_name() {
            if is_client {
                PeerIdentityType::SharedNode
            } else if remote_sent_secret_proof {
                PeerIdentityType::Admin
            } else {
                PeerIdentityType::Credential
            }
        } else {
            if matches!(secure_auth_level, SecureAuthLevel::NetworkSecretConfirmed)
                || remote_sent_secret_proof
            {
                return PeerIdentityType::Admin;
            }

            PeerIdentityType::Credential
        }
    }

    async fn do_noise_handshake_as_client(&self) -> Result<NoiseHandshakeResult, Error> {
        let prologue = b"easytier-peerconn-noise".to_vec();

        let params: NoiseParams = "Noise_XX_25519_ChaChaPoly_SHA256"
            .parse()
            .map_err(|e| Error::WaitRespError(format!("parse noise params failed: {e:?}")))?;

        let pinned_remote_pubkey = self
            .get_pinned_remote_static_pubkey_b64()
            .map(|v| Self::decode_b64_32(&v))
            .transpose()?;

        let builder = snow::Builder::new(params);
        let (local_private_key, local_static_pubkey) = self.get_keypair()?;

        let network = self.context.network_identity();
        let a_session_generation = self
            .peer_id_hint
            .and_then(|peer_id| {
                self.get_peer_session_store()
                    .get(&SessionKey::new(network.network_name.clone(), peer_id))
            })
            .map(|s| s.session_generation());

        let a_conn_id = uuid::Uuid::new_v4();
        let msg1_pb = PeerConnNoiseMsg1Pb {
            version: VERSION,
            a_network_name: network.network_name.clone(),
            a_session_generation,
            a_conn_id: Some(a_conn_id.into()),
            client_encryption_algorithm: self.my_encrypt_algo.clone(),
            features: handshake_features(),
        };

        let mut hs = builder
            .prologue(&prologue)?
            .local_private_key(&local_private_key)?
            .build_initiator()?;

        self.send_noise_msg(
            msg1_pb,
            PacketType::NoiseHandshakeMsg1,
            PeerId::default(),
            &network.network_name,
            &mut hs,
        )
        .await?;

        let server_handshake_hash = hs.get_handshake_hash().to_vec();

        let msg2 = timeout(
            Duration::from_secs(5),
            self.recv_next_peer_manager_packet(Some(PacketType::NoiseHandshakeMsg2)),
        )
        .await??;
        self.record_control_rx(&network.network_name, msg2.buf_len() as u64);
        let remote_peer_id = msg2.get_src_peer_id().expect("missing src peer id");
        if let Some(hint) = self.peer_id_hint
            && hint != remote_peer_id
        {
            return Err(Error::WaitRespError("peer_id mismatch".to_owned()));
        }
        let msg2_pb = Self::decode_handshake_message::<PeerConnNoiseMsg2Pb>(
            PacketType::NoiseHandshakeMsg2,
            Some(&mut hs),
            msg2,
        )?;
        if msg2_pb.a_conn_id_echo != Some(a_conn_id.into()) {
            return Err(Error::WaitRespError(
                "noise msg2 conn_id_echo mismatch".to_owned(),
            ));
        }
        let action = PeerConnSessionActionPb::try_from(msg2_pb.action)
            .map_err(|_| Error::WaitRespError("invalid session action".to_owned()))?;
        let remote_network_name = msg2_pb.b_network_name.clone();
        let remote_sent_secret_proof = msg2_pb.secret_proof_32.is_some();

        if remote_network_name == network.network_name && msg2_pb.role_hint != 1 {
            return Err(Error::WaitRespError(
                "role_hint must be 1 when network_name is same".to_owned(),
            ));
        }

        let handshake_hash_for_proof = hs.get_handshake_hash().to_vec();
        let secret_proof_32 = self
            .context
            .secret_proof(&handshake_hash_for_proof)
            .map(|mac| mac.finalize().into_bytes().to_vec());

        let secret_digest = self.context.secret_digest(&network);

        let msg3_pb = PeerConnNoiseMsg3Pb {
            a_conn_id_echo: Some(a_conn_id.into()),
            b_conn_id_echo: msg2_pb.b_conn_id,
            secret_proof_32,
            secret_digest: secret_digest.clone(),
        };
        self.send_noise_msg(
            msg3_pb,
            PacketType::NoiseHandshakeMsg3,
            remote_peer_id,
            &network.network_name,
            &mut hs,
        )
        .await?;

        let remote_static = hs
            .get_remote_static()
            .map(|x: &[u8]| x.to_vec())
            .unwrap_or_default();
        let remote_static_key = if remote_static.len() == 32 {
            let mut key = [0u8; 32];
            key.copy_from_slice(&remote_static);
            Some(key)
        } else {
            None
        };

        // Verify server authentication using unified logic
        let secure_auth_level = if msg2_pb.role_hint != 1 && pinned_remote_pubkey.is_none() {
            SecureAuthLevel::EncryptedUnauthenticated
        } else {
            self.verify_remote_auth(
                msg2_pb.secret_proof_32.as_deref(),
                &server_handshake_hash,
                &remote_static,
                pinned_remote_pubkey.as_deref(),
                network.network_secret.is_some(),
                true, // is_initiator
                &remote_network_name,
            )?
        };
        let peer_identity_type = self.classify_remote_identity(
            &remote_network_name,
            secure_auth_level,
            msg2_pb.role_hint == 1,
            remote_sent_secret_proof,
            true,
        );

        let algo = self.context.flags().encryption_algorithm.clone();
        let root_key = msg2_pb
            .root_key_32
            .as_deref()
            .filter(|v| v.len() == 32)
            .map(|v| {
                let mut key = [0u8; 32];
                key.copy_from_slice(v);
                key
            });
        let session_action = match action {
            PeerConnSessionActionPb::Join => PeerSessionAction::Join,
            PeerConnSessionActionPb::Sync => PeerSessionAction::Sync,
            PeerConnSessionActionPb::Create => PeerSessionAction::Create,
        };
        let session = self.get_peer_session_store().apply_initiator_action(
            &SessionKey::new(network.network_name.clone(), remote_peer_id),
            session_action,
            msg2_pb.b_session_generation,
            root_key,
            msg2_pb.initial_epoch,
            algo,
            msg2_pb.server_encryption_algorithm.clone(),
            remote_static_key,
        )?;

        Ok(NoiseHandshakeResult {
            peer_id: remote_peer_id,
            session,
            local_static_pubkey: local_static_pubkey.to_vec(),
            remote_static_pubkey: remote_static,
            secure_auth_level,
            peer_identity_type,
            remote_network_name,
            // we have authorized the peer with noise handshake, so just set secret digest same as us even remote is a shared node.
            secret_digest,
            client_secret_proof: None,
            remote_features: msg2_pb.features,
        })
    }

    fn decode_handshake_message<MsgT>(
        expected_pkt_type: PacketType,
        hs: Option<&mut HandshakeState>,
        pkt: ZCPacket,
    ) -> Result<MsgT, Error>
    where
        MsgT: prost::Message + Default,
    {
        tracing::info!(
            "decode_handshake_message: {:?}, expected_pkt_type: {:?}",
            pkt,
            expected_pkt_type
        );
        let Some(hdr) = pkt.peer_manager_header() else {
            return Err(Error::WaitRespError(
                "packet without peer manager header".to_owned(),
            ));
        };

        if hdr.packet_type != expected_pkt_type as u8 {
            return Err(Error::WaitRespError(format!(
                "packet type not {:?}",
                expected_pkt_type
            )));
        }

        let msg = match hs {
            Some(hs) => {
                let mut out = vec![0u8; 4096];
                let out_len = hs
                    .read_message(pkt.payload(), &mut out)
                    .map_err(|e| Error::WaitRespError(format!("noise read msg failed: {e:?}")))?;
                MsgT::decode(&out[..out_len])
                    .map_err(|e| Error::WaitRespError(format!("decode message failed: {e:?}")))?
            }
            None => MsgT::decode(pkt.payload())
                .map_err(|e| Error::WaitRespError(format!("decode message failed: {e:?}")))?,
        };

        Ok(msg)
    }

    async fn do_noise_handshake_as_server<Fn>(
        &mut self,
        first_msg1: ZCPacket,
        mut handshake_recved: Fn,
    ) -> Result<NoiseHandshakeResult, Error>
    where
        Fn: FnMut(&mut PeerConn, &str) -> Result<(), Error> + Send,
    {
        let prologue = b"easytier-peerconn-noise".to_vec();

        let params: NoiseParams = "Noise_XX_25519_ChaChaPoly_SHA256"
            .parse()
            .map_err(|e| Error::WaitRespError(format!("parse noise params failed: {e:?}")))?;
        let builder = snow::Builder::new(params);

        let (local_static_private_key, local_static_pubkey) = self.get_keypair()?;

        let mut hs = builder
            .prologue(&prologue)?
            .local_private_key(&local_static_private_key)?
            .build_responder()?;

        let remote_peer_id = first_msg1
            .get_src_peer_id()
            .expect("msg1 must have src peer id");
        let first_msg1_len = first_msg1.buf_len() as u64;

        let msg1_pb = Self::decode_handshake_message::<PeerConnNoiseMsg1Pb>(
            PacketType::NoiseHandshakeMsg1,
            Some(&mut hs),
            first_msg1,
        )?;
        let remote_network_name = msg1_pb.a_network_name.clone();
        self.record_control_rx(&remote_network_name, first_msg1_len);

        // this may update my peer id
        handshake_recved(self, &remote_network_name)?;

        let server_network_name = self.context.network_name();
        let (role_hint, secret_proof_32) = if msg1_pb.a_network_name == server_network_name {
            (
                1,
                self.context
                    .secret_proof(hs.get_handshake_hash())
                    .map(|m| m.finalize().into_bytes().to_vec()),
            )
        } else {
            (2, None)
        };

        let algo = self.context.flags().encryption_algorithm.clone();
        let UpsertResponderSessionReturn {
            session,
            action,
            session_generation: b_session_generation,
            root_key: root_key_32,
            initial_epoch,
        } = self.get_peer_session_store().upsert_responder_session(
            &SessionKey::new(remote_network_name.clone(), remote_peer_id),
            msg1_pb.a_session_generation,
            algo.clone(),
            msg1_pb.client_encryption_algorithm.clone(),
            None,
        )?;

        let b_conn_id = uuid::Uuid::new_v4();
        let msg2_pb = PeerConnNoiseMsg2Pb {
            b_network_name: server_network_name,
            role_hint,
            action: match action {
                PeerSessionAction::Join => PeerConnSessionActionPb::Join as i32,
                PeerSessionAction::Sync => PeerConnSessionActionPb::Sync as i32,
                PeerSessionAction::Create => PeerConnSessionActionPb::Create as i32,
            },
            b_session_generation,
            root_key_32: root_key_32.map(|k| k.to_vec()),
            initial_epoch,
            b_conn_id: Some(b_conn_id.into()),
            a_conn_id_echo: msg1_pb.a_conn_id,
            secret_proof_32,
            server_encryption_algorithm: algo,
            features: handshake_features(),
        };
        self.send_noise_msg(
            msg2_pb,
            PacketType::NoiseHandshakeMsg2,
            remote_peer_id,
            &remote_network_name,
            &mut hs,
        )
        .await?;

        let handshake_hash_for_proof = hs.get_handshake_hash().to_vec();

        let msg3_pkt = timeout(
            Duration::from_secs(5),
            self.recv_next_peer_manager_packet(Some(PacketType::NoiseHandshakeMsg3)),
        )
        .await??;
        self.record_control_rx(&remote_network_name, msg3_pkt.buf_len() as u64);
        let msg3_pb = Self::decode_handshake_message::<PeerConnNoiseMsg3Pb>(
            PacketType::NoiseHandshakeMsg3,
            Some(&mut hs),
            msg3_pkt,
        )?;

        if msg3_pb.a_conn_id_echo != msg1_pb.a_conn_id {
            return Err(Error::WaitRespError(
                "noise msg3 a_conn_id mismatch".to_owned(),
            ));
        }
        if msg3_pb.b_conn_id_echo != Some(b_conn_id.into()) {
            return Err(Error::WaitRespError(
                "noise msg3 b_conn_id mismatch".to_owned(),
            ));
        }

        let remote_static = hs
            .get_remote_static()
            .map(|x: &[u8]| x.to_vec())
            .unwrap_or_default();
        let remote_static_key = if remote_static.len() == 32 {
            let mut key = [0u8; 32];
            key.copy_from_slice(&remote_static);
            Some(key)
        } else {
            None
        };
        session.check_or_set_peer_static_pubkey(remote_static_key)?;

        // Verify client authentication using unified logic
        // Note: Server doesn't use pinned_pubkey since it's the responder
        let secure_auth_level = if role_hint == 1 {
            self.verify_remote_auth(
                msg3_pb.secret_proof_32.as_deref(),
                &handshake_hash_for_proof,
                &remote_static,
                None, // Server doesn't have pinned_remote_pubkey
                self.context.network_identity().network_secret.is_some(),
                false, // is_initiator
                &remote_network_name,
            )?
        } else {
            SecureAuthLevel::EncryptedUnauthenticated
        };
        let peer_identity_type = self.classify_remote_identity(
            &remote_network_name,
            secure_auth_level,
            role_hint == 1,
            msg3_pb.secret_proof_32.is_some(),
            false,
        );

        Ok(NoiseHandshakeResult {
            peer_id: remote_peer_id,
            session,
            local_static_pubkey: local_static_pubkey.to_vec(),
            remote_static_pubkey: remote_static,
            secure_auth_level,
            peer_identity_type,
            remote_network_name,
            secret_digest: msg3_pb.secret_digest,
            client_secret_proof: msg3_pb.secret_proof_32.as_ref().map(|p| SecretProof {
                challenge: handshake_hash_for_proof,
                proof: p.clone(),
            }),
            remote_features: msg1_pb.features,
        })
    }

    fn build_handshake_rsp(&self, noise: &NoiseHandshakeResult) -> HandshakeRequest {
        tracing::info!("build_handshake_rsp: {:?}", noise);
        HandshakeRequest {
            magic: MAGIC,
            my_peer_id: noise.peer_id,
            version: VERSION,
            network_name: noise.remote_network_name.clone(),

            features: noise.remote_features.clone(),
            network_secret_digest: noise.secret_digest.clone(),
            ..Default::default()
        }
    }

    #[tracing::instrument(skip(handshake_recved))]
    pub async fn do_handshake_as_server_ext<Fn>(
        &mut self,
        mut handshake_recved: Fn,
    ) -> Result<(), Error>
    where
        Fn: FnMut(&mut PeerConn, &str) -> Result<(), Error> + Send,
    {
        let first_pkt = timeout(
            Duration::from_secs(5),
            self.recv_next_peer_manager_packet(None),
        )
        .await??;
        let Some(hdr) = first_pkt.peer_manager_header() else {
            return Err(Error::WaitRespError(
                "first packet must have peer manager header".to_owned(),
            ));
        };

        if self.is_secure_mode_enabled() && hdr.packet_type == PacketType::NoiseHandshakeMsg1 as u8
        {
            let noise = self
                .do_noise_handshake_as_server(first_pkt, handshake_recved)
                .await?;
            // construct handshake rsp from noise result for compat.
            let handshake_rsp = self.build_handshake_rsp(&noise);
            self.session_filter.set_session(noise.session.clone());
            self.session_filter.set_peer_id(noise.peer_id);
            self.noise_handshake_result = Some(noise);

            self.info = Some(handshake_rsp);
            self.is_client = Some(false);
        } else if hdr.packet_type == PacketType::HandShake as u8 {
            let rsp = Self::decode_handshake_packet(&first_pkt)?;
            handshake_recved(self, &rsp.network_name)?;
            tracing::info!("handshake request: {:?}", rsp);
            self.record_control_rx(&rsp.network_name, first_pkt.buf_len() as u64);
            self.info = Some(rsp);
            self.is_client = Some(false);

            if let Some(version) = self.negotiated_challenge_version() {
                self.respond_with_challenge(version).await?;
            } else {
                let send_digest = self.get_network_identity() == self.context.network_identity();
                self.send_handshake(
                    HandshakeSecret::Static { send: send_digest },
                    &self.get_network_identity().network_name,
                )
                .await?;
            }
        } else {
            return Err(Error::WaitRespError(format!(
                "unexpected packet type during handshake: {}",
                hdr.packet_type
            )));
        }

        self.liveness
            .set_remote_features(&self.info.as_ref().unwrap().features);

        if self.get_peer_id() == self.my_peer_id {
            Err(Error::WaitRespError("peer id conflict".to_owned()))
        } else {
            Ok(())
        }
    }

    #[tracing::instrument]
    pub async fn do_handshake_as_client(&mut self) -> Result<(), Error> {
        if self.is_secure_mode_enabled() {
            let noise = self.do_noise_handshake_as_client().await?;
            self.session_filter.set_session(noise.session.clone());
            self.session_filter.set_peer_id(noise.peer_id);

            let handshake_rsp = self.build_handshake_rsp(&noise);
            self.noise_handshake_result = Some(noise);
            self.info = Some(handshake_rsp);
            self.is_client = Some(true);
        } else {
            let network = self.context.network_identity();
            // Challenge the responder when the network is secret-gated; open
            // networks keep the static-digest flow for interop.
            let use_challenge = self.local_network_has_secret();
            let initiator_nonce: [u8; CHALLENGE_FIELD_LEN] = rand::random();
            let secret = if use_challenge {
                HandshakeSecret::Challenge {
                    nonce: initiator_nonce,
                    proof: None,
                }
            } else {
                HandshakeSecret::Static { send: true }
            };
            self.send_handshake(secret, &network.network_name).await?;
            tracing::info!("waiting for handshake request from server");
            let rsp = self.wait_handshake_loop().await?;
            tracing::info!("handshake response: {:?}", rsp);
            if use_challenge {
                self.finish_challenge_as_client(rsp, initiator_nonce)
                    .await?;
            } else {
                self.info = Some(rsp);
            }
            self.is_client = Some(true);
        }

        self.liveness
            .set_remote_features(&self.info.as_ref().unwrap().features);

        if self.get_peer_id() == self.my_peer_id {
            Err(Error::WaitRespError(
                "peer id conflict, are you connecting to yourself?".to_owned(),
            ))
        } else {
            Ok(())
        }
    }

    fn record_control_tx(&self, network_name: &str, bytes: u64) {
        self.context.record_control_tx(network_name, bytes);
    }

    fn record_control_rx(&self, network_name: &str, bytes: u64) {
        self.context.record_control_rx(network_name, bytes);
    }

    pub async fn start_recv_loop(&mut self, packet_recv_chan: PacketRecvChan) {
        let mut stream = self.recv.lock().await.take().unwrap();
        let sink = self.sink.clone();
        let sender = packet_recv_chan.clone();
        let close_event_notifier = self.close_event_notifier.clone();
        let ctrl_sender = self.ctrl_resp_sender.clone();
        let conn_info_for_instrument = self.get_conn_info();
        let context = self.context.clone();
        let ingress = PeerPacketIngress::Peer {
            peer_id: self.get_peer_id(),
            conn_id: self.conn_id,
            origin: self.origin,
        };
        let control_network_name = conn_info_for_instrument.network_name.clone();

        let is_foreign_network =
            conn_info_for_instrument.network_name != self.context.network_identity().network_name;
        let recv_limiter = self
            .context
            .recv_limiter(&conn_info_for_instrument.network_name, is_foreign_network);

        self.tasks.spawn(
            async move {
                tracing::info!("start recving peer conn packet");
                let mut task_ret = Ok(());
                while let Some(ret) = stream.next().await {
                    if ret.is_err() {
                        tracing::error!(error = ?ret, "peer conn recv error");
                        task_ret = Err(ret.err().unwrap());
                        break;
                    }

                    let mut zc_packet = ret.unwrap();
                    let buf_len = zc_packet.buf_len() as u64;
                    let limited_payload_len = data_packet_payload_len(&zc_packet);
                    let Some(peer_mgr_hdr) = zc_packet.mut_peer_manager_header() else {
                        tracing::error!(
                            "unexpected packet: {:?}, cannot decode peer manager hdr",
                            zc_packet
                        );
                        break;
                    };

                    if peer_mgr_hdr.packet_type == PacketType::Ping as u8 {
                        context.record_control_rx(&control_network_name, buf_len);
                        peer_mgr_hdr.packet_type = PacketType::Pong as u8;
                        if let Err(e) = sink.send(zc_packet).await {
                            tracing::error!(?e, "peer conn send req error");
                        } else {
                            context.record_control_tx(&control_network_name, buf_len);
                        }
                    } else if peer_mgr_hdr.packet_type == PacketType::Pong as u8 {
                        context.record_control_rx(&control_network_name, buf_len);
                        if let Err(e) = ctrl_sender.send(zc_packet) {
                            tracing::error!(?e, "peer conn send ctrl resp error");
                        }
                    } else if send_peer_packet_to_chan(&sender, zc_packet, ingress)
                        .await
                        .is_err()
                    {
                        break;
                    }

                    if let Some(payload_len) = limited_payload_len
                        && let Some(limiter) = recv_limiter.as_ref()
                    {
                        limiter.consume(payload_len).await;
                    }
                }

                tracing::info!("end recving peer conn packet");

                drop(sink);
                close_event_notifier.notify_close();

                task_ret
            }
            .instrument(
                tracing::info_span!("peer conn recv loop", conn_info = ?conn_info_for_instrument),
            ),
        );
    }

    pub fn start_pingpong(&mut self) {
        let mut pingpong = PeerConnPinger::new(
            self.my_peer_id,
            self.get_peer_id(),
            self.sink.clone(),
            self.ctrl_resp_sender.clone(),
            self.latency_stats.clone(),
            self.loss_rate_stats.clone(),
            self.throughput.clone(),
            self.context.clone(),
            self.get_conn_info().network_name,
            self.liveness.clone(),
        );

        let close_event_notifier = self.close_event_notifier.clone();

        self.tasks.spawn(async move {
            pingpong.pingpong().await;

            tracing::warn!(?pingpong, "pingpong task exit");

            close_event_notifier.notify_close();

            Ok(())
        });
    }

    pub async fn send_msg(&self, msg: ZCPacket) -> Result<(), Error> {
        Ok(self.sink.send(msg).await?)
    }

    pub fn get_peer_id(&self) -> PeerId {
        self.info.as_ref().unwrap().my_peer_id
    }

    pub fn get_network_identity(&self) -> NetworkIdentity {
        let info = self.info.as_ref().unwrap();
        let mut ret = NetworkIdentity {
            network_name: info.network_name.clone(),
            network_secret: None,
            network_secret_digest: Some([0u8; 32]),
        };
        ret.network_secret_digest
            .as_mut()
            .unwrap()
            .copy_from_slice(&info.network_secret_digest);
        ret
    }

    fn network_secret_digest_is_empty(network: &NetworkIdentity) -> bool {
        network
            .secret_digest()
            .as_ref()
            .is_none_or(|digest| digest.iter().all(|byte| *byte == 0))
    }

    fn matches_local_secret_proof(&self) -> bool {
        let Some(secret_proof) = self
            .noise_handshake_result
            .as_ref()
            .and_then(|noise| noise.client_secret_proof.as_ref())
        else {
            return false;
        };

        self.context
            .secret_proof(&secret_proof.challenge)
            .is_some_and(|mac| mac.verify_slice(&secret_proof.proof).is_ok())
    }

    pub fn matches_local_network_secret(&self) -> bool {
        if self.matches_local_secret_proof() {
            return true;
        }

        let my_identity = self.context.network_identity();
        let peer_identity = self.get_network_identity();

        !Self::network_secret_digest_is_empty(&my_identity)
            && !Self::network_secret_digest_is_empty(&peer_identity)
            && my_identity.secret_digest() == peer_identity.secret_digest()
    }

    pub fn get_close_notifier(&self) -> Arc<PeerConnCloseNotify> {
        self.close_event_notifier.clone()
    }

    /// True when the remote's handshake declared [`HEADER_AAD_FEATURE`], i.e.
    /// it can decrypt packets whose header is bound into the AEAD AAD.
    pub fn supports_header_aad(&self) -> bool {
        self.remote_supports(HEADER_AAD_FEATURE)
    }

    /// True when the remote's handshake declared [`KDF_V2_FEATURE`], i.e. it
    /// derives its legacy data-plane keys with argon2id and can open
    /// [`crate::packet::KDF_V2_MARKER`]-marked packets.
    pub fn supports_kdf_v2(&self) -> bool {
        self.remote_supports(KDF_V2_FEATURE)
    }

    fn remote_supports(&self, feature: &str) -> bool {
        self.info
            .as_ref()
            .is_some_and(|info| info.features.iter().any(|f| f == feature))
    }

    pub fn get_stats(&self) -> PeerConnStats {
        PeerConnStats {
            latency_us: self.latency_stats.get_latency_us(),

            tx_bytes: self.throughput.tx_bytes(),
            rx_bytes: self.throughput.rx_bytes(),

            tx_packets: self.throughput.tx_packets(),
            rx_packets: self.throughput.rx_packets(),
        }
    }

    pub fn get_conn_info(&self) -> PeerConnInfo {
        let info = self.info.as_ref().unwrap();
        PeerConnInfo {
            conn_id: self.conn_id.to_string(),
            my_peer_id: self.my_peer_id,
            peer_id: self.get_peer_id(),
            features: info.features.clone(),
            tunnel: self.tunnel_info.clone(),
            stats: Some(self.get_stats()),
            loss_rate: (f64::from(self.loss_rate_stats.load(Ordering::Relaxed)) / 100.0) as f32,
            is_client: self.is_client.unwrap_or_default(),
            network_name: info.network_name.clone(),
            is_closed: self.close_event_notifier.is_closed(),
            noise_local_static_pubkey: self
                .noise_handshake_result
                .as_ref()
                .map(|x| x.local_static_pubkey.clone())
                .unwrap_or_default(),
            noise_remote_static_pubkey: self
                .noise_handshake_result
                .as_ref()
                .map(|x| x.remote_static_pubkey.clone())
                .unwrap_or_default(),
            secure_auth_level: self
                .noise_handshake_result
                .as_ref()
                .map(|x| x.secure_auth_level as i32)
                .unwrap_or_default(),
            peer_identity_type: self
                .noise_handshake_result
                .as_ref()
                .map(|x| x.peer_identity_type as i32)
                .unwrap_or(PeerIdentityType::Admin as i32),
        }
    }

    pub fn get_peer_identity_type(&self) -> PeerIdentityType {
        self.noise_handshake_result
            .as_ref()
            .map(|x| x.peer_identity_type)
            .unwrap_or(PeerIdentityType::Admin)
    }

    pub fn set_peer_id(&mut self, peer_id: PeerId) {
        if self.info.is_some() {
            panic!("set_peer_id should only be called before handshake");
        }
        self.my_peer_id = peer_id;
        self.session_filter.set_my_peer_id(peer_id);
    }

    pub fn get_my_peer_id(&self) -> PeerId {
        self.my_peer_id
    }
}

impl Drop for PeerConn {
    fn drop(&mut self) {
        // if someone drop a conn manually, the notifier is not called.
        self.close_event_notifier.notify_close();
    }
}
