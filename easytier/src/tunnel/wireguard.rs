use std::{
    fmt::{Debug, Formatter},
    net::SocketAddr,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use quanta::Instant;

use super::FromUrl;
use crate::{
    common::{netns::NetNS, shrink_dashmap},
    proto::common::TunnelInfo,
    socket::udp::{RuntimeUdpSessionSocketListener, new_runtime_udp_session_listener},
    tunnel::{TunnelUrl, build_url_from_socket_addr},
};
use anyhow::Context;
use async_recursion::async_recursion;
use async_trait::async_trait;
use boringtun::{
    noise::{Tunn, TunnResult, errors::WireGuardError},
    x25519::{PublicKey, StaticSecret},
};
use bytes::BytesMut;
use crossbeam::atomic::AtomicCell;
use dashmap::DashMap;
use easytier_core::tunnel::ring::create_ring_tunnel_pair;
use easytier_core::tunnel::{
    IpVersion, Tunnel, TunnelError, ZCPacketSink, ZCPacketStream, derive_domain_key_argon2id,
};
use easytier_core::{
    connectivity::transport::ConnectedUdpSession,
    packet::{PEER_MANAGER_HEADER_SIZE, WG_TUNNEL_HEADER_SIZE, ZCPacket, ZCPacketType},
    socket::udp::{
        UdpBindOptions, UdpSession, UdpSessionAcceptKind, UdpSessionListenRequest,
        UdpSessionProtocol, UdpSessionSocket,
    },
    tunnel::wrapper::TunnelWrapper,
};
use futures::{SinkExt, StreamExt};
use rand::RngCore;
use tokio::{
    sync::{Mutex, mpsc::unbounded_channel},
    task::JoinSet,
};

const MAX_PACKET: usize = 2048;

/// Salt domain of the wg:// tunnel static keys (crypto-review S1.1).
/// Independent of every other argon2id domain (data plane
/// `easytier-kdf-v2`, challenge `easytier-kdf-v2-challenge`), so keys of one
/// domain can never be replayed in another.
const WG_TUNNEL_ARGON2_SALT: &[u8] = b"easytier-wireguard-tunnel-v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WgType {
    InternalUse,
    ExternalUse,
}

/// Which end of a wg:// connection a [`WgConfig`] keys (crypto-review S1.1).
///
/// The tunnel derives one 64-byte argon2id tag from the network identity and
/// splits it into a dialer half and a listener half, so the two ends of a
/// connection hold different WireGuard static keys. This removes the legacy
/// single-key shape where both ends shared one static key and the identity of
/// the whole network degenerated to that key. Either side may still
/// (re)initiate handshakes: boringtun's Noise IK is symmetric once each side
/// holds (own static, peer public).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WgRole {
    /// Outgoing connections (client adapter, [`upgrade_connected`]): holds
    /// the first half of the derived tag.
    Dialer,
    /// Accepted connections (server adapter, [`upgrade_accepted`]): holds
    /// the second half of the derived tag.
    Listener,
}

/// Keys of the retired SipHash derivation, under which both ends shared one
/// static key. Argon2id configs keep them to deterministically recognize
/// pre-upgrade peers ([`is_legacy_handshake_init`]); the explicit
/// `#legacy-keys=1` opt-in serves them to old nodes. Never used for new
/// tunnels.
#[derive(Clone)]
pub(crate) struct WgLegacyKeys {
    shared_secret: StaticSecret,
    shared_public: PublicKey,
}

impl WgLegacyKeys {
    fn derive(network_name: &str, network_secret: &str) -> Self {
        let mut secret = [0u8; 32];
        super::generate_digest_from_str(network_name, network_secret, &mut secret);
        let shared_secret = StaticSecret::from(secret);
        let shared_public = PublicKey::from(&shared_secret);
        Self {
            shared_secret,
            shared_public,
        }
    }
}

/// One-time warning for the `#legacy-keys=1` security downgrade, mirroring
/// the quic `#plain=1` escape hatch.
fn warn_legacy_keys() {
    static WARNED: AtomicBool = AtomicBool::new(false);
    if !WARNED.swap(true, Ordering::Relaxed) {
        tracing::warn!(
            "legacy wg key derivation: the tunnel reuses the old fast SipHash digest, \
             so a captured handshake again allows high-rate offline guessing of weak \
             network secrets. This exists only for peers that have not upgraded; \
             drop '#legacy-keys=1' to return to the argon2id derivation."
        );
    }
}

#[derive(Clone)]
pub struct WgConfig {
    my_secret_key: StaticSecret,
    my_public_key: PublicKey,
    peer_secret_key: StaticSecret,
    peer_public_key: PublicKey,
    /// Retired-derivation keys of the same network identity, kept for old
    /// peer detection; `None` for external-use and legacy configs.
    legacy_keys: Option<Arc<WgLegacyKeys>>,
    wg_type: WgType,
}

impl WgConfig {
    /// Derive the wg:// tunnel static keys from the network identity with
    /// argon2id (crypto-review S1.1).
    ///
    /// Replaces the retired SipHash digest, which allowed high-rate offline
    /// guessing of weak network secrets from one captured handshake. The
    /// salt gives the wg keys their own argon2id domain; the NUL separator
    /// keeps the joined input unambiguous (names and secrets are url/config
    /// strings and cannot contain NUL, unlike the legacy bare concatenation
    /// where ("ab", "c") and ("a", "bc") collided). The derivation is cached
    /// process-wide per (salt, secret) by the kdf core, so per-connection
    /// configs do not pay the argon2id cost.
    ///
    /// Breaking change: peers still on the SipHash derivation cannot connect.
    /// They are recognized and logged (see [`is_legacy_handshake_init`]), and
    /// `#legacy-keys=1` opts one link back into the old keys.
    pub fn new_from_network_identity(
        network_name: &str,
        network_secret: &str,
        role: WgRole,
    ) -> Self {
        let input = format!("{network_name}\0{network_secret}");
        let tag = derive_domain_key_argon2id(&input, WG_TUNNEL_ARGON2_SALT, 64);
        let (dialer_key, listener_key) = tag.split_at(32);
        let (my_key, peer_key) = match role {
            WgRole::Dialer => (dialer_key, listener_key),
            WgRole::Listener => (listener_key, dialer_key),
        };
        let mut ret = Self::new_internal(
            <[u8; 32]>::try_from(my_key).unwrap(),
            <[u8; 32]>::try_from(peer_key).unwrap(),
        );
        ret.legacy_keys = Some(Arc::new(WgLegacyKeys::derive(network_name, network_secret)));
        ret
    }

    /// The retired SipHash derivation: both ends share one static key.
    /// Reachable only through the explicit `#legacy-keys=1` url opt-in for
    /// peers that have not upgraded.
    pub fn new_legacy_from_network_identity(network_name: &str, network_secret: &str) -> Self {
        warn_legacy_keys();
        let mut secret = [0u8; 32];
        super::generate_digest_from_str(network_name, network_secret, &mut secret);
        Self::new_internal(secret, secret)
    }

    pub fn new_for_portal(server_key_seed: &str, client_key_seed: &str) -> Self {
        // The portal server accepts the external clients' connections
        // (listener role) and the WireGuard clients dial in (dialer role), so
        // the seeds map to complementary halves of the derivation.
        let server_cfg =
            Self::new_from_network_identity("server", server_key_seed, WgRole::Listener);
        let client_cfg = Self::new_from_network_identity("client", client_key_seed, WgRole::Dialer);
        Self {
            my_secret_key: server_cfg.my_secret_key,
            my_public_key: server_cfg.my_public_key,
            peer_secret_key: client_cfg.my_secret_key,
            peer_public_key: client_cfg.my_public_key,
            wg_type: WgType::ExternalUse,
            legacy_keys: None,
        }
    }

    pub fn new_internal(my_secret_key: [u8; 32], peer_secret_key: [u8; 32]) -> Self {
        let my_secret_key = StaticSecret::from(my_secret_key);
        let my_public_key = PublicKey::from(&my_secret_key);
        let peer_secret_key = StaticSecret::from(peer_secret_key);
        let peer_public_key = PublicKey::from(&peer_secret_key);
        Self {
            my_secret_key,
            my_public_key,
            peer_secret_key,
            peer_public_key,
            legacy_keys: None,
            wg_type: WgType::InternalUse,
        }
    }

    pub(crate) fn legacy_keys(&self) -> Option<Arc<WgLegacyKeys>> {
        self.legacy_keys.clone()
    }

    pub fn my_secret_key(&self) -> &[u8] {
        self.my_secret_key.as_bytes()
    }

    pub fn peer_secret_key(&self) -> &[u8] {
        self.peer_secret_key.as_bytes()
    }

    pub fn my_public_key(&self) -> &[u8] {
        self.my_public_key.as_bytes()
    }

    pub fn peer_public_key(&self) -> &[u8] {
        self.peer_public_key.as_bytes()
    }

    pub fn is_internal(&self) -> bool {
        self.wg_type == WgType::InternalUse
    }
}

/// Connection options carried in wg url fragments:
///
/// - `#legacy-keys=1` (peer or listener urls): derive the static keys with
///   the retired SipHash digest to interoperate with old EasyTier nodes. A
///   legacy listener serves legacy peers only — the derivations cannot share
///   one port — and no automatic fallback ever happens.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(crate) struct WgUrlOptions {
    pub(crate) legacy_keys: bool,
}

/// Parses wg connection options from the url fragment. Unknown pairs are
/// ignored for forward compatibility; a present but malformed `legacy-keys`
/// value is an error.
pub(crate) fn url_options(url: &url::Url) -> Result<WgUrlOptions, TunnelError> {
    let mut options = WgUrlOptions::default();
    let Some(fragment) = url.fragment() else {
        return Ok(options);
    };
    for pair in fragment.split('&') {
        if let Some(value) = pair.strip_prefix("legacy-keys=") {
            options.legacy_keys = match value {
                "1" => true,
                "0" => false,
                _ => {
                    return Err(TunnelError::InvalidProtocol(format!(
                        "invalid wg legacy-keys option in url fragment: {value} (expected 1 or 0)"
                    )));
                }
            };
        }
    }
    Ok(options)
}

/// Deterministic old-peer recognition (crypto-review S1.1).
///
/// boringtun does not expose the peer static key carried inside a received
/// handshake, so instead of comparing key fingerprints the rejected datagram
/// is replayed through a `Tunn` configured with the retired keys: `mac1` is
/// keyed with the receiver's static public key and the encrypted static only
/// opens under the legacy shared secret, so a datagram that passes both was
/// built by a peer still deriving keys the legacy way. A positive is a
/// proof, not a heuristic.
fn is_legacy_handshake_init(datagram: &[u8], legacy: &WgLegacyKeys) -> bool {
    if !matches!(
        Tunn::parse_incoming_packet(datagram),
        Ok(boringtun::noise::Packet::HandshakeInit(_))
    ) {
        return false;
    }
    let mut probe = Tunn::new(
        legacy.shared_secret.clone(),
        legacy.shared_public,
        None,
        None,
        0,
        None,
    );
    let mut buf = vec![0u8; MAX_PACKET];
    matches!(
        probe.decapsulate(None, datagram, &mut buf),
        TunnResult::WriteToNetwork(_)
    )
}

#[cfg(test)]
mod config_tests {
    use super::*;

    fn static_key(config: &WgConfig, f: fn(&WgConfig) -> &[u8]) -> [u8; 32] {
        <[u8; 32]>::try_from(f(config)).unwrap()
    }

    #[test]
    fn network_identity_derives_role_complementary_keys() {
        let dialer = WgConfig::new_from_network_identity("network", "secret", WgRole::Dialer);
        let listener = WgConfig::new_from_network_identity("network", "secret", WgRole::Listener);

        assert!(dialer.is_internal());
        assert!(listener.is_internal());
        // Complementary halves: each side's key is the peer's key, and the
        // two roles never share one static key (the legacy single-key shape).
        assert_eq!(dialer.my_secret_key(), listener.peer_secret_key());
        assert_eq!(dialer.peer_secret_key(), listener.my_secret_key());
        assert_ne!(dialer.my_secret_key(), listener.my_secret_key());
        assert_ne!(dialer.my_secret_key(), dialer.peer_secret_key());

        // Deterministic through the process cache: same inputs, same keys.
        assert_eq!(
            WgConfig::new_from_network_identity("network", "secret", WgRole::Dialer)
                .my_secret_key(),
            dialer.my_secret_key(),
        );

        // x25519 consistency between the secret and public halves.
        assert_eq!(
            PublicKey::from(&StaticSecret::from(static_key(
                &dialer,
                WgConfig::my_secret_key
            )))
            .as_bytes(),
            dialer.my_public_key(),
        );
    }

    #[test]
    fn argon2id_keys_differ_from_legacy_and_other_domains() {
        let dialer = WgConfig::new_from_network_identity("network", "secret", WgRole::Dialer);
        let legacy = WgConfig::new_legacy_from_network_identity("network", "secret");

        // New derivation is not the old digest, and the old config keeps the
        // same-key shape both ends used to share.
        assert_ne!(dialer.my_secret_key(), legacy.my_secret_key());
        assert_ne!(dialer.my_public_key(), legacy.my_public_key());
        assert_eq!(legacy.my_secret_key(), legacy.peer_secret_key());

        // Own salt domain: the same joined input under the data-plane salt
        // derives unrelated keys, so the domains never share material.
        let data_plane_domain =
            derive_domain_key_argon2id("network\0secret", b"easytier-kdf-v2", 64);
        assert_ne!(&data_plane_domain[..32], dialer.my_secret_key());
        assert_ne!(&data_plane_domain[32..], dialer.peer_secret_key());

        // The network name participates in the derivation, and the NUL
        // separator removes the legacy ("ab","c") == ("a","bc") collision.
        assert_ne!(
            dialer.my_secret_key(),
            WgConfig::new_from_network_identity("network2", "secret", WgRole::Dialer)
                .my_secret_key(),
        );
        assert_ne!(
            WgConfig::new_from_network_identity("ab", "c", WgRole::Dialer).my_secret_key(),
            WgConfig::new_from_network_identity("a", "bc", WgRole::Dialer).my_secret_key(),
        );
    }

    #[test]
    fn portal_uses_distinct_external_key_pairs() {
        let config = WgConfig::new_for_portal("server-seed", "client-seed");

        assert!(!config.is_internal());
        assert_ne!(config.my_secret_key(), config.peer_secret_key());
        assert_ne!(config.my_public_key(), config.peer_public_key());
        // The portal halves are the complementary role keys of the seeds.
        assert_eq!(
            config.my_secret_key(),
            WgConfig::new_from_network_identity("server", "server-seed", WgRole::Listener)
                .my_secret_key(),
        );
        assert_eq!(
            config.peer_secret_key(),
            WgConfig::new_from_network_identity("client", "client-seed", WgRole::Dialer)
                .my_secret_key(),
        );
    }

    #[test]
    fn legacy_handshake_detection_is_deterministic() {
        let legacy_keys = WgLegacyKeys::derive("network", "secret");
        let legacy_cfg = WgConfig::new_legacy_from_network_identity("network", "secret");
        let new_cfg = WgConfig::new_from_network_identity("network", "secret", WgRole::Dialer);

        let mut old_tunn = Tunn::new(
            StaticSecret::from(static_key(&legacy_cfg, WgConfig::my_secret_key)),
            PublicKey::from(<[u8; 32]>::try_from(legacy_cfg.peer_public_key()).unwrap()),
            None,
            None,
            1,
            None,
        );
        let mut buf = vec![0u8; MAX_PACKET];
        let initiation = old_tunn.format_handshake_initiation(&mut buf, false);
        let TunnResult::WriteToNetwork(msg) = initiation else {
            panic!("handshake initiation must format");
        };

        // An old node's initiation verifies under the legacy keys...
        assert!(is_legacy_handshake_init(msg, &legacy_keys));
        // ...is rejected under a different secret's legacy keys...
        assert!(!is_legacy_handshake_init(
            msg,
            &WgLegacyKeys::derive("network", "secret2"),
        ));
        // ...and new-derivation initiations are not legacy.
        let mut new_tunn = Tunn::new(
            StaticSecret::from(static_key(&new_cfg, WgConfig::my_secret_key)),
            PublicKey::from(<[u8; 32]>::try_from(new_cfg.peer_public_key()).unwrap()),
            None,
            None,
            2,
            None,
        );
        let mut buf2 = vec![0u8; MAX_PACKET];
        let TunnResult::WriteToNetwork(new_msg) =
            new_tunn.format_handshake_initiation(&mut buf2, false)
        else {
            panic!("handshake initiation must format");
        };
        assert!(!is_legacy_handshake_init(new_msg, &legacy_keys));

        // Non-handshake datagrams never match the probe.
        assert!(!is_legacy_handshake_init(&[0u8; 4], &legacy_keys));
    }

    #[test]
    fn url_fragment_parses_legacy_keys_opt_in() {
        let parse = |s: &str| url_options(&s.parse().unwrap()).unwrap();
        assert!(!parse("wg://1.2.3.4:1").legacy_keys);
        assert!(!parse("wg://1.2.3.4:1#unknown=7").legacy_keys);
        assert!(parse("wg://1.2.3.4:1#legacy-keys=1").legacy_keys);
        assert!(!parse("wg://1.2.3.4:1#legacy-keys=0").legacy_keys);
        assert!(url_options(&"wg://1.2.3.4:1#legacy-keys=2".parse().unwrap()).is_err());
    }
}

#[derive(Clone)]
struct WgPeerData {
    session: Arc<dyn UdpSessionSocket>,
    endpoint: SocketAddr,
    tunn: Arc<Mutex<Tunn>>,
    internal_use: bool,
    /// Retired-derivation keys of the network identity, for deterministic
    /// old-peer detection; `None` disables detection.
    legacy_keys: Option<Arc<WgLegacyKeys>>,
    legacy_probe_done: Arc<AtomicBool>,
    handshake_stalled_warned: Arc<AtomicBool>,
    access_time: Arc<AtomicCell<Instant>>,
    stopped: Arc<AtomicBool>,
}

impl Debug for WgPeerData {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WgPeerData")
            .field("endpoint", &self.endpoint)
            .field("local", &self.session.local_addr())
            .finish()
    }
}

impl WgPeerData {
    #[tracing::instrument]
    async fn handle_one_packet_from_me(&self, zc_packet: ZCPacket) -> Result<(), anyhow::Error> {
        let mut send_buf = vec![0u8; MAX_PACKET];

        let packet = if self.internal_use {
            let mut zc_packet = zc_packet.convert_type(ZCPacketType::WG);
            Self::fill_ip_header(&mut zc_packet);
            zc_packet.into_bytes()
        } else {
            zc_packet.convert_type(ZCPacketType::WG).into_bytes()
        };
        tracing::trace!(?packet, "Sending packet to peer");

        let encapsulate_result = {
            let mut peer = self.tunn.lock().await;
            peer.encapsulate(&packet, &mut send_buf)
        };

        tracing::trace!(
            ?encapsulate_result,
            "Received {} bytes from me",
            packet.len()
        );

        match encapsulate_result {
            TunnResult::WriteToNetwork(packet) => {
                self.session
                    .send(packet)
                    .await
                    .context("Failed to send encrypted IP packet to WireGuard endpoint.")?;
                tracing::debug!(
                    "Sent {} bytes to WireGuard endpoint (encrypted IP packet)",
                    packet.len()
                );
            }
            TunnResult::Err(e) => {
                tracing::error!("Failed to encapsulate IP packet: {:?}", e);
            }
            TunnResult::Done => {
                // Ignored
            }
            other => {
                tracing::error!(
                    "Unexpected WireGuard state during encapsulation: {:?}",
                    other
                );
            }
        };
        Ok(())
    }

    /// WireGuard consumption task. Receives encrypted packets from the WireGuard endpoint,
    /// decapsulates them, and dispatches newly received IP packets.
    #[tracing::instrument(skip(sink))]
    pub async fn handle_one_packet_from_peer<S: ZCPacketSink + Unpin>(
        &self,
        mut sink: S,
        recv_buf: &[u8],
    ) {
        self.access_time.store(Instant::now());
        let mut send_buf = vec![0u8; MAX_PACKET];
        let data = recv_buf;
        let decapsulate_result = {
            let mut peer = self.tunn.lock().await;
            peer.decapsulate(None, data, &mut send_buf)
        };

        tracing::debug!("Decapsulation result: {:?}", decapsulate_result);

        match decapsulate_result {
            TunnResult::WriteToNetwork(packet) => {
                match self.session.send(packet).await {
                    Ok(_) => {}
                    Err(e) => {
                        tracing::error!(
                            "Failed to send decapsulation-instructed packet to WireGuard endpoint: {:?}",
                            e
                        );
                        return;
                    }
                };
                let mut peer = self.tunn.lock().await;
                loop {
                    let mut send_buf = vec![0u8; MAX_PACKET];
                    match peer.decapsulate(None, &[], &mut send_buf) {
                        TunnResult::WriteToNetwork(packet) => {
                            match self.session.send(packet).await {
                                Ok(_) => {}
                                Err(e) => {
                                    tracing::error!(
                                        "Failed to send decapsulation-instructed packet to WireGuard endpoint: {:?}",
                                        e
                                    );
                                    break;
                                }
                            };
                        }
                        _ => {
                            break;
                        }
                    }
                }
            }
            TunnResult::WriteToTunnelV4(packet, _) | TunnResult::WriteToTunnelV6(packet, _) => {
                tracing::debug!(
                    ?packet,
                    "receive IP packet from peer: {} bytes",
                    packet.len()
                );
                let mut b = BytesMut::new();
                if self.internal_use {
                    b.resize(WG_TUNNEL_HEADER_SIZE, 0);
                    b.extend_from_slice(self.remove_ip_header(packet, packet[0] >> 4 == 4));
                } else {
                    b.extend_from_slice(packet);
                };
                let zc_packet = ZCPacket::new_from_buf(b, ZCPacketType::WG);
                tracing::trace!(?zc_packet, "forward zc_packet to sink");
                let ret = sink.send(zc_packet).await;
                if ret.is_err() {
                    tracing::error!("Failed to send packet to tunnel: {:?}", ret);
                }
            }
            TunnResult::Err(_) => {
                tracing::debug!(
                    "Unexpected WireGuard state during decapsulation: {:?}",
                    decapsulate_result
                );
                // A handshake initiation our keys reject is the one packet
                // that can prove the peer still derives keys the legacy way.
                if matches!(
                    Tunn::parse_incoming_packet(data),
                    Ok(boringtun::noise::Packet::HandshakeInit(_))
                ) {
                    self.detect_legacy_peer(data).await;
                }
            }
            _ => {
                tracing::debug!(
                    "Unexpected WireGuard state during decapsulation: {:?}",
                    decapsulate_result
                );
            }
        }
    }

    /// Deterministic old-peer detection (crypto-review S1.1): replay a
    /// handshake initiation rejected by our keys through the retired
    /// derivation ([`is_legacy_handshake_init`]). Runs at most once per peer:
    /// a mismatched peer retries its initiation every few seconds and the
    /// outcome cannot change, so one probe is enough for the log message.
    async fn detect_legacy_peer(&self, datagram: &[u8]) {
        if self.legacy_probe_done.swap(true, Ordering::Relaxed) {
            return;
        }
        let Some(legacy) = self.legacy_keys.as_ref() else {
            return;
        };
        if is_legacy_handshake_init(datagram, legacy) {
            tracing::warn!(
                peer = %self.endpoint,
                "WireGuard peer uses the legacy SipHash key derivation: it is running an older \
                 EasyTier and cannot connect with the argon2id keys. Upgrade the peer, or opt \
                 this link into the old keys with '#legacy-keys=1'"
            );
        }
    }

    /// Generic timeout-side warning (crypto-review S1.1): a peer that never
    /// completes a handshake may be an old EasyTier. Old responders drop our
    /// initiation silently, so no legacy fingerprint ever reaches the
    /// deterministic probe — only this symptom-based hint covers them. A
    /// wrong network name or secret looks the same, hence the wording.
    /// Fires at most once per peer.
    async fn warn_if_handshake_stalled(&self) {
        if self.handshake_stalled_warned.swap(true, Ordering::Relaxed) {
            return;
        }
        let (last_handshake, tx_bytes, rx_bytes, ..) = self.tunn.lock().await.stats();
        if last_handshake.is_none() && tx_bytes == 0 && rx_bytes == 0 {
            tracing::warn!(
                peer = %self.endpoint,
                "WireGuard handshake with peer never completed. If the peer runs an older \
                 EasyTier (legacy SipHash key derivation) the wg:// tunnel needs both nodes \
                 upgraded, or an explicit '#legacy-keys=1'; a wrong network name or secret \
                 produces the same symptom"
            );
        }
    }

    #[tracing::instrument]
    #[async_recursion]
    async fn handle_routine_tun_result<'a: 'async_recursion>(&self, result: TunnResult<'a>) -> () {
        match result {
            TunnResult::WriteToNetwork(packet) => {
                tracing::debug!(
                    "Sending routine packet of {} bytes to WireGuard endpoint",
                    packet.len()
                );
                match self.session.send(packet).await {
                    Ok(_) => {}
                    Err(e) => {
                        tracing::error!(
                            "Failed to send routine packet to WireGuard endpoint: {:?}",
                            e
                        );
                    }
                };
            }
            TunnResult::Err(WireGuardError::ConnectionExpired) => {
                tracing::warn!("Wireguard handshake has expired!");
                self.warn_if_handshake_stalled().await;

                let mut buf = vec![0u8; MAX_PACKET];
                let result = self
                    .tunn
                    .lock()
                    .await
                    .format_handshake_initiation(&mut buf[..], false);

                self.handle_routine_tun_result(result).await
            }
            TunnResult::Err(e) => {
                tracing::error!(
                    "Failed to prepare routine packet for WireGuard endpoint: {:?}",
                    e
                );
            }
            TunnResult::Done => {
                // Sleep for a bit
                tokio::time::sleep(Duration::from_millis(250)).await;
            }
            other => {
                tracing::warn!("Unexpected WireGuard routine task state: {:?}", other);
                tokio::time::sleep(Duration::from_millis(250)).await;
            }
        };
    }

    /// WireGuard Routine task. Handles Handshake, keep-alive, etc.
    pub async fn routine_task(self) {
        loop {
            let mut send_buf = vec![0u8; MAX_PACKET];
            let tun_result = { self.tunn.lock().await.update_timers(&mut send_buf) };
            self.handle_routine_tun_result(tun_result).await;
        }
    }

    fn fill_ip_header(zc_packet: &mut ZCPacket) {
        let len = zc_packet.payload_len() + PEER_MANAGER_HEADER_SIZE;
        let ip_header = &mut zc_packet.mut_wg_tunnel_header().unwrap().ipv4_header;
        ip_header[0] = 0x45;
        ip_header[1] = 0;
        ip_header[2..4].copy_from_slice(&((len + 20) as u16).to_be_bytes());
        ip_header[4..6].copy_from_slice(&0u16.to_be_bytes());
        ip_header[6..8].copy_from_slice(&0u16.to_be_bytes());
        ip_header[8] = 64;
        ip_header[9] = 0;
        ip_header[10..12].copy_from_slice(&0u16.to_be_bytes());
        ip_header[12..16].copy_from_slice(&0u32.to_be_bytes());
        ip_header[16..20].copy_from_slice(&0u32.to_be_bytes());
    }

    fn remove_ip_header<'a>(&self, packet: &'a [u8], is_v4: bool) -> &'a [u8] {
        if is_v4 { &packet[20..] } else { &packet[40..] }
    }
}

struct WgPeer {
    tunn: Option<Mutex<Tunn>>,
    _session_guard: Box<dyn Send + Sync>,
    session: Arc<dyn UdpSessionSocket>,
    config: WgConfig,
    endpoint: SocketAddr,

    sink: std::sync::Mutex<Option<Pin<Box<dyn ZCPacketSink>>>>,

    data: Option<WgPeerData>,
    tasks: JoinSet<()>,

    access_time: Arc<AtomicCell<Instant>>,
}

impl WgPeer {
    fn new(
        session_guard: Box<dyn Send + Sync>,
        session: Arc<dyn UdpSessionSocket>,
        config: WgConfig,
        endpoint: SocketAddr,
    ) -> Self {
        WgPeer {
            tunn: Some(Mutex::new(Tunn::new(
                StaticSecret::from(<[u8; 32]>::try_from(config.my_secret_key()).unwrap()),
                PublicKey::from(<[u8; 32]>::try_from(config.peer_public_key()).unwrap()),
                None,
                None,
                rand::thread_rng().next_u32(),
                None,
            ))),

            _session_guard: session_guard,
            session,
            config,
            endpoint,
            sink: std::sync::Mutex::new(None),

            data: None,
            tasks: JoinSet::new(),

            access_time: Arc::new(AtomicCell::new(Instant::now())),
        }
    }

    async fn handle_packet_from_me<S: ZCPacketStream + Unpin>(mut stream: S, data: WgPeerData) {
        while let Some(Ok(packet)) = stream.next().await {
            let ret = data.handle_one_packet_from_me(packet).await;
            if let Err(e) = ret {
                tracing::error!("Failed to handle packet from me: {}", e);
            }
        }
        data.stopped
            .store(true, std::sync::atomic::Ordering::Relaxed);
    }

    fn start_and_get_tunnel(&mut self) -> Box<dyn Tunnel> {
        let (stunnel, ctunnel) = create_ring_tunnel_pair();

        let (stream, sink) = stunnel.split();

        let data = WgPeerData {
            session: self.session.clone(),
            endpoint: self.endpoint,
            tunn: Arc::new(self.tunn.take().unwrap()),
            internal_use: self.config.is_internal(),
            legacy_keys: self.config.legacy_keys(),
            legacy_probe_done: Arc::new(AtomicBool::new(false)),
            handshake_stalled_warned: Arc::new(AtomicBool::new(false)),
            access_time: self.access_time.clone(),
            stopped: Arc::new(AtomicBool::new(false)),
        };

        self.data = Some(data.clone());
        self.sink.lock().unwrap().replace(sink);

        self.tasks
            .spawn(Self::handle_packet_from_me(stream, data.clone()));
        self.tasks.spawn(data.routine_task());

        ctunnel
    }

    fn stopped(&self) -> bool {
        self.data
            .as_ref()
            .unwrap()
            .stopped
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    async fn create_handshake_init(&self) -> Vec<u8> {
        let mut dst = vec![0u8; 2048];
        let handshake_init = self
            .tunn
            .as_ref()
            .unwrap()
            .lock()
            .await
            .format_handshake_initiation(&mut dst, false);
        assert!(matches!(handshake_init, TunnResult::WriteToNetwork(_)));
        let handshake_init = if let TunnResult::WriteToNetwork(sent) = handshake_init {
            sent
        } else {
            unreachable!();
        };

        handshake_init.into()
    }

    fn spawn_session_recv_task(&mut self, first_packet: Option<Vec<u8>>) {
        let session = self.session.clone();
        let data = self.data.as_ref().unwrap().clone();
        let mut sink = self.sink.lock().unwrap().take().unwrap();
        self.tasks.spawn(async move {
            if let Some(packet) = first_packet {
                data.handle_one_packet_from_peer(&mut sink, &packet).await;
            }

            let mut buf = vec![0u8; MAX_PACKET];
            loop {
                let n = match session.recv(&mut buf).await {
                    Ok(n) => n,
                    Err(e) => {
                        tracing::error!("Failed to receive wg packet: {}", e);
                        data.stopped
                            .store(true, std::sync::atomic::Ordering::Relaxed);
                        break;
                    }
                };
                data.handle_one_packet_from_peer(&mut sink, &buf[..n]).await;
            }
        });
    }
}

type ConnSender = tokio::sync::mpsc::UnboundedSender<Box<dyn Tunnel>>;
type ConnReceiver = tokio::sync::mpsc::UnboundedReceiver<Box<dyn Tunnel>>;

pub struct WgTunnelListener {
    addr: url::Url,
    session_listener: Option<Arc<RuntimeUdpSessionSocketListener>>,
    socket_mark: Option<u32>,
    config: WgConfig,

    conn_recv: ConnReceiver,
    conn_send: Option<ConnSender>,

    wg_peer_map: Arc<DashMap<SocketAddr, Arc<WgPeer>>>,

    tasks: JoinSet<()>,
}

impl Debug for WgTunnelListener {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("WgTunnelListener")
            .field("addr", &self.addr)
            .field("listening", &self.session_listener.is_some())
            .finish()
    }
}

impl WgTunnelListener {
    pub fn new(addr: url::Url, config: WgConfig) -> Self {
        let (conn_send, conn_recv) = unbounded_channel();
        WgTunnelListener {
            addr,
            session_listener: None,
            socket_mark: None,
            config,

            conn_recv,
            conn_send: Some(conn_send),

            wg_peer_map: Arc::new(DashMap::new()),

            tasks: JoinSet::new(),
        }
    }

    pub fn set_socket_mark(&mut self, socket_mark: Option<u32>) {
        self.socket_mark = socket_mark;
    }

    async fn accept_udp_sessions(
        session_listener: Arc<RuntimeUdpSessionSocketListener>,
        config: WgConfig,
        conn_sender: ConnSender,
        peer_map: Arc<DashMap<SocketAddr, Arc<WgPeer>>>,
    ) {
        let mut tasks = JoinSet::new();

        let peer_map_clone: Arc<DashMap<SocketAddr, Arc<WgPeer>>> = peer_map.clone();
        tasks.spawn(async move {
            loop {
                peer_map_clone.retain(|_, peer| {
                    peer.access_time.load().elapsed().as_secs() < 61 && !peer.stopped()
                });
                shrink_dashmap(&peer_map_clone, None);
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
        });

        loop {
            let session = match session_listener.accept_session().await {
                Ok(session) => Arc::new(session) as Arc<dyn UdpSessionSocket>,
                Err(e) => {
                    tracing::error!("Failed to accept wg udp session: {}", e);
                    break;
                }
            };
            let addr = match session.peer_addr() {
                Ok(addr) => addr,
                Err(e) => {
                    tracing::error!("Failed to get wg session peer addr: {}", e);
                    continue;
                }
            };
            if peer_map.contains_key(&addr) {
                continue;
            }
            let local_addr = match session.local_addr() {
                Ok(addr) => addr,
                Err(e) => {
                    tracing::error!("Failed to get wg session local addr: {}", e);
                    continue;
                }
            };

            tracing::info!("New peer: {}", addr);
            let mut wg = WgPeer::new(
                Box::new(session_listener.clone()),
                session,
                config.clone(),
                addr,
            );
            let (stream, sink) = wg.start_and_get_tunnel().split();
            wg.spawn_session_recv_task(None);
            let tunnel = Box::new(TunnelWrapper::new(
                stream,
                sink,
                Some(TunnelInfo {
                    tunnel_type: "wg".to_owned(),
                    local_addr: Some(
                        build_url_from_socket_addr(&local_addr.to_string(), "wg").into(),
                    ),
                    remote_addr: Some(build_url_from_socket_addr(&addr.to_string(), "wg").into()),
                    resolved_remote_addr: Some(
                        build_url_from_socket_addr(&addr.to_string(), "wg").into(),
                    ),
                }),
            ));
            if let Err(e) = conn_sender.send(tunnel) {
                tracing::error!("Failed to send tunnel to conn_sender: {}", e);
                break;
            }
            peer_map.insert(addr, Arc::new(wg));
        }
    }

    async fn listen_tunnel(&mut self) -> Result<(), TunnelError> {
        if self.session_listener.is_some() {
            return Ok(());
        }

        let local_addr = SocketAddr::from_url(self.addr.clone(), IpVersion::Both).await?;
        let bind = UdpBindOptions::port_bound_listener(local_addr)
            .with_socket_mark(self.socket_mark)
            .with_bind_device(TunnelUrl::from(self.addr.clone()).bind_dev())
            .with_only_v6(true);
        let mut session_listener = new_runtime_udp_session_listener(
            self.addr.clone(),
            UdpSessionListenRequest::new(bind),
            UdpSessionAcceptKind::Classified(UdpSessionProtocol::WireGuard),
            NetNS::new(None),
        );
        easytier_core::socket::SocketListener::listen(&mut session_listener).await?;
        let session_listener = Arc::new(session_listener);

        self.tasks.spawn(Self::accept_udp_sessions(
            session_listener.clone(),
            self.config.clone(),
            self.conn_send.take().unwrap(),
            self.wg_peer_map.clone(),
        ));
        self.session_listener = Some(session_listener);

        Ok(())
    }

    async fn accept_tunnel(&mut self) -> Result<Box<dyn Tunnel>, TunnelError> {
        if let Some(tunnel) = self.conn_recv.recv().await {
            tracing::info!(?tunnel, "Accepted tunnel");
            return Ok(tunnel);
        }
        Err(TunnelError::Shutdown)
    }
}

#[async_trait]
impl easytier_core::socket::SocketListener for WgTunnelListener {
    type Accepted = Box<dyn Tunnel>;

    async fn listen(&mut self) -> anyhow::Result<()> {
        Ok(self.listen_tunnel().await?)
    }

    async fn accept(&mut self) -> anyhow::Result<Self::Accepted> {
        Ok(self.accept_tunnel().await?)
    }

    fn local_url(&self) -> url::Url {
        self.session_listener
            .as_ref()
            .map(|listener| easytier_core::socket::SocketListener::local_url(listener.as_ref()))
            .unwrap_or_else(|| self.addr.clone())
    }
}

pub(crate) async fn upgrade_connected(
    connected: ConnectedUdpSession,
    addr_url: url::Url,
    config: WgConfig,
) -> Result<Box<dyn Tunnel>, TunnelError> {
    let (session, session_guard) = connected.into_parts();
    let session = Arc::new(session) as Arc<dyn UdpSessionSocket>;
    let addr = session.peer_addr()?;
    let local_addr = session
        .local_addr()
        .with_context(|| "Failed to get local addr")?
        .to_string();

    let mut wg_peer = WgPeer::new(session_guard, session.clone(), config.clone(), addr);

    // do handshake here so we will return after receive first packet
    let handshake = wg_peer.create_handshake_init().await;
    session.send(&handshake).await?;
    let mut buf = [0u8; MAX_PACKET];
    let n = match session.recv(&mut buf).await {
        Ok(ret) => ret,
        Err(e) => {
            tracing::error!("Failed to receive handshake response: {}", e);
            return Err(TunnelError::IOError(e));
        }
    };

    let tunnel = wg_peer.start_and_get_tunnel();
    wg_peer.spawn_session_recv_task(Some(buf[..n].to_vec()));

    let (stream, sink) = tunnel.split();
    let ret = Box::new(TunnelWrapper::new_with_associate_data(
        stream,
        sink,
        Some(TunnelInfo {
            tunnel_type: "wg".to_owned(),
            local_addr: Some(super::build_url_from_socket_addr(&local_addr, "wg").into()),
            remote_addr: Some(addr_url.into()),
            resolved_remote_addr: Some(
                super::build_url_from_socket_addr(&addr.to_string(), "wg").into(),
            ),
        }),
        Some(Box::new(wg_peer)),
    ));

    Ok(ret)
}

pub(crate) fn upgrade_accepted(
    session: UdpSession,
    config: WgConfig,
) -> Result<Box<dyn Tunnel>, TunnelError> {
    let session = Arc::new(session) as Arc<dyn UdpSessionSocket>;
    let remote_addr = session.peer_addr()?;
    let local_addr = session.local_addr()?;
    let mut wg_peer = WgPeer::new(Box::new(()), session, config, remote_addr);
    let tunnel = wg_peer.start_and_get_tunnel();
    wg_peer.spawn_session_recv_task(None);

    let (stream, sink) = tunnel.split();
    let remote_url = build_url_from_socket_addr(&remote_addr.to_string(), "wg");
    Ok(Box::new(TunnelWrapper::new_with_associate_data(
        stream,
        sink,
        Some(TunnelInfo {
            tunnel_type: "wg".to_owned(),
            local_addr: Some(build_url_from_socket_addr(&local_addr.to_string(), "wg").into()),
            remote_addr: Some(remote_url.clone().into()),
            resolved_remote_addr: Some(remote_url.into()),
        }),
        Some(Box::new(wg_peer)),
    )))
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::{
        common::global_ctx::tests::get_mock_global_ctx, host_runtime::native_host_runtime,
        tunnel::protocol::runtime_client_protocol_upgrader,
    };
    use easytier_core::{
        connectivity::transport::{ConnectedTransport, UdpSessionMode, connect_udp},
        socket::SocketListener,
        socket::udp::{UdpBindOptions, UdpSessionProtocol},
    };

    fn test_wg_config() -> WgConfig {
        WgConfig::new_from_network_identity("test", "secret", WgRole::Listener)
    }

    #[tokio::test]
    async fn wg_server_erase_from_map_after_close() {
        let global_ctx = get_mock_global_ctx();
        let identity = global_ctx.get_network_identity();
        let server_cfg = WgConfig::new_from_network_identity(
            &identity.network_name,
            &identity.network_secret.unwrap_or_default(),
            WgRole::Listener,
        );
        let client = runtime_client_protocol_upgrader(global_ctx);
        let mut listener = WgTunnelListener::new("wg://127.0.0.1:0".parse().unwrap(), server_cfg);
        listener.listen().await.unwrap();
        let remote_url = listener.local_url();
        let remote_addr = remote_url.socket_addrs(|| None).unwrap()[0];

        const CONN_COUNT: usize = 10;

        let client_task = tokio::spawn(async move {
            let mut tunnels = Vec::with_capacity(CONN_COUNT);
            for _ in 0..CONN_COUNT {
                let connected = connect_udp(
                    native_host_runtime(),
                    remote_addr,
                    Vec::new(),
                    UdpBindOptions::direct_connect(),
                    UdpSessionMode::Classified(UdpSessionProtocol::WireGuard),
                )
                .await
                .unwrap();
                let tunnel = client
                    .upgrade_client(ConnectedTransport::Udp(connected), remote_url.clone())
                    .await
                    .unwrap();
                let (_stream, mut sink) = tunnel.split();
                sink.send(ZCPacket::new_with_payload(b"payload"))
                    .await
                    .unwrap();
                tunnels.push(tunnel);
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
        });

        for _ in 0..CONN_COUNT {
            let tunnel = listener.accept().await.unwrap();
            let (mut stream, _sink) = tunnel.split();
            let packet = stream.next().await.unwrap().unwrap();
            assert_eq!(packet.payload(), b"payload");
        }

        client_task.await.unwrap();
        tokio::time::sleep(Duration::from_secs(2)).await;
        assert!(listener.wg_peer_map.is_empty());
    }

    #[tokio::test]
    async fn bind_same_port() {
        let server_cfg = test_wg_config();
        let mut listener = WgTunnelListener::new("wg://[::1]:31015".parse().unwrap(), server_cfg);
        let server_cfg = test_wg_config();
        let mut listener2 = WgTunnelListener::new("wg://[::1]:31015".parse().unwrap(), server_cfg);
        listener.listen().await.unwrap();
        listener2.listen().await.unwrap();
    }

    #[tokio::test]
    async fn test_alloc_port() {
        // v4
        let server_cfg = test_wg_config();
        let mut listener = WgTunnelListener::new("wg://0.0.0.0:0".parse().unwrap(), server_cfg);
        listener.listen().await.unwrap();
        let port = listener.local_url().port().unwrap();
        assert!(port > 0);

        // v6
        let server_cfg = test_wg_config();
        let mut listener = WgTunnelListener::new("wg://[::]:0".parse().unwrap(), server_cfg);
        listener.listen().await.unwrap();
        let port = listener.local_url().port().unwrap();
        assert!(port > 0);
    }
}
