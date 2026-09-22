use std::pin::Pin;
use std::sync::Arc;

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
use futures::{SinkExt, StreamExt};
use prost::Message;
use x25519_dalek::{PublicKey, StaticSecret};

use crate::foundation::time::{Duration, timeout};

use crate::{
    packet::{PacketType, ZCPacket},
    peers::{
        PeerConnectionOrigin, PeerPacketIngress,
        conn::{
            peer_conn::{
                HEADER_AAD_FEATURE, KDF_V2_FEATURE, PeerConn, PeerConnId, SECRET_CHALLENGE_FEATURE,
                SECRET_CHALLENGE_V2_FEATURE,
            },
            peer_map::PeerMap,
            peer_session::PeerSessionStore,
        },
        context::NetworkIdentity,
        create_packet_recv_chan,
        error::Error,
        recv_packet_envelope_from_chan,
        test_support::NoopPeerContext,
    },
    proto::peer_rpc::HandshakeRequest,
    tunnel::{
        Tunnel, TunnelError, encrypt::derive_challenge_key_argon2id, ring::create_ring_tunnel_pair,
        wrapper::TunnelWrapper,
    },
};

impl PeerConn {
    #[tracing::instrument]
    async fn do_handshake_as_server(&mut self) -> Result<(), Error> {
        self.do_handshake_as_server_ext(|_, _| Ok(())).await
    }
}

#[tokio::test]
async fn peer_conn_handshake_over_memory_tunnel() {
    let peer_session_store = Arc::new(PeerSessionStore::new());
    let (client_tunnel, server_tunnel) = create_ring_tunnel_pair();
    let client_ctx = Arc::new(NoopPeerContext::default());
    let server_ctx = Arc::new(NoopPeerContext::default());

    let mut client = PeerConn::new(1, client_ctx, client_tunnel, peer_session_store.clone());
    let mut server = PeerConn::new(2, server_ctx, server_tunnel, peer_session_store);

    let (client_ret, server_ret) = tokio::join!(
        client.do_handshake_as_client(),
        server.do_handshake_as_server()
    );

    client_ret.unwrap();
    server_ret.unwrap();
    assert_eq!(client.get_peer_id(), 2);
    assert_eq!(server.get_peer_id(), 1);
    assert_eq!(
        client.get_conn_info().features,
        [
            "liveness-echo-v1",
            "header-aad-v1",
            "kdf-v2",
            "secret-challenge-v1",
            "secret-challenge-v2"
        ]
    );
    assert_eq!(
        server.get_conn_info().features,
        [
            "liveness-echo-v1",
            "header-aad-v1",
            "kdf-v2",
            "secret-challenge-v1",
            "secret-challenge-v2"
        ]
    );
    assert!(client.supports_header_aad());
    assert!(server.supports_header_aad());
    assert!(client.supports_kdf_v2());
    assert!(server.supports_kdf_v2());
}

#[tokio::test]
async fn peer_conn_noise_handshake_advertises_liveness_echo() {
    fn context(peer_key: u8) -> Arc<NoopPeerContext> {
        let private = StaticSecret::from([peer_key; 32]);
        let public = PublicKey::from(&private);
        Arc::new(
            NoopPeerContext::new(NetworkIdentity {
                network_name: "net".to_owned(),
                network_secret: Some("secret".to_owned()),
                network_secret_digest: None,
            })
            .with_secure_mode(crate::proto::common::SecureModeConfig {
                enabled: true,
                local_private_key: Some(BASE64_STANDARD.encode(private.as_bytes())),
                local_public_key: Some(BASE64_STANDARD.encode(public.as_bytes())),
            }),
        )
    }

    let (client_tunnel, server_tunnel) = create_ring_tunnel_pair();
    let mut client = PeerConn::new(
        1,
        context(1),
        client_tunnel,
        Arc::new(PeerSessionStore::new()),
    );
    let mut server = PeerConn::new(
        2,
        context(2),
        server_tunnel,
        Arc::new(PeerSessionStore::new()),
    );

    let (client_ret, server_ret) = tokio::join!(
        client.do_handshake_as_client(),
        server.do_handshake_as_server()
    );

    client_ret.unwrap();
    server_ret.unwrap();
    assert_eq!(
        client.get_conn_info().features,
        [
            "liveness-echo-v1",
            "header-aad-v1",
            "kdf-v2",
            "secret-challenge-v1",
            "secret-challenge-v2"
        ]
    );
    assert_eq!(
        server.get_conn_info().features,
        [
            "liveness-echo-v1",
            "header-aad-v1",
            "kdf-v2",
            "secret-challenge-v1",
            "secret-challenge-v2"
        ]
    );
    assert!(client.supports_header_aad());
    assert!(server.supports_header_aad());
    assert!(client.supports_kdf_v2());
    assert!(server.supports_kdf_v2());
}

#[tokio::test]
async fn peer_conn_handshake_matches_plaintext_secret_identity() {
    let peer_session_store = Arc::new(PeerSessionStore::new());
    let (client_tunnel, server_tunnel) = create_ring_tunnel_pair();
    let client_ctx = Arc::new(NoopPeerContext::new(NetworkIdentity {
        network_name: "net".to_string(),
        network_secret: Some("secret".to_string()),
        network_secret_digest: None,
    }));
    let server_ctx = Arc::new(NoopPeerContext::new(NetworkIdentity {
        network_name: "net".to_string(),
        network_secret: Some("secret".to_string()),
        network_secret_digest: None,
    }));

    let mut client = PeerConn::new(1, client_ctx, client_tunnel, peer_session_store.clone());
    let mut server = PeerConn::new(2, server_ctx, server_tunnel, peer_session_store);

    let (client_ret, server_ret) = tokio::join!(
        client.do_handshake_as_client(),
        server.do_handshake_as_server()
    );

    client_ret.unwrap();
    server_ret.unwrap();
    assert!(client.matches_local_network_secret());
    assert!(server.matches_local_network_secret());
}

/// mpsc-backed tunnel pair that records every packet each side sends
/// (crypto-review S1.2 tests need wire-level access).
type SentLog = std::sync::Arc<std::sync::Mutex<Vec<ZCPacket>>>;

fn recording_channel_tunnel_pair() -> (Box<dyn Tunnel>, Box<dyn Tunnel>, SentLog, SentLog) {
    fn recorder_sink(
        tx: tokio::sync::mpsc::UnboundedSender<ZCPacket>,
        log: SentLog,
    ) -> Pin<Box<dyn crate::tunnel::ZCPacketSink>> {
        Box::pin(futures::sink::unfold(tx, move |tx, pkt: ZCPacket| {
            let log = log.clone();
            async move {
                log.lock().unwrap().push(pkt.clone());
                tx.send(pkt).map_err(|_| TunnelError::Shutdown).map(|_| tx)
            }
        }))
    }

    fn receiver_stream(
        rx: tokio::sync::mpsc::UnboundedReceiver<ZCPacket>,
    ) -> Pin<Box<dyn crate::tunnel::ZCPacketStream>> {
        Box::pin(futures::stream::unfold(rx, |mut rx| async move {
            rx.recv().await.map(|pkt| (Ok(pkt), rx))
        }))
    }

    let (a_to_b, a_rx) = tokio::sync::mpsc::unbounded_channel();
    let (b_to_a, b_rx) = tokio::sync::mpsc::unbounded_channel();
    let a_log: SentLog = Default::default();
    let b_log: SentLog = Default::default();
    let a = TunnelWrapper::new(
        receiver_stream(b_rx),
        recorder_sink(a_to_b, a_log.clone()),
        None,
    );
    let b = TunnelWrapper::new(
        receiver_stream(a_rx),
        recorder_sink(b_to_a, b_log.clone()),
        None,
    );
    (Box::new(a), Box::new(b), a_log, b_log)
}

fn secret_context(secret: &str) -> Arc<NoopPeerContext> {
    Arc::new(NoopPeerContext::new(NetworkIdentity {
        network_name: "net".to_string(),
        network_secret: Some(secret.to_string()),
        network_secret_digest: None,
    }))
}

fn handshake_packets(log: &SentLog) -> Vec<ZCPacket> {
    log.lock()
        .unwrap()
        .iter()
        .filter(|pkt| {
            pkt.peer_manager_header()
                .is_some_and(|hdr| hdr.packet_type == PacketType::HandShake as u8)
        })
        .cloned()
        .collect()
}

fn rewrite_handshake_packet<F: FnOnce(&mut HandshakeRequest)>(pkt: &ZCPacket, edit: F) -> ZCPacket {
    let mut req = HandshakeRequest::decode(pkt.payload()).unwrap();
    edit(&mut req);
    let mut out = ZCPacket::new_with_payload(&req.encode_to_vec());
    out.fill_peer_manager_hdr(
        pkt.peer_manager_header().unwrap().from_peer_id.get(),
        pkt.peer_manager_header().unwrap().to_peer_id.get(),
        PacketType::HandShake as u8,
    );
    out
}

/// Runs one full challenge handshake and returns both send logs.
async fn captured_challenge_handshake() -> (SentLog, SentLog) {
    let (client_tunnel, server_tunnel, client_log, server_log) = recording_channel_tunnel_pair();
    let mut client = PeerConn::new(
        1,
        secret_context("secret"),
        client_tunnel,
        Arc::new(PeerSessionStore::new()),
    );
    let mut server = PeerConn::new(
        2,
        secret_context("secret"),
        server_tunnel,
        Arc::new(PeerSessionStore::new()),
    );
    let (client_ret, server_ret) = tokio::join!(
        client.do_handshake_as_client(),
        server.do_handshake_as_server()
    );
    client_ret.unwrap();
    server_ret.unwrap();
    (client_log, server_log)
}

#[tokio::test]
async fn legacy_handshake_challenges_without_leaking_the_static_digest() {
    let (client_log, server_log) = captured_challenge_handshake().await;

    // The static digest is an equivalent password (crypto-review S1.2); it
    // must not appear in any packet of a challenge handshake.
    let digest = NetworkIdentity::new("net".to_string(), "secret".to_string())
        .network_secret_digest
        .unwrap();
    for log in [&client_log, &server_log] {
        for pkt in log.lock().unwrap().iter() {
            assert!(
                !pkt.payload().windows(digest.len()).any(|w| w == digest),
                "static digest leaked in a handshake packet"
            );
        }
    }
    // Three rounds total: nonce request + nonce/proof response + proof.
    assert_eq!(handshake_packets(&client_log).len(), 2);
    assert_eq!(handshake_packets(&server_log).len(), 1);
}

#[tokio::test]
async fn legacy_handshake_rejects_secret_mismatch() {
    let (client_tunnel, server_tunnel, _, _) = recording_channel_tunnel_pair();
    let mut client = PeerConn::new(
        1,
        secret_context("secret-a"),
        client_tunnel,
        Arc::new(PeerSessionStore::new()),
    );
    let mut server = PeerConn::new(
        2,
        secret_context("secret-b"),
        server_tunnel,
        Arc::new(PeerSessionStore::new()),
    );

    let (client_ret, server_ret) = tokio::join!(
        client.do_handshake_as_client(),
        server.do_handshake_as_server()
    );
    // The responder's proof does not verify, so the initiator refuses.
    assert!(matches!(
        client_ret.unwrap_err(),
        Error::SecretKeyError(_) | Error::WaitRespError(_)
    ));
    // Dropping the failed initiator closes the tunnel; the responder sees a
    // closed conn instead of hanging for its proof timeout.
    let _ = server_ret;
}

#[tokio::test]
async fn replayed_handshake_proofs_do_not_authenticate() {
    let (client_log, _) = captured_challenge_handshake().await;
    let client_packets = handshake_packets(&client_log);
    assert_eq!(client_packets.len(), 2); // msg1 and msg3
    let (msg1, msg3) = (&client_packets[0], &client_packets[1]);

    // Fresh responder: replaying both captured messages must not pass, since
    // the msg3 proof only covers the nonce of the original responder.
    let (attacker_tunnel, server_tunnel, _, _) = recording_channel_tunnel_pair();
    let mut server = PeerConn::new(
        2,
        secret_context("secret"),
        server_tunnel,
        Arc::new(PeerSessionStore::new()),
    );
    let server_task = tokio::spawn(async move { server.do_handshake_as_server().await });

    let (mut stream, mut sink) = attacker_tunnel.split();
    sink.send(msg1.clone()).await.unwrap();
    sink.send(msg3.clone()).await.unwrap();
    let rsp = timeout(Duration::from_secs(2), stream.next())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(
        rsp.peer_manager_header().unwrap().packet_type,
        PacketType::HandShake as u8
    );

    let ret = timeout(Duration::from_secs(2), server_task)
        .await
        .unwrap()
        .unwrap();
    assert!(
        ret.is_err(),
        "replayed initiator proof must not authenticate"
    );
}

#[tokio::test]
async fn legacy_handshake_accepts_featureless_initiator() {
    // Old peers send their static digest and declare no features; the
    // responder must keep the static-digest flow for them.
    let (client_log, _) = captured_challenge_handshake().await;
    let real_msg1 = &handshake_packets(&client_log)[0];
    let digest = NetworkIdentity::new("net".to_string(), "secret".to_string())
        .network_secret_digest
        .unwrap();
    let old_msg1 = rewrite_handshake_packet(real_msg1, |req| {
        req.features.clear();
        req.challenge_nonce.clear();
        req.network_secret_digest = digest.to_vec();
    });

    let (old_client_tunnel, server_tunnel, _, _) = recording_channel_tunnel_pair();
    let mut server = PeerConn::new(
        2,
        secret_context("secret"),
        server_tunnel,
        Arc::new(PeerSessionStore::new()),
    );
    let server_task = tokio::spawn(async move { server.do_handshake_as_server().await });

    let (mut stream, mut sink) = old_client_tunnel.split();
    sink.send(old_msg1).await.unwrap();
    let rsp = timeout(Duration::from_secs(2), stream.next())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    let rsp_req = HandshakeRequest::decode(rsp.payload()).unwrap();
    // Digests matched, so the responder still answers with its digest.
    assert_eq!(rsp_req.network_secret_digest, digest.to_vec());
    assert!(rsp_req.challenge_nonce.is_empty());
    assert!(rsp_req.secret_proof.is_empty());

    timeout(Duration::from_secs(2), server_task)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn legacy_handshake_refuses_featureless_responder() {
    // An old responder cannot authenticate itself to a challenge initiator
    // without the initiator revealing the digest, so the initiator refuses
    // rather than downgrading (documented interop cost of secret-challenge).
    let (_, server_log) = captured_challenge_handshake().await;
    let real_msg2 = &handshake_packets(&server_log)[0];
    let old_msg2 = rewrite_handshake_packet(real_msg2, |req| {
        req.features.clear();
        req.challenge_nonce.clear();
        req.secret_proof.clear();
        req.network_secret_digest = vec![0u8; 32];
    });

    let (client_tunnel, scripted_tunnel, client_log, _) = recording_channel_tunnel_pair();
    let mut client = PeerConn::new(
        1,
        secret_context("secret"),
        client_tunnel,
        Arc::new(PeerSessionStore::new()),
    );
    let client_task = tokio::spawn(async move { client.do_handshake_as_client().await });

    let (mut stream, mut sink) = scripted_tunnel.split();
    let msg1 = timeout(Duration::from_secs(2), stream.next())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    // The initiator's first message carries a fresh nonce and a zeroed
    // digest: nothing offline-verifiable leaves the node.
    let msg1_req = HandshakeRequest::decode(msg1.payload()).unwrap();
    assert_eq!(msg1_req.network_secret_digest, vec![0u8; 32]);
    assert_eq!(msg1_req.challenge_nonce.len(), 32);
    assert!(
        msg1_req
            .features
            .iter()
            .any(|f| f == SECRET_CHALLENGE_FEATURE)
    );

    sink.send(old_msg2).await.unwrap();
    let ret = timeout(Duration::from_secs(2), client_task)
        .await
        .unwrap()
        .unwrap();
    assert!(matches!(ret.unwrap_err(), Error::SecretKeyError(_)));
    // Only the nonce-bearing request was ever sent.
    assert_eq!(handshake_packets(&client_log).len(), 1);
}

#[tokio::test]
async fn challenge_handshake_conn_passes_identity_admission() {
    // The proof-verified conn carries the backfilled digest, so the
    // zeros-digest rejection in add_new_peer_conn does not refuse it.
    let (client_tunnel, server_tunnel, _, _) = recording_channel_tunnel_pair();
    let client_ctx = secret_context("secret");
    let mut client = PeerConn::new(
        1,
        client_ctx.clone(),
        client_tunnel,
        Arc::new(PeerSessionStore::new()),
    );
    let mut server = PeerConn::new(
        2,
        secret_context("secret"),
        server_tunnel,
        Arc::new(PeerSessionStore::new()),
    );
    let (client_ret, server_ret) = tokio::join!(
        client.do_handshake_as_client(),
        server.do_handshake_as_server()
    );
    client_ret.unwrap();
    server_ret.unwrap();

    let (tx, _rx) = create_packet_recv_chan();
    let peers = PeerMap::new(tx, client_ctx, 1);
    let local_identity = NetworkIdentity {
        network_name: "net".to_string(),
        network_secret: Some("secret".to_string()),
        network_secret_digest: None,
    };
    let peer_id = timeout(
        Duration::from_secs(2),
        crate::peers::peer_manager::add_new_peer_conn(&peers, &local_identity, false, client),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(peer_id, 2);
}

#[tokio::test]
async fn local_packet_channel_injection_has_no_attached_privilege() {
    let (sender, mut receiver) = create_packet_recv_chan();
    let mut packet = ZCPacket::new_with_payload(b"local");
    packet.fill_peer_manager_hdr(77, 3, PacketType::Data as u8);

    sender.send(packet).await.unwrap();

    let envelope = recv_packet_envelope_from_chan(&mut receiver).await.unwrap();
    let (_, ingress) = envelope.into_parts();
    assert_eq!(ingress, PeerPacketIngress::Local);
    assert!(!ingress.is_attached());
}

#[tokio::test]
async fn peer_map_forwards_packet_over_memory_tunnel() {
    let peer_session_store = Arc::new(PeerSessionStore::new());
    let (client_tunnel, server_tunnel) = create_ring_tunnel_pair();
    let client_ctx = Arc::new(NoopPeerContext::default());
    let server_ctx = Arc::new(NoopPeerContext::default());

    let mut client_conn = PeerConn::new(
        1,
        client_ctx.clone(),
        client_tunnel,
        peer_session_store.clone(),
    );
    let mut server_conn = PeerConn::new(2, server_ctx.clone(), server_tunnel, peer_session_store);

    let (client_ret, server_ret) = tokio::join!(
        client_conn.do_handshake_as_client(),
        server_conn.do_handshake_as_server()
    );
    client_ret.unwrap();
    server_ret.unwrap();

    let (client_tx, _client_rx) = create_packet_recv_chan();
    let (server_tx, mut server_rx) = create_packet_recv_chan();
    let client_map = PeerMap::new(client_tx, client_ctx, 1);
    let server_map = PeerMap::new(server_tx, server_ctx, 2);

    client_map.add_new_peer_conn(client_conn).await.unwrap();
    server_map.add_new_peer_conn(server_conn).await.unwrap();

    let mut packet = ZCPacket::new_with_payload(b"hello");
    packet.fill_peer_manager_hdr(1, 2, PacketType::Data as u8);
    client_map.send_msg_directly(packet, 2).await.unwrap();

    let received = timeout(Duration::from_secs(1), server_rx.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(received.payload(), b"hello");
}

#[tokio::test]
async fn peer_channel_uses_admission_origin_instead_of_packet_header() {
    let peer_session_store = Arc::new(PeerSessionStore::new());
    let (client_tunnel, server_tunnel) = create_ring_tunnel_pair();
    let client_ctx = Arc::new(NoopPeerContext::default());
    let server_ctx = Arc::new(NoopPeerContext::default());

    let mut client_conn = PeerConn::new(
        1,
        client_ctx.clone(),
        client_tunnel,
        peer_session_store.clone(),
    );
    let mut server_conn = PeerConn::new_with_peer_id_hint_and_origin(
        2,
        server_ctx.clone(),
        server_tunnel,
        None,
        peer_session_store,
        PeerConnectionOrigin::Attached,
    );
    let (client_ret, server_ret) = tokio::join!(
        client_conn.do_handshake_as_client(),
        server_conn.do_handshake_as_server()
    );
    client_ret.unwrap();
    server_ret.unwrap();
    server_conn.set_is_hole_punched(false);
    let server_conn_id = server_conn.get_conn_id();

    let (client_tx, _client_rx) = create_packet_recv_chan();
    let (server_tx, mut server_rx) = create_packet_recv_chan();
    let client_map = PeerMap::new(client_tx, client_ctx, 1);
    let server_map = PeerMap::new(server_tx, server_ctx, 2);
    client_map.add_new_peer_conn(client_conn).await.unwrap();
    server_map.add_new_peer_conn(server_conn).await.unwrap();
    assert!(server_map.has_direct_attached_peer(1));

    let mut packet = ZCPacket::new_with_payload(b"forged source");
    packet.fill_peer_manager_hdr(77, 3, PacketType::Data as u8);
    client_map.send_msg_directly(packet, 2).await.unwrap();

    let envelope = timeout(
        Duration::from_secs(1),
        recv_packet_envelope_from_chan(&mut server_rx),
    )
    .await
    .unwrap()
    .unwrap();
    let (received, ingress) = envelope.into_parts();
    assert_eq!(
        received.peer_manager_header().unwrap().from_peer_id.get(),
        77
    );
    assert_eq!(
        ingress,
        PeerPacketIngress::Peer {
            peer_id: 1,
            conn_id: server_conn_id,
            origin: PeerConnectionOrigin::Attached,
        }
    );
}

#[tokio::test]
async fn peer_map_reselects_cached_connection_after_close() {
    let peer_session_store = Arc::new(PeerSessionStore::new());
    let (client_tunnel_a, server_tunnel_a) = create_ring_tunnel_pair();
    let (client_tunnel_b, server_tunnel_b) = create_ring_tunnel_pair();
    let client_ctx = Arc::new(NoopPeerContext::default());
    let server_ctx = Arc::new(NoopPeerContext::default());

    let mut client_conn_a = PeerConn::new(
        1,
        client_ctx.clone(),
        client_tunnel_a,
        peer_session_store.clone(),
    );
    let mut server_conn_a = PeerConn::new(
        2,
        server_ctx.clone(),
        server_tunnel_a,
        peer_session_store.clone(),
    );
    let mut client_conn_b = PeerConn::new(
        1,
        client_ctx.clone(),
        client_tunnel_b,
        peer_session_store.clone(),
    );
    let mut server_conn_b =
        PeerConn::new(2, server_ctx.clone(), server_tunnel_b, peer_session_store);

    let (client_a_ret, server_a_ret, client_b_ret, server_b_ret) = tokio::join!(
        client_conn_a.do_handshake_as_client(),
        server_conn_a.do_handshake_as_server(),
        client_conn_b.do_handshake_as_client(),
        server_conn_b.do_handshake_as_server(),
    );
    client_a_ret.unwrap();
    server_a_ret.unwrap();
    client_b_ret.unwrap();
    server_b_ret.unwrap();

    let (client_tx, _client_rx) = create_packet_recv_chan();
    let (server_tx, mut server_rx) = create_packet_recv_chan();
    let client_map = PeerMap::new(client_tx, client_ctx, 1);
    let server_map = PeerMap::new(server_tx, server_ctx, 2);

    client_map.add_new_peer_conn(client_conn_a).await.unwrap();
    client_map.add_new_peer_conn(client_conn_b).await.unwrap();
    server_map.add_new_peer_conn(server_conn_a).await.unwrap();
    server_map.add_new_peer_conn(server_conn_b).await.unwrap();

    let mut first_packet = ZCPacket::new_with_payload(b"first");
    first_packet.fill_peer_manager_hdr(1, 2, PacketType::Data as u8);
    client_map.send_msg_directly(first_packet, 2).await.unwrap();
    let first_received = timeout(Duration::from_secs(1), server_rx.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(first_received.payload(), b"first");

    let first_conn_id = client_map.get_peer_default_conn_id(2).await.unwrap();
    assert_ne!(first_conn_id, PeerConnId::default());
    client_map.close_peer_conn(2, &first_conn_id).await.unwrap();
    timeout(Duration::from_secs(1), async {
        while client_map.get_peer_default_conn_id(2).await == Some(first_conn_id) {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();

    let mut second_packet = ZCPacket::new_with_payload(b"second");
    second_packet.fill_peer_manager_hdr(1, 2, PacketType::Data as u8);
    client_map
        .send_msg_directly(second_packet, 2)
        .await
        .unwrap();
    let second_received = timeout(Duration::from_secs(1), server_rx.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(second_received.payload(), b"second");
    assert_ne!(
        client_map.get_peer_default_conn_id(2).await,
        Some(first_conn_id)
    );
}

// --- secret-challenge-v2 (crypto-review N2: stretched proof keys) ---

/// Test-local reimplementation of the `secret-challenge-v2` transcript
/// format. Keeping an independent copy here catches accidental drift in the
/// production builder, which would silently break interop between builds.
fn v2_transcript(
    role: &[u8],
    network_name: &str,
    initiator_peer_id: u32,
    responder_peer_id: u32,
    initiator_nonce: &[u8],
    responder_nonce: &[u8],
    initiator_features: &[String],
    responder_features: &[String],
) -> Vec<u8> {
    fn put_len_prefixed(buf: &mut Vec<u8>, bytes: &[u8]) {
        buf.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
        buf.extend_from_slice(bytes);
    }
    // Sorted, length-prefixed feature lists mirroring the production
    // canonical encoding (crypto-review N3).
    fn canonical_features(features: &[String]) -> Vec<u8> {
        let mut sorted: Vec<&str> = features.iter().map(String::as_str).collect();
        sorted.sort_unstable();
        let mut buf = Vec::new();
        buf.extend_from_slice(&(sorted.len() as u32).to_be_bytes());
        for feature in sorted {
            buf.extend_from_slice(&(feature.len() as u32).to_be_bytes());
            buf.extend_from_slice(feature.as_bytes());
        }
        buf
    }

    let mut buf = Vec::new();
    buf.extend_from_slice(b"easytier-legacy-hs-challenge-v2");
    buf.extend_from_slice(role);
    put_len_prefixed(&mut buf, network_name.as_bytes());
    buf.extend_from_slice(&initiator_peer_id.to_be_bytes());
    buf.extend_from_slice(&responder_peer_id.to_be_bytes());
    put_len_prefixed(&mut buf, initiator_nonce);
    put_len_prefixed(&mut buf, responder_nonce);
    put_len_prefixed(&mut buf, &canonical_features(initiator_features));
    put_len_prefixed(&mut buf, &canonical_features(responder_features));
    buf
}

fn hmac_sha256(key: &[u8], transcript: &[u8]) -> [u8; 32] {
    use hmac::Mac;
    let mut mac = hmac::Hmac::<sha2::Sha256>::new_from_slice(key).unwrap();
    mac.update(transcript);
    mac.finalize().into_bytes().into()
}

/// Parses a captured handshake packet into its protobuf form.
fn parse_handshake(pkt: &ZCPacket) -> HandshakeRequest {
    HandshakeRequest::decode(pkt.payload()).unwrap()
}

#[test]
fn challenge_v2_stretched_proof_is_not_recomputable_from_the_raw_secret() {
    // Pure-property check for N2: the v2 proof key must be the argon2id
    // stretched secret, never the raw secret bytes (guards against
    // implementation regressions to the v1 keying).
    let features = ["a".to_string(), "b".to_string()];
    let transcript = v2_transcript(
        b":initiator",
        "net",
        1,
        2,
        &[1u8; 32],
        &[2u8; 32],
        &features,
        &features,
    );
    let stretched = hmac_sha256(&derive_challenge_key_argon2id("secret"), &transcript);
    let raw = hmac_sha256(b"secret", &transcript);
    assert_ne!(stretched, raw);
    assert_eq!(
        stretched,
        hmac_sha256(&derive_challenge_key_argon2id("secret"), &transcript)
    );
}

#[tokio::test]
async fn challenge_v2_handshake_proves_with_stretched_key() {
    // Both sides are current builds, so the handshake must negotiate v2 and
    // both proofs must verify under the argon2id-stretched key. The proofs
    // are recomputed here from the captured wire to pin the actual version,
    // keying, and feature binding used on the wire.
    let (client_tunnel, server_tunnel, client_log, server_log) = recording_channel_tunnel_pair();
    let mut client = PeerConn::new(
        1,
        secret_context("secret"),
        client_tunnel,
        Arc::new(PeerSessionStore::new()),
    );
    let mut server = PeerConn::new(
        2,
        secret_context("secret"),
        server_tunnel,
        Arc::new(PeerSessionStore::new()),
    );
    let (client_ret, server_ret) = tokio::join!(
        client.do_handshake_as_client(),
        server.do_handshake_as_server()
    );
    client_ret.unwrap();
    server_ret.unwrap();

    let client_packets = handshake_packets(&client_log);
    let server_packets = handshake_packets(&server_log);
    assert_eq!(client_packets.len(), 2); // msg1, msg3
    assert_eq!(server_packets.len(), 1); // msg2
    let msg1 = parse_handshake(&client_packets[0]);
    let msg2 = parse_handshake(&server_packets[0]);
    let msg3 = parse_handshake(&client_packets[1]);

    assert!(
        msg1.features
            .contains(&SECRET_CHALLENGE_V2_FEATURE.to_string())
    );
    assert!(
        msg2.features
            .contains(&SECRET_CHALLENGE_V2_FEATURE.to_string())
    );

    let stretched = derive_challenge_key_argon2id("secret");
    let expected = |role: &[u8], proof_features: &[Vec<String>]| {
        hmac_sha256(
            &stretched,
            &v2_transcript(
                role,
                "net",
                1,
                2,
                &msg1.challenge_nonce,
                &msg2.challenge_nonce,
                &proof_features[0],
                &proof_features[1],
            ),
        )
    };
    // Both proofs bind both feature declarations as seen on the wire.
    let wire_features = [msg1.features.clone(), msg2.features.clone()];
    assert_eq!(
        msg2.secret_proof,
        expected(b":responder", &wire_features).to_vec()
    );
    assert_eq!(
        msg3.secret_proof,
        expected(b":initiator", &wire_features).to_vec()
    );

    // The same proofs must NOT verify under v1 keying: they are stretched,
    // not raw-secret HMACs.
    let raw_secret_proof = |role: &[u8]| {
        use hmac::Mac;
        crate::peers::context::secret_proof_from_secret(
            "secret",
            &v2_transcript(
                role,
                "net",
                1,
                2,
                &msg1.challenge_nonce,
                &msg2.challenge_nonce,
                &msg1.features,
                &msg2.features,
            ),
        )
        .unwrap()
        .finalize()
        .into_bytes()
        .to_vec()
    };
    assert_ne!(msg2.secret_proof, raw_secret_proof(b":responder"));
    assert_ne!(msg3.secret_proof, raw_secret_proof(b":initiator"));
}

/// Handshake rewriter simulating an active relay (crypto-review N3): every
/// handshake packet is decoded, mutated, and re-encoded in flight. The
/// rewrite callback receives the direction (`true` = initiator to
/// responder) so tests can tamper one or both directions.
type HandshakeRewrite = Box<dyn Fn(bool, &mut HandshakeRequest) + Send + Sync>;

fn mitm_rewriting_tunnel_pair(rewrite: HandshakeRewrite) -> (Box<dyn Tunnel>, Box<dyn Tunnel>) {
    fn endpoint(
        tx: tokio::sync::mpsc::UnboundedSender<ZCPacket>,
        rx: tokio::sync::mpsc::UnboundedReceiver<ZCPacket>,
    ) -> Box<dyn Tunnel> {
        let sink = futures::sink::unfold(tx, |tx, pkt: ZCPacket| async move {
            tx.send(pkt).map_err(|_| TunnelError::Shutdown).map(|_| tx)
        });
        let stream = futures::stream::unfold(rx, |mut rx| async move {
            rx.recv().await.map(|pkt| (Ok(pkt), rx))
        });
        Box::new(TunnelWrapper::new(Box::pin(stream), Box::pin(sink), None))
    }

    fn channel() -> (
        tokio::sync::mpsc::UnboundedSender<ZCPacket>,
        tokio::sync::mpsc::UnboundedReceiver<ZCPacket>,
    ) {
        tokio::sync::mpsc::unbounded_channel()
    }

    let (c_out_tx, mut c_out_rx) = channel(); // client -> mitm
    let (s_in_tx, s_in_rx) = channel(); // mitm -> server
    let (s_out_tx, mut s_out_rx) = channel(); // server -> mitm
    let (c_in_tx, c_in_rx) = channel(); // mitm -> client

    let client = endpoint(c_out_tx, c_in_rx);
    let server = endpoint(s_out_tx, s_in_rx);

    let rewrite = std::sync::Arc::new(rewrite);
    tokio::spawn(async move {
        fn forward(
            pkt: ZCPacket,
            initiator_to_responder: bool,
            rewrite: &HandshakeRewrite,
        ) -> ZCPacket {
            let is_handshake = pkt
                .peer_manager_header()
                .is_some_and(|hdr| hdr.packet_type == PacketType::HandShake as u8);
            if !is_handshake {
                return pkt;
            }
            let mut req = HandshakeRequest::decode(pkt.payload()).unwrap();
            rewrite(initiator_to_responder, &mut req);
            let mut out = ZCPacket::new_with_payload(&req.encode_to_vec());
            out.fill_peer_manager_hdr(
                pkt.peer_manager_header().unwrap().from_peer_id.get(),
                pkt.peer_manager_header().unwrap().to_peer_id.get(),
                PacketType::HandShake as u8,
            );
            out
        }

        loop {
            tokio::select! {
                pkt = c_out_rx.recv() => {
                    let Some(pkt) = pkt else { break };
                    if s_in_tx.send(forward(pkt, true, &rewrite)).is_err() {
                        break;
                    }
                }
                pkt = s_out_rx.recv() => {
                    let Some(pkt) = pkt else { break };
                    if c_in_tx.send(forward(pkt, false, &rewrite)).is_err() {
                        break;
                    }
                }
            }
        }
    });

    (client, server)
}

/// Runs a secret-gated legacy handshake through a rewriting relay and
/// returns both handshake results.
async fn mitm_handshake(rewrite: HandshakeRewrite) -> (Result<(), Error>, Result<(), Error>) {
    let (client_tunnel, server_tunnel) = mitm_rewriting_tunnel_pair(rewrite);
    let mut client = PeerConn::new(
        1,
        secret_context("secret"),
        client_tunnel,
        Arc::new(PeerSessionStore::new()),
    );
    let mut server = PeerConn::new(
        2,
        secret_context("secret"),
        server_tunnel,
        Arc::new(PeerSessionStore::new()),
    );
    tokio::join!(
        client.do_handshake_as_client(),
        server.do_handshake_as_server()
    )
}

fn strip_feature(feature: &str) -> impl Fn(bool, &mut HandshakeRequest) + Send + Sync + '_ {
    move |_initiator_to_responder, req| {
        req.features.retain(|f| f != feature);
    }
}

#[tokio::test]
async fn challenge_v2_peers_fall_back_to_v1_when_relay_strips_v2() {
    // A relay (or a genuine pre-v2 peer) removes secret-challenge-v2 in both
    // directions: both sides still declare secret-challenge-v1, so they fall
    // back to the v1 flow and the handshake succeeds (interop preserved).
    let (client_ret, server_ret) =
        mitm_handshake(Box::new(strip_feature(SECRET_CHALLENGE_V2_FEATURE))).await;
    client_ret.unwrap();
    server_ret.unwrap();
}

#[tokio::test]
async fn challenge_v2_rejects_relay_stripping_kdf_v2_from_the_initiator() {
    // crypto-review N3: a malicious relay strips kdf-v2 from the initiator's
    // declaration (initiator -> responder direction only). The responder
    // proves over the stripped list it saw, the initiator recomputes with its
    // own intact list, and the proof mismatch refuses the downgraded
    // handshake instead of silently falling back to SipHash keys.
    let strip_one_direction = |feature: &'static str| {
        move |initiator_to_responder: bool, req: &mut HandshakeRequest| {
            if initiator_to_responder {
                req.features.retain(|f| f != feature);
            }
        }
    };
    let (client_ret, server_ret) =
        mitm_handshake(Box::new(strip_one_direction(KDF_V2_FEATURE))).await;
    assert!(
        matches!(client_ret.unwrap_err(), Error::SecretKeyError(e) if e.contains("proof mismatch")),
        "the initiator must reject the tampered proof"
    );
    // The responder fails too: the initiator never sends a valid msg3 after
    // rejecting msg2 (timeout or closed conn).
    assert!(server_ret.is_err());
}

#[tokio::test]
async fn challenge_v2_rejects_relay_stripping_kdf_v2_from_the_responder() {
    // Same attack on the responder -> initiator direction: the responder
    // signed its full feature list, the initiator verifies against the
    // stripped list it received, and the proof fails.
    let strip_one_direction = |feature: &'static str| {
        move |initiator_to_responder: bool, req: &mut HandshakeRequest| {
            if !initiator_to_responder {
                req.features.retain(|f| f != feature);
            }
        }
    };
    let (client_ret, server_ret) =
        mitm_handshake(Box::new(strip_one_direction(KDF_V2_FEATURE))).await;
    assert!(
        matches!(client_ret.unwrap_err(), Error::SecretKeyError(e) if e.contains("proof mismatch")),
        "the initiator must reject the stripped responder declaration"
    );
    assert!(server_ret.is_err());
}

#[test]
fn canonical_feature_encoding_is_order_independent_and_unambiguous() {
    use crate::peers::conn::peer_conn::canonical_features;

    let a = ["kdf-v2".to_string(), "header-aad-v1".to_string()];
    let b = ["header-aad-v1".to_string(), "kdf-v2".to_string()];
    assert_eq!(canonical_features(&a), canonical_features(&b));

    // Length prefixes keep concatenated and split lists distinct: no two
    // different declarations may produce the same transcript bytes.
    let concatenated = ["kdf-v2header-aad-v1".to_string()];
    let split = ["kdf-v2header-aad".to_string(), "-v1".to_string()];
    assert_ne!(
        canonical_features(&concatenated),
        canonical_features(&split)
    );
}

// --- strict_crypto (crypto-review batch 2: reject legacy crypto downgrade) ---

/// Secret-gated context with the network option `strict_crypto` enabled.
fn strict_secret_context(secret: &str) -> Arc<NoopPeerContext> {
    Arc::new(
        NoopPeerContext::new(NetworkIdentity {
            network_name: "net".to_string(),
            network_secret: Some(secret.to_string()),
            network_secret_digest: None,
        })
        .with_strict_crypto(true),
    )
}

/// Test-local reimplementation of the `secret-challenge-v1` transcript, kept
/// independent from the production builder for the same reason as
/// [`v2_transcript`].
fn v1_transcript(
    role: &[u8],
    network_name: &str,
    initiator_peer_id: u32,
    responder_peer_id: u32,
    initiator_nonce: &[u8],
    responder_nonce: &[u8],
) -> Vec<u8> {
    fn put_len_prefixed(buf: &mut Vec<u8>, bytes: &[u8]) {
        buf.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
        buf.extend_from_slice(bytes);
    }

    let mut buf = Vec::new();
    buf.extend_from_slice(b"easytier-legacy-hs-challenge-v1");
    buf.extend_from_slice(role);
    put_len_prefixed(&mut buf, network_name.as_bytes());
    buf.extend_from_slice(&initiator_peer_id.to_be_bytes());
    buf.extend_from_slice(&responder_peer_id.to_be_bytes());
    put_len_prefixed(&mut buf, initiator_nonce);
    put_len_prefixed(&mut buf, responder_nonce);
    buf
}

/// The declaration a genuine peer missing exactly `feature` would send: the
/// current build's feature list without that one entry.
fn declaration_without(feature: &str) -> Vec<String> {
    [
        "liveness-echo-v1",
        HEADER_AAD_FEATURE,
        KDF_V2_FEATURE,
        SECRET_CHALLENGE_FEATURE,
        SECRET_CHALLENGE_V2_FEATURE,
    ]
    .iter()
    .filter(|f| **f != feature)
    .map(|f| f.to_string())
    .collect()
}

/// Proof of `role` over the two declarations exactly as a genuine peer that
/// declares `own_features` computes it: v2 (argon2id-stretched, feature
/// bound) when both declarations carry v2, v1 (raw-secret) otherwise.
#[allow(clippy::too_many_arguments)]
fn genuine_peer_proof(
    role: &[u8],
    initiator_features: &[String],
    responder_features: &[String],
    initiator_nonce: &[u8],
    responder_nonce: &[u8],
) -> Vec<u8> {
    use hmac::Mac;
    let use_v2 = initiator_features
        .iter()
        .chain(responder_features.iter())
        .filter(|f| **f == SECRET_CHALLENGE_V2_FEATURE)
        .count()
        == 2;
    if use_v2 {
        hmac_sha256(
            &derive_challenge_key_argon2id("secret"),
            &v2_transcript(
                role,
                "net",
                1,
                2,
                initiator_nonce,
                responder_nonce,
                initiator_features,
                responder_features,
            ),
        )
        .to_vec()
    } else {
        crate::peers::context::secret_proof_from_secret(
            "secret",
            &v1_transcript(role, "net", 1, 2, initiator_nonce, responder_nonce),
        )
        .unwrap()
        .finalize()
        .into_bytes()
        .to_vec()
    }
}

fn handshake_packet(req: &HandshakeRequest, from: u32, to: u32) -> ZCPacket {
    let mut pkt = ZCPacket::new_with_payload(&req.encode_to_vec());
    pkt.fill_peer_manager_hdr(from, to, PacketType::HandShake as u8);
    pkt
}

/// Runs a strict initiator against a scripted responder that consistently
/// declares `responder_features` (its proofs are recomputed over its own
/// list, so it behaves like a genuine older build, not a tampering relay).
/// Returns the initiator's handshake result.
async fn strict_initiator_vs_scripted_responder(
    responder_features: Vec<String>,
) -> Result<(), Error> {
    let (client_tunnel, scripted_tunnel, _, _) = recording_channel_tunnel_pair();
    let mut client = PeerConn::new(
        1,
        strict_secret_context("secret"),
        client_tunnel,
        Arc::new(PeerSessionStore::new()),
    );
    let client_task = tokio::spawn(async move { client.do_handshake_as_client().await });

    let (mut stream, mut sink) = scripted_tunnel.split();
    let msg1 = timeout(Duration::from_secs(2), stream.next())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    let msg1_req = parse_handshake(&msg1);

    let responder_nonce = [3u8; 32];
    let rsp = HandshakeRequest {
        magic: 0xd1e1a5e1,
        my_peer_id: 2,
        version: 1,
        secret_proof: genuine_peer_proof(
            b":responder",
            &msg1_req.features,
            &responder_features,
            &msg1_req.challenge_nonce,
            &responder_nonce,
        ),
        challenge_nonce: responder_nonce.to_vec(),
        features: responder_features,
        network_name: "net".to_owned(),
        network_secret_digest: vec![0u8; 32],
    };
    sink.send(handshake_packet(&rsp, 2, 1)).await.unwrap();

    timeout(Duration::from_secs(2), client_task)
        .await
        .unwrap()
        .unwrap()
}

/// Runs a strict responder against a scripted initiator that consistently
/// declares `initiator_features`. Returns the responder's handshake result.
async fn strict_responder_vs_scripted_initiator(
    initiator_features: Vec<String>,
) -> Result<(), Error> {
    let (scripted_tunnel, server_tunnel, _, _) = recording_channel_tunnel_pair();
    let mut server = PeerConn::new(
        2,
        strict_secret_context("secret"),
        server_tunnel,
        Arc::new(PeerSessionStore::new()),
    );
    let server_task = tokio::spawn(async move { server.do_handshake_as_server().await });

    let (mut stream, mut sink) = scripted_tunnel.split();
    let initiator_nonce = [4u8; 32];
    let req = HandshakeRequest {
        magic: 0xd1e1a5e1,
        my_peer_id: 1,
        version: 1,
        features: initiator_features.clone(),
        network_name: "net".to_owned(),
        network_secret_digest: vec![0u8; 32],
        challenge_nonce: initiator_nonce.to_vec(),
        secret_proof: vec![],
    };
    sink.send(handshake_packet(&req, 1, 0)).await.unwrap();

    let msg2 = timeout(Duration::from_secs(2), stream.next())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    let msg2_req = parse_handshake(&msg2);

    let msg3 = HandshakeRequest {
        magic: 0xd1e1a5e1,
        my_peer_id: 1,
        version: 1,
        features: initiator_features.clone(),
        network_name: "net".to_owned(),
        network_secret_digest: vec![0u8; 32],
        challenge_nonce: initiator_nonce.to_vec(),
        secret_proof: genuine_peer_proof(
            b":initiator",
            &initiator_features,
            &msg2_req.features,
            &initiator_nonce,
            &msg2_req.challenge_nonce,
        ),
    };
    sink.send(handshake_packet(&msg3, 1, 2)).await.unwrap();

    timeout(Duration::from_secs(2), server_task)
        .await
        .unwrap()
        .unwrap()
}

#[tokio::test]
async fn strict_crypto_accepts_fully_negotiated_handshake() {
    // Both sides strict, both sides current builds: the full suite is
    // negotiated and the connection is established normally.
    let (client_tunnel, server_tunnel) = create_ring_tunnel_pair();
    let mut client = PeerConn::new(
        1,
        strict_secret_context("secret"),
        client_tunnel,
        Arc::new(PeerSessionStore::new()),
    );
    let mut server = PeerConn::new(
        2,
        strict_secret_context("secret"),
        server_tunnel,
        Arc::new(PeerSessionStore::new()),
    );
    let (client_ret, server_ret) = tokio::join!(
        client.do_handshake_as_client(),
        server.do_handshake_as_server()
    );
    client_ret.unwrap();
    server_ret.unwrap();
    assert!(client.supports_header_aad() && client.supports_kdf_v2());
    assert!(server.supports_header_aad() && server.supports_kdf_v2());
}

#[tokio::test]
async fn strict_crypto_initiator_rejects_responder_missing_required_features() {
    // A strict initiator must refuse a peer whose declaration misses any one
    // of the required features, naming the missing one.
    for feature in [
        SECRET_CHALLENGE_V2_FEATURE,
        KDF_V2_FEATURE,
        HEADER_AAD_FEATURE,
    ] {
        let ret = strict_initiator_vs_scripted_responder(declaration_without(feature)).await;
        assert!(
            matches!(&ret, Err(Error::SecretKeyError(e)) if e.contains("strict_crypto") && e.contains(feature)),
            "missing {feature} must be rejected with the feature named, got: {ret:?}"
        );
    }
}

#[tokio::test]
async fn strict_crypto_responder_rejects_initiator_missing_required_features() {
    // Same policy on the responder side: the challenge itself still verifies
    // (the scripted initiator is genuine), so only the strict check rejects.
    for feature in [
        SECRET_CHALLENGE_V2_FEATURE,
        KDF_V2_FEATURE,
        HEADER_AAD_FEATURE,
    ] {
        let ret = strict_responder_vs_scripted_initiator(declaration_without(feature)).await;
        assert!(
            matches!(&ret, Err(Error::SecretKeyError(e)) if e.contains("strict_crypto") && e.contains(feature)),
            "missing {feature} must be rejected with the feature named, got: {ret:?}"
        );
    }
}

#[tokio::test]
async fn strict_crypto_rejects_relay_downgrade_of_secret_challenge_v2() {
    // A stripping relay (or a genuine v1-only peer) forces the v2 -> v1
    // fallback; v1 proofs carry no features so the challenge still verifies,
    // and both strict sides must refuse the connection naming the missing
    // feature. With strict_crypto off this is the accepted interop fallback
    // covered by challenge_v2_peers_fall_back_to_v1_when_relay_strips_v2.
    let (client_tunnel, server_tunnel) =
        mitm_rewriting_tunnel_pair(Box::new(strip_feature(SECRET_CHALLENGE_V2_FEATURE)));
    let mut client = PeerConn::new(
        1,
        strict_secret_context("secret"),
        client_tunnel,
        Arc::new(PeerSessionStore::new()),
    );
    let mut server = PeerConn::new(
        2,
        strict_secret_context("secret"),
        server_tunnel,
        Arc::new(PeerSessionStore::new()),
    );
    let (client_ret, server_ret) = tokio::join!(
        client.do_handshake_as_client(),
        server.do_handshake_as_server()
    );
    for ret in [client_ret, server_ret] {
        assert!(
            matches!(&ret, Err(Error::SecretKeyError(e)) if e.contains("strict_crypto") && e.contains(SECRET_CHALLENGE_V2_FEATURE)),
            "the v2 downgrade must be rejected with the feature named, got: {ret:?}"
        );
    }
}

#[tokio::test]
async fn strict_crypto_leaves_secure_mode_handshake_unaffected() {
    // Secure mode authenticates with a noise transcript and per-session keys
    // and never relies on the legacy feature suite, so a strict node must
    // keep accepting noise handshakes.
    fn strict_secure_context(peer_key: u8) -> Arc<NoopPeerContext> {
        let private = StaticSecret::from([peer_key; 32]);
        let public = PublicKey::from(&private);
        Arc::new(
            NoopPeerContext::new(NetworkIdentity {
                network_name: "net".to_owned(),
                network_secret: Some("secret".to_owned()),
                network_secret_digest: None,
            })
            .with_secure_mode(crate::proto::common::SecureModeConfig {
                enabled: true,
                local_private_key: Some(BASE64_STANDARD.encode(private.as_bytes())),
                local_public_key: Some(BASE64_STANDARD.encode(public.as_bytes())),
            })
            .with_strict_crypto(true),
        )
    }

    let (client_tunnel, server_tunnel) = create_ring_tunnel_pair();
    let mut client = PeerConn::new(
        1,
        strict_secure_context(1),
        client_tunnel,
        Arc::new(PeerSessionStore::new()),
    );
    let mut server = PeerConn::new(
        2,
        strict_secure_context(2),
        server_tunnel,
        Arc::new(PeerSessionStore::new()),
    );
    let (client_ret, server_ret) = tokio::join!(
        client.do_handshake_as_client(),
        server.do_handshake_as_server()
    );
    client_ret.unwrap();
    server_ret.unwrap();
}
