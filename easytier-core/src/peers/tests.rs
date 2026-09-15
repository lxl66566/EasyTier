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
            peer_conn::{PeerConn, PeerConnId, SECRET_CHALLENGE_FEATURE},
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
    tunnel::{Tunnel, TunnelError, ring::create_ring_tunnel_pair, wrapper::TunnelWrapper},
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
            "secret-challenge-v1"
        ]
    );
    assert_eq!(
        server.get_conn_info().features,
        [
            "liveness-echo-v1",
            "header-aad-v1",
            "kdf-v2",
            "secret-challenge-v1"
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
            "secret-challenge-v1"
        ]
    );
    assert_eq!(
        server.get_conn_info().features,
        [
            "liveness-echo-v1",
            "header-aad-v1",
            "kdf-v2",
            "secret-challenge-v1"
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
