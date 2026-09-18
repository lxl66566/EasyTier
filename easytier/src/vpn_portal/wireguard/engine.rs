//! Shared WireGuard packet engine for named portal clients.

use atomic_shim::AtomicU64;
use std::{
    collections::{BTreeSet, HashMap},
    net::SocketAddr,
    sync::{
        Arc, RwLock,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use boringtun::{
    noise::{
        Packet, Tunn, TunnResult, errors::WireGuardError, handshake::parse_handshake_anon,
        rate_limiter::RateLimiter,
    },
    x25519::{PublicKey, StaticSecret},
};
use bytes::{Bytes, BytesMut};
use easytier_core::{
    gateway::vpn_portal::{PortalClientConfig, PortalSession},
    socket::udp::VirtualUdpSocket,
};
use rand::rngs::OsRng;
use tokio::{
    sync::{Mutex, mpsc, watch},
    task::JoinSet,
};
use tokio_util::sync::CancellationToken;

use crate::socket::udp::RuntimeUdpSocket;
const MIN_WIREGUARD_PACKET_CAPACITY: usize = 148;
// We pre-verify through this shared limiter and BoringTun verifies again inside
// each Tunn. Doubling the threshold preserves the intended 100 datagrams/s
// transition to cookies while retaining the upstream security ordering.
const DOUBLE_VERIFY_HANDSHAKE_LIMIT: u64 = 200;
const TIMER_INTERVAL: Duration = Duration::from_millis(250);
const PORTAL_PACKET_CAPACITY: usize = 128;
/// Fresh decapsulation scratch chunks reserve this much capacity so the tail
/// survives several packets between allocations. Only the datagram-sized
/// prefix is ever initialized or touched.
const SCRATCH_CHUNK_CAPACITY: usize = 8 * 1024;
/// Upper bound of downlink packets encrypted under one session-lock
/// acquisition while draining an already-queued backlog.
const ENCAPSULATE_BATCH_CAPACITY: usize = 16;
#[derive(Clone)]
pub(super) struct DerivedClient {
    pub(super) config: PortalClientConfig,
    pub(super) wireguard_private: [u8; 32],
    pub(super) wireguard_public: PublicKey,
}

struct PortalChannels {
    endpoint: watch::Receiver<String>,
    from_client: mpsc::Receiver<Bytes>,
    to_client: mpsc::Sender<Bytes>,
}

struct ClientSession {
    generation: u64,
    identity_private_key: [u8; 32],
    endpoint: Option<Endpoint>,
    endpoint_updates: watch::Sender<String>,
    tunnel: Tunn,
    from_client: mpsc::Sender<Bytes>,
    /// Reusable decapsulation output chunk. Owned by the session (guarded by
    /// the session mutex, i.e. held only while `handle_datagram` runs) so the
    /// receive path never allocates per datagram.
    decapsulate_scratch: BytesMut,
    portal_channels: Option<PortalChannels>,
    drain_capacity: usize,
    tasks: JoinSet<()>,
}

struct ClientSlot {
    client: DerivedClient,
    index: u32,
    next_generation: AtomicU64,
    session: Mutex<Option<ClientSession>>,
    retired: AtomicBool,
}

#[derive(Default)]
struct EngineSlots {
    by_name: HashMap<String, Arc<ClientSlot>>,
    by_public_key: HashMap<[u8; 32], Arc<ClientSlot>>,
    by_index: HashMap<u32, Arc<ClientSlot>>,
    free_indices: BTreeSet<u32>,
    highest_index: u32,
}

impl EngineSlots {
    fn allocate_index(&mut self) -> anyhow::Result<u32> {
        if let Some(index) = self.free_indices.pop_first() {
            return Ok(index);
        }
        let next = self
            .highest_index
            .checked_add(1)
            .ok_or_else(|| anyhow::anyhow!("WireGuard portal client index space is exhausted"))?;
        self.highest_index = next;
        Ok(next)
    }
}

#[derive(Clone)]
struct Endpoint {
    socket: Arc<RuntimeUdpSocket>,
    remote: SocketAddr,
}

impl ClientSession {
    fn update_endpoint(&mut self, socket: Arc<RuntimeUdpSocket>, remote: SocketAddr) {
        let changed = self
            .endpoint
            .as_ref()
            .is_none_or(|endpoint| endpoint.remote != remote);
        self.endpoint = Some(Endpoint { socket, remote });
        if changed {
            self.endpoint_updates.send_replace(remote.to_string());
        }
    }
}

pub(super) struct PortalEngine {
    server_private: StaticSecret,
    server_public: PublicKey,
    rate_limiter: Arc<RateLimiter>,
    slots: RwLock<EngineSlots>,
    accepted: mpsc::UnboundedSender<PortalSession>,
    cancel: CancellationToken,
}

impl PortalEngine {
    pub(super) fn new(
        server_private: [u8; 32],
        clients: Vec<DerivedClient>,
        accepted: mpsc::UnboundedSender<PortalSession>,
    ) -> Arc<Self> {
        let server_private = StaticSecret::from(server_private);
        let server_public = PublicKey::from(&server_private);
        let mut slots = EngineSlots::default();
        for client in clients {
            let public = *client.wireguard_public.as_bytes();
            let index = slots
                .allocate_index()
                .expect("initial portal clients fit the index space");
            let slot = Arc::new(ClientSlot {
                client,
                index,
                next_generation: AtomicU64::new(1),
                session: Mutex::new(None),
                retired: AtomicBool::new(false),
            });
            slots
                .by_name
                .insert(slot.client.config.name.clone(), slot.clone());
            slots.by_public_key.insert(public, slot.clone());
            slots.by_index.insert(index, slot);
        }
        Arc::new(Self {
            server_private,
            server_public,
            rate_limiter: Arc::new(RateLimiter::new(
                &server_public,
                DOUBLE_VERIFY_HANDSHAKE_LIMIT,
            )),
            slots: RwLock::new(slots),
            accepted,
            cancel: CancellationToken::new(),
        })
    }

    pub(super) fn add_client(&self, client: DerivedClient) -> anyhow::Result<()> {
        let public = *client.wireguard_public.as_bytes();
        let name = client.config.name.clone();
        let mut slots = self.slots.write().unwrap();
        if slots.by_name.contains_key(&name) || slots.by_public_key.contains_key(&public) {
            anyhow::bail!("WireGuard portal client {name} already exists");
        }
        let index = slots.allocate_index()?;
        let slot = Arc::new(ClientSlot {
            client,
            index,
            next_generation: AtomicU64::new(1),
            session: Mutex::new(None),
            retired: AtomicBool::new(false),
        });
        slots.by_name.insert(name, slot.clone());
        slots.by_public_key.insert(public, slot.clone());
        slots.by_index.insert(index, slot);
        Ok(())
    }

    /// Removes a client by name. Any active session is expired so Core tears
    /// down the attached peer through its regular channel-close path.
    pub(super) async fn remove_client(&self, name: &str) -> bool {
        let slot = {
            let mut slots = self.slots.write().unwrap();
            slots.by_name.remove(name).inspect(|slot| {
                slot.retired.store(true, Ordering::Relaxed);
                let public = *slot.client.wireguard_public.as_bytes();
                slots.by_public_key.remove(&public);
                slots.by_index.remove(&slot.index);
                slots.free_indices.insert(slot.index);
            })
        };
        let Some(slot) = slot else {
            return false;
        };
        let expired = slot.session.lock().await.take();
        Self::retire_session(expired);
        true
    }

    pub(super) fn cancel(&self) {
        self.cancel.cancel();
    }
    pub(super) fn connection_count(&self) -> u32 {
        let slots = self.slots.read().unwrap();
        slots
            .by_index
            .values()
            .filter(|slot| {
                slot.session.try_lock().is_ok_and(|guard| {
                    guard
                        .as_ref()
                        .is_some_and(|session| session.portal_channels.is_none())
                })
            })
            .count() as u32
    }

    pub(super) async fn handle_datagram(
        self: &Arc<Self>,
        socket: Arc<RuntimeUdpSocket>,
        remote: SocketAddr,
        datagram: &[u8],
    ) {
        let mut cookie = [0u8; 148];
        let parsed = match self
            .rate_limiter
            .verify_packet(Some(remote.ip()), datagram, &mut cookie)
        {
            Ok(packet) => packet,
            Err(TunnResult::WriteToNetwork(reply)) => {
                let _ = socket.send_to(reply, remote).await;
                return;
            }
            Err(_) => return,
        };
        let slot = match &parsed {
            Packet::HandshakeInit(init) => {
                parse_handshake_anon(&self.server_private, &self.server_public, init)
                    .ok()
                    .and_then(|handshake| {
                        self.slots
                            .read()
                            .unwrap()
                            .by_public_key
                            .get(&handshake.peer_static_public)
                            .cloned()
                    })
            }
            Packet::HandshakeResponse(response) => self.slot_by_receiver(response.receiver_idx),
            Packet::PacketCookieReply(reply) => self.slot_by_receiver(reply.receiver_idx),
            Packet::PacketData(data) => self.slot_by_receiver(data.receiver_idx),
        };
        let Some(slot) = slot else { return };
        if slot.retired.load(Ordering::Relaxed) {
            return;
        }

        // Per-datagram session lock: boringtun's Tunn is a single mutable
        // object shared by this receive path and the encapsulation task, and
        // the mutex also orders the retired-slot re-check below, so it stays.
        let mut session = slot.session.lock().await;
        // Re-check after acquiring the lock: remove_client retires the slot
        // and drains the session under this same lock, so a datagram that
        // raced with removal cannot resurrect a session here.
        if slot.retired.load(Ordering::Relaxed) {
            return;
        }
        if session.is_none() {
            if !matches!(parsed, Packet::HandshakeInit(_)) {
                return;
            }
            *session = Some(self.new_session(&slot, socket.clone(), remote));
        }
        let current = session.as_mut().expect("created above");
        let is_data = matches!(&parsed, Packet::PacketData(_));
        let is_handshake_response = matches!(&parsed, Packet::HandshakeResponse(_));

        // The shared pre-verification establishes the correct upstream order.
        // Tunn::decapsulate performs a second MAC/cookie check because the
        // dependency's verified-dispatch method is not public.
        //
        // The decapsulation output is the session's reusable scratch chunk,
        // taken out of the session so boringtun's borrowed result slices do
        // not alias the session struct; it is restored on every path that
        // keeps the session alive. Decrypted packets are handed to Core as
        // frozen `Bytes` views split off the chunk, so the steady-state
        // uplink performs no per-packet allocation. Each split advances the
        // chunk tail; once the tail cannot hold the next datagram the chunk
        // is replaced instead of growing it without bound (live prefixes
        // stay pinned by the handed-off views until Core drops them). Only
        // the datagram-sized prefix is initialized, so a tiny
        // unauthenticated packet still cannot amplify into touching a
        // full-size buffer.
        let mut output = std::mem::take(&mut current.decapsulate_scratch);
        let output_len = datagram.len().max(MIN_WIREGUARD_PACKET_CAPACITY);
        if output.capacity() < output_len {
            output = BytesMut::with_capacity(output_len.max(SCRATCH_CHUNK_CAPACITY));
        }
        output.clear();
        output.resize(output_len, 0);
        let mut result = current
            .tunnel
            .decapsulate(Some(remote.ip()), datagram, &mut output);
        let mut first_result = true;
        loop {
            match result {
                TunnResult::Done => {
                    if is_data {
                        current.update_endpoint(socket.clone(), remote);
                        self.activate_client(&slot, current);
                    }
                    current.drain_capacity = MIN_WIREGUARD_PACKET_CAPACITY;
                    break;
                }
                TunnResult::Err(WireGuardError::ConnectionExpired) => {
                    // The expired session is dropped below, taking the
                    // (emptied) scratch field with it; the chunk held locally
                    // is simply freed, which only costs a fresh chunk on the
                    // next session's first datagram.
                    let expired = session.take();
                    drop(session);
                    Self::retire_session(expired);
                    return;
                }
                TunnResult::Err(_) => break,
                TunnResult::WriteToNetwork(packet) => {
                    if (first_result && is_handshake_response && is_transport_data_packet(packet))
                        || is_handshake_response_packet(packet)
                    {
                        current.update_endpoint(socket.clone(), remote);
                    }
                    let _ = socket.send_to(packet, remote).await;

                    // BoringTun queues a Core packet while it establishes a
                    // session. Its contract requires empty decapsulate calls
                    // after every network write until Done releases that queue.
                    first_result = false;
                    if output.len() < current.drain_capacity {
                        output.resize(current.drain_capacity, 0);
                    }
                    result = current.tunnel.decapsulate(None, &[], &mut output);
                }
                TunnResult::WriteToTunnelV4(packet, _) => {
                    current.update_endpoint(socket.clone(), remote);
                    self.activate_client(&slot, current);
                    // Zero-copy handoff: split the decrypted prefix off the
                    // scratch chunk and freeze it. The view pins only its own
                    // bytes while the scratch keeps reusing the chunk tail.
                    let payload_len = packet.len();
                    let payload = output.split_to(payload_len).freeze();
                    match current.from_client.try_send(payload) {
                        Ok(()) => {}
                        Err(mpsc::error::TrySendError::Full(_)) => {
                            tracing::debug!(
                                client = %slot.client.config.name,
                                "dropping WireGuard packet because the client queue is full"
                            );
                        }
                        Err(mpsc::error::TrySendError::Closed(_)) => {
                            let generation = current.generation;
                            drop(session);
                            self.expire_if_current(slot, generation).await;
                            return;
                        }
                    }
                    break;
                }
                TunnResult::WriteToTunnelV6(_, _) => {
                    // Portal traffic is deliberately IPv4-only.
                    break;
                }
            }
        }
        current.decapsulate_scratch = output;
    }

    fn activate_client(&self, slot: &ClientSlot, session: &mut ClientSession) {
        let Some(channels) = session.portal_channels.take() else {
            return;
        };
        let _ = self.accepted.send(PortalSession {
            client_name: slot.client.config.name.clone(),
            endpoint: channels.endpoint,
            identity_private_key: session.identity_private_key,
            from_client: channels.from_client,
            to_client: channels.to_client,
        });
    }

    fn slot_by_receiver(&self, receiver: u32) -> Option<Arc<ClientSlot>> {
        self.slots
            .read()
            .unwrap()
            .by_index
            .get(&(receiver >> 8))
            .cloned()
    }

    fn new_session(
        self: &Arc<Self>,
        slot: &Arc<ClientSlot>,
        socket: Arc<RuntimeUdpSocket>,
        remote: SocketAddr,
    ) -> ClientSession {
        let generation = slot.next_generation.fetch_add(1, Ordering::Relaxed);
        let (from_client, portal_from_client) = mpsc::channel(PORTAL_PACKET_CAPACITY);
        let (portal_to_client, mut to_client) = mpsc::channel::<Bytes>(PORTAL_PACKET_CAPACITY);
        let (endpoint_updates, portal_endpoint) = watch::channel(remote.to_string());
        let engine = Arc::downgrade(self);
        let slot_for_task = Arc::downgrade(slot);
        let mut tasks = JoinSet::new();
        tasks.spawn(async move {
            // Task-local send scratch: never shared with the receive path,
            // which owns its own scratch behind the session mutex.
            let mut scratch = Vec::new();
            // Reused drain buffer: packets already queued when the task wakes
            // are encrypted under a single session-lock acquisition instead
            // of one acquisition per packet.
            let mut batch = Vec::with_capacity(ENCAPSULATE_BATCH_CAPACITY);
            while let Some(payload) = to_client.recv().await {
                let Some(engine) = engine.upgrade() else {
                    return;
                };
                let Some(slot) = slot_for_task.upgrade() else {
                    return;
                };
                batch.push(payload);
                while batch.len() < ENCAPSULATE_BATCH_CAPACITY {
                    match to_client.try_recv() {
                        Ok(payload) => batch.push(payload),
                        Err(_) => break,
                    }
                }
                engine
                    .encapsulate_for_client(&slot, generation, &batch, &mut scratch)
                    .await;
                batch.clear();
            }
            if let (Some(engine), Some(slot)) = (engine.upgrade(), slot_for_task.upgrade()) {
                engine.expire_if_current(slot, generation).await;
            }
        });
        ClientSession {
            generation,
            identity_private_key: new_attached_identity_private_key(),
            endpoint: Some(Endpoint { socket, remote }),
            endpoint_updates,
            tunnel: Tunn::new(
                self.server_private.clone(),
                slot.client.wireguard_public,
                None,
                None,
                slot.index,
                Some(self.rate_limiter.clone()),
            ),
            from_client,
            decapsulate_scratch: BytesMut::new(),
            portal_channels: Some(PortalChannels {
                endpoint: portal_endpoint,
                from_client: portal_from_client,
                to_client: portal_to_client,
            }),
            drain_capacity: MIN_WIREGUARD_PACKET_CAPACITY,
            tasks,
        }
    }

    async fn encapsulate_for_client(
        self: &Arc<Self>,
        slot: &Arc<ClientSlot>,
        generation: u64,
        payloads: &[Bytes],
        scratch: &mut Vec<u8>,
    ) {
        // One lock acquisition covers the whole batch; the session cannot be
        // replaced while the guard is held, so the generation check runs once.
        let mut guard = slot.session.lock().await;
        let Some(session) = guard
            .as_mut()
            .filter(|session| session.generation == generation)
        else {
            return;
        };
        for payload in payloads {
            scratch.clear();
            scratch.resize(
                payload.len().saturating_add(MIN_WIREGUARD_PACKET_CAPACITY),
                0,
            );
            match session.tunnel.encapsulate(payload, scratch) {
                TunnResult::WriteToNetwork(packet) => {
                    if is_handshake_initiation(packet) {
                        session.drain_capacity =
                            session.drain_capacity.max(payload.len().saturating_add(32));
                    }
                    if let Some(endpoint) = session.endpoint.clone() {
                        let _ = endpoint.socket.send_to(packet, endpoint.remote).await;
                    }
                }
                TunnResult::Done => {
                    session.drain_capacity =
                        session.drain_capacity.max(payload.len().saturating_add(32));
                }
                TunnResult::Err(WireGuardError::ConnectionExpired) => {
                    // Remaining payloads are dropped: the expired session's
                    // generation check would reject them anyway.
                    drop(guard);
                    self.expire_if_current(slot.clone(), generation).await;
                    return;
                }
                _ => {}
            }
        }
    }

    async fn expire_if_current(self: &Arc<Self>, slot: Arc<ClientSlot>, generation: u64) {
        let expired = {
            let mut guard = slot.session.lock().await;
            if guard
                .as_ref()
                .is_some_and(|session| session.generation == generation)
            {
                guard.take()
            } else {
                None
            }
        };
        Self::retire_session(expired);
    }

    fn retire_session(expired: Option<ClientSession>) {
        if let Some(mut expired) = expired {
            expired.tasks.abort_all();
            // Dropping the ring sink atomically disconnects the matching Core
            // generation. A newer generation, if any, owns a different ring.
        }
    }

    pub(super) async fn run_timers(self: Arc<Self>) {
        let mut interval = tokio::time::interval(TIMER_INTERVAL);
        loop {
            tokio::select! {
                _ = self.cancel.cancelled() => return,
                _ = interval.tick() => {}
            }
            self.rate_limiter.reset_count();
            let slots = self
                .slots
                .read()
                .unwrap()
                .by_index
                .values()
                .cloned()
                .collect::<Vec<_>>();
            for slot in slots {
                let mut output = [0u8; 148];
                let mut guard = slot.session.lock().await;
                let Some(session) = guard.as_mut() else {
                    continue;
                };
                match session.tunnel.update_timers(&mut output) {
                    TunnResult::WriteToNetwork(packet) => {
                        if let Some(endpoint) = session.endpoint.clone() {
                            let _ = endpoint.socket.send_to(packet, endpoint.remote).await;
                        }
                    }
                    TunnResult::Err(WireGuardError::ConnectionExpired) => {
                        let expired = guard.take();
                        drop(guard);
                        Self::retire_session(expired);
                    }
                    _ => {}
                }
            }
        }
    }
}

fn new_attached_identity_private_key() -> [u8; 32] {
    StaticSecret::random_from_rng(OsRng).to_bytes()
}

fn is_handshake_initiation(packet: &[u8]) -> bool {
    packet.len() == 148 && packet.get(..4) == Some(&1u32.to_le_bytes())
}

fn is_handshake_response_packet(packet: &[u8]) -> bool {
    packet.len() == 92 && packet.get(..4) == Some(&2u32.to_le_bytes())
}

fn is_transport_data_packet(packet: &[u8]) -> bool {
    packet.len() >= 32 && packet.get(..4) == Some(&4u32.to_le_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    const MAX_TEST_DATAGRAM: usize = 65535;

    fn derived(name: &str, seed: u8) -> DerivedClient {
        let secret = StaticSecret::from([seed; 32]);
        DerivedClient {
            config: PortalClientConfig {
                name: name.to_owned(),
                virtual_ip: "10.82.0.2/24".parse().unwrap(),
                groups: Vec::new(),
            },
            wireguard_private: secret.to_bytes(),
            wireguard_public: PublicKey::from(&secret),
        }
    }

    #[test]
    fn attached_identity_is_unique_to_each_live_session() {
        assert_ne!(
            new_attached_identity_private_key(),
            new_attached_identity_private_key()
        );
    }

    fn slot_index(engine: &PortalEngine, name: &str) -> Option<u32> {
        engine
            .slots
            .read()
            .unwrap()
            .by_name
            .get(name)
            .map(|slot| slot.index)
    }

    #[tokio::test]
    async fn remove_client_drops_slot_and_recycles_index() {
        let (accepted, _receiver) = mpsc::unbounded_channel();
        let engine = PortalEngine::new([1; 32], vec![derived("a", 10), derived("b", 11)], accepted);
        assert_eq!(slot_index(&engine, "a"), Some(1));
        assert_eq!(slot_index(&engine, "b"), Some(2));

        assert!(engine.remove_client("a").await);
        assert!(!engine.remove_client("a").await);

        engine.add_client(derived("c", 12)).unwrap();
        assert_eq!(slot_index(&engine, "c"), Some(1), "freed index is reused");
        assert!(
            engine.add_client(derived("c", 13)).is_err(),
            "duplicate client name is rejected"
        );
        assert!(
            engine.add_client(derived("d", 11)).is_err(),
            "duplicate client public key is rejected"
        );

        engine.add_client(derived("d", 14)).unwrap();
        assert_eq!(slot_index(&engine, "d"), Some(3));
    }

    /// Minimal raw IPv4 packet: version/IHL, total length, protocol ICMP,
    /// source and destination addresses.
    fn raw_ipv4_packet(source: Ipv4Addr, destination: Ipv4Addr) -> Vec<u8> {
        let mut packet = vec![0u8; 28];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&28u16.to_be_bytes());
        packet[8] = 64;
        packet[9] = 1;
        packet[12..16].copy_from_slice(&source.octets());
        packet[16..20].copy_from_slice(&destination.octets());
        packet[20] = 8;
        packet
    }

    /// Loopback data-path test: a real boringtun client handshakes with the
    /// engine over loopback UDP sockets, one packet travels client-to-mesh
    /// and one travels mesh-to-client, exercising decapsulation (including
    /// the scratch `Bytes` handoff) and encapsulation end to end.
    #[tokio::test]
    async fn wireguard_datapath_loops_packets_both_ways() {
        let server_socket = {
            let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
            Arc::new(RuntimeUdpSocket::new(Arc::new(socket)))
        };
        let client_socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let client_addr = client_socket.local_addr().unwrap();

        let server_secret = StaticSecret::from([31; 32]);
        let client_secret = StaticSecret::from([21; 32]);
        let (accepted, mut accepted_rx) = mpsc::unbounded_channel();
        let engine = PortalEngine::new(
            server_secret.to_bytes(),
            vec![DerivedClient {
                config: PortalClientConfig {
                    name: "loop".to_owned(),
                    virtual_ip: "10.82.0.2/24".parse().unwrap(),
                    groups: Vec::new(),
                },
                wireguard_private: client_secret.to_bytes(),
                wireguard_public: PublicKey::from(&client_secret),
            }],
            accepted,
        );

        let mut client = Tunn::new(
            client_secret,
            PublicKey::from(&server_secret),
            None,
            None,
            0,
            None,
        );
        let mut client_buf = vec![0u8; MAX_TEST_DATAGRAM];

        // Handshake initiation from the client; the engine replies with a
        // handshake response addressed to the client endpoint.
        let TunnResult::WriteToNetwork(initiation) = client.encapsulate(&[], &mut client_buf)
        else {
            panic!("client did not produce a handshake initiation");
        };
        engine
            .handle_datagram(server_socket.clone(), client_addr, initiation)
            .await;

        let mut server_buf = vec![0u8; MAX_TEST_DATAGRAM];
        let (len, _) = client_socket.recv_from(&mut server_buf).await.unwrap();
        match client.decapsulate(None, &server_buf[..len], &mut client_buf) {
            TunnResult::Done => {}
            TunnResult::WriteToNetwork(reply) => {
                engine
                    .handle_datagram(server_socket.clone(), client_addr, reply)
                    .await;
            }
            other => panic!("unexpected handshake result: {other:?}"),
        }

        // Uplink: an IPv4 packet traverses the tunnel and leaves the engine
        // as a `Bytes` view on the accepted session's channel.
        let uplink = raw_ipv4_packet(
            std::net::Ipv4Addr::new(10, 82, 0, 2),
            std::net::Ipv4Addr::new(10, 126, 0, 1),
        );
        let TunnResult::WriteToNetwork(transport) = client.encapsulate(&uplink, &mut client_buf)
        else {
            panic!("client did not encrypt the uplink packet");
        };
        engine
            .handle_datagram(server_socket.clone(), client_addr, transport)
            .await;

        let session = tokio::time::timeout(Duration::from_secs(5), accepted_rx.recv())
            .await
            .expect("first data packet must activate the portal session")
            .expect("engine stays alive");
        let mut from_client = session.from_client;
        let received = tokio::time::timeout(Duration::from_secs(5), from_client.recv())
            .await
            .expect("decapsulated uplink packet was not delivered")
            .expect("session channel closed before the uplink packet");
        assert_eq!(&received[..], uplink.as_slice());

        // Downlink: Core sends a reply through to_client; the engine's
        // encapsulation task encrypts it back to the client endpoint.
        let downlink = raw_ipv4_packet(
            std::net::Ipv4Addr::new(10, 126, 0, 1),
            std::net::Ipv4Addr::new(10, 82, 0, 2),
        );
        session
            .to_client
            .send(Bytes::from(downlink.clone()))
            .await
            .unwrap();
        let (len, _) = tokio::time::timeout(
            Duration::from_secs(5),
            client_socket.recv_from(&mut server_buf),
        )
        .await
        .expect("engine did not send the downlink packet")
        .unwrap();
        match client.decapsulate(None, &server_buf[..len], &mut client_buf) {
            TunnResult::WriteToTunnelV4(payload, _) => assert_eq!(payload, downlink.as_slice()),
            other => panic!("unexpected downlink result: {other:?}"),
        }
    }
}
