//! Counter nonces and replay protection for the legacy data-plane encryptor
//! (crypto-review S1.3 / S1.4, hardening N1 / N4 / N5).
//!
//! The wire format is unchanged: `ciphertext ‖ tag(16B) ‖ nonce(12B)` in the
//! AEAD tail. Receivers only read the nonce out of the tail and feed it to
//! the AEAD, so the nonce layouts below are transparent to the cipher
//! backends and to unupgraded peers. Magic-less random nonces (pre-fix
//! peers) get a best-effort duplicate cache instead of a window (N5).

use std::{
    mem::size_of,
    sync::{Arc, Mutex},
};

use rand::{RngCore, rngs::OsRng};
use zerocopy::FromBytes as _;

use crate::packet::{StandardAeadTail, ZCPacket};

use super::{
    AeadBinding, Encryptor, Error,
    replay_window::{ReplayWindow256, now_ms},
};

/// Magic of the v1 counter-nonce format shipped by earlier ext builds:
/// `MAGIC_V1 ‖ random PREFIX(3B) ‖ COUNTER(6B big-endian)`. Still parsed on
/// receive so peers running those builds keep full replay protection.
///
/// A random nonce hits the magic with probability 2^-24 per packet (the
/// review's false-classification budget); such a nonce is merely booked
/// under the random 3-byte prefix it carries.
const NONCE_MAGIC_V1: [u8; 3] = [0xc3, 0x9f, 0x51];

/// Magic of the current v2 counter-nonce format:
/// `MAGIC_V2 ‖ random PREFIX(5B) ‖ COUNTER(4B big-endian)`.
///
/// v2 widens the per-instance random prefix from 24 to 40 bits (N1): all
/// instances sharing the static network key must never draw the same
/// prefix, because both sides count from 0 and equal prefixes then
/// guarantee AES-GCM (key, nonce) reuse. The 24-bit space
/// birthday-collides among only ~5800 instances (each peer manager and
/// each restart draws one); 40 bits push that bound beyond a million
/// instances, unreachable by the deployment model.
///
/// Interop: the magic is the only thing a peer sees change. A v1-only
/// receiver finds no matching magic and treats the nonce as random — the
/// pre-counter-peer path. The 12 bytes are still fed to the AEAD verbatim,
/// so decryption keeps working; only replay protection is lost, which is
/// the same graceful degradation already accepted for pre-fix peers. In
/// the other direction this node keeps parsing v1 by [`NONCE_MAGIC_V1`].
const NONCE_MAGIC_V2: [u8; 3] = [0x6a, 0x09, 0xe6];

/// v1 layout: nonce bytes that randomly identify the sending instance.
const PREFIX_LEN_V1: usize = 3;

/// v1 layout: nonce bytes reserved for the send counter (48-bit).
const COUNTER_LEN_V1: usize = 6;

/// v2 layout: nonce bytes that randomly identify the sending instance.
const PREFIX_LEN_V2: usize = 5;

/// v2 layout: nonce bytes reserved for the send counter (32-bit).
const COUNTER_LEN_V2: usize = 4;

/// Offset of the v1 counter inside the nonce.
const COUNTER_OFFSET_V1: usize = NONCE_MAGIC_V1.len() + PREFIX_LEN_V1;

/// Offset of the v2 counter inside the nonce.
const COUNTER_OFFSET_V2: usize = NONCE_MAGIC_V2.len() + PREFIX_LEN_V2;

// Both layouts must fill the 12-byte nonce exactly.
const _: () = {
    assert!(NONCE_MAGIC_V1.len() + PREFIX_LEN_V1 + COUNTER_LEN_V1 == StandardAeadTail::NONCE_SIZE);
    assert!(NONCE_MAGIC_V2.len() + PREFIX_LEN_V2 + COUNTER_LEN_V2 == StandardAeadTail::NONCE_SIZE);
};

/// Send counters rotate to a fresh prefix with 2^24 (~16M packets) of
/// headroom before the 32-bit field could run out. Rotation is routine
/// (~4.3e9 packets per prefix, ~80 minutes at 1M pps) and safe: the 40-bit
/// prefix space makes colliding with any other live instance negligible.
const ROTATE_AT: u32 = u32::MAX - (1 << 24) + 1;

/// Nonce sequence for one sending Encryptor instance:
/// `MAGIC_V2 ‖ random PREFIX ‖ 32-bit big-endian counter`.
struct SendNonceSequence {
    /// Prefix and counter are one unit under a single lock: rotation swaps
    /// the prefix and restarts the counter together, so a nonce can never
    /// pair an old prefix with a new-era counter or vice versa. A
    /// fetch_add-only scheme cannot keep that pairing atomic across a
    /// rotation without a re-validation loop; one uncontended mutex
    /// acquisition per packet is noise next to the AEAD sealing cost.
    state: Mutex<SendNonceState>,
}

struct SendNonceState {
    magic_and_prefix: [u8; COUNTER_OFFSET_V2],
    counter: u32,
}

impl SendNonceSequence {
    fn new() -> Self {
        Self {
            state: Mutex::new(SendNonceState::new()),
        }
    }

    fn next(&self) -> [u8; StandardAeadTail::NONCE_SIZE] {
        let mut state = self.state.lock().unwrap();
        if state.counter >= ROTATE_AT {
            state.rotate_prefix();
        }
        let counter = state.counter;
        state.counter += 1;
        let mut nonce = [0u8; StandardAeadTail::NONCE_SIZE];
        nonce[..COUNTER_OFFSET_V2].copy_from_slice(&state.magic_and_prefix);
        nonce[COUNTER_OFFSET_V2..].copy_from_slice(&counter.to_be_bytes());
        nonce
    }
}

impl SendNonceState {
    fn new() -> Self {
        let mut magic_and_prefix = [0u8; COUNTER_OFFSET_V2];
        magic_and_prefix[..NONCE_MAGIC_V2.len()].copy_from_slice(&NONCE_MAGIC_V2);
        // Random per-instance prefix: distinguishes senders sharing one
        // network key (independent replay windows) and re-randomizes on
        // process restart so (key, nonce) pairs never repeat across
        // lifetimes while the static key stays the same.
        OsRng.fill_bytes(&mut magic_and_prefix[NONCE_MAGIC_V2.len()..]);
        Self {
            magic_and_prefix,
            counter: 0,
        }
    }

    /// Draws a fresh random prefix and restarts the counter at 0. The draw
    /// is repeated on the (2^-40) chance of redrawing the outgoing prefix:
    /// counters restart at 0, so keeping it would repeat (key, nonce)
    /// pairs.
    fn rotate_prefix(&mut self) {
        loop {
            let mut candidate = [0u8; PREFIX_LEN_V2];
            OsRng.fill_bytes(&mut candidate);
            if candidate != self.magic_and_prefix[NONCE_MAGIC_V2.len()..] {
                self.magic_and_prefix[NONCE_MAGIC_V2.len()..].copy_from_slice(&candidate);
                self.counter = 0;
                return;
            }
        }
    }
}

/// Receiver-side classification of a nonce tail.
#[derive(Debug, PartialEq, Eq)]
enum NonceClass {
    /// Current v2 format: 40-bit prefix + 32-bit counter.
    V2 {
        prefix: [u8; PREFIX_LEN_V2],
        counter: u64,
    },
    /// v1 format from earlier ext builds: 24-bit prefix + 48-bit counter.
    V1 {
        prefix: [u8; PREFIX_LEN_V1],
        counter: u64,
    },
    /// Uniformly random nonce from peers predating counter nonces.
    Random,
}

fn classify_nonce(nonce: &[u8; StandardAeadTail::NONCE_SIZE]) -> NonceClass {
    if nonce[..NONCE_MAGIC_V2.len()] == NONCE_MAGIC_V2 {
        return NonceClass::V2 {
            prefix: nonce[NONCE_MAGIC_V2.len()..COUNTER_OFFSET_V2]
                .try_into()
                .unwrap(),
            counter: u64::from(u32::from_be_bytes(
                nonce[COUNTER_OFFSET_V2..].try_into().unwrap(),
            )),
        };
    }
    if nonce[..NONCE_MAGIC_V1.len()] == NONCE_MAGIC_V1 {
        // 48-bit big-endian counter living in the low 6 bytes of a u64.
        let mut counter_bytes = [0u8; size_of::<u64>()];
        counter_bytes[size_of::<u64>() - COUNTER_LEN_V1..]
            .copy_from_slice(&nonce[COUNTER_OFFSET_V1..]);
        return NonceClass::V1 {
            prefix: nonce[NONCE_MAGIC_V1.len()..COUNTER_OFFSET_V1]
                .try_into()
                .unwrap(),
            counter: u64::from_be_bytes(counter_bytes),
        };
    }
    NonceClass::Random
}

/// Identity of one sending instance for replay bookkeeping, tagged by
/// format so v1 and v2 prefixes can never alias each other.
#[derive(Debug, PartialEq, Eq)]
enum SenderPrefix {
    V1([u8; PREFIX_LEN_V1]),
    V2([u8; PREFIX_LEN_V2]),
}

/// Distinct sender prefixes tracked for replay protection. One window per
/// prefix. Every mesh peer is itself a sender, so the capacity must cover
/// the peer table plus recently restarted peers still inside their replay
/// horizon; 16 (N4) was too small for mid-size meshes, 128 windows cost
/// ~8 KB total. More concurrent senders than this evict the stalest
/// window.
const REPLAY_TRACKED_PREFIXES: usize = 128;

/// Replay window state for one sender prefix.
struct PrefixReplaySlot {
    prefix: SenderPrefix,
    window: ReplayWindow256,
    last_seen_ms: u64,
}

/// Best-effort replay filter for received legacy AEAD packets.
///
/// - Random nonces (pre-fix peers, N5) have no sequence to window, so the
///   only usable replay signal is the nonce itself; they go through the
///   direct-mapped [`RandomNonceCache`], which rejects an exact duplicate
///   of a recently authenticated nonce. Purely additive soft state:
///   evicted or cross-restart replays still pass (strictly better than
///   the previous always-accept).
/// - Counter nonces (v1 and v2) are checked against the window of their
///   PREFIX. Windows are per prefix so a fast sender cannot push the window
///   of a slow sender (e.g. an idle node sending only heartbeats) out of
///   range.
/// - Only authenticated packets may update the filter (see
///   [`ReplayProtectedEncryptor::decrypt`]), so an attacker without the
///   network key cannot burn window slots, churn the seen-cache, or push
///   `max_seq` ahead of real traffic. More than
///   [`REPLAY_TRACKED_PREFIXES`] concurrent senders evict the stalest
///   window; the evicted prefix then restarts from its next packet, which
///   can admit very old replays of that prefix.
struct ReplayFilter {
    slots: Mutex<Vec<PrefixReplaySlot>>,
    random_seen: RandomNonceCache,
}

impl ReplayFilter {
    fn new() -> Self {
        Self {
            slots: Mutex::new(Vec::with_capacity(REPLAY_TRACKED_PREFIXES)),
            random_seen: RandomNonceCache::new(),
        }
    }

    /// Cheap pre-check before decryption; rejects nonces that are already
    /// provably stale (counter nonces) or known duplicates (random nonces).
    fn pre_check(&self, nonce: &[u8; StandardAeadTail::NONCE_SIZE]) -> bool {
        match classify_nonce(nonce) {
            NonceClass::Random => !self.random_seen.contains(nonce),
            NonceClass::V1 { prefix, counter } => {
                self.window_can_accept(SenderPrefix::V1(prefix), counter)
            }
            NonceClass::V2 { prefix, counter } => {
                self.window_can_accept(SenderPrefix::V2(prefix), counter)
            }
        }
    }

    /// Check-and-set after successful authentication. Returns `false` for
    /// detected replays.
    fn commit(&self, nonce: &[u8; StandardAeadTail::NONCE_SIZE]) -> bool {
        match classify_nonce(nonce) {
            NonceClass::Random => self.random_seen.insert(nonce),
            NonceClass::V1 { prefix, counter } => {
                self.window_accept(SenderPrefix::V1(prefix), counter)
            }
            NonceClass::V2 { prefix, counter } => {
                self.window_accept(SenderPrefix::V2(prefix), counter)
            }
        }
    }

    fn window_can_accept(&self, prefix: SenderPrefix, counter: u64) -> bool {
        let slots = self.slots.lock().unwrap();
        match slots.iter().find(|slot| slot.prefix == prefix) {
            Some(slot) => slot.window.can_accept(counter),
            // First packet of an unseen prefix: accept and let commit()
            // establish its window.
            None => true,
        }
    }

    fn window_accept(&self, prefix: SenderPrefix, counter: u64) -> bool {
        let mut slots = self.slots.lock().unwrap();
        let now = now_ms();
        if let Some(slot) = slots.iter_mut().find(|slot| slot.prefix == prefix) {
            slot.last_seen_ms = now;
            return slot.window.accept(counter);
        }
        if slots.len() >= REPLAY_TRACKED_PREFIXES {
            let stalest = slots
                .iter()
                .enumerate()
                .min_by_key(|(_, slot)| slot.last_seen_ms)
                .map(|(idx, _)| idx)
                .unwrap();
            slots.swap_remove(stalest);
        }
        let mut window = ReplayWindow256::default();
        let accepted = window.accept(counter);
        slots.push(PrefixReplaySlot {
            prefix,
            window,
            last_seen_ms: now,
        });
        accepted
    }
}

/// Best-effort seen-cache for random nonces (N5): pre-counter peers send
/// uniformly random nonces with no sequence, so the only replay signal is
/// the nonce itself.
///
/// Direct-mapped with 4096 slots: the nonce hash picks one slot, a hit
/// with a fully equal nonce is a replay, anything else replaces the slot.
/// This is purely additive soft state — an evicted (or cross-restart)
/// replay can still pass, and entries are only written after the AEAD
/// authenticated a packet, so attackers without the network key cannot
/// churn the cache. It intercepts nothing but exact immediate duplicates;
/// accepted packets still go through the normal AEAD path.
struct RandomNonceCache {
    slots: Mutex<Box<[Option<[u8; StandardAeadTail::NONCE_SIZE]>]>>,
}

impl RandomNonceCache {
    /// Power of two so the hash can be masked into a slot index.
    const SLOTS: usize = 4096;

    fn new() -> Self {
        Self {
            slots: Mutex::new((0..Self::SLOTS).map(|_| None).collect()),
        }
    }

    fn index(nonce: &[u8; StandardAeadTail::NONCE_SIZE]) -> usize {
        nonce_hash(nonce) as usize & (Self::SLOTS - 1)
    }

    /// Read-only probe for the pre-decryption check.
    fn contains(&self, nonce: &[u8; StandardAeadTail::NONCE_SIZE]) -> bool {
        self.slots.lock().unwrap()[Self::index(nonce)].as_ref() == Some(nonce)
    }

    /// Check-and-set after authentication; `false` marks a replay.
    fn insert(&self, nonce: &[u8; StandardAeadTail::NONCE_SIZE]) -> bool {
        let mut slots = self.slots.lock().unwrap();
        let slot = &mut slots[Self::index(nonce)];
        if slot.as_ref() == Some(nonce) {
            return false;
        }
        *slot = Some(*nonce);
        true
    }
}

/// FxHash-style mixing of the 12 nonce bytes (three 4-byte words). Only
/// needs to spread nonces uniformly over the cache; no cryptographic
/// strength required.
fn nonce_hash(nonce: &[u8; StandardAeadTail::NONCE_SIZE]) -> u32 {
    let words = [
        u32::from_be_bytes(nonce[0..4].try_into().unwrap()),
        u32::from_be_bytes(nonce[4..8].try_into().unwrap()),
        u32::from_be_bytes(nonce[8..12].try_into().unwrap()),
    ];
    let mut hash = 0x9e37_79b9u32;
    for word in words {
        hash = (hash.rotate_left(5) ^ word).wrapping_mul(0x85eb_ca6b);
    }
    hash
}

/// Reads the nonce an encrypted packet carries in its AEAD tail.
fn aead_tail_nonce(packet: &ZCPacket) -> Option<[u8; StandardAeadTail::NONCE_SIZE]> {
    if !packet.peer_manager_header()?.is_encrypted() {
        return None;
    }
    Some(StandardAeadTail::ref_from_suffix(packet.payload())?.nonce)
}

/// Legacy data-plane wrapper around any AEAD backend: counter nonces on
/// send, prefix-keyed replay filtering on receive.
pub(super) struct ReplayProtectedEncryptor {
    inner: Arc<dyn Encryptor>,
    tx: SendNonceSequence,
    rx: ReplayFilter,
}

impl ReplayProtectedEncryptor {
    pub(super) fn new(inner: Arc<dyn Encryptor>) -> Self {
        Self {
            inner,
            tx: SendNonceSequence::new(),
            rx: ReplayFilter::new(),
        }
    }
}

impl Encryptor for ReplayProtectedEncryptor {
    fn encrypt(&self, zc_packet: &mut ZCPacket, binding: AeadBinding) -> Result<(), Error> {
        let nonce = self.tx.next();
        self.inner
            .encrypt_with_nonce(zc_packet, Some(&nonce), binding)
    }

    fn encrypt_with_nonce(
        &self,
        zc_packet: &mut ZCPacket,
        _nonce: Option<&[u8]>,
        binding: AeadBinding,
    ) -> Result<(), Error> {
        // The wrapper owns nonce selection; caller-supplied nonces are
        // ignored so the counter invariant cannot be violated from outside.
        self.encrypt(zc_packet, binding)
    }

    fn decrypt(&self, zc_packet: &mut ZCPacket) -> Result<(), Error> {
        let nonce = aead_tail_nonce(zc_packet);
        if let Some(nonce) = nonce.as_ref()
            && !self.rx.pre_check(nonce)
        {
            return Err(Error::ReplayDetected);
        }
        self.inner.decrypt(zc_packet)?;
        // Account only after the AEAD authenticated the packet, so forged
        // traffic cannot pollute windows. The nonce itself is authenticated
        // indirectly: mutating it makes decryption fail.
        if let Some(nonce) = nonce.as_ref()
            && !self.rx.commit(nonce)
        {
            return Err(Error::ReplayDetected);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::HashSet, thread, time::Duration};

    use super::*;
    use crate::tunnel::encrypt::{create_encryptor, create_legacy_encryptor};

    const KEY_128: [u8; 16] = [1; 16];
    const KEY_256: [u8; 32] = [2; 32];

    fn legacy_aes256() -> Arc<dyn Encryptor> {
        create_legacy_encryptor("aes-256-gcm", KEY_128, KEY_256)
    }

    fn raw_aes256() -> Arc<dyn Encryptor> {
        create_encryptor("aes-256-gcm", KEY_128, KEY_256)
    }

    fn sealed_packet(payload: &[u8]) -> ZCPacket {
        let mut packet = ZCPacket::new_with_payload(payload);
        packet.fill_peer_manager_hdr(1, 2, 1);
        packet
    }

    /// Builds a v2 nonce by hand, as a v2-capable sender would emit it.
    fn v2_nonce(prefix: &[u8; PREFIX_LEN_V2], counter: u32) -> [u8; StandardAeadTail::NONCE_SIZE] {
        let mut nonce = [0u8; StandardAeadTail::NONCE_SIZE];
        nonce[..NONCE_MAGIC_V2.len()].copy_from_slice(&NONCE_MAGIC_V2);
        nonce[NONCE_MAGIC_V2.len()..COUNTER_OFFSET_V2].copy_from_slice(prefix);
        nonce[COUNTER_OFFSET_V2..].copy_from_slice(&counter.to_be_bytes());
        nonce
    }

    /// Builds a v1 nonce by hand, as an earlier ext build would emit it.
    fn v1_nonce(prefix: &[u8; PREFIX_LEN_V1], counter: u64) -> [u8; StandardAeadTail::NONCE_SIZE] {
        let mut nonce = [0u8; StandardAeadTail::NONCE_SIZE];
        nonce[..NONCE_MAGIC_V1.len()].copy_from_slice(&NONCE_MAGIC_V1);
        nonce[NONCE_MAGIC_V1.len()..COUNTER_OFFSET_V1].copy_from_slice(prefix);
        nonce[COUNTER_OFFSET_V1..]
            .copy_from_slice(&counter.to_be_bytes()[size_of::<u64>() - COUNTER_LEN_V1..]);
        nonce
    }

    /// Seals a packet through the raw backend so the nonce layout is fully
    /// controlled by the test.
    fn sealed_with_nonce(nonce: &[u8; StandardAeadTail::NONCE_SIZE], payload: &[u8]) -> ZCPacket {
        let mut packet = sealed_packet(payload);
        raw_aes256()
            .encrypt_with_nonce(&mut packet, Some(nonce), AeadBinding::None)
            .unwrap();
        packet
    }

    fn classified_v2(nonce: &[u8; StandardAeadTail::NONCE_SIZE]) -> ([u8; PREFIX_LEN_V2], u64) {
        match classify_nonce(nonce) {
            NonceClass::V2 { prefix, counter } => (prefix, counter),
            other => panic!("expected a v2 counter nonce, got {other:?}"),
        }
    }

    #[test]
    fn counter_nonces_are_unique_under_concurrency() {
        let seq = SendNonceSequence::new();
        let nonces: Vec<_> = thread::scope(|scope| {
            let handles: Vec<_> = (0..8)
                .map(|_| {
                    let seq = &seq;
                    scope.spawn(move || (0..1000).map(|_| seq.next()).collect::<Vec<_>>())
                })
                .collect();
            handles
                .into_iter()
                .flat_map(|handle| handle.join().unwrap())
                .collect()
        });
        let unique: HashSet<_> = nonces.iter().collect();
        assert_eq!(unique.len(), 8 * 1000);
        for nonce in &nonces {
            assert_eq!(&nonce[..NONCE_MAGIC_V2.len()], &NONCE_MAGIC_V2);
        }
    }

    #[test]
    fn counter_nonce_layout_round_trips() {
        let seq = SendNonceSequence::new();
        let nonce = seq.next();
        let (prefix, counter) = classified_v2(&nonce);
        assert_eq!(counter, 0);
        let expected: [u8; PREFIX_LEN_V2] = seq.state.lock().unwrap().magic_and_prefix
            [NONCE_MAGIC_V2.len()..]
            .try_into()
            .unwrap();
        assert_eq!(prefix, expected);

        assert_eq!(classified_v2(&seq.next()).1, 1);

        // Random nonces do not parse as counter nonces of either format.
        let mut random = [0u8; StandardAeadTail::NONCE_SIZE];
        OsRng.fill_bytes(&mut random);
        if random[..NONCE_MAGIC_V2.len()] != NONCE_MAGIC_V2
            && random[..NONCE_MAGIC_V1.len()] != NONCE_MAGIC_V1
        {
            assert_eq!(classify_nonce(&random), NonceClass::Random);
        }
    }

    #[test]
    fn v1_nonce_layout_still_parses() {
        let prefix = [7; PREFIX_LEN_V1];
        assert_eq!(
            classify_nonce(&v1_nonce(&prefix, 0x0102_0304_0506)),
            NonceClass::V1 {
                prefix,
                counter: 0x0102_0304_0506
            }
        );
        // The v1 counter field spans 48 bits.
        assert_eq!(
            classify_nonce(&v1_nonce(&prefix, 1 << 40)),
            NonceClass::V1 {
                prefix,
                counter: 1 << 40
            }
        );
    }

    #[test]
    fn prefix_rotation_reserves_a_fresh_namespace() {
        let seq = SendNonceSequence::new();
        let (old_prefix, first_counter) = classified_v2(&seq.next());
        assert_eq!(first_counter, 0);

        // Simulate the send budget running out; the next nonce must rotate
        // to a different prefix and restart counting from 0.
        seq.state.lock().unwrap().counter = ROTATE_AT;
        let (new_prefix, counter) = classified_v2(&seq.next());
        assert_ne!(new_prefix, old_prefix);
        assert_eq!(counter, 0);
        // Counting continues inside the fresh namespace.
        assert_eq!(classified_v2(&seq.next()).1, 1);
    }

    #[test]
    fn counter_nonce_replay_is_rejected() {
        let sender = legacy_aes256();
        let receiver = legacy_aes256();

        let mut first = sealed_packet(b"first");
        sender.encrypt(&mut first, AeadBinding::None).unwrap();
        let mut second = sealed_packet(b"second");
        sender.encrypt(&mut second, AeadBinding::None).unwrap();
        let mut replayed = first.clone();

        receiver.decrypt(&mut first).unwrap();
        assert_eq!(first.payload(), b"first");
        assert!(matches!(
            receiver.decrypt(&mut replayed),
            Err(Error::ReplayDetected)
        ));
        // Subsequent fresh packets are unaffected by the rejection.
        receiver.decrypt(&mut second).unwrap();
        assert_eq!(second.payload(), b"second");
    }

    #[test]
    fn receiver_tracks_sender_prefix_rotation() {
        // Sender-side rotation looks like an unseen prefix that legally
        // restarts at counter 0; the pre-rotation prefix keeps its window.
        let receiver = legacy_aes256();
        let old_prefix = [0x11; PREFIX_LEN_V2];
        let new_prefix = [0x22; PREFIX_LEN_V2];

        let mut first = sealed_with_nonce(&v2_nonce(&old_prefix, 5), b"before rotation");
        receiver.decrypt(&mut first).unwrap();

        let mut second = sealed_with_nonce(&v2_nonce(&new_prefix, 0), b"after rotation");
        receiver.decrypt(&mut second).unwrap();
        assert_eq!(second.payload(), b"after rotation");

        let mut replay = sealed_with_nonce(&v2_nonce(&old_prefix, 5), b"before rotation");
        assert!(matches!(
            receiver.decrypt(&mut replay),
            Err(Error::ReplayDetected)
        ));
    }

    #[test]
    fn v1_packets_from_ext_peers_are_tracked() {
        let receiver = legacy_aes256();
        let prefix = [0xab; PREFIX_LEN_V1];

        let mut first = sealed_with_nonce(&v1_nonce(&prefix, 0), b"ext peer packet");
        receiver.decrypt(&mut first).unwrap();
        assert_eq!(first.payload(), b"ext peer packet");

        let mut replay = sealed_with_nonce(&v1_nonce(&prefix, 0), b"ext peer packet");
        assert!(matches!(
            receiver.decrypt(&mut replay),
            Err(Error::ReplayDetected)
        ));

        // In-sequence counters keep flowing.
        let mut second = sealed_with_nonce(&v1_nonce(&prefix, 1), b"ext peer packet 2");
        receiver.decrypt(&mut second).unwrap();
    }

    #[test]
    fn out_of_order_packets_within_window_are_accepted() {
        let sender = legacy_aes256();
        let receiver = legacy_aes256();

        let sealed: Vec<_> = (0..100u32)
            .map(|i| {
                let mut packet = sealed_packet(format!("packet {i}").as_bytes());
                sender.encrypt(&mut packet, AeadBinding::None).unwrap();
                packet
            })
            .collect();
        // Fully reversed arrival: every packet is within the 256-slot window.
        for packet in &sealed {
            let mut received = packet.clone();
            receiver.decrypt(&mut received).unwrap();
        }
        // Replaying any of them is still rejected.
        for packet in &sealed {
            let mut replayed = packet.clone();
            assert!(matches!(
                receiver.decrypt(&mut replayed),
                Err(Error::ReplayDetected)
            ));
        }
    }

    #[test]
    fn random_nonce_packets_from_old_peers_are_accepted() {
        let old_peer = raw_aes256();
        let receiver = legacy_aes256();

        for i in 0..64u8 {
            // Keep the first byte clear of both magics so the nonce is
            // deterministically classified as random (old-peer style).
            let mut nonce = [0u8; StandardAeadTail::NONCE_SIZE];
            nonce[0] = i;
            nonce[11] = i.wrapping_mul(3);
            let mut packet = sealed_packet(b"old peer payload");
            old_peer
                .encrypt_with_nonce(&mut packet, Some(&nonce), AeadBinding::None)
                .unwrap();
            receiver.decrypt(&mut packet).unwrap();
            assert_eq!(packet.payload(), b"old peer payload");
            // N5: an immediate resend of the very same nonce is now a
            // caught replay; the next iteration shows that distinct fresh
            // nonces keep flowing.
            let mut resent = sealed_packet(b"old peer payload");
            old_peer
                .encrypt_with_nonce(&mut resent, Some(&nonce), AeadBinding::None)
                .unwrap();
            assert!(matches!(
                receiver.decrypt(&mut resent),
                Err(Error::ReplayDetected)
            ));
        }
    }

    #[test]
    fn random_nonce_cache_churn_does_not_reject_fresh_nonces() {
        let old_peer = raw_aes256();
        let receiver = legacy_aes256();

        let nonce_of = |i: u32| {
            // First byte stays 0, clear of both magics, so every nonce is
            // classified as random.
            let mut nonce = [0u8; StandardAeadTail::NONCE_SIZE];
            nonce[..4].copy_from_slice(&i.to_be_bytes());
            nonce
        };
        let sealed = |i: u32| {
            let mut packet = sealed_packet(b"old peer payload");
            old_peer
                .encrypt_with_nonce(&mut packet, Some(&nonce_of(i)), AeadBinding::None)
                .unwrap();
            packet
        };

        // Churn the whole direct-mapped cache with distinct nonces: none
        // may be falsely rejected, hash collisions included.
        let churned = RandomNonceCache::SLOTS as u32 * 2;
        for i in 0..churned {
            receiver.decrypt(&mut sealed(i)).unwrap();
        }

        // The most recent nonce is still cached, so its duplicate is caught.
        let mut replay = sealed(churned - 1);
        assert!(matches!(
            receiver.decrypt(&mut replay),
            Err(Error::ReplayDetected)
        ));

        // A slot collision replaces the entry instead of rejecting: a
        // different nonce hashing to the same slot is admitted...
        let base = churned;
        let colliding = (base + 1..)
            .find(|&j| {
                RandomNonceCache::index(&nonce_of(j)) == RandomNonceCache::index(&nonce_of(base))
            })
            .unwrap();
        receiver.decrypt(&mut sealed(base)).unwrap();
        receiver.decrypt(&mut sealed(colliding)).unwrap();
        // ...and the displaced entry is treated as unseen again, the
        // documented eviction-based miss.
        receiver.decrypt(&mut sealed(base)).unwrap();
    }

    #[test]
    fn upgraded_sender_interoperates_with_old_receiver() {
        // A v2 nonce carries a new magic, which an old receiver classifies
        // as a random nonce: the AEAD still opens it (the 12-byte nonce is
        // used verbatim), only replay protection is lost — the same
        // degradation already accepted for pre-counter peers. The raw
        // backend here plays the receiver role such a peer effectively
        // runs.
        let sender = legacy_aes256();
        let old_receiver = raw_aes256();

        let mut packet = sealed_packet(b"to old receiver");
        sender.encrypt(&mut packet, AeadBinding::None).unwrap();
        old_receiver.decrypt(&mut packet).unwrap();
        assert_eq!(packet.payload(), b"to old receiver");
    }

    #[cfg(any(
        feature = "chacha20",
        feature = "openssl-crypto",
        feature = "ring-crypto"
    ))]
    #[test]
    fn chacha20_backend_gets_the_same_protection() {
        let sender = create_legacy_encryptor("chacha20", KEY_128, KEY_256);
        let receiver = create_legacy_encryptor("chacha20", KEY_128, KEY_256);

        let mut first = sealed_packet(b"chacha20 packet");
        sender.encrypt(&mut first, AeadBinding::None).unwrap();
        let mut replayed = first.clone();
        receiver.decrypt(&mut first).unwrap();
        assert_eq!(first.payload(), b"chacha20 packet");
        assert!(matches!(
            receiver.decrypt(&mut replayed),
            Err(Error::ReplayDetected)
        ));
    }

    #[test]
    fn senders_with_different_prefixes_do_not_interfere() {
        let fast_sender = legacy_aes256();
        let slow_sender = legacy_aes256();
        let receiver = legacy_aes256();

        let mut slow_first = sealed_packet(b"slow first");
        slow_sender
            .encrypt(&mut slow_first, AeadBinding::None)
            .unwrap();
        receiver.decrypt(&mut slow_first).unwrap();

        // The fast sender pushes its own window far beyond the slow one's
        // counter; a shared window would starve the slow sender out.
        for i in 0..600u32 {
            let mut packet = sealed_packet(format!("fast {i}").as_bytes());
            fast_sender.encrypt(&mut packet, AeadBinding::None).unwrap();
            receiver.decrypt(&mut packet).unwrap();
        }

        let mut slow_second = sealed_packet(b"slow second");
        slow_sender
            .encrypt(&mut slow_second, AeadBinding::None)
            .unwrap();
        receiver.decrypt(&mut slow_second).unwrap();
        assert_eq!(slow_second.payload(), b"slow second");
    }

    #[test]
    fn many_senders_keep_their_replay_windows() {
        // N4: in a mesh every peer is a sender, so the filter must track far
        // more prefixes than a small star topology needs. Distinct prefixes
        // come from the low bytes so small indices stay distinct.
        let receiver = legacy_aes256();
        let prefixes: Vec<[u8; PREFIX_LEN_V2]> = (0..REPLAY_TRACKED_PREFIXES as u64 + 12)
            .map(|i| {
                i.to_be_bytes()[size_of::<u64>() - PREFIX_LEN_V2..]
                    .try_into()
                    .unwrap()
            })
            .collect();

        let mut first = sealed_with_nonce(&v2_nonce(&prefixes[0], 0), b"mesh traffic");
        receiver.decrypt(&mut first).unwrap();
        // Give the first sender a strictly older timestamp so the eviction
        // below deterministically targets it (equal timestamps tie-break
        // towards later slots).
        thread::sleep(Duration::from_millis(2));
        for (counter, prefix) in prefixes.iter().enumerate().skip(1) {
            let mut packet = sealed_with_nonce(&v2_nonce(prefix, counter as u32), b"mesh traffic");
            receiver.decrypt(&mut packet).unwrap();
        }

        // The most recent senders are fully protected...
        let last = prefixes.last().unwrap();
        let mut replay = sealed_with_nonce(
            &v2_nonce(last, (prefixes.len() - 1) as u32),
            b"mesh traffic",
        );
        assert!(matches!(
            receiver.decrypt(&mut replay),
            Err(Error::ReplayDetected)
        ));

        // ...while the stalest prefix was evicted once the capacity ran out:
        // its replay is admitted, the documented best-effort bound.
        let mut ancient = sealed_with_nonce(&v2_nonce(&prefixes[0], 0), b"mesh traffic");
        receiver.decrypt(&mut ancient).unwrap();
    }

    #[test]
    fn unauthenticated_far_future_nonce_cannot_poison_windows() {
        let sender = legacy_aes256();
        let receiver = legacy_aes256();

        let mut packet = sealed_packet(b"real packet");
        sender.encrypt(&mut packet, AeadBinding::None).unwrap();
        // Extract the nonce before decryption truncates the tail.
        let sender_nonce = aead_tail_nonce(&packet).unwrap();
        receiver.decrypt(&mut packet).unwrap();

        // Seal a packet whose tail carries the sender's prefix with a
        // far-future counter, then corrupt one ciphertext byte: an attacker
        // without the network key can only produce authentication failures,
        // and those must leave the sender's window untouched.
        let mut nonce = sender_nonce;
        nonce[COUNTER_OFFSET_V2..].copy_from_slice(&1_000_000u32.to_be_bytes());
        let mut forged = sealed_packet(b"attacker controlled bytes");
        raw_aes256()
            .encrypt_with_nonce(&mut forged, Some(&nonce), AeadBinding::None)
            .unwrap();
        forged.mut_payload()[0] ^= 0xff;

        assert!(matches!(
            receiver.decrypt(&mut forged),
            Err(Error::DecryptionFailed)
        ));

        let mut next = sealed_packet(b"next real packet");
        sender.encrypt(&mut next, AeadBinding::None).unwrap();
        receiver.decrypt(&mut next).unwrap();
        assert_eq!(next.payload(), b"next real packet");
    }
}
