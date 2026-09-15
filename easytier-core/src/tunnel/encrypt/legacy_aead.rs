//! Counter nonces and replay protection for the legacy data-plane encryptor
//! (crypto-review S1.3 / S1.4).
//!
//! The wire format is unchanged: `ciphertext ‖ tag(16B) ‖ nonce(12B)` in the
//! AEAD tail. Receivers only read the nonce out of the tail and feed it to
//! the AEAD, so switching the sender from random to counter nonces is fully
//! compatible with peers that have not upgraded.

use std::{
    mem::size_of,
    sync::{Arc, Mutex, atomic::Ordering},
};

use atomic_shim::AtomicU64;
use rand::{RngCore, rngs::OsRng};
use zerocopy::FromBytes as _;

use crate::packet::{StandardAeadTail, ZCPacket};

use super::{
    Encryptor, Error,
    replay_window::{ReplayWindow256, now_ms},
};

/// 24-bit marker distinguishing counter nonces from the uniformly random
/// nonces that pre-fix peers send.
///
/// A random nonce hits the marker with probability 2^-24 per packet (the
/// review's budget). Such a collision only makes the receiver book the
/// packet under the random 3-byte PREFIX it carries; to actually poison a
/// live sender's replay window the random nonce would additionally have to
/// match that sender's prefix, i.e. probability 2^-48 per packet.
const NONCE_MAGIC: [u8; 3] = [0xc3, 0x9f, 0x51];

/// Bytes of the nonce that randomly identify the sending Encryptor instance.
const PREFIX_LEN: usize = 3;

/// Bytes of the nonce reserved for the send counter.
const COUNTER_LEN: usize = StandardAeadTail::NONCE_SIZE - NONCE_MAGIC.len() - PREFIX_LEN;

/// Offset of the counter inside the nonce.
const COUNTER_OFFSET: usize = NONCE_MAGIC.len() + PREFIX_LEN;

/// Distinct sender prefixes tracked for replay protection. One window per
/// prefix; more concurrent senders than this evict the stalest window.
const REPLAY_TRACKED_PREFIXES: usize = 16;

/// Nonce sequence for one sending Encryptor instance:
/// `MAGIC ‖ random PREFIX ‖ 48-bit big-endian counter`.
struct SendNonceSequence {
    magic_and_prefix: [u8; COUNTER_OFFSET],
    counter: AtomicU64,
}

impl SendNonceSequence {
    fn new() -> Self {
        let mut magic_and_prefix = [0u8; COUNTER_OFFSET];
        magic_and_prefix[..NONCE_MAGIC.len()].copy_from_slice(&NONCE_MAGIC);
        // Random per-instance prefix: distinguishes senders sharing one
        // network key (independent replay windows) and re-randomizes on
        // process restart so (key, nonce) pairs never repeat across
        // lifetimes while the static key stays the same.
        OsRng.fill_bytes(&mut magic_and_prefix[NONCE_MAGIC.len()..]);
        Self {
            magic_and_prefix,
            counter: AtomicU64::new(0),
        }
    }

    fn next(&self) -> [u8; StandardAeadTail::NONCE_SIZE] {
        // fetch_add guarantees uniqueness under concurrent sends. The counter
        // is truncated to 48 bits: 2^48 nonces at 1M pps take ~8.9 years, so
        // wrap-around is unreachable in practice and no runtime guard (or
        // panic path) is warranted.
        let counter = self.counter.fetch_add(1, Ordering::Relaxed);
        let mut nonce = [0u8; StandardAeadTail::NONCE_SIZE];
        nonce[..COUNTER_OFFSET].copy_from_slice(&self.magic_and_prefix);
        nonce[COUNTER_OFFSET..]
            .copy_from_slice(&counter.to_be_bytes()[size_of::<u64>() - COUNTER_LEN..]);
        nonce
    }
}

/// Splits a counter nonce into (prefix, counter); `None` for random nonces.
fn parse_counter_nonce(
    nonce: &[u8; StandardAeadTail::NONCE_SIZE],
) -> Option<([u8; PREFIX_LEN], u64)> {
    if nonce[..NONCE_MAGIC.len()] != NONCE_MAGIC {
        return None;
    }
    let mut counter_bytes = [0u8; size_of::<u64>()];
    counter_bytes[size_of::<u64>() - COUNTER_LEN..].copy_from_slice(&nonce[COUNTER_OFFSET..]);
    Some((
        nonce[NONCE_MAGIC.len()..COUNTER_OFFSET].try_into().unwrap(),
        u64::from_be_bytes(counter_bytes),
    ))
}

/// Replay window state for one sender prefix.
struct PrefixReplaySlot {
    prefix: [u8; PREFIX_LEN],
    window: ReplayWindow256,
    last_seen_ms: u64,
}

/// Best-effort replay filter for received legacy AEAD packets.
///
/// - Random nonces (pre-fix peers) are passed through unchecked, matching
///   the historical receiver behavior; replaying them stays possible, which
///   is the price of mixed-version interoperability.
/// - Counter nonces are checked against the window of their PREFIX. Windows
///   are per prefix so a fast sender cannot push the window of a slow
///   sender (e.g. an idle node sending only heartbeats) out of range.
/// - Only authenticated packets may update the filter (see
///   [`ReplayProtectedEncryptor::decrypt`]), so an attacker without the
///   network key cannot burn window slots or push `max_seq` ahead of real
///   traffic. More than [`REPLAY_TRACKED_PREFIXES`] concurrent senders
///   evict the stalest window; the evicted prefix then restarts from its
///   next packet, which can admit very old replays of that prefix.
struct ReplayFilter {
    slots: Mutex<Vec<PrefixReplaySlot>>,
}

impl ReplayFilter {
    fn new() -> Self {
        Self {
            slots: Mutex::new(Vec::with_capacity(REPLAY_TRACKED_PREFIXES)),
        }
    }

    /// Cheap pre-check before decryption; only rejects counter nonces that
    /// are already provably stale for their prefix.
    fn pre_check(&self, nonce: &[u8; StandardAeadTail::NONCE_SIZE]) -> bool {
        let Some((prefix, counter)) = parse_counter_nonce(nonce) else {
            return true;
        };
        let slots = self.slots.lock().unwrap();
        match slots.iter().find(|slot| slot.prefix == prefix) {
            Some(slot) => slot.window.can_accept(counter),
            // First packet of an unseen prefix: accept and let commit()
            // establish its window.
            None => true,
        }
    }

    /// Check-and-set after successful authentication. Returns `false` for
    /// detected replays.
    fn commit(&self, nonce: &[u8; StandardAeadTail::NONCE_SIZE]) -> bool {
        let Some((prefix, counter)) = parse_counter_nonce(nonce) else {
            return true;
        };
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
    fn encrypt(&self, zc_packet: &mut ZCPacket) -> Result<(), Error> {
        let nonce = self.tx.next();
        self.inner.encrypt_with_nonce(zc_packet, Some(&nonce))
    }

    fn encrypt_with_nonce(
        &self,
        zc_packet: &mut ZCPacket,
        _nonce: Option<&[u8]>,
    ) -> Result<(), Error> {
        // The wrapper owns nonce selection; caller-supplied nonces are
        // ignored so the counter invariant cannot be violated from outside.
        self.encrypt(zc_packet)
    }

    fn decrypt(&self, zc_packet: &mut ZCPacket) -> Result<(), Error> {
        let nonce = aead_tail_nonce(zc_packet);
        if let Some(nonce) = nonce.as_ref() {
            if !self.rx.pre_check(nonce) {
                return Err(Error::ReplayDetected);
            }
        }
        self.inner.decrypt(zc_packet)?;
        // Account only after the AEAD authenticated the packet, so forged
        // traffic cannot pollute windows. The nonce itself is authenticated
        // indirectly: mutating it makes decryption fail.
        if let Some(nonce) = nonce.as_ref() {
            if !self.rx.commit(nonce) {
                return Err(Error::ReplayDetected);
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::HashSet, thread};

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
            assert_eq!(&nonce[..NONCE_MAGIC.len()], &NONCE_MAGIC);
        }
    }

    #[test]
    fn counter_nonce_layout_round_trips() {
        let seq = SendNonceSequence::new();
        let nonce = seq.next();
        let (prefix, counter) = parse_counter_nonce(&nonce).unwrap();
        assert_eq!(counter, 0);
        assert_eq!(prefix, seq.magic_and_prefix[NONCE_MAGIC.len()..]);

        let nonce = seq.next();
        assert_eq!(parse_counter_nonce(&nonce).unwrap().1, 1);

        // Random nonces do not parse as counter nonces.
        let mut random = [0u8; StandardAeadTail::NONCE_SIZE];
        OsRng.fill_bytes(&mut random);
        if random[..NONCE_MAGIC.len()] != NONCE_MAGIC {
            assert!(parse_counter_nonce(&random).is_none());
        }
    }

    #[test]
    fn counter_nonce_replay_is_rejected() {
        let sender = legacy_aes256();
        let receiver = legacy_aes256();

        let mut first = sealed_packet(b"first");
        sender.encrypt(&mut first).unwrap();
        let mut second = sealed_packet(b"second");
        sender.encrypt(&mut second).unwrap();
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
    fn out_of_order_packets_within_window_are_accepted() {
        let sender = legacy_aes256();
        let receiver = legacy_aes256();

        let sealed: Vec<_> = (0..100u32)
            .map(|i| {
                let mut packet = sealed_packet(format!("packet {i}").as_bytes());
                sender.encrypt(&mut packet).unwrap();
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
            // Keep the first byte clear of the magic so the nonce is
            // deterministically classified as random (old-peer style).
            let mut nonce = [0u8; StandardAeadTail::NONCE_SIZE];
            nonce[0] = i;
            nonce[11] = i.wrapping_mul(3);
            let mut packet = sealed_packet(b"old peer payload");
            old_peer
                .encrypt_with_nonce(&mut packet, Some(&nonce))
                .unwrap();
            receiver.decrypt(&mut packet).unwrap();
            assert_eq!(packet.payload(), b"old peer payload");
            // Random nonces skip replay bookkeeping: an immediate resend is
            // still accepted, preserving old-version interoperability.
            let mut resent = sealed_packet(b"old peer payload");
            old_peer
                .encrypt_with_nonce(&mut resent, Some(&nonce))
                .unwrap();
            receiver.decrypt(&mut resent).unwrap();
        }
    }

    #[test]
    fn upgraded_sender_interoperates_with_old_receiver() {
        let sender = legacy_aes256();
        let old_receiver = raw_aes256();

        let mut packet = sealed_packet(b"to old receiver");
        sender.encrypt(&mut packet).unwrap();
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
        sender.encrypt(&mut first).unwrap();
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
        slow_sender.encrypt(&mut slow_first).unwrap();
        receiver.decrypt(&mut slow_first).unwrap();

        // The fast sender pushes its own window far beyond the slow one's
        // counter; a shared window would starve the slow sender out.
        for i in 0..600u32 {
            let mut packet = sealed_packet(format!("fast {i}").as_bytes());
            fast_sender.encrypt(&mut packet).unwrap();
            receiver.decrypt(&mut packet).unwrap();
        }

        let mut slow_second = sealed_packet(b"slow second");
        slow_sender.encrypt(&mut slow_second).unwrap();
        receiver.decrypt(&mut slow_second).unwrap();
        assert_eq!(slow_second.payload(), b"slow second");
    }

    #[test]
    fn unauthenticated_far_future_nonce_cannot_poison_windows() {
        let sender = legacy_aes256();
        let receiver = legacy_aes256();

        let mut packet = sealed_packet(b"real packet");
        sender.encrypt(&mut packet).unwrap();
        // Extract the nonce before decryption truncates the tail.
        let sender_nonce = aead_tail_nonce(&packet).unwrap();
        receiver.decrypt(&mut packet).unwrap();

        // Seal a packet whose tail carries the sender's prefix with a
        // far-future counter, then corrupt one ciphertext byte: an attacker
        // without the network key can only produce authentication failures,
        // and those must leave the sender's window untouched.
        let mut nonce = sender_nonce;
        nonce[COUNTER_OFFSET..]
            .copy_from_slice(&1_000_000u64.to_be_bytes()[size_of::<u64>() - COUNTER_LEN..]);
        let mut forged = sealed_packet(b"attacker controlled bytes");
        raw_aes256()
            .encrypt_with_nonce(&mut forged, Some(&nonce))
            .unwrap();
        forged.mut_payload()[0] ^= 0xff;

        assert!(matches!(
            receiver.decrypt(&mut forged),
            Err(Error::DecryptionFailed)
        ));

        let mut next = sealed_packet(b"next real packet");
        sender.encrypt(&mut next).unwrap();
        receiver.decrypt(&mut next).unwrap();
        assert_eq!(next.payload(), b"next real packet");
    }
}
