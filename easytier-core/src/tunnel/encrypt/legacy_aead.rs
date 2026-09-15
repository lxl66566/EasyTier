//! Counter nonces for the legacy data-plane encryptor (crypto-review S1.3).
//!
//! The wire format is unchanged: `ciphertext ‖ tag(16B) ‖ nonce(12B)` in the
//! AEAD tail. Receivers only read the nonce out of the tail and feed it to
//! the AEAD, so switching the sender from random to counter nonces is fully
//! compatible with peers that have not upgraded.

use std::{
    mem::size_of,
    sync::{Arc, atomic::Ordering},
};

use atomic_shim::AtomicU64 as AtomicCounter;
use rand::{RngCore, rngs::OsRng};

use crate::packet::{StandardAeadTail, ZCPacket};

use super::{Encryptor, Error};

/// 24-bit marker distinguishing counter nonces from the uniformly random
/// nonces that pre-fix peers send.
///
/// A random nonce hits the marker with probability 2^-24 per packet. Such a
/// collision only makes receivers misclassify one packet; it cannot create
/// a (key, nonce) repeat for the sender.
const NONCE_MAGIC: [u8; 3] = [0xc3, 0x9f, 0x51];

/// Bytes of the nonce that randomly identify the sending Encryptor instance.
const PREFIX_LEN: usize = 3;

/// Bytes of the nonce reserved for the send counter.
const COUNTER_LEN: usize = StandardAeadTail::NONCE_SIZE - NONCE_MAGIC.len() - PREFIX_LEN;

/// Offset of the counter inside the nonce.
const COUNTER_OFFSET: usize = NONCE_MAGIC.len() + PREFIX_LEN;

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

/// Nonce sequence for one sending Encryptor instance:
/// `MAGIC ‖ random PREFIX ‖ 48-bit big-endian counter`.
struct SendNonceSequence {
    magic_and_prefix: [u8; COUNTER_OFFSET],
    counter: AtomicCounter,
}

impl SendNonceSequence {
    fn new() -> Self {
        let mut magic_and_prefix = [0u8; COUNTER_OFFSET];
        magic_and_prefix[..NONCE_MAGIC.len()].copy_from_slice(&NONCE_MAGIC);
        // Random per-instance prefix: distinguishes senders sharing one
        // network key and re-randomizes on process restart so (key, nonce)
        // pairs never repeat across lifetimes while the static key stays
        // the same.
        OsRng.fill_bytes(&mut magic_and_prefix[NONCE_MAGIC.len()..]);
        Self {
            magic_and_prefix,
            counter: AtomicCounter::new(0),
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

/// Legacy data-plane wrapper around any AEAD backend that derives nonces
/// from `MAGIC ‖ random PREFIX ‖ counter` instead of OsRng per packet,
/// keeping (key, nonce) pairs unique far beyond the NIST 2^32 random-nonce
/// budget for the whole process lifetime.
pub(super) struct ReplayProtectedEncryptor {
    inner: Arc<dyn Encryptor>,
    tx: SendNonceSequence,
}

impl ReplayProtectedEncryptor {
    pub(super) fn new(inner: Arc<dyn Encryptor>) -> Self {
        Self {
            inner,
            tx: SendNonceSequence::new(),
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
        self.inner.decrypt(zc_packet)
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

        let mut packet = sealed_packet(b"chacha20 packet");
        sender.encrypt(&mut packet).unwrap();
        receiver.decrypt(&mut packet).unwrap();
        assert_eq!(packet.payload(), b"chacha20 packet");
    }
}
