//! Password-based key derivation for the legacy data plane (crypto-review
//! S1.1).
//!
//! v1 derives keys with `DefaultHasher` (SipHash-1-3, fixed key): no salt, no
//! stretching, billions of offline guesses per second against a captured
//! ciphertext, and `std` does not guarantee the algorithm across Rust
//! releases. v2 replaces it with Argon2id; peers negotiate the `kdf-v2`
//! handshake feature and fall back to v1 keys for old peers, so both suites
//! coexist per destination.

use std::{
    collections::HashMap,
    sync::{Arc, Mutex, OnceLock},
};

use argon2::{Algorithm, Argon2, Params, Version};

use crate::packet::ZCPacket;

use super::{AeadBinding, Encryptor, Error};

/// Key-derivation suite for legacy data-plane keys derived from the network
/// secret. Mirrors the `kdf-v2` handshake feature: a packet sealed under
/// [`KdfSuite::Argon2id`] carries [`crate::packet::KDF_V2_MARKER`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum KdfSuite {
    /// SipHash-based v1 derivation; the only suite peers predating `kdf-v2`
    /// can derive, so it stays the default for unaudited destinations.
    #[default]
    V1SipHash,
    /// Argon2id v2 derivation.
    V2Argon2id,
}

/// Argon2id parameters: m = 19456 KiB, t = 2, p = 1 (RFC 9106 second
/// recommended option).
///
/// Derivation happens at startup per network secret (and per PeerManager
/// rebuild, see [`KEY_CACHE`]), never per packet. 19 MiB of transient memory
/// keeps public servers and embedded targets comfortable while making offline
/// guessing several orders of magnitude slower than the v1 derivation.
const ARGON2_M_KIB: u32 = 19456;
const ARGON2_T: u32 = 2;
const ARGON2_P: u32 = 1;

/// Fixed salt. A per-network random salt would need online agreement between
/// peers; this domain string instead prevents cross-protocol reuse of the
/// derived keys.
const ARGON2_SALT: &[u8] = b"easytier-kdf-v2";

/// The two legacy data-plane keys derived from one secret.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DerivedKeys {
    pub key_128: [u8; 16],
    pub key_256: [u8; 32],
}

/// Process-wide cache of argon2id derivations, keyed by secret. Argon2id is
/// expensive by design; the cache keeps repeated PeerManager construction
/// (config reloads) from paying the cost again for the same secret.
static KEY_CACHE: OnceLock<Mutex<HashMap<Box<str>, DerivedKeys>>> = OnceLock::new();

/// Cache capacity. A process realistically serves a handful of secrets; when
/// the cap is hit the cache is rebuilt lazily instead of growing unbounded.
const KEY_CACHE_CAP: usize = 16;

fn argon2_derive(secret: &str) -> DerivedKeys {
    let params = Params::new(ARGON2_M_KIB, ARGON2_T, ARGON2_P, Some(48))
        .expect("argon2id parameters are valid");
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    // One run for both keys: the 48-byte tag is split into the AES-128 key
    // and the 256-bit key, so the suite shares a single derivation cost.
    let mut out = [0u8; 48];
    argon2
        .hash_password_into(secret.as_bytes(), ARGON2_SALT, &mut out)
        .expect("argon2id derivation with valid parameters cannot fail");
    let mut keys = DerivedKeys {
        key_128: [0u8; 16],
        key_256: [0u8; 32],
    };
    keys.key_128.copy_from_slice(&out[..16]);
    keys.key_256.copy_from_slice(&out[16..]);
    keys
}

/// Argon2id-derived legacy data-plane keys, cached per secret.
pub fn derive_key_pair_argon2id(secret: &str) -> DerivedKeys {
    let cache = KEY_CACHE.get_or_init(|| Mutex::new(HashMap::new()));
    let mut guard = cache.lock().unwrap();
    if let Some(keys) = guard.get(secret) {
        return *keys;
    }
    let keys = argon2_derive(secret);
    if guard.len() >= KEY_CACHE_CAP {
        guard.clear();
    }
    guard.insert(secret.into(), keys);
    keys
}

/// Legacy data-plane encryptor that carries both KDF suites and selects one
/// per packet (crypto-review S1.1).
///
/// Sealing picks the suite named by the caller (negotiated from the
/// destination's handshake features) and records the choice in the packet
/// header marker, mirroring how `AeadBinding` is negotiated. Opening reads
/// that marker, so the receiver needs no per-peer state — in particular
/// relayed packets decrypt correctly even when sender and receiver have no
/// direct connection to negotiate on. Flipping the marker without the key
/// only makes authentication fail.
pub struct NegotiatedKdfEncryptor {
    v1: Arc<dyn Encryptor>,
    v2: Option<Arc<dyn Encryptor>>,
}

impl NegotiatedKdfEncryptor {
    pub fn new(v1: Arc<dyn Encryptor>, v2: Option<Arc<dyn Encryptor>>) -> Self {
        Self { v1, v2 }
    }

    fn select(&self, v2: bool) -> &Arc<dyn Encryptor> {
        if v2 {
            self.v2.as_ref().unwrap_or(&self.v1)
        } else {
            &self.v1
        }
    }
}

impl Encryptor for NegotiatedKdfEncryptor {
    fn decrypt(&self, zc_packet: &mut ZCPacket) -> Result<(), Error> {
        let uses_v2 = zc_packet
            .peer_manager_header()
            .is_some_and(|hdr| hdr.is_kdf_v2());
        let ret = self.select(uses_v2).decrypt(zc_packet);
        if ret.is_ok() && uses_v2 {
            // Clear the selector once the packet is plaintext again, matching
            // how AEAD backends clear the header-AAD marker after opening.
            if let Some(hdr) = zc_packet.mut_peer_manager_header() {
                hdr.set_kdf_v2(false);
            }
        }
        ret
    }

    fn encrypt(&self, zc_packet: &mut ZCPacket, binding: AeadBinding) -> Result<(), Error> {
        self.encrypt_with_suite(zc_packet, binding, KdfSuite::V1SipHash)
    }

    fn encrypt_with_suite(
        &self,
        zc_packet: &mut ZCPacket,
        binding: AeadBinding,
        kdf: KdfSuite,
    ) -> Result<(), Error> {
        // Mark before sealing: the receiver selects its decryptor from this
        // bit. Backends only manage their own header bits, so the marker
        // survives `seal_aad` untouched. Without a v2 encryptor (encryption
        // disabled builds never construct one) fall back to v1 and clear the
        // marker so both sides agree.
        let uses_v2 = kdf == KdfSuite::V2Argon2id && self.v2.is_some();
        if let Some(hdr) = zc_packet.mut_peer_manager_header() {
            hdr.set_kdf_v2(uses_v2);
        }
        self.select(uses_v2).encrypt(zc_packet, binding)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tunnel::encrypt::{
        create_encryptor, create_legacy_encryptor, derive_key_128, derive_key_256,
    };

    fn sealed_packet(payload: &[u8]) -> ZCPacket {
        let mut packet = ZCPacket::new_with_payload(payload);
        packet.fill_peer_manager_hdr(1, 2, 1);
        packet
    }

    #[test]
    fn argon2id_keys_are_stable_and_distinct_from_v1() {
        let keys = derive_key_pair_argon2id("secret");
        // Cache hit returns the same derivation.
        assert_eq!(derive_key_pair_argon2id("secret"), keys);
        assert_ne!(derive_key_pair_argon2id("secret2"), keys);

        let legacy_128 = derive_key_128("secret");
        let legacy_256 = derive_key_256("secret");
        assert_ne!(keys.key_128, legacy_128);
        assert_ne!(keys.key_256, legacy_256);
    }

    #[test]
    fn negotiated_encryptor_round_trips_both_suites() {
        let v1 = create_legacy_encryptor("aes-gcm", [1; 16], [1; 32]);
        let v2_keys = derive_key_pair_argon2id("secret");
        let v2 = create_legacy_encryptor("aes-gcm", v2_keys.key_128, v2_keys.key_256);
        let sender = NegotiatedKdfEncryptor::new(v1.clone(), Some(v2.clone()));
        let receiver = NegotiatedKdfEncryptor::new(v1, Some(v2));

        for (suite, payload) in [
            (KdfSuite::V1SipHash, "legacy suite payload"),
            (KdfSuite::V2Argon2id, "argon2id suite payload"),
        ] {
            let mut packet = sealed_packet(payload.as_bytes());
            sender
                .encrypt_with_suite(&mut packet, AeadBinding::None, suite)
                .unwrap();
            assert_eq!(
                packet.peer_manager_header().unwrap().is_kdf_v2(),
                suite == KdfSuite::V2Argon2id
            );
            receiver.decrypt(&mut packet).unwrap();
            assert_eq!(packet.payload(), payload.as_bytes());
            assert!(!packet.peer_manager_header().unwrap().is_kdf_v2());
        }
    }

    #[test]
    fn v2_packets_interoperate_with_plain_v2_key_encryptors() {
        // A v2-keyed encryptor without marker handling (e.g. the secure-mode
        // session layer reusing the same backends) must open what the
        // negotiated encryptor seals: the marker is inert for backends that
        // ignore it. The reverse direction cannot exist on the wire — a
        // marker-less v2-keyed sender is either an old peer (v1 keys) or a
        // new peer (always marks) — so it is not tested.
        let v2_keys = derive_key_pair_argon2id("secret");
        let plain = create_encryptor("aes-gcm", v2_keys.key_128, v2_keys.key_256);
        let negotiated = NegotiatedKdfEncryptor::new(
            create_legacy_encryptor("aes-gcm", [9; 16], [9; 32]),
            Some(create_legacy_encryptor(
                "aes-gcm",
                v2_keys.key_128,
                v2_keys.key_256,
            )),
        );

        let mut packet = sealed_packet(b"cross format");
        negotiated
            .encrypt_with_suite(&mut packet, AeadBinding::None, KdfSuite::V2Argon2id)
            .unwrap();
        plain.decrypt(&mut packet).unwrap();
        assert_eq!(packet.payload(), b"cross format");
    }

    #[test]
    fn v1_packets_stay_v1_and_interoperate_with_plain_v1_encryptors() {
        let v2_keys = derive_key_pair_argon2id("secret");
        let negotiated = NegotiatedKdfEncryptor::new(
            create_legacy_encryptor("aes-gcm", [1; 16], [1; 32]),
            Some(create_legacy_encryptor(
                "aes-gcm",
                v2_keys.key_128,
                v2_keys.key_256,
            )),
        );
        let plain_v1 = create_legacy_encryptor("aes-gcm", [1; 16], [1; 32]);

        let mut packet = sealed_packet(b"v1 interop");
        negotiated
            .encrypt_with_suite(&mut packet, AeadBinding::None, KdfSuite::V1SipHash)
            .unwrap();
        assert!(!packet.peer_manager_header().unwrap().is_kdf_v2());
        plain_v1.decrypt(&mut packet).unwrap();
        assert_eq!(packet.payload(), b"v1 interop");
    }

    #[test]
    fn marker_tampering_fails_closed() {
        let v2_keys = derive_key_pair_argon2id("secret");
        let receiver = NegotiatedKdfEncryptor::new(
            create_legacy_encryptor("aes-gcm", [1; 16], [1; 32]),
            Some(create_legacy_encryptor(
                "aes-gcm",
                v2_keys.key_128,
                v2_keys.key_256,
            )),
        );

        // Strip the marker: the packet is then opened with v1 keys and must
        // fail authentication.
        let mut packet = sealed_packet(b"marked");
        receiver
            .encrypt_with_suite(&mut packet, AeadBinding::None, KdfSuite::V2Argon2id)
            .unwrap();
        packet.mut_peer_manager_header().unwrap().set_kdf_v2(false);
        assert!(receiver.decrypt(&mut packet).is_err());

        // Forge the marker on a v1 packet: v2 keys, same failure.
        let mut packet = sealed_packet(b"unmarked");
        receiver
            .encrypt_with_suite(&mut packet, AeadBinding::None, KdfSuite::V1SipHash)
            .unwrap();
        packet.mut_peer_manager_header().unwrap().set_kdf_v2(true);
        assert!(receiver.decrypt(&mut packet).is_err());
    }

    #[test]
    fn negotiated_encryptor_keeps_replay_protection_per_suite() {
        let v2_keys = derive_key_pair_argon2id("secret");
        let sender = NegotiatedKdfEncryptor::new(
            create_legacy_encryptor("aes-gcm", [1; 16], [1; 32]),
            Some(create_legacy_encryptor(
                "aes-gcm",
                v2_keys.key_128,
                v2_keys.key_256,
            )),
        );
        let receiver = NegotiatedKdfEncryptor::new(
            create_legacy_encryptor("aes-gcm", [1; 16], [1; 32]),
            Some(create_legacy_encryptor(
                "aes-gcm",
                v2_keys.key_128,
                v2_keys.key_256,
            )),
        );

        let mut packet = sealed_packet(b"only once");
        sender
            .encrypt_with_suite(&mut packet, AeadBinding::None, KdfSuite::V2Argon2id)
            .unwrap();
        let mut replay = packet.clone();
        receiver.decrypt(&mut packet).unwrap();
        assert!(matches!(
            receiver.decrypt(&mut replay),
            Err(Error::ReplayDetected)
        ));
    }
}
