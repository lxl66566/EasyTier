use crate::{
    config::EncryptionAlgorithm,
    packet::{PEER_MANAGER_HEADER_SIZE, ZCPacket},
};
use std::{collections::hash_map::DefaultHasher, hash::Hasher, sync::Arc};

#[cfg(feature = "aes-gcm")]
#[cfg_attr(
    any(feature = "openssl-crypto", feature = "ring-crypto"),
    allow(dead_code)
)]
pub mod aes_gcm;
#[cfg(feature = "chacha20")]
#[cfg_attr(
    any(feature = "openssl-crypto", feature = "ring-crypto"),
    allow(dead_code)
)]
pub mod chacha20;
#[cfg(feature = "openssl-crypto")]
mod openssl;
#[cfg(all(feature = "ring-crypto", any(not(feature = "openssl-crypto"), test)))]
mod ring;
#[cfg(all(target_os = "wasi", feature = "wasi-crypto-offload"))]
mod wasi_host;

pub(crate) mod kdf;
mod legacy_aead;
pub(crate) mod replay_window;

pub mod xor;

pub use kdf::{
    KdfSuite, NegotiatedKdfEncryptor, derive_challenge_key_argon2id, derive_key_pair_argon2id,
};

// The disabled backends keep the same error Interface as the AEAD backends.
#[allow(dead_code)]
#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("packet is too short. len: {0}")]
    PacketTooShort(usize),
    #[error("decryption failed")]
    DecryptionFailed,
    #[error("encryption failed")]
    EncryptionFailed,
    #[error("invalid encryption algorithm: {0}")]
    InvalidAlgorithm(String),
    #[error("encryption algorithm is unavailable in this build: {0}")]
    AlgorithmUnavailable(String),
    #[error("replayed packet rejected")]
    ReplayDetected,
}

/// Sender-side choice of AEAD additional-data binding.
///
/// AEAD backends honor this when sealing; unauthenticated backends (xor, null)
/// ignore it. [`AeadBinding::Header`] marks the packet (reserved byte) so the
/// receiver's `decrypt` picks the same binding; tampering with the marker only
/// makes decryption fail.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AeadBinding {
    /// Empty AAD, interoperable with peers predating header authentication.
    #[default]
    None,
    /// Bind the canonicalized [`crate::packet::PeerManagerHeader`] into the
    /// AAD, authenticating from/to peer ids, packet type, stable flags and
    /// payload length. Requires the final header to be complete at seal time.
    Header,
}

/// AAD bytes for sealing: marks the packet per `binding` first so the wire
/// marker and the authenticated bytes cannot disagree.
pub(super) fn seal_aad(
    zc_packet: &mut ZCPacket,
    binding: AeadBinding,
) -> Result<Option<[u8; PEER_MANAGER_HEADER_SIZE]>, Error> {
    let header = zc_packet
        .mut_peer_manager_header()
        .ok_or(Error::EncryptionFailed)?;
    match binding {
        AeadBinding::None => {
            header.set_header_aad(false);
            Ok(None)
        }
        AeadBinding::Header => {
            header.set_header_aad(true);
            Ok(Some(header.aad_bytes()))
        }
    }
}

/// AAD bytes for opening, selected by the packet's wire marker.
pub(super) fn open_aad(zc_packet: &ZCPacket) -> Option<[u8; PEER_MANAGER_HEADER_SIZE]> {
    let header = zc_packet.peer_manager_header()?;
    header.is_header_aad().then(|| header.aad_bytes())
}

pub trait Encryptor: Send + Sync + 'static {
    /// Decrypts in place. AEAD backends select the AAD from the packet's
    /// header marker (see [`crate::packet::HEADER_AAD_MARKER`]), so no
    /// binding parameter is needed here.
    fn decrypt(&self, zc_packet: &mut ZCPacket) -> Result<(), Error>;
    fn encrypt(&self, zc_packet: &mut ZCPacket, binding: AeadBinding) -> Result<(), Error>;
    fn encrypt_with_nonce(
        &self,
        zc_packet: &mut ZCPacket,
        _nonce: Option<&[u8]>,
        binding: AeadBinding,
    ) -> Result<(), Error> {
        self.encrypt(zc_packet, binding)
    }
    /// Seals under a chosen key-derivation suite (crypto-review S1.1).
    ///
    /// Backends that do not derive keys from the network secret (secure-mode
    /// session ciphers, single-suite encryptors) ignore the suite; only
    /// [`NegotiatedKdfEncryptor`] acts on it, recording the choice in the
    /// packet header (see [`crate::packet::KDF_V2_MARKER`]).
    fn encrypt_with_suite(
        &self,
        zc_packet: &mut ZCPacket,
        binding: AeadBinding,
        _kdf: KdfSuite,
    ) -> Result<(), Error> {
        self.encrypt(zc_packet, binding)
    }
}

pub struct NullCipher;

struct UnsupportedCipher {
    algorithm: String,
    unavailable: bool,
}

pub fn derive_key_128(secret: &str) -> [u8; 16] {
    let mut key = [0u8; 16];
    let mut hasher = DefaultHasher::new();
    hasher.write(secret.as_bytes());
    key[0..8].copy_from_slice(&hasher.finish().to_be_bytes());
    hasher.write(&key[0..8]);
    key[8..16].copy_from_slice(&hasher.finish().to_be_bytes());
    hasher.write(&key);
    key
}

pub fn derive_key_256(secret: &str) -> [u8; 32] {
    let mut key = [0u8; 32];
    let mut hasher = DefaultHasher::new();
    hasher.write(secret.as_bytes());
    hasher.write(b"easytier-256bit-key");
    for i in 0..4 {
        let chunk_start = i * 8;
        let chunk_end = chunk_start + 8;
        hasher.write(&key[0..chunk_start]);
        hasher.write(&[i as u8]);
        key[chunk_start..chunk_end].copy_from_slice(&hasher.finish().to_be_bytes());
    }
    key
}

impl Encryptor for NullCipher {
    fn decrypt(&self, zc_packet: &mut ZCPacket) -> Result<(), Error> {
        let pm_header = zc_packet.peer_manager_header().unwrap();
        if pm_header.is_encrypted() {
            Err(Error::DecryptionFailed)
        } else {
            Ok(())
        }
    }

    // No authentication to bind; the AAD binding is meaningless without a tag.
    fn encrypt(&self, _zc_packet: &mut ZCPacket, _binding: AeadBinding) -> Result<(), Error> {
        Ok(())
    }
}

impl UnsupportedCipher {
    fn error(&self) -> Error {
        if self.unavailable {
            Error::AlgorithmUnavailable(self.algorithm.clone())
        } else {
            Error::InvalidAlgorithm(self.algorithm.clone())
        }
    }
}

impl Encryptor for UnsupportedCipher {
    fn decrypt(&self, _zc_packet: &mut ZCPacket) -> Result<(), Error> {
        Err(self.error())
    }

    fn encrypt(&self, _zc_packet: &mut ZCPacket, _binding: AeadBinding) -> Result<(), Error> {
        Err(self.error())
    }
}

fn invalid_encryptor(algorithm: &str) -> Arc<dyn Encryptor> {
    Arc::new(UnsupportedCipher {
        algorithm: algorithm.to_owned(),
        unavailable: false,
    })
}

#[allow(dead_code)] // Selected disabled backends call this in reduced profiles.
fn unavailable_encryptor(algorithm: &str) -> Arc<dyn Encryptor> {
    Arc::new(UnsupportedCipher {
        algorithm: algorithm.to_owned(),
        unavailable: true,
    })
}

pub(crate) fn algorithm_is_available(algorithm: EncryptionAlgorithm) -> bool {
    match algorithm {
        EncryptionAlgorithm::Xor => true,
        EncryptionAlgorithm::AesGcm | EncryptionAlgorithm::Aes256Gcm => cfg!(any(
            feature = "aes-gcm",
            feature = "openssl-crypto",
            feature = "ring-crypto"
        )),
        EncryptionAlgorithm::ChaCha20 => cfg!(any(
            feature = "chacha20",
            feature = "openssl-crypto",
            feature = "ring-crypto"
        )),
    }
}

fn is_aead_algorithm(algorithm: EncryptionAlgorithm) -> bool {
    matches!(
        algorithm,
        EncryptionAlgorithm::AesGcm
            | EncryptionAlgorithm::Aes256Gcm
            | EncryptionAlgorithm::ChaCha20
    )
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AeadBackend {
    #[cfg(feature = "openssl-crypto")]
    OpenSsl,
    #[cfg(all(not(feature = "openssl-crypto"), feature = "ring-crypto"))]
    Ring,
    #[cfg(all(
        not(feature = "openssl-crypto"),
        not(feature = "ring-crypto"),
        any(feature = "aes-gcm", feature = "chacha20")
    ))]
    RustCrypto,
}

#[cfg(feature = "openssl-crypto")]
fn preferred_aead_backend(algorithm: EncryptionAlgorithm) -> Option<AeadBackend> {
    is_aead_algorithm(algorithm).then_some(AeadBackend::OpenSsl)
}

#[cfg(all(not(feature = "openssl-crypto"), feature = "ring-crypto"))]
fn preferred_aead_backend(algorithm: EncryptionAlgorithm) -> Option<AeadBackend> {
    is_aead_algorithm(algorithm).then_some(AeadBackend::Ring)
}

#[cfg(all(
    not(feature = "openssl-crypto"),
    not(feature = "ring-crypto"),
    any(feature = "aes-gcm", feature = "chacha20")
))]
fn preferred_aead_backend(algorithm: EncryptionAlgorithm) -> Option<AeadBackend> {
    (is_aead_algorithm(algorithm) && algorithm_is_available(algorithm))
        .then_some(AeadBackend::RustCrypto)
}

#[cfg(not(any(
    feature = "openssl-crypto",
    feature = "ring-crypto",
    feature = "aes-gcm",
    feature = "chacha20"
)))]
fn preferred_aead_backend(_algorithm: EncryptionAlgorithm) -> Option<AeadBackend> {
    None
}

#[allow(unreachable_patterns)]
fn create_aes_128(key: [u8; 16]) -> Arc<dyn Encryptor> {
    let fallback = match preferred_aead_backend(EncryptionAlgorithm::AesGcm) {
        #[cfg(feature = "openssl-crypto")]
        Some(AeadBackend::OpenSsl) => Arc::new(openssl::OpenSslCipher::new_aes128_gcm(key)),
        #[cfg(all(not(feature = "openssl-crypto"), feature = "ring-crypto"))]
        Some(AeadBackend::Ring) => Arc::new(ring::RingCipher::new_aes128_gcm(key)),
        #[cfg(all(
            not(feature = "openssl-crypto"),
            not(feature = "ring-crypto"),
            feature = "aes-gcm"
        ))]
        Some(AeadBackend::RustCrypto) => Arc::new(aes_gcm::AesGcmCipher::new_128(key)),
        _ => unavailable_encryptor("aes-gcm"),
    };
    maybe_offload_aead(EncryptionAlgorithm::AesGcm, &key, fallback)
}

#[allow(unreachable_patterns)]
fn create_aes_256(key: [u8; 32]) -> Arc<dyn Encryptor> {
    let fallback = match preferred_aead_backend(EncryptionAlgorithm::Aes256Gcm) {
        #[cfg(feature = "openssl-crypto")]
        Some(AeadBackend::OpenSsl) => Arc::new(openssl::OpenSslCipher::new_aes256_gcm(key)),
        #[cfg(all(not(feature = "openssl-crypto"), feature = "ring-crypto"))]
        Some(AeadBackend::Ring) => Arc::new(ring::RingCipher::new_aes256_gcm(key)),
        #[cfg(all(
            not(feature = "openssl-crypto"),
            not(feature = "ring-crypto"),
            feature = "aes-gcm"
        ))]
        Some(AeadBackend::RustCrypto) => Arc::new(aes_gcm::AesGcmCipher::new_256(key)),
        _ => unavailable_encryptor("aes-256-gcm"),
    };
    maybe_offload_aead(EncryptionAlgorithm::Aes256Gcm, &key, fallback)
}

#[allow(unreachable_patterns)]
fn create_chacha20(key: [u8; 32]) -> Arc<dyn Encryptor> {
    let fallback = match preferred_aead_backend(EncryptionAlgorithm::ChaCha20) {
        #[cfg(feature = "openssl-crypto")]
        Some(AeadBackend::OpenSsl) => Arc::new(openssl::OpenSslCipher::new_chacha20(key)),
        #[cfg(all(not(feature = "openssl-crypto"), feature = "ring-crypto"))]
        Some(AeadBackend::Ring) => Arc::new(ring::RingCipher::new_chacha20(key)),
        #[cfg(all(
            not(feature = "openssl-crypto"),
            not(feature = "ring-crypto"),
            feature = "chacha20"
        ))]
        Some(AeadBackend::RustCrypto) => Arc::new(chacha20::ChaCha20Cipher::new(key)),
        _ => unavailable_encryptor("chacha20"),
    };
    maybe_offload_aead(EncryptionAlgorithm::ChaCha20, &key, fallback)
}

#[cfg(all(target_os = "wasi", feature = "wasi-crypto-offload"))]
fn maybe_offload_aead(
    algorithm: EncryptionAlgorithm,
    key: &[u8],
    fallback: Arc<dyn Encryptor>,
) -> Arc<dyn Encryptor> {
    Arc::new(wasi_host::WasiHostAead::new(algorithm, key, fallback))
}

#[cfg(not(all(target_os = "wasi", feature = "wasi-crypto-offload")))]
fn maybe_offload_aead(
    _algorithm: EncryptionAlgorithm,
    _key: &[u8],
    fallback: Arc<dyn Encryptor>,
) -> Arc<dyn Encryptor> {
    fallback
}

pub(crate) fn validate_algorithm(algorithm: &str) -> Result<(), Error> {
    let parsed = algorithm
        .parse::<EncryptionAlgorithm>()
        .map_err(|()| Error::InvalidAlgorithm(algorithm.to_owned()))?;
    if algorithm_is_available(parsed) {
        Ok(())
    } else {
        Err(Error::AlgorithmUnavailable(parsed.to_string()))
    }
}

/// Create an encryptor based on the algorithm name.
///
/// Callers that accept user configuration validate it during construction.
/// Protocol paths remain infallible here and receive an encryptor that returns
/// an explicit error if a peer names an invalid or unavailable algorithm.
pub fn create_encryptor(
    algorithm: &str,
    key_128: [u8; 16],
    key_256: [u8; 32],
) -> Arc<dyn Encryptor> {
    let Ok(algorithm) = algorithm.parse::<EncryptionAlgorithm>() else {
        return invalid_encryptor(algorithm);
    };

    match algorithm {
        EncryptionAlgorithm::Xor => Arc::new(xor::XorCipher::new(&key_128)),
        EncryptionAlgorithm::AesGcm => create_aes_128(key_128),
        EncryptionAlgorithm::Aes256Gcm => create_aes_256(key_256),
        EncryptionAlgorithm::ChaCha20 => create_chacha20(key_256),
    }
}

/// Creates the legacy data-plane encryptor (crypto-review S1.3 / S1.4).
///
/// AEAD backends are wrapped with counter-nonce generation and replay
/// filtering; the wire format is unchanged so upgraded and old peers
/// interoperate freely. XOR keeps its historical behavior: it has no
/// authentication tag and no nonce on the wire, so neither nonce management
/// nor replay filtering applies. Invalid algorithms return the plain error
/// cipher unchanged.
pub fn create_legacy_encryptor(
    algorithm: &str,
    key_128: [u8; 16],
    key_256: [u8; 32],
) -> Arc<dyn Encryptor> {
    let inner = create_encryptor(algorithm, key_128, key_256);
    let uses_aead = algorithm
        .parse::<EncryptionAlgorithm>()
        .is_ok_and(is_aead_algorithm);
    if uses_aead {
        Arc::new(legacy_aead::ReplayProtectedEncryptor::new(inner))
    } else {
        inner
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::{StandardAeadTail, ZCPacket};

    // Callers are combinations of feature-gated backends; keep it linked
    // whenever any pair could be compiled.
    #[allow(dead_code)]
    fn assert_interoperable(left: &dyn Encryptor, right: &dyn Encryptor) {
        // Both binding modes must interoperate across backends: `None` keeps
        // the legacy wire format, `Header` must produce identical ciphertext
        // (same AAD, same nonce) on every backend.
        for binding in [AeadBinding::None, AeadBinding::Header] {
            let plaintext = b"cross-backend compatibility";
            let nonce = [9; StandardAeadTail::NONCE_SIZE];
            let mut left_packet = ZCPacket::new_with_payload(plaintext);
            left_packet.fill_peer_manager_hdr(1, 2, 1);
            let mut right_packet = ZCPacket::new_with_payload(plaintext);
            right_packet.fill_peer_manager_hdr(1, 2, 1);

            left.encrypt_with_nonce(&mut left_packet, Some(&nonce), binding)
                .unwrap();
            right
                .encrypt_with_nonce(&mut right_packet, Some(&nonce), binding)
                .unwrap();
            assert_eq!(left_packet.payload(), right_packet.payload());

            left.decrypt(&mut right_packet).unwrap();
            right.decrypt(&mut left_packet).unwrap();
            assert_eq!(left_packet.payload(), plaintext);
            assert_eq!(right_packet.payload(), plaintext);
            assert!(!left_packet.peer_manager_header().unwrap().is_header_aad());
        }
    }

    #[test]
    fn network_secret_key_derivation_is_stable() {
        assert_eq!(
            derive_key_128("secret"),
            [
                86, 90, 25, 219, 78, 240, 193, 33, 168, 172, 88, 14, 218, 248, 78, 166,
            ]
        );
        assert_eq!(
            derive_key_256("secret"),
            [
                199, 205, 248, 94, 194, 101, 97, 138, 79, 69, 167, 248, 140, 5, 165, 163, 192, 139,
                166, 217, 166, 152, 28, 230, 146, 109, 150, 196, 66, 242, 231, 140,
            ]
        );
    }

    #[cfg(not(any(
        feature = "aes-gcm",
        feature = "openssl-crypto",
        feature = "ring-crypto"
    )))]
    #[test]
    fn unavailable_aes_is_known_but_rejected() {
        assert_eq!(
            validate_algorithm("aes-gcm").unwrap_err().to_string(),
            "encryption algorithm is unavailable in this build: aes-gcm"
        );
    }

    #[cfg(any(
        feature = "aes-gcm",
        feature = "openssl-crypto",
        feature = "ring-crypto"
    ))]
    #[test]
    fn compiled_aes_is_available() {
        validate_algorithm("aes-gcm").unwrap();
        validate_algorithm("aes-256-gcm").unwrap();
    }

    #[cfg(not(any(
        feature = "chacha20",
        feature = "openssl-crypto",
        feature = "ring-crypto"
    )))]
    #[test]
    fn unavailable_chacha20_is_known_but_rejected() {
        assert_eq!(
            validate_algorithm("chacha20-poly1305")
                .unwrap_err()
                .to_string(),
            "encryption algorithm is unavailable in this build: chacha20"
        );
    }

    #[cfg(any(
        feature = "chacha20",
        feature = "openssl-crypto",
        feature = "ring-crypto"
    ))]
    #[test]
    fn compiled_chacha20_is_available() {
        validate_algorithm("chacha20").unwrap();
    }

    #[test]
    fn accelerated_backends_take_precedence_over_rustcrypto() {
        #[cfg(feature = "openssl-crypto")]
        assert_eq!(
            preferred_aead_backend(EncryptionAlgorithm::AesGcm),
            Some(AeadBackend::OpenSsl)
        );

        #[cfg(all(not(feature = "openssl-crypto"), feature = "ring-crypto"))]
        assert_eq!(
            preferred_aead_backend(EncryptionAlgorithm::AesGcm),
            Some(AeadBackend::Ring)
        );

        #[cfg(all(
            not(feature = "openssl-crypto"),
            not(feature = "ring-crypto"),
            feature = "aes-gcm"
        ))]
        assert_eq!(
            preferred_aead_backend(EncryptionAlgorithm::AesGcm),
            Some(AeadBackend::RustCrypto)
        );
    }

    #[cfg(all(feature = "ring-crypto", feature = "aes-gcm"))]
    #[test]
    fn ring_and_rustcrypto_aes_are_interoperable() {
        assert_interoperable(
            &ring::RingCipher::new_aes128_gcm([1; 16]),
            &aes_gcm::AesGcmCipher::new_128([1; 16]),
        );
        assert_interoperable(
            &ring::RingCipher::new_aes256_gcm([2; 32]),
            &aes_gcm::AesGcmCipher::new_256([2; 32]),
        );
    }

    #[cfg(all(feature = "ring-crypto", feature = "chacha20"))]
    #[test]
    fn ring_and_rustcrypto_chacha20_are_interoperable() {
        assert_interoperable(
            &ring::RingCipher::new_chacha20([3; 32]),
            &chacha20::ChaCha20Cipher::new([3; 32]),
        );
    }

    #[cfg(all(feature = "openssl-crypto", feature = "aes-gcm"))]
    #[test]
    fn openssl_and_rustcrypto_aes_are_interoperable() {
        assert_interoperable(
            &openssl::OpenSslCipher::new_aes128_gcm([1; 16]),
            &aes_gcm::AesGcmCipher::new_128([1; 16]),
        );
        assert_interoperable(
            &openssl::OpenSslCipher::new_aes256_gcm([2; 32]),
            &aes_gcm::AesGcmCipher::new_256([2; 32]),
        );
    }

    #[cfg(all(feature = "openssl-crypto", feature = "chacha20"))]
    #[test]
    fn openssl_and_rustcrypto_chacha20_are_interoperable() {
        assert_interoperable(
            &openssl::OpenSslCipher::new_chacha20([3; 32]),
            &chacha20::ChaCha20Cipher::new([3; 32]),
        );
    }

    #[cfg(all(feature = "openssl-crypto", feature = "ring-crypto"))]
    #[test]
    fn openssl_and_ring_algorithms_are_interoperable() {
        assert_interoperable(
            &openssl::OpenSslCipher::new_aes128_gcm([1; 16]),
            &ring::RingCipher::new_aes128_gcm([1; 16]),
        );
        assert_interoperable(
            &openssl::OpenSslCipher::new_aes256_gcm([2; 32]),
            &ring::RingCipher::new_aes256_gcm([2; 32]),
        );
        assert_interoperable(
            &openssl::OpenSslCipher::new_chacha20([3; 32]),
            &ring::RingCipher::new_chacha20([3; 32]),
        );
    }

    #[test]
    fn invalid_algorithm_is_rejected() {
        assert_eq!(
            validate_algorithm("rot13").unwrap_err().to_string(),
            "invalid encryption algorithm: rot13"
        );
    }

    #[cfg(any(
        feature = "aes-gcm",
        feature = "openssl-crypto",
        feature = "ring-crypto"
    ))]
    mod header_aad {
        use super::*;
        use crate::packet::PacketType;

        fn aead_encryptor() -> Arc<dyn Encryptor> {
            create_encryptor("aes-gcm", [1; 16], [2; 32])
        }

        fn encrypted_packet(binding: AeadBinding) -> ZCPacket {
            let cipher = aead_encryptor();
            let mut packet = ZCPacket::new_with_payload(b"authenticated payload");
            packet.fill_peer_manager_hdr(11, 22, PacketType::Data as u8);
            cipher.encrypt(&mut packet, binding).unwrap();
            packet
        }

        #[test]
        fn header_binding_round_trips() {
            let cipher = aead_encryptor();
            let mut packet = encrypted_packet(AeadBinding::Header);
            assert!(packet.peer_manager_header().unwrap().is_header_aad());
            cipher.decrypt(&mut packet).unwrap();
            assert_eq!(packet.payload(), b"authenticated payload");
            assert!(!packet.peer_manager_header().unwrap().is_encrypted());
            assert!(!packet.peer_manager_header().unwrap().is_header_aad());
        }

        #[test]
        fn tampering_any_authenticated_header_field_fails() {
            let cipher = aead_encryptor();
            let tamper_from = |p: &mut ZCPacket| {
                p.mut_peer_manager_header().unwrap().from_peer_id.set(33);
            };
            let tamper_to =
                |p: &mut ZCPacket| p.mut_peer_manager_header().unwrap().to_peer_id.set(44);
            let tamper_type = |p: &mut ZCPacket| {
                p.mut_peer_manager_header().unwrap().packet_type = PacketType::RoutePacket as u8;
            };
            let tamper_flags = |p: &mut ZCPacket| {
                p.mut_peer_manager_header().unwrap().set_no_proxy(true);
            };
            let tamper_len = |p: &mut ZCPacket| {
                let hdr = p.mut_peer_manager_header().unwrap();
                hdr.len.set(hdr.len.get() + 1);
            };

            for tamper in [
                tamper_from,
                tamper_to,
                tamper_type,
                tamper_flags,
                tamper_len,
            ] {
                let mut packet = encrypted_packet(AeadBinding::Header);
                tamper(&mut packet);
                assert!(
                    cipher.decrypt(&mut packet).is_err(),
                    "tampered header must not decrypt"
                );
            }
        }

        #[test]
        fn relay_legal_header_mutations_still_decrypt() {
            // Intermediate hops bump forward_counter and may clear
            // LATENCY_FIRST while forwarding an encrypted packet; both are
            // excluded from the canonical AAD.
            let cipher = aead_encryptor();
            let mut packet = encrypted_packet(AeadBinding::Header);
            {
                let hdr = packet.mut_peer_manager_header().unwrap();
                hdr.set_latency_first(true);
                hdr.forward_counter += 1;
            }
            cipher.decrypt(&mut packet).unwrap();
            assert_eq!(packet.payload(), b"authenticated payload");
        }

        #[test]
        fn marker_tampering_fails_closed() {
            let cipher = aead_encryptor();

            // Stripping the marker downgrades to the empty AAD and must fail.
            let mut packet = encrypted_packet(AeadBinding::Header);
            packet
                .mut_peer_manager_header()
                .unwrap()
                .set_header_aad(false);
            assert!(cipher.decrypt(&mut packet).is_err());

            // Forging the marker on a legacy-format packet must fail too.
            let mut legacy = encrypted_packet(AeadBinding::None);
            assert!(!legacy.peer_manager_header().unwrap().is_header_aad());
            legacy
                .mut_peer_manager_header()
                .unwrap()
                .set_header_aad(true);
            assert!(cipher.decrypt(&mut legacy).is_err());
        }

        #[test]
        fn none_binding_interoperates_with_legacy_decrypt() {
            // `None` produces exactly the legacy wire format: an old peer
            // (empty AAD, marker ignored) can still open the packet.
            let cipher = aead_encryptor();
            let mut packet = encrypted_packet(AeadBinding::None);
            assert!(!packet.peer_manager_header().unwrap().is_header_aad());
            cipher.decrypt(&mut packet).unwrap();
            assert_eq!(packet.payload(), b"authenticated payload");
        }

        #[test]
        fn seal_aad_and_open_aad_agree() {
            let cipher = aead_encryptor();
            let mut packet = ZCPacket::new_with_payload(b"payload");
            packet.fill_peer_manager_hdr(5, 6, PacketType::RpcReq as u8);
            let sealed = seal_aad(&mut packet, AeadBinding::Header).unwrap();
            assert_eq!(
                sealed.as_ref().map(|b| &b[..]),
                open_aad(&packet).as_ref().map(|b| &b[..])
            );
            assert_eq!(
                seal_aad(&mut packet, AeadBinding::None).unwrap(),
                None,
                "None must clear a stale marker so both sides agree"
            );
            assert_eq!(open_aad(&packet), None);

            cipher.encrypt(&mut packet, AeadBinding::Header).unwrap();
            assert_eq!(
                open_aad(&packet).as_ref().map(|b| &b[..]),
                sealed.as_ref().map(|b| &b[..])
            );
        }
    }
}
