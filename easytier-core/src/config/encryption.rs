use serde::{Deserialize, Serialize};
use strum::VariantArray;

/// Stable configuration vocabulary for every known encryption algorithm.
#[derive(
    Debug,
    Default,
    Clone,
    Copy,
    PartialEq,
    Eq,
    VariantArray,
    strum::Display,
    strum::EnumString,
    strum::IntoStaticStr,
    strum::AsRefStr,
    Serialize,
    Deserialize,
)]
#[strum(ascii_case_insensitive)]
pub enum EncryptionAlgorithm {
    #[strum(to_string = "xor", serialize = "xor")]
    #[serde(rename = "xor")]
    Xor,

    #[default]
    #[strum(
        to_string = "aes-gcm",
        serialize = "aes-gcm",
        serialize = "openssl-aes-gcm"
    )]
    #[serde(rename = "aes-gcm", alias = "openssl-aes-gcm")]
    AesGcm,

    #[strum(
        to_string = "aes-256-gcm",
        serialize = "aes-256-gcm",
        serialize = "openssl-aes-256-gcm"
    )]
    #[serde(rename = "aes-256-gcm", alias = "openssl-aes-256-gcm")]
    Aes256Gcm,

    #[strum(
        to_string = "chacha20",
        serialize = "chacha20",
        serialize = "chacha20-poly1305",
        serialize = "openssl-chacha20"
    )]
    #[serde(
        rename = "chacha20",
        alias = "chacha20-poly1305",
        alias = "openssl-chacha20"
    )]
    ChaCha20,
}

impl EncryptionAlgorithm {
    /// True when the algorithm is obfuscation only: no integrity, no replay
    /// protection, and passive attackers can tamper with traffic undetected.
    pub const fn is_insecure(self) -> bool {
        matches!(self, Self::Xor)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_algorithm_names_are_stable() {
        let cases = [
            ("xor", EncryptionAlgorithm::Xor),
            ("aes-gcm", EncryptionAlgorithm::AesGcm),
            ("aes-256-gcm", EncryptionAlgorithm::Aes256Gcm),
            ("chacha20", EncryptionAlgorithm::ChaCha20),
            ("chacha20-poly1305", EncryptionAlgorithm::ChaCha20),
            ("openssl-aes-gcm", EncryptionAlgorithm::AesGcm),
            ("openssl-aes-256-gcm", EncryptionAlgorithm::Aes256Gcm),
            ("openssl-chacha20", EncryptionAlgorithm::ChaCha20),
        ];

        for (name, expected) in cases {
            assert_eq!(name.parse(), Ok(expected));
        }
        assert_eq!(EncryptionAlgorithm::ChaCha20.to_string(), "chacha20");
    }

    #[test]
    fn aes_is_the_stable_default() {
        assert_eq!(EncryptionAlgorithm::default(), EncryptionAlgorithm::AesGcm);
    }

    #[test]
    fn xor_is_the_only_insecure_algorithm() {
        // Drives the peer-manager warning path: only an explicitly selected
        // xor must be flagged, never the AEAD defaults.
        for algorithm in EncryptionAlgorithm::VARIANTS {
            assert_eq!(
                algorithm.is_insecure(),
                *algorithm == EncryptionAlgorithm::Xor,
                "{algorithm} misclassified"
            );
        }
        assert!("xor".parse::<EncryptionAlgorithm>().unwrap().is_insecure());
    }
}
