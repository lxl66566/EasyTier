use std::{fmt, str::FromStr};

use strum::VariantArray;

/// Stable configuration vocabulary for every known encryption algorithm.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, VariantArray)]
pub enum EncryptionAlgorithm {
    Xor,
    #[default]
    AesGcm,
    Aes256Gcm,
    ChaCha20,
}

impl EncryptionAlgorithm {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Xor => "xor",
            Self::AesGcm => "aes-gcm",
            Self::Aes256Gcm => "aes-256-gcm",
            Self::ChaCha20 => "chacha20",
        }
    }

    /// True when the algorithm is obfuscation only: no integrity, no replay
    /// protection, and passive attackers can tamper with traffic undetected.
    pub const fn is_insecure(self) -> bool {
        matches!(self, Self::Xor)
    }
}

impl fmt::Display for EncryptionAlgorithm {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl FromStr for EncryptionAlgorithm {
    type Err = ();

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.to_ascii_lowercase().as_str() {
            "xor" => Ok(Self::Xor),
            "aes-gcm" | "openssl-aes-gcm" => Ok(Self::AesGcm),
            "aes-256-gcm" | "openssl-aes-256-gcm" => Ok(Self::Aes256Gcm),
            "chacha20" | "chacha20-poly1305" | "openssl-chacha20" => Ok(Self::ChaCha20),
            _ => Err(()),
        }
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
