//! SHA-256 fingerprint parsing, formatting and comparison shared by
//! transport pinning surfaces (wss certificate pins, web portal server
//! identity pins).

use subtle::ConstantTimeEq as _;

const HEX_ALPHABET: &[u8; 16] = b"0123456789abcdef";

const SHA256_HEX_LEN: usize = 32 * 2;

fn hex_val(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

/// Parses a `sha256:<64 hex chars>` fingerprint (hex digits case-insensitive).
pub fn parse_sha256_fingerprint(value: &str) -> Option<[u8; 32]> {
    let hex = value.strip_prefix("sha256:")?;
    if hex.len() != SHA256_HEX_LEN {
        return None;
    }
    let bytes = hex.as_bytes();
    let mut digest = [0u8; 32];
    for (i, chunk) in bytes.as_chunks::<2>().0.iter().enumerate() {
        let hi = hex_val(chunk[0])?;
        let lo = hex_val(chunk[1])?;
        digest[i] = (hi << 4) | lo;
    }
    Some(digest)
}

/// Formats a digest as `sha256:<lowercase hex>`.
pub fn format_sha256_fingerprint(digest: &[u8; 32]) -> String {
    let mut out = String::with_capacity("sha256:".len() + SHA256_HEX_LEN);
    out.push_str("sha256:");
    for byte in digest {
        out.push(HEX_ALPHABET[(byte >> 4) as usize] as char);
        out.push(HEX_ALPHABET[(byte & 0xf) as usize] as char);
    }
    out
}

/// Constant-time equality for pinned fingerprints. Compared values are
/// public, so timing leaks are a minor risk, but every pinning surface
/// (web noise pins, wss/quic certificate pins) goes through this one
/// helper so none of them can short-circuit on the first differing byte.
pub fn fingerprint_eq(expected: &[u8; 32], actual: &[u8; 32]) -> bool {
    expected.ct_eq(actual).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let mut digest = [0u8; 32];
        digest[..4].copy_from_slice(&[0x0a, 0xbc, 0xff, 0x10]);
        let formatted = format_sha256_fingerprint(&digest);
        assert_eq!(formatted, format!("sha256:0abcff10{}", "0".repeat(56)));
        assert_eq!(parse_sha256_fingerprint(&formatted), Some(digest));
    }

    #[test]
    fn rejects_malformed_values() {
        assert_eq!(parse_sha256_fingerprint(""), None);
        assert_eq!(parse_sha256_fingerprint("sha256:"), None);
        assert_eq!(parse_sha256_fingerprint("00:11"), None);
        assert_eq!(parse_sha256_fingerprint("sha256:abcd"), None);
        // one hex digit short
        let short = format!("sha256:{}", "a".repeat(63));
        assert_eq!(parse_sha256_fingerprint(&short), None);
        // non-hex characters
        let bad = format!("sha256:{}", "g".repeat(64));
        assert_eq!(parse_sha256_fingerprint(&bad), None);
    }

    #[test]
    fn accepts_uppercase_hex() {
        let value = format!("sha256:{}", "Ab".repeat(32));
        assert_eq!(parse_sha256_fingerprint(&value), Some([0xabu8; 32]));
    }

    #[test]
    fn fingerprint_eq_matches_only_identical_digests() {
        // Correctness at the first, middle and last differing byte; timing
        // uniformity itself cannot be asserted in a unit test, it follows
        // from the constant-time implementation (subtle's ct_eq).
        let digest = [0x5au8; 32];
        assert!(fingerprint_eq(&digest, &digest));
        for position in [0, 15, 31] {
            let mut other = digest;
            other[position] ^= 1;
            assert!(!fingerprint_eq(&digest, &other), "position {position}");
        }
        assert!(!fingerprint_eq(&digest, &[0x5bu8; 32]));
    }
}
