//! Persistent self-signed certificate for quic listeners.
//!
//! quic clients authenticate servers by pinning the certificate fingerprint
//! (see `tunnel::tls_verification`), which only works if the certificate and
//! its private key survive restarts. The key pair is stored as PEM in the
//! per-user EasyTier state directory (the same directory that hosts the
//! machine id), written via temp + rename so a crash cannot leave a truncated
//! file behind. A corrupt file is a hard error: silently regenerating the key
//! would rotate the server identity and break pinned peers without a signal.

use std::path::{Path, PathBuf};

use anyhow::{Context as _, bail};
use base64::Engine as _;
#[cfg(not(test))]
use easytier_core::tunnel::fingerprint::format_sha256_fingerprint;
use sha2::{Digest, Sha256};

/// ALPN protocol identifier that quic clients and servers must agree on.
pub(crate) const QUIC_ALPN: &[u8] = b"easytier-quic";

const CERT_FILE_NAME: &str = "quic-server-key.pem";

#[derive(Debug)]
pub(crate) struct QuicServerCert {
    tls: std::sync::Arc<rustls::ServerConfig>,
    fingerprint: [u8; 32],
    // DER material kept around for persistence; the rustls config cannot be
    // introspected back into certificate/key bytes.
    cert_der: Vec<u8>,
    key_der: Vec<u8>,
}

impl QuicServerCert {
    /// Loads the certificate stored in `dir`, generating and persisting a
    /// fresh one on first start. Corrupt or unreadable files are errors.
    pub(crate) fn load_or_generate(dir: &Path) -> anyhow::Result<Self> {
        let path = dir.join(CERT_FILE_NAME);
        match std::fs::read_to_string(&path) {
            Ok(pem) => Self::from_pem(&pem).with_context(|| {
                format!("corrupt quic server certificate file {}", path.display())
            }),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                let cert = Self::generate()?;
                write_pem(&path, &cert)?;
                Ok(cert)
            }
            Err(error) => Err(error).with_context(|| format!("read {}", path.display())),
        }
    }

    fn generate() -> anyhow::Result<Self> {
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()])
            .context("generate quic server certificate")?;
        let cert_der = cert.serialize_der().unwrap();
        let key_der = cert.serialize_private_key_der();
        Self::from_der(cert_der, key_der)
    }

    fn from_der(cert_der: Vec<u8>, key_der: Vec<u8>) -> anyhow::Result<Self> {
        let provider = crate::tunnel::tls_verification::ring_provider();
        let mut tls = rustls::ServerConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])
            .expect("ring provider supports TLS 1.3")
            .with_no_client_auth()
            .with_single_cert(
                vec![rustls::pki_types::CertificateDer::from(cert_der.clone())],
                rustls::pki_types::PrivatePkcs8KeyDer::from(key_der.clone()).into(),
            )
            .context("load quic server certificate")?;
        tls.alpn_protocols = vec![QUIC_ALPN.to_vec()];
        Ok(Self {
            tls: std::sync::Arc::new(tls),
            fingerprint: Sha256::digest(&cert_der).into(),
            cert_der,
            key_der,
        })
    }

    /// Parses the PEM file written by [`write_pem`]: one PKCS#8 private key
    /// block followed by one certificate block (order-insensitive).
    fn from_pem(pem: &str) -> anyhow::Result<Self> {
        let Some(key_der) = pem_block(pem, "PRIVATE KEY") else {
            bail!("missing PRIVATE KEY block");
        };
        let Some(cert_der) = pem_block(pem, "CERTIFICATE") else {
            bail!("missing CERTIFICATE block");
        };
        Self::from_der(cert_der, key_der)
    }

    pub(crate) fn tls_config(&self) -> std::sync::Arc<rustls::ServerConfig> {
        self.tls.clone()
    }

    pub(crate) fn fingerprint(&self) -> [u8; 32] {
        self.fingerprint
    }
}

/// The process-wide quic server certificate.
///
/// Loading is deferred to the first quic listener so processes that never
/// serve quic do not touch the state directory. Errors are sticky: a broken
/// certificate file fails every subsequent use loudly instead of falling back
/// to a fresh key.
static QUIC_SERVER_CERT: std::sync::LazyLock<Result<QuicServerCert, String>> =
    std::sync::LazyLock::new(|| load_for_process().map_err(|error| format!("{error:#}")));

fn load_for_process() -> anyhow::Result<QuicServerCert> {
    #[cfg(test)]
    {
        // Unit tests run in one process and must not write to (or fight over)
        // the real per-user state directory; persistence itself is covered by
        // the load_or_generate tests below.
        return QuicServerCert::generate();
    }
    #[cfg(not(test))]
    {
        let cert = match crate::common::machine_id::default_state_dir() {
            Ok(dir) => QuicServerCert::load_or_generate(&dir)?,
            Err(error) => {
                // No stable state directory (e.g. sandboxed platforms without
                // a home): fall back to an ephemeral key. The fingerprint then
                // rotates on every restart, so pinning is unavailable.
                tracing::warn!(
                    %error,
                    "no state directory for the quic server certificate; using an \
                     ephemeral key, the certificate fingerprint changes on restart"
                );
                QuicServerCert::generate()?
            }
        };
        tracing::info!(
            fingerprint = %format_sha256_fingerprint(&cert.fingerprint()),
            "quic server certificate ready; clients can pin it via '#fingerprint=sha256:<hex>'"
        );
        Ok(cert)
    }
}

pub(crate) fn quic_server_cert() -> anyhow::Result<&'static QuicServerCert> {
    QUIC_SERVER_CERT
        .as_ref()
        .map_err(|error| anyhow::anyhow!("quic server certificate: {error}"))
}

fn write_pem(path: &Path, cert: &QuicServerCert) -> anyhow::Result<()> {
    let (cert_der, key_der) = (cert.cert_der.clone(), cert.key_der.clone());
    let parent = path
        .parent()
        .with_context(|| format!("{} has no parent directory", path.display()))?;
    std::fs::create_dir_all(parent)
        .with_context(|| format!("create quic certificate directory {}", parent.display()))?;
    let pem = format!(
        "{}{}",
        pem_encode("PRIVATE KEY", &key_der),
        pem_encode("CERTIFICATE", &cert_der)
    );
    // Write via temp + rename so a crash mid-write cannot leave a truncated
    // file that would silently rotate the server identity on next start.
    let tmp = PathBuf::from(format!("{}.tmp", path.display()));
    std::fs::write(&tmp, pem).with_context(|| format!("write {}", tmp.display()))?;
    restrict_permissions(&tmp)?;
    std::fs::rename(&tmp, path)
        .with_context(|| format!("rename {} -> {}", tmp.display(), path.display()))?;
    Ok(())
}

fn pem_encode(tag: &str, der: &[u8]) -> String {
    let encoded = base64::engine::general_purpose::STANDARD.encode(der);
    let mut out = format!("-----BEGIN {tag}-----\n");
    for chunk in encoded.as_bytes().chunks(64) {
        out.push_str(std::str::from_utf8(chunk).expect("base64 is ascii"));
        out.push('\n');
    }
    out.push_str(&format!("-----END {tag}-----\n"));
    out
}

/// Extracts and decodes the first `-----BEGIN <tag>-----` block. Whitespace
/// inside the block is ignored, so CRLF-encoded PEM is accepted too.
fn pem_block(pem: &str, tag: &str) -> Option<Vec<u8>> {
    let begin = format!("-----BEGIN {tag}-----");
    let end = format!("-----END {tag}-----");
    let start = pem.find(&begin)? + begin.len();
    let stop = start + pem[start..].find(&end)?;
    let body: String = pem[start..stop]
        .chars()
        .filter(|char| !char.is_whitespace())
        .collect();
    base64::engine::general_purpose::STANDARD.decode(body).ok()
}

#[cfg(unix)]
fn restrict_permissions(path: &Path) -> anyhow::Result<()> {
    use std::os::unix::fs::PermissionsExt as _;
    let mut permissions = std::fs::metadata(path)?.permissions();
    permissions.set_mode(0o600);
    std::fs::set_permissions(path, permissions)?;
    Ok(())
}

#[cfg(not(unix))]
fn restrict_permissions(_path: &Path) -> anyhow::Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn persisted_certificate_keeps_its_fingerprint() {
        let dir = tempfile::tempdir().unwrap();
        let first = QuicServerCert::load_or_generate(dir.path()).unwrap();
        let second = QuicServerCert::load_or_generate(dir.path()).unwrap();
        assert_eq!(first.fingerprint(), second.fingerprint());
        assert!(dir.path().join(CERT_FILE_NAME).is_file());
    }

    #[test]
    fn corrupt_certificate_files_fail_loudly() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(CERT_FILE_NAME);
        std::fs::write(&path, "not a pem file").unwrap();
        let error = QuicServerCert::load_or_generate(dir.path()).unwrap_err();
        assert!(format!("{error:#}").contains("corrupt"), "{error:#}");
    }

    #[test]
    fn pem_blocks_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(CERT_FILE_NAME);
        let cert = QuicServerCert::generate().unwrap();
        write_pem(&path, &cert).unwrap();
        let reloaded = QuicServerCert::from_pem(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(cert.fingerprint(), reloaded.fingerprint());
    }

    #[test]
    fn pem_parser_ignores_line_endings() {
        let key = pem_encode("PRIVATE KEY", &[1, 2, 3]).replace('\n', "\r\n");
        assert_eq!(pem_block(&key, "PRIVATE KEY"), Some(vec![1, 2, 3]));
        assert_eq!(pem_block(&key, "CERTIFICATE"), None);
    }
}
