//! Shared rustls server verification for transports that authenticate
//! self-signed servers out-of-band (wss, quic).
//!
//! These transports do not use a PKI: the server identity is either pinned
//! via a SHA-256 fingerprint taken from the url fragment, or — by default —
//! accepted without verification. Unverified still means encrypted, but an
//! active man-in-the-middle can impersonate the server; callers warn about
//! that once per process.

use easytier_core::tunnel::{
    TunnelError,
    fingerprint::{fingerprint_eq, format_sha256_fingerprint, parse_sha256_fingerprint},
};
use sha2::{Digest, Sha256};
use std::sync::Arc;

/// Installs the ring crypto provider as the process-wide rustls default.
/// Safe to call repeatedly; the first call wins, later calls are no-ops.
pub(crate) fn init_crypto_provider() {
    let _ =
        rustls::crypto::CryptoProvider::install_default(rustls::crypto::ring::default_provider());
}

/// Returns the process-wide ring crypto provider, installing it first if
/// needed. Never fails: the provider installed above is always available.
pub(crate) fn ring_provider() -> Arc<rustls::crypto::CryptoProvider> {
    init_crypto_provider();
    rustls::crypto::CryptoProvider::get_default()
        .expect("ring crypto provider installed")
        .clone()
}

#[derive(Debug)]
pub(crate) struct SkipServerVerification(Arc<rustls::crypto::CryptoProvider>);

impl SkipServerVerification {
    pub(crate) fn new(provider: Arc<rustls::crypto::CryptoProvider>) -> Arc<Self> {
        Arc::new(Self(provider))
    }
}

impl rustls::client::danger::ServerCertVerifier for SkipServerVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

/// Verifies the server end-entity certificate against a pinned SHA-256
/// fingerprint instead of a PKI. Handshake signature schemes still follow the
/// process-wide crypto provider; only the certificate identity is pinned.
/// Fingerprint comparison is constant-time via [`fingerprint_eq`]: pins are
/// public values so the risk is low, but the shared helper keeps every
/// pinning surface uniform.
#[derive(Debug)]
pub(crate) struct PinnedServerVerification {
    provider: Arc<rustls::crypto::CryptoProvider>,
    expected: [u8; 32],
}

impl PinnedServerVerification {
    pub(crate) fn new(
        provider: Arc<rustls::crypto::CryptoProvider>,
        expected: [u8; 32],
    ) -> Arc<Self> {
        Arc::new(Self { provider, expected })
    }

    fn verify_pinned(
        &self,
        end_entity: &rustls::pki_types::CertificateDer<'_>,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        let digest: [u8; 32] = Sha256::digest(end_entity.as_ref()).into();
        if !fingerprint_eq(&self.expected, &digest) {
            return Err(rustls::Error::General(format!(
                "server certificate fingerprint mismatch: expected {}, got {}",
                format_sha256_fingerprint(&self.expected),
                format_sha256_fingerprint(&digest),
            )));
        }
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }
}

impl rustls::client::danger::ServerCertVerifier for PinnedServerVerification {
    fn verify_server_cert(
        &self,
        end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        self.verify_pinned(end_entity)
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// Builds a TLS client config that trusts any server certificate
/// (`None`) or enforces a pinned fingerprint (`Some`). ALPN is left to the
/// caller.
pub(crate) fn tls_client_config(pinned: Option<[u8; 32]>) -> rustls::ClientConfig {
    let provider = ring_provider();
    let verifier: Arc<dyn rustls::client::danger::ServerCertVerifier> = match pinned {
        Some(expected) => PinnedServerVerification::new(provider.clone(), expected),
        None => SkipServerVerification::new(provider.clone()),
    };
    let mut config = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();
    config.enable_sni = true;
    config.enable_early_data = false;
    config
}

/// Extracts a pinned certificate fingerprint from the url fragment
/// (`#fingerprint=sha256:<hex>`). A present but malformed pin is an error:
/// silently ignoring it would turn an intended fail-closed configuration into
/// an open one.
pub(crate) fn pinned_fingerprint(url: &url::Url) -> Result<Option<[u8; 32]>, TunnelError> {
    let Some(fragment) = url.fragment() else {
        return Ok(None);
    };
    for pair in fragment.split('&') {
        let Some(value) = pair.strip_prefix("fingerprint=") else {
            continue;
        };
        return parse_sha256_fingerprint(value).map(Some).ok_or_else(|| {
            TunnelError::InvalidProtocol(format!(
                "invalid certificate fingerprint in url fragment: {value}"
            ))
        });
    }
    Ok(None)
}
