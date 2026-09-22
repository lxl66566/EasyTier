//! Listener certificate for quic, persisted in the per-user state directory
//! by the shared self-signed certificate module (see [`super::super::cert`]).
//!
//! quic clients authenticate servers by pinning the certificate fingerprint
//! (see `tunnel::tls_verification`), so the key pair must survive restarts;
//! persistence, atomic writes and corrupt-file handling live in the shared
//! module and are reused by the wss listener.

use std::sync::LazyLock;

use super::super::cert::{PersistentServerCert, ServerCertSpec, load_process_cert};

/// ALPN protocol identifier that quic clients and servers must agree on.
pub(crate) const QUIC_ALPN: &[u8] = b"easytier-quic";

const QUIC_CERT_SPEC: ServerCertSpec = ServerCertSpec {
    file_name: "quic-server-key.pem",
    label: "quic",
    alpn: Some(QUIC_ALPN),
    // quinn negotiates TLS 1.3 only.
    tls13_only: true,
};

/// The process-wide quic server certificate.
///
/// Loading is deferred to the first quic listener so processes that never
/// serve quic do not touch the state directory. Errors are sticky: a broken
/// certificate file fails every subsequent use loudly instead of falling back
/// to a fresh key.
static QUIC_SERVER_CERT: LazyLock<Result<PersistentServerCert, String>> =
    LazyLock::new(|| load_process_cert(&QUIC_CERT_SPEC).map_err(|error| format!("{error:#}")));

pub(crate) fn quic_server_cert() -> anyhow::Result<&'static PersistentServerCert> {
    QUIC_SERVER_CERT
        .as_ref()
        .map_err(|error| anyhow::anyhow!("quic server certificate: {error}"))
}
