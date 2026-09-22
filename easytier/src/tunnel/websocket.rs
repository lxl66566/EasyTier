use super::FromUrl;
use super::cert::{PersistentServerCert, ServerCertSpec, load_process_cert};
use super::tls_verification::{init_crypto_provider, pinned_fingerprint};
use crate::tunnel::common::bind;
use crate::{proto::common::TunnelInfo, socket::tcp::RuntimeTcpSocket};
use bytes::BytesMut;
use cidr::IpCidr;
use easytier_core::{
    packet::{ZCPacket, ZCPacketType},
    socket::tcp::VirtualTcpSocket,
    tunnel::{IpVersion, Tunnel, TunnelError, wrapper::TunnelWrapper},
};
use forwarded_header_value::ForwardedHeaderValue;
use futures::{Sink, StreamExt};
use std::{
    net::{IpAddr, SocketAddr},
    pin::Pin,
    sync::{Arc, LazyLock},
    task::{Context, Poll},
    time::Duration,
};
use tokio::{net::TcpListener, time::timeout};
use tokio_rustls::TlsAcceptor;
use tokio_util::either::Either;
use tokio_websockets::{ClientBuilder, Limits, MaybeTlsStream, Message, ServerBuilder};
use zerocopy::AsBytes as _;

pub(crate) const CONNECT_TIMEOUT: Duration = Duration::from_secs(20);
pub(crate) const SERVER_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(3);

static TRUSTED_PROXIES: LazyLock<Vec<IpCidr>> = LazyLock::new(|| {
    [
        "127.0.0.0/8",
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "::1/128",
        "fc00::/7",
    ]
    .into_iter()
    .map(|cidr| cidr.parse().unwrap())
    .collect()
});

fn trusted_proxy_contains(ip: IpAddr) -> bool {
    TRUSTED_PROXIES.iter().any(|cidr| match (cidr, ip) {
        (IpCidr::V4(cidr), IpAddr::V4(ip)) => cidr.contains(&ip),
        (IpCidr::V6(cidr), IpAddr::V6(ip)) => cidr.contains(&ip),
        _ => false,
    })
}

fn websocket_error(error: impl std::fmt::Display) -> TunnelError {
    TunnelError::ProtocolError(format!("websocket error: {error}"))
}

fn is_wss(url: &url::Url) -> Result<bool, TunnelError> {
    match url.scheme() {
        "ws" => Ok(false),
        "wss" => Ok(true),
        scheme => Err(TunnelError::InvalidProtocol(scheme.to_owned())),
    }
}

struct WebSocketPacketSink<S> {
    inner: S,
}

impl<S> WebSocketPacketSink<S> {
    fn new(inner: S) -> Self {
        Self { inner }
    }
}

impl<S, E> Sink<ZCPacket> for WebSocketPacketSink<S>
where
    S: Sink<Message, Error = E> + Unpin,
    E: std::fmt::Display,
{
    type Error = TunnelError;

    fn poll_ready(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Pin::new(&mut self.inner)
            .poll_ready(cx)
            .map(|result| result.map_err(websocket_error))
    }

    fn start_send(mut self: Pin<&mut Self>, packet: ZCPacket) -> Result<(), Self::Error> {
        Pin::new(&mut self.inner)
            .start_send(Message::binary(packet.tunnel_payload_bytes().freeze()))
            .map_err(websocket_error)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Pin::new(&mut self.inner)
            .poll_flush(cx)
            .map(|result| result.map_err(websocket_error))
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Pin::new(&mut self.inner)
            .poll_close(cx)
            .map(|result| result.map_err(websocket_error))
    }
}

async fn map_from_ws_message(
    message: Result<Message, tokio_websockets::Error>,
) -> Option<Result<ZCPacket, TunnelError>> {
    let message = match message {
        Ok(message) => message,
        Err(error) => {
            tracing::error!(?error, "recv from websocket error");
            return Some(Err(websocket_error(error)));
        }
    };
    if message.is_close() {
        tracing::warn!("recv close message from websocket");
        return None;
    }
    if !message.is_binary() {
        let message = format!("{message:?}");
        tracing::error!(?message, "Invalid packet");
        return Some(Err(TunnelError::InvalidPacket(message)));
    }
    Some(Ok(ZCPacket::new_from_buf(
        BytesMut::from(message.into_payload().as_bytes()),
        ZCPacketType::DummyTunnel,
    )))
}

/// Warn once per process that unpinned wss tunnels trust any server
/// certificate, which an active man-in-the-middle can exploit.
fn warn_no_pin() {
    static WARNED: std::sync::OnceLock<()> = std::sync::OnceLock::new();
    WARNED.get_or_init(|| {
        tracing::warn!(
            "wss server certificate is not verified: no fingerprint pinned in the \
             peer url, so an active man-in-the-middle can impersonate the server. \
             Append '#fingerprint=sha256:<hash>' to the peer url to pin it."
        );
    });
}

fn get_tls_client_config(pinned: Option<[u8; 32]>) -> rustls::ClientConfig {
    if pinned.is_none() {
        warn_no_pin();
    }
    super::tls_verification::tls_client_config(pinned)
}

/// Self-signed certificate served by wss listeners.
///
/// The key pair is persisted in the per-user state directory by the shared
/// certificate module ([`super::cert`], same mechanism as the quic listener),
/// so the fingerprint stays stable across restarts and clients can pin it
/// via `#fingerprint=sha256:<hex>`. The fingerprint is logged once per
/// process when the certificate is first loaded.
static SERVER_TLS_CERT: LazyLock<Result<PersistentServerCert, String>> =
    LazyLock::new(|| load_process_cert(&WSS_CERT_SPEC).map_err(|error| format!("{error:#}")));

const WSS_CERT_SPEC: ServerCertSpec = ServerCertSpec {
    file_name: "wss-server-key.pem",
    label: "wss",
    alpn: None,
    // Keep TLS 1.2 so browser-era websocket clients still interoperate.
    tls13_only: false,
};

/// The process-wide wss server certificate. A broken certificate file is a
/// sticky error: failing loudly beats silently rotating the server identity
/// and breaking every pinned peer.
fn wss_server_cert() -> Result<&'static PersistentServerCert, TunnelError> {
    SERVER_TLS_CERT
        .as_ref()
        .map_err(|error| TunnelError::InternalError(format!("wss server certificate: {error}")))
}

pub(crate) async fn upgrade_accepted<S>(
    stream: S,
    local_url: url::Url,
) -> Result<Box<dyn Tunnel>, TunnelError>
where
    S: VirtualTcpSocket,
{
    let peer_addr = stream.peer_addr()?;
    let mut remote_url = socket_url(local_url.scheme(), peer_addr);
    let stream = if is_wss(&local_url)? {
        let acceptor = TlsAcceptor::from(wss_server_cert()?.tls_config());
        Either::Left(acceptor.accept(stream).await?)
    } else {
        Either::Right(stream)
    };

    let (request, stream) = ServerBuilder::new()
        .limits(Limits::unlimited())
        .max_headers(128)
        .accept(stream)
        .await
        .map_err(websocket_error)?;

    if trusted_proxy_contains(peer_addr.ip())
        && let Some(forwarded) = request
            .headers()
            .get("Forwarded")
            .and_then(|value| value.to_str().ok())
            .and_then(|value| ForwardedHeaderValue::from_forwarded(value).ok())
            .or_else(|| {
                request
                    .headers()
                    .get("X-Forwarded-For")
                    .and_then(|value| value.to_str().ok())
                    .and_then(|value| ForwardedHeaderValue::from_x_forwarded_for(value).ok())
            })
        && let Some(ip) = forwarded.remotest_forwarded_for_ip()
    {
        remote_url
            .set_host(Some(&ip.to_string()))
            .map_err(|_| TunnelError::InvalidAddr(format!("invalid forwarded ip {ip}")))?;
        remote_url
            .query_pairs_mut()
            .append_pair("proxy", &peer_addr.to_string());
    }

    let (write, read) = stream.split();
    let remote_url: crate::proto::common::Url = remote_url.into();
    let info = TunnelInfo {
        tunnel_type: local_url.scheme().to_owned(),
        local_addr: Some(local_url.into()),
        remote_addr: Some(remote_url.clone()),
        resolved_remote_addr: Some(remote_url),
    };
    Ok(Box::new(TunnelWrapper::new(
        read.filter_map(map_from_ws_message),
        WebSocketPacketSink::new(write),
        Some(info),
    )))
}

fn socket_url(scheme: &str, addr: SocketAddr) -> url::Url {
    let mut url = url::Url::parse(&format!("{scheme}://0.0.0.0"))
        .expect("WebSocket transport scheme should be a valid URL scheme");
    url.set_ip_host(addr.ip()).unwrap();
    url.set_port(Some(addr.port())).unwrap();
    url
}

#[derive(Debug)]
pub struct WsTunnelListener {
    addr: url::Url,
    listener: Option<TcpListener>,
    socket_mark: Option<u32>,
}

impl WsTunnelListener {
    pub fn new(addr: url::Url) -> Self {
        WsTunnelListener {
            addr,
            listener: None,
            socket_mark: None,
        }
    }

    pub fn set_socket_mark(&mut self, socket_mark: Option<u32>) {
        self.socket_mark = socket_mark;
    }

    async fn listen_tunnel(&mut self) -> Result<(), TunnelError> {
        self.listener = None;

        let addr = SocketAddr::from_url(self.addr.clone(), IpVersion::Both).await?;
        let listener = bind::<TcpListener>()
            .addr(addr)
            .only_v6(true)
            .maybe_socket_mark(self.socket_mark)
            .call()
            .await?;

        self.addr
            .set_port(Some(listener.local_addr()?.port()))
            .unwrap();
        self.listener = Some(listener);

        Ok(())
    }

    async fn accept_tunnel(&mut self) -> Result<Box<dyn Tunnel>, TunnelError> {
        loop {
            let listener = self.listener.as_ref().unwrap();
            // only fail on tcp accept error
            let (stream, _) = listener.accept().await?;
            stream.set_nodelay(true).unwrap();
            match timeout(
                SERVER_HANDSHAKE_TIMEOUT,
                upgrade_accepted(RuntimeTcpSocket::new(stream), self.addr.clone()),
            )
            .await
            {
                Ok(Ok(tunnel)) => return Ok(tunnel),
                e => {
                    tracing::error!(?e, ?self, "Failed to accept ws/wss tunnel");
                    continue;
                }
            }
        }
    }
}

#[async_trait::async_trait]
impl easytier_core::socket::SocketListener for WsTunnelListener {
    type Accepted = Box<dyn Tunnel>;

    async fn listen(&mut self) -> anyhow::Result<()> {
        Ok(self.listen_tunnel().await?)
    }

    async fn accept(&mut self) -> anyhow::Result<Self::Accepted> {
        Ok(self.accept_tunnel().await?)
    }

    fn local_url(&self) -> url::Url {
        self.addr.clone()
    }
}

pub(crate) async fn upgrade_connected<S>(
    stream: S,
    mut remote_url: url::Url,
) -> Result<Box<dyn Tunnel>, TunnelError>
where
    S: VirtualTcpSocket,
{
    let is_wss = is_wss(&remote_url)?;
    // The fragment carries connection options (certificate pins), never part
    // of the HTTP request; http::Uri rejects it outright, so strip it first.
    let pinned = if is_wss {
        pinned_fingerprint(&remote_url)?
    } else {
        None
    };
    remote_url.set_fragment(None);
    let local_addr = stream.local_addr()?;
    let resolved_remote_addr = stream.peer_addr()?;
    let info = TunnelInfo {
        tunnel_type: remote_url.scheme().to_owned(),
        local_addr: Some(
            super::build_url_from_socket_addr(&local_addr.to_string(), remote_url.scheme()).into(),
        ),
        remote_addr: Some(remote_url.clone().into()),
        resolved_remote_addr: Some(
            super::build_url_from_socket_addr(
                &resolved_remote_addr.to_string(),
                remote_url.scheme(),
            )
            .into(),
        ),
    };

    let client = ClientBuilder::from_uri(http::Uri::try_from(remote_url.to_string()).unwrap())
        .max_headers(128);
    let stream: MaybeTlsStream<S> = if is_wss {
        init_crypto_provider();
        let tls = tokio_rustls::TlsConnector::from(Arc::new(get_tls_client_config(pinned)));
        let sni = remote_url.domain().unwrap_or("localhost").to_owned();
        let server_name = rustls::pki_types::ServerName::try_from(sni)
            .map_err(|_| TunnelError::InvalidProtocol("Invalid SNI".to_owned()))?;
        MaybeTlsStream::Rustls(tls.connect(server_name, stream).await?)
    } else {
        MaybeTlsStream::Plain(stream)
    };

    let (client, _) = client.connect_on(stream).await.map_err(websocket_error)?;
    let (write, read) = client.split();
    Ok(Box::new(TunnelWrapper::new(
        read.filter_map(map_from_ws_message),
        WebSocketPacketSink::new(write),
        Some(info),
    )))
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use easytier_core::socket::SocketListener;
    use easytier_core::tunnel::fingerprint::format_sha256_fingerprint;
    use futures::{SinkExt, StreamExt};
    use sha2::{Digest, Sha256};
    use std::io;
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpSocket,
    };

    struct FailingWebSocketSink {
        close_called: bool,
    }

    impl Sink<Message> for FailingWebSocketSink {
        type Error = io::Error;

        fn poll_ready(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }

        fn start_send(self: Pin<&mut Self>, _item: Message) -> Result<(), Self::Error> {
            Ok(())
        }

        fn poll_flush(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "send failed",
            )))
        }

        fn poll_close(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Result<(), Self::Error>> {
            self.close_called = true;
            Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "close failed",
            )))
        }
    }

    #[tokio::test]
    async fn packet_sink_maps_send_and_close_errors_independently() {
        let mut sink = WebSocketPacketSink::new(FailingWebSocketSink {
            close_called: false,
        });

        sink.send(ZCPacket::new_with_payload(b"packet"))
            .await
            .expect_err("send should fail");
        sink.close().await.expect_err("close should fail");
        assert!(sink.inner.close_called);
    }

    #[tokio::test]
    async fn ws_forwarded() {
        let mut listener = WsTunnelListener::new("ws://127.0.0.1:25559".parse().unwrap());
        listener.listen().await.unwrap();

        let server_task = tokio::spawn(async move {
            let tunnel = listener.accept().await.unwrap();

            let remote_addr = tunnel
                .info()
                .unwrap()
                .remote_addr
                .unwrap()
                .url
                .parse::<url::Url>()
                .unwrap();

            assert_eq!(remote_addr.host_str().unwrap(), "203.0.113.5");
            let proxy_addr = remote_addr
                .query_pairs()
                .find(|(k, _)| k == "proxy")
                .map(|(_, v)| v.into_owned())
                .unwrap();
            assert_eq!(proxy_addr, "127.0.0.1:25560");

            tunnel
        });

        let socket = TcpSocket::new_v4().unwrap();
        socket.bind("127.0.0.1:25560".parse().unwrap()).unwrap();
        let mut stream = socket
            .connect("127.0.0.1:25559".parse().unwrap())
            .await
            .unwrap();

        let handshake = "GET / HTTP/1.1\r\n\
                         Host: 127.0.0.1:25559\r\n\
                         Upgrade: websocket\r\n\
                         Connection: Upgrade\r\n\
                         Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
                         Sec-WebSocket-Version: 13\r\n\
                         X-Forwarded-For: 203.0.113.5, 192.168.1.1\r\n\
                         \r\n";

        stream.write_all(handshake.as_bytes()).await.unwrap();

        let mut buf = [0u8; 1024];
        let bytes_read = stream.read(&mut buf).await.unwrap();
        let response = String::from_utf8_lossy(&buf[..bytes_read]);

        assert!(response.contains("101 Switching Protocols"));

        let _tunnel = server_task.await.unwrap();
    }

    fn wss_url_with_fragment(addr: std::net::SocketAddr, fragment: &str) -> url::Url {
        format!("wss://{addr}{fragment}").parse().unwrap()
    }

    fn self_signed_cert() -> rustls::pki_types::CertificateDer<'static> {
        init_crypto_provider();
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        rustls::pki_types::CertificateDer::from(cert.serialize_der().unwrap())
    }

    fn pinned_verifier(expected: [u8; 32]) -> Arc<dyn rustls::client::danger::ServerCertVerifier> {
        use crate::tunnel::tls_verification::PinnedServerVerification;
        PinnedServerVerification::new(crate::tunnel::tls_verification::ring_provider(), expected)
    }

    #[test]
    fn pinned_fingerprint_fragment_parses_only_well_formed_pins() {
        // absent fragment / unrelated pairs mean no pin
        assert_eq!(
            pinned_fingerprint(&"wss://h:1".parse::<url::Url>().unwrap()).unwrap(),
            None
        );
        assert_eq!(
            pinned_fingerprint(&"wss://h:1#other=1".parse::<url::Url>().unwrap()).unwrap(),
            None
        );

        let digest = [0xabu8; 32];
        let value = format_sha256_fingerprint(&digest);
        assert_eq!(
            pinned_fingerprint(&wss_url_with_fragment(
                "127.0.0.1:1".parse().unwrap(),
                &format!("#noise=1&fingerprint={value}")
            ))
            .unwrap(),
            Some(digest)
        );

        // malformed pins fail closed instead of silently disabling the pin
        let bad = wss_url_with_fragment(
            "127.0.0.1:1".parse().unwrap(),
            "#fingerprint=sha256:not-hex",
        );
        assert!(matches!(
            pinned_fingerprint(&bad),
            Err(TunnelError::InvalidProtocol(_))
        ));
    }

    #[test]
    fn pinned_verifier_checks_end_entity_digest() {
        let cert = self_signed_cert();
        let server_name = rustls::pki_types::ServerName::try_from("localhost").unwrap();

        // wrong pin rejects the certificate
        let err = pinned_verifier([0x11u8; 32])
            .verify_server_cert(
                &cert,
                &[],
                &server_name,
                &[],
                rustls::pki_types::UnixTime::now(),
            )
            .unwrap_err();
        assert!(err.to_string().contains("fingerprint mismatch"), "{err}");

        // matching pin accepts it
        let real_digest: [u8; 32] = Sha256::digest(cert.as_ref()).into();
        pinned_verifier(real_digest)
            .verify_server_cert(
                &cert,
                &[],
                &server_name,
                &[],
                rustls::pki_types::UnixTime::now(),
            )
            .unwrap();
    }

    #[tokio::test]
    async fn wss_tunnel_enforces_pinned_certificate_fingerprint() {
        let mut listener = WsTunnelListener::new("wss://127.0.0.1:0".parse().unwrap());
        listener.listen().await.unwrap();
        let local_url = listener.local_url();
        let addr: std::net::SocketAddr = format!(
            "{}:{}",
            local_url.host_str().unwrap(),
            local_url.port().unwrap()
        )
        .parse()
        .unwrap();

        // two sequential connections: one accepted, one aborted during TLS
        let server_task = tokio::spawn(async move {
            for _ in 0..2 {
                let tunnel = listener.accept().await.unwrap();
                crate::tunnel::common::tests::_tunnel_echo_server(tunnel, true).await;
            }
        });

        let pinned = wss_server_cert().unwrap().fingerprint();
        let pin_value = format_sha256_fingerprint(&pinned);

        // matching pin: handshake succeeds and data flows
        let url = wss_url_with_fragment(addr, &format!("#fingerprint={pin_value}"));
        let socket = tokio::net::TcpStream::connect(addr).await.unwrap();
        let tunnel = upgrade_connected(RuntimeTcpSocket::new(socket), url)
            .await
            .unwrap();
        let (mut recv, mut send) = tunnel.split();
        send.send(ZCPacket::new_with_payload(b"pinned wss"))
            .await
            .unwrap();
        let packet = tokio::time::timeout(Duration::from_secs(5), recv.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(packet.payload(), b"pinned wss".as_slice());
        let _ = send.close().await;

        // mismatching pin: fail closed at the TLS handshake
        let mut wrong = pinned;
        wrong[0] ^= 0xff;
        let url = wss_url_with_fragment(
            addr,
            &format!("#fingerprint={}", format_sha256_fingerprint(&wrong)),
        );
        let socket = tokio::net::TcpStream::connect(addr).await.unwrap();
        let err = upgrade_connected(RuntimeTcpSocket::new(socket), url)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("fingerprint mismatch"), "{err}");

        // The listener keeps accepting after a failed TLS handshake (it only
        // fails on tcp accept errors), so the server task never finishes on
        // its own after the aborted second connection; tear it down.
        server_task.abort();
    }

    #[tokio::test]
    async fn wss_tunnel_without_pin_keeps_legacy_skip_verification() {
        let mut listener = WsTunnelListener::new("wss://127.0.0.1:0".parse().unwrap());
        listener.listen().await.unwrap();
        let local_url = listener.local_url();
        let addr: std::net::SocketAddr = format!(
            "{}:{}",
            local_url.host_str().unwrap(),
            local_url.port().unwrap()
        )
        .parse()
        .unwrap();

        let server_task = tokio::spawn(async move {
            let tunnel = listener.accept().await.unwrap();
            crate::tunnel::common::tests::_tunnel_echo_server(tunnel, true).await;
        });

        // no pin configured: connect as before (warns once per process)
        let url = wss_url_with_fragment(addr, "");
        let socket = tokio::net::TcpStream::connect(addr).await.unwrap();
        let tunnel = upgrade_connected(RuntimeTcpSocket::new(socket), url)
            .await
            .unwrap();
        let (mut recv, mut send) = tunnel.split();
        send.send(ZCPacket::new_with_payload(b"unpinned wss"))
            .await
            .unwrap();
        let packet = tokio::time::timeout(Duration::from_secs(5), recv.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(packet.payload(), b"unpinned wss".as_slice());
        let _ = send.close().await;
        server_task.await.unwrap();
    }
}
