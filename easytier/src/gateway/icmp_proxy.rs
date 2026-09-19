use std::{
    io::ErrorKind,
    mem::MaybeUninit,
    net::{IpAddr, Ipv4Addr, SocketAddrV4},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use easytier_core::{
    gateway::proxy::icmp_host::{IcmpProxyHost, IcmpProxySocket, ProxyRuntimeError},
    socket::SocketContext,
};
use socket2::Socket;

use crate::common::netns::NetNS;

/// Poll interval for the blocking ICMP receive loop. `shutdown()` on a raw
/// ICMP socket does not interrupt a blocked `recv_from` on Windows, so the
/// read must time out periodically to notice `close()` and let the
/// `spawn_blocking` thread return (tokio waits for blocking threads on
/// runtime drop, otherwise the runtime hangs forever).
const ICMP_RECV_POLL_INTERVAL: Duration = Duration::from_millis(500);

#[derive(Debug, Default)]
pub(crate) struct RuntimeIcmpProxyHost;

impl RuntimeIcmpProxyHost {
    fn create_raw_socket(context: &SocketContext) -> Result<Socket, std::io::Error> {
        let _guard = NetNS::from_socket_context(context).guard();
        let socket = Socket::new(
            socket2::Domain::IPV4,
            socket2::Type::RAW,
            Some(socket2::Protocol::ICMPV4),
        )?;
        socket.bind(&socket2::SockAddr::from(SocketAddrV4::new(
            Ipv4Addr::UNSPECIFIED,
            0,
        )))?;
        socket.set_read_timeout(Some(ICMP_RECV_POLL_INTERVAL))?;
        Ok(socket)
    }
}

#[derive(Debug)]
struct RuntimeIcmpSocket {
    socket: Arc<Socket>,
    closed: Arc<AtomicBool>,
}

#[async_trait::async_trait]
impl IcmpProxySocket for RuntimeIcmpSocket {
    async fn send(&self, destination: Ipv4Addr, packet: &[u8]) -> Result<(), ProxyRuntimeError> {
        self.socket
            .send_to(packet, &SocketAddrV4::new(destination, 0).into())?;
        Ok(())
    }

    async fn recv(&self) -> Result<(IpAddr, Vec<u8>), ProxyRuntimeError> {
        let socket = self.socket.clone();
        let closed = self.closed.clone();
        tokio::task::spawn_blocking(move || {
            let mut buffer = vec![0_u8; 8192];
            let uninitialized: &mut [MaybeUninit<u8>] =
                unsafe { std::mem::transmute(&mut buffer[..]) };
            loop {
                match socket_recv(&socket, uninitialized) {
                    Ok((length, peer_ip)) => {
                        buffer.truncate(length);
                        return Ok((peer_ip, buffer));
                    }
                    Err(error) => match error.kind() {
                        ErrorKind::TimedOut | ErrorKind::WouldBlock
                            if closed.load(Ordering::Acquire) =>
                        {
                            return Err(std::io::Error::other("icmp socket closed").into());
                        }
                        _ => return Err(error.into()),
                    },
                }
            }
        })
        .await
        .map_err(|error| ProxyRuntimeError::Other(error.into()))?
    }

    fn close(&self) {
        self.closed.store(true, Ordering::Release);
        let _ = self.socket.shutdown(std::net::Shutdown::Both);
    }
}

#[async_trait::async_trait]
impl IcmpProxyHost for RuntimeIcmpProxyHost {
    async fn open_icmp_v4(
        &self,
        context: SocketContext,
    ) -> Result<Arc<dyn IcmpProxySocket>, ProxyRuntimeError> {
        let socket = Self::create_raw_socket(&context).inspect_err(|error| {
            tracing::warn!(?error, "create ICMP socket failed");
        })?;
        Ok(Arc::new(RuntimeIcmpSocket {
            socket: Arc::new(socket),
            closed: Arc::new(AtomicBool::new(false)),
        }))
    }
}

fn socket_recv(
    socket: &Socket,
    buffer: &mut [MaybeUninit<u8>],
) -> Result<(usize, IpAddr), std::io::Error> {
    let (size, address) = socket.recv_from(buffer)?;
    let peer_ip = address
        .as_socket()
        .map(|address| address.ip())
        .unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED));
    Ok((size, peer_ip))
}
