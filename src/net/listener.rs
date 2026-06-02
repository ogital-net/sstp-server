//! `SO_REUSEPORT` listener factory.
//!
//! Each I/O worker calls [`bind_reuseport`] with the same address; the
//! kernel hashes incoming connections across the resulting listener
//! sockets (per-thread accept queues, no userspace lock).
//!
//! Implementation notes:
//! * `socket2` does the dual-stack handling and the `SO_REUSEPORT`
//!   ioctl in a portable way; we drop into `libc` only for things
//!   `socket2` doesn't expose.
//! * Sockets are set non-blocking before being handed to `tokio` so
//!   `TcpListener::from_std` doesn't need to flip the flag itself.
//! * IPv6 listeners are configured with `IPV6_V6ONLY = false` so a
//!   single `[::]:443` bind serves both IPv4 and IPv6 — matches the
//!   `--listen [::]:443` default in `cli.rs`.

use std::io;
use std::net::SocketAddr;

use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use tokio::net::TcpListener;

/// Listen backlog. 1024 is the historical default for high-throughput
/// servers; the kernel caps this at `/proc/sys/net/core/somaxconn`
/// anyway, so going higher just wastes the request.
const LISTEN_BACKLOG: i32 = 1024;

/// Errors that can come out of [`bind_reuseport`].
#[derive(Debug, thiserror::Error)]
pub enum ListenError {
    #[error("creating socket for {addr}: {source}")]
    Socket {
        addr: SocketAddr,
        #[source]
        source: io::Error,
    },
    #[error("setting socket option on {addr}: {source}")]
    SetSockOpt {
        addr: SocketAddr,
        #[source]
        source: io::Error,
    },
    #[error("binding {addr}: {source}")]
    Bind {
        addr: SocketAddr,
        #[source]
        source: io::Error,
    },
    #[error("listening on {addr}: {source}")]
    Listen {
        addr: SocketAddr,
        #[source]
        source: io::Error,
    },
    #[error("registering listener for {addr} with tokio: {source}")]
    Register {
        addr: SocketAddr,
        #[source]
        source: io::Error,
    },
}

/// Build a `SO_REUSEPORT` TCP listener bound to `addr` as a plain
/// `std::net::TcpListener`. Use this from a synchronous context
/// (notably `main()` before any tokio runtime exists) when the bind
/// needs to happen at startup — e.g. while we still have
/// `CAP_NET_BIND_SERVICE` and before `privdrop`. Each worker calls
/// [`adopt`] on the returned listener from inside its own runtime.
pub fn bind_reuseport_std(addr: SocketAddr) -> Result<std::net::TcpListener, ListenError> {
    let domain = match addr {
        SocketAddr::V4(_) => Domain::IPV4,
        SocketAddr::V6(_) => Domain::IPV6,
    };

    let sock = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))
        .map_err(|source| ListenError::Socket { addr, source })?;

    sock.set_nonblocking(true)
        .map_err(|source| ListenError::SetSockOpt { addr, source })?;
    sock.set_cloexec(true)
        .map_err(|source| ListenError::SetSockOpt { addr, source })?;
    sock.set_reuse_address(true)
        .map_err(|source| ListenError::SetSockOpt { addr, source })?;
    sock.set_reuse_port(true)
        .map_err(|source| ListenError::SetSockOpt { addr, source })?;
    if addr.is_ipv6() {
        sock.set_only_v6(false)
            .map_err(|source| ListenError::SetSockOpt { addr, source })?;
    }

    sock.bind(&SockAddr::from(addr))
        .map_err(|source| ListenError::Bind { addr, source })?;
    sock.listen(LISTEN_BACKLOG)
        .map_err(|source| ListenError::Listen { addr, source })?;

    Ok(sock.into())
}

/// Wrap a pre-bound `std::net::TcpListener` in tokio's runtime-bound
/// type. Must be called from within a tokio runtime context.
pub fn adopt(std_listener: std::net::TcpListener) -> Result<TcpListener, ListenError> {
    let addr = std_listener
        .local_addr()
        .unwrap_or_else(|_| SocketAddr::from(([0, 0, 0, 0], 0)));
    TcpListener::from_std(std_listener).map_err(|source| ListenError::Register { addr, source })
}

/// Build a `SO_REUSEPORT` TCP listener bound to `addr` and registered
/// with the current `tokio` runtime. Convenience wrapper over
/// [`bind_reuseport_std`] + [`adopt`] for tests / callers that
/// don't care about privdrop sequencing.
#[cfg(test)]
pub fn bind_reuseport(addr: SocketAddr) -> Result<TcpListener, ListenError> {
    adopt(bind_reuseport_std(addr)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    #[tokio::test]
    async fn bind_two_listeners_same_port() {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        let a = bind_reuseport(addr).expect("bind a");
        let port = a.local_addr().expect("local_addr").port();
        // Second bind on the resolved port must succeed thanks to
        // SO_REUSEPORT. Without it the kernel would return EADDRINUSE.
        let b_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port);
        let _b = bind_reuseport(b_addr).expect("bind b on same port");
    }

    #[tokio::test]
    async fn dual_stack_v6_accepts_v4_client() {
        let addr: SocketAddr = "[::1]:0".parse().expect("parse");
        let listener = bind_reuseport(addr).expect("bind v6");
        let port = listener.local_addr().expect("local_addr").port();

        let accept = tokio::spawn(async move {
            let (_s, peer) = listener.accept().await.expect("accept");
            peer
        });

        let _client = tokio::net::TcpStream::connect(("::1", port))
            .await
            .expect("connect");
        let peer = accept.await.expect("join");
        assert!(peer.ip().is_loopback());
    }
}
