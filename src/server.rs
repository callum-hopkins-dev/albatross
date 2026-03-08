//! Server builders and shutdown primitives.
//!
//! This module contains the [`Server`] builder and [`Shutdown`] handle, which
//! form the core of building and controlling an *albatross* server.
//!
//! # Core types
//!
//! - **`Server`** – Configures a listening server, including its socket
//!   address and connection acceptors. Acceptors can be layered or replaced
//!   to customize connection behavior.
//!
//! - **`Shutdown`** – A clonable handle used to trigger a graceful server
//!   shutdown. Multiple tasks can share a `Shutdown` handle to coordinate
//!   orderly termination of connections.
//!
//! # Usage
//!
//! Construct a server with [`Server::new`] or the top-level [`server`] function,
//! optionally attaching a shutdown handle with [`Server::with_shutdown`] and
//! configuring acceptors using [`Server::map_acceptor`] or [`Server::with_acceptor`].
//!
//! [`Server`]: crate::server::Server
//! [`Shutdown`]: crate::server::Shutdown
//! [`server`]: crate::server::server
//! [`Server::map_acceptor`]: crate::server::Server::map_acceptor
//! [`Server::with_acceptor`]: crate::server::Server::with_acceptor
//! [`Server::with_shutdown`]: crate::server::Server::with_shutdown

use std::{
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use http::{Request, Response};
use hyper::body::{Body, Incoming};
use hyper_util::{
    rt::{TokioExecutor, TokioIo},
    server::{conn::auto::Builder, graceful::GracefulShutdown},
    service::TowerToHyperService,
};
use socket2::{Domain, Protocol, Socket, TcpKeepalive, Type};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::{TcpListener, TcpStream, ToSocketAddrs},
    sync::Notify,
};
use tower::{MakeService, Service};

use crate::{Accept, IntoAccept};

#[cfg(feature = "systemd")]
use crate::accept::systemd;

#[cfg(feature = "https-upgrade")]
use crate::accept::https_upgrade;

macro_rules! ok_or_continue {
    ($expr:expr) => {
        match $expr {
            ::core::result::Result::Ok(x) => x,
            ::core::result::Result::Err(_) => continue,
        }
    };
}

/// A handle used to trigger a graceful server shutdown.
///
/// `Shutdown` provides a simple signal that can be shared between tasks.
/// Clones of this handle refer to the same underlying notification
/// primitive, allowing one part of the program to request shutdown
/// while another part awaits it.
///
/// This is typically attached to a [`Server`] using
/// [`Server::with_shutdown`]. Calling [`notify`](Self::notify) will
/// signal the server to stop accepting new connections and begin
/// shutting down existing ones.
#[derive(Debug, Default, Clone)]
pub struct Shutdown(Arc<Notify>);

impl Shutdown {
    /// Creates a new shutdown handle.
    ///
    /// The returned handle can be cloned and shared across tasks.
    /// Calling [`notify`](Self::notify) on any clone will trigger
    /// the shutdown signal for all listeners.
    #[inline]
    pub fn new() -> Self {
        Self(Arc::new(Notify::new()))
    }

    /// Triggers the shutdown signal.
    ///
    /// All tasks currently waiting for the shutdown notification will
    /// be woken. In the context of a [`Server`], this initiates a
    /// graceful shutdown procedure.
    #[inline]
    pub fn notify(&self) {
        self.0.notify_waiters();
    }
}

/// A configurable server builder.
///
/// `Server` stores the configuration required to start a listening
/// server, including the socket address, an optional graceful shutdown
/// handle, and an **acceptor** responsible for handling incoming
/// connections.
///
/// The server is generic over two types:
///
/// - `A` — the socket address or listener configuration used when
///   binding the server.
/// - `U` — the acceptor used to process incoming connections.
///
/// The acceptor determines how connections are established before they
/// reach the application. It may implement behaviors such as TLS
/// termination, protocol detection, or integration with external
/// systems. The default acceptor is `()`, which performs no additional
/// processing.
///
/// Acceptors can be replaced or transformed using methods such as
/// [`with_acceptor`](Self::with_acceptor) and
/// [`map_acceptor`](Self::map_acceptor), allowing connection behavior
/// to be composed as the server is configured.
///
/// A [`Shutdown`] handle can optionally be attached to enable graceful
/// shutdown triggered from another task.
#[derive(Debug, Clone)]
pub struct Server<A, U = ()> {
    socket_addr: A,
    shutdown: Option<Shutdown>,
    acceptor: U,
}

impl<A> Server<A> {
    /// Creates a new [`Server`] bound to the provided socket address.
    ///
    /// The returned server uses the default acceptor (`()`) and has no
    /// configured shutdown handle. Additional behavior can be configured
    /// by transforming or replacing the acceptor with methods such as
    /// [`map_acceptor`](Self::map_acceptor) or [`with_acceptor`](Self::with_acceptor),
    /// and by attaching a shutdown handle with [`with_shutdown`](Self::with_shutdown).
    ///
    /// This constructor only initializes the server configuration; it does
    /// not start listening or accepting connections.
    #[inline]
    pub const fn new(socket_addr: A) -> Self {
        Self {
            socket_addr,
            shutdown: None,
            acceptor: (),
        }
    }
}

impl<A, U> Server<A, U> {
    /// Installs a new acceptor for the server.
    ///
    /// This replaces the currently configured acceptor with `acceptor`.
    /// Any previously configured acceptor layers will be discarded.
    ///
    /// This method is useful when constructing a server with a completely
    /// custom acceptor pipeline.
    ///
    /// If you only want to wrap or extend the existing acceptor, consider
    /// using [`map_acceptor`](Self::map_acceptor) instead.
    #[inline]
    pub fn with_acceptor<S>(self, acceptor: S) -> Server<A, S> {
        self.map_acceptor(|_| acceptor)
    }

    /// Transforms the server's acceptor using the provided function.
    ///
    /// The function receives the current acceptor and returns a new one.
    /// This allows the acceptor configuration to be replaced or adapted
    /// as the server is being built.
    ///
    /// Some acceptors wrap an existing acceptor to extend its behavior,
    /// while others may ignore the input entirely and construct a new
    /// acceptor instead.
    ///
    /// Most higher-level configuration helpers are implemented internally
    /// in terms of this method.
    #[inline]
    pub fn map_acceptor<F, S>(self, f: F) -> Server<A, S>
    where
        F: FnOnce(U) -> S,
    {
        Server {
            socket_addr: self.socket_addr,
            shutdown: self.shutdown,
            acceptor: f(self.acceptor),
        }
    }

    /// Configures a graceful shutdown handle for the server.
    ///
    /// The provided [`Shutdown`] handle can be triggered by another task
    /// to initiate shutdown. Once triggered, the server will stop accepting
    /// new connections and begin shutting down existing ones in an orderly
    /// manner.
    ///
    /// This allows integration with signal handlers, orchestration systems,
    /// or other application-level shutdown logic.
    #[inline]
    pub fn with_shutdown(self, shutdown: Shutdown) -> Self {
        Self {
            socket_addr: self.socket_addr,
            shutdown: Some(shutdown),
            acceptor: self.acceptor,
        }
    }

    /// Wraps the current acceptor with a `systemd` notification layer.
    ///
    /// This enables integration with the
    /// `sd_notify` protocol used by systemd service units. When enabled,
    /// the server will notify systemd about important lifecycle events
    /// such as when the service has finished starting and is ready to
    /// accept connections.
    ///
    /// This is primarily useful when running the server as a `Type=notify`
    /// service under systemd, allowing the service manager to reliably
    /// detect readiness.
    ///
    /// The notification layer is implemented as an acceptor wrapper, so it
    /// composes with other acceptors such as TLS or HTTPS upgrade.
    #[cfg(feature = "systemd")]
    #[inline]
    pub fn with_systemd_notify(self) -> Server<A, systemd::Notify<U>> {
        self.map_acceptor(|x| systemd::Notify::new(x))
    }

    /// Wraps the current acceptor with an HTTPS upgrade layer.
    ///
    /// This acceptor inspects incoming connections and detects whether the
    /// client is initiating a TLS session. If a non-TLS (plain HTTP) request
    /// is detected, the connection can be upgraded or redirected to HTTPS,
    /// allowing a single listener to transparently support both HTTP and
    /// HTTPS traffic.
    ///
    /// This is particularly useful when running a server that listens on a
    /// single port but prefers secure connections.
    ///
    /// Like other acceptors, this layer composes with TLS termination and
    /// other acceptor wrappers.
    #[cfg(feature = "https-upgrade")]
    #[inline]
    pub fn with_https_upgrade(self) -> Server<A, https_upgrade::HttpsUpgrade<U>> {
        self.map_acceptor(|x| https_upgrade::HttpsUpgrade::new(x))
    }
}

impl<A, U> Server<A, U>
where
    A: ToSocketAddrs,
{
    pub async fn serve<M, K, S, B>(self, mut make_service: M) -> std::io::Result<()>
    where
        M: MakeService<SocketAddr, Request<Incoming>>,
        M::MakeError: Into<Box<dyn std::error::Error + Send + Sync + 'static>>,
        M::Service: Send + 'static,
        B: Body + Send + 'static,
        B::Data: Send,
        B::Error: Into<Box<dyn std::error::Error + Send + Sync + 'static>>,
        U: IntoAccept<TcpStream, M::Service, Accept = K>,
        K: Accept<TcpStream, M::Service, Service = S> + Send + Sync + 'static,
        K::Future: Send + 'static,
        K::Stream: AsyncRead + AsyncWrite + Unpin + Send + 'static,
        S: Service<Request<Incoming>, Response = Response<B>> + Clone + Send + 'static,
        S::Future: Send + 'static,
        S::Error: Into<Box<dyn std::error::Error + Send + Sync + 'static>>,
    {
        let socket_addr = tokio::net::lookup_host(self.socket_addr)
            .await?
            .next()
            .ok_or_else(|| std::io::Error::from(std::io::ErrorKind::InvalidInput))?;

        let socket = Socket::new(
            Domain::for_address(socket_addr),
            Type::STREAM,
            Some(Protocol::TCP),
        )?;

        socket.set_reuse_address(true)?;
        socket.set_reuse_port(true)?;
        socket.set_tcp_nodelay(true)?;
        socket.set_nonblocking(true)?;

        socket.set_tcp_keepalive(
            &TcpKeepalive::new()
                .with_time(Duration::from_secs(60))
                .with_interval(Duration::from_secs(10))
                .with_retries(5),
        )?;

        socket.bind(&socket_addr.into())?;
        socket.listen(1024)?;

        let listener = TcpListener::from_std(socket.into())?;
        let graceful = GracefulShutdown::new();

        let state = Arc::new(State {
            inflight: AtomicUsize::new(0),
            inflight_notify: Notify::new(),
            acceptor: self.acceptor.into_accept().await?,
            builder: Builder::new(TokioExecutor::new()),
        });

        loop {
            let (stream, socket_addr) = tokio::select! {
                biased;

                _ = async {
                    match &self.shutdown {
                        Some(shutdown) => shutdown.0.notified().await,
                        None => ::core::future::pending().await,
                    }
                } => break,

                result = listener.accept() => ok_or_continue!(result),
            };

            ::core::future::poll_fn(|cx| make_service.poll_ready(cx))
                .await
                .map_err(std::io::Error::other)?;

            let service = ok_or_continue!(make_service.make_service(socket_addr).await);

            let state = Arc::clone(&state);

            state.inflight.fetch_add(1, Ordering::Relaxed);

            let watcher = graceful.watcher();

            tokio::task::spawn(async move {
                if let Ok((stream, service)) = state.acceptor.accept(stream, service).await {
                    let io = TokioIo::new(stream);
                    let service = TowerToHyperService::new(service);

                    let _ = watcher
                        .watch(state.builder.serve_connection_with_upgrades(io, service))
                        .await;
                }

                if state.inflight.fetch_sub(1, Ordering::Release) == 1 {
                    state.inflight_notify.notify_one();
                }
            });
        }

        graceful.shutdown().await;

        if state.inflight.load(Ordering::Acquire) != 0 {
            state.inflight_notify.notified().await;
        }

        Ok(())
    }
}

struct State<T> {
    inflight: AtomicUsize,
    inflight_notify: Notify,
    acceptor: T,
    builder: Builder<TokioExecutor>,
}
