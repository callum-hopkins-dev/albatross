//! Core connection acceptors and utilities.
//!
//! This module defines the abstractions and building blocks for handling
//! incoming connections in *albatross*. Acceptors sit between the raw
//! listener and your service, and determine how each connection is
//! processed.
//!
//! # Traits
//!
//! - [`Accept`] – Processes each connection individually, potentially
//!   transforming the stream, modifying the service, wrapping it with
//!   additional behavior (like TLS), or terminating the connection early.
//!
//! - [`IntoAccept`] – Constructs an [`Accept`] instance, allowing
//!   asynchronous initialization such as loading certificates, creating
//!   keys, or preparing internal state.
//!
//! # Provided Acceptors
//!
//! The crate provides several feature-gated, ready-to-use acceptors as
//! submodules of `accept`:
//!
//! - [`accept::tls`](crate::accept::tls) – Terminates TLS connections.  
//! - [`accept::acme`](crate::accept::acme) – Obtains and renews certificates automatically
//!   via ACME (e.g., Let’s Encrypt).  
//! - [`accept::https_upgrade`](crate::accept::https_upgrade) – Detects plain HTTP connections and upgrades
//!   or redirects them to HTTPS.  
//! - [`accept::systemd`](crate::accept::systemd) – Integrates with systemd, sending readiness
//!   notifications and supporting the systemd watchdog.
//!
//! All built-in acceptors implement the [`Accept`] trait and can be composed
//! with other acceptors using the server’s acceptor mapping methods.
//!
//! # Usage
//!
//! You can implement custom acceptors by implementing [`Accept`] and
//! [`IntoAccept`], or use the built-in acceptors directly. Acceptors can
//! be composed in layers to handle connection transformation, protocol
//! upgrades, or integration with external systems.
//!
//! [`Accept`]: crate::accept::Accept
//! [`IntoAccept`]: crate::accept::IntoAccept

use std::future::Ready;

#[cfg(feature = "systemd")]
pub mod systemd;

#[cfg(feature = "tls")]
pub mod tls;

#[cfg(feature = "acme")]
pub mod acme;

#[cfg(feature = "https-upgrade")]
pub mod https_upgrade;

/// Processes an incoming connection before it is handed to the application.
///
/// An `Accept` implementation is responsible for preparing a newly accepted
/// connection. It receives the raw transport (`stream`) together with the
/// initial [`tower::Service`] that will handle requests, and returns a possibly
/// transformed stream and service.
///
/// Acceptors can perform tasks such as:
///
/// - wrapping the stream (for example TLS termination),
/// - inspecting the connection before it is used,
/// - replacing or adapting the request service,
/// - redirecting or upgrading protocols.
///
/// Some acceptors wrap another acceptor internally so that multiple behaviors
/// can be composed together. In those cases the implementation typically
/// delegates to an inner `Accept` after performing its own processing.
///
/// An acceptor may also decide that normal request handling should not
/// continue. For example, an implementation might intercept a connection to
/// perform a protocol upgrade or emit a redirect response. In such situations
/// the acceptor may return an error to indicate that no further processing of
/// the connection is required.
///
/// This trait is called once for each newly accepted connection.
pub trait Accept<I, S> {
    /// The stream type produced by this acceptor.
    type Stream;

    /// The service that will be used to handle requests on the connection.
    type Service;

    /// The future returned by [`accept`](Self::accept).
    type Future: Future<Output = std::io::Result<(Self::Stream, Self::Service)>>;

    /// Processes a newly accepted connection.
    ///
    /// Implementations may transform the provided stream and service before
    /// returning them.
    fn accept(&self, stream: I, service: S) -> Self::Future;
}

/// Creates an [`Accept`] instance from a configuration value.
///
/// Types implementing `IntoAccept` act as *builders* for acceptors. This
/// conversion step occurs when the server starts, allowing any required
/// initialization to run before the main connection loop begins.
///
/// The conversion may perform asynchronous work such as loading keys,
/// initializing external resources, or constructing internal state.
///
/// The server guarantees that this method is called only after it is ready
/// to begin accepting connections, but before the connection processing loop
/// starts.
///
/// Implementors typically pair `IntoAccept` with a corresponding [`Accept`]
/// implementation: the former constructs the runtime acceptor, while the
/// latter performs per-connection processing.
pub trait IntoAccept<I, S> {
    /// The acceptor produced by this conversion.
    type Accept: Accept<I, S>;

    /// The future returned by [`into_accept`](Self::into_accept).
    type Future: Future<Output = std::io::Result<Self::Accept>>;

    /// Converts this value into an [`Accept`] implementation.
    fn into_accept(self) -> Self::Future;
}

impl<I, S> Accept<I, S> for () {
    type Stream = I;

    type Service = S;

    type Future = Ready<std::io::Result<(Self::Stream, Self::Service)>>;

    #[inline]
    fn accept(&self, stream: I, service: S) -> Self::Future {
        ::core::future::ready(Ok((stream, service)))
    }
}

impl<I, S> IntoAccept<I, S> for () {
    type Accept = ();

    type Future = Ready<std::io::Result<Self::Accept>>;

    #[inline]
    fn into_accept(self) -> Self::Future {
        ::core::future::ready(Ok(()))
    }
}
