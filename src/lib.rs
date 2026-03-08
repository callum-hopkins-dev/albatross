//! # albatross
//!
//! A composable HTTP server for [`tower::Service`] built around pluggable connection acceptors.
//!
//! **albatross** provides a small, focused API for flexible connection
//! handling through **pluggable acceptors**. Acceptors allow you to inspect,
//! transform, or wrap incoming connections before they reach your application,
//! without complicating the core server interface.
//!
//! This makes it easy to add functionality such as TLS termination, automatic
//! certificate management, protocol detection, or integration with service
//! managers, all in a modular and composable way.
//!
//! `albatross` works with any tower [`Service`](tower::Service) that matches the expected
//! signature. While it is generally intended for use with [axum](https://docs.rs/axum),
//! it can serve any compatible tower service.
//!
//! ## Pluggable Acceptors
//!
//! An **acceptor** sits between the listener and your service. Acceptors can:
//!
//! - Wrap connections (e.g., TLS termination)  
//! - Inspect or modify connection metadata  
//! - Conditionally redirect or upgrade protocols  
//! - Integrate with external systems
//!
//! Multiple acceptors can be composed together to create the exact connection
//! behavior your server needs.
//!
//! ## Built-in Acceptors
//!
//! The library provides several ready-to-use acceptors behind feature flags:
//!
//! - `systemd` — integrates with systemd notifications and watchdogs  
//! - `tls` — terminates HTTPS connections  
//! - `acme` — similar to `tls` but automatically obtains and renews certificates  
//! - `https-upgrade` — detects plain HTTP connections and upgrades or redirects them to HTTPS
//!
//! ## Getting Started
//!
//! Add **albatross** to your project:
//!
//! ```sh
//! cargo add albatross --features tls,https-upgrade
//! ```
//!
//! Create a server by binding a socket address and serving a `tower::Service`.
//! Additional connection behavior (such as TLS or redirects) can be added using acceptors.
//!
//! ```rust,no_run
//! # use axum::{Router, routing::get};
//! #[tokio::main]
//! async fn main() {
//!     let router = Router::new()
//!       .route("/", get(|| async { "Hello, world!" }));
//!
//! # #[cfg(all(feature = "tls", feature = "https-upgrade"))]
//!     albatross::server("0.0.0.0:443")
//!         .with_acceptor(albatross::tls().with_certificate("cert.pem"))
//!         .with_https_upgrade()
//!         .serve(router.into_make_service())
//!         .await
//!         .unwrap();
//!
//! # #[cfg(not(all(feature = "tls", feature = "https-upgrade")))]
//!     albatross::server("0.0.0.0:443")
//!         .serve(router.into_make_service())
//!         .await
//!         .unwrap();
//! }
//! ```

#[cfg(feature = "acme")]
use crate::accept::acme::Acme;

#[cfg(feature = "tls")]
use crate::accept::tls::Tls;

pub use crate::{
    accept::{Accept, IntoAccept},
    server::{Server, Shutdown},
};

pub mod accept;
pub mod server;

/// Creates a new [`Server`] bound to the given socket address.
///
/// This is a shorthand for [`Server::new`]. The returned server
/// initially has no acceptor or shutdown handle configured; you can
/// customize it using methods like [`map_acceptor`](Server::map_acceptor)
/// or [`with_shutdown`](Server::with_shutdown).
#[inline]
pub const fn server<A>(socket_addr: A) -> Server<A> {
    Server::new(socket_addr)
}

/// Creates a new TLS acceptor.
///
/// This is a convenience wrapper for [`Tls::new`](crate::accept::tls::Tls::new) and
/// produces a TLS acceptor ready to be composed with a server.
///
/// The acceptor can be further configured before use.
#[cfg(feature = "tls")]
#[inline]
pub const fn tls() -> Tls {
    Tls::new()
}

/// Creates a new ACME acceptor using the specified ACME directory URL.
///
/// This is a convenience wrapper for [`Acme::new`](crate::accept::acme::Acme::new) and returns
/// an acceptor that can automatically obtain and renew certificates via
/// the ACME protocol (e.g., Let's Encrypt).
///
/// The `directory` parameter should be the ACME server URL, such as the
/// production or staging endpoint provided by your ACME provider.
#[cfg(feature = "acme")]
#[inline]
pub fn acme(directory: &str) -> Acme {
    Acme::new(directory)
}
