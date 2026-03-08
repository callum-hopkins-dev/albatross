//! TLS acceptor implementation.
//!
//! This module provides TLS support for incoming connections using
//! [`rustls`]. The types defined here allow a server to terminate TLS
//! connections before passing them to the application service.
//!
//! The TLS acceptor integrates with the crate’s connection pipeline by
//! implementing [`IntoAccept`] and [`Accept`]. A [`Tls`] builder is used
//! to configure certificate resolution, which is then converted into a
//! runtime [`TlsAcceptor`] that performs TLS handshakes for each
//! connection.
//!
//! Certificates can be supplied statically or resolved dynamically
//! using the [`Resolver`] trait.
//!
//! [`Accept`]: crate::accept::Accept
//! [`IntoAccept`]: crate::accept::IntoAccept

use std::{future::Ready, path::Path, sync::Arc, task::Poll};

use pin_project_lite::pin_project;
use rustls::{
    OtherError, ServerConfig,
    pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject},
    server::ClientHello,
    sign::CertifiedKey,
};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_rustls::server::TlsStream;

use crate::{Accept, IntoAccept};

macro_rules! r#try {
    ($($tt:tt)*) => {
        (|| { $($tt)* })()
    };
}

/// A TLS certificate and private key pair.
///
/// `Certificate` wraps a [`rustls::sign::CertifiedKey`] and represents
/// a certificate chain together with its corresponding private key.
///
/// Instances of this type can be used directly as a [`Resolver`],
/// allowing a single certificate to be returned for all connections.
#[derive(Debug, Clone)]
pub struct Certificate(Arc<CertifiedKey>);

impl Certificate {
    /// Constructs a certificate from PEM-encoded data.
    ///
    /// The provided PEM data must contain both the certificate chain
    /// and the corresponding private key.
    #[inline]
    pub fn from_pem(pem: &[u8]) -> Result<Self, rustls::Error> {
        Self::from_der(
            CertificateDer::pem_slice_iter(pem)
                .collect::<Result<_, rustls::pki_types::pem::Error>>()
                .map_err(|err| rustls::Error::Other(OtherError(Arc::new(err))))?,
            PrivateKeyDer::from_pem_slice(pem)
                .map_err(|err| rustls::Error::Other(OtherError(Arc::new(err))))?,
        )
    }

    /// Constructs a certificate from DER-encoded certificate chain
    #[inline]
    pub fn from_der(
        cert_chain: Box<[CertificateDer<'static>]>,
        private_key: PrivateKeyDer<'static>,
    ) -> Result<Self, rustls::Error> {
        Ok(Self(Arc::new(CertifiedKey::from_der(
            cert_chain.into_vec(),
            private_key,
            &rustls::crypto::aws_lc_rs::default_provider(),
        )?)))
    }
}

impl From<CertifiedKey> for Certificate {
    #[inline]
    fn from(value: CertifiedKey) -> Self {
        Self(Arc::new(value))
    }
}

impl From<Arc<CertifiedKey>> for Certificate {
    #[inline]
    fn from(value: Arc<CertifiedKey>) -> Self {
        Self(value)
    }
}

/// Resolves a certificate for an incoming TLS connection.
///
/// Implementations receive the TLS [`ClientHello`] and may return a
/// certificate appropriate for the connection. This allows servers to
/// select certificates dynamically, for example based on SNI.
///
/// Returning `None` indicates that no certificate is available.
pub trait Resolver {
    /// Resolve a certificate for the provided client hello.
    fn resolve(&self, client_hello: ClientHello<'_>) -> Option<Certificate>;
}

impl Resolver for () {
    #[inline]
    fn resolve(&self, _client_hello: ClientHello<'_>) -> Option<Certificate> {
        None
    }
}

impl Resolver for Certificate {
    #[inline]
    fn resolve(&self, _client_hello: ClientHello<'_>) -> Option<Certificate> {
        Some(self.clone())
    }
}

/// Converts a type into a [`Resolver`].
///
/// This trait allows different resolver sources to be used with the
/// [`Tls`] builder. For example, a static [`Certificate`], a custom
/// resolver implementation, or a certificate loaded from disk.
pub trait IntoResolver {
    /// The resolver type produced by this conversion.
    type Resolver: Resolver;

    /// The resolver type produced by this conversion.
    fn into_resolver(self) -> std::io::Result<Self::Resolver>;
}

impl<T> IntoResolver for T
where
    T: Resolver,
{
    type Resolver = T;

    #[inline]
    fn into_resolver(self) -> std::io::Result<Self::Resolver> {
        Ok(self)
    }
}

/// A resolver that loads a certificate from a PEM file.
///
/// This type is primarily used by [`Tls::with_certificate`] to create
/// a resolver backed by a certificate stored on disk.
pub struct Pem<P>(P);

impl<P> IntoResolver for Pem<P>
where
    P: AsRef<Path>,
{
    type Resolver = Certificate;

    #[inline]
    fn into_resolver(self) -> std::io::Result<Self::Resolver> {
        Certificate::from_pem(&std::fs::read(self.0)?).map_err(std::io::Error::other)
    }
}

/// A TLS acceptor builder.
///
/// `Tls` configures how TLS connections should be handled by the server.
/// It can be converted into a runtime acceptor through [`IntoAccept`],
/// which prepares the TLS configuration and constructs the underlying
/// `rustls` acceptor.
///
/// By default no certificate resolver is configured. A resolver must be
/// attached using [`with_resolver`](Tls::with_resolver) or
/// [`with_certificate`](Tls::with_certificate) before the acceptor can
/// be used.
#[derive(Debug, Default)]
pub struct Tls<T = ()>(T);

impl Tls {
    /// Creates a new TLS builder with no resolver configured.
    ///
    /// A certificate resolver must be attached before the acceptor
    /// can be used.
    #[inline]
    pub const fn new() -> Self {
        Self(())
    }
}

impl<T> Tls<T> {
    /// Attaches a certificate resolver.
    ///
    /// The resolver determines which certificate should be used for a
    /// connection based on the TLS client hello. This allows certificates
    /// to be selected dynamically, for example based on the requested
    /// server name.
    #[inline]
    pub fn with_resolver<R>(self, resolver: R) -> Tls<R>
    where
        R: IntoResolver,
    {
        Tls(resolver)
    }

    /// Attaches a certificate resolver.
    ///
    /// The resolver determines which certificate should be used for a
    /// connection based on the TLS client hello. This allows certificates
    /// to be selected dynamically, for example based on the requested
    /// server name.
    #[inline]
    pub fn with_certificate<P>(self, path: P) -> Tls<Pem<P>>
    where
        P: AsRef<Path>,
    {
        self.with_resolver(Pem(path))
    }
}

impl<I, S, T> IntoAccept<I, S> for Tls<T>
where
    I: AsyncRead + AsyncWrite + Unpin,
    T: IntoResolver,
    T::Resolver: Send + Sync + 'static,
{
    type Accept = TlsAcceptor;

    type Future = Ready<std::io::Result<Self::Accept>>;

    #[inline]
    fn into_accept(self) -> Self::Future {
        ::core::future::ready(r#try! {
            let resolver = Arc::new(ResolvesServerCert(self.0.into_resolver()?));
            let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());

            let mut config = ServerConfig::builder_with_provider(provider)
                .with_safe_default_protocol_versions()
                .map_err(std::io::Error::other)?
                .with_no_client_auth()
                .with_cert_resolver(resolver);

            config.alpn_protocols = vec![b"h2".into(), b"http/1.1".into()];

            let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));

            Ok(TlsAcceptor(acceptor))
        })
    }
}

/// Runtime TLS acceptor.
///
/// `TlsAcceptor` is produced from a [`Tls`] builder when the server
/// starts. It wraps a `tokio_rustls::TlsAcceptor` and performs the TLS
/// handshake for each incoming connection.
///
/// After a successful handshake the accepted stream is returned as a
/// [`TlsStream`].
pub struct TlsAcceptor(tokio_rustls::TlsAcceptor);

impl<I, S> Accept<I, S> for TlsAcceptor
where
    I: AsyncRead + AsyncWrite + Unpin,
{
    type Stream = TlsStream<I>;

    type Service = S;

    type Future = TlsAcceptorFuture<I, S>;

    #[inline]
    fn accept(&self, stream: I, service: S) -> Self::Future {
        TlsAcceptorFuture {
            service: Some(service),
            accept: self.0.accept(stream),
        }
    }
}

pin_project! {
    #[doc(hidden)]
    pub struct TlsAcceptorFuture<I, S> {
        service: Option<S>,
        #[pin] accept: tokio_rustls::Accept<I>,
    }
}

impl<I, S> Future for TlsAcceptorFuture<I, S>
where
    I: AsyncRead + AsyncWrite + Unpin,
{
    type Output = std::io::Result<(TlsStream<I>, S)>;

    fn poll(self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> Poll<Self::Output> {
        let this = self.project();

        match this.accept.poll(cx) {
            Poll::Ready(Ok(stream)) => Poll::Ready(Ok((stream, this.service.take().unwrap()))),
            Poll::Ready(Err(err)) => Poll::Ready(Err(err)),
            Poll::Pending => Poll::Pending,
        }
    }
}

struct ResolvesServerCert<T>(T);

impl<T> std::fmt::Debug for ResolvesServerCert<T> {
    #[inline]
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("ResolvesServerCert")
            .field(&::core::any::type_name::<T>())
            .finish()
    }
}

impl<T> rustls::server::ResolvesServerCert for ResolvesServerCert<T>
where
    T: Resolver + Send + Sync,
{
    #[inline]
    fn resolve(&self, client_hello: ClientHello<'_>) -> Option<Arc<rustls::sign::CertifiedKey>> {
        self.0.resolve(client_hello).map(|x| x.0)
    }
}
