//! ACME TLS acceptor.
//!
//! This module provides automatic certificate management using the
//! ACME protocol (for example, Let's Encrypt).
//!
//! The [`Acme`] builder configures how certificates should be obtained
//! and renewed. When the server starts, the builder is converted into
//! an [`AcmeAcceptor`] through [`IntoAccept`]. The acceptor performs TLS
//! handshakes for incoming connections while a background task manages
//! certificate issuance and renewal.
//!
//! Certificates are obtained using the **TLS-ALPN-01** challenge and are
//! automatically refreshed as needed.
//!
//! [`Accept`]: crate::accept::Accept
//! [`IntoAccept`]: crate::accept::IntoAccept

use std::{fmt::Debug, future::Ready, path::Path, pin::Pin, sync::Arc, task::Poll};

use futures_core::Stream;
use pin_project_lite::pin_project;
use rustls::ServerConfig;
use rustls_acme::{
    AccountCache, AcmeConfig, CertCache, UseChallenge,
    caches::{DirCache, NoCache},
};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    task::AbortHandle,
};
use tokio_rustls::server::TlsStream;

use crate::{Accept, IntoAccept};

macro_rules! r#try {
    ($($tt:tt)*) => {
        (|| { $($tt)* })()
    };
}

/// ACME acceptor builder.
///
/// `Acme` configures automatic certificate issuance using an ACME
/// provider. The builder collects configuration such as the ACME
/// directory endpoint, the domains that should receive certificates,
/// and contact information associated with the ACME account.
///
/// When the server starts, the builder is converted into an
/// [`AcmeAcceptor`] which performs TLS handshakes and manages the
/// certificate lifecycle in the background.
#[derive(Debug)]
pub struct Acme<C = NoCache> {
    directory: Box<str>,
    domains: Vec<Box<str>>,
    contacts: Vec<Box<str>>,
    cache: C,
}

impl Acme {
    /// Creates a new ACME configuration using the specified directory.
    ///
    /// The `directory` identifies the ACME server endpoint used for
    /// certificate issuance.
    #[inline]
    pub fn new(directory: &str) -> Self {
        Self {
            directory: directory.to_owned().into_boxed_str(),
            domains: Vec::new(),
            contacts: Vec::new(),
            cache: NoCache::default(),
        }
    }
}

impl<C> Acme<C> {
    /// Replaces the certificate and account cache implementation.
    ///
    /// Caches allow ACME state and certificates to persist across
    /// restarts.
    #[inline]
    pub fn with_cache<U>(self, cache: U) -> Acme<U> {
        Acme {
            directory: self.directory,
            domains: self.domains,
            contacts: self.contacts,
            cache,
        }
    }

    /// Configures a filesystem-backed cache for ACME state.
    ///
    /// This stores account and certificate data in the provided
    /// directory.
    #[inline]
    pub fn with_file_cache<P>(self, path: P) -> Acme<DirCache<Box<Path>>>
    where
        P: AsRef<Path>,
    {
        self.with_cache(DirCache::new(path.as_ref().into()))
    }

    /// Adds multiple domains for which certificates should be issued.
    ///
    /// Each domain listed here will be included in the requested
    /// certificate.
    #[inline]
    pub fn with_domains<I>(mut self, domains: I) -> Self
    where
        I: IntoIterator,
        I::Item: AsRef<str>,
    {
        self.domains
            .extend(domains.into_iter().map(|x| x.as_ref().into()));

        self
    }

    /// Adds a single domain to the certificate request.
    #[inline]
    pub fn with_domain<T>(self, domain: T) -> Self
    where
        T: AsRef<str>,
    {
        self.with_domains([domain])
    }

    /// Adds contact addresses associated with the ACME account.
    ///
    /// These are typically email addresses used by the certificate
    /// authority for important notifications.
    #[inline]
    pub fn with_contacts<I>(mut self, contacts: I) -> Self
    where
        I: IntoIterator,
        I::Item: AsRef<str>,
    {
        self.contacts
            .extend(contacts.into_iter().map(|x| x.as_ref().into()));

        self
    }

    /// Adds a single contact address.
    #[inline]
    pub fn with_contact<T>(self, contact: T) -> Self
    where
        T: AsRef<str>,
    {
        self.with_contacts([contact])
    }
}

impl<I, S, C> IntoAccept<I, S> for Acme<C>
where
    I: AsyncRead + AsyncWrite + Unpin,
    C: AccountCache + CertCache + 'static + Debug,
{
    type Accept = AcmeAcceptor;

    type Future = Ready<std::io::Result<Self::Accept>>;

    fn into_accept(self) -> Self::Future {
        ::core::future::ready(r#try! {
            let mut state = AcmeConfig::new(self.domains)
                .cache(self.cache)
                .challenge_type(UseChallenge::TlsAlpn01)
                .contact(self.contacts)
                .directory(self.directory)
                .state();

            let provider = Arc::new(rustls_acme::rustls::crypto::aws_lc_rs::default_provider());

            let mut config = ServerConfig::builder_with_provider(provider)
                .with_safe_default_protocol_versions()
                .map_err(std::io::Error::other)?
                .with_no_client_auth()
                .with_cert_resolver(state.resolver());

            config.alpn_protocols = vec![b"acme-tls/1".into(), b"h2".into(), b"http/1.1".into()];

            let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));

            let task = tokio::task::spawn(async move {
                loop {
                    match ::core::future::poll_fn(|cx| Pin::new(&mut state).poll_next(cx))
                        .await
                        .unwrap()
                    {
                        Ok(x) => tracing::info!(target: "rustls_acme", "{x:?}"),
                        Err(err) => tracing::error!(target: "rustls_acme", "{err:?}"),
                    }
                }
            });

            Ok(AcmeAcceptor { inner: acceptor, task: task.abort_handle() })
        })
    }
}

/// Runtime ACME TLS acceptor.
///
/// `AcmeAcceptor` is produced from an [`Acme`] configuration when the
/// server starts. It performs TLS handshakes for incoming connections
/// while a background task manages certificate issuance and renewal.
pub struct AcmeAcceptor {
    inner: tokio_rustls::TlsAcceptor,
    task: AbortHandle,
}

impl<I, S> Accept<I, S> for AcmeAcceptor
where
    I: AsyncRead + AsyncWrite + Unpin,
{
    type Stream = TlsStream<I>;

    type Service = S;

    type Future = AcmeAcceptorFuture<I, S>;

    #[inline]
    fn accept(&self, stream: I, service: S) -> Self::Future {
        AcmeAcceptorFuture {
            service: Some(service),
            accept: self.inner.accept(stream),
        }
    }
}

impl Drop for AcmeAcceptor {
    #[inline]
    fn drop(&mut self) {
        self.task.abort();
    }
}

pin_project! {
    #[doc(hidden)]
    pub struct AcmeAcceptorFuture<I, S> {
        service: Option<S>,
        #[pin] accept: tokio_rustls::Accept<I>,
    }
}

impl<I, S> Future for AcmeAcceptorFuture<I, S>
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
