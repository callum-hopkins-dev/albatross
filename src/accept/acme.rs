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

use std::{
    any::TypeId,
    collections::HashMap,
    convert::Infallible,
    fmt::Debug,
    fs::TryLockError,
    future::Ready,
    hash::Hash,
    io::{Cursor, Read},
    path::Path,
    pin::Pin,
    str::FromStr,
    sync::Arc,
    task::Poll,
};

use async_trait::async_trait;
use const_hex::FromHexError;
use futures_core::Stream;
use pin_project_lite::pin_project;
use rustls::ServerConfig;
use rustls_acme::{AccountCache, AcmeConfig, CertCache, UseChallenge};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::Value;
use sha2::{Digest, Sha256};
use tokio::{
    fs::File,
    io::{AsyncRead, AsyncWrite, AsyncWriteExt},
    sync::Mutex,
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
pub struct Acme<C = ()> {
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
            cache: (),
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
    pub fn with_file_cache<P>(self, path: P) -> Acme<FileCache>
    where
        P: AsRef<Path>,
    {
        self.with_cache(FileCache::open(path).unwrap())
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
    C: Cache<Certificate> + Cache<Account>,
{
    type Accept = AcmeAcceptor;

    type Future = Ready<std::io::Result<Self::Accept>>;

    fn into_accept(self) -> Self::Future {
        ::core::future::ready(r#try! {
            let mut state = AcmeConfig::new(self.domains)
                .cache(AcmeCache(Arc::new(Mutex::new(self.cache))))
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

#[derive(
    Debug, Default, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
#[serde(transparent)]
pub struct Id(#[serde(with = "const_hex::serde")] [u8; 32]);

impl Id {
    #[inline]
    pub const fn from_bytes(x: [u8; 32]) -> Self {
        Self(x)
    }

    #[inline]
    pub const fn to_bytes(self) -> [u8; 32] {
        self.0
    }

    #[inline]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl FromStr for Id {
    type Err = FromHexError;

    #[inline]
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        const_hex::const_decode_to_array(s.as_bytes()).map(Self)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Certificate(#[serde(with = "const_hex::serde")] Box<[u8]>);

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Account(#[serde(with = "const_hex::serde")] Box<[u8]>);

pub trait Cache<T>
where
    Self: Send + 'static,
{
    type Error: Into<Box<dyn std::error::Error + Send + Sync + 'static>>;

    fn get(&self, id: Id) -> impl Future<Output = Result<Option<T>, Self::Error>> + Send;

    fn set(&mut self, id: Id, value: T) -> impl Future<Output = Result<(), Self::Error>> + Send;
}

impl<T> Cache<T> for ()
where
    T: Send,
{
    type Error = Infallible;

    #[inline]
    async fn get(&self, _id: Id) -> Result<Option<T>, Self::Error> {
        Ok(None)
    }

    #[inline]
    async fn set(&mut self, _id: Id, _value: T) -> Result<(), Self::Error> {
        Ok(())
    }
}

#[derive(Debug)]
pub struct FileCache {
    map: HashMap<Id, Value>,
    buf: Vec<u8>,

    file: File,
}

impl FileCache {
    pub fn open<P>(path: P) -> std::io::Result<Self>
    where
        P: AsRef<Path>,
    {
        let mut file = std::fs::File::options()
            .create(true)
            .read(true)
            .write(true)
            .truncate(false)
            .open(&path)?;

        match file.try_lock() {
            Ok(_) => {
                let mut buf = Vec::new();
                file.read_to_end(&mut buf)?;

                Ok(Self {
                    map: serde_json::from_slice(&buf).unwrap_or_default(),
                    buf,
                    file: File::from_std(file),
                })
            }

            Err(TryLockError::WouldBlock) => {
                Err(std::io::Error::from(std::io::ErrorKind::ResourceBusy))
            }

            Err(TryLockError::Error(err)) => Err(err),
        }
    }
}

impl<T> Cache<T> for FileCache
where
    T: Serialize + DeserializeOwned + Send,
{
    type Error = std::io::Error;

    async fn get(&self, id: Id) -> Result<Option<T>, Self::Error> {
        match self.map.get(&id) {
            Some(value) => Ok(Some(
                T::deserialize(value).map_err(std::io::Error::other)?,
            )),
            None => Ok(None),
        }
    }

    async fn set(&mut self, id: Id, value: T) -> Result<(), Self::Error> {
        self.map.insert(
            id,
            serde_json::to_value(value).map_err(std::io::Error::other)?,
        );

        self.buf.clear();

        serde_json::to_writer(Cursor::new(&mut self.buf), &self.map)
            .map_err(std::io::Error::other)?;

        self.file.set_len(0).await?;
        self.file.write_all(&self.buf).await?;
        self.file.sync_data().await?;

        Ok(())
    }
}

#[derive(Debug, Default, Clone)]
struct Sha256Hasher(Sha256);

impl Sha256Hasher {
    #[inline]
    fn finish(self) -> [u8; 32] {
        self.0.finalize().into()
    }
}

impl std::hash::Hasher for Sha256Hasher {
    #[inline]
    fn finish(&self) -> u64 {
        u64::from_ne_bytes(*self.clone().0.finalize().first_chunk().unwrap())
    }

    #[inline]
    fn write(&mut self, bytes: &[u8]) {
        self.0.update(bytes);
    }
}

struct AcmeCache<T>(Arc<Mutex<T>>);

impl<T> Debug for AcmeCache<T> {
    #[inline]
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("AcmeCache")
            .field(&::core::any::type_name::<T>())
            .finish()
    }
}

#[async_trait]
impl<T> CertCache for AcmeCache<T>
where
    T: Cache<Certificate>,
{
    type EC = Box<dyn std::error::Error + Send + Sync + 'static>;

    async fn load_cert(
        &self,
        domains: &[String],
        directory_url: &str,
    ) -> Result<Option<Vec<u8>>, Self::EC> {
        let mut hasher = Sha256Hasher::default();

        TypeId::of::<Certificate>().hash(&mut hasher);
        domains.hash(&mut hasher);
        directory_url.hash(&mut hasher);

        let id = Id::from_bytes(hasher.finish());

        let cache = self.0.lock().await;

        cache
            .get(id)
            .await
            .map_err(|x| x.into())
            .map(|x| x.map(|x| x.0.into_vec()))
    }

    async fn store_cert(
        &self,
        domains: &[String],
        directory_url: &str,
        cert: &[u8],
    ) -> Result<(), Self::EC> {
        let mut hasher = Sha256Hasher::default();

        TypeId::of::<Certificate>().hash(&mut hasher);
        domains.hash(&mut hasher);
        directory_url.hash(&mut hasher);

        let id = Id::from_bytes(hasher.finish());

        let mut cache = self.0.lock().await;

        cache
            .set(id, Certificate(cert.into()))
            .await
            .map_err(|x| x.into())
    }
}

#[async_trait]
impl<T> AccountCache for AcmeCache<T>
where
    T: Cache<Account>,
{
    type EA = Box<dyn std::error::Error + Send + Sync + 'static>;

    async fn load_account(
        &self,
        contact: &[String],
        directory_url: &str,
    ) -> Result<Option<Vec<u8>>, Self::EA> {
        let mut hasher = Sha256Hasher::default();

        TypeId::of::<Account>().hash(&mut hasher);
        contact.hash(&mut hasher);
        directory_url.hash(&mut hasher);

        let id = Id::from_bytes(hasher.finish());

        let cache = self.0.lock().await;

        cache
            .get(id)
            .await
            .map_err(|x| x.into())
            .map(|x| x.map(|x| x.0.into_vec()))
    }

    async fn store_account(
        &self,
        contact: &[String],
        directory_url: &str,
        account: &[u8],
    ) -> Result<(), Self::EA> {
        let mut hasher = Sha256Hasher::default();

        TypeId::of::<Account>().hash(&mut hasher);
        contact.hash(&mut hasher);
        directory_url.hash(&mut hasher);

        let id = Id::from_bytes(hasher.finish());

        let mut cache = self.0.lock().await;

        cache
            .set(id, Account(account.into()))
            .await
            .map_err(|x| x.into())
    }
}
