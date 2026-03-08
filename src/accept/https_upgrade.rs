//! HTTPS upgrade acceptor.
//!
//! This module provides an acceptor that transparently upgrades HTTP
//! connections to HTTPS.
//!
//! The [`HttpsUpgrade`] acceptor inspects the first byte of an incoming
//! connection to determine whether the client is initiating a TLS
//! handshake or sending a plain HTTP request.
//!
//! - If the connection begins with a TLS handshake, the stream is passed
//!   to the inner acceptor for normal TLS processing.
//! - If the connection appears to be plain HTTP, a temporary HTTP
//!   connection is served which returns a **308 Permanent Redirect**
//!   response pointing to the equivalent HTTPS URL.
//!
//! This allows a single listener to support both HTTPS and HTTP upgrade
//! behavior without requiring a separate HTTP server for redirects.
//!
//! [`Accept`]: crate::accept::Accept
//! [`IntoAccept`]: crate::accept::IntoAccept

use std::{convert::Infallible, future::Ready, pin::Pin, sync::Arc, task::Poll};

use bytes::Bytes;
use http::{
    HeaderValue, Request, Response, StatusCode, Uri,
    header::{HOST, LOCATION},
    uri::{Authority, Scheme},
};
use http_body_util::Empty;
use hyper::{body::Incoming, service::Service};
use hyper_util::{
    rt::{TokioExecutor, TokioIo},
    server::conn::auto::{Builder, Connection},
};
use pin_project_lite::pin_project;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::{Accept, IntoAccept};

/// HTTPS upgrade acceptor builder.
///
/// `HttpsUpgrade` wraps another acceptor and adds logic that detects
/// whether an incoming connection is TLS or plain HTTP. TLS connections
/// are forwarded to the inner acceptor, while HTTP connections are
/// handled by issuing a redirect to the corresponding HTTPS URL.
///
/// This type is typically placed before a TLS acceptor in the acceptor
/// chain.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct HttpsUpgrade<T>(T);

impl<T> HttpsUpgrade<T> {
    /// Creates a new HTTPS upgrade wrapper around another acceptor
    /// configuration.
    #[inline]
    pub const fn new(inner: T) -> Self {
        Self(inner)
    }
}

impl<I, S, T> IntoAccept<I, S> for HttpsUpgrade<T>
where
    I: AsyncRead + AsyncWrite + Unpin + 'static,
    T: IntoAccept<HttpsUpgradeStream<I>, S>,
{
    type Accept = HttpsUpgradeAcceptor<T::Accept>;

    type Future = HttpsUpgradeFuture<T::Future>;

    #[inline]
    fn into_accept(self) -> Self::Future {
        HttpsUpgradeFuture {
            future: self.0.into_accept(),
        }
    }
}

pin_project! {
    #[doc(hidden)]
    pub struct HttpsUpgradeFuture<F> {
        #[pin] future: F,
    }
}

impl<F, T> Future for HttpsUpgradeFuture<F>
where
    F: Future<Output = std::io::Result<T>>,
{
    type Output = std::io::Result<HttpsUpgradeAcceptor<T>>;

    #[inline]
    fn poll(self: Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> Poll<Self::Output> {
        self.project()
            .future
            .poll(cx)
            .map(|x| x.map(|x| HttpsUpgradeAcceptor(Arc::new(x))))
    }
}

/// Runtime HTTPS upgrade acceptor.
///
/// This type is produced from [`HttpsUpgrade`] when the server starts.
/// It wraps another acceptor and intercepts connections in order to
/// determine whether they should be processed as TLS or redirected
/// to HTTPS.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct HttpsUpgradeAcceptor<T>(Arc<T>);

impl<T, I, S> Accept<I, S> for HttpsUpgradeAcceptor<T>
where
    I: AsyncRead + AsyncWrite + Unpin + 'static,
    T: Accept<HttpsUpgradeStream<I>, S>,
{
    type Stream = T::Stream;

    type Service = T::Service;

    type Future = HttpsUpgradeAcceptFuture<I, S, T>;

    #[inline]
    fn accept(&self, stream: I, service: S) -> Self::Future {
        HttpsUpgradeAcceptFuture {
            acceptor: Arc::clone(&self.0),
            accept: None,
            stream: Some(HttpsUpgradeStream {
                next: None,
                inner: stream,
            }),
            service: Some(service),
            connection: None,
        }
    }
}

pin_project! {
    #[doc(hidden)]
    pub struct HttpsUpgradeStream<T> {
        next: Option<u8>,
        #[pin] inner: T,
    }
}

impl<T> HttpsUpgradeStream<T>
where
    T: AsyncRead,
{
    fn poll_next(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<std::io::Result<u8>> {
        let this = self.project();

        match *this.next {
            Some(x) => Poll::Ready(Ok(x)),

            None => {
                let mut buf = [0u8; 1];
                let mut buf = ReadBuf::new(&mut buf);

                match this.inner.poll_read(cx, &mut buf) {
                    Poll::Ready(Ok(_)) => match buf.filled() {
                        [next] => {
                            *this.next = Some(*next);

                            Poll::Ready(Ok(*next))
                        }

                        _ => Poll::Ready(Err(std::io::Error::from(
                            std::io::ErrorKind::UnexpectedEof,
                        ))),
                    },

                    Poll::Ready(Err(err)) => Poll::Ready(Err(err)),
                    Poll::Pending => Poll::Pending,
                }
            }
        }
    }
}

impl<T> AsyncRead for HttpsUpgradeStream<T>
where
    T: AsyncRead,
{
    #[inline]
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.project();

        if let Some(next) = *this.next
            && buf.remaining() >= 1
        {
            buf.put_slice(&[next]);
            this.next.take();
        }

        this.inner.poll_read(cx, buf)
    }
}

impl<T> AsyncWrite for HttpsUpgradeStream<T>
where
    T: AsyncWrite,
{
    #[inline]
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        self.project().inner.poll_write(cx, buf)
    }

    #[inline]
    fn poll_flush(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        self.project().inner.poll_flush(cx)
    }

    #[inline]
    fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        self.project().inner.poll_flush(cx)
    }
}

pin_project! {
    #[doc(hidden)]
    pub struct HttpsUpgradeAcceptFuture<I, S, T>
    where
        T: Accept<HttpsUpgradeStream<I>, S>,
    {
        acceptor: Arc<T>,
        #[pin] accept: Option<T::Future>,
        #[pin] stream: Option<HttpsUpgradeStream<I>>,
        service: Option<S>,
        #[pin] connection: Option<Connection<'static, TokioIo<HttpsUpgradeStream<I>>, HttpsUpgradeService, TokioExecutor>>,
    }
}

impl<I, S, T> Future for HttpsUpgradeAcceptFuture<I, S, T>
where
    I: AsyncRead + AsyncWrite + Unpin + 'static,
    T: Accept<HttpsUpgradeStream<I>, S>,
{
    type Output = std::io::Result<(T::Stream, T::Service)>;

    fn poll(self: Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> Poll<Self::Output> {
        let mut this = self.project();

        match this.accept.as_mut().as_pin_mut() {
            Some(fut) => fut.poll(cx),

            None => match this.connection.as_mut().as_pin_mut() {
                Some(fut) => match fut.poll(cx) {
                    Poll::Ready(Ok(_)) => {
                        Poll::Ready(Err(std::io::Error::from(std::io::ErrorKind::Other)))
                    }

                    Poll::Ready(Err(err)) => {
                        Poll::Ready(Err(std::io::Error::from(std::io::Error::other(err))))
                    }

                    Poll::Pending => Poll::Pending,
                },

                None => match this.stream.as_mut().as_pin_mut().unwrap().poll_next(cx) {
                    Poll::Ready(Ok(0x16)) => {
                        this.accept.set(Some(this.acceptor.accept(
                            this.stream.get_mut().take().unwrap(),
                            this.service.take().unwrap(),
                        )));

                        this.accept.as_mut().as_pin_mut().unwrap().poll(cx)
                    }

                    Poll::Ready(Ok(_)) => {
                        let io = TokioIo::new(this.stream.get_mut().take().unwrap());

                        this.connection.set(Some(
                            Builder::new(TokioExecutor::new())
                                .serve_connection(io, HttpsUpgradeService)
                                .into_owned(),
                        ));

                        match this.connection.as_mut().as_pin_mut().unwrap().poll(cx) {
                            Poll::Ready(Ok(_)) => {
                                Poll::Ready(Err(std::io::Error::from(std::io::ErrorKind::Other)))
                            }

                            Poll::Ready(Err(err)) => {
                                Poll::Ready(Err(std::io::Error::from(std::io::Error::other(err))))
                            }

                            Poll::Pending => Poll::Pending,
                        }
                    }

                    Poll::Ready(Err(err)) => Poll::Ready(Err(err)),

                    Poll::Pending => Poll::Pending,
                },
            },
        }
    }
}

struct HttpsUpgradeService;

impl Service<Request<Incoming>> for HttpsUpgradeService {
    type Response = Response<Empty<Bytes>>;

    type Error = Infallible;

    type Future = Ready<Result<Self::Response, Self::Error>>;

    fn call(&self, req: Request<Incoming>) -> Self::Future {
        let (req, _) = req.into_parts();

        let mut uri = req.uri.into_parts();

        uri.authority = uri.authority.or_else(|| {
            req.headers
                .get(HOST)
                .and_then(|x| Authority::from_maybe_shared(x.to_owned()).ok())
        });

        uri.scheme = Some(Scheme::HTTPS);

        if let Some(location) = Uri::from_parts(uri)
            .ok()
            .and_then(|uri| HeaderValue::from_maybe_shared(uri.to_string()).ok())
        {
            let mut res = Response::new(Empty::new());
            *res.status_mut() = StatusCode::PERMANENT_REDIRECT;

            res.headers_mut().insert(LOCATION, location);

            ::core::future::ready(Ok(res))
        } else {
            let mut res = Response::new(Empty::new());
            *res.status_mut() = StatusCode::BAD_REQUEST;

            ::core::future::ready(Ok(res))
        }
    }
}
