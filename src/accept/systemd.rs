//! systemd notification acceptor.
//!
//! This module provides integration with `systemd` service notifications.
//!
//! The [`Notify`] wrapper adds support for:
//!
//! - sending a readiness notification when the server starts, and
//! - sending periodic watchdog notifications when a systemd watchdog
//!   is configured.
//!
//! When converted into an acceptor, [`Notify`] forwards all connection
//! handling to an inner acceptor while managing systemd lifecycle
//! notifications in the background.
//!
//! If the process is not running under systemd, the wrapper becomes a
//! no-op and simply delegates to the inner acceptor.
//!
//! [`Accept`]: crate::accept::Accept
//! [`IntoAccept`]: crate::accept::IntoAccept

use std::task::Poll;

use libsystemd::daemon::NotifyState;
use pin_project_lite::pin_project;
use tokio::task::{AbortHandle, JoinHandle};

use crate::{Accept, IntoAccept};

/// A systemd notification wrapper.
///
/// `Notify` wraps another acceptor configuration and augments it with
/// systemd service notifications.
///
/// When the server starts, it sends a readiness notification to systemd.
/// If a watchdog interval is configured, it also starts a background
/// task that periodically sends watchdog keepalive notifications for as
/// long as the acceptor remains alive.
///
/// Aside from systemd integration, this type does not alter connection
/// handling and simply delegates to the wrapped acceptor.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Notify<T>(T);

impl<T> Notify<T> {
    /// Creates a new systemd notification wrapper around an inner
    /// acceptor configuration.
    #[inline]
    pub const fn new(inner: T) -> Self {
        Self(inner)
    }
}

impl<I, S, T> IntoAccept<I, S> for Notify<T>
where
    T: IntoAccept<I, S>,
{
    type Accept = NotifyAcceptor<T::Accept>;

    type Future = NotifyFuture<T::Future>;

    fn into_accept(self) -> Self::Future {
        fn notify() -> std::io::Result<Option<JoinHandle<()>>> {
            if !libsystemd::daemon::booted() {
                return Ok(None);
            }

            libsystemd::daemon::notify(false, &[NotifyState::Ready])
                .map_err(|err| std::io::Error::other(err))?;

            if let Some(duration) = libsystemd::daemon::watchdog_enabled(false) {
                Ok(Some(tokio::task::spawn(async move {
                    while libsystemd::daemon::notify(false, &[NotifyState::Watchdog]).is_ok() {
                        tokio::time::sleep(duration).await;
                    }
                })))
            } else {
                Ok(None)
            }
        }

        NotifyFuture {
            inner: match notify() {
                Ok(task) => NotifyFutureInner::Future {
                    future: self.0.into_accept(),
                    task: task.map(|x| x.abort_handle()),
                },

                Err(err) => NotifyFutureInner::Err { err: Some(err) },
            },
        }
    }
}

pin_project! {
    #[doc(hidden)]
    pub struct NotifyFuture<F> {
        #[pin] inner: NotifyFutureInner<F>
    }
}

impl<F, T> Future for NotifyFuture<F>
where
    F: Future<Output = std::io::Result<T>>,
{
    type Output = std::io::Result<NotifyAcceptor<T>>;

    #[inline]
    fn poll(self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> Poll<Self::Output> {
        self.project().inner.poll(cx)
    }
}

pin_project! {
    #[project = NotifyFutureInnerProj]
    enum NotifyFutureInner<F> {
        Err {
            err: Option<std::io::Error>,
        },

        Future {
            #[pin] future: F,
            task: Option<AbortHandle>,
        },
    }
}

impl<F, T> Future for NotifyFutureInner<F>
where
    F: Future<Output = std::io::Result<T>>,
{
    type Output = std::io::Result<NotifyAcceptor<T>>;

    #[inline]
    fn poll(self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> Poll<Self::Output> {
        match self.project() {
            NotifyFutureInnerProj::Err { err } => Poll::Ready(Err(err.take().unwrap())),

            NotifyFutureInnerProj::Future { future, task } => match future.poll(cx) {
                Poll::Ready(Ok(inner)) => Poll::Ready(Ok(NotifyAcceptor {
                    inner,
                    task: task.take(),
                })),

                Poll::Ready(Err(err)) => Poll::Ready(Err(err)),

                Poll::Pending => Poll::Pending,
            },
        }
    }
}

/// Runtime systemd notification acceptor.
///
/// `NotifyAcceptor` is produced from [`Notify`] when the server starts.
/// It forwards all accepted connections to the wrapped acceptor and
/// manages any background watchdog task required by systemd.
pub struct NotifyAcceptor<T> {
    inner: T,
    task: Option<AbortHandle>,
}

impl<I, S, T> Accept<I, S> for NotifyAcceptor<T>
where
    T: Accept<I, S>,
{
    type Stream = T::Stream;

    type Service = T::Service;

    type Future = T::Future;

    #[inline]
    fn accept(&self, stream: I, service: S) -> Self::Future {
        self.inner.accept(stream, service)
    }
}

impl<T> Drop for NotifyAcceptor<T> {
    #[inline]
    fn drop(&mut self) {
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}
