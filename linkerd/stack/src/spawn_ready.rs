// Vendored from upstream tower to add a `NewService` impl.
use crate::NewService;
use futures::ready;
use pin_project::pin_project;
use std::{
    future::Future,
    pin::Pin,
    task::{Context, Poll},
};
pub use tower::spawn_ready::SpawnReady;
use tower::{Layer, Service};

/// Spawns tasks to drive its inner service to readiness.
#[derive(Debug, Clone)]
pub struct SpawnReadyLayer;

impl SpawnReadyLayer {
    /// Builds a SpawnReady layer with the default executor.
    pub fn new() -> Self {
        Self
    }
}

impl<S> Layer<S> for SpawnReadyLayer {
    type Service = MakeSpawnReady<S>;

    fn layer(&self, service: S) -> Self::Service {
        MakeSpawnReady::new(service)
    }
}

/// Builds SpawnReady instances with the result of an inner Service.
#[derive(Clone, Debug)]
pub struct MakeSpawnReady<S> {
    inner: S,
}

impl<S> MakeSpawnReady<S> {
    /// Creates a new `MakeSpawnReady` wrapping `service`.
    pub fn new(service: S) -> Self {
        Self { inner: service }
    }
}

/// Builds a SpawnReady with the result of an inner Future.
#[pin_project]
#[derive(Debug)]
pub struct MakeFuture<F> {
    #[pin]
    inner: F,
}

impl<S, Target> Service<Target> for MakeSpawnReady<S>
where
    S: Service<Target>,
{
    type Response = SpawnReady<S::Response>;
    type Error = S::Error;
    type Future = MakeFuture<S::Future>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, target: Target) -> Self::Future {
        MakeFuture {
            inner: self.inner.call(target),
        }
    }
}

impl<F, T, E> Future for MakeFuture<F>
where
    F: Future<Output = Result<T, E>>,
{
    type Output = Result<SpawnReady<T>, E>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.project();
        let inner = ready!(this.inner.poll(cx))?;
        let svc = SpawnReady::new(inner);
        Poll::Ready(Ok(svc))
    }
}

impl<S, Target> NewService<Target> for MakeSpawnReady<S>
where
    S: NewService<Target>,
{
    type Service = SpawnReady<S::Service>;

    fn new_service(&mut self, target: Target) -> Self::Service {
        SpawnReady::new(self.inner.new_service(target))
    }
}
