use crate::{glue::Body, h1, h2, Version};
use futures::{future, prelude::*};
use linkerd2_error::Error;
use std::{
    marker::PhantomData,
    task::{Context, Poll},
};
use tower::ServiceExt;
use tracing::{debug, debug_span, trace};
use tracing_futures::{Instrument, Instrumented};

/// Configures an HTTP client that uses a `C`-typed connector
#[derive(Debug)]
pub struct MakeClientLayer<B> {
    h2_settings: crate::h2::Settings,
    _marker: PhantomData<fn() -> B>,
}

/// A `MakeService` that can speak either HTTP/1 or HTTP/2.
pub struct MakeClient<C, B> {
    connect: C,
    h2_settings: crate::h2::Settings,
    _marker: PhantomData<fn(B)>,
}

/// The `Service` yielded by `MakeClient::new_service()`.
pub enum Client<C, T, B> {
    Http1(h1::Client<C, T, B>),
    Http2(h2::Connection<B>),
}

// === impl MakeClientLayer ===

impl<B> MakeClientLayer<B> {
    pub fn new(h2_settings: crate::h2::Settings) -> Self {
        Self {
            h2_settings,
            _marker: PhantomData,
        }
    }
}

impl<B> Clone for MakeClientLayer<B> {
    fn clone(&self) -> Self {
        Self {
            h2_settings: self.h2_settings,
            _marker: self._marker,
        }
    }
}

impl<C, B> tower::layer::Layer<C> for MakeClientLayer<B> {
    type Service = MakeClient<C, B>;

    fn layer(&self, connect: C) -> Self::Service {
        MakeClient {
            connect,
            h2_settings: self.h2_settings,
            _marker: PhantomData,
        }
    }
}

// === impl MakeClient ===

impl<C, T, B> tower::Service<T> for MakeClient<C, B>
where
    T: AsRef<Version> + Clone + Send + Sync + 'static,
    C: tower::make::MakeConnection<T> + Clone + Unpin + Send + Sync + 'static,
    C::Future: Unpin + Send + 'static,
    C::Error: Into<Error>,
    C::Connection: Unpin + Send + 'static,
    B: hyper::body::HttpBody + Send + 'static,
    B::Data: Send,
    B::Error: Into<Error> + Send + Sync,
{
    type Response = Client<C, T, B>;
    type Error = Error;
    type Future = future::Either<
        future::Ready<Result<Client<C, T, B>, Error>>,
        future::MapOk<
            tower::util::Oneshot<h2::Connect<C, B>, T>,
            fn(h2::Connection<B>) -> Client<C, T, B>,
        >,
    >;

    fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, target: T) -> Self::Future {
        trace!("Building HTTP client");
        let connect = self.connect.clone();
        let h2_settings = self.h2_settings;

        match *target.as_ref() {
            Version::Http1 => {
                future::Either::Left(future::ok(Client::Http1(h1::Client::new(connect, target))))
            }
            Version::H2 => future::Either::Right(
                h2::Connect::new(connect, h2_settings)
                    .oneshot(target)
                    .map_ok(Client::Http2),
            ),
        }
    }
}

impl<C: Clone, B> Clone for MakeClient<C, B> {
    fn clone(&self) -> Self {
        Self {
            connect: self.connect.clone(),
            h2_settings: self.h2_settings,
            _marker: self._marker,
        }
    }
}

// === impl Client ===

impl<C, T, B> tower::Service<http::Request<B>> for Client<C, T, B>
where
    T: Clone + Send + Sync + 'static,
    C: tower::make::MakeConnection<T> + Clone + Send + Sync + 'static,
    C::Connection: Unpin + Send + 'static,
    C::Future: Unpin + Send + 'static,
    C::Error: Into<Error>,
    B: hyper::body::HttpBody + Send + 'static,
    B::Data: Send,
    B::Error: Into<Error> + Send + Sync,
{
    type Response = http::Response<Body>;
    type Error = Error;
    type Future = future::Either<
        future::ErrInto<
            Instrumented<<h1::Client<C, T, B> as tower::Service<http::Request<B>>>::Future>,
            Error,
        >,
        future::MapOk<
            future::ErrInto<
                Instrumented<<h2::Connection<B> as tower::Service<http::Request<B>>>::Future>,
                Error,
            >,
            fn(http::Response<hyper::Body>) -> hyper::Response<Body>,
        >,
    >;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        match *self {
            Client::Http1(ref mut h1) => h1.poll_ready(cx).map_err(Into::into),
            Client::Http2(ref mut h2) => h2.poll_ready(cx).map_err(Into::into),
        }
    }

    fn call(&mut self, req: http::Request<B>) -> Self::Future {
        let span = debug_span!(
            "request",
            method = %req.method(),
            uri = %req.uri(),
            version = ?req.version(),
        );
        let _e = span.enter();
        debug!(headers = ?req.headers(), "client request");

        match self {
            Client::Http1(ref mut h1) => {
                future::Either::Left(h1.call(req).instrument(span.clone()).err_into::<Error>())
            }
            Client::Http2(ref mut h2) => future::Either::Right(
                h2.call(req)
                    .instrument(span.clone())
                    .err_into::<Error>()
                    .map_ok(|rsp| {
                        rsp.map(|b| Body {
                            body: Some(b),
                            upgrade: None,
                        })
                    }),
            ),
        }
    }
}
