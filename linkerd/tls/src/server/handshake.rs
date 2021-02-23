use super::{ConditionalServerTls, Config, Io, NoServerTls, ServerTls};
use crate::{ClientId, LocalId, NegotiatedProtocol, ServerId};
use futures::prelude::*;
use linkerd_conditional::Conditional;
use linkerd_dns_name as dns;
use linkerd_error::Error;
use linkerd_identity as id;
use linkerd_io::{self as io, EitherIo};
use linkerd_stack::{layer, NewService, Param};
use rustls::Session;
use std::{
    pin::Pin,
    task::{Context, Poll},
};
pub use tokio_rustls::server::TlsStream;
use tower::util::ServiceExt;
use tracing::debug;

#[derive(Clone, Debug)]
pub struct NewHandshake<L, N> {
    identity: Option<L>,
    inner: N,
}

#[derive(Clone, Debug)]
pub enum Handshake<T, L, N, S> {
    Enabled { target: T, identity: L, inner: N },
    Disabled(S),
}

impl<L, N> NewHandshake<L, N> {
    pub fn new(identity: Option<L>, inner: N) -> Self {
        Self { identity, inner }
    }

    pub fn layer(identity: Option<L>) -> impl layer::Layer<N, Service = Self> + Clone
    where
        L: Clone,
    {
        layer::mk(move |inner| Self::new(identity.clone(), inner))
    }
}

impl<T, L, N> NewService<(Option<ServerId>, T)> for NewHandshake<L, N>
where
    L: Clone + Param<LocalId> + Param<Config>,
    N: NewService<(ConditionalServerTls, T)> + Clone,
{
    type Service = Handshake<T, L, N, N::Service>;

    fn new_service(&mut self, (sni, target): (Option<ServerId>, T)) -> Self::Service {
        let tls = match (self.identity.as_ref(), sni) {
            (Some(identity), Some(ServerId(sni))) => {
                let LocalId(id) = identity.param();
                if sni == id {
                    return Handshake::Enabled {
                        target,
                        identity: identity.clone(),
                        inner: self.inner.clone(),
                    };
                }

                Conditional::Some(ServerTls::Passthru { sni: ServerId(sni) })
            }
            (None, _) => Conditional::None(NoServerTls::NoClientHello),
            (_, None) => Conditional::None(NoServerTls::Disabled),
        };
        Handshake::Disabled(self.inner.new_service((tls, target)))
    }
}

impl<I, L, N, NSvc, T> tower::Service<I> for Handshake<T, L, N, N::Service>
where
    I: io::AsyncRead + io::AsyncWrite + Send + Sync + Unpin + 'static,
    L: Param<LocalId> + Param<Config>,
    N: NewService<(ConditionalServerTls, T), Service = NSvc> + Clone + Send + 'static,
    NSvc: tower::Service<Io<I>, Response = ()> + Send + 'static,
    NSvc::Error: Into<Error>,
    NSvc::Future: Send,
    T: Clone + Send + 'static,
{
    type Response = ();
    type Error = Error;
    type Future = Pin<Box<dyn Future<Output = Result<(), Error>> + Send + 'static>>;

    #[inline]
    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        match self {
            Self::Disabled(inner) => inner.poll_ready(cx).map_err(Into::into),
            Self::Enabled { .. } => Poll::Ready(Ok(())),
        }
    }

    #[inline]
    fn call(&mut self, io: I) -> Self::Future {
        match self {
            Self::Enabled {
                target,
                identity,
                inner,
            } => {
                let target = target.clone();
                let config = Param::<Config>::param(identity);
                let mut inner = inner.clone();
                Box::pin(async move {
                    let (tls, io) = Self::handshake(config, io).await?;
                    inner
                        .new_service((Conditional::Some(tls), target))
                        .oneshot(EitherIo::Right(io))
                        .err_into::<Error>()
                        .await
                })
            }

            Self::Disabled(inner) => Box::pin(inner.call(EitherIo::Left(io)).err_into::<Error>()),
        }
    }
}

impl<T, L, N, S> Handshake<T, L, N, S> {
    async fn handshake<I>(tls_config: Config, io: I) -> io::Result<(ServerTls, TlsStream<I>)>
    where
        I: io::AsyncRead + io::AsyncWrite + Unpin,
    {
        let io = tokio_rustls::TlsAcceptor::from(tls_config)
            .accept(io)
            .await?;

        // Determine the peer's identity, if it exist.
        let client_id = Self::client_identity(&io);

        let negotiated_protocol = io
            .get_ref()
            .1
            .get_alpn_protocol()
            .map(|b| NegotiatedProtocol(b.into()));

        debug!(client.id = ?client_id, alpn = ?negotiated_protocol, "Accepted TLS connection");
        let tls = ServerTls::Established {
            client_id,
            negotiated_protocol,
        };
        Ok((tls, io))
    }

    fn client_identity<I>(tls: &TlsStream<I>) -> Option<ClientId> {
        use webpki::GeneralDNSNameRef;

        let (_io, session) = tls.get_ref();
        let certs = session.get_peer_certificates()?;
        let c = certs.first().map(rustls::Certificate::as_ref)?;
        let end_cert = webpki::EndEntityCert::from(c).ok()?;
        let dns_names = end_cert.dns_names().ok()?;

        match dns_names.first()? {
            GeneralDNSNameRef::DNSName(n) => {
                Some(ClientId(id::Name::from(dns::Name::from(n.to_owned()))))
            }
            GeneralDNSNameRef::Wildcard(_) => {
                // Wildcards can perhaps be handled in a future path...
                None
            }
        }
    }
}
