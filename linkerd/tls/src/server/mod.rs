mod client_hello;
mod detect;
mod handshake;

pub use self::{
    detect::DetectSni,
    handshake::{Handshake, NewHandshake},
};
use crate::{NegotiatedProtocol, ServerId};
use linkerd_conditional::Conditional;
use linkerd_detect::{DetectService, NewDetectService};
use linkerd_identity as id;
use linkerd_io as io;
use linkerd_stack::{layer, NewService, Param};
use std::{fmt, str::FromStr, sync::Arc, time::Duration};
pub use tokio_rustls::server::TlsStream;

pub type Config = Arc<rustls::ServerConfig>;

/// Produces a server config that fails to handshake all connections.
pub fn empty_config() -> Config {
    let verifier = rustls::NoClientAuth::new();
    Arc::new(rustls::ServerConfig::new(verifier))
}

/// A newtype for remote client idenities.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct ClientId(pub id::Name);

/// Indicates a serverside connection's TLS status.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub enum ServerTls {
    Established {
        client_id: Option<ClientId>,
        negotiated_protocol: Option<NegotiatedProtocol>,
    },
    Passthru {
        sni: ServerId,
    },
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub enum NoServerTls {
    /// Identity is administratively disabled.
    Disabled,

    /// No TLS is wanted because the connection is a loopback connection which
    /// doesn't need or support TLS.
    Loopback,

    /// No TLS is wanted because the connection is a loopback connection which
    /// doesn't need or support TLS.
    PortSkipped,

    // No TLS Client Hello detected
    NoClientHello,

    // TLS Client Hello could not be detected within a .timeout
    DetectTimeout,
}

/// Indicates whether TLS was established on an accepted connection.
pub type ConditionalServerTls = Conditional<ServerTls, NoServerTls>;

pub type Meta<T> = (ConditionalServerTls, T);

pub type TransparentIo<T> = io::EitherIo<io::PrefixedIo<T>, TlsStream<io::PrefixedIo<T>>>;

#[derive(Clone, Debug)]
pub struct NewTransparentTls<L, N>(NewDetectService<DetectSni, NewHandshake<L, N>>);

impl<L, N> NewTransparentTls<L, N> {
    pub fn new(identity: Option<L>, inner: N, timeout: Duration) -> Self {
        Self(NewDetectService::new(
            timeout,
            DetectSni::default(),
            NewHandshake::new(identity, inner),
        ))
    }

    pub fn layer(
        identity: Option<L>,
        timeout: Duration,
    ) -> impl layer::Layer<N, Service = Self> + Clone
    where
        L: Clone,
    {
        layer::mk(move |inner| Self::new(identity.clone(), inner, timeout))
    }
}

impl<T, L, N> NewService<T> for NewTransparentTls<L, N>
where
    L: Clone + Param<crate::LocalId> + Param<Config>,
    N: NewService<(ConditionalServerTls, T)> + Clone,
{
    type Service = DetectService<T, DetectSni, NewHandshake<L, N>>;

    fn new_service(&mut self, target: T) -> Self::Service {
        self.0.new_service(target)
    }
}

// === impl ClientId ===

impl From<id::Name> for ClientId {
    fn from(n: id::Name) -> Self {
        Self(n)
    }
}

impl Into<id::Name> for ClientId {
    fn into(self) -> id::Name {
        self.0
    }
}

impl AsRef<id::Name> for ClientId {
    fn as_ref(&self) -> &id::Name {
        &self.0
    }
}

impl fmt::Display for ClientId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl FromStr for ClientId {
    type Err = id::InvalidName;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        id::Name::from_str(s).map(Self)
    }
}

// === impl NoClientId ===

impl fmt::Display for NoServerTls {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Disabled => write!(f, "disabled"),
            Self::Loopback => write!(f, "loopback"),
            Self::PortSkipped => write!(f, "port_skipped"),
            Self::NoClientHello => write!(f, "no_tls_from_remote"),
            Self::DetectTimeout => write!(f, "detect_timeout"),
        }
    }
}
