mod client_hello;
mod handshake;

use self::handshake::NewHandshake;
use crate::{NegotiatedProtocol, ServerId};
use bytes::BytesMut;
use linkerd_conditional::Conditional;
use linkerd_detect::NewDetectService;
use linkerd_identity as id;
use linkerd_io::{self as io, AsyncReadExt, EitherIo, PrefixedIo};
use linkerd_stack::layer;
use std::{fmt, str::FromStr, sync::Arc, time::Duration};
pub use tokio_rustls::server::TlsStream;
use tracing::{debug, trace, warn};

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
}

/// Indicates whether TLS was established on an accepted connection.
pub type ConditionalServerTls = Conditional<ServerTls, NoServerTls>;

pub type Meta<T> = (ConditionalServerTls, T);

pub type Io<T> = EitherIo<T, TlsStream<T>>;

pub type Connection<T, I> = (Meta<T>, Io<I>);

#[derive(Clone, Debug)]
pub struct NewTransparentTls<L, A> {
    identity: Option<L>,
    inner: A,
    timeout: Duration,
}

#[derive(Clone, Debug)]
pub struct DetectTimeout(());

#[derive(Clone, Debug)]
pub struct DetectSni(());

type TransparentTls<L, N> = NewDetectService<DetectSni, NewHandshake<L, N>>;

pub fn new<L, N>(identity: Option<L>, inner: N, timeout: Duration) -> TransparentTls<L, N> {
    NewDetectService::new(timeout, DetectSni(()), NewHandshake::new(identity, inner))
}

pub fn layer<L, N>(
    identity: Option<L>,
    timeout: Duration,
) -> impl layer::Layer<N, Service = TransparentTls<L, N>> + Clone
where
    L: Clone,
    N: Clone,
{
    layer::mk(move |inner| new(identity.clone(), inner, timeout))
}

async fn detect<I>(mut io: I) -> io::Result<(Option<ServerId>, io::PrefixedIo<I>)>
where
    I: io::Peek + io::AsyncRead + Send + Sync + Unpin,
{
    // The initial peek buffer is statically allocated on the stack and is fairly small; but it is
    // large enough to hold the ~300B ClientHello sent by proxies.
    const PEEK_CAPACITY: usize = 512;

    // A larger fallback buffer is allocated onto the heap if the initial peek buffer is
    // insufficient. This is the same value used in HTTP detection.
    const BUFFER_CAPACITY: usize = 8192;

    // First, try to use MSG_PEEK to read the SNI from the TLS ClientHello.
    // Because peeked data does not need to be retained, we use a static
    // buffer to prevent needless heap allocation.
    //
    // Anecdotally, the ClientHello sent by Linkerd proxies is <300B. So a
    // ~500B byte buffer is more than enough.
    let mut buf = [0u8; PEEK_CAPACITY];
    let sz = io.peek(&mut buf).await?;
    debug!(sz, "Peeked bytes from TCP stream");
    match client_hello::parse_sni(&buf) {
        Ok(sni) => return Ok((sni, PrefixedIo::from(io))),
        Err(client_hello::Incomplete) => {}
    }

    // Peeking didn't return enough data, so instead we'll allocate more
    // capacity and try reading data from the socket.
    debug!("Attempting to buffer TLS ClientHello after incomplete peek");
    let mut buf = BytesMut::with_capacity(BUFFER_CAPACITY);
    debug!(buf.capacity = %buf.capacity(), "Reading bytes from TCP stream");
    while io.read_buf(&mut buf).await? != 0 {
        debug!(buf.len = %buf.len(), "Read bytes from TCP stream");
        match client_hello::parse_sni(buf.as_ref()) {
            Ok(sni) => return Ok((sni, io.into())),

            Err(client_hello::Incomplete) => {
                if buf.capacity() == 0 {
                    // If we can't buffer an entire TLS ClientHello, it
                    // almost definitely wasn't initiated by another proxy,
                    // at least.
                    warn!("Buffer insufficient for TLS ClientHello");
                    break;
                }
                // Continue if there is still buffer capacity.
            }
        }
    }

    trace!("Could not read TLS ClientHello via buffering");
    let io = PrefixedIo::new(buf.freeze(), io);
    Ok((None, io))
}

impl fmt::Display for DetectTimeout {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "TLS detection timeout")
    }
}

impl std::error::Error for DetectTimeout {}

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
        }
    }
}
