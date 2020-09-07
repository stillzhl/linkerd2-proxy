use crate::http::uri::Authority;
use indexmap::IndexMap;
use linkerd2_app_core::{
    dst, metric_labels,
    metric_labels::{prefix_labels, EndpointLabels},
    profiles,
    proxy::{
        api_resolve::{Metadata, ProtocolHint},
        http::override_authority::CanOverrideAuthority,
        http::{self, identity_from_header},
        identity,
        resolve::map_endpoint::MapEndpoint,
        tap,
    },
    router,
    transport::{listen, tls},
    Addr, Conditional, L5D_REQUIRE_ID,
};
use std::net::SocketAddr;
use std::sync::Arc;

#[derive(Copy, Clone, Debug)]
pub struct FromMetadata;

#[derive(Clone, Debug)]
pub struct LogicalPerRequest(listen::Addrs);

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Logical {
    pub dst: Addr,
    pub orig_target: SocketAddr,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Concrete {
    pub dst: Addr,
    pub logical: Logical,
}

#[derive(Clone, Debug)]
pub struct Profile {
    pub rx: profiles::Receiver,
    pub logical: Logical,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HttpEndpoint {
    pub addr: SocketAddr,
    pub identity: tls::PeerIdentity,
    pub metadata: Metadata,
    pub concrete: Concrete,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TcpEndpoint {
    pub addr: SocketAddr,
    pub identity: tls::PeerIdentity,
}

impl From<(Addr, Profile)> for Concrete {
    fn from((dst, Profile { logical, .. }): (Addr, Profile)) -> Self {
        Self { dst, logical }
    }
}

// === impl Logical ===

impl std::fmt::Display for Logical {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.dst.fmt(f)
    }
}

impl http::canonicalize::Target for Logical {
    fn addr(&self) -> &Addr {
        &self.dst
    }

    fn addr_mut(&mut self) -> &mut Addr {
        &mut self.dst
    }
}

impl<'t> From<&'t Logical> for http::header::HeaderValue {
    fn from(target: &'t Logical) -> Self {
        http::header::HeaderValue::from_str(&target.dst.to_string())
            .expect("addr must be a valid header")
    }
}

impl AsRef<Addr> for Logical {
    fn as_ref(&self) -> &Addr {
        &self.dst
    }
}

// === impl HttpEndpoint ===

// impl HttpEndpoint {
//     pub fn can_use_orig_proto(&self) -> bool {
//         if let ProtocolHint::Unknown = self.metadata.protocol_hint() {
//             return false;
//         }
//         // Look at the original settings, ignoring any authority overrides.
//         match self.settings {
//             http::Settings::Http2 => false,
//             http::Settings::Http1 {
//                 wants_h1_upgrade, ..
//             } => !wants_h1_upgrade,
//         }
//     }
// }

impl std::fmt::Display for HttpEndpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.addr.fmt(f)
    }
}

impl std::hash::Hash for HttpEndpoint {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.addr.hash(state);
        self.identity.hash(state);
        self.settings.hash(state);
        // Ignore metadata.
    }
}

impl tls::HasPeerIdentity for HttpEndpoint {
    fn peer_identity(&self) -> tls::PeerIdentity {
        self.identity.clone()
    }
}

impl Into<SocketAddr> for HttpEndpoint {
    fn into(self) -> SocketAddr {
        self.addr
    }
}

// impl AsRef<http::Settings> for HttpEndpoint {
//     fn as_ref(&self) -> &http::Settings {
//         &self.settings
//     }
// }

impl tap::Inspect for HttpEndpoint {
    fn src_addr<B>(&self, req: &http::Request<B>) -> Option<SocketAddr> {
        req.extensions().get::<listen::Addrs>().map(|s| s.peer())
    }

    fn src_tls<'a, B>(
        &self,
        _: &'a http::Request<B>,
    ) -> Conditional<&'a identity::Name, tls::ReasonForNoPeerName> {
        Conditional::None(tls::ReasonForNoPeerName::Loopback.into())
    }

    fn dst_addr<B>(&self, _: &http::Request<B>) -> Option<SocketAddr> {
        Some(self.addr)
    }

    fn dst_labels<B>(&self, _: &http::Request<B>) -> Option<&IndexMap<String, String>> {
        Some(self.metadata.labels())
    }

    fn dst_tls<B>(
        &self,
        _: &http::Request<B>,
    ) -> Conditional<&identity::Name, tls::ReasonForNoPeerName> {
        self.identity.as_ref()
    }

    fn route_labels<B>(&self, req: &http::Request<B>) -> Option<Arc<IndexMap<String, String>>> {
        req.extensions()
            .get::<dst::Route>()
            .map(|r| r.route.labels().clone())
    }

    fn is_outbound<B>(&self, _: &http::Request<B>) -> bool {
        true
    }
}

impl MapEndpoint<Concrete, Metadata> for FromMetadata {
    type Out = HttpEndpoint;

    fn map_endpoint(&self, concrete: &Concrete, addr: SocketAddr, metadata: Metadata) -> Self::Out {
        tracing::trace!(service = ?concrete, %addr, ?metadata, "Resolved endpoint");
        let identity = metadata
            .identity()
            .cloned()
            .map(Conditional::Some)
            .unwrap_or_else(|| {
                Conditional::None(tls::ReasonForNoPeerName::NotProvidedByServiceDiscovery.into())
            });

        HttpEndpoint {
            addr,
            identity,
            metadata,
            concrete: concrete.clone(),
        }
    }
}

impl CanOverrideAuthority for HttpEndpoint {
    fn override_authority(&self) -> Option<Authority> {
        self.metadata.authority_override().cloned()
    }
}

impl Into<EndpointLabels> for HttpEndpoint {
    fn into(self) -> EndpointLabels {
        use linkerd2_app_core::metric_labels::{Direction, TlsId};
        EndpointLabels {
            authority: Some(self.concrete.logical.dst.to_http_authority()),
            direction: Direction::Out,
            tls_id: self.identity.as_ref().map(|id| TlsId::ServerId(id.clone())),
            labels: prefix_labels("dst", self.metadata.labels().into_iter()),
        }
    }
}

// === impl TcpEndpoint ===

impl From<listen::Addrs> for TcpEndpoint {
    fn from(addrs: listen::Addrs) -> Self {
        Self {
            addr: addrs.target_addr(),
            identity: Conditional::None(tls::ReasonForNoPeerName::NotHttp.into()),
        }
    }
}

impl Into<SocketAddr> for TcpEndpoint {
    fn into(self) -> SocketAddr {
        self.addr
    }
}

impl tls::HasPeerIdentity for TcpEndpoint {
    fn peer_identity(&self) -> tls::PeerIdentity {
        self.identity.clone()
    }
}

impl Into<EndpointLabels> for TcpEndpoint {
    fn into(self) -> EndpointLabels {
        use linkerd2_app_core::metric_labels::{Direction, TlsId};
        EndpointLabels {
            direction: Direction::Out,
            tls_id: self.identity.as_ref().map(|id| TlsId::ServerId(id.clone())),
            authority: None,
            labels: None,
        }
    }
}

// === impl LogicalPerRequest ===

impl From<listen::Addrs> for LogicalPerRequest {
    fn from(t: listen::Addrs) -> Self {
        LogicalPerRequest(t)
    }
}

impl<B> router::Recognize<http::Request<B>> for LogicalPerRequest {
    type Key = Logical;

    fn recognize(&self, req: &http::Request<B>) -> Self::Key {
        use linkerd2_app_core::{
            http_request_authority_addr, http_request_host_addr, http_request_l5d_override_dst_addr,
        };

        let dst = http_request_l5d_override_dst_addr(req)
            .map(|addr| {
                tracing::debug!(%addr, "using dst-override");
                addr
            })
            .or_else(|_| {
                http_request_authority_addr(req).map(|addr| {
                    tracing::debug!(%addr, "using authority");
                    addr
                })
            })
            .or_else(|_| {
                http_request_host_addr(req).map(|addr| {
                    tracing::debug!(%addr, "using host");
                    addr
                })
            })
            .unwrap_or_else(|_| {
                let addr = self.0.target_addr();
                tracing::debug!(%addr, "using socket target");
                addr.into()
            });

        tracing::debug!(headers = ?req.headers(), uri = %req.uri(), dst = %dst, "Logical target");
        Logical {
            dst,
            orig_target: self.0.target_addr(),
        }
    }
}

pub fn route((route, profile): (profiles::http::Route, Profile)) -> dst::Route {
    dst::Route {
        route,
        target: profile.logical.dst,
        direction: metric_labels::Direction::Out,
    }
}

// === impl Profile ===

impl From<(profiles::Receiver, Logical)> for Profile {
    fn from((rx, logical): (profiles::Receiver, Logical)) -> Self {
        Self { rx, logical }
    }
}

impl AsRef<Addr> for Profile {
    fn as_ref(&self) -> &Addr {
        &self.logical.dst
    }
}

impl AsRef<profiles::Receiver> for Profile {
    fn as_ref(&self) -> &profiles::Receiver {
        &self.rx
    }
}

impl From<Profile> for Logical {
    fn from(Profile { logical, .. }: Profile) -> Self {
        logical
    }
}
