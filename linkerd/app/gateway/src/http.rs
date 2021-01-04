use futures::{future, TryFutureExt};
use linkerd2_app_core::{
    dns,
    errors::HttpError,
    profiles,
    proxy::{http, identity},
    svc,
    transport::tls,
    Error, NameAddr,
};
use linkerd2_app_inbound::endpoint as inbound;
use linkerd2_app_outbound as outbound;
use std::task::{Context, Poll};
use tracing::debug;

#[derive(Clone, Debug)]
pub(crate) struct NewHttpGateway<O> {
    outbound: O,
    local_id: tls::PeerIdentity,
}

#[derive(Clone, Debug)]
pub(crate) enum HttpGateway<O> {
    NoAuthority,
    NoIdentity,
    BadDomain(dns::Name),
    Outbound {
        outbound: O,
        local_identity: identity::Name,
        host_header: http::header::HeaderValue,
        forwarded_header: http::header::HeaderValue,
    },
}

// === impl NewHttpGateway ===

impl<O> NewHttpGateway<O> {
    pub fn new(outbound: O, local_id: tls::PeerIdentity) -> Self {
        Self { outbound, local_id }
    }

    pub fn layer(local_id: tls::PeerIdentity) -> impl svc::Layer<O, Service = Self> + Clone {
        svc::layer::mk(move |inner| Self::new(inner, local_id.clone()))
    }
}

pub(crate) type Target = (Option<profiles::Receiver>, inbound::Target);

impl<O> svc::NewService<Target> for NewHttpGateway<O>
where
    O: svc::NewService<outbound::http::Logical>,
{
    type Service = HttpGateway<O::Service>;

    fn new_service(&mut self, (profile, target): Target) -> Self::Service {
        let inbound::Target {
            dst,
            tls_client_id,
            http_version,
            socket_addr: _,
        } = target;

        let (source_id, local_id) = match (tls_client_id, self.local_id.clone()) {
            (tls::Conditional::Some(src), tls::Conditional::Some(local)) => (src, local),
            _ => return HttpGateway::NoIdentity,
        };

        let dst = match profile.as_ref().and_then(|p| p.borrow().name.clone()) {
            Some(name) => NameAddr::from((name, dst.port())),
            None => match dst.name_addr() {
                Some(n) => return HttpGateway::BadDomain(n.name().clone()),
                None => return HttpGateway::NoAuthority,
            },
        };

        // Create an outbound target using the resolved name and an address
        // including the original port. We don't know the IP of the target, so
        // we use an unroutable one.
        let target = outbound::http::Logical {
            profile,
            protocol: http_version,
            orig_dst: ([0, 0, 0, 0], dst.port()).into(),
        };
        debug!(?target, "Creating outbound service");
        let svc = self.outbound.new_service(target);

        HttpGateway::new(svc, dst, source_id, local_id)
    }
}

// === impl HttpGateway ===

impl<O> HttpGateway<O> {
    pub fn new(
        outbound: O,
        dst: NameAddr,
        source_identity: identity::Name,
        local_identity: identity::Name,
    ) -> Self {
        let host = dst.as_http_authority().to_string();
        let fwd = format!(
            "by={};for={};host={};proto=https",
            local_identity, source_identity, host
        );
        HttpGateway::Outbound {
            outbound,
            local_identity,
            host_header: http::header::HeaderValue::from_str(&host)
                .expect("Host header value must be valid"),
            forwarded_header: http::header::HeaderValue::from_str(&fwd)
                .expect("Forwarded header value must be valid"),
        }
    }

    fn fwd_by(fwd: &str) -> Option<&str> {
        for kv in fwd.split(';') {
            let mut kv = kv.split('=');
            if let Some("by") = kv.next() {
                return kv.next();
            }
        }
        None
    }
}

type OutFut<F, E> = future::MapErr<F, fn(E) -> Error>;
type ErrFut = future::Ready<Result<http::Response<http::BoxBody>, Error>>;

impl<B, O> tower::Service<http::Request<B>> for HttpGateway<O>
where
    B: http::HttpBody + 'static,
    O: tower::Service<http::Request<B>, Response = http::Response<http::BoxBody>>,
    O::Error: Into<Error> + 'static,
    O::Future: Send + 'static,
{
    type Response = http::Response<http::BoxBody>;
    type Error = Error;
    type Future = future::Either<OutFut<O::Future, O::Error>, ErrFut>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        match self {
            Self::Outbound { outbound, .. } => outbound.poll_ready(cx).map_err(Into::into),
            _ => Poll::Ready(Ok(())),
        }
    }

    fn call(&mut self, mut request: http::Request<B>) -> Self::Future {
        match self {
            Self::Outbound {
                ref mut outbound,
                ref local_identity,
                ref host_header,
                ref forwarded_header,
            } => {
                // Check forwarded headers to see if this request has already
                // transited through this gateway.
                for forwarded in request
                    .headers()
                    .get_all(http::header::FORWARDED)
                    .into_iter()
                    .filter_map(|h| h.to_str().ok())
                {
                    if let Some(by) = Self::fwd_by(forwarded) {
                        tracing::info!(%forwarded);
                        if by == local_identity.as_ref() {
                            return future::Either::Right(future::err(
                                HttpError::gateway_loop().into(),
                            ));
                        }
                    }
                }

                // Add a forwarded header.
                request
                    .headers_mut()
                    .append(http::header::FORWARDED, forwarded_header.clone());

                // If we're forwarding HTTP/1 requests, the old `Host` header
                // was stripped on the peer's outbound proxy. But the request
                // should have an updated `Host` header now that it's being
                // routed in the cluster.
                if let ::http::Version::HTTP_11 | ::http::Version::HTTP_10 = request.version() {
                    request
                        .headers_mut()
                        .insert(http::header::HOST, host_header.clone());
                }

                tracing::debug!(
                    headers = ?request.headers(),
                    "Passing request to outbound"
                );
                future::Either::Left(outbound.call(request).map_err(Into::into))
            }
            Self::NoAuthority => {
                future::Either::Right(future::err(HttpError::not_found("no authority").into()))
            }
            Self::NoIdentity => future::Either::Right(future::err(
                HttpError::identity_required("no identity").into(),
            )),
            Self::BadDomain(..) => {
                future::Either::Right(future::err(HttpError::not_found("bad domain").into()))
            }
        }
    }
}
