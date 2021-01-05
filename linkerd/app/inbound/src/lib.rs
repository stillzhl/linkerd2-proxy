//! Configures and runs the inbound proxy.
//!
//! The inbound proxy is responsible for terminating traffic from other network
//! endpoints inbound to the local application.

#![deny(warnings, rust_2018_idioms)]

use self::allow_discovery::AllowProfile;
pub use self::endpoint::{
    HttpEndpoint, ProfileTarget, RequestTarget, Target, TcpAccept, TcpEndpoint,
};
use self::prevent_loop::PreventLoop;
use self::require_identity_for_ports::RequireIdentityForPorts;
use linkerd2_app_core::{
    classify,
    config::{ConnectConfig, ProxyConfig},
    drain, dst, errors, metrics, opaque_transport,
    opencensus::proto::trace::v1 as oc,
    profiles,
    proxy::{
        http::{self, orig_proto, strip_header},
        identity, tap, tcp,
    },
    reconnect,
    spans::SpanConverter,
    svc,
    transport::{self, io, listen, tls, NewDetectService},
    Error, NameAddr, NameMatch, TraceContext, DST_OVERRIDE_HEADER,
};
use metrics::Direction;
use std::{collections::HashMap, fmt::Debug, net::SocketAddr, time::Duration};
use tokio::sync::mpsc;
use tracing::debug_span;

mod allow_discovery;
pub mod endpoint;
mod prevent_loop;
mod require_identity_for_ports;

#[derive(Clone, Debug)]
pub struct Config {
    pub allow_discovery: NameMatch,
    pub proxy: ProxyConfig,
    pub require_identity_for_inbound_ports: RequireIdentityForPorts,
    pub disable_protocol_detection_for_ports: SkipByPort,
    pub profile_idle_timeout: Duration,
}

#[derive(Clone)]
pub struct Inbound<C, P> {
    config: Config,
    prevent_loop: PreventLoop,
    local_identity: tls::Conditional<identity::Local>,
    connect: svc::Stack<C>,
    profiles: P,
    tap: tap::Registry,
    metrics: metrics::Proxy,
    traces: Option<mpsc::Sender<oc::Span>>,
    drain: drain::Watch,
}

#[derive(Clone, Debug)]
pub struct SkipByPort(std::sync::Arc<indexmap::IndexSet<u16>>);

#[derive(Default)]
pub struct NonOpaqueRefused(());

// === impl Config ===

impl Config {
    #[allow(clippy::clippy::too_many_arguments)]
    pub fn build<P>(
        self,
        prevent_loop: impl Into<PreventLoop>,
        local_identity: tls::Conditional<identity::Local>,
        profiles: P,
        tap: tap::Registry,
        metrics: metrics::Proxy,
        traces: Option<mpsc::Sender<oc::Span>>,
        drain: drain::Watch,
    ) -> Inbound<
        impl svc::Service<
                TcpEndpoint,
                Response = impl io::AsyncRead + io::AsyncWrite + Send,
                Error = Error,
                Future = impl Send,
            > + Clone,
        P,
    > {
        let connect = tcp_connect_loopback(&self.proxy.connect);
        Inbound {
            config: self,
            prevent_loop: prevent_loop.into(),
            local_identity,
            connect,
            profiles,
            tap,
            metrics,
            traces,
            drain,
        }
    }
}

pub fn tcp_connect_loopback(
    config: &ConnectConfig,
) -> svc::Stack<
    impl svc::Service<
            TcpEndpoint,
            Response = impl io::AsyncRead + io::AsyncWrite + Send,
            Error = Error,
            Future = impl Send,
        > + Clone,
> {
    // Establishes connections to remote peers (for both TCP
    // forwarding and HTTP proxying).
    svc::stack(transport::ConnectTcp::new(config.keepalive))
        .push_map_target(|t: TcpEndpoint| ([127, 0, 0, 1], t.port))
        // Limits the time we wait for a connection to be established.
        .push_timeout(config.timeout)
}

// === impl Inbound ===

impl<C, P> Inbound<C, P>
where
    C: svc::Service<TcpEndpoint> + Clone + Send + Sync + Unpin + 'static,
    C::Response: io::AsyncRead + io::AsyncWrite + Send + Unpin + 'static,
    C::Error: Into<Error>,
    C::Future: Send + Unpin,
    P: profiles::GetProfile<NameAddr> + Clone + Send + Sync + 'static,
    P::Error: Send,
    P::Future: Send,
{
    pub fn server<I, G, GSvc>(
        self,
        http_gateway: svc::Stack<G>,
    ) -> svc::Stack<
        impl svc::NewService<
                listen::Addrs,
                Service = impl svc::Service<I, Response = (), Error = Error, Future = impl Send>,
            > + Clone,
    >
    where
        I: tls::accept::Detectable
            + io::AsyncRead
            + io::AsyncWrite
            + io::PeerAddr
            + Debug
            + Send
            + Unpin
            + 'static,
        G: svc::NewService<Target, Service = GSvc> + Clone + Send + Sync + Unpin + 'static,
        GSvc: svc::Service<http::Request<http::BoxBody>, Response = http::Response<http::BoxBody>>
            + Send
            + Unpin
            + 'static,
        GSvc::Error: Into<Error>,
        GSvc::Future: Send,
    {
        // Handles traffic that directly targets the inbound port.
        let direct = {
            let http = http_gateway
                .push_on_response(
                    svc::layers()
                        .push(svc::FailFast::layer(
                            "HTTP Gateway",
                            self.config.proxy.dispatch_timeout,
                        ))
                        .push_spawn_buffer(self.config.proxy.buffer_capacity),
                )
                .push_cache(self.config.proxy.cache_max_idle_age)
                .push(svc::NewRouter::layer(RequestTarget::from));

            // If there is a transport header, use its port to redirect the
            // connection to a different localhost port.
            //
            // TODO support TCP gateway when the connection header provides an
            // alternate destination.
            self.tcp_forward()
                .check_new_service::<TcpEndpoint, _>()
                .push_map_target(|(h, _)| TcpEndpoint::from(h))
                .push(svc::NewUnwrapOr::layer(
                    // If there's no transport header on the connection, handle
                    // it via the HTTP gateway.
                    self.http_server(http_gateway)
                        .push(svc::NewUnwrapOr::layer(
                            // If there's neither a transport header nor a HTTP
                            // preamble, fail the connection.
                            svc::Fail::<_, NonOpaqueRefused>::default(),
                        ))
                        .push(NewDetectService::layer(
                            self.config.proxy.detect_protocol_timeout,
                            http::DetectHttp::default(),
                        ))
                        .check_new_service::<TcpAccept, _>()
                        .into_inner(),
                ))
                .push(NewDetectService::layer(
                    self.config.proxy.detect_protocol_timeout,
                    opaque_transport::DetectHeader::default(),
                ))
                .check_new_service::<TcpAccept, _>()
                .into_inner()
        };

        // Route HTTP traffic through the inbound profile router to a local
        // endpoint.
        self.http_server(self.http_router())
            .check_new_service::<(http::Version, TcpAccept), _>()
            .push_cache(self.config.proxy.cache_max_idle_age)
            .push(svc::NewUnwrapOr::layer(
                // If there's no HTTP preamble, forward the connection to a localhost port.
                self.tcp_forward()
                    .push_map_target(TcpEndpoint::from)
                    .check_new_service::<TcpAccept, _>()
                    .into_inner(),
            ))
            .push(NewDetectService::layer(
                self.config.proxy.detect_protocol_timeout,
                http::DetectHttp::default(),
            ))
            .check_new_service::<TcpAccept, _>()
            .push_switch(self.prevent_loop, direct)
            .push_request_filter(self.config.require_identity_for_inbound_ports.clone())
            .push(self.metrics.transport.layer_accept())
            .check_new_service::<TcpAccept, _>()
            .push_map_target(TcpAccept::from)
            .push(tls::NewDetectTls::layer(
                self.local_identity.clone(),
                self.config.proxy.detect_protocol_timeout,
            ))
            .push_switch(
                self.config.disable_protocol_detection_for_ports.clone(),
                self.tcp_forward()
                    .push_map_target(TcpEndpoint::from)
                    .push(self.metrics.transport.layer_accept())
                    .push_map_target(TcpAccept::from)
                    .into_inner(),
            )
    }

    // Forwards TCP connections to localhost.
    pub fn tcp_forward<I: io::AsyncRead + io::AsyncWrite + Debug + Send + Unpin + 'static>(
        &self,
    ) -> svc::Stack<
        impl svc::NewService<
                TcpEndpoint,
                Service = impl svc::Service<I, Response = (), Error = Error, Future = impl Send>,
            > + Clone,
    > {
        svc::stack(self.connect.clone())
            .push(self.metrics.transport.layer_connect())
            .push_make_thunk()
            .push_on_response(
                svc::layers()
                    .push(tcp::Forward::layer())
                    .push(drain::Retain::layer(self.drain.clone())),
            )
            .instrument(|_: &_| debug_span!("tcp"))
    }

    // Routes HTTP requests to localhost.
    fn http_router(
        &self,
    ) -> svc::Stack<
        impl svc::NewService<
                TcpAccept,
                Service = impl svc::Service<
                    http::Request<http::BoxBody>,
                    Response = http::Response<http::BoxBody>,
                    Error = Error,
                    Future = impl Send,
                > + Clone,
            > + Clone,
    > {
        // Creates HTTP clients for each inbound port & HTTP settings.
        let endpoint = svc::stack(self.connect.clone())
            .push(self.metrics.transport.layer_connect())
            .push_map_target(TcpEndpoint::from)
            .push(http::client::layer(
                self.config.proxy.connect.h1_settings,
                self.config.proxy.connect.h2_settings,
            ))
            .push(reconnect::layer({
                let backoff = self.config.proxy.connect.backoff;
                move |_| Ok(backoff.stream())
            }))
            .check_new_service::<HttpEndpoint, http::Request<_>>();

        let target = endpoint
            .push_map_target(HttpEndpoint::from)
            // Registers the stack to be tapped.
            .push(tap::NewTapHttp::layer(self.tap.clone()))
            // Records metrics for each `Target`.
            .push(
                self.metrics
                    .http_endpoint
                    .to_layer::<classify::Response, _>(),
            )
            .push_on_response(TraceContext::layer(
                self.traces
                    .clone()
                    .map(|t| SpanConverter::client(t, trace_labels())),
            ))
            .push_on_response(http::BoxResponse::layer())
            .check_new_service::<Target, http::Request<_>>();

        // Attempts to discover a service profile for each logical target (as
        // informed by the request's headers). The stack is cached until a
        // request has not been received for `cache_max_idle_age`.
        let profile = target
            .clone()
            .check_new_service::<Target, http::Request<http::BoxBody>>()
            .push_on_response(http::BoxRequest::layer())
            // The target stack doesn't use the profile resolution, so drop it.
            .push_map_target(endpoint::Target::from)
            .push(profiles::http::route_request::layer(
                svc::proxies()
                    // Sets the route as a request extension so that it can be used
                    // by tap.
                    .push_http_insert_target()
                    // Records per-route metrics.
                    .push(self.metrics.http_route.to_layer::<classify::Response, _>())
                    // Sets the per-route response classifier as a request
                    // extension.
                    .push(classify::NewClassify::layer())
                    .check_new_clone::<dst::Route>()
                    .push_map_target(endpoint::route)
                    .into_inner(),
            ))
            .push_map_target(endpoint::Logical::from)
            .push(profiles::discover::layer(
                self.profiles.clone(),
                AllowProfile(self.config.allow_discovery.clone()),
            ))
            .push_on_response(http::BoxResponse::layer())
            .instrument(|_: &Target| debug_span!("profile"))
            // Skip the profile stack if it takes too long to become ready.
            .push_when_unready(target.clone(), self.config.profile_idle_timeout)
            .check_new_service::<Target, http::Request<http::BoxBody>>();

        // If the traffic is targeted at the inbound port, send it through
        // the loopback service (i.e. as a gateway).
        svc::stack(profile)
            .check_new_service::<Target, http::Request<http::BoxBody>>()
            .push_on_response(
                svc::layers()
                    .push(svc::FailFast::layer(
                        "Logical",
                        self.config.proxy.dispatch_timeout,
                    ))
                    .push_spawn_buffer(self.config.proxy.buffer_capacity)
                    .push(self.metrics.stack.layer(stack_labels("http", "logical"))),
            )
            .push_cache(self.config.proxy.cache_max_idle_age)
            .push_on_response(
                svc::layers()
                    .push(http::Retain::layer())
                    .push(http::BoxResponse::layer()),
            )
            // Boxing is necessary purely to limit the link-time overhead of
            // having enormous types.
            .push(svc::BoxNewService::layer())
            .check_new_service::<Target, http::Request<http::BoxBody>>()
            // Removes the override header after it has been used to
            // determine a reuquest target.
            .push_on_response(strip_header::request::layer(DST_OVERRIDE_HEADER))
            // Routes each request to a target, obtains a service for that
            // target, and dispatches the request.
            .instrument_from_target()
            .push(svc::NewRouter::layer(RequestTarget::from))
    }

    // Binds an inner HTTP stack to a connection-level HTTP server.
    fn http_server<T, I, H, HSvc>(
        &self,
        http: svc::Stack<H>,
    ) -> svc::Stack<
        impl svc::NewService<
                (http::Version, T),
                Service = impl svc::Service<I, Response = (), Error = Error, Future = impl Send> + Clone,
            > + Clone,
    >
    where
        T: Clone + Send + Sync + Unpin + 'static,
        for<'t> &'t T: Into<SocketAddr>,
        I: io::AsyncRead + io::AsyncWrite + io::PeerAddr + Send + Unpin + 'static,
        H: svc::NewService<T, Service = HSvc> + Clone + Send + 'static,
        HSvc: svc::Service<http::Request<http::BoxBody>, Response = http::Response<http::BoxBody>>
            + Clone
            + Send
            + Unpin
            + 'static,
        HSvc::Error: Into<Error>,
        HSvc::Future: Send,
    {
        http.push_http_insert_target() // Used by tap.
            .push_on_response(
                svc::layers()
                    // Downgrades the protocol if upgraded by an outbound proxy.
                    .push(orig_proto::Downgrade::layer())
                    // Limits the number of in-flight requests.
                    .push(svc::ConcurrencyLimit::layer(
                        self.config.proxy.max_in_flight_requests,
                    ))
                    // Eagerly fail requests when the proxy is out of capacity for a
                    // dispatch_timeout.
                    .push(svc::FailFast::layer(
                        "HTTP Server",
                        self.config.proxy.dispatch_timeout,
                    ))
                    .push(self.metrics.http_errors.clone())
                    // Synthesizes responses for proxy errors.
                    .push(errors::layer())
                    .push(TraceContext::layer(
                        self.traces
                            .clone()
                            .map(|t| SpanConverter::server(t, trace_labels())),
                    ))
                    .push(self.metrics.stack.layer(stack_labels("http", "server")))
                    .push(http::BoxResponse::layer())
                    .push(http::BoxRequest::layer()),
            )
            .push(http::NewNormalizeUri::layer())
            .push_map_target(|(_, t): (_, T)| t)
            .instrument(|(v, _): &(http::Version, _)| debug_span!("http", %v))
            .push(http::NewServeHttp::layer(
                self.config.proxy.server.h2_settings,
                self.drain.clone(),
            ))
            .check_new_service::<(http::Version, T), I>()
    }

    /// Replaces the connection implementation.
    pub fn with_connect<C2>(self, connect: C2) -> Inbound<C2, P> {
        Inbound {
            connect: svc::stack(connect),
            config: self.config,
            prevent_loop: self.prevent_loop,
            local_identity: self.local_identity,
            profiles: self.profiles,
            tap: self.tap,
            metrics: self.metrics,
            traces: self.traces,
            drain: self.drain,
        }
    }
}

pub fn trace_labels() -> HashMap<String, String> {
    let mut l = HashMap::new();
    l.insert("direction".to_string(), "inbound".to_string());
    l
}

fn stack_labels(proto: &'static str, name: &'static str) -> metrics::StackLabels {
    metrics::StackLabels::inbound(proto, name)
}

// === impl SkipByPort ===

impl From<indexmap::IndexSet<u16>> for SkipByPort {
    fn from(ports: indexmap::IndexSet<u16>) -> Self {
        SkipByPort(ports.into())
    }
}

impl svc::stack::Switch<listen::Addrs> for SkipByPort {
    fn use_primary(&self, t: &listen::Addrs) -> bool {
        !self.0.contains(&t.target_addr().port())
    }
}

// === impl NonOpaqueRefused ===

impl Into<Error> for NonOpaqueRefused {
    fn into(self) -> Error {
        Error::from(io::Error::new(
            io::ErrorKind::ConnectionRefused,
            "Non-opaque-transport connection refused",
        ))
    }
}
