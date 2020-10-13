pub use linkerd2_app_core::config::*;
use linkerd2_app_core::{exp_backoff, proxy::http::h2, transport::listen};
use std::{net::SocketAddr, time::Duration};

const LOCALHOST: [u8; 4] = [127, 0, 0, 1];

pub fn default_proxy(orig_dst: SocketAddr) -> ProxyConfig {
    ProxyConfig {
        server: default_server(orig_dst),
        connect: default_connect(),
        buffer_capacity: 10_000,
        cache_max_idle_age: Duration::from_secs(60),
        disable_protocol_detection_for_ports: Default::default(),
        dispatch_timeout: Duration::from_secs(3),
        max_in_flight_requests: 10_000,
        detect_protocol_timeout: Duration::from_secs(3),
    }
}

pub fn default_server(orig_dst: SocketAddr) -> ServerConfig<listen::DefaultOrigDstAddr> {
    ServerConfig {
        bind: listen::Bind::new(SocketAddr::new(LOCALHOST.into(), 0), None)
            .with_orig_dst_addr(orig_dst.into()),
        h2_settings: h2::Settings::default(),
    }
}

pub fn default_connect() -> ConnectConfig {
    ConnectConfig {
        keepalive: None,
        timeout: Duration::from_secs(1),
        backoff: exp_backoff::ExponentialBackoff::new(
            Duration::from_millis(100),
            Duration::from_millis(500),
            0.1,
        )
        .unwrap(),
        h2_settings: h2::Settings::default(),
    }
}
