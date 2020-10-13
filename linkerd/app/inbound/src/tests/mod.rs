use super::Config;
use linkerd2_app_test as test_support;
use std::{net::SocketAddr, time::Duration};
mod tcp;

fn default_config(orig_dst: SocketAddr) -> Config {
    Config {
        allow_discovery: Default::default(),
        require_identity_for_inbound_ports: std::iter::empty().into(),
        profile_idle_timeout: Duration::from_secs(5),
        proxy: test_support::config::default_proxy(orig_dst),
    }
}
