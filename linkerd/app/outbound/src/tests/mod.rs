use crate::{
    endpoint::{TcpConcrete, TcpLogical},
    Config,
};
use futures::prelude::*;
use ipnet::IpNet;
use linkerd2_app_core::{profiles, Error, IpMatch};
use linkerd2_app_test as test_support;
use std::{net::SocketAddr, str::FromStr};

mod tcp;
fn profile() -> profiles::Receiver {
    let (mut tx, rx) = tokio::sync::watch::channel(profiles::Profile::default());
    tokio::spawn(async move { tx.closed().await });
    rx
}

fn default_config(orig_dst: SocketAddr) -> Config {
    Config {
        allow_discovery: IpMatch::new(Some(IpNet::from_str("0.0.0.0/0").unwrap())),
        proxy: test_support::config::default_proxy(orig_dst),
    }
}
