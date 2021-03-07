use crate::{classify, metrics, profiles};
use linkerd_http_classify::CanClassify;
use linkerd_proxy_http::timeout;
use std::time::Duration;

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Route {
    pub addr: profiles::LogicalAddr,
    pub route: profiles::http::Route,
    pub direction: super::metrics::Direction,
}

// === impl Route ===

impl Route {
    pub fn outbound(route: profiles::http::Route, addr: profiles::LogicalAddr) -> Self {
        Self {
            route,
            addr,
            direction: metrics::Direction::Out,
        }
    }

    pub fn inbound(route: profiles::http::Route, addr: profiles::LogicalAddr) -> Self {
        Self {
            route,
            addr,
            direction: metrics::Direction::In,
        }
    }
}

impl CanClassify for Route {
    type Classify = classify::Request;

    fn classify(&self) -> classify::Request {
        self.route.response_classes().clone().into()
    }
}

impl timeout::HasTimeout for Route {
    fn timeout(&self) -> Option<Duration> {
        self.route.timeout()
    }
}
