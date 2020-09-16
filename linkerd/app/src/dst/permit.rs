use ipnet::{Contains, IpNet};
use linkerd2_app_core::{dns::Suffix, request_filter, Addr, DiscoveryRejected, Error};
use linkerd2_app_inbound as inbound;
use linkerd2_app_outbound as outbound;
use std::marker::PhantomData;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

pub struct PermitConfiguredDsts<E = DiscoveryRejected> {
    name_suffixes: Arc<Vec<Suffix>>,
    networks: Arc<Vec<IpNet>>,
    _error: PhantomData<fn(E)>,
}

// === impl PermitConfiguredDsts ===

impl PermitConfiguredDsts {
    pub fn new(
        name_suffixes: impl IntoIterator<Item = Suffix>,
        nets: impl IntoIterator<Item = IpNet>,
    ) -> Self {
        Self {
            name_suffixes: Arc::new(name_suffixes.into_iter().collect()),
            networks: Arc::new(nets.into_iter().collect()),
            _error: PhantomData,
        }
    }

    /// Configures the returned error type when the target is outside of the
    /// configured set of destinations.
    pub fn with_error<E>(self) -> PermitConfiguredDsts<E>
    where
        E: Into<Error> + From<Addr>,
    {
        PermitConfiguredDsts {
            name_suffixes: self.name_suffixes,
            networks: self.networks,
            _error: PhantomData,
        }
    }
}

impl<E> Clone for PermitConfiguredDsts<E> {
    fn clone(&self) -> Self {
        Self {
            name_suffixes: self.name_suffixes.clone(),
            networks: self.networks.clone(),
            _error: PhantomData,
        }
    }
}

impl<E> request_filter::RequestFilter<inbound::Target> for PermitConfiguredDsts<E>
where
    E: Into<Error> + From<SocketAddr>,
{
    type Error = E;

    fn filter(&self, t: inbound::Target) -> Result<inbound::Target, Self::Error> {
        self.filter(t.socket_addr).map(move |_| t)
    }
}

impl<E> request_filter::RequestFilter<outbound::HttpConcrete> for PermitConfiguredDsts<E>
where
    E: Into<Error>,
    Self: request_filter::RequestFilter<Addr, Error = E>,
{
    type Error = E;

    fn filter(&self, t: outbound::HttpConcrete) -> Result<outbound::HttpConcrete, Self::Error> {
        self.filter(t.dst.clone()).map(move |_| t)
    }
}

impl<E> request_filter::RequestFilter<outbound::HttpLogical> for PermitConfiguredDsts<E>
where
    E: Into<Error>,
    Self: request_filter::RequestFilter<Addr, Error = E>,
{
    type Error = E;

    fn filter(&self, t: outbound::HttpLogical) -> Result<outbound::HttpLogical, Self::Error> {
        self.filter(t.dst.clone()).map(move |_| t)
    }
}

impl<E> request_filter::RequestFilter<Addr> for PermitConfiguredDsts<E>
where
    E: Into<Error> + From<Addr>,
    Self: request_filter::RequestFilter<SocketAddr, Error = E>,
{
    type Error = E;

    fn filter(&self, addr: Addr) -> Result<Addr, Self::Error> {
        let permitted = match addr {
            Addr::Socket(sa) => return self.filter(sa).map(Into::into),
            Addr::Name(ref name) => self
                .name_suffixes
                .iter()
                .any(|suffix| suffix.contains(name.name())),
        };

        if permitted {
            Ok(addr)
        } else {
            Err(E::from(addr.clone()))
        }
    }
}

impl<E> request_filter::RequestFilter<SocketAddr> for PermitConfiguredDsts<E>
where
    E: Into<Error> + From<SocketAddr>,
{
    type Error = E;

    fn filter(&self, sa: SocketAddr) -> Result<SocketAddr, Self::Error> {
        let permitted = self.networks.iter().any(|net| match (net, sa.ip()) {
            (IpNet::V4(net), IpAddr::V4(addr)) => net.contains(&addr),
            (IpNet::V6(net), IpAddr::V6(addr)) => net.contains(&addr),
            _ => false,
        });

        if permitted {
            Ok(sa)
        } else {
            Err(E::from(sa.clone()))
        }
    }
}
