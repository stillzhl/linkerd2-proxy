use crate::{layer, Either, NewService};

#[derive(Clone, Debug, Default)]
pub struct NewOptional<N, O> {
    inner: N,
    opt: Option<O>,
}

// === impl NewOptional ===

impl<N, O: Clone> NewOptional<N, O> {
    pub fn new(inner: N, opt: Option<O>) -> Self {
        Self { inner, opt }
    }

    pub fn layer(opt: Option<O>) -> impl layer::Layer<N, Service = Self> {
        layer::mk(move |inner| Self::new(inner, opt.clone()))
    }
}

impl<T, N, O> NewService<T> for NewOptional<N, O>
where
    N: NewService<T> + Clone,
    O: NewService<T> + Clone,
{
    type Service = Either<N::Service, O::Service>;

    fn new_service(&mut self, t: T) -> Self::Service {
        match self.opt.as_mut() {
            None => Either::A(self.inner.new_service(t)),
            Some(o) => Either::B(o.new_service(t)),
        }
    }
}
