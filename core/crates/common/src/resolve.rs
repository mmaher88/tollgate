//! Looking up host names for upstream connections, implemented outside the proxy so that
//! `mitm` does not depend on `dns`.

use std::fmt;
use std::future::Future;
use std::net::IpAddr;
use std::pin::Pin;

/// The addresses of one host name, in the order to try them. Empty when the lookup failed
/// or found nothing; the caller then falls back to the system resolver.
pub type LookupFuture<'a> = Pin<Box<dyn Future<Output = Vec<IpAddr>> + Send + 'a>>;

/// Resolves host names for the proxy's upstream connections.
pub trait Resolve: Send + Sync + fmt::Debug {
    fn lookup<'a>(&'a self, host: &'a str) -> LookupFuture<'a>;
}
