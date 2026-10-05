//! Everything that speaks DSM: the wire, the login session, and the typed
//! responses.

pub mod api;
pub mod endpoint;
pub mod error;
#[cfg(test)]
pub mod fake;
pub mod model;
pub mod session;
pub mod tls;
pub mod transport;
