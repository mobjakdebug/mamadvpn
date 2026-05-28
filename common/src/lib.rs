//! # MamadVPN Common
//!
//! Foundational types, packet definitions, TLS templates, and configuration
//! shared across all MamadVPN crates.
//!
//! ## Design Philosophy
//!
//! - **Zero-copy** where feasible — packet parsing uses `bytes::Bytes` for
//!   reference-counted, sliceable buffers.
//! - **Strongly typed** — TCP flags, connection states, and bypass methods are
//!   enums, never raw integers.
//! - **Python-behavior compatible** — the TLS ClientHello builder and
//!   connection-id scheme exactly match the original Python prototype.

pub mod config;
pub mod connection_id;
pub mod error;
pub mod packet;
pub mod tls;

pub use config::{AppConfig, ConnectionMode, EngineConfig, DynamicConfig, BypassMethod, DataMode, TlsConnectorBackend, TlsFingerprintKind, TrojanTransport};
pub use connection_id::*;
pub use error::*;
pub use packet::*;
pub use tls::*;

pub use bytes;

use std::net::Ipv4Addr;
use std::net::UdpSocket;

/// Determine the default IPv4 interface address by connecting a UDP socket
/// to a known external address.
///
/// This exactly replicates Python's `get_default_interface_ipv4`:
///
/// ```python
/// def get_default_interface_ipv4(addr="8.8.8.8"):
///     s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
///     s.connect((addr, 53))
///     return s.getsockname()[0]
/// ```
///
/// Returns `None` if the system has no default route (e.g. no network
/// interface available).
pub fn get_default_interface_ipv4() -> Option<Ipv4Addr> {
    let sock = UdpSocket::bind("0.0.0.0:0").ok()?;
    sock.connect(("8.8.8.8", 53)).ok()?;
    let local_addr = sock.local_addr().ok()?;
    if let std::net::IpAddr::V4(ip) = local_addr.ip() {
        Some(ip)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_default_interface_ipv4() {
        // This may fail in CI/containerized environments, so we just check
        // it doesn't panic and returns a valid result or None.
        let result = get_default_interface_ipv4();
        if let Some(ip) = result {
            assert!(!ip.is_unspecified(), "Interface IP should not be 0.0.0.0");
        }
    }
}
