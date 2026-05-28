use std::fmt;
use std::hash::{Hash, Hasher};
use std::net::Ipv4Addr;

/// Uniquely identifies a TCP connection by its 4-tuple.
///
/// Matches the `(src_ip, src_port, dst_ip, dst_port)` keying scheme from
/// the original Python `MonitorConnection.id`.
///
/// ## Ordering
///
/// Two connection IDs are considered equal regardless of the tuple order
/// (i.e. `(src, sport, dst, dport)` == `(dst, dport, src, sport)` would be
/// the *inverse* direction).  Because the injector looks up connections by
/// direction, we keep the tuple directional.
#[derive(Copy, Clone, Eq, PartialEq, Hash)]
pub struct ConnectionId {
    pub src_ip: Ipv4Addr,
    pub src_port: u16,
    pub dst_ip: Ipv4Addr,
    pub dst_port: u16,
}

impl ConnectionId {
    pub const fn new(src_ip: Ipv4Addr, src_port: u16, dst_ip: Ipv4Addr, dst_port: u16) -> Self {
        Self {
            src_ip,
            src_port,
            dst_ip,
            dst_port,
        }
    }

    /// Return the inverse-direction connection ID (for reverse-path lookups).
    ///
    /// The Python code uses two separate lookup keys depending on
    /// `packet.is_inbound` vs `packet.is_outbound`:
    ///
    /// - **Inbound**: `(packet.dst, dst_port, packet.src, src_port)`
    /// - **Outbound**: `(packet.src, src_port, packet.dst, dst_port)`
    ///
    /// This method computes the key that would be used to look up this
    /// connection when the **opposite** direction packet arrives.
    pub fn inverse(&self) -> Self {
        Self {
            src_ip: self.dst_ip,
            src_port: self.dst_port,
            dst_ip: self.src_ip,
            dst_port: self.src_port,
        }
    }
}

impl fmt::Debug for ConnectionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}:{} -> {}:{}",
            self.src_ip, self.src_port, self.dst_ip, self.dst_port
        )
    }
}

impl fmt::Display for ConnectionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}:{} -> {}:{}",
            self.src_ip, self.src_port, self.dst_ip, self.dst_port
        )
    }
}
