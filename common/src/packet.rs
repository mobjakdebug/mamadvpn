use std::fmt;
use std::net::Ipv4Addr;

use bytes::Bytes;

use crate::connection_id::ConnectionId;
use crate::error::CommonError;

// ---------------------------------------------------------------------------
// TCP flags
// ---------------------------------------------------------------------------

/// TCP control flags, modeled as a bitflag set.
///
/// Matches the field checks performed in the Python injector, e.g.:
/// ```python
/// if packet.tcp.ack and packet.tcp.syn and (not packet.tcp.rst) ...
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct TcpFlags(u8);

#[allow(dead_code)]
impl TcpFlags {
    pub const FIN: u8 = 0x01;
    pub const SYN: u8 = 0x02;
    pub const RST: u8 = 0x04;
    pub const PSH: u8 = 0x08;
    pub const ACK: u8 = 0x10;
    pub const URG: u8 = 0x20;
    pub const ECE: u8 = 0x40;
    pub const CWR: u8 = 0x80;

    pub const fn from_bits(bits: u8) -> Self {
        Self(bits)
    }

    pub const fn bits(self) -> u8 {
        self.0
    }

    pub const fn syn(self) -> bool {
        self.0 & Self::SYN != 0
    }
    pub const fn ack(self) -> bool {
        self.0 & Self::ACK != 0
    }
    pub const fn rst(self) -> bool {
        self.0 & Self::RST != 0
    }
    pub const fn fin(self) -> bool {
        self.0 & Self::FIN != 0
    }
    pub const fn psh(self) -> bool {
        self.0 & Self::PSH != 0
    }

    pub fn set_syn(&mut self, v: bool) {
        if v {
            self.0 |= Self::SYN;
        } else {
            self.0 &= !Self::SYN;
        }
    }
    pub fn set_ack(&mut self, v: bool) {
        if v {
            self.0 |= Self::ACK;
        } else {
            self.0 &= !Self::ACK;
        }
    }
    pub fn set_psh(&mut self, v: bool) {
        if v {
            self.0 |= Self::PSH;
        } else {
            self.0 &= !Self::PSH;
        }
    }
}

impl fmt::Display for TcpFlags {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut s = String::with_capacity(6);
        if self.syn() {
            s.push('S');
        }
        if self.ack() {
            s.push('A');
        }
        if self.rst() {
            s.push('R');
        }
        if self.fin() {
            s.push('F');
        }
        if self.psh() {
            s.push('P');
        }
        write!(f, "{s}")
    }
}

// ---------------------------------------------------------------------------
// Parsed TCP header fields — the minimum set needed by the bypass logic.
// ---------------------------------------------------------------------------

/// Parsed TCP header fields relevant to the bypass engine.
///
/// Derived from the raw TCP header bytes.  We do **not** attempt to
/// re-implement a full TCP stack; we only extract what the Python injector
/// uses.
#[derive(Debug, Clone, PartialEq)]
pub struct TcpHeader {
    pub src_port: u16,
    pub dst_port: u16,
    pub seq_num: u32,
    pub ack_num: u32,
    pub data_offset: u8, // in 32-bit words
    pub flags: TcpFlags,
    pub window_size: u16,
    pub checksum: u16,
    pub urgent_ptr: u16,
    /// Raw options bytes (if any).
    pub options: Bytes,
}

impl TcpHeader {
    /// Parse a TCP header from raw bytes (minimum 20 bytes).
    ///
    /// Returns the header and the remaining payload bytes.
    pub fn parse(data: &[u8]) -> Result<(Self, &[u8]), CommonError> {
        if data.len() < 20 {
            return Err(CommonError::Packet(format!(
                "TCP header too short: {} bytes (min 20)",
                data.len()
            )));
        }

        let src_port = u16::from_be_bytes([data[0], data[1]]);
        let dst_port = u16::from_be_bytes([data[2], data[3]]);
        let seq_num = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
        let ack_num = u32::from_be_bytes([data[8], data[9], data[10], data[11]]);
        let data_offset = (data[12] >> 4) & 0x0f;
        let flags = TcpFlags::from_bits(data[13]);
        let window_size = u16::from_be_bytes([data[14], data[15]]);
        let checksum = u16::from_be_bytes([data[16], data[17]]);
        let urgent_ptr = u16::from_be_bytes([data[18], data[19]]);

        let header_len = (data_offset as usize) * 4;
        if header_len < 20 || header_len > data.len() {
            return Err(CommonError::Packet(format!(
                "Invalid TCP header length: data_offset={data_offset}, header_len={header_len}"
            )));
        }

        let options = Bytes::copy_from_slice(&data[20..header_len]);
        let payload = &data[header_len..];

        Ok((
            Self {
                src_port,
                dst_port,
                seq_num,
                ack_num,
                data_offset,
                flags,
                window_size,
                checksum,
                urgent_ptr,
                options,
            },
            payload,
        ))
    }

    /// Serialize the TCP header back into bytes (for injection).
    ///
    /// The caller MUST recompute the checksum after setting the payload.
    pub fn to_bytes(&self) -> Vec<u8> {
        let header_len = ((self.data_offset as usize) * 4).max(20);
        let mut buf = Vec::with_capacity(header_len);

        buf.extend_from_slice(&self.src_port.to_be_bytes());
        buf.extend_from_slice(&self.dst_port.to_be_bytes());
        buf.extend_from_slice(&self.seq_num.to_be_bytes());
        buf.extend_from_slice(&self.ack_num.to_be_bytes());
        buf.push(self.data_offset << 4);
        buf.push(self.flags.bits());
        buf.extend_from_slice(&self.window_size.to_be_bytes());
        buf.extend_from_slice(&self.checksum.to_be_bytes());
        buf.extend_from_slice(&self.urgent_ptr.to_be_bytes());

        // Options (padded to 4-byte boundary by the original header)
        buf.extend_from_slice(&self.options);

        // Zero-pad to header_len
        buf.resize(header_len, 0);
        buf
    }
}

// ---------------------------------------------------------------------------
// IPv4 header (minimal — only what the injector touches)
// ---------------------------------------------------------------------------

/// Parsed IPv4 header fields relevant to the bypass engine.
#[derive(Debug, Clone, PartialEq)]
pub struct Ipv4Header {
    pub version_ihl: u8,
    pub dscp_ecn: u8,
    pub total_length: u16,
    pub ident: u16,
    pub flags_fragment: u16,
    pub ttl: u8,
    pub protocol: u8,
    pub header_checksum: u16,
    pub src_ip: Ipv4Addr,
    pub dst_ip: Ipv4Addr,
}

impl Ipv4Header {
    /// Parse an IPv4 header from raw bytes (minimum 20 bytes).
    pub fn parse(data: &[u8]) -> Result<(Self, &[u8]), CommonError> {
        if data.len() < 20 {
            return Err(CommonError::Packet(format!(
                "IPv4 header too short: {} bytes",
                data.len()
            )));
        }

        let version_ihl = data[0];
        let ihl = (version_ihl & 0x0f) as usize;
        if ihl < 5 {
            return Err(CommonError::Packet(format!(
                "Invalid IPv4 IHL: {ihl} (min 5)"
            )));
        }

        let header = Self {
            version_ihl,
            dscp_ecn: data[1],
            total_length: u16::from_be_bytes([data[2], data[3]]),
            ident: u16::from_be_bytes([data[4], data[5]]),
            flags_fragment: u16::from_be_bytes([data[6], data[7]]),
            ttl: data[8],
            protocol: data[9],
            header_checksum: u16::from_be_bytes([data[10], data[11]]),
            src_ip: Ipv4Addr::new(data[12], data[13], data[14], data[15]),
            dst_ip: Ipv4Addr::new(data[16], data[17], data[18], data[19]),
        };

        let header_len = ihl * 4;
        let remaining = &data[header_len..];

        Ok((header, remaining))
    }

    /// Serialize the IPv4 header back into bytes.
    ///
    /// The caller should recompute the header checksum after any mutation.
    pub fn to_bytes(&self) -> Vec<u8> {
        let ihl = (self.version_ihl & 0x0f) as usize;
        let header_len = ihl * 4;
        let mut buf = Vec::with_capacity(header_len);

        buf.push(self.version_ihl);
        buf.push(self.dscp_ecn);
        buf.extend_from_slice(&self.total_length.to_be_bytes());
        buf.extend_from_slice(&self.ident.to_be_bytes());
        buf.extend_from_slice(&self.flags_fragment.to_be_bytes());
        buf.push(self.ttl);
        buf.push(self.protocol);
        buf.extend_from_slice(&self.header_checksum.to_be_bytes());
        buf.extend_from_slice(&self.src_ip.octets());
        buf.extend_from_slice(&self.dst_ip.octets());

        // Options / padding (if IHL > 5, we just pad with zeros)
        buf.resize(header_len, 0);
        buf
    }

    /// Compute the IPv4 header checksum (RFC 1071).
    pub fn compute_checksum(&self) -> u16 {
        let bytes = self.to_bytes();
        let mut sum = 0u32;
        for chunk in bytes.chunks(2) {
            let word = u16::from_be_bytes([chunk[0], if chunk.len() > 1 { chunk[1] } else { 0 }]);
            sum = sum.wrapping_add(word as u32);
        }
        while sum >> 16 != 0 {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        !(sum as u16)
    }
}

// ---------------------------------------------------------------------------
// Composite captured packet (IP + TCP + payload)
// ---------------------------------------------------------------------------

/// A fully parsed packet with IPv4 + TCP headers and payload.
///
/// This is the unit of work processed by the packet interceptor and bypass
/// engine.  It is intentionally **mutable** — the bypass methods may rewrite
/// any field before re-injection.
#[derive(Debug, Clone)]
pub struct CapturedPacket {
    pub ip: Ipv4Header,
    pub tcp: TcpHeader,
    pub payload: Bytes,
    /// The entire raw packet bytes (for reference / replay).
    pub raw: Bytes,
}

impl CapturedPacket {
    /// Parse a raw IPv4 packet into its IP + TCP components.
    ///
    /// Validates that the protocol field is TCP (6).
    pub fn from_raw(raw: Bytes) -> Result<Self, CommonError> {
        let (ip, rest) = Ipv4Header::parse(&raw)?;

        if ip.protocol != 6 {
            return Err(CommonError::Packet(format!(
                "Non-TCP protocol: {}",
                ip.protocol
            )));
        }

        let (tcp, payload) = TcpHeader::parse(rest)?;

        Ok(Self {
            ip,
            tcp,
            payload: Bytes::copy_from_slice(payload),
            raw,
        })
    }

    /// Build the connection ID for **outbound** direction lookup.
    ///
    /// Matches Python: `(packet.ip.src_addr, packet.tcp.src_port, packet.ip.dst_addr, packet.tcp.dst_port)`
    pub fn outbound_id(&self) -> ConnectionId {
        ConnectionId::new(self.ip.src_ip, self.tcp.src_port, self.ip.dst_ip, self.tcp.dst_port)
    }

    /// Build the connection ID for **inbound** direction lookup.
    ///
    /// Matches Python: `(packet.ip.dst_addr, packet.tcp.dst_port, packet.ip.src_addr, packet.tcp.src_port)`
    pub fn inbound_id(&self) -> ConnectionId {
        ConnectionId::new(self.ip.dst_ip, self.tcp.dst_port, self.ip.src_ip, self.tcp.src_port)
    }

    /// Reconstruct the packet bytes after modifications.
    ///
    /// Recomputes the IP total_length from the new IP header + TCP header + payload,
    /// and recomputes the IP header checksum.  The TCP checksum is computed using
    /// the pseudo-header.
    pub fn rebuild(&self) -> Vec<u8> {
        let tcp_bytes = self.tcp.to_bytes();
        let tcp_len = tcp_bytes.len() + self.payload.len();
        let total_len = 20 + tcp_len; // IP header is always 20 bytes for our use

        let mut ip = self.ip.clone();
        ip.total_length = total_len as u16;

        // Compute TCP checksum with pseudo-header
        let tcp_checksum = compute_tcp_checksum(
            &ip.src_ip,
            &ip.dst_ip,
            &tcp_bytes,
            &self.payload,
        );
        let mut tcp = self.tcp.clone();
        tcp.checksum = tcp_checksum;

        let ip_bytes = ip.to_bytes();
        let tcp_bytes = tcp.to_bytes();

        let mut packet = Vec::with_capacity(total_len);
        packet.extend_from_slice(&ip_bytes);
        packet.extend_from_slice(&tcp_bytes);
        packet.extend_from_slice(&self.payload);

        // Recompute IP checksum
        let ip_checksum = {
            let mut sum = 0u32;
            let mut i = 0;
            while i + 1 < 20 {
                let word = u16::from_be_bytes([packet[i], packet[i + 1]]);
                sum = sum.wrapping_add(word as u32);
                i += 2;
            }
            while sum >> 16 != 0 {
                sum = (sum & 0xffff) + (sum >> 16);
            }
            !(sum as u16)
        };
        packet[10..12].copy_from_slice(&ip_checksum.to_be_bytes());
        packet[16..18].copy_from_slice(&tcp_checksum.to_be_bytes());

        packet
    }

}

/// Packet direction, matching `packet.is_inbound` / `packet.is_outbound`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    Inbound,
    Outbound,
}

// ---------------------------------------------------------------------------
// TCP checksum (RFC 793 with IPv4 pseudo-header)
// ---------------------------------------------------------------------------

/// Compute the TCP checksum including the IPv4 pseudo-header.
///
/// Used when rebuilding modified packets before re-injection.
fn compute_tcp_checksum(src: &Ipv4Addr, dst: &Ipv4Addr, tcp_hdr: &[u8], payload: &[u8]) -> u16 {
    let pseudo_len = 12 + tcp_hdr.len() + payload.len();
    let mut buf = Vec::with_capacity(pseudo_len);

    // Pseudo-header
    buf.extend_from_slice(&src.octets());
    buf.extend_from_slice(&dst.octets());
    buf.push(0u8); // zero
    buf.push(6u8); // TCP protocol number
    let tcp_len = (tcp_hdr.len() + payload.len()) as u16;
    buf.extend_from_slice(&tcp_len.to_be_bytes());

    // TCP header + payload
    buf.extend_from_slice(tcp_hdr);
    buf.extend_from_slice(payload);

    // Pad to even length
    if buf.len() % 2 != 0 {
        buf.push(0);
    }

    // Compute complement-sum (RFC 1071)
    let mut sum = 0u32;
    for chunk in buf.chunks(2) {
        let word = u16::from_be_bytes([chunk[0], if chunk.len() > 1 { chunk[1] } else { 0 }]);
        sum = sum.wrapping_add(word as u32);
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Minimal TCP SYN packet (no options, no payload).
    fn make_syn_packet() -> Vec<u8> {
        let mut pkt = Vec::new();
        // IP header (20 bytes)
        pkt.push(0x45); // version 4, IHL 5
        pkt.push(0x00); // DSCP/ECN
        pkt.extend_from_slice(&[0x00, 0x28]); // total length = 40
        pkt.extend_from_slice(&[0x00, 0x01]); // ident
        pkt.extend_from_slice(&[0x40, 0x00]); // flags/fragment
        pkt.push(0x40); // ttl = 64
        pkt.push(0x06); // protocol = TCP
        pkt.extend_from_slice(&[0x00, 0x00]); // checksum (placeholder)
        pkt.extend_from_slice(&[10, 0, 0, 1]); // src = 10.0.0.1
        pkt.extend_from_slice(&[10, 0, 0, 2]); // dst = 10.0.0.2
        // TCP header (20 bytes)
        pkt.extend_from_slice(&[0x1f, 0x90]); // src_port = 8080
        pkt.extend_from_slice(&[0x00, 0x50]); // dst_port = 80
        pkt.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]); // seq = 1
        pkt.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // ack = 0
        pkt.push(0x50); // data_offset = 5 (20 bytes)
        pkt.push(0x02); // flags = SYN
        pkt.extend_from_slice(&[0x72, 0x10]); // window
        pkt.extend_from_slice(&[0x00, 0x00]); // checksum (placeholder)
        pkt.extend_from_slice(&[0x00, 0x00]); // urgent ptr
        pkt
    }

    #[test]
    fn test_parse_syn_packet() {
        let raw = make_syn_packet();
        let pkt = CapturedPacket::from_raw(Bytes::copy_from_slice(&raw)).unwrap();
        assert_eq!(pkt.ip.src_ip, Ipv4Addr::new(10, 0, 0, 1));
        assert_eq!(pkt.ip.dst_ip, Ipv4Addr::new(10, 0, 0, 2));
        assert_eq!(pkt.tcp.src_port, 8080);
        assert_eq!(pkt.tcp.dst_port, 80);
        assert_eq!(pkt.tcp.seq_num, 1);
        assert_eq!(pkt.tcp.flags.syn(), true);
        assert_eq!(pkt.tcp.flags.ack(), false);
        assert!(pkt.payload.is_empty());
    }

    #[test]
    fn test_rebuild_roundtrip() {
        let raw = make_syn_packet();
        let pkt = CapturedPacket::from_raw(Bytes::copy_from_slice(&raw)).unwrap();
        let rebuilt = pkt.rebuild();
        // The TCP checksum field is computed now, so we zero it for comparison
        let mut raw_zero_checksum = raw.clone();
        raw_zero_checksum[16..18].copy_from_slice(&[0, 0]);
        let mut rebuilt_zero = rebuilt.clone();
        rebuilt_zero[16..18].copy_from_slice(&[0, 0]);
        assert_eq!(raw_zero_checksum, rebuilt_zero);
    }
}
