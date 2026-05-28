//! # Raw Packet Construction
//!
//! Utilities for building raw IPv4+TCP packets from header structs.
//! Used when injecting modified packets into the wire.

use std::net::Ipv4Addr;

use bytes::Bytes;

use mamadvpn_common::packet::{Ipv4Header, TcpHeader};

/// Compute the IPv4 header checksum (RFC 1071).
pub fn ipv4_checksum(header: &[u8]) -> u16 {
    let mut sum = 0u32;
    for chunk in header.chunks(2) {
        let word = if chunk.len() == 2 {
            u16::from_be_bytes([chunk[0], chunk[1]])
        } else {
            u16::from_be_bytes([chunk[0], 0])
        };
        sum = sum.wrapping_add(word as u32);
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// Compute the TCP checksum including the IPv4 pseudo-header (RFC 793).
pub fn tcp_checksum(src: Ipv4Addr, dst: Ipv4Addr, tcp_segment: &[u8]) -> u16 {
    let len = tcp_segment.len();
    let mut buffer = Vec::with_capacity(12 + len + 1);

    // Pseudo-header
    buffer.extend_from_slice(&src.octets());
    buffer.extend_from_slice(&dst.octets());
    buffer.push(0u8);
    buffer.push(6u8); // TCP protocol
    buffer.extend_from_slice(&(len as u16).to_be_bytes());

    // TCP segment
    buffer.extend_from_slice(tcp_segment);

    // Pad to even length
    if buffer.len() % 2 != 0 {
        buffer.push(0);
    }

    let mut sum = 0u32;
    for chunk in buffer.chunks(2) {
        let word = u16::from_be_bytes([chunk[0], chunk[1]]);
        sum = sum.wrapping_add(word as u32);
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// Build a complete IPv4+TCP packet from header structs and payload.
///
/// This is the primary interface used by bypass handlers to construct
/// packets for injection.  It computes both the IP and TCP checksums.
pub fn build_ipv4_tcp_packet(ip: &Ipv4Header, tcp: &TcpHeader, payload: &[u8]) -> Vec<u8> {
    let ip_header = ip.to_bytes();
    let ip_hdr_len = ip_header.len();

    // Build the TCP segment (header + payload)
    let tcp_header = tcp.to_bytes();
    let mut tcp_segment = Vec::with_capacity(tcp_header.len() + payload.len());
    tcp_segment.extend_from_slice(&tcp_header);
    tcp_segment.extend_from_slice(payload);

    // Compute TCP checksum (zero the checksum field first)
    let old_checksum_pos = 16;
    let saved_checksum = tcp_segment[old_checksum_pos..old_checksum_pos + 2].to_vec();
    tcp_segment[old_checksum_pos] = 0;
    tcp_segment[old_checksum_pos + 1] = 0;

    let tcp_csum = tcp_checksum(ip.src_ip, ip.dst_ip, &tcp_segment);
    tcp_segment[old_checksum_pos] = tcp_csum.to_be_bytes()[0];
    tcp_segment[old_checksum_pos + 1] = tcp_csum.to_be_bytes()[1];

    // Compute IP checksum
    let ip_csum_pos = 10;
    let mut ip_header_for_csum = ip_header.clone();
    ip_header_for_csum[ip_csum_pos] = 0;
    ip_header_for_csum[ip_csum_pos + 1] = 0;
    let ip_csum = ipv4_checksum(&ip_header_for_csum);

    // Assemble final packet with updated total length and checksum
    let total_len = ip_hdr_len + tcp_segment.len();
    let mut final_ip = ip_header;
    final_ip[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
    final_ip[ip_csum_pos] = ip_csum.to_be_bytes()[0];
    final_ip[ip_csum_pos + 1] = ip_csum.to_be_bytes()[1];

    let mut packet = Vec::with_capacity(total_len);
    packet.extend_from_slice(&final_ip);
    packet.extend_from_slice(&tcp_segment);

    packet
}

#[cfg(test)]
mod tests {
    use super::*;
    use mamadvpn_common::packet::{CapturedPacket, TcpFlags};

    fn make_minimal_syn() -> Vec<u8> {
        let mut pkt = Vec::new();
        // IPv4 header (20 bytes)
        pkt.extend_from_slice(&[0x45, 0x00, 0x00, 0x28, 0x00, 0x01, 0x40, 0x00, 0x40, 0x06]);
        pkt.extend_from_slice(&[0x00, 0x00]); // checksum placeholder
        pkt.extend_from_slice(&[10, 0, 0, 1]); // src
        pkt.extend_from_slice(&[10, 0, 0, 2]); // dst
        // TCP header (20 bytes)
        pkt.extend_from_slice(&[0x1f, 0x90]); // src port 8080
        pkt.extend_from_slice(&[0x00, 0x50]); // dst port 80
        pkt.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]); // seq=1
        pkt.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // ack=0
        pkt.push(0x50); // data offset=5
        pkt.push(0x02); // flags=SYN
        pkt.extend_from_slice(&[0x72, 0x10, 0x00, 0x00, 0x00, 0x00]);
        pkt
    }

    #[test]
    fn test_build_roundtrip() {
        let raw = make_minimal_syn();
        let pkt = CapturedPacket::from_raw(Bytes::copy_from_slice(&raw)).unwrap();
        let rebuilt = build_ipv4_tcp_packet(&pkt.ip, &pkt.tcp, &[]);
        assert_eq!(rebuilt.len(), raw.len());
        assert_eq!(rebuilt[0] >> 4, 4);
        assert_eq!(rebuilt[9], 6);
    }

    #[test]
    fn test_build_with_payload() {
        let raw = make_minimal_syn();
        let pkt = CapturedPacket::from_raw(Bytes::copy_from_slice(&raw)).unwrap();
        let payload = b"\x16\x03\x01\x00\x01";
        let rebuilt = build_ipv4_tcp_packet(&pkt.ip, &pkt.tcp, payload);
        assert!(rebuilt.len() > raw.len());
        // TCP checksum should be non-zero
        let tcp_csum = u16::from_be_bytes([rebuilt[36], rebuilt[37]]);
        assert_ne!(tcp_csum, 0, "TCP checksum should be non-zero");
    }
}
