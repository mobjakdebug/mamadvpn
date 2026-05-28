//! # MamadVPN Integration Tests
//!
//! Test suites covering:
//!
//! * **Unit tests** — state machine transitions, packet parsing, TLS generation.
//! * **Integration tests** — full connection lifecycle with mock interceptors.
//! * **Replay tests** — replay captured packet sequences through the engine.
//! * **Stress tests** — high-concurrency connection handling.

#[cfg(test)]
mod tests {
    //! The actual test modules are defined in their respective crates.
    //! This crate exists as a workspace member for future end-to-end tests
    //! that span multiple crates (e.g., engine + interceptor).
}

// ---------------------------------------------------------------------------
// Unit test helpers
// ---------------------------------------------------------------------------

/// Helper to create a minimal SYN packet for testing.
pub fn make_syn_packet(src_ip: [u8; 4], dst_ip: [u8; 4], src_port: u16, dst_port: u16, seq: u32) -> Vec<u8> {
    let mut pkt = Vec::new();
    // IPv4 header (20 bytes)
    pkt.push(0x45);
    pkt.push(0x00);
    pkt.extend_from_slice(&[0x00, 0x28]); // total length = 40
    pkt.extend_from_slice(&[0x00, 0x01]); // ident
    pkt.extend_from_slice(&[0x40, 0x00]); // flags/fragment
    pkt.push(0x40); // ttl = 64
    pkt.push(0x06); // protocol = TCP
    pkt.extend_from_slice(&[0x00, 0x00]); // checksum placeholder
    pkt.extend_from_slice(&src_ip);
    pkt.extend_from_slice(&dst_ip);
    // TCP header (20 bytes)
    pkt.extend_from_slice(&src_port.to_be_bytes());
    pkt.extend_from_slice(&dst_port.to_be_bytes());
    pkt.extend_from_slice(&seq.to_be_bytes());
    pkt.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // ack = 0
    pkt.push(0x50); // data offset = 5
    pkt.push(0x02); // flags = SYN
    pkt.extend_from_slice(&[0x72, 0x10]); // window
    pkt.extend_from_slice(&[0x00, 0x00]); // checksum placeholder
    pkt.extend_from_slice(&[0x00, 0x00]); // urgent ptr
    pkt
}

/// Helper to create a minimal SYN-ACK packet for testing.
pub fn make_syn_ack_packet(
    src_ip: [u8; 4],
    dst_ip: [u8; 4],
    src_port: u16,
    dst_port: u16,
    seq: u32,
    ack: u32,
) -> Vec<u8> {
    let mut pkt = make_syn_packet(src_ip, dst_ip, src_port, dst_port, seq);
    // Modify to SYN-ACK
    pkt[33] = 0x12; // flags = SYN + ACK
    pkt[8..12].copy_from_slice(&ack.to_be_bytes()); // set ack number
    pkt
}

/// Helper to create a minimal ACK packet for testing.
pub fn make_ack_packet(
    src_ip: [u8; 4],
    dst_ip: [u8; 4],
    src_port: u16,
    dst_port: u16,
    seq: u32,
    ack: u32,
) -> Vec<u8> {
    let mut pkt = make_syn_packet(src_ip, dst_ip, src_port, dst_port, seq);
    pkt[33] = 0x10; // flags = ACK only
    pkt[8..12].copy_from_slice(&ack.to_be_bytes());
    pkt
}

// ---------------------------------------------------------------------------
// Integration test: full state machine lifecycle
// ---------------------------------------------------------------------------

#[cfg(test)]
mod state_machine_tests {
    use bytes::Bytes;
    use mamadvpn_common::config::EngineConfig;
    use mamadvpn_common::connection_id::ConnectionId;
    use mamadvpn_common::packet::CapturedPacket;
    use mamadvpn_core::connection::{ConnectionEvent, ManagedConnection};
    use mamadvpn_core::state::ConnectionState;
    use std::net::Ipv4Addr;
    use std::net::SocketAddr;
    use std::sync::Arc;

    fn make_test_connection() -> Arc<ManagedConnection> {
        let config = EngineConfig::default();
        let id = ConnectionId::new(
            Ipv4Addr::new(10, 0, 0, 1),
            12345,
            Ipv4Addr::new(10, 0, 0, 2),
            443,
        );
        let fake_data = vec![0x16, 0x03, 0x01, 0x00, 0x05]; // fake TLS record
        Arc::new(ManagedConnection::new(
            id,
            Bytes::from(fake_data),
            config,
            SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), 0),
            SocketAddr::new(Ipv4Addr::new(10, 0, 0, 2).into(), 443),
            Ipv4Addr::new(10, 0, 0, 1),
        ))
    }

    #[tokio::test]
    async fn test_full_handshake() {
        let conn = make_test_connection();

        // Initial state
        assert_eq!(conn.current_state(), ConnectionState::Initial);

        // Outbound SYN (seq=1000)
        let state = conn.handle_event(ConnectionEvent::OutboundSyn { seq: 1000 }).unwrap();
        assert_eq!(state, ConnectionState::SynSent { syn_seq: 1000 });

        // Inbound SYN-ACK (seq=5000, ack=1001)
        let state = conn
            .handle_event(ConnectionEvent::InboundSynAck {
                seq: 5000,
                ack: 1001,
            })
            .unwrap();
        assert_eq!(
            state,
            ConnectionState::SynAckReceived {
                syn_seq: 1000,
                syn_ack_seq: 5000
            }
        );

        // Outbound ACK (seq=1001, ack=5001)
        let state = conn
            .handle_event(ConnectionEvent::OutboundAck {
                seq: 1001,
                ack: 5001,
            })
            .unwrap();
        assert_eq!(
            state,
            ConnectionState::AckSent {
                syn_seq: 1000,
                syn_ack_seq: 5000
            }
        );

        // Fake data injected
        let state = conn.handle_event(ConnectionEvent::FakeDataInjected).unwrap();
        assert_eq!(
            state,
            ConnectionState::FakeSent {
                syn_seq: 1000,
                syn_ack_seq: 5000
            }
        );

        // Inbound ACK for fake data (seq=5001, ack=1001)
        conn.fake_sent = true;
        let state = conn
            .handle_event(ConnectionEvent::InboundAck {
                seq: 5001,
                ack: 1001,
            })
            .unwrap();
        assert_eq!(
            state,
            ConnectionState::FakeAcked {
                syn_seq: 1000,
                syn_ack_seq: 5000
            }
        );

        // Start relay
        let state = conn.handle_event(ConnectionEvent::StartRelay).unwrap();
        assert_eq!(state, ConnectionState::Relaying);
    }

    #[tokio::test]
    async fn test_unexpected_inbound_before_syn() {
        let conn = make_test_connection();
        let result = conn.handle_event(ConnectionEvent::InboundSynAck {
            seq: 5000,
            ack: 1,
        });
        assert!(result.is_err(), "Should reject inbound before SYN");
    }

    #[tokio::test]
    async fn test_wrong_ack_num_in_syn_ack() {
        let conn = make_test_connection();
        conn.handle_event(ConnectionEvent::OutboundSyn { seq: 1000 }).unwrap();
        let result = conn.handle_event(ConnectionEvent::InboundSynAck {
            seq: 5000,
            ack: 9999, // wrong! should be 1001
        });
        assert!(result.is_err(), "Should reject wrong ack_num in SYN-ACK");
    }
}

// ---------------------------------------------------------------------------
// TLS generation tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tls_tests {
    use mamadvpn_common::tls::ClientHelloBuilder;

    #[test]
    fn test_client_hello_sni() {
        let sni = b"www.example.com";
        let ch = ClientHelloBuilder::generate(sni);
        // Verify sni appears in the generated message
        assert!(
            ch.windows(sni.len()).any(|w| w == sni),
            "Generated ClientHello should contain the requested SNI"
        );
    }

    #[test]
    fn test_client_hello_different_per_call() {
        let sni = b"auth.vercel.com";
        let ch1 = ClientHelloBuilder::generate(sni);
        let ch2 = ClientHelloBuilder::generate(sni);
        // Random fields (bytes 11..43) should differ
        assert_ne!(&ch1[11..43], &ch2[11..43], "Random should differ");
    }
}

// ---------------------------------------------------------------------------
// Packet parsing tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod packet_tests {
    use bytes::Bytes;
    use mamadvpn_common::packet::CapturedPacket;

    #[test]
    fn test_parse_syn_packet() {
        let raw = crate::make_syn_packet([10, 0, 0, 1], [10, 0, 0, 2], 12345, 443, 1000);
        let pkt = CapturedPacket::from_raw(Bytes::from(raw)).unwrap();
        assert_eq!(pkt.tcp.src_port, 12345);
        assert_eq!(pkt.tcp.dst_port, 443);
        assert!(pkt.tcp.flags.syn());
        assert!(!pkt.tcp.flags.ack());
        assert!(pkt.payload.is_empty());
    }
}
