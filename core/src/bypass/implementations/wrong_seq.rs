//! # Wrong Sequence Number Bypass
//!
//! Implements the TCP sequence desynchronization technique.
//!
//! ## How It Works
//!
//! 1. Three-way handshake (SYN → SYN-ACK → ACK) completes normally while
//!    the injector tracks sequence numbers.
//! 2. After the ACK, the injector sends the fake TLS ClientHello with a
//!    **deliberately wrong sequence number**:
//!    `seq_num = syn_seq + 1 - len(fake_data)`.
//! 3. The real server sees this as out-of-order data and ignores it.
//! 4. The DPI sees the fake ClientHello first and uses its SNI to decide.

use std::sync::atomic::Ordering;

use bytes::Bytes;

use mamadvpn_common::packet::CapturedPacket;

use crate::bypass::{BypassAction, BypassContext, BypassHandler, PipelineSlot};
use crate::connection::{ConnectionEvent, HandshakeResult, ManagedConnection};
use crate::raw::build_ipv4_tcp_packet;
use crate::state::ConnectionState;

/// The wrong-seq bypass handler.
#[derive(Debug)]
pub struct WrongSeqHandler;

impl BypassHandler for WrongSeqHandler {
    fn process(&self, ctx: &BypassContext) -> BypassAction {
        let conn = &ctx.connection;

        let parsed = match CapturedPacket::from_raw(ctx.raw_packet.clone()) {
            Ok(p) => p,
            Err(_) => return BypassAction::PassThrough,
        };

        conn.record_intercept();

        if ctx.is_inbound {
            self.handle_inbound(conn, &parsed)
        } else {
            self.handle_outbound(conn, &parsed)
        }
    }

    fn slot(&self) -> PipelineSlot {
        PipelineSlot::Bypass
    }
}

impl WrongSeqHandler {
    fn handle_inbound(&self, conn: &ManagedConnection, pkt: &CapturedPacket) -> BypassAction {
        let tcp = &pkt.tcp;

        // ---- SYN-ACK (inbound) ----
        if tcp.flags.ack() && tcp.flags.syn() && !tcp.flags.rst() && !tcp.flags.fin() && pkt.payload.is_empty() {
            return match conn.handle_event(ConnectionEvent::InboundSynAck {
                seq: tcp.seq_num,
                ack: tcp.ack_num,
            }) {
                Ok(_) => BypassAction::Forward,
                Err(e) => {
                    tracing::warn!(%e, %conn.id, "Unexpected SYN-ACK");
                    conn.record_unexpected();
                    conn.notify_handshake(HandshakeResult::UnexpectedClose(e.to_string()));
                    BypassAction::Drop
                }
            };
        }

        // ---- ACK for fake data (inbound) ----
        if tcp.flags.ack()
            && !tcp.flags.syn()
            && !tcp.flags.rst()
            && !tcp.flags.fin()
            && pkt.payload.is_empty()
            && conn.fake_sent.load(Ordering::SeqCst)
        {
            return match conn.handle_event(ConnectionEvent::InboundAck {
                seq: tcp.seq_num,
                ack: tcp.ack_num,
            }) {
                Ok(_) => {
                    tracing::info!(%conn.id, "Fake data ACKed, proceeding to relay");
                    conn.notify_handshake(HandshakeResult::FakeDataAcked);
                    BypassAction::Forward
                }
                Err(e) => {
                    tracing::warn!(%e, %conn.id, "Unexpected ACK for fake data");
                    conn.record_unexpected();
                    conn.notify_handshake(HandshakeResult::UnexpectedClose(e.to_string()));
                    BypassAction::Drop
                }
            };
        }

        // ---- Unexpected inbound ----
        tracing::warn!(conn_id = %conn.id, flags = %tcp.flags, "Unexpected inbound packet");
        conn.record_unexpected();
        conn.notify_handshake(HandshakeResult::UnexpectedClose("unexpected inbound packet".into()));
        BypassAction::Drop
    }

    fn handle_outbound(&self, conn: &ManagedConnection, pkt: &CapturedPacket) -> BypassAction {
        let tcp = &pkt.tcp;

        // ---- Python: check sch_fake_sent FIRST ----
        // if connection.sch_fake_sent: on_unexpected_packet(...)
        if conn.scheduled_fake_sent.load(Ordering::SeqCst) {
            tracing::warn!(%conn.id, "Unexpected outbound packet after fake scheduled");
            conn.record_unexpected();
            conn.notify_handshake(HandshakeResult::UnexpectedClose(
                "unexpected outbound after fake scheduled".into(),
            ));
            return BypassAction::Drop;
        }

        // ---- SYN (outbound) ----
        if tcp.flags.syn() && !tcp.flags.ack() && !tcp.flags.rst() && !tcp.flags.fin() && pkt.payload.is_empty() {
            // Python also checks: ack_num != 0
            if tcp.ack_num != 0 {
                tracing::warn!(%conn.id, "SYN with non-zero ack_num: {}", tcp.ack_num);
                conn.record_unexpected();
                conn.notify_handshake(HandshakeResult::UnexpectedClose(
                    "SYN with non-zero ack_num".into(),
                ));
                return BypassAction::Drop;
            }
            return match conn.handle_event(ConnectionEvent::OutboundSyn { seq: tcp.seq_num }) {
                Ok(_) => BypassAction::Forward,
                Err(e) => {
                    tracing::warn!(%e, %conn.id, "Unexpected SYN");
                    conn.record_unexpected();
                    conn.notify_handshake(HandshakeResult::UnexpectedClose(e.to_string()));
                    BypassAction::Drop
                }
            };
        }

        // ---- ACK (outbound, completing handshake) ----
        if tcp.flags.ack() && !tcp.flags.syn() && !tcp.flags.rst() && !tcp.flags.fin() && pkt.payload.is_empty() {
            return match conn.handle_event(ConnectionEvent::OutboundAck {
                seq: tcp.seq_num,
                ack: tcp.ack_num,
            }) {
                Ok(_) => {
                    conn.scheduled_fake_sent.store(true, Ordering::SeqCst);
                    // Return Inject — the engine will apply the timing delay
                    // (configurable via inject_delay_us) before sending.
                    BypassAction::Inject(self.build_fake_packet(conn, pkt))
                }
                Err(e) => {
                    tracing::warn!(%e, %conn.id, "Unexpected ACK");
                    conn.record_unexpected();
                    conn.notify_handshake(HandshakeResult::UnexpectedClose(e.to_string()));
                    BypassAction::Drop
                }
            };
        }

        // ---- Unexpected outbound ----
        tracing::warn!(conn_id = %conn.id, flags = %tcp.flags, "Unexpected outbound packet");
        conn.record_unexpected();
        conn.notify_handshake(HandshakeResult::UnexpectedClose("unexpected outbound packet".into()));
        BypassAction::Drop
    }

    /// Build the fake injected packet with wrong seq number.
    /// Matches Python's `fake_send_thread` exactly.
    fn build_fake_packet(&self, conn: &ManagedConnection, pkt: &CapturedPacket) -> Bytes {
        let state = conn.current_state();
        let syn_seq = match &state {
            ConnectionState::AckSent { syn_seq, .. } => *syn_seq,
            _ => {
                tracing::warn!(%conn.id, ?state, "build_fake_packet in unexpected state");
                0
            }
        };

        let fake_data = &conn.fake_data;
        let fake_len = fake_data.len() as u32;

        let mut ip = pkt.ip.clone();
        let mut tcp = pkt.tcp.clone();

        // Python: packet.tcp.psh = True
        tcp.flags.set_psh(true);

        // Python: packet.ip.packet_len = packet.ip.packet_len + len(connection.fake_data)
        ip.total_length = ip.total_length.wrapping_add(fake_len as u16);

        // Python: packet.ipv4.ident = (packet.ipv4.ident + 1) & 0xffff
        ip.ident = ip.ident.wrapping_add(1) & 0xffff;

        // Python: seq_num = (connection.syn_seq + 1 - len(packet.tcp.payload)) & 0xffffffff
        tcp.seq_num = syn_seq.wrapping_add(1).wrapping_sub(fake_len);

        Bytes::from(build_ipv4_tcp_packet(&ip, &tcp, fake_data))
    }
}
