//! # Connection Tracking
//!
//! Wraps a `ConnectionState` machine with thread-safe access, event
//! notification, and channel-based communication between the packet
//! injector thread and the async relay task.

use std::fmt;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use bytes::Bytes;
use parking_lot::Mutex;
use tokio::sync::oneshot;

use mamadvpn_common::{BypassMethod, ConnectionId, EngineConfig};

use crate::state::{ConnectionState, UnexpectedEvent};

// ---------------------------------------------------------------------------
// ConnectionEvent
// ---------------------------------------------------------------------------

/// Events that drive the `ConnectionState` transitions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConnectionEvent {
    OutboundSyn { seq: u32 },
    InboundSynAck { seq: u32, ack: u32 },
    OutboundAck { seq: u32, ack: u32 },
    FakeDataInjected,
    InboundAck { seq: u32, ack: u32 },
    StartRelay,
    Close,
    Error(String),
}

// ---------------------------------------------------------------------------
// HandshakeResult
// ---------------------------------------------------------------------------

/// Result of the handshake phase, sent via the `handshake_notifier`.
#[derive(Debug, Clone)]
pub enum HandshakeResult {
    FakeDataAcked,
    UnexpectedClose(String),
    Timeout,
}

// ---------------------------------------------------------------------------
// ConnectionStats
// ---------------------------------------------------------------------------

/// Per-connection statistics.
#[derive(Debug, Clone, Default)]
pub struct ConnectionStats {
    pub tx_bytes: u64,
    pub rx_bytes: u64,
    pub packets_intercepted: u64,
    pub packets_injected: u64,
    pub unexpected_packets: u64,
}

// ---------------------------------------------------------------------------
// ManagedConnection
// ---------------------------------------------------------------------------

/// A single tracked connection with its state machine, configuration, and
/// notification channels.
pub struct ManagedConnection {
    pub id: ConnectionId,
    state: Mutex<ConnectionState>,
    pub fake_data: Bytes,
    pub scheduled_fake_sent: AtomicBool,
    pub fake_sent: AtomicBool,
    pub bypass_method: BypassMethod,
    pub config: EngineConfig,
    pub local_addr: SocketAddr,
    pub remote_addr: SocketAddr,
    pub interface_ip: Ipv4Addr,
    handshake_notifier: Mutex<Option<oneshot::Sender<HandshakeResult>>>,
    pub stats: Mutex<ConnectionStats>,
}

impl ManagedConnection {
    pub fn new(
        id: ConnectionId,
        fake_data: Bytes,
        config: EngineConfig,
        local_addr: SocketAddr,
        remote_addr: SocketAddr,
        interface_ip: Ipv4Addr,
    ) -> Self {
        Self {
            id,
            state: Mutex::new(ConnectionState::Initial),
            fake_data,
            scheduled_fake_sent: AtomicBool::new(false),
            fake_sent: AtomicBool::new(false),
            bypass_method: config.bypass_mode.clone(),
            config,
            local_addr,
            remote_addr,
            interface_ip,
            handshake_notifier: Mutex::new(None),
            stats: Mutex::new(ConnectionStats::default()),
        }
    }

    pub fn set_handshake_channel(&self, tx: oneshot::Sender<HandshakeResult>) {
        *self.handshake_notifier.lock() = Some(tx);
    }

    pub fn notify_handshake(&self, result: HandshakeResult) {
        if let Some(tx) = self.handshake_notifier.lock().take() {
            let _ = tx.send(result);
        }
    }

    pub fn handle_event(&self, event: ConnectionEvent) -> Result<ConnectionState, UnexpectedEvent> {
        let mut state = self.state.lock();
        let new_state = state.clone().transition(&event)?;
        *state = new_state.clone();
        Ok(new_state)
    }

    pub fn current_state(&self) -> ConnectionState {
        self.state.lock().clone()
    }

    pub fn is_alive(&self) -> bool {
        self.state.lock().is_alive()
    }

    pub fn can_relay(&self) -> bool {
        self.state.lock().can_relay()
    }

    pub fn record_intercept(&self) {
        self.stats.lock().packets_intercepted += 1;
    }

    pub fn record_injection(&self) {
        self.stats.lock().packets_injected += 1;
    }

    pub fn record_unexpected(&self) {
        self.stats.lock().unexpected_packets += 1;
    }

    pub fn close(&self) {
        let _ = self.handle_event(ConnectionEvent::Close);
        self.notify_handshake(HandshakeResult::UnexpectedClose("connection closed".into()));
    }
}

impl fmt::Debug for ManagedConnection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ManagedConnection")
            .field("id", &self.id)
            .field("state", &self.state)
            .field("fake_data_len", &self.fake_data.len())
            .field("scheduled_fake_sent", &self.scheduled_fake_sent.load(Ordering::Relaxed))
            .field("fake_sent", &self.fake_sent.load(Ordering::Relaxed))
            .field("bypass_method", &self.bypass_method)
            .field("local_addr", &self.local_addr)
            .field("remote_addr", &self.remote_addr)
            .field("interface_ip", &self.interface_ip)
            .field("stats", &self.stats)
            .finish()
    }
}
