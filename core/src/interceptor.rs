//! # Packet Interception Abstraction
//!
//! Defines the `PacketInterceptor` trait that all platform backends
//! (WinDivert, NFQUEUE, TUN) must implement.
//!
//! The design follows the original Python `TcpInjector` ABC:
//!
//! ```python
//! class TcpInjector(ABC):
//!     def __init__(self, w_filter: str): ...
//!     def inject(self, packet: Packet): ...
//!     def run(self): ...
//! ```

use std::sync::Arc;

use async_trait::async_trait;
use bytes::Bytes;

use mamadvpn_common::{ConnectionId, EngineConfig};

use crate::connection::ManagedConnection;

/// Action to take after processing a packet through the handler.
#[derive(Debug, Clone)]
pub enum PacketAction {
    /// Forward the original packet unchanged.
    Forward,
    /// Drop the packet (do not forward).
    Drop,
    /// Send a modified copy of the packet.
    Modify(Bytes),
    /// Send an entirely new injected packet.
    Inject(Bytes),
}

/// The handler that processes intercepted packets.
///
/// Implemented by the `TransportEngine`.  The interceptor calls these
/// methods for each captured packet that matches a tracked connection.
#[async_trait]
pub trait PacketHandler: Send + Sync {
    /// Handle an inbound packet (from remote to local).
    ///
    /// `conn` is an `Arc<ManagedConnection>` so the handler can mutate the
    /// connection state machine and send handshake notifications through
    /// the bypass pipeline.
    async fn handle_inbound(
        &self,
        conn: Arc<ManagedConnection>,
        raw_packet: Bytes,
    ) -> PacketAction;

    /// Handle an outbound packet (from local to remote).
    async fn handle_outbound(
        &self,
        conn: Arc<ManagedConnection>,
        raw_packet: Bytes,
    ) -> PacketAction;

    /// Look up a connection by its ID.
    fn lookup_connection(&self, id: &ConnectionId) -> Option<Arc<ManagedConnection>>;

    /// Handle a packet that didn't match any tracked connection.
    fn handle_unknown_packet(&self, raw_packet: Bytes) -> PacketAction;
}

/// Platform-agnostic packet interceptor.
///
/// Each platform backend implements this trait.
#[async_trait]
pub trait PacketInterceptor: Send + Sync {
    /// Start capturing packets and feeding them to the handler.
    ///
    /// This is typically a long-running task that runs on a dedicated
    /// thread or tokio task.
    async fn start(self: Box<Self>, engine: Arc<dyn PacketHandler>) -> anyhow::Result<()>;

    /// Stop the interceptor gracefully.
    async fn stop(&self) -> anyhow::Result<()>;
}
