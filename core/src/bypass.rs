//! # Bypass Method Trait
//!
//! Defines the `BypassMethod` trait that all DPI evasion techniques must
//! implement.  The transport engine dispatches to the appropriate bypass
//! implementation based on the configuration.
//!
//! ## Available Bypass Methods
//!
//! * `WrongSeq` — Sends fake TLS ClientHello with an intentionally wrong
//!   sequence number.  (Port of the Python original.)
//! * `BadChecksum` — Sends packets with deliberately incorrect TCP checksums
//!   so the real server discards them but the DPI processes them.
//! * `Fragmentation` — Fragments TCP segments to evade DPI pattern matching.
//! * `DelayedAck` — Introduces timing jitter in ACK packets.
//! * `FakeRst` — Sends fake RST packets to reset DPI state tracking.
//!
//! ## Adding a New Bypass
//!
//! 1. Create a new module in `crate::bypass::implementations`.
//! 2. Implement the `BypassMethodHandler` trait.
//! 3. Register it in the dispatch table in `bypass::registry`.

use std::fmt;
use std::sync::Arc;

use bytes::Bytes;

use mamadvpn_common::BypassMethod;

use crate::connection::ManagedConnection;

/// Result of processing a packet through a bypass method.
#[derive(Debug, Clone)]
pub enum BypassAction {
    /// Forward the packet unchanged.
    Forward,
    /// Drop the packet.
    Drop,
    /// Send a modified version of the packet.
    Modify(Bytes),
    /// Send an entirely new injected packet.
    Inject(Bytes),
    /// Continue to next stage in the pipeline.
    PassThrough,
}

/// Context provided to bypass methods when processing a packet.
#[derive(Debug, Clone)]
pub struct BypassContext {
    /// The raw captured packet bytes (for reference).
    pub raw_packet: Bytes,
    /// Whether the packet is inbound (from remote) or outbound (from local).
    pub is_inbound: bool,
    /// The managed connection this packet belongs to.
    pub connection: Arc<ManagedConnection>,
}

/// A single handler in the bypass pipeline.
///
/// Bypass methods can be chained (e.g., `WrongSeq` + `Fragmentation`).
pub trait BypassHandler: Send + Sync + fmt::Debug {
    /// Process a packet and decide what to do with it.
    fn process(&self, ctx: &BypassContext) -> BypassAction;

    /// The slot in the pipeline where this handler runs.
    fn slot(&self) -> PipelineSlot;
}

/// Ordering slot in the bypass pipeline.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum PipelineSlot {
    /// Runs before the main bypass logic (e.g., connection tracking).
    PreProcessor,
    /// Main bypass logic.
    Bypass,
    /// Runs after the main bypass (e.g., packet modification for relay).
    PostProcessor,
}

/// Registry that maps `BypassMethod` variants to handler instances.
pub struct BypassRegistry {
    handlers: Vec<Box<dyn BypassHandler>>,
}

impl BypassRegistry {
    /// Create a new registry with the default handler for the given method.
    pub fn new(method: &BypassMethod) -> Self {
        let mut handlers: Vec<Box<dyn BypassHandler>> = Vec::new();
        match method {
            BypassMethod::WrongSeq => {
                handlers.push(Box::new(crate::bypass::implementations::WrongSeqHandler));
            }
            BypassMethod::BadChecksum => {
                // Placeholder — not yet implemented.
                tracing::warn!("BadChecksum bypass not yet implemented, falling back to WrongSeq");
                handlers.push(Box::new(crate::bypass::implementations::WrongSeqHandler));
            }
            BypassMethod::Fragmentation => {
                tracing::warn!("Fragmentation bypass not yet implemented, falling back to WrongSeq");
                handlers.push(Box::new(crate::bypass::implementations::WrongSeqHandler));
            }
            BypassMethod::DelayedAck => {
                tracing::warn!("DelayedAck bypass not yet implemented, falling back to WrongSeq");
                handlers.push(Box::new(crate::bypass::implementations::WrongSeqHandler));
            }
            BypassMethod::FakeRst => {
                tracing::warn!("FakeRst bypass not yet implemented, falling back to WrongSeq");
                handlers.push(Box::new(crate::bypass::implementations::WrongSeqHandler));
            }
        }
        Self { handlers }
    }

    /// Process a packet through all registered handlers.
    pub fn process(&self, ctx: &BypassContext) -> BypassAction {
        for handler in &self.handlers {
            match handler.process(ctx) {
                BypassAction::PassThrough => continue,
                action => return action,
            }
        }
        BypassAction::Forward
    }
}

pub mod implementations {
    //! Built-in bypass method implementations.

    mod wrong_seq;
    pub use wrong_seq::WrongSeqHandler;
}
