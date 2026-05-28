//! # Windows WinDivert Packet Interception Backend
//!
//! Implements the `PacketInterceptor` trait for Windows using
//! [WinDivert](https://reqrypt.org/windivert.html).
//!
//! ## Architecture
//!
//! WinDivert is a kernel-mode driver that intercepts network packets at
//! the network stack.  It matches the original Python prototype which uses
//! `pydivert` (a Python binding for WinDivert).
//!
//! ```text
//! ┌──────────────┐  WinDivertRecv  ┌──────────────────┐
//! │  WinDivert   │ ──────────────► │  WinDivertBackend │
//! │  (kernel)    │ ◄────────────── │                   │
//! └──────────────┘  WinDivertSend  │  → parse packet   │
//!                                   │  → lookup conn    │
//!                                   │  → call handler   │
//!                                   │  → verdict        │
//!                                   └──────────────────┘
//! ```

use std::sync::Arc;

use anyhow::Result;
use async_trait::async_trait;
use bytes::Bytes;

use mamadvpn_core::interceptor::{PacketAction, PacketHandler, PacketInterceptor};
use mamadvpn_common::ConnectionId;

/// WinDivert packet interceptor.
///
/// This is a stub for non-Windows platforms.  On Windows, it will use the
/// `windivert` crate to capture and inject packets.
pub struct WinDivertInterceptor {
    /// WinDivert filter string (e.g., "tcp and ip.SrcAddr == 1.2.3.4").
    filter: String,
    /// Whether the interceptor is running.
    running: Arc<std::sync::atomic::AtomicBool>,
}

impl WinDivertInterceptor {
    /// Create a new WinDivert interceptor.
    ///
    /// The `filter` string follows WinDivert's packet filter syntax
    /// (similar to Wireshark's display filters).
    pub fn new(filter: &str) -> Self {
        Self {
            filter: filter.to_string(),
            running: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        }
    }
}

#[async_trait]
impl PacketInterceptor for WinDivertInterceptor {
    async fn start(self: Box<Self>, _engine: Arc<dyn PacketHandler>) -> Result<()> {
        tracing::info!(
            "Starting Windows WinDivert interceptor with filter: {}",
            self.filter
        );
        self.running.store(true, std::sync::atomic::Ordering::SeqCst);

        // TODO: Implement WinDivert packet capture loop.
        //
        // Pattern (matches Python's `injecter.py`):
        // 1. Open WinDivert handle: `WinDivert::new(&filter)`.
        // 2. Loop: `recv()` → parse IP/TCP headers → lookup connection →
        //    call engine handler → verdict (`send()` modified or original).
        //
        // Using the `windivert` crate:
        // ```
        // let mut divert = windivert::WinDivert::new(&filter, windivert::LAYER_NETWORK, 0, 0)?;
        // loop {
        //     let (packet, addr) = divert.recv()?;
        //     // ... process ...
        //     divert.send(&packet, &addr)?;
        // }
        // ```

        tracing::warn!("WinDivert backend is a stub — packets pass through unmodified");
        Ok(())
    }

    async fn stop(&self) -> Result<()> {
        self.running.store(false, std::sync::atomic::Ordering::SeqCst);
        tracing::info!("Windows WinDivert interceptor stopped");
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Windows service mode support
// ---------------------------------------------------------------------------

/// Configuration for running as a Windows service.
pub struct WindowsServiceConfig {
    pub service_name: String,
    pub display_name: String,
    pub description: String,
}

impl Default for WindowsServiceConfig {
    fn default() -> Self {
        Self {
            service_name: "MamadVPN".into(),
            display_name: "MamadVPN Transport Engine".into(),
            description: "TCP desynchronization-based censorship circumvention transport".into(),
        }
    }
}

/// Run the engine as a Windows service.
///
/// This function is called by the service entry point and manages the
/// service lifecycle (start, stop, pause, continue).
pub fn run_as_service(_config: WindowsServiceConfig) -> Result<()> {
    // TODO: Implement Windows service integration using `windows-service` crate.
    //
    // Pattern:
    // 1. Define service control handler.
    // 2. Register the service with the SCM.
    // 3. On start, create the engine, attach WinDivert, and begin relay.
    // 4. On stop, gracefully shut down the engine and close WinDivert.
    tracing::warn!("Windows service mode is a stub");
    Ok(())
}
