//! # Android TUN Packet Interceptor
//!
//! Implements `PacketInterceptor` for Android's VpnService TUN interface.
//!
//! ## Packet Flow
//!
//! ```text
//! TUN fd ──read()──► parse IP/TCP ──► lookup connection ──► handler ──► action
//!                                                                    │
//!                    ◄── write() ─────────────────────────────────────┘
//! ```
//!
//! For outbound TCP SYN packets, a `ManagedConnection` is created and
//! tracked.  The bypass pipeline processes each packet and returns an
//! action (Forward/Drop/Modify/Inject), which the interceptor applies
//! to the TUN fd.
//!
//! ## JNI Bridge (stub)
//!
//! JNI functions are provided for direct native access, but the primary
//! path is via Dart FFI (`mamadvpn_set_tun_fd` → engine → interceptor).

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::os::unix::io::RawFd;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use anyhow::{Context, Result};
use async_trait::async_trait;
use bytes::Bytes;
use parking_lot::Mutex;
use tokio::io::unix::AsyncFd;

use mamadvpn_common::config::DynamicConfig;
use mamadvpn_common::connection_id::ConnectionId;
use mamadvpn_common::packet::CapturedPacket;
use mamadvpn_common::tls::ClientHelloBuilder;
use mamadvpn_common::{get_default_interface_ipv4, EngineConfig};
use mamadvpn_core::connection::ManagedConnection;
use mamadvpn_core::interceptor::{PacketAction, PacketHandler, PacketInterceptor};

// ── TUN fd wrapper for AsyncFd ─────────────────────────────────

/// Wrapper around a raw fd so it implements `AsRawFd` for `tokio::io::unix::AsyncFd`.
struct TunFd(RawFd);

// SAFETY: `AsRawFd` is a safe trait in std. The fd must be valid
// and remain open for the lifetime of this wrapper.
impl std::os::unix::io::AsRawFd for TunFd {
    fn as_raw_fd(&self) -> RawFd {
        self.0
    }
}

// ── TunInterceptor ─────────────────────────────────────────────

/// Android TUN interface packet interceptor.
///
/// Reads raw IP packets from the TUN fd (provided by VpnService),
/// tracks TCP connections, processes them through the bypass engine,
/// and writes the results back to the TUN fd.
pub struct TunInterceptor {
    tun_fd: Option<i32>,
    running: Arc<AtomicBool>,
    /// Our own connection map (TUN mode maintains its own tracking).
    connections: Arc<Mutex<HashMap<ConnectionId, Arc<ManagedConnection>>>>,
    /// Engine config (cloned so we can create connections independently).
    config: DynamicConfig,
    /// Local TUN interface IP address (set from config or auto-detect).
    local_tun_ip: Ipv4Addr,
}

impl TunInterceptor {
    /// Create a new TUN interceptor.
    ///
    /// `config` is cloned from the engine so we can read fake_sni, bypass_mode, etc.
    pub fn new(config: DynamicConfig, local_tun_ip: Option<Ipv4Addr>) -> Self {
        let tun_ip = local_tun_ip.unwrap_or_else(|| {
            get_default_interface_ipv4().unwrap_or(Ipv4Addr::new(10, 0, 0, 2))
        });

        Self {
            tun_fd: None,
            running: Arc::new(AtomicBool::new(false)),
            connections: Arc::new(Mutex::new(HashMap::new())),
            config,
            local_tun_ip: tun_ip,
        }
    }

    /// Set the TUN file descriptor (called before start).
    pub fn set_tun_fd(&mut self, fd: i32) {
        self.tun_fd = Some(fd);
    }

    /// Determine if a packet is outbound (device → internet) based on src IP.
    fn is_outbound(&self, pkt: &CapturedPacket) -> bool {
        pkt.ip.src_ip == self.local_tun_ip
    }

    /// Create a new ManagedConnection for an outbound TCP SYN.
    fn create_connection(&self, pkt: &CapturedPacket) -> Arc<ManagedConnection> {
        let cfg = self.config.read();

        let fake_data = ClientHelloBuilder::generate(cfg.fake_sni.as_bytes());

        let conn_id = ConnectionId::new(
            pkt.ip.src_ip,
            pkt.tcp.src_port,
            pkt.ip.dst_ip,
            pkt.tcp.dst_port,
        );

        let local_addr = std::net::SocketAddr::new(
            std::net::IpAddr::V4(pkt.ip.src_ip),
            pkt.tcp.src_port,
        );
        let remote_addr = std::net::SocketAddr::new(
            std::net::IpAddr::V4(pkt.ip.dst_ip),
            pkt.tcp.dst_port,
        );

        let conn = Arc::new(ManagedConnection::new(
            conn_id,
            fake_data,
            cfg,
            local_addr,
            remote_addr,
            self.local_tun_ip,
        ));

        conn
    }
}

#[async_trait]
impl PacketInterceptor for TunInterceptor {
    async fn start(self: Box<Self>, engine: Arc<dyn PacketHandler>) -> Result<()> {
        let tun_fd = self.tun_fd.ok_or_else(|| anyhow::anyhow!("TUN fd not set"))?;
        self.running.store(true, Ordering::SeqCst);
        tracing::info!("Starting TUN interceptor on fd {tun_fd}");

        // Wrap fd for async I/O
        let async_fd = AsyncFd::new(TunFd(tun_fd))
            .context("Failed to create AsyncFd for TUN fd")?;

        let running = self.running.clone();
        let connections = self.connections.clone();
        let config = self.config.clone();
        let local_tun_ip = self.local_tun_ip;

        // Shared references for the packet processing closures below
        let state = Arc::new(InterceptorState {
            connections,
            config,
            local_tun_ip,
            running: running.clone(),
        });

        // ── Main TUN read/write loop ─────────────────────────────
        //
        // Reads packets from the TUN fd, processes them through the
        // engine handler, and writes results back.
        //
        // Injection (modify/drop/inject actions) happens directly in
        // the PacketAction match arm below via write_to_tun().

        let mut buf = vec![0u8; 65535]; // Max IP packet size

        'main_loop: while running.load(Ordering::SeqCst) {
            // Wait for readability
            let mut guard = match async_fd.readable().await {
                Ok(g) => g,
                Err(e) => {
                    tracing::error!("TUN fd readability error: {e}");
                    break;
                }
            };

            // Read from TUN fd
            let n = match unsafe {
                libc::read(
                    tun_fd,
                    buf.as_mut_ptr() as *mut std::ffi::c_void,
                    buf.len(),
                )
            } {
                n if n > 0 => n as usize,
                0 => {
                    tracing::info!("TUN fd closed (EOF)");
                    break;
                }
                err => {
                    let e = std::io::Error::last_os_error();
                    if e.kind() == std::io::ErrorKind::WouldBlock {
                        guard.retain_ready();
                        continue;
                    }
                    tracing::error!("TUN read error: {e}");
                    break;
                }
            };

            guard.retain_ready();

            let raw_packet = Bytes::copy_from_slice(&buf[..n]);

            // Parse the raw IP packet
            let parsed = match CapturedPacket::from_raw(raw_packet.clone()) {
                Ok(p) => p,
                Err(_) => {
                    // Non-TCP or unparseable — forward to TUN
                    write_to_tun(tun_fd, &raw_packet);
                    continue;
                }
            };

            // Determine direction
            let is_outbound = parsed.ip.src_ip == local_tun_ip;
            let conn_id = if is_outbound {
                parsed.outbound_id()
            } else {
                parsed.inbound_id()
            };

            // Look up or create connection
            let conn = {
                let mut guard = state.connections.lock();
                guard.get(&conn_id).cloned()
            };

            let action = if let Some(conn) = &conn {
                // Connection is tracked — process through handler
                if is_outbound {
                    engine.handle_outbound(conn.clone(), raw_packet.clone()).await
                } else {
                    engine.handle_inbound(conn.clone(), raw_packet.clone()).await
                }
            } else if is_outbound
                && parsed.tcp.flags.syn()
                && !parsed.tcp.flags.ack()
                && !parsed.tcp.flags.rst()
            {
                // New outbound TCP SYN — create connection and process
                let new_conn = {
                    let s = state.clone();
                    // Generate fake_data from config
                    let cfg = s.config.read();
                    let fake_data = ClientHelloBuilder::generate(cfg.fake_sni.as_bytes());
                    let id = conn_id;
                    drop(cfg);
                    // Create ManagedConnection
                    let local_addr = std::net::SocketAddr::new(
                        std::net::IpAddr::V4(parsed.ip.src_ip),
                        parsed.tcp.src_port,
                    );
                    let remote_addr = std::net::SocketAddr::new(
                        std::net::IpAddr::V4(parsed.ip.dst_ip),
                        parsed.tcp.dst_port,
                    );
                    let cfg = s.config.read();
                    let managed = Arc::new(ManagedConnection::new(
                        id,
                        fake_data,
                        cfg,
                        local_addr,
                        remote_addr,
                        s.local_tun_ip,
                    ));
                    managed
                };

                // Insert into map
                {
                    let mut guard = state.connections.lock();
                    guard.insert(conn_id, new_conn.clone());
                }

                // Process through handler
                engine.handle_outbound(new_conn.clone(), raw_packet.clone()).await
            } else {
                // Unknown packet — let handler decide
                engine.handle_unknown_packet(raw_packet.clone())
            };

            // Apply the action to the TUN fd
            match action {
                PacketAction::Forward => {
                    // Write the original packet back to TUN
                    write_to_tun(tun_fd, &raw_packet);
                }
                PacketAction::Drop => {
                    // Do not forward
                }
                PacketAction::Modify(modified) => {
                    // Write modified version instead of original
                    write_to_tun(tun_fd, &modified);
                }
                PacketAction::Inject(injected) => {
                    // Write original AND the injected packet
                    write_to_tun(tun_fd, &raw_packet);
                    write_to_tun(tun_fd, &injected);
                }
            }
        }

        tracing::info!("TUN interceptor loop exited");
        Ok(())
    }

    async fn stop(&self) -> Result<()> {
        self.running.store(false, Ordering::SeqCst);
        tracing::info!("TUN interceptor stopping");
        Ok(())
    }
}

// ── Internal state shared across packet processing ─────────────

struct InterceptorState {
    connections: Arc<Mutex<HashMap<ConnectionId, Arc<ManagedConnection>>>>,
    config: DynamicConfig,
    local_tun_ip: Ipv4Addr,
    running: Arc<AtomicBool>,
}

// ── TUN fd write helper ───────────────────────────────────────

/// Write raw bytes to the TUN fd.  Used for both forwarded and
/// injected packets.
fn write_to_tun(fd: i32, data: &[u8]) {
    let written = unsafe {
        libc::write(
            fd,
            data.as_ptr() as *const std::ffi::c_void,
            data.len(),
        )
    };
    if written < 0 {
        let e = std::io::Error::last_os_error();
        if e.kind() != std::io::ErrorKind::WouldBlock {
            tracing::warn!("TUN write error: {e}");
        }
    }
}

// ── JNI Bridge (stub — for future use) ─────────────────────────
//
// These JNI stubs remain for completeness.  The primary TUN fd path
// is via the C API (mamadvpn_set_tun_fd → C ABI → Dart FFI).

pub mod jni {
    use super::*;

    #[no_mangle]
    pub extern "system" fn Java_com_mamadvpn_vpn_MamadVPNService_nativeInit(
        _env: *mut std::ffi::c_void,
        _thiz: *mut std::ffi::c_void,
        _config_json: *const std::os::raw::c_char,
    ) -> i32 {
        tracing::info!("JNI: nativeInit called");
        0
    }

    #[no_mangle]
    pub extern "system" fn Java_com_mamadvpn_vpn_MamadVPNService_nativeStart(
        _env: *mut std::ffi::c_void,
        _thiz: *mut std::ffi::c_void,
        _tun_fd: i32,
    ) -> i32 {
        tracing::info!("JNI: nativeStart called with fd={_tun_fd}");
        0
    }

    #[no_mangle]
    pub extern "system" fn Java_com_mamadvpn_vpn_MamadVPNService_nativeStop(
        _env: *mut std::ffi::c_void,
        _thiz: *mut std::ffi::c_void,
    ) -> i32 {
        tracing::info!("JNI: nativeStop called");
        0
    }

    #[no_mangle]
    pub extern "system" fn Java_com_mamadvpn_vpn_MamadVPNService_nativeReadPacket(
        _env: *mut std::ffi::c_void,
        _thiz: *mut std::ffi::c_void,
        _buf: *mut u8,
        _len: i32,
    ) -> i32 {
        0
    }

    #[no_mangle]
    pub extern "system" fn Java_com_mamadvpn_vpn_MamadVPNService_nativeWritePacket(
        _env: *mut std::ffi::c_void,
        _thiz: *mut std::ffi::c_void,
        _buf: *const u8,
        _len: i32,
    ) -> i32 {
        0
    }
}
