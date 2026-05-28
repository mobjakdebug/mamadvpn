//! # Linux Packet Interception Backend
//!
//! Implements the `PacketInterceptor` trait for Linux using:
//!
//! * **NFQUEUE** (iptables `NFQUEUE` target) — user-space packet interception
//!   via `libnetfilter_queue`.  Requires `CAP_NET_ADMIN`.
//! * **Raw socket injection** — for sending modified/injected packets when the
//!   bypass handler returns `Modify` or `Inject`.
//!
//! ## Architecture
//!
//! ```text
//! ┌─────────────┐   iptables NFQUEUE   ┌──────────────────┐
//! │    Kernel    │ ──────────────────►  │  NFQUEUE thread   │
//! │  Network     │                     │  (blocking, sync)  │
//! │  Stack       │ ◄────────────────── │  verdict + modify  │
//! └─────────────┘     accept / drop    └────────┬─────────┘
//!                                               │
//!                                     std::sync::mpsc channel
//!                                               │
//!                                         ┌─────▼──────┐
//!                                         │ Bridge task │
//!                                         │ (spawn_blk) │
//!                                         └─────┬──────┘
//!                                               │
//!                                   tokio::sync::mpsc channel
//!                                               │
//!                                         ┌─────▼──────┐
//!                                         │ PacketHndlr│
//!                                         │ (engine)    │
//!                                         └────────────┘
//! ```
//!
//! ## iptables Setup
//!
//! Before starting the interceptor, the user must add iptables rules to
//! direct traffic to the NFQUEUE:
//!
//! ```bash
//! # Redirect outbound TCP to queue 0
//! iptables -I OUTPUT -p tcp -j NFQUEUE --queue-num 0
//!
//! # Redirect inbound TCP to queue 0
//! iptables -I INPUT -p tcp -j NFQUEUE --queue-num 0
//! ```
//!
//! ## Injection
//!
//! When the bypass pipeline returns `PacketAction::Inject` or `PacketAction::Modify`,
//! the original packet is dropped from the queue and the modified/injected packet
//! is sent via a raw socket (`AF_INET`, `SOCK_RAW`, IPPROTO_RAW).

use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};

use anyhow::{Context, Result};
use async_trait::async_trait;
use bytes::Bytes;
use nix::sys::socket::{sendto, SockaddrIn, SockFlag};
use nix::unistd::close;

use mamadvpn_common::{ConnectionId, CapturedPacket};
use mamadvpn_core::interceptor::{PacketAction, PacketHandler, PacketInterceptor};

// ---------------------------------------------------------------------------
// NFQUEUE verdict constants (libnetfilter_queue)
// ---------------------------------------------------------------------------

const NF_ACCEPT: u32 = 1;
const NF_DROP: u32 = 0;

/// Handle to signal the bridge task to stop.
///
/// The bridge task loops on a blocking `recv()` from the mpsc channel.
/// To stop it without waiting for the NFQUEUE thread to exit (which never
/// happens because `loop_run()` blocks forever), we send a shutdown signal
/// through this dedicated channel.
type StopSignal = Arc<Mutex<Option<mpsc::Sender<()>>>>;

/// Linux NFQUEUE-based packet interceptor.

pub struct NfqueueInterceptor {
    queue_num: u16,
    running: Arc<AtomicBool>,
    /// Sender used to signal the bridge task to exit on `stop()`.
    stop_tx: StopSignal,
}

impl NfqueueInterceptor {
    /// Create a new NFQUEUE interceptor.
    ///
    /// Requires that `iptables -I FORWARD -j NFQUEUE --queue-num <n>` (or
    /// similar INPUT/OUTPUT rules) has been configured.
    pub fn new(queue_num: u16) -> Self {
        Self {
            queue_num,
            running: Arc::new(AtomicBool::new(false)),
            stop_tx: Arc::new(Mutex::new(None)),
        }
    }
}

#[async_trait]
impl PacketInterceptor for NfqueueInterceptor {
    async fn start(self: Box<Self>, engine: Arc<dyn PacketHandler>) -> Result<()> {
        tracing::info!(queue = self.queue_num, "Starting Linux NFQUEUE interceptor");

        self.running.store(true, Ordering::SeqCst);

        // Create a shutdown channel for the bridge task
        let (stop_tx, stop_rx): (mpsc::Sender<()>, mpsc::Receiver<()>) = mpsc::channel();
        *self.stop_tx.lock().unwrap() = Some(stop_tx);

        // Open a raw socket for packet injection when the bypass pipeline
        // returns Modify or Inject actions.
        let inject_sock = RawInjectSocket::new()
            .context("Failed to open raw injection socket")?;

        // Create the sync↔async bridge channels.
        //
        // The NFQUEUE callback runs in a blocking thread (libnetfilter_queue's
        // event loop).  It sends captured packets through this channel, and
        // receives the verdict (ACCEPT / DROP) back through a per-packet
        // oneshot channel.
        let (packet_tx, packet_rx): (
            mpsc::Sender<NfqueuePacketEvent>,
            mpsc::Receiver<NfqueuePacketEvent>,
        ) = mpsc::channel();

        let queue_num = self.queue_num;
        let running = self.running.clone();

        // ── Thread 1: NFQUEUE blocking event loop (detached) ─────
        //
        // libnetfilter_queue's event loop is synchronous and blocking.
        // We run it on a dedicated OS thread.  The callback fires for
        // each intercepted packet and communicates via mpsc channels.
        //
        // The event loop runs until the process exits — `loop_run()` is
        // a blocking syscall that only returns on unbind or error.  Since
        // we don't have access to the `Queue` from outside the closure,
        // the thread is detached.  On process shutdown, the kernel cleans
        // up the NFQUEUE queue automatically.
        //
        // We pass owned `running` (Arc) and `packet_tx` so the closure
        // satisfies the `'static` lifetime required by nfqueue::Queue.
        let _nfqueue_handle = std::thread::Builder::new()
            .name("nfqueue-event-loop".into())
            .spawn(move || {
                if let Err(e) = run_nfqueue_loop(queue_num, packet_tx, running) {
                    tracing::error!("NFQUEUE event loop failed: {e}");
                }
            })
            .context("Failed to spawn NFQUEUE event loop thread")?;

        // ── Thread 2: Packet processing bridge (spawn_blocking) ────
        //
        // This bridge task sits between the sync NFQUEUE callback and
        // the async engine.  It reads from the mpsc channel (blocking),
        // calls the async engine via `Handle::block_on`, and sends the
        // verdict back to the NFQUEUE callback.
        //
        // The bridge also listens on `stop_rx` — when `stop()` is called,
        // a message is sent on this channel, causing the bridge to exit
        // its event loop.
        let engine_clone = engine.clone();
        let inject_sock = Arc::new(inject_sock);
        let bridge_handle = tokio::task::spawn_blocking(move || {
            let rt_handle = tokio::runtime::Handle::current();
            loop {
                // Select between packet events and stop signal
                let event = if let Ok(()) = stop_rx.try_recv() {
                    tracing::info!("Bridge stop signal received, exiting");
                    break;
                } else {
                    // Block until a packet arrives or the channel closes
                    match packet_rx.recv() {
                        Ok(ev) => ev,
                        Err(_) => {
                            tracing::info!("NFQUEUE packet channel closed, bridge exiting");
                            break;
                        }
                    }
                };
                let NfqueuePacketEvent {
                    packet_data,
                    verdict_tx,
                } = event;

                // Determine direction: check src/dst IPs to decide
                // whether this is inbound or outbound.
                let is_inbound = infer_direction(&packet_data);

                // Parse the packet to extract the connection ID
                let conn_id = match CapturedPacket::from_slice(&packet_data) {
                    Ok(pkt) => {
                        let src_ip = pkt.ip_header.src_ip;
                        let dst_ip = pkt.ip_header.dst_ip;
                        let src_port = pkt.tcp_header.src_port;
                        let dst_port = pkt.tcp_header.dst_port;
                        ConnectionId::new(src_ip, src_port, dst_ip, dst_port)
                    }
                    Err(_) => {
                        // Can't parse → accept
                        let _ = verdict_tx.send(NF_ACCEPT);
                        continue;
                    }
                };

                // Look up the connection in the engine
                let action = if let Some(conn) = engine_clone.lookup_connection(&conn_id) {
                    let fut = if is_inbound {
                        engine_clone.handle_inbound(conn, Bytes::from(packet_data.clone()))
                    } else {
                        engine_clone.handle_outbound(conn, Bytes::from(packet_data.clone()))
                    };
                    rt_handle.block_on(fut)
                } else {
                    // Not a tracked connection → let it through
                    rt_handle.block_on(engine_clone.handle_unknown_packet(Bytes::from(packet_data)))
                };

                match action {
                    PacketAction::Forward => {
                        let _ = verdict_tx.send(NF_ACCEPT);
                    }
                    PacketAction::Drop => {
                        let _ = verdict_tx.send(NF_DROP);
                    }
                    PacketAction::Modify(data) => {
                        // Drop original, inject modified version
                        let _ = verdict_tx.send(NF_DROP);
                        if let Err(e) = inject_sock.send_raw(&data) {
                            tracing::warn!("Raw socket modify injection failed: {e}");
                        }
                    }
                    PacketAction::Inject(data) => {
                        // Let the original through, inject additional packet
                        let _ = verdict_tx.send(NF_ACCEPT);
                        if let Err(e) = inject_sock.send_raw(&data) {
                            tracing::warn!("Raw socket inject failed: {e}");
                        }
                    }
                }
            }
        });

        // Wait for the bridge task to complete.  The NFQUEUE event loop
        // thread is detached — it runs until process exit.
        bridge_handle.await?;

        tracing::info!("Linux NFQUEUE interceptor stopped");
        Ok(())
    }

    async fn stop(&self) -> Result<()> {
        self.running.store(false, Ordering::SeqCst);

        // Signal the bridge task to exit
        if let Some(tx) = self.stop_tx.lock().unwrap().take() {
            let _ = tx.send(());
        }

        tracing::info!("Linux NFQUEUE interceptor stop requested");
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// NFQUEUE event types
// ---------------------------------------------------------------------------

/// A packet intercepted by NFQUEUE, sent from the sync callback to the
/// async bridge.
struct NfqueuePacketEvent {
    packet_data: Vec<u8>,
    verdict_tx: mpsc::Sender<u32>,
}

// ---------------------------------------------------------------------------
// NFQUEUE event loop (blocking, runs on dedicated thread)
// ---------------------------------------------------------------------------

/// Run the NFQUEUE event loop.  This is a blocking function that creates
/// an `nfqueue::Queue`, sets the callback, and enters the dispatch loop.
fn run_nfqueue_loop(
    queue_num: u16,
    event_tx: mpsc::Sender<NfqueuePacketEvent>,
    running: Arc<AtomicBool>,
) -> Result<()> {
    // Open the NFQUEUE queue
    let mut queue = nfqueue::Queue::new(queue_num)
        .map_err(|e| anyhow::anyhow!("Failed to open NFQUEUE queue {queue_num}: {e}"))?;

    tracing::info!(queue_num, "NFQUEUE queue opened");

    // Bind to AF_INET (IPv4)
    queue
        .bind_pf(nfqueue::ProtocolFamily::INET)
        .map_err(|e| anyhow::anyhow!("Failed to bind NFQUEUE to AF_INET: {e}"))?;

    tracing::debug!("NFQUEUE bound to AF_INET");

    // Set copy mode to copy entire packets
    queue
        .set_copy_mode(nfqueue::CopyMode::PACKET, 0xFFFF)
        .map_err(|e| anyhow::anyhow!("Failed to set NFQUEUE copy mode: {e}"))?;

    tracing::debug!("NFQUEUE copy mode set to COPY_PACKET");

    // Set callback — this closure runs for each intercepted packet.
    // Both `event_tx` (`mpsc::Sender`, owned) and `running` (`Arc`)
    // satisfy the `'static` bound required by `nfqueue::Queue`.
    queue.set_callback(Box::new(move |packet| {
        if !running.load(Ordering::Relaxed) {
            return nfqueue::Verdict::DROP;
        }

        let packet_data = packet.to_vec();

        // Create a verdict response channel (one-shot per packet)
        let (verdict_tx, verdict_rx) = mpsc::channel();

        // Send the packet to the bridge for async processing
        let event = NfqueuePacketEvent {
            packet_data,
            verdict_tx,
        };

        if event_tx.send(event).is_err() {
            // Bridge is gone → accept
            return nfqueue::Verdict::ACCEPT;
        }

        // Block until the bridge sends the verdict back
        match verdict_rx.recv() {
            Ok(NF_DROP) => nfqueue::Verdict::DROP,
            _ => nfqueue::Verdict::ACCEPT,
        }
    }));

    tracing::info!("Entering NFQUEUE dispatch loop");

    // Enter the dispatch loop (blocking)
    queue
        .loop_run()
        .map_err(|e| anyhow::anyhow!("NFQUEUE dispatch loop exited with error: {e}"))?;

    tracing::info!("NFQUEUE dispatch loop ended");
    Ok(())
}

// ---------------------------------------------------------------------------
// Raw socket injection
// ---------------------------------------------------------------------------

/// A raw socket (`AF_INET`, `SOCK_RAW`, IPPROTO_RAW) used to inject
/// modified or new packets into the network stack.
///
/// Using a raw socket lets us send arbitrary IP packets.  The kernel
/// handles IP header checksum and fragmentation; we provide the IP
/// header ourselves.
struct RawInjectSocket {
    fd: std::os::unix::io::RawFd,
}

impl RawInjectSocket {
    /// Open a raw IP socket for packet injection.
    ///
    /// Requires `CAP_NET_RAW` (or root).
    fn new() -> Result<Self> {
        // Use libc::socket() directly because nix 0.29's SockProtocol
        // enum doesn't expose IPPROTO_RAW (255) which is required for
        // raw sockets that carry user-provided IP headers.
        let fd = unsafe {
            let fd = libc::socket(
                libc::AF_INET as libc::c_int,
                libc::SOCK_RAW as libc::c_int,
                libc::IPPROTO_RAW as libc::c_int,
            );
            if fd < 0 {
                return Err(std::io::Error::last_os_error()).context(
                    "Failed to create raw socket (CAP_NET_RAW required)",
                );
            }
            fd
        };
        tracing::debug!("Raw injection socket opened (fd={fd})");
        Ok(Self { fd })
    }

    /// Send a raw IP packet onto the wire.
    ///
    /// `data` must include the full IP header + TCP header + payload.
    fn send_raw(&self, data: &[u8]) -> Result<()> {
        // Parse the destination IP from the IP header (bytes 16..20)
        if data.len() < 20 {
            anyhow::bail!("Packet too short for IP header: {} bytes", data.len());
        }
        let dst_ip = Ipv4Addr::new(data[16], data[17], data[18], data[19]);
        let sock_addr = std::net::SocketAddrV4::new(dst_ip, 0);
        let addr = SockaddrIn::from(sock_addr);

        sendto(self.fd, data, &addr, SockFlag::empty())
            .context("Raw socket sendto failed")?;

        Ok(())
    }
}

impl Drop for RawInjectSocket {
    fn drop(&mut self) {
        let _ = close(self.fd);
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Infer whether a captured packet is inbound (from remote → local) or
/// outbound (from local → remote) by looking at the destination IP.
///
/// If the destination is a private / loopback / link-local address, it's
/// likely outbound (heading to the local client).  Otherwise, it's
/// likely inbound from the remote server.
///
/// This is a heuristic — the correct approach would be to use the
/// connection tracker, but we may not have a tracked connection yet
/// for the initial SYN.
fn infer_direction(packet: &[u8]) -> bool {
    if packet.len() < 20 {
        return false;
    }
    let dst_ip = Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);
    // If dst is private/loopback, it's going to the local client
    dst_ip.is_private() || dst_ip.is_loopback() || dst_ip.is_link_local()
}

// ---------------------------------------------------------------------------
// Raw socket interceptor (alternative to NFQUEUE)
// ---------------------------------------------------------------------------

/// Linux raw socket-based packet interceptor (fallback when NFQUEUE is
/// not available).
///
/// Uses `AF_PACKET` + `SOCK_RAW` to capture packets directly from the
/// network interface.  This is less efficient than NFQUEUE but works
/// without configuring iptables rules.
pub struct RawSocketInterceptor {
    /// BPF filter string (e.g., "tcp and host 1.2.3.4").
    filter: String,
    /// Interface name to bind to (empty = all interfaces).
    interface: String,
    running: Arc<AtomicBool>,
}

impl RawSocketInterceptor {
    pub fn new(filter: &str, interface: &str) -> Self {
        Self {
            filter: filter.to_string(),
            interface: interface.to_string(),
            running: Arc::new(AtomicBool::new(false)),
        }
    }
}

#[async_trait]
impl PacketInterceptor for RawSocketInterceptor {
    async fn start(self: Box<Self>, _engine: Arc<dyn PacketHandler>) -> Result<()> {
        tracing::info!(
            filter = %self.filter,
            interface = %self.interface,
            "Starting Linux raw socket interceptor"
        );

        // TODO: Full AF_PACKET capture loop using pnet or pcap crate.
        //
        // The raw socket approach requires:
        // 1. Creating an AF_PACKET socket with ETH_P_ALL protocol
        // 2. Binding to the interface (or listen on all)
        // 3. Setting a BPF filter to capture only matching traffic
        // 4. Looping: recvfrom() → parse → handle → [re-]send
        //
        // This is more complex than NFQUEUE because:
        // - We need to handle Ethernet + IP + TCP headers manually
        // - Packets must be re-injected via a separate raw socket
        // - The kernel doesn't automatically queue them for us
        //
        // For production use, prefer the NFQUEUE backend.

        tracing::warn!("Raw socket backend is a stub — all packets are accepted. \
                        Use the NFQUEUE backend for production.");

        self.running.store(true, Ordering::SeqCst);
        // Keep running until stopped (stub: just sleep)
        while self.running.load(Ordering::SeqCst) {
            tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
        }

        Ok(())
    }

    async fn stop(&self) -> Result<()> {
        self.running.store(false, Ordering::SeqCst);
        tracing::info!("Linux raw socket interceptor stopped");
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_infer_direction_outbound() {
        // Packet to 10.0.0.1 (private) → outbound
        let mut packet = vec![0u8; 40];
        packet[16] = 10;  // 10.0.0.1
        packet[17] = 0;
        packet[18] = 0;
        packet[19] = 1;
        assert!(infer_direction(&packet), "10.0.0.1 should be outbound");
    }

    #[test]
    fn test_infer_direction_inbound() {
        // Packet to 1.1.1.1 (public) → inbound
        let mut packet = vec![0u8; 40];
        packet[16] = 1;   // 1.1.1.1
        packet[17] = 1;
        packet[18] = 1;
        packet[19] = 1;
        assert!(!infer_direction(&packet), "1.1.1.1 should be inbound");
    }

    #[test]
    fn test_infer_direction_loopback() {
        let mut packet = vec![0u8; 40];
        packet[16] = 127; // 127.0.0.1
        packet[17] = 0;
        packet[18] = 0;
        packet[19] = 1;
        assert!(infer_direction(&packet), "127.0.0.1 should be outbound");
    }
}
