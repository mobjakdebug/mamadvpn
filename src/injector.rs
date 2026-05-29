//! Kernel-level DPI bypass using WinDivert packet injection.
//!
//! Implements the "wrong_seq" strategy: injects a fake TLS ClientHello with a
//! whitelisted SNI that tricks the DPI firewall into classifying the connection
//! as safe. The fake packet has a deliberately wrong TCP sequence number so the
//! target server silently drops it, while the real traffic flows unimpeded.

use std::net::{IpAddr, Ipv4Addr};
use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use anyhow::{Context, Result};
use dashmap::DashMap;
use once_cell::sync::Lazy;
use tokio::sync::Notify;
use windivert::prelude::*;

// ── ClientHello template (ported from Python packet_templates.py) ──────────
// The static parts of the TLS 1.2 ClientHello template are decoded once.
// The original template is 517 bytes with "mci.ir" as the baked-in SNI.
// `build_client_hello` swaps in any target SNI while maintaining 517 bytes.

const TLS_CH_TEMPLATE_HEX: &str = "\
1603010200010001fc030341d5b549d9cd1adfa7296c8418d157dc7b624c842824\
ff493b9375bb48d34f2b20bf018bcc90a7c89a230094815ad0c15b736e38c01209\
d72d282cb5e2105328150024130213031301c02cc030c02bc02fcca9cca8c024c0\
28c023c027009f009e006b006700ff0100018f0000000b00090000066d63692e69\
72000b000403000102000a00160014001d0017001e001900180100010101020103\
0104002300000010000e000c02683208687474702f312e31001600000017000000\
000d002a0028040305030603080708080809080a080b0804080508060401050106\
01030303010302040205020602002b00050403040303002d000201010033002600\
24001d0020435bacc4d05f9d41fef44ab3ad55616c36e0613473e2338770efdaa9\
8693d217001500d500000000000000000000000000000000000000000000000000\
000000000000000000000000000000000000000000000000000000000000000000\
000000000000000000000000000000000000000000000000000000000000000000\
000000000000000000000000000000000000000000000000000000000000000000\
000000000000000000000000000000000000000000000000000000000000000000\
000000000000000000000000000000000000000000000000000000000000000000\
0000000000000000000000000000000000";

/// Lazily-decoded TLS ClientHello template (517 bytes).
static TLS_CH_TEMPLATE: Lazy<Vec<u8>> =
    Lazy::new(|| hex::decode(TLS_CH_TEMPLATE_HEX).expect("Invalid TLS ClientHello template hex"));

// Pre-sliced static parts from the template (offsets based on 6-byte SNI "mci.ir")
// Using Vec<u8> instead of &[u8] to avoid lifetime inference issues with Lazy
static STATIC1: Lazy<Vec<u8>> = Lazy::new(|| TLS_CH_TEMPLATE[..11].to_vec());
static STATIC3: Lazy<Vec<u8>> = Lazy::new(|| TLS_CH_TEMPLATE[76..120].to_vec());
static STATIC4: Lazy<Vec<u8>> = Lazy::new(|| TLS_CH_TEMPLATE[133..268].to_vec());

/// Build a complete TLS 1.2 ClientHello packet with the given parameters.
///
/// * `rnd` – 32 random bytes for ClientRandom
/// * `sess_id` – 32 bytes for Session ID
/// * `target_sni` – SNI hostname to inject (the "fake" whitelisted SNI)
/// * `key_share` – 32 bytes for the key share extension
pub fn build_client_hello(rnd: &[u8], sess_id: &[u8], target_sni: &[u8], key_share: &[u8]) -> Vec<u8> {
    let static2: &[u8] = &[0x20];
    let static5: &[u8] = &[0x00, 0x15];

    // Build SNI extension dynamically
    // Format: ext_len(2) + name_list_len(2) + name_type(1) + name_len(2) + name
    let sni_ext_len = (target_sni.len() + 5) as u16;
    let sni_inner_len = (target_sni.len() + 3) as u16;
    let mut server_name_ext = Vec::with_capacity(7 + target_sni.len());
    server_name_ext.extend_from_slice(&sni_ext_len.to_be_bytes());
    server_name_ext.extend_from_slice(&sni_inner_len.to_be_bytes());
    server_name_ext.push(0x00); // name_type = host_name
    server_name_ext.extend_from_slice(&(target_sni.len() as u16).to_be_bytes());
    server_name_ext.extend_from_slice(target_sni);

    // Build padding extension: length(2) + zeros
    let padding_len = 219usize.saturating_sub(target_sni.len());
    let mut padding_ext = Vec::with_capacity(2 + padding_len);
    padding_ext.extend_from_slice(&(padding_len as u16).to_be_bytes());
    padding_ext.resize(2 + padding_len, 0x00);

    // Assemble the full ClientHello (always 517 bytes regardless of SNI length)
    let mut result = Vec::with_capacity(517);
    result.extend_from_slice(&STATIC1);          // 11 bytes
    result.extend_from_slice(rnd);               // 32 bytes (offsets 11..43)
    result.extend_from_slice(static2);           // 1 byte
    result.extend_from_slice(sess_id);           // 32 bytes (offsets 44..76)
    result.extend_from_slice(&STATIC3);          // 44 bytes (offsets 76..120)
    result.extend_from_slice(&server_name_ext);  // 7 + len(sni) bytes
    result.extend_from_slice(&STATIC4);          // 135 bytes
    result.extend_from_slice(key_share);         // 32 bytes
    result.extend_from_slice(static5);           // 2 bytes
    result.extend_from_slice(&padding_ext);      // 2 + (219 - len(sni)) bytes

    debug_assert_eq!(result.len(), 517, "ClientHello must always be 517 bytes");
    result
}

// ── Connection tracking ────────────────────────────────────────────────────

/// Type alias for the WinDivert connection map key.
/// (src_ip, src_port, dst_ip, dst_port)
pub type ConnKey = (Ipv4Addr, u16, Ipv4Addr, u16);

/// Thread-safe shared state for a single monitored TCP connection.
pub struct FakeInjectiveConnection {
    /// Whether this connection is still being monitored.
    pub monitor: AtomicBool,
    /// The local TCP sequence number from the SYN packet (-1 if not yet seen).
    pub syn_seq: AtomicI64,
    /// The remote TCP sequence number from the SYN-ACK packet (-1 if not yet seen).
    pub syn_ack_seq: AtomicI64,
    /// Source IP address.
    pub src_ip: Ipv4Addr,
    /// Destination IP address.
    pub dst_ip: Ipv4Addr,
    /// Source port.
    pub src_port: u16,
    /// Destination port.
    pub dst_port: u16,
    /// Connection identifier tuple.
    pub id: ConnKey,
    /// Mutex serialising access from the WinDivert thread and async tasks.
    pub lock: Mutex<()>,
    /// The fake TLS ClientHello payload to inject.
    pub fake_data: Vec<u8>,
    /// True after the real ACK has been forwarded and the fake-send is scheduled.
    pub sch_fake_sent: AtomicBool,
    /// True after the fake packet has been sent via WinDivert.
    pub fake_sent: AtomicBool,
    /// Tokio notify primitive used to wake the async handler when injection completes.
    pub t2a_notify: Notify,
    /// Message set by the WinDivert thread describing the outcome.
    pub t2a_msg: Mutex<String>,
    /// The bypass method ("wrong_seq").
    pub bypass_method: String,
}

impl FakeInjectiveConnection {
    pub fn new(
        src_ip: Ipv4Addr,
        dst_ip: Ipv4Addr,
        src_port: u16,
        dst_port: u16,
        fake_data: Vec<u8>,
        bypass_method: &str,
    ) -> Self {
        Self {
            monitor: AtomicBool::new(true),
            syn_seq: AtomicI64::new(-1),
            syn_ack_seq: AtomicI64::new(-1),
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            id: (src_ip, src_port, dst_ip, dst_port),
            lock: Mutex::new(()),
            fake_data,
            sch_fake_sent: AtomicBool::new(false),
            fake_sent: AtomicBool::new(false),
            t2a_notify: Notify::new(),
            t2a_msg: Mutex::new(String::new()),
            bypass_method: bypass_method.to_string(),
        }
    }
}

// ── The WinDivert packet injector ──────────────────────────────────────────

/// Builds the WinDivert filter string for the given interface and target IPs.
/// WinDivert filters MUST use IP addresses, not hostnames.
pub fn build_filter(interface_ipv4: &str, connect_ip: &str) -> String {
    format!(
        "tcp and ((ip.SrcAddr == {} and ip.DstAddr == {}) or (ip.SrcAddr == {} and ip.DstAddr == {}))",
        interface_ipv4, connect_ip, connect_ip, interface_ipv4
    )
}

/// Discovers the default IPv4 address of the local machine by connecting a
/// UDP socket to a well-known address (Google DNS).
pub fn get_default_interface_ipv4() -> Option<Ipv4Addr> {
    use std::net::UdpSocket;
    let socket = UdpSocket::bind("0.0.0.0:0").ok()?;
    socket.connect("8.8.8.8:53").ok()?;
    match socket.local_addr().ok()? {
        std::net::SocketAddr::V4(v4) => Some(*v4.ip()),
        _ => None,
    }
}

/// Extract IPv4 and TCP header information common across windivert API variants.
///
/// Different versions of the `windivert` crate expose slightly different APIs.
/// This helper abstracts the extraction so the rest of the logic is crate-agnostic.
struct PacketInfo {
    is_inbound: bool,
    syn: bool,
    ack: bool,
    rst: bool,
    fin: bool,
    seq_num: u32,
    ack_num: u32,
    payload_len: u32,
    src_addr: Ipv4Addr,
    dst_addr: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
}

/// The main WinDivert packet processing loop. Runs in a dedicated OS thread.
///
/// # Arguments
/// * `filter` – WinDivert packet filter string.
/// * `connections` – Shared connection map keyed by `(src_ip, src_port, dst_ip, dst_port)`.
pub fn run_injector(
    filter: &str,
    connections: Arc<DashMap<ConnKey, FakeInjectiveConnection>>,
) -> Result<()> {
    let wd = WinDivert::new(filter, windivert::Layer::Network, 0, 0)
        .context("Failed to open WinDivert handle")?;

    loop {
        let mut packet = wd.recv().context("WinDivert recv error")?;

        let info = match extract_packet_info(&packet) {
            Some(i) => i,
            None => {
                // Non-TCP or unparseable; pass through
                let _ = wd.send(&packet, false);
                continue;
            }
        };

        let c_id: ConnKey = if info.is_inbound {
            (info.dst_addr, info.dst_port, info.src_addr, info.src_port)
        } else {
            (info.src_addr, info.src_port, info.dst_addr, info.dst_port)
        };

        match connections.get(&c_id) {
            Some(conn_ref) => {
                // Quick check under lock: is this connection still alive?
                {
                    let guard = conn_ref.lock.lock().unwrap();
                    if !conn_ref.monitor.load(Ordering::Acquire) {
                        drop(guard);
                        let _ = wd.send(&packet, false);
                        continue;
                    }
                }
                // Lock released — handlers will re-acquire as needed.
                // This is critical: `handle_outbound` does a sleep + re-lock,
                // and `std::sync::Mutex` is NOT reentrant.

                if info.is_inbound {
                    handle_inbound(&wd, &mut packet, &info, &conn_ref);
                } else {
                    handle_outbound(&wd, &mut packet, &info, &conn_ref);
                }
            }
            None => {
                // Connection not tracked; pass through
                let _ = wd.send(&packet, false);
            }
        }
    }
}

/// Extract common header fields from a WinDivert packet.
/// Abstracts over potential API differences between `windivert` crate versions.
fn extract_packet_info(packet: &WinDivertPacket) -> Option<PacketInfo> {
    let is_inbound = packet.is_inbound();

    let ip_hdr = packet.get_ip_header().or_else(|| packet.get_ipv6_header())?;
    let tcp = packet.get_tcp_header()?;

    // Normalise IPv6-mapped IPv4 addresses back to Ipv4Addr
    let src_addr = to_ipv4(ip_hdr.src_addr)?;
    let dst_addr = to_ipv4(ip_hdr.dst_addr)?;

    Some(PacketInfo {
        is_inbound,
        syn: tcp.syn,
        ack: tcp.ack,
        rst: tcp.rst,
        fin: tcp.fin,
        seq_num: tcp.seq_num,
        ack_num: tcp.ack_num,
        payload_len: tcp.payload_len as u32,
        src_addr,
        dst_addr,
        src_port: tcp.src_port,
        dst_port: tcp.dst_port,
    })
}

fn to_ipv4(addr: IpAddr) -> Option<Ipv4Addr> {
    match addr {
        IpAddr::V4(v4) => Some(v4),
        IpAddr::V6(v6) => v6.to_ipv4_mapped(),
    }
}

// ── Outbound packet handler ────────────────────────────────────────────────

fn handle_outbound(
    wd: &WinDivert,
    packet: &mut WinDivertPacket,
    info: &PacketInfo,
    conn: &FakeInjectiveConnection,
) {
    let _guard = conn.lock.lock().unwrap();

    if !conn.monitor.load(Ordering::Acquire) {
        return;
    }

    if conn.sch_fake_sent.load(Ordering::Acquire) {
        on_unexpected_locked(
            wd, packet, conn,
            "unexpected outbound packet, recv packet after fake sent!",
        );
        return;
    }

    // ── Outbound SYN ──────────────────────────────────────────────────
    if info.syn && !info.ack && !info.rst && !info.fin && info.payload_len == 0 {
        if info.ack_num != 0 {
            on_unexpected_locked(wd, packet, conn, "unexpected outbound syn packet, ack_num is not zero!");
            return;
        }
        let existing = conn.syn_seq.load(Ordering::Acquire);
        if existing != -1 && existing as u32 != info.seq_num {
            on_unexpected_locked(
                wd, packet, conn,
                &format!(
                    "unexpected outbound syn packet, seq not matched! {} {}",
                    info.seq_num, existing
                ),
            );
            return;
        }
        conn.syn_seq.store(info.seq_num as i64, Ordering::Release);
        let _ = wd.send(packet, false);
        return;
    }

    // ── Outbound ACK (handshake completion) ────────────────────────────
    if info.ack && !info.syn && !info.rst && !info.fin && info.payload_len == 0 {
        let syn_seq = conn.syn_seq.load(Ordering::Acquire);
        let syn_ack_seq = conn.syn_ack_seq.load(Ordering::Acquire);

        if syn_seq == -1 || (syn_seq as u32).wrapping_add(1) != info.seq_num {
            on_unexpected_locked(
                wd, packet, conn,
                &format!(
                    "unexpected outbound ack packet, seq not matched! {} {}",
                    info.seq_num, syn_seq
                ),
            );
            return;
        }
        if syn_ack_seq == -1 || info.ack_num != (syn_ack_seq as u32).wrapping_add(1) {
            on_unexpected_locked(
                wd, packet, conn,
                &format!(
                    "unexpected outbound ack packet, ack not matched! {} {}",
                    info.ack_num, syn_ack_seq
                ),
            );
            return;
        }

        // Forward the real ACK packet
        let _ = wd.send(packet, false);
        conn.sch_fake_sent.store(true, Ordering::Release);

        // Release the lock before sleeping (matches Python's thread-based approach)
        drop(_guard);

        // ── Inject the fake ClientHello packet ────────────────────────
        // 0.001s delay ensures the real ACK reaches the wire first
        thread::sleep(Duration::from_micros(1000));

        // Re-acquire lock and verify the connection is still monitored
        let _guard = conn.lock.lock().unwrap();
        if !conn.monitor.load(Ordering::Acquire) {
            return;
        }

        if conn.bypass_method == "wrong_seq" {
            inject_fake_packet(wd, packet, conn);
        } else {
            on_unexpected_locked(wd, packet, conn, &format!("unknown bypass method: {}", conn.bypass_method));
        }
        return;
    }

    on_unexpected_locked(wd, packet, conn, "unexpected outbound packet");
}

// ── Inbound packet handler ─────────────────────────────────────────────────

fn handle_inbound(
    wd: &WinDivert,
    packet: &mut WinDivertPacket,
    info: &PacketInfo,
    conn: &FakeInjectiveConnection,
) {
    let _guard = conn.lock.lock().unwrap();

    if !conn.monitor.load(Ordering::Acquire) {
        return;
    }

    let syn_seq = conn.syn_seq.load(Ordering::Acquire);

    if syn_seq == -1 {
        on_unexpected_locked(wd, packet, conn, "unexpected inbound packet, no syn sent!");
        return;
    }

    // ── Inbound SYN-ACK ───────────────────────────────────────────────
    if info.ack && info.syn && !info.rst && !info.fin && info.payload_len == 0 {
        let syn_ack_seq = conn.syn_ack_seq.load(Ordering::Acquire);
        if syn_ack_seq != -1 && syn_ack_seq as u32 != info.seq_num {
            on_unexpected_locked(
                wd, packet, conn,
                &format!(
                    "unexpected inbound syn-ack packet, seq change! {} {}",
                    info.seq_num, syn_ack_seq
                ),
            );
            return;
        }
        if info.ack_num != (syn_seq as u32).wrapping_add(1) {
            on_unexpected_locked(
                wd, packet, conn,
                &format!(
                    "unexpected inbound syn-ack packet, ack not matched! {} {}",
                    info.ack_num, syn_seq
                ),
            );
            return;
        }
        conn.syn_ack_seq.store(info.seq_num as i64, Ordering::Release);
        let _ = wd.send(packet, false);
        return;
    }

    // ── Inbound ACK of fake data ──────────────────────────────────────
    if info.ack && !info.syn && !info.rst && !info.fin
        && info.payload_len == 0
        && conn.fake_sent.load(Ordering::Acquire)
    {
        let syn_ack_seq = conn.syn_ack_seq.load(Ordering::Acquire);
        if syn_ack_seq == -1 || (syn_ack_seq as u32).wrapping_add(1) != info.seq_num {
            on_unexpected_locked(
                wd, packet, conn,
                &format!(
                    "unexpected inbound ack packet, seq not matched! {} {}",
                    info.seq_num, syn_ack_seq
                ),
            );
            return;
        }
        if info.ack_num != (syn_seq as u32).wrapping_add(1) {
            on_unexpected_locked(
                wd, packet, conn,
                &format!(
                    "unexpected inbound ack packet, ack not matched! {} {}",
                    info.ack_num, syn_seq
                ),
            );
            return;
        }

        // Success: the server acknowledged our fake packet (meaning it didn't
        // RST — DPI firewall cached the safe SNI, server silently dropped it).
        conn.monitor.store(false, Ordering::Release);
        *conn.t2a_msg.lock().unwrap() = "fake_data_ack_recv".to_string();
        conn.t2a_notify.notify_one();
        return;
    }

    on_unexpected_locked(wd, packet, conn, "unexpected inbound packet");
}

// ── Error helper (caller MUST hold conn.lock) ──────────────────────────────

fn on_unexpected_locked(
    wd: &WinDivert,
    packet: &WinDivertPacket,
    conn: &FakeInjectiveConnection,
    info: &str,
) {
    eprintln!("{}", info);
    conn.monitor.store(false, Ordering::Release);
    *conn.t2a_msg.lock().unwrap() = "unexpected_close".to_string();
    conn.t2a_notify.notify_one();
    let _ = wd.send(packet, false);
}

// ── Fake packet injection ──────────────────────────────────────────────────

/// Construct and send the fake TLS ClientHello packet with a wrong sequence
/// number. This is the core of the DPI bypass strategy.
///
/// The DPI firewall inspects this packet, sees the whitelisted SNI, and caches
/// the connection as safe. The target server receives a packet with a sequence
/// number that is behind the expected window and silently drops it (no RST
/// because the seq is within acceptable range, just not the next expected).
///
/// # Arguments
/// * `wd` – WinDivert handle for sending the injected packet.
/// * `packet` – The original outbound ACK packet (modified in-place for injection).
/// * `conn` – The tracked connection containing the fake `ClientHello` payload.
pub fn inject_fake_packet(
    wd: &WinDivert,
    packet: &mut WinDivertPacket,
    conn: &FakeInjectiveConnection,
) {
    let syn_seq = conn.syn_seq.load(Ordering::Acquire) as u32;
    let fake_payload_len = conn.fake_data.len() as u32;

    // Set PSH flag so the DPI firewall processes the payload immediately
    packet.set_tcp_psh(true);

    // Extend IP packet length to account for the fake payload
    let old_ip_len = packet.get_ip_packet_len();
    packet.set_ip_packet_len(old_ip_len + fake_payload_len as u16);

    // Set the fake TLS ClientHello as the TCP payload
    packet.set_tcp_payload(&conn.fake_data);

    // Increment IPv4 identification field (if IPv4)
    if let Some(ipv4_hdr) = packet.get_ipv4_header() {
        packet.set_ipv4_ident(ipv4_hdr.ident.wrapping_add(1) & 0xffff);
    }

    // ── THE CRITICAL WRONG SEQUENCE FORMULA ───────────────────────────
    // seq = (syn_seq + 1 - payload_len) & 0xffffffff
    //
    // The sequence number is set BEHIND the expected next sequence number.
    // The target server expects `syn_seq + 1` but receives a packet starting
    // at `syn_seq + 1 - payload_len`. Since the sequence number is still
    // within the receive window, the server silently drops the duplicate/
    // out-of-order segment rather than sending a RST.
    //
    // Meanwhile, the DPI firewall has already processed the TLS ClientHello
    // and cached this connection as "safe" based on the whitelisted SNI.
    let wrong_seq = syn_seq.wrapping_add(1).wrapping_sub(fake_payload_len);
    packet.set_tcp_seq_num(wrong_seq);

    conn.fake_sent.store(true, Ordering::Release);

    // Inject the fake packet (recalculate_checksum = true)
    let _ = wd.send(packet, true);
}

// ── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_client_hello_construction() {
        let rnd = [0xAAu8; 32];
        let sess_id = [0xBBu8; 32];
        let sni = b"auth.vercel.com";
        let key_share = [0xCCu8; 32];

        let ch = build_client_hello(&rnd, &sess_id, sni, &key_share);
        assert_eq!(ch.len(), 517, "ClientHello must be 517 bytes");

        // Verify the SNI appears in the packet
        let sni_str = std::str::from_utf8(sni).unwrap();
        let ch_str = String::from_utf8_lossy(&ch);
        assert!(ch_str.contains(sni_str), "ClientHello must contain the target SNI");

        // Verify random bytes at offset 11
        assert_eq!(&ch[11..43], &rnd);
        // Verify session ID at offset 44
        assert_eq!(&ch[44..76], &sess_id);
    }

    #[test]
    fn test_client_hello_different_sni_lengths() {
        let rnd = [0x11u8; 32];
        let sess_id = [0x22u8; 32];
        let key_share = [0x33u8; 32];

        // Short SNI
        let ch1 = build_client_hello(&rnd, &sess_id, b"x.com", &key_share);
        assert_eq!(ch1.len(), 517);

        // Long SNI
        let ch2 = build_client_hello(&rnd, &sess_id, b"very-long-subdomain.example.com", &key_share);
        assert_eq!(ch2.len(), 517);
    }

    #[test]
    fn test_wrong_seq_formula() {
        // Simulate the wrong_seq bitwise formula
        let syn_seq: u32 = 0x12345678;
        let payload_len: u32 = 517;
        let expected = syn_seq.wrapping_add(1).wrapping_sub(payload_len);
        let python_style = (syn_seq.wrapping_add(1).wrapping_sub(payload_len)) & 0xffffffff;

        assert_eq!(expected, python_style);
        assert_ne!(expected, syn_seq.wrapping_add(1));
        // The seq points BEFORE the expected next byte
        assert!(expected < syn_seq.wrapping_add(1));
    }

    #[test]
    fn test_build_filter() {
        let filter = build_filter("192.168.1.100", "1.2.3.4");
        assert!(filter.contains("192.168.1.100"));
        assert!(filter.contains("1.2.3.4"));
        assert!(filter.starts_with("tcp"));
    }

    #[test]
    fn test_lazy_template_loaded() {
        // Force evaluation of the Lazy
        let _ = &*TLS_CH_TEMPLATE;
        assert_eq!(TLS_CH_TEMPLATE.len(), 517);
    }
}
