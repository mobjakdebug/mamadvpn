//! Kernel-level DPI bypass using WinDivert packet injection.
//!
//! Implements the "wrong_seq" strategy: injects a fake TLS ClientHello with a
//! whitelisted SNI that tricks the DPI firewall into classifying the connection
//! as safe. The fake packet has a deliberately wrong TCP sequence number so the
//! target server silently drops it, while the real traffic flows unimpeded.

use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use anyhow::{Context, Result};
use dashmap::DashMap;
use once_cell::sync::Lazy;
use tokio::sync::Notify;
use windivert::prelude::*;
use windivert_sys::ChecksumFlags;

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
static STATIC1: Lazy<Vec<u8>> = Lazy::new(|| TLS_CH_TEMPLATE[..11].to_vec());
static STATIC3: Lazy<Vec<u8>> = Lazy::new(|| TLS_CH_TEMPLATE[76..120].to_vec());
static STATIC4: Lazy<Vec<u8>> = Lazy::new(|| TLS_CH_TEMPLATE[133..268].to_vec());

/// Build a complete TLS 1.2 ClientHello packet with the given parameters.
pub fn build_client_hello(
    rnd: &[u8],
    sess_id: &[u8],
    target_sni: &[u8],
    key_share: &[u8],
) -> Vec<u8> {
    let static2: &[u8] = &[0x20];
    let static5: &[u8] = &[0x00, 0x15];

    // Build SNI extension dynamically
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
    result.extend_from_slice(&STATIC1); // 11 bytes
    result.extend_from_slice(rnd); // 32 bytes (offsets 11..43)
    result.extend_from_slice(static2); // 1 byte
    result.extend_from_slice(sess_id); // 32 bytes (offsets 44..76)
    result.extend_from_slice(&STATIC3); // 44 bytes (offsets 76..120)
    result.extend_from_slice(&server_name_ext); // 7 + len(sni) bytes
    result.extend_from_slice(&STATIC4); // 135 bytes
    result.extend_from_slice(key_share); // 32 bytes
    result.extend_from_slice(static5); // 2 bytes
    result.extend_from_slice(&padding_ext); // 2 + (219 - len(sni)) bytes

    debug_assert_eq!(result.len(), 517, "ClientHello must always be 517 bytes");
    result
}

// ── Manual IPv4/TCP header parsing ─────────────────────────────────────────
// WinDivert 0.7.x provides raw packet bytes — we parse the headers ourselves.

const IPV4_PROTOCOL_TCP: u8 = 6;

struct IpHeader {
    src_addr: Ipv4Addr,
    dst_addr: Ipv4Addr,
    ident: u16,
    header_length: usize, // IHL * 4
}

/// Parse an IPv4 header from raw packet bytes.
/// Returns `None` if the packet isn't IPv4 or doesn't contain TCP.
fn parse_ipv4(data: &[u8]) -> Option<IpHeader> {
    if data.len() < 20 {
        return None;
    }
    let version_ihl = data[0];
    let version = version_ihl >> 4;
    let ihl = (version_ihl & 0x0f) as usize;
    if version != 4 {
        return None;
    }
    let header_length = ihl * 4;
    if data.len() < header_length || data[9] != IPV4_PROTOCOL_TCP {
        return None;
    }
    Some(IpHeader {
        src_addr: Ipv4Addr::new(data[12], data[13], data[14], data[15]),
        dst_addr: Ipv4Addr::new(data[16], data[17], data[18], data[19]),
        ident: u16::from_be_bytes([data[4], data[5]]),
        header_length,
    })
}

struct TcpHeader {
    src_port: u16,
    dst_port: u16,
    seq_num: u32,
    ack_num: u32,
    data_offset: usize, // TCP header length in bytes
    syn: bool,
    ack: bool,
    rst: bool,
    fin: bool,
    psh: bool,
}

/// Parse a TCP header from raw packet bytes at the given IP header offset.
fn parse_tcp(data: &[u8], ip_hdr_len: usize) -> Option<TcpHeader> {
    let tcp_start = ip_hdr_len;
    if data.len() < tcp_start + 20 {
        return None;
    }
    let data_offset = ((data[tcp_start + 12] >> 4) as usize) * 4;
    if data.len() < tcp_start + data_offset {
        return None;
    }
    let flags = data[tcp_start + 13];
    Some(TcpHeader {
        src_port: u16::from_be_bytes([data[tcp_start], data[tcp_start + 1]]),
        dst_port: u16::from_be_bytes([data[tcp_start + 2], data[tcp_start + 3]]),
        seq_num: u32::from_be_bytes([
            data[tcp_start + 4],
            data[tcp_start + 5],
            data[tcp_start + 6],
            data[tcp_start + 7],
        ]),
        ack_num: u32::from_be_bytes([
            data[tcp_start + 8],
            data[tcp_start + 9],
            data[tcp_start + 10],
            data[tcp_start + 11],
        ]),
        data_offset,
        syn: flags & 0x02 != 0,
        ack: flags & 0x10 != 0,
        rst: flags & 0x04 != 0,
        fin: flags & 0x01 != 0,
        psh: flags & 0x08 != 0,
    })
}

/// Convenience struct holding the fields we inspect during connection tracking.
struct PacketInfo {
    is_inbound: bool,
    syn: bool,
    ack: bool,
    rst: bool,
    fin: bool,
    seq_num: u32,
    ack_num: u32,
    payload_len: usize,
    src_addr: Ipv4Addr,
    dst_addr: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    ip_header_len: usize,
    tcp_header_len: usize,
}

/// Extract header info from raw IP+TCP packet bytes.
fn extract_packet_info(data: &[u8], is_inbound: bool) -> Option<PacketInfo> {
    let ip = parse_ipv4(data)?;
    let tcp = parse_tcp(data, ip.header_length)?;
    // Payload length = total packet length - IP header - TCP header
    let payload_len = data
        .len()
        .saturating_sub(ip.header_length + tcp.data_offset);

    Some(PacketInfo {
        is_inbound,
        syn: tcp.syn,
        ack: tcp.ack,
        rst: tcp.rst,
        fin: tcp.fin,
        seq_num: tcp.seq_num,
        ack_num: tcp.ack_num,
        payload_len,
        src_addr: ip.src_addr,
        dst_addr: ip.dst_addr,
        src_port: tcp.src_port,
        dst_port: tcp.dst_port,
        ip_header_len: ip.header_length,
        tcp_header_len: tcp.data_offset,
    })
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

/// The main WinDivert packet processing loop. Runs in a dedicated OS thread.
pub fn run_injector(
    filter: &str,
    connections: Arc<DashMap<ConnKey, FakeInjectiveConnection>>,
) -> Result<()> {
    let wd = WinDivert::network(filter, 0, Default::default())
        .context("Failed to open WinDivert handle")?;

    let mut buf = vec![0u8; 65535];

    loop {
        let packet = match wd.recv(&mut buf) {
            Ok(p) => p,
            Err(e) => {
                eprintln!("WinDivert recv error: {}", e);
                continue;
            }
        };

        let is_inbound = !packet.address.outbound();

        let info = match extract_packet_info(&packet.data, is_inbound) {
            Some(i) => i,
            None => {
                // Non-TCP or unparseable; pass through
                let _ = wd.send(&packet);
                continue;
            }
        };

        let c_id: ConnKey = if is_inbound {
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
                        let _ = wd.send(&packet);
                        continue;
                    }
                }
                // Lock released — handlers will re-acquire as needed.

                if is_inbound {
                    handle_inbound(&wd, &packet, &info, &conn_ref);
                } else {
                    handle_outbound(&wd, &packet, &info, &conn_ref);
                }
            }
            None => {
                // Connection not tracked; pass through
                let _ = wd.send(&packet);
            }
        }
    }
}

// ── Outbound packet handler ────────────────────────────────────────────────

fn handle_outbound(
    wd: &WinDivert<NetworkLayer>,
    packet: &WinDivertPacket<'_, NetworkLayer>,
    info: &PacketInfo,
    conn: &FakeInjectiveConnection,
) {
    let _guard = conn.lock.lock().unwrap();

    if !conn.monitor.load(Ordering::Acquire) {
        return;
    }

    if conn.sch_fake_sent.load(Ordering::Acquire) {
        on_unexpected_locked(
            wd,
            packet,
            conn,
            "unexpected outbound packet, recv packet after fake sent!",
        );
        return;
    }

    // ── Outbound SYN ──────────────────────────────────────────────────
    if info.syn && !info.ack && !info.rst && !info.fin && info.payload_len == 0 {
        if info.ack_num != 0 {
            on_unexpected_locked(
                wd,
                packet,
                conn,
                "unexpected outbound syn packet, ack_num is not zero!",
            );
            return;
        }
        let existing = conn.syn_seq.load(Ordering::Acquire);
        if existing != -1 && existing as u32 != info.seq_num {
            on_unexpected_locked(
                wd,
                packet,
                conn,
                &format!(
                    "unexpected outbound syn packet, seq not matched! {} {}",
                    info.seq_num, existing
                ),
            );
            return;
        }
        conn.syn_seq.store(info.seq_num as i64, Ordering::Release);
        let _ = wd.send(packet);
        return;
    }

    // ── Outbound ACK (handshake completion) ────────────────────────────
    if info.ack && !info.syn && !info.rst && !info.fin && info.payload_len == 0 {
        let syn_seq = conn.syn_seq.load(Ordering::Acquire);
        let syn_ack_seq = conn.syn_ack_seq.load(Ordering::Acquire);

        if syn_seq == -1 || (syn_seq as u32).wrapping_add(1) != info.seq_num {
            on_unexpected_locked(
                wd,
                packet,
                conn,
                &format!(
                    "unexpected outbound ack packet, seq not matched! {} {}",
                    info.seq_num, syn_seq
                ),
            );
            return;
        }
        if syn_ack_seq == -1 || info.ack_num != (syn_ack_seq as u32).wrapping_add(1) {
            on_unexpected_locked(
                wd,
                packet,
                conn,
                &format!(
                    "unexpected outbound ack packet, ack not matched! {} {}",
                    info.ack_num, syn_ack_seq
                ),
            );
            return;
        }

        // Forward the real ACK packet
        let _ = wd.send(packet);
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
            on_unexpected_locked(
                wd,
                packet,
                conn,
                &format!("unknown bypass method: {}", conn.bypass_method),
            );
        }
        return;
    }

    on_unexpected_locked(wd, packet, conn, "unexpected outbound packet");
}

// ── Inbound packet handler ─────────────────────────────────────────────────

fn handle_inbound(
    wd: &WinDivert<NetworkLayer>,
    packet: &WinDivertPacket<'_, NetworkLayer>,
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
                wd,
                packet,
                conn,
                &format!(
                    "unexpected inbound syn-ack packet, seq change! {} {}",
                    info.seq_num, syn_ack_seq
                ),
            );
            return;
        }
        if info.ack_num != (syn_seq as u32).wrapping_add(1) {
            on_unexpected_locked(
                wd,
                packet,
                conn,
                &format!(
                    "unexpected inbound syn-ack packet, ack not matched! {} {}",
                    info.ack_num, syn_seq
                ),
            );
            return;
        }
        conn.syn_ack_seq
            .store(info.seq_num as i64, Ordering::Release);
        let _ = wd.send(packet);
        return;
    }

    // ── Inbound ACK of fake data ──────────────────────────────────────
    if info.ack
        && !info.syn
        && !info.rst
        && !info.fin
        && info.payload_len == 0
        && conn.fake_sent.load(Ordering::Acquire)
    {
        let syn_ack_seq = conn.syn_ack_seq.load(Ordering::Acquire);
        if syn_ack_seq == -1 || (syn_ack_seq as u32).wrapping_add(1) != info.seq_num {
            on_unexpected_locked(
                wd,
                packet,
                conn,
                &format!(
                    "unexpected inbound ack packet, seq not matched! {} {}",
                    info.seq_num, syn_ack_seq
                ),
            );
            return;
        }
        if info.ack_num != (syn_seq as u32).wrapping_add(1) {
            on_unexpected_locked(
                wd,
                packet,
                conn,
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
    wd: &WinDivert<NetworkLayer>,
    packet: &WinDivertPacket<'_, NetworkLayer>,
    conn: &FakeInjectiveConnection,
    info: &str,
) {
    eprintln!("{}", info);
    conn.monitor.store(false, Ordering::Release);
    *conn.t2a_msg.lock().unwrap() = "unexpected_close".to_string();
    conn.t2a_notify.notify_one();
    let _ = wd.send(packet);
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
/// We take the real ACK packet (which has no payload), clone its IP+TCP headers,
/// append the fake ClientHello payload, and send with a deliberately wrong seq.
pub fn inject_fake_packet(
    wd: &WinDivert<NetworkLayer>,
    packet: &WinDivertPacket<'_, NetworkLayer>,
    conn: &FakeInjectiveConnection,
) {
    let syn_seq = conn.syn_seq.load(Ordering::Acquire) as u32;
    let fake_payload_len = conn.fake_data.len() as u32;

    // Clone the borrowed packet so we can modify it
    let mut owned = packet.clone().into_owned();

    // ── Modify the cloned packet header & payload ────────────────────
    // This block keeps the mutable borrow of `owned.data` scoped so it
    // doesn't conflict with the subsequent `recalculate_checksums` call.
    {
        let data = owned.data.to_mut();

        // ── Find IP header length first ──────────────────────────────
        let ip_hdr_len = match parse_ipv4(data) {
            Some(ip) => ip.header_length,
            None => {
                eprintln!("inject_fake_packet: failed to parse IPv4 header");
                return;
            }
        };
        let tcp_flags_byte = ip_hdr_len + 13;
        if tcp_flags_byte >= data.len() {
            eprintln!("inject_fake_packet: packet too short for TCP flags");
            return;
        }
        data[tcp_flags_byte] |= 0x08; // Set PSH flag

        // ── Extend packet with the fake ClientHello payload ──────────
        data.extend_from_slice(&conn.fake_data);

        // ── Update IPv4 total length ─────────────────────────────────
        let new_total_len = (data.len() as u16).to_be_bytes();
        data[2] = new_total_len[0];
        data[3] = new_total_len[1];

        // ── Increment IPv4 identification ────────────────────────────
        let old_ident = u16::from_be_bytes([data[4], data[5]]);
        let new_ident = old_ident.wrapping_add(1) & 0xffff;
        data[4] = (new_ident >> 8) as u8;
        data[5] = (new_ident & 0xff) as u8;

        // ── THE CRITICAL WRONG SEQUENCE FORMULA ───────────────────────
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
        let tcp_seq_offset = ip_hdr_len + 4;
        let seq_bytes = wrong_seq.to_be_bytes();
        data[tcp_seq_offset] = seq_bytes[0];
        data[tcp_seq_offset + 1] = seq_bytes[1];
        data[tcp_seq_offset + 2] = seq_bytes[2];
        data[tcp_seq_offset + 3] = seq_bytes[3];
    } // `data` dropped → mutable borrow of `owned.data` released

    conn.fake_sent.store(true, Ordering::Release);

    // ── Recalculate checksums and send ───────────────────────────────
    // ChecksumFlags::default() = 0 => recalculate all checksums (IP, TCP)
    if let Err(e) = owned.recalculate_checksums(ChecksumFlags::default()) {
        eprintln!("inject_fake_packet: checksum recalculation failed: {}", e);
    }
    let _ = wd.send(&owned);
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
        assert!(
            ch_str.contains(sni_str),
            "ClientHello must contain the target SNI"
        );

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
        let ch2 = build_client_hello(
            &rnd,
            &sess_id,
            b"very-long-subdomain.example.com",
            &key_share,
        );
        assert_eq!(ch2.len(), 517);
    }

    #[test]
    fn test_wrong_seq_formula() {
        let syn_seq: u32 = 0x12345678;
        let payload_len: u32 = 517;
        let result = syn_seq.wrapping_add(1).wrapping_sub(payload_len);
        let python_style = (syn_seq.wrapping_add(1).wrapping_sub(payload_len)) & 0xffffffff;

        assert_eq!(result, python_style);
        assert_ne!(result, syn_seq.wrapping_add(1));
        // The seq points BEFORE the expected next byte
        assert!(result < syn_seq.wrapping_add(1));
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
        let _ = &*TLS_CH_TEMPLATE;
        assert_eq!(TLS_CH_TEMPLATE.len(), 517);
    }

    #[test]
    fn test_parse_ipv4() {
        // Build a minimal IPv4 packet with TCP
        let mut pkt = vec![
            0x45, 0x00, 0x00, 0x28, // Version=4, IHL=5, Total Length=40
            0xab, 0xcd, 0x40, 0x00, // ID=0xabcd, flags=0x40, frag_offset=0
            0x40, 0x06, 0x00, 0x00, // TTL=64, Protocol=TCP=6, checksum=0
            0xc0, 0xa8, 0x01, 0x64, // Src=192.168.1.100
            0x08, 0x08, 0x08, 0x08, // Dst=8.8.8.8
        ];
        // Append a minimal TCP header (20 bytes)
        pkt.extend_from_slice(&[
            0x1f, 0x90, 0x00, 0x50, // src_port=8080, dst_port=80
            0x00, 0x00, 0x00, 0x01, // seq_num=1
            0x00, 0x00, 0x00, 0x00, // ack_num=0
            0x50, 0x02, 0x71, 0x10, // data_offset=5, SYN=1, win=28944
            0x00, 0x00, 0x00, 0x00, // checksum=0, urg_ptr=0
        ]);

        let ip = parse_ipv4(&pkt).expect("Should parse IPv4 header");
        assert_eq!(ip.src_addr, Ipv4Addr::new(192, 168, 1, 100));
        assert_eq!(ip.dst_addr, Ipv4Addr::new(8, 8, 8, 8));
        assert_eq!(ip.ident, 0xabcd);
        assert_eq!(ip.header_length, 20);

        let tcp = parse_tcp(&pkt, ip.header_length).expect("Should parse TCP header");
        assert_eq!(tcp.src_port, 8080);
        assert_eq!(tcp.dst_port, 80);
        assert_eq!(tcp.seq_num, 1);
        assert!(tcp.syn);
        assert!(!tcp.ack);
        assert!(!tcp.psh);
        assert!(!tcp.fin);
        assert!(!tcp.rst);
    }

    #[test]
    fn test_extract_packet_info() {
        // Build a SYN-ACK packet (inbound)
        let mut pkt = vec![
            0x45, 0x00, 0x00, 0x28, // Version=4, IHL=5, Total Length=40
            0x00, 0x01, 0x40, 0x00, // ID=1
            0x40, 0x06, 0x00, 0x00, // TTL=64, TCP
            0x08, 0x08, 0x08, 0x08, // Src=8.8.8.8
            0xc0, 0xa8, 0x01, 0x64, // Dst=192.168.1.100
        ];
        pkt.extend_from_slice(&[
            0x00, 0x50, 0x1f, 0x90, // src=80, dst=8080
            0x00, 0x00, 0xab, 0xcd, // seq=43981
            0x00, 0x00, 0x00, 0x02, // ack=2
            0x50, 0x12, 0x71, 0x10, // data_offset=5, SYN+ACK
            0x00, 0x00, 0x00, 0x00,
        ]);

        let info = extract_packet_info(&pkt, false).expect("Should parse packet info");
        assert_eq!(info.src_addr, Ipv4Addr::new(8, 8, 8, 8));
        assert_eq!(info.dst_addr, Ipv4Addr::new(192, 168, 1, 100));
        assert_eq!(info.src_port, 80);
        assert_eq!(info.dst_port, 8080);
        assert_eq!(info.seq_num, 43981);
        assert_eq!(info.ack_num, 2);
        assert!(info.syn);
        assert!(info.ack);
        assert!(!info.rst);
        assert!(!info.fin);
        assert_eq!(info.payload_len, 0);
        assert!(!info.is_inbound);
    }
}
