//! Mamad VPN — DPI Circumvention Tool
//!
//! High-performance Windows application that bypasses deep packet inspection
//! using kernel-level TCP sequence number manipulation via WinDivert.
//!
//! Developed by **mobjak**.

mod api;
mod injector;
mod xray;

use std::net::{Ipv4Addr, SocketAddrV4};
use std::process::Child;
use std::sync::Arc;

use anyhow::{Context, Result};
use dashmap::DashMap;
use dialoguer::{theme::ColorfulTheme, Select};
use rand::Rng;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpSocket, TcpStream};
use tokio::time::timeout;

use crate::api::Node;
use crate::injector::{build_client_hello, build_filter, ConnKey, FakeInjectiveConnection};
use crate::xray::{extract_xray_binary, generate_xray_config, spawn_xray, write_xray_config};

// ── ASCII banner ───────────────────────────────────────────────────────────

const BANNER: &str = r#"
 __  __                        __      ___  ________  _   __
|  \/  |                       \ \    / / | |  __ \ \| | / /
| \  / | __ _ _ __ ___   __ _   \ \  / /| | | |__) |\ \_/ / 
| |\/| |/ _` | '_ ` _ \ / _` |   \ \/ / | | |  ___/  \   /  
| |  | | (_| | | | | | | (_| |    \  /  | | | |       | |   
|_|  |_|\__,_|_| |_| |_|\__,_|     \/   |_| |_|       |_|   
                                                             
"#;

const VERSION: &str = env!("CARGO_PKG_VERSION");

const DISCLAIMER_EN: &str = r#"
DISCLAIMER: This tool is designed to facilitate access to the free internet.
It is intended for educational and research purposes only.
Users are responsible for complying with all applicable laws.
"#;

const DISCLAIMER_FA: &str = r#"
سلب مسئولیت: این ابزار برای تسهیل دسترسی به اینترنت آزاد طراحی شده است.
این نرم‌افزار صرفاً برای اهداف آموزشی و پژوهشی در نظر گرفته شده است.
کاربران مسئول رعایت تمام قوانین قابل اجرا می‌باشند.
"#;

// ── Default API endpoint ───────────────────────────────────────────────────

const DEFAULT_API_URL: &str = "https://your-cpanel-domain.com/api.php";
const DEFAULT_ACCESS_TOKEN: &str = "CHANGE_ME";

/// Resolve a hostname to an IPv4 address using the system resolver.
async fn resolve_host(host: &str) -> Result<Ipv4Addr> {
    // Try to parse as an IP first
    if let Ok(ip) = host.parse::<Ipv4Addr>() {
        return Ok(ip);
    }

    // Otherwise resolve via DNS
    let addr_str = format!("{}:443", host);
    let addrs = tokio::net::lookup_host(&addr_str)
        .await
        .with_context(|| format!("DNS resolution failed for {}", host))?;

    for addr in addrs {
        match addr {
            std::net::SocketAddr::V4(v4) => return Ok(*v4.ip()),
            _ => continue,
        }
    }

    anyhow::bail!("No IPv4 address found for {}", host);
}

// ── Entry point ────────────────────────────────────────────────────────────

fn main() -> Result<()> {
    // Print branding
    println!("{}", BANNER);
    println!("  Developed by mobjak  |  v{}\n", VERSION);
    println!("{}", DISCLAIMER_EN);
    println!("{}", DISCLAIMER_FA);

    // Windows-specific: ensure we're running as admin
    #[cfg(windows)]
    {
        if !is_elevated() {
            eprintln!("\nERROR: Mamad VPN requires Administrator privileges.");
            eprintln!("Please right-click and select 'Run as Administrator'.\n");
            std::process::exit(1);
        }
    }

    // Build the Tokio runtime and run the main async logic
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .worker_threads(4)
        .thread_name("mamad-vpn")
        .build()
        .context("Failed to build Tokio runtime")?;

    rt.block_on(async_main())
}

// ── Windows elevation check ────────────────────────────────────────────────

#[cfg(windows)]
fn is_elevated() -> bool {
    use windows::Win32::Foundation::{CloseHandle, HANDLE};
    use windows::Win32::Security::{TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY};
    use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    unsafe {
        let mut token: HANDLE = HANDLE::default();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token).is_err() {
            return false;
        }

        let mut elevation = TOKEN_ELEVATION::default();
        let size = std::mem::size_of::<TOKEN_ELEVATION>() as u32;
        let mut returned = 0u32;
        let result = windows::Win32::Security::GetTokenInformation(
            token,
            TokenElevation,
            Some(&mut elevation as *mut _ as *mut _),
            size,
            &mut returned,
        );

        let _ = CloseHandle(token);

        result.is_ok() && elevation.TokenIsElevated != 0
    }
}

#[cfg(not(windows))]
fn is_elevated() -> bool {
    true
}

// ── Main async flow ────────────────────────────────────────────────────────

async fn async_main() -> Result<()> {
    // ── Fetch node list from API ───────────────────────────────────────
    println!("\n[1/5] Fetching available nodes from API...\n");

    let nodes = fetch_nodes_with_fallback().await?;

    // ── CLI interactive selection ──────────────────────────────────────
    let selection = build_selection_menu(&nodes)?;
    let node = &nodes[selection];

    println!("\n✓ Selected: {} — {}", node.country, node.name);
    println!("  Fake SNI  : {}", node.fake_sni);
    println!("  Connect IP: {}", node.connect_ip);
    println!("  Method    : {}", node.bypass_method);

    // ── Resolve interface IP ───────────────────────────────────────────
    let interface_ipv4 = injector::get_default_interface_ipv4()
        .context("Could not determine default interface IPv4 address")?;
    println!("  Interface : {}", interface_ipv4);

    // Resolve the connect IP (may be a hostname)
    let connect_ip = resolve_host(&node.connect_ip)
        .await
        .context("Failed to resolve connect target IP")?;

    // ── Start WinDivert injector in background thread ──────────────────
    println!("\n[2/5] Starting kernel-level packet injector...");
    let connections: Arc<DashMap<ConnKey, FakeInjectiveConnection>> =
        Arc::new(DashMap::new());
    let connections_for_injector = Arc::clone(&connections);

    let listen_host = "0.0.0.0";
    let listen_port: u16 = 40443;
    let connect_port: u16 = 443;
    let fake_sni = node.fake_sni.as_bytes().to_vec();
    let bypass_method = node.bypass_method.clone();

    let filter = build_filter(&interface_ipv4.to_string(), &connect_ip.to_string());
    println!("  WinDivert filter: {}", filter);

    std::thread::Builder::new()
        .name("windivert-injector".to_string())
        .spawn(move || {
            if let Err(e) = injector::run_injector(&filter, connections_for_injector) {
                eprintln!("FATAL: WinDivert injector thread died: {}", e);
                std::process::exit(1);
            }
        })
        .context("Failed to spawn WinDivert injector thread")?;

    // Give WinDivert a moment to open its handle
    tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;

    // ── Initialize Xray sidecar ────────────────────────────────────────
    println!("\n[3/5] Initializing Xray-core sidecar...");

    let mut xray_child: Option<Child> = None;

    if !node.config_url.is_empty() {
        xray_child = initialize_xray_sidecar(node, listen_host, listen_port)?;
        println!("  Xray-core sidecar initialized");
    } else {
        println!("  No subscription URL; skipping Xray sidecar");
    }

    // ── Start proxy listener ───────────────────────────────────────────
    println!("\n[4/5] Starting proxy listener on {}:{}\n", listen_host, listen_port);

    let bind_addr = SocketAddrV4::new(
        listen_host.parse::<Ipv4Addr>().unwrap_or(Ipv4Addr::UNSPECIFIED),
        listen_port,
    );
    let listener = TcpListener::bind(bind_addr)
        .await
        .context("Failed to bind proxy listener")?;

    println!("[5/5] Mamad VPN is running. Press Ctrl+C to stop.\n");
    println!("{:-<60}", "");
    println!();

    // ── Graceful shutdown on Ctrl+C ────────────────────────────────────
    let shutdown = tokio::signal::ctrl_c();
    tokio::pin!(shutdown);

    // ── Accept loop ────────────────────────────────────────────────────
    loop {
        tokio::select! {
            accept_result = listener.accept() => {
                match accept_result {
                    Ok((incoming, addr)) => {
                        let conn_map = Arc::clone(&connections);
                        let f_sni = fake_sni.clone();
                        let conn_ip = connect_ip;
                        let if_ip = interface_ipv4;
                        let conn_port = connect_port;
                        let bm = bypass_method.clone();

                        tokio::spawn(async move {
                            if let Err(e) = handle_connection(
                                incoming,
                                conn_map,
                                f_sni,
                                conn_ip,
                                conn_port,
                                if_ip,
                                bm,
                            )
                            .await
                            {
                                eprintln!("Connection error from {}: {}", addr, e);
                            }
                        });
                    }
                    Err(e) => {
                        eprintln!("Accept error: {}", e);
                    }
                }
            }
            _ = &mut shutdown => {
                println!("\nShutting down Mamad VPN...");

                // Kill Xray sidecar
                if let Some(mut child) = xray_child.take() {
                    let _ = child.kill();
                    let _ = child.wait();
                }
                xray::cleanup(None);

                println!("Goodbye.");
                return Ok(());
            }
        }
    }
}

// ── Connection handler ─────────────────────────────────────────────────────
///
/// CRITICAL ORDERING: The connection MUST be registered in the DashMap BEFORE
/// the TCP handshake completes, so WinDivert can intercept SYN/SYN-ACK/ACK.
/// We use `TcpSocket` to bind (which gives us the source port), register the
/// connection, then call `connect()`.

async fn handle_connection(
    mut incoming: TcpStream,
    connections: Arc<DashMap<ConnKey, FakeInjectiveConnection>>,
    fake_sni: Vec<u8>,
    connect_ip: Ipv4Addr,
    connect_port: u16,
    interface_ipv4: Ipv4Addr,
    bypass_method: String,
) -> Result<()> {
    // Generate random material for the fake ClientHello
    let mut rng = rand::thread_rng();
    let rnd: [u8; 32] = rng.gen();
    let sess_id: [u8; 32] = rng.gen();
    let key_share: [u8; 32] = rng.gen();

    let fake_data = build_client_hello(&rnd, &sess_id, &fake_sni, &key_share);

    // ── Bind outgoing socket FIRST to get source port ─────────────────
    // This allows us to register the connection in the DashMap BEFORE the
    // TCP 3-way handshake begins, so WinDivert sees all packets.
    let socket = TcpSocket::new_v4()
        .context("Failed to create outgoing TCP socket")?;

    socket
        .bind(SocketAddrV4::new(interface_ipv4, 0).into())
        .context("Failed to bind outgoing socket")?;

    let src_port = socket
        .local_addr()
        .context("Failed to get local address")?
        .port();

    // ── Register the connection NOW, before connect() ──────────────────
    let conn = FakeInjectiveConnection::new(
        interface_ipv4,
        connect_ip,
        src_port,
        connect_port,
        fake_data,
        &bypass_method,
    );
    let conn_id = conn.id;
    connections.insert(conn_id, conn);

    // ── Now connect to the target (TCP handshake packets will be seen by WinDivert) ──
    let target = SocketAddrV4::new(connect_ip, connect_port);
    let outgoing = match timeout(
        tokio::time::Duration::from_secs(10),
        socket.connect(target),
    )
    .await
    {
        Ok(Ok(sock)) => sock,
        _ => {
            connections.remove(&conn_id);
            return Ok(());
        }
    };

    // ── Wait for WinDivert to signal that the fake injection succeeded ──
    if bypass_method == "wrong_seq" {
        let notified = {
            let entry = connections.get(&conn_id);
            match entry {
                Some(conn_ref) => {
                    tokio::select! {
                        _ = conn_ref.t2a_notify.notified() => {
                            let msg = conn_ref.t2a_msg.lock().unwrap().clone();
                            msg == "fake_data_ack_recv"
                        }
                        _ = tokio::time::sleep(tokio::time::Duration::from_secs(5)) => {
                            false
                        }
                    }
                }
                None => false,
            }
        };

        if !notified {
            connections.remove(&conn_id);
            return Ok(());
        }
    }

    // Remove from tracking map (WinDivert no longer needs to intercept)
    connections.remove(&conn_id);

    // ── Bidirectional relay ────────────────────────────────────────────
    let (mut incoming_read, mut incoming_write) = incoming.split();
    let (mut outgoing_read, mut outgoing_write) = outgoing.into_split();

    // Relay incoming → outgoing
    let t1 = tokio::spawn(async move {
        let mut buf = vec![0u8; 65535];
        loop {
            match incoming_read.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => {
                    if outgoing_write.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
        let _ = outgoing_write.shutdown().await;
    });

    // Relay outgoing → incoming
    let t2 = tokio::spawn(async move {
        let mut buf = vec![0u8; 65535];
        loop {
            match outgoing_read.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => {
                    if incoming_write.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
        let _ = incoming_write.shutdown().await;
    });

    let _ = tokio::join!(t1, t2);

    Ok(())
}

// ── Node fetching with fallback ────────────────────────────────────────────

async fn fetch_nodes_with_fallback() -> Result<Vec<Node>> {
    match api::fetch_nodes(DEFAULT_API_URL, DEFAULT_ACCESS_TOKEN).await {
        Ok(nodes) => Ok(nodes),
        Err(e) => {
            eprintln!("API fetch failed: {}", e);
            eprintln!("Falling back to local default nodes.\n");
            Ok(default_nodes())
        }
    }
}

/// Default nodes used when the API is unreachable.
fn default_nodes() -> Vec<Node> {
    vec![
        Node {
            name: "Germany-Frankfurt".to_string(),
            country: "Germany".to_string(),
            fake_sni: "auth.vercel.com".to_string(),
            bypass_method: "wrong_seq".to_string(),
            config_url: String::new(),
            connect_ip: "188.114.98.0".to_string(),
        },
        Node {
            name: "Netherlands-Amsterdam".to_string(),
            country: "Netherlands".to_string(),
            fake_sni: "www.speedtest.net".to_string(),
            bypass_method: "wrong_seq".to_string(),
            config_url: String::new(),
            connect_ip: "141.101.121.0".to_string(),
        },
    ]
}

// ── CLI selection menu ─────────────────────────────────────────────────────

fn build_selection_menu(nodes: &[Node]) -> Result<usize> {
    let items: Vec<String> = nodes
        .iter()
        .map(|n| format!("{} — {}  [SNI: {}]", n.country, n.name, n.fake_sni))
        .collect();

    let selection = Select::with_theme(&ColorfulTheme::default())
        .with_prompt("Select a VPN node:")
        .items(&items)
        .default(0)
        .interact()
        .context("Failed to display node selection menu")?;

    Ok(selection)
}

// ── Xray sidecar initialisation ────────────────────────────────────────────

fn initialize_xray_sidecar(
    node: &Node,
    listen_host: &str,
    listen_port: u16,
) -> Result<Option<Child>> {
    // Generate Xray configuration
    let config_json =
        generate_xray_config(listen_host, listen_port, &node.config_url)?;

    let config_path = write_xray_config(&config_json)?;

    // If we have an embedded xray.exe binary, extract and spawn it.
    let xray_binary = match try_get_xray_binary() {
        Some(b) => b,
        None => {
            eprintln!("  ⚠ xray.exe not embedded; Xray sidecar unavailable.");
            return Ok(None);
        }
    };

    let exe_path = extract_xray_binary(xray_binary)?;
    let child = spawn_xray(&exe_path, &config_path)?;

    Ok(Some(child))
}

/// Attempt to retrieve the compiled-in `xray.exe` binary.
/// Returns `None` if the binary was not embedded at build time.
fn try_get_xray_binary() -> Option<&'static [u8]> {
    #[cfg(feature = "embed_xray")]
    {
        Some(include_bytes!("../xray.exe"))
    }
    #[cfg(not(feature = "embed_xray"))]
    {
        None
    }
}
