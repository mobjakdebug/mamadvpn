//! Xray-core binary embedding and sidecar process management.
//!
//! To support complex subscription protocols (Trojan, VLESS, VMess) without
//! bloating the Rust codebase, a compiled `xray.exe` Windows binary is embedded
//! directly inside Mamad VPN via `include_bytes!`. At runtime the binary is
//! extracted to a hidden temporary directory, a routing `config.json` is
//! generated dynamically, and Xray is spawned as a child process.
//!
//! The Xray outbound is configured to route through the local loopback port
//! where the Rust WinDivert injector is listening, so all traffic passes through
//! the kernel-level DPI bypass.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};

use anyhow::{Context, Result};
use base64::Engine;
use serde_json::json;

// ── Embed the Xray binary ──────────────────────────────────────────────────

/// The compiled `xray.exe` binary embedded at compile time.
///
/// If `xray.exe` is not present in the project root at build time this will
/// produce a compile error. Place the Xray-core Windows executable next to
/// `Cargo.toml` before building.
// const XRAY_BINARY: &[u8] = include_bytes!("../xray.exe");
pub const XRAY_EXE_NAME: &str = "xray.exe";

/// Hidden temporary directory name used for extracting the Xray binary.
const XRAY_HIDDEN_DIR: &str = "mamad_temp";

/// Returns the path to the operating system's temp directory for the user.
fn temp_dir() -> PathBuf {
    dirs::cache_dir()
        .or_else(|| dirs::data_local_dir())
        .unwrap_or_else(|| PathBuf::from(std::env::temp_dir()))
        .join(XRAY_HIDDEN_DIR)
}

/// Extract the embedded `xray.exe` binary to the hidden temp directory.
///
/// Returns the full path to the extracted executable.
pub fn extract_xray_binary(binary_bytes: &[u8]) -> Result<PathBuf> {
    let dest_dir = temp_dir();
    fs::create_dir_all(&dest_dir).context("Failed to create Xray temp directory")?;

    let exe_path = dest_dir.join(XRAY_EXE_NAME);

    // Only write if the file doesn't already exist (avoid re-extracting)
    if !exe_path.exists() {
        let mut f = fs::File::create(&exe_path)
            .with_context(|| format!("Failed to create {}", exe_path.display()))?;
        f.write_all(binary_bytes)
            .with_context(|| format!("Failed to write {}", exe_path.display()))?;
    }

    Ok(exe_path)
}

// ── Xray configuration generation ──────────────────────────────────────────

/// Generate a valid Xray-core `config.json` that routes all traffic through
/// the local Mamad VPN proxy.
///
/// # Arguments
/// * `listen_host` – The host the Mamad VPN proxy is bound to.
/// * `listen_port` – The port the Mamad VPN proxy is listening on.
/// * `subscription_url` – The Trojan/VLESS subscription URI from the selected node.
pub fn generate_xray_config(
    listen_host: &str,
    listen_port: u16,
    subscription_url: &str,
) -> Result<String> {
    // Parse subscription URL to determine protocol type
    let (protocol, config) = parse_subscription_url(subscription_url)?;

    // Extract stream-level settings from the parsed config (prefixed with _)
    let sni = config["_sni"].as_str().unwrap_or(listen_host);
    let security = config["_security"].as_str().unwrap_or("tls");
    let network = config["_network"].as_str().unwrap_or("tcp");

    // Build protocol-level settings by stripping the underscore-prefixed fields
    let mut protocol_settings = config.clone();
    if let Some(obj) = protocol_settings.as_object_mut() {
        obj.remove("_sni");
        obj.remove("_security");
        obj.remove("_network");
    }

    let config_json = json!({
        "log": {
            "loglevel": "warning"
        },
        "inbounds": [{
            "port": 10808,
            "listen": "127.0.0.1",
            "protocol": "socks",
            "settings": {
                "udp": true
            },
            "sniffing": {
                "enabled": true,
                "destOverride": ["http", "tls"]
            }
        }],
        "outbounds": [{
            "protocol": protocol,
            "tag": "proxy",
            "settings": protocol_settings,
            "streamSettings": {
                "network": network,
                "security": security,
                "tlsSettings": {
                    "serverName": sni,
                    "allowInsecure": false
                },
                "sockopt": {
                    "tcpFastOpen": true
                }
            }
        }, {
            "protocol": "freedom",
            "tag": "direct",
            "settings": {}
        }],
        "routing": {
            "domainStrategy": "IPIfNonMatch",
            "rules": [{
                "type": "field",
                "outboundTag": "proxy",
                "network": "tcp,udp"
            }]
        }
    });

    Ok(serde_json::to_string_pretty(&config_json)?)
}

/// Naive parser for Trojan / VLESS subscription URIs.
///
/// Recognises `trojan://` and `vless://` schemes and extracts the essential
/// configuration fields needed by Xray-core.
fn parse_subscription_url(url: &str) -> Result<(String, serde_json::Value)> {
    if url.starts_with("trojan://") {
        let (protocol, settings) = parse_trojan_url(url)?;
        Ok((protocol, settings))
    } else if url.starts_with("vless://") {
        let (protocol, settings) = parse_vless_url(url)?;
        Ok((protocol, settings))
    } else if url.starts_with("vmess://") {
        let (protocol, settings) = parse_vmess_url(url)?;
        Ok((protocol, settings))
    } else {
        anyhow::bail!("Unsupported subscription protocol in URL: {:.50}...", url);
    }
}

/// Parse a `trojan://password@host:port?sni=...` URI.
fn parse_trojan_url(url: &str) -> Result<(String, serde_json::Value)> {
    let stripped = url.strip_prefix("trojan://").unwrap_or(url);

    // Split at '@' to separate password from host:port
    let (password, rest) = stripped
        .split_once('@')
        .context("Invalid Trojan URL: missing '@' separator")?;

    // Split rest at '?' to separate host:port from query params
    let (host_port, query) = rest.split_once('?').unwrap_or((rest, ""));

    let (host, port_str) = host_port
        .split_once(':')
        .context("Invalid Trojan URL: missing port")?;
    let port: u16 = port_str.parse().context("Invalid Trojan port")?;

    // Extract SNI from query string
    let sni = query
        .split('&')
        .find_map(|p| {
            let (k, v) = p.split_once('=')?;
            if k == "sni" { Some(v.to_string()) } else { None }
        })
        .unwrap_or_else(|| host.to_string());

    // streamSettings goes at the outbound level, not inside settings.
    // Pass the SNI separately so generate_xray_config can place it correctly.
    let settings = json!({
        "servers": [{
            "address": host,
            "port": port,
            "password": password,
        }],
        "_sni": sni,
        "_security": "tls",
        "_network": "tcp"
    });

    Ok(("trojan".to_string(), settings))
}

/// Parse a `vless://uuid@host:port?encryption=none&security=tls&sni=...` URI.
fn parse_vless_url(url: &str) -> Result<(String, serde_json::Value)> {
    let stripped = url.strip_prefix("vless://").unwrap_or(url);

    let (uuid, rest) = stripped
        .split_once('@')
        .context("Invalid VLESS URL: missing '@' separator")?;

    let (host_port, query) = rest.split_once('?').unwrap_or((rest, ""));

    let (host, port_str) = host_port
        .split_once(':')
        .context("Invalid VLESS URL: missing port")?;
    let port: u16 = port_str.parse().context("Invalid VLESS port")?;

    let sni = query
        .split('&')
        .find_map(|p| {
            let (k, v) = p.split_once('=')?;
            if k == "sni" { Some(v.to_string()) } else { None }
        })
        .unwrap_or_else(|| host.to_string());

    let security = query
        .split('&')
        .find_map(|p| {
            let (k, v) = p.split_once('=')?;
            if k == "security" { Some(v.to_string()) } else { None }
        })
        .unwrap_or_else(|| "tls".to_string());

    let settings = json!({
        "vnext": [{
            "address": host,
            "port": port,
            "users": [{
                "id": uuid,
                "encryption": "none",
                "flow": ""
            }]
        }],
        "_sni": sni,
        "_security": security,
        "_network": "tcp"
    });

    Ok(("vless".to_string(), settings))
}

/// Parse a `vmess://base64(...)` URI.
fn parse_vmess_url(url: &str) -> Result<(String, serde_json::Value)> {
    let stripped = url.strip_prefix("vmess://").unwrap_or(url);

    // VMess URIs are base64-encoded JSON
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(stripped)
        .context("Failed to decode VMess base64 URI")?;

    let decoded_str =
        String::from_utf8(decoded).context("VMess decoded data is not valid UTF-8")?;

    let v: serde_json::Value =
        serde_json::from_str(&decoded_str).context("VMess decoded data is not valid JSON")?;

    let settings = json!({
        "vnext": [{
            "address": v["add"],
            "port": v["port"].as_u64().unwrap_or(443) as u16,
            "users": [{
                "id": v["id"],
                "alterId": v["aid"].as_u64().unwrap_or(0),
                "security": v["scy"].as_str().unwrap_or("auto")
            }]
        }],
        "_sni": v["sni"].as_str().unwrap_or(""),
        "_security": v["tls"].as_str().unwrap_or("none"),
        "_network": v["net"].as_str().unwrap_or("tcp")
    });

    Ok(("vmess".to_string(), settings))
}

// ── Xray process lifecycle ─────────────────────────────────────────────────

/// Spawn Xray-core as a hidden child process with the given configuration.
///
/// # Arguments
/// * `xray_path` – Full path to the extracted `xray.exe`.
/// * `config_path` – Full path to the generated `config.json`.
///
/// Returns the child process handle so the caller can kill it on shutdown.
pub fn spawn_xray(xray_path: &Path, config_path: &Path) -> Result<Child> {
    let child = Command::new(xray_path)
        .arg("-config")
        .arg(config_path)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        // Windows-specific: hide the console window
        .creation_flags(0x08000000) // CREATE_NO_WINDOW
        .spawn()
        .with_context(|| format!("Failed to spawn Xray at {}", xray_path.display()))?;

    Ok(child)
}

/// Write the Xray `config.json` to the hidden temp directory.
///
/// Returns the full path to the written config file.
pub fn write_xray_config(config_json: &str) -> Result<PathBuf> {
    let dest_dir = temp_dir();
    fs::create_dir_all(&dest_dir).context("Failed to create Xray temp directory")?;

    let config_path = dest_dir.join("config.json");
    let mut f = fs::File::create(&config_path)
        .with_context(|| format!("Failed to create {}", config_path.display()))?;
    f.write_all(config_json.as_bytes())
        .with_context(|| format!("Failed to write Xray config to {}", config_path.display()))?;

    Ok(config_path)
}

/// Clean up the Xray temporary directory and kill any running processes.
pub fn cleanup(xray_child: Option<Child>) {
    if let Some(mut child) = xray_child {
        let _ = child.kill();
        let _ = child.wait();
    }

    let dir = temp_dir();
    let _ = fs::remove_dir_all(&dir);
}
