use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use parking_lot::RwLock;

use crate::error::CommonError;

// ---------------------------------------------------------------------------
// Connection mode
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ConnectionMode {
    /// Our core bypass engine — TCP desync via wrong_seq
    #[serde(alias = "SNI Only")]
    SniOnly,
    /// Trojan proxy protocol (TLS + WebSocket optional)
    Trojan,
    /// Cloudflare WARP / WireGuard-based tunnel
    Warp,
    /// Psiphon protocol
    Psiphon,
}

impl Default for ConnectionMode {
    fn default() -> Self {
        Self::SniOnly
    }
}

// ---------------------------------------------------------------------------
// Bypass method enum
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum BypassMethod {
    WrongSeq,
    BadChecksum,
    Fragmentation,
    DelayedAck,
    FakeRst,
}

impl Default for BypassMethod {
    fn default() -> Self {
        Self::WrongSeq
    }
}

// ---------------------------------------------------------------------------
// Data mode enum
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DataMode {
    Tls,
    Http,
}

impl Default for DataMode {
    fn default() -> Self {
        Self::Tls
    }
}

// ---------------------------------------------------------------------------
// TLS connector backend enum
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TlsConnectorBackend {
    Rustls,
    Custom,
}

impl Default for TlsConnectorBackend {
    fn default() -> Self {
        Self::Custom
    }
}

// ---------------------------------------------------------------------------
// TLS fingerprint kind enum
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TlsFingerprintKind {
    Chrome,
    Firefox,
    Android,
    Random,
}

impl Default for TlsFingerprintKind {
    fn default() -> Self {
        Self::Chrome
    }
}

// ---------------------------------------------------------------------------
// Trojan transport enum
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TrojanTransport {
    /// Raw TCP (standard Trojan)
    Tcp,
    /// WebSocket transport
    Ws,
    /// gRPC transport
    Grpc,
}

impl Default for TrojanTransport {
    fn default() -> Self {
        Self::Tcp
    }
}

// ---------------------------------------------------------------------------
// Full app configuration
// ---------------------------------------------------------------------------

/// Top-level MamadVPN app configuration covering all connection modes.
///
/// Supports both snake_case and SCREAMING_SNAKE_CASE key naming for
/// backward compatibility with the original Python config files.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppConfig {
    // ── Connection mode ──────────────────────────────────────────
    /// Active connection mode.
    #[serde(alias = "CONNECTION_MODE", default)]
    pub connection_mode: ConnectionMode,

    // ── SNI Bypass engine (core) ─────────────────────────────────
    /// Local listen address for the bypass listener.
    #[serde(alias = "LISTEN_HOST")]
    pub listen_host: IpAddr,
    /// Local listen port for the bypass listener.
    #[serde(alias = "LISTEN_PORT")]
    pub listen_port: u16,
    /// Remote target host to tunnel to.
    #[serde(alias = "CONNECT_IP")]
    pub connect_host: IpAddr,
    /// Remote target port.
    #[serde(alias = "CONNECT_PORT")]
    pub connect_port: u16,
    /// SNI hostname for the fake TLS ClientHello.
    #[serde(alias = "FAKE_SNI", default = "default_fake_sni")]
    pub fake_sni: String,
    /// Active bypass method.
    #[serde(default)]
    pub bypass_mode: BypassMethod,
    /// Data transport mode.
    #[serde(default)]
    pub data_mode: DataMode,

    // ── Proxy ports ──────────────────────────────────────────────
    /// SOCKS5 proxy port (for SOCKS-to- bypass translation).
    #[serde(alias = "SOCKS_PORT", default = "default_socks_port")]
    pub socks_port: u16,
    /// HTTP proxy port (for HTTP CONNECT-to-bypass translation).
    #[serde(alias = "HTTP_PORT", default = "default_http_port")]
    pub http_port: u16,

    // ── Trojan settings ──────────────────────────────────────────
    /// Trojan protocol password.
    #[serde(alias = "TROJAN_PASSWORD", default)]
    pub trojan_password: String,
    /// Trojan TLS SNI hostname.
    #[serde(alias = "TROJAN_SNI", default)]
    pub trojan_sni: String,
    /// Trojan transport type.
    #[serde(alias = "TROJAN_TRANSPORT", default)]
    pub trojan_transport: TrojanTransport,
    /// Trojan WebSocket path (for ws transport).
    #[serde(alias = "TROJAN_PATH", default)]
    pub trojan_path: String,
    /// Trojan WebSocket host header.
    #[serde(alias = "TROJAN_HOST", default)]
    pub trojan_host: String,

    // ── WARP settings ────────────────────────────────────────────
    /// WARP endpoint IP.
    #[serde(alias = "WARP_ENDPOINT", default = "default_warp_endpoint")]
    pub warp_endpoint: String,
    /// WARP license key.
    #[serde(alias = "WARP_LICENSE", default)]
    pub warp_license: String,

    // ── Psiphon settings ─────────────────────────────────────────
    /// Psiphon connection country.
    #[serde(alias = "PSIPHON_COUNTRY", default = "default_psiphon_country")]
    pub psiphon_country: String,
    /// Psiphon endpoint.
    #[serde(alias = "PSIPHON_ENDPOINT", default = "default_psiphon_endpoint")]
    pub psiphon_endpoint: String,
    /// Psiphon license key.
    #[serde(alias = "PSIPHON_LICENSE", default)]
    pub psiphon_license: String,

    // ── Engine settings ──────────────────────────────────────────
    /// Local interface binding hint.
    #[serde(alias = "INTERFACE_IPV4", default)]
    pub interface_ipv4: Option<IpAddr>,
    /// TCP keepalive idle time in seconds.
    #[serde(default = "default_keepalive_idle")]
    pub keepalive_idle: u32,
    /// TCP keepalive interval in seconds.
    #[serde(default = "default_keepalive_interval")]
    pub keepalive_interval: u32,
    /// TCP keepalive count before dropping.
    #[serde(default = "default_keepalive_count")]
    pub keepalive_count: u32,
    /// Max seconds to wait for fake data ack.
    #[serde(default = "default_handshake_timeout")]
    pub handshake_timeout_secs: u64,
    /// Delay in µs before injecting fake packets.
    #[serde(default = "default_inject_delay_us")]
    pub inject_delay_us: u64,
    /// Enable verbose packet dump logging.
    #[serde(default)]
    pub debug_packet_dump: bool,

    // ── TLS settings ─────────────────────────────────────────────
    /// ALPN protocols (comma-separated).
    #[serde(alias = "TLS_ALPN", default = "default_tls_alpn")]
    pub tls_alpn: String,
    /// TLS connector backend.
    #[serde(alias = "TLS_CONNECTOR", default)]
    pub tls_connector: TlsConnectorBackend,
    /// TLS fingerprint kind.
    #[serde(alias = "TLS_FINGERPRINT", default)]
    pub tls_fingerprint: TlsFingerprintKind,
    /// Whether to enable TLS on outbound relay.
    #[serde(alias = "TLS_ENABLED", default)]
    pub tls_enabled: bool,
    /// Whether to verify server TLS certs.
    #[serde(alias = "TLS_VERIFY_CERTS", default = "default_tls_verify")]
    pub tls_verify_certs: bool,
    /// Custom SNI for TLS ClientHello.
    #[serde(alias = "TLS_SNI", default)]
    pub tls_sni: Option<String>,
}

// ── Default values ────────────────────────────────────────────────

fn default_fake_sni() -> String {
    "hcaptcha.com".to_string()
}
fn default_socks_port() -> u16 {
    10808
}
fn default_http_port() -> u16 {
    10809
}
fn default_warp_endpoint() -> String {
    "162.159.192.1".to_string()
}
fn default_psiphon_country() -> String {
    "US".to_string()
}
fn default_psiphon_endpoint() -> String {
    "162.159.192.1".to_string()
}
fn default_tls_alpn() -> String {
    "h2,http/1.1".to_string()
}
fn default_tls_verify() -> bool {
    true
}
fn default_keepalive_idle() -> u32 {
    11
}
fn default_keepalive_interval() -> u32 {
    2
}
fn default_keepalive_count() -> u32 {
    3
}
fn default_handshake_timeout() -> u64 {
    2
}
fn default_inject_delay_us() -> u64 {
    1000
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            connection_mode: ConnectionMode::default(),
            listen_host: "127.0.0.1".parse().unwrap(),
            listen_port: 40443,
            connect_host: "104.19.229.21".parse().unwrap(),
            connect_port: 443,
            fake_sni: default_fake_sni(),
            bypass_mode: BypassMethod::default(),
            data_mode: DataMode::default(),
            socks_port: default_socks_port(),
            http_port: default_http_port(),
            trojan_password: String::new(),
            trojan_sni: String::new(),
            trojan_transport: TrojanTransport::default(),
            trojan_path: String::new(),
            trojan_host: String::new(),
            warp_endpoint: default_warp_endpoint(),
            warp_license: String::new(),
            psiphon_country: default_psiphon_country(),
            psiphon_endpoint: default_psiphon_endpoint(),
            psiphon_license: String::new(),
            interface_ipv4: None,
            keepalive_idle: default_keepalive_idle(),
            keepalive_interval: default_keepalive_interval(),
            keepalive_count: default_keepalive_count(),
            handshake_timeout_secs: default_handshake_timeout(),
            inject_delay_us: default_inject_delay_us(),
            debug_packet_dump: false,
            tls_alpn: default_tls_alpn(),
            tls_connector: TlsConnectorBackend::default(),
            tls_fingerprint: TlsFingerprintKind::default(),
            tls_enabled: true,
            tls_verify_certs: default_tls_verify(),
            tls_sni: None,
        }
    }
}

impl AppConfig {
    /// Parse from JSON string.
    pub fn from_json_str(json: &str) -> Result<Self, CommonError> {
        serde_json::from_str(json)
            .map_err(|e| CommonError::Config(format!("Failed to parse config JSON: {e}")))
    }

    /// Serialize to JSON string.
    pub fn to_json_string(&self) -> Result<String, CommonError> {
        serde_json::to_string_pretty(self)
            .map_err(|e| CommonError::Config(format!("Failed to serialize config: {e}")))
    }

    /// Load from JSON file.
    pub fn from_json_file<P: AsRef<Path>>(path: P) -> Result<Self, CommonError> {
        let contents = std::fs::read_to_string(path.as_ref())
            .map_err(|e| CommonError::Config(format!("Failed to read config file: {e}")))?;
        Self::from_json_str(&contents)
    }

    /// Parse a Trojan share URL (trojan://...).
    pub fn from_trojan_url(url: &str) -> Result<Self, CommonError> {
        let url = url
            .strip_prefix("trojan://")
            .ok_or_else(|| CommonError::Config("Not a valid trojan:// URL".into()))?;

        let (password_host, fragment) = match url.split_once('#') {
            Some((ph, f)) => (ph, Some(f)),
            None => (url, None),
        };

        let (password, host_port_query) = password_host
            .split_once('@')
            .ok_or_else(|| CommonError::Config("Missing @ in trojan URL".into()))?;

        let (host_port, query) = match host_port_query.split_once('?') {
            Some((hp, q)) => (hp, Some(q)),
            None => (host_port_query, None),
        };

        let (host, port_str) = host_port.split_once(':').unwrap_or((host_port, "443"));
        let port: u16 = port_str.parse().unwrap_or(443);
        let host_is_local_proxy = matches!(host, "127.0.0.1" | "localhost" | "::1");

        let mut config = AppConfig {
            connection_mode: if host_is_local_proxy {
                ConnectionMode::SniOnly
            } else {
                ConnectionMode::Trojan
            },
            trojan_password: password.to_string(),
            trojan_sni: host.to_string(),
            trojan_host: host.to_string(),
            listen_host: if host_is_local_proxy {
                "127.0.0.1".parse().unwrap()
            } else {
                AppConfig::default().listen_host
            },
            listen_port: if host_is_local_proxy { port } else { 40443 },
            connect_host: if host_is_local_proxy {
                AppConfig::default().connect_host
            } else {
                host.parse()
                    .unwrap_or_else(|_| AppConfig::default().connect_host)
            },
            connect_port: if host_is_local_proxy { 443 } else { port },
            fake_sni: host.to_string(),
            bypass_mode: BypassMethod::WrongSeq,
            data_mode: DataMode::Tls,
            ..Default::default()
        };

        // Parse query parameters
        if let Some(q) = query {
            for pair in q.split('&') {
                if let Some((k, v)) = pair.split_once('=') {
                    match k {
                        "sni" => {
                            config.trojan_sni = v.to_string();
                            config.tls_sni = Some(v.to_string());
                            config.fake_sni = v.to_string();
                        }
                        "security" => {
                            config.tls_enabled = v == "tls";
                        }
                        "type" => {
                            config.trojan_transport = match v {
                                "ws" => TrojanTransport::Ws,
                                "grpc" => TrojanTransport::Grpc,
                                _ => TrojanTransport::Tcp,
                            };
                            config.data_mode = DataMode::Tls;
                        }
                        "path" => config.trojan_path = urlencoding_decode(v),
                        "host" => {
                            config.trojan_host = v.to_string();
                            if config.fake_sni == host {
                                config.fake_sni = v.to_string();
                            }
                        }
                        "insecure" | "allowInsecure" => {
                            config.tls_verify_certs = v != "1" && v != "true";
                        }
                        _ => {}
                    }
                }
            }
        }

        // If there was a fragment, store it as a note
        if let Some(_frag) = fragment {
            // Fragment is typically a display name; we ignore it
        }

        Ok(config)
    }
}

fn urlencoding_decode(s: &str) -> String {
    // Simple URL decoder for percent-encoded chars
    let mut result = String::with_capacity(s.len());
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c == '%' {
            let hex: String = chars.by_ref().take(2).collect();
            if let Ok(byte) = u8::from_str_radix(&hex, 16) {
                result.push(byte as char);
            }
        } else {
            result.push(c);
        }
    }
    result
}

// ── Backward compatibility: map old EngineConfig fields ───────────

impl From<AppConfig> for crate::EngineConfig {
    fn from(app: AppConfig) -> Self {
        Self {
            listen_host: app.listen_host,
            listen_port: app.listen_port,
            connect_host: app.connect_host,
            connect_port: app.connect_port,
            fake_sni: app.fake_sni,
            bypass_mode: app.bypass_mode,
            data_mode: app.data_mode,
            interface_ipv4: app.interface_ipv4,
            keepalive_idle: app.keepalive_idle,
            keepalive_interval: app.keepalive_interval,
            keepalive_count: app.keepalive_count,
            handshake_timeout_secs: app.handshake_timeout_secs,
            inject_delay_us: app.inject_delay_us,
            debug_packet_dump: app.debug_packet_dump,
            tls_alpn: app.tls_alpn,
            tls_connector: app.tls_connector,
            tls_fingerprint: app.tls_fingerprint,
            tls_enabled: app.tls_enabled,
            tls_verify_certs: app.tls_verify_certs,
            tls_sni: app.tls_sni,
        }
    }
}

// ═══════════════════════════════════════════════════════════════════
// Keep original EngineConfig for backward compat
// ═══════════════════════════════════════════════════════════════════

/// Legacy engine-only configuration (kept for backward compatibility).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EngineConfig {
    #[serde(alias = "LISTEN_HOST")]
    pub listen_host: IpAddr,
    #[serde(alias = "LISTEN_PORT")]
    pub listen_port: u16,
    #[serde(alias = "CONNECT_IP")]
    pub connect_host: IpAddr,
    #[serde(alias = "CONNECT_PORT")]
    pub connect_port: u16,
    #[serde(alias = "FAKE_SNI", default = "default_fake_sni")]
    pub fake_sni: String,
    #[serde(default)]
    pub bypass_mode: BypassMethod,
    #[serde(default)]
    pub data_mode: DataMode,
    #[serde(alias = "INTERFACE_IPV4", default)]
    pub interface_ipv4: Option<IpAddr>,
    #[serde(default = "default_keepalive_idle")]
    pub keepalive_idle: u32,
    #[serde(default = "default_keepalive_interval")]
    pub keepalive_interval: u32,
    #[serde(default = "default_keepalive_count")]
    pub keepalive_count: u32,
    #[serde(default = "default_handshake_timeout")]
    pub handshake_timeout_secs: u64,
    #[serde(default = "default_inject_delay_us")]
    pub inject_delay_us: u64,
    #[serde(default)]
    pub debug_packet_dump: bool,
    #[serde(alias = "TLS_ALPN", default = "default_tls_alpn")]
    pub tls_alpn: String,
    #[serde(alias = "TLS_CONNECTOR", default)]
    pub tls_connector: TlsConnectorBackend,
    #[serde(alias = "TLS_FINGERPRINT", default)]
    pub tls_fingerprint: TlsFingerprintKind,
    #[serde(alias = "TLS_ENABLED", default)]
    pub tls_enabled: bool,
    #[serde(alias = "TLS_VERIFY_CERTS", default = "default_tls_verify")]
    pub tls_verify_certs: bool,
    #[serde(alias = "TLS_SNI", default)]
    pub tls_sni: Option<String>,
}

impl Default for EngineConfig {
    fn default() -> Self {
        Self {
            listen_host: "127.0.0.1".parse().unwrap(),
            listen_port: 1080,
            connect_host: "188.114.98.0".parse().unwrap(),
            connect_port: 443,
            fake_sni: default_fake_sni(),
            bypass_mode: BypassMethod::default(),
            data_mode: DataMode::default(),
            interface_ipv4: None,
            keepalive_idle: default_keepalive_idle(),
            keepalive_interval: default_keepalive_interval(),
            keepalive_count: default_keepalive_count(),
            handshake_timeout_secs: default_handshake_timeout(),
            inject_delay_us: default_inject_delay_us(),
            debug_packet_dump: false,
            tls_alpn: default_tls_alpn(),
            tls_connector: TlsConnectorBackend::default(),
            tls_fingerprint: TlsFingerprintKind::default(),
            tls_enabled: true,
            tls_verify_certs: default_tls_verify(),
            tls_sni: None,
        }
    }
}

impl EngineConfig {
    pub fn from_json_file<P: AsRef<Path>>(path: P) -> Result<Self, CommonError> {
        let contents = std::fs::read_to_string(path.as_ref())
            .map_err(|e| CommonError::Config(format!("Failed to read config file: {e}")))?;
        Self::from_json_str(&contents)
    }
    pub fn from_json_str(json: &str) -> Result<Self, CommonError> {
        serde_json::from_str(json)
            .map_err(|e| CommonError::Config(format!("Failed to parse config JSON: {e}")))
    }
    pub fn to_json_string(&self) -> Result<String, CommonError> {
        serde_json::to_string_pretty(self)
            .map_err(|e| CommonError::Config(format!("Failed to serialize config: {e}")))
    }
}

// ── Hot-reloadable config wrapper ─────────────────────────────────

#[derive(Clone)]
pub struct DynamicConfig {
    inner: Arc<RwLock<EngineConfig>>,
}

impl DynamicConfig {
    pub fn new(config: EngineConfig) -> Self {
        Self {
            inner: Arc::new(RwLock::new(config)),
        }
    }
    pub fn read(&self) -> EngineConfig {
        self.inner.read().clone()
    }
    pub fn swap(&self, new: EngineConfig) {
        *self.inner.write() = new;
    }
    pub fn reload_from_file<P: AsRef<Path>>(&self, path: P) -> Result<(), CommonError> {
        let new = EngineConfig::from_json_file(path)?;
        self.swap(new);
        Ok(())
    }
}

// ── Tests ─────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_old_python_format() {
        let json = r#"{
            "LISTEN_HOST": "0.0.0.0",
            "LISTEN_PORT": 40443,
            "CONNECT_IP": "188.114.98.0",
            "CONNECT_PORT": 443,
            "FAKE_SNI": "auth.vercel.com"
        }"#;
        let config = EngineConfig::from_json_str(json).unwrap();
        assert_eq!(config.listen_port, 40443);
    }

    #[test]
    fn test_parse_new_format() {
        let json = r#"{
            "listen_host": "127.0.0.1",
            "listen_port": 1080,
            "connect_host": "1.2.3.4",
            "connect_port": 8443,
            "fake_sni": "www.cloudflare.com",
            "bypass_mode": "wrong_seq"
        }"#;
        let config = EngineConfig::from_json_str(json).unwrap();
        assert_eq!(config.listen_port, 1080);
    }

    #[test]
    fn test_parse_app_config() {
        let json = r#"{
            "connection_mode": "sni_only",
            "listen_host": "0.0.0.0",
            "listen_port": 40443,
            "connect_host": "104.19.229.21",
            "connect_port": 443,
            "fake_sni": "hcaptcha.com",
            "socks_port": 10808,
            "http_port": 10809,
            "trojan_password": "humanity",
            "trojan_sni": "www.multiplydose.com"
        }"#;
        let config = AppConfig::from_json_str(json).unwrap();
        assert_eq!(config.connection_mode, ConnectionMode::SniOnly);
        assert_eq!(config.socks_port, 10808);
        assert_eq!(config.trojan_password, "humanity");
    }

    #[test]
    fn test_trojan_url_parse() {
        let url = "trojan://humanity@127.0.0.1:40443?security=tls&sni=www.multiplydose.com&insecure=0&allowInsecure=0&type=ws&path=%2Fassignment#%40V2raysCollector%20%F0%9F%92%98";
        let config = AppConfig::from_trojan_url(url).unwrap();
        assert_eq!(config.connection_mode, ConnectionMode::SniOnly);
        assert_eq!(config.trojan_password, "humanity");
        assert_eq!(config.trojan_sni, "www.multiplydose.com");
        assert_eq!(config.trojan_transport, TrojanTransport::Ws);
        assert_eq!(config.trojan_path, "/assignment");
        assert_eq!(config.trojan_host, "www.multiplydose.com");
        assert_eq!(config.tls_sni, Some("www.multiplydose.com".into()));
        assert_eq!(config.listen_host, "127.0.0.1".parse().unwrap());
        assert_eq!(config.listen_port, 40443);
        assert_eq!(config.connect_host, AppConfig::default().connect_host);
        assert_eq!(config.connect_port, 443);
        assert_eq!(config.fake_sni, "www.multiplydose.com");
        assert!(config.tls_verify_certs);
    }
}
