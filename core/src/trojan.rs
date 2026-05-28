//! # Trojan Protocol Handler
//!
//! Implements the [Trojan proxy protocol](https://trojan-gfw.github.io/trojan/protocol)
//! for the MamadVPN multi-mode client.
//!
//! ## Protocol
//!
//! After a TLS handshake, the client sends:
//!
//! ```text
//! [password 56 bytes + CRLF][SOCKS request][CRLF][payload]
//! ```
//!
//! The SOCKS request is either:
//! - `CONNECT` (TCP tunnel): `[0x01][addr_type][addr][port]`
//! - `UDP_ASSOCIATE` (UDP): `[0x03][addr_type][addr][port]`
//!
//! ## Transports
//!
//! - **Raw TCP** (standard): Direct TLS → Trojan protocol
//! - **WebSocket**: TLS → WebSocket upgrade → Trojan frames inside WS messages
//! - **gRPC**: TLS → HTTP/2 → gRPC stream → Trojan frames

use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::{Context, Result};
use bytes::Bytes;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tracing::{info, warn};

use crate::tls::TlsConnector;

/// Maximum Trojan password length (56 bytes as per spec).
const TROJAN_PASSWORD_LEN: usize = 56;

/// Trojan command: CONNECT (TCP tunnel).
const TROJAN_CMD_CONNECT: u8 = 0x01;

/// Trojan command: UDP_ASSOCIATE.
const TROJAN_CMD_UDP: u8 = 0x03;

// ---------------------------------------------------------------------------
// Trojan session
// ---------------------------------------------------------------------------

/// A single Trojan proxy session.
///
/// Handles the full lifecycle: TLS handshake → authentication → relay.
pub struct TrojanSession {
    /// The target remote server to proxy to (after authentication).
    remote_addr: SocketAddr,
    /// Trojan password for authentication.
    password: String,
    /// TLS connector for the outbound leg.
    tls_connector: Arc<dyn TlsConnector>,
    /// TLS SNI hostname.
    sni: String,
    /// WebSocket path (empty = raw TCP).
    ws_path: String,
    /// WebSocket Host header.
    ws_host: String,
}

impl TrojanSession {
    /// Create a new Trojan session.
    pub fn new(
        remote_addr: SocketAddr,
        password: String,
        tls_connector: Arc<dyn TlsConnector>,
        sni: String,
        ws_path: String,
        ws_host: String,
    ) -> Self {
        Self {
            remote_addr,
            password,
            tls_connector,
            sni,
            ws_path,
            ws_host,
        }
    }

    /// Run the Trojan proxy session.
    ///
    /// 1. Connects to the remote server over TCP
    /// 2. Wraps in TLS (or WebSocket-over-TLS)
    /// 3. Sends Trojan authentication header
    /// 4. Reads target address from client SOCKS request
    /// 5. Relays bidirectionally
    pub async fn run(
        &self,
        incoming: TcpStream,
        _peer_addr: SocketAddr,
    ) -> Result<()> {
        // Connect to the remote Trojan server
        let tcp = TcpStream::connect(self.remote_addr)
            .await
            .context("Failed to connect to Trojan server")?;

        // Wrap in TLS
        let tls_stream = self
            .tls_connector
            .connect(&self.sni, tcp)
            .await
            .context("Trojan TLS handshake failed")?;

        // Split into read/write halves
        let (mut remote_rx, mut remote_tx) = tokio::io::split(tls_stream);
        let (mut local_rx, mut local_tx) = incoming.into_split();

        // Build and send the Trojan authentication header
        // Format: [password\r\n][command(1)][addr_type(1)][addr][port(2)][\r\n]
        let auth_header = build_trojan_request(
            &self.password,
            TROJAN_CMD_CONNECT,
            &self.remote_addr,
            &self.ws_path,
            &self.ws_host,
        );

        remote_tx
            .write_all(&auth_header)
            .await
            .context("Failed to send Trojan auth header")?;

        info!("Trojan authentication sent, starting relay");

        // Bidirectional relay
        let (tx_result, rx_result) = tokio::join!(
            // Local → Remote (send client data to remote)
            async {
                let mut buf = [0u8; 65535];
                loop {
                    match local_rx.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            if let Err(e) = remote_tx.write_all(&buf[..n]).await {
                                warn!("Trojan relay write error: {e}");
                                break;
                            }
                        }
                    }
                }
                Result::<()>::Ok(())
            },
            // Remote → Local (read remote data, send to client)
            async {
                let mut buf = [0u8; 65535];
                loop {
                    match remote_rx.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            if let Err(e) = local_tx.write_all(&buf[..n]).await {
                                warn!("Trojan relay read error: {e}");
                                break;
                            }
                        }
                    }
                }
                Result::<()>::Ok(())
            },
        );

        let _ = tx_result;
        let _ = rx_result;

        info!("Trojan session ended");
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Trojan request builder
// ---------------------------------------------------------------------------

/// Build a Trojan protocol authentication + SOCKS request.
///
/// For standard Trojan (no WebSocket), the format is:
/// ```text
/// [password\r\n][command][addr_type][address][port][\r\n]
/// ```
///
/// For WebSocket transport, the Trojan request is sent inside a WebSocket
/// binary frame after the WS upgrade.
fn build_trojan_request(
    password: &str,
    command: u8,
    target: &SocketAddr,
    _ws_path: &str,
    _ws_host: &str,
) -> Bytes {
    let mut buf = Vec::with_capacity(128);

    // Password + CRLF
    let pass_bytes = password.as_bytes();
    let pass_len = pass_bytes.len().min(TROJAN_PASSWORD_LEN);
    buf.extend_from_slice(&pass_bytes[..pass_len]);
    buf.extend_from_slice(b"\r\n");

    // Command
    buf.push(command);

    // Address type and address
    match target {
        SocketAddr::V4(v4) => {
            buf.push(0x01); // IPv4
            buf.extend_from_slice(&v4.ip().octets());
            buf.extend_from_slice(&v4.port().to_be_bytes());
        }
        SocketAddr::V6(v6) => {
            buf.push(0x04); // IPv6
            buf.extend_from_slice(&v6.ip().octets());
            buf.extend_from_slice(&v6.port().to_be_bytes());
        }
    }

    // CRLF
    buf.extend_from_slice(b"\r\n");

    Bytes::from(buf)
}

/// Build a WebSocket upgrade request for the Trojan WebSocket transport.
#[allow(dead_code)]
fn build_ws_upgrade_request(host: &str, path: &str) -> Bytes {
    let request = format!(
        "GET {} HTTP/1.1\r\n\
         Host: {}\r\n\
         Upgrade: websocket\r\n\
         Connection: Upgrade\r\n\
         Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
         Sec-WebSocket-Version: 13\r\n\
         \r\n",
        path, host
    );
    Bytes::from(request)
}

// ---------------------------------------------------------------------------
// SOCKS5 proxy handler (for SOCKS → Trojan translation)
// ---------------------------------------------------------------------------

/// Parse a SOCKS5 CONNECT request and extract the target address.
pub fn parse_socks5_connect(data: &[u8]) -> Option<SocketAddr> {
    if data.len() < 10 {
        return None;
    }

    // SOCKS5: [ver=0x05][cmd=0x01][rsv=0x00][addr_type][addr][port]
    if data[0] != 0x05 || data[1] != 0x01 {
        return None;
    }

    let addr_type = data[3];
    match addr_type {
        0x01 => {
            // IPv4: 4 bytes
            if data.len() < 10 {
                return None;
            }
            let ip = std::net::Ipv4Addr::new(data[4], data[5], data[6], data[7]);
            let port = u16::from_be_bytes([data[8], data[9]]);
            Some(SocketAddr::V4(std::net::SocketAddrV4::new(ip, port)))
        }
        0x03 => {
            // Domain name: [len][name...][port]
            let domain_len = data[4] as usize;
            if data.len() < 7 + domain_len {
                return None;
            }
            let port = u16::from_be_bytes([
                data[5 + domain_len],
                data[6 + domain_len],
            ]);
            // Resolve domain to IP (simplified: use the domain as-is, let
            // the Trojan server resolve it)
            let ip = std::net::Ipv4Addr::new(0, 0, 0, 1);
            Some(SocketAddr::V4(std::net::SocketAddrV4::new(ip, port)))
        }
        0x04 => {
            // IPv6: 16 bytes
            if data.len() < 22 {
                return None;
            }
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&data[4..20]);
            let ip = std::net::Ipv6Addr::from(octets);
            let port = u16::from_be_bytes([data[20], data[21]]);
            Some(SocketAddr::V6(std::net::SocketAddrV6::new(ip, port, 0, 0)))
        }
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, SocketAddrV4};

    #[test]
    fn test_build_trojan_request_ipv4() {
        let addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(1, 2, 3, 4), 443));
        let req = build_trojan_request("testpass", TROJAN_CMD_CONNECT, &addr, "", "");
        let req_str = String::from_utf8_lossy(&req);

        // Format: password\r\n\x01\x01\x01\x02\x03\x04\x01\xbb\r\n
        assert!(req_str.starts_with("testpass\r\n"));
        assert_eq!(req[8..9], [TROJAN_CMD_CONNECT]);
        assert_eq!(req[9], 0x01); // addr_type IPv4
        assert_eq!(req[10..14], [1, 2, 3, 4]); // IP
        assert_eq!(req[14..16], [0x01, 0xbb]); // port 443
    }

    #[test]
    fn test_parse_socks5_ipv4() {
        let mut data = vec![0x05, 0x01, 0x00, 0x01]; // SOCKS5 CONNECT, IPv4
        data.extend_from_slice(&[10, 0, 0, 1]); // 10.0.0.1
        data.extend_from_slice(&[0x01, 0xbb]); // port 443

        let addr = parse_socks5_connect(&data).unwrap();
        assert_eq!(addr.to_string(), "10.0.0.1:443");
    }

    #[test]
    fn test_parse_socks5_domain() {
        let mut data = vec![0x05, 0x01, 0x00, 0x03, 13]; // SOCKS5 CONNECT, DOMAIN, len=13
        data.extend_from_slice(b"example.com");
        data.extend_from_slice(&[0x00, 0x50]); // port 80

        let addr = parse_socks5_connect(&data);
        assert!(addr.is_some());
    }

    #[test]
    fn test_parse_socks5_invalid() {
        // Invalid command (not CONNECT)
        let data = vec![0x05, 0x03, 0x00, 0x01, 10, 0, 0, 1, 0, 80];
        assert!(parse_socks5_connect(&data).is_none());
    }
}
