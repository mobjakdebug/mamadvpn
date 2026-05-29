//! Remote API synchronization — fetches available VPN nodes from a PHP backend.
//!
//! Each node specifies a country, a fake SNI to use for DPI bypass, and a
//! configuration URL for Xray-core (Trojan / VLESS subscription URIs).

use anyhow::{Context, Result};
use serde::Deserialize;

/// Represents a single VPN node fetched from the remote API.
#[derive(Debug, Clone, Deserialize)]
pub struct Node {
    /// Human-readable name for this node (e.g. "Germany-Frankfurt").
    pub name: String,
    /// ISO country code or display name.
    pub country: String,
    /// The whitelisted SNI hostname used to trick the DPI firewall.
    pub fake_sni: String,
    /// The bypass method to use (e.g. "wrong_seq").
    pub bypass_method: String,
    /// Subscription URI (Trojan / VLESS / VMess) that Xray-core will consume.
    pub config_url: String,
    /// The actual proxy server IPv4 address to connect to for the TCP relay.
    /// This is DIFFERENT from `fake_sni` — `connect_ip` is the real target
    /// server, while `fake_sni` is the hostname spoofed in the fake ClientHello.
    /// May be a hostname (resolved at runtime) or an IP address.
    #[serde(default)]
    pub connect_ip: String,
}

/// Full API response envelope.
#[derive(Debug, Deserialize)]
pub struct ApiResponse {
    pub nodes: Vec<Node>,
}

/// Fetch the list of available nodes from the remote API endpoint.
///
/// # Arguments
/// * `api_url` – Full URL to the PHP endpoint (e.g. `https://example.com/api.php`).
/// * `access_token` – Bearer-style token sent in the `X-Access-Token` header.
pub async fn fetch_nodes(api_url: &str, access_token: &str) -> Result<Vec<Node>> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(15))
        .danger_accept_invalid_certs(false) // enforce TLS validation
        .build()
        .context("Failed to build HTTP client")?;

    let resp = client
        .get(api_url)
        .header("X-Access-Token", access_token)
        .header("User-Agent", "MamadVPN/1.0")
        .header("Accept", "application/json")
        .send()
        .await
        .context("API request failed")?;

    let status = resp.status();
    if !status.is_success() {
        anyhow::bail!("API returned HTTP {}", status);
    }

    let body: ApiResponse = resp.json().await.context("Failed to parse API JSON")?;

    if body.nodes.is_empty() {
        anyhow::bail!("API returned an empty node list");
    }

    Ok(body.nodes)
}
