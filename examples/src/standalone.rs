//! # MamadVPN Standalone
//!
//! A standalone executable that loads a JSON configuration file and runs
//! the transport engine.
//!
//! ## Usage
//!
//! ```bash
//! # With a config file
//! cargo run --bin standalone -- --config /path/to/config.json
//!
//! # Or use environment variables (for quick testing)
//! LISTEN_HOST=127.0.0.1 LISTEN_PORT=1080 \
//! CONNECT_HOST=1.2.3.4 CONNECT_PORT=443 \
//! FAKE_SNI=www.cloudflare.com \
//! cargo run --bin standalone
//! ```

use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::Parser;
use tracing_subscriber::{fmt, prelude::*, EnvFilter};

use mamadvpn_common::{DynamicConfig, EngineConfig};
use mamadvpn_core::TransportEngine;

#[derive(Parser, Debug)]
#[command(name = "mamadvpn", version, about = "MamadVPN Transport Engine")]
struct Args {
    /// Path to JSON configuration file.
    #[arg(short, long)]
    config: Option<PathBuf>,

    /// Listen host (overrides config file).
    #[arg(long, default_value = "127.0.0.1")]
    listen_host: String,

    /// Listen port (overrides config file).
    #[arg(long, default_value_t = 1080)]
    listen_port: u16,

    /// Remote connect host (overrides config file).
    #[arg(long)]
    connect_host: Option<String>,

    /// Remote connect port (overrides config file).
    #[arg(long, default_value_t = 443)]
    connect_port: u16,

    /// Fake SNI hostname (overrides config file).
    #[arg(long)]
    fake_sni: Option<String>,

    /// Bypass method (overrides config file).
    #[arg(long, default_value = "wrong_seq")]
    bypass_mode: String,
}

fn load_config(args: &Args) -> Result<EngineConfig> {
    // Try loading from file first
    if let Some(config_path) = &args.config {
        let config = EngineConfig::from_json_file(config_path)
            .with_context(|| format!("Failed to load config from {}", config_path.display()))?;
        return Ok(config);
    }

    // Build from environment variables with CLI overrides
    let mut config = EngineConfig::default();

    if let Ok(host) = std::env::var("LISTEN_HOST") {
        config.listen_host = host.parse().context("Invalid LISTEN_HOST")?;
    }
    if let Ok(port) = std::env::var("LISTEN_PORT") {
        config.listen_port = port.parse().context("Invalid LISTEN_PORT")?;
    }
    if let Ok(host) = std::env::var("CONNECT_HOST") {
        config.connect_host = host.parse().context("Invalid CONNECT_HOST")?;
    }
    if let Ok(port) = std::env::var("CONNECT_PORT") {
        config.connect_port = port.parse().context("Invalid CONNECT_PORT")?;
    }
    if let Ok(sni) = std::env::var("FAKE_SNI") {
        config.fake_sni = sni;
    }
    if let Ok(mode) = std::env::var("BYPASS_MODE") {
        config.bypass_mode = serde_json::from_str(&format!("\"{mode}\""))
            .context("Invalid BYPASS_MODE")?;
    }

    // CLI overrides take priority
    config.listen_host = args.listen_host.parse().context("Invalid --listen-host")?;
    config.listen_port = args.listen_port;
    if let Some(connect_host) = &args.connect_host {
        config.connect_host = connect_host.parse().context("Invalid --connect-host")?;
    }
    config.connect_port = args.connect_port;
    if let Some(fake_sni) = &args.fake_sni {
        config.fake_sni = fake_sni.clone();
    }
    config.bypass_mode = serde_json::from_str(&format!("\"{}\"", args.bypass_mode))
        .context("Invalid --bypass-mode")?;

    Ok(config)
}

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize tracing
    tracing_subscriber::registry()
        .with(fmt::layer().pretty())
        .with(EnvFilter::from_default_env().add_directive(tracing::Level::INFO.into()))
        .init();

    let args = Args::parse();
    let config = load_config(&args)?;

    tracing::info!(
        "Starting MamadVPN engine — listening on {}:{}, target {}:{}, fake SNI: {}, bypass: {:?}",
        config.listen_host,
        config.listen_port,
        config.connect_host,
        config.connect_port,
        config.fake_sni,
        config.bypass_mode,
    );

    let dynamic_config = DynamicConfig::new(config);
    let engine = TransportEngine::new(dynamic_config);

    tracing::info!("Engine started. Press Ctrl+C to stop.");

    // Run until Ctrl+C
    tokio::select! {
        result = engine.run() => {
            result?;
        }
        _ = tokio::signal::ctrl_c() => {
            tracing::info!("Received Ctrl+C, shutting down");
        }
    }

    tracing::info!("MamadVPN engine stopped");
    Ok(())
}
