//! # Configuration Demo
//!
//! Demonstrates how to:
//! 1. Load configuration from a JSON file.
//! 2. Create a dynamic config handle for hot-reloading.
//! 3. Generate a fake TLS ClientHello.
//! 4. Print engine statistics.

use mamadvpn_common::{ClientHelloBuilder, DynamicConfig, EngineConfig};

fn main() {
    println!("=== MamadVPN Configuration Demo ===\n");

    // Load from JSON string (equivalent to reading from file)
    let config_json = r#"{
        "listen_host": "127.0.0.1",
        "listen_port": 1080,
        "connect_host": "188.114.98.0",
        "connect_port": 443,
        "fake_sni": "auth.vercel.com",
        "bypass_mode": "wrong_seq",
        "data_mode": "tls"
    }"#;

    let config = EngineConfig::from_json_str(config_json).expect("Failed to parse config");
    println!("Loaded config:");
    println!("  Listen:     {}:{}", config.listen_host, config.listen_port);
    println!("  Target:     {}:{}", config.connect_host, config.connect_port);
    println!("  Fake SNI:   {}", config.fake_sni);
    println!("  Bypass:     {:?}", config.bypass_mode);
    println!("  Data mode:  {:?}", config.data_mode);
    println!();

    // Create hot-reloadable config
    let dynamic_config = DynamicConfig::new(config);
    println!("Dynamic config handle created. Current config:");
    let current = dynamic_config.read();
    println!("  Listen: {}:{}", current.listen_host, current.listen_port);
    println!();

    // Generate a fake TLS ClientHello
    let sni = current.fake_sni.as_bytes();
    let client_hello = ClientHelloBuilder::generate(sni);
    println!(
        "Generated fake TLS ClientHello ({} bytes) with SNI: {}",
        client_hello.len(),
        current.fake_sni
    );
    println!("  First 16 bytes (hex): {:02x?}", &client_hello[..16]);
    println!();

    // Sign extension length [0:2]
    let ext_len = u16::from_be_bytes([client_hello[120], client_hello[121]]);
    println!("  SNI extension length: {ext_len}");

    // SNI position (offset 127 by template)
    let sni_pos = 127;
    let sni_bytes = &client_hello[sni_pos..sni_pos + sni.len()];
    let sni_str = std::str::from_utf8(sni_bytes).unwrap_or("<invalid>");
    println!("  Embedded SNI: {sni_str}");

    println!("\n=== Demo complete ===");
}
