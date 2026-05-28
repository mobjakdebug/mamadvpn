# MamadVPN

**TCP/TLS Desynchronization-Based Censorship Circumvention Transport Engine**

A modern, production-grade Rust rewrite of a legacy Python censorship-circumvention system. Uses TCP sequence desynchronization, fake TLS ClientHello injection, and raw packet manipulation to bypass Deep Packet Inspection (DPI).

---

## Architecture

```
┌──────────────────────────────────────────────────────────────┐
│                     External Applications                    │
│  (Flutter, Android VPN, Windows App, CLI)                    │
└──────────────────────────┬───────────────────────────────────┘
                           │ FFI / JNI / IPC
┌──────────────────────────▼───────────────────────────────────┐
│                       API Layer (api/)                        │
│              C ABI · Flutter Bindings · JNI Bridge            │
└──────────────────────────┬───────────────────────────────────┘
                           │
┌──────────────────────────▼───────────────────────────────────┐
│                   Transport Core (core/)                       │
│                                                               │
│  ┌─────────────┐  ┌──────────────┐  ┌──────────────────────┐ │
│  │ State Mach. │  │   Bypass     │  │   Relay Engine        │ │
│  │ (state.rs)  │  │   Registry   │  │   (relay.rs)          │ │
│  └──────┬──────┘  └──────┬───────┘  └──────────┬───────────┘ │
│         │                │                      │             │
│  ┌──────▼────────────────▼──────────────────────▼───────────┐ │
│  │               Connection Tracker (connection.rs)          │ │
│  └──────────────────────────────────────────────────────────┘ │
└──────────────────────────┬───────────────────────────────────┘
                           │
┌──────────────────────────▼───────────────────────────────────┐
│                    Common Layer (common/)                      │
│  Packet Types · TLS Templates · Config · Connection IDs       │
└──────────────────────────┬───────────────────────────────────┘
                           │
┌──────────────────────────▼───────────────────────────────────┐
│                  Platform Backends (platforms/)                │
│  ┌──────────┐  ┌────────────┐  ┌────────────┐  ┌──────────┐ │
│  │ Windows  │  │   Linux    │  │  Android   │  │  macOS   │ │
│  │WinDivert │  │ NFQUEUE    │  │ TUN/VPN    │  │ (future) │ │
│  └──────────┘  └────────────┘  └────────────┘  └──────────┘ │
└──────────────────────────────────────────────────────────────┘
```

### Bypass Flow (wrong_seq method)

```
Client                    Injector                     Server
  │                         │                            │
  │─────── SYN ────────────►│ (capture, record syn_seq)  │
  │                         │─────────── SYN ───────────►│
  │                         │◄───────── SYN-ACK ────────│
  │◄────── SYN-ACK ────────│ (validate, record syn_ack)  │
  │─────── ACK ────────────►│ (validate, schedule inject)│
  │                         │─────────── ACK ───────────►│
  │                         │                             │
  │                         │ (1ms delay)                 │
  │                         │──── Fake CH (wrong seq) ──►│ (ignores - OOO)
  │                         │                             │
  │──── Real CH (correct) ──►───────── Real CH ──────────►│
  │                         │                             │
  │                         │◄─────────── ACK ───────────│
  │◄──────── ACK ──────────│ (fake data ACKed! proceed)   │
  │                         │                             │
  │◄══════════════ Relay ═══════════════════════════════►│
```

The fake TLS ClientHello is sent with **`seq_num = syn_seq + 1 - len(fake_data)`**, making it appear as an out-of-order segment to the real server (which ignores it) while the DPI processes it first and sees the fake SNI.

---

## Project Structure

```
mamadvpn/
├── Cargo.toml              # Workspace manifest
├── common/                 # Shared types, config, packet parsing, TLS templates
│   └── src/
│       ├── lib.rs
│       ├── config.rs       # EngineConfig, DynamicConfig (hot-reload)
│       ├── connection_id.rs # ConnectionId (4-tuple)
│       ├── error.rs        # Error types
│       ├── packet.rs       # IP/TCP header parsing and reconstruction
│       └── tls.rs          # ClientHello/ServerHello builder (Python-compatible)
├── core/                   # Transport engine
│   └── src/
│       ├── lib.rs
│       ├── state.rs        # ConnectionState machine
│       ├── connection.rs   # ManagedConnection (thread-safe)
│       ├── bypass.rs       # BypassHandler trait + registry
│       │   └── implementations/
│       │       └── wrong_seq.rs  # WrongSeq bypass
│       ├── engine.rs       # TransportEngine orchestrator
│       ├── interceptor.rs  # PacketInterceptor trait
│       ├── raw.rs          # Raw packet construction
│       └── relay.rs        # Bidirectional async relay
├── api/                    # C ABI / FFI bindings
│   └── src/lib.rs          # mamadvpn_initialize, connect, disconnect, etc.
├── platforms/
│   ├── linux/              # NFQUEUE + raw socket backend
│   │   └── src/lib.rs
│   ├── windows/            # WinDivert backend
│   │   └── src/lib.rs
│   └── android/            # TUN/VpnService + JNI bridge
│       └── src/lib.rs
├── tests/                  # Integration test helpers
│   └── src/lib.rs
├── examples/               # Usage examples
│   └── src/
│       ├── standalone.rs   # CLI binary
│       └── demo_config.rs  # Config demo
└── docs/                   # Architecture documentation
```

---

## Build Instructions

### Prerequisites

- Rust 1.75+ (edition 2021)
- Cargo (included with Rust)

### Build All

```bash
cargo build --workspace
```

### Build Specific Crate

```bash
cargo build -p mamadvpn-core
cargo build -p mamadvpn-common
cargo build -p mamadvpn-api       # Requires: cargo build -p mamadvpn-api --lib
```

### Run Tests

```bash
cargo test --workspace
```

### Run the Standalone Binary

```bash
# With a config file
cargo run --bin standalone -- --config /path/to/config.json

# With CLI arguments
cargo run --bin standalone -- \
    --listen-host 127.0.0.1 \
    --listen-port 1080 \
    --connect-host 188.114.98.0 \
    --connect-port 443 \
    --fake-sni auth.vercel.com

# With environment variables
LISTEN_HOST=127.0.0.1 LISTEN_PORT=1080 \
CONNECT_HOST=188.114.98.0 CONNECT_PORT=443 \
FAKE_SNI=auth.vercel.com \
cargo run --bin standalone
```

### Run Demo

```bash
cargo run --bin demo-config
```

---

## Configuration

### JSON Configuration File

```json
{
  "listen_host": "127.0.0.1",
  "listen_port": 1080,
  "connect_host": "188.114.98.0",
  "connect_port": 443,
  "fake_sni": "auth.vercel.com",
  "bypass_mode": "wrong_seq",
  "data_mode": "tls",
  "keepalive_idle": 11,
  "keepalive_interval": 2,
  "keepalive_count": 3,
  "handshake_timeout_secs": 2,
  "inject_delay_us": 1000,
  "debug_packet_dump": false
}
```

### Bypass Modes

| Mode | Description | Status |
|------|-------------|--------|
| `wrong_seq` | Fake TLS with manipulated sequence number | ✅ Implemented |
| `bad_checksum` | Packets with incorrect TCP checksum | 🔄 Planned |
| `fragmentation` | TCP fragmentation to evade DPI | 🔄 Planned |
| `delayed_ack` | Intentional ACK delays | 🔄 Planned |
| `fake_rst` | Fake RST packets to disrupt DPI state | 🔄 Planned |

---

## API Usage (C ABI)

```c
#include "mamadvpn.h"

int main() {
    // Initialize with JSON config
    const char* config = "{ \"listen_host\": \"127.0.0.1\", ... }";
    mamadvpn_initialize(config);

    // Update config at runtime (hot-reload)
    mamadvpn_update_config(new_config);

    // Get statistics
    MamadVPNStats stats;
    mamadvpn_get_stats(&stats);

    // Graceful shutdown
    mamadvpn_shutdown();
    return 0;
}
```

### Rust API

```rust
use mamadvpn_common::EngineConfig;
use mamadvpn_common::DynamicConfig;
use mamadvpn_core::TransportEngine;

let config = EngineConfig::default();
let dynamic_config = DynamicConfig::new(config);
let engine = TransportEngine::new(dynamic_config);

// Run the engine
tokio::spawn(async move {
    engine.run().await
});
```

---

## Android Integration

The Android backend uses JNI to bridge Kotlin's `VpnService` with the Rust engine. Key files:

- `platforms/android/src/lib.rs` — JNI bridge and TUN interceptor
- `platforms/android/Cargo.toml` — Uses `jni` crate for JNI bindings

### Building for Android

```bash
# Requires Android NDK + cargo-ndk
cargo ndk -t arm64-v8a -o ../android/app/src/main/jniLibs build --package mamadvpn-platform-android
```

### Kotlin Integration

```kotlin
class MamadVPNService : VpnService() {
    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        val tunFd = Builder().apply {
            addAddress("10.0.0.1", 24)
            addRoute("0.0.0.0", 0)
            setMtu(1500)
        }.establish()

        nativeInit(configJson)
        nativeStart(tunFd.detachFd())
        return START_STICKY
    }

    companion object {
        init {
            System.loadLibrary("mamadvpn_platform_android")
        }
    }

    private external fun nativeInit(configJson: String): Int
    private external fun nativeStart(tunFd: Int): Int
    private external fun nativeStop(): Int
}
```

---

## Windows Integration

The Windows backend uses WinDivert for packet interception. The API crate provides a standalone executable mode and a Windows service mode.

### Building for Windows

```bash
# Requires WinDivert64.dll in PATH
cargo build -p mamadvpn-platform-windows
cargo build -p mamadvpn-api --lib
```

---

## Performance Characteristics

- **Zero-copy packet parsing** using `bytes::Bytes`
- **Async I/O** with `tokio` for high-concurrency relay
- **Lock-free** read paths where possible
- **Parking-lot mutexes** for low-contention state access
- **Per-connection concurrency** via `tokio::spawn`
- **Configurable** inject delay (default 1ms, matching Python)

---

## Security Considerations

- **No `unsafe` code** in the core engine (platform backends may need it for raw socket access)
- **All packet fields validated** before processing — malformed packets are dropped
- **No panics** in production paths — all errors are handled gracefully
- **Structured logging** via `tracing` for debugging and monitoring
- **Graceful shutdown** — all connections are cleaned up on exit
- **Memory safe** — Rust's ownership model prevents use-after-free and buffer overflows

---

## License

MIT

## Acknowledgments

- Original Python prototype by [@patterniha](https://t.me/patterniha)
- Built for the MamadVPN project
