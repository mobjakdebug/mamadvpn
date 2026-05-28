# MamadVPN — Rust Implementation Status

> **Date:** May 27, 2026
> **Status:** Core transport engine complete. TLS connector system integrated. **Linux NFQUEUE backend fully implemented.**
> **Latest:** **Full Flutter Android app built** — 4-mode UI, Rust FFI bridge, VpnService, config management, build scripts.

---

## Project Structure

```
mamadvpn/                          # Cargo workspace root
├── Cargo.toml                     # 8-crate workspace
├── common/                        # Shared types, packet parsing, TLS, config
│   ├── Cargo.toml
│   └── src/
│       ├── lib.rs                 # Crate root, re-exports, get_default_interface_ipv4()
│       ├── config.rs              # EngineConfig + AppConfig (multi-mode), DynamicConfig, all enums
│       ├── connection_id.rs       # ConnectionId type (src_ip+port ↔ dst_ip+port)
│       ├── error.rs               # CommonError enum using thiserror
│       ├── packet.rs              # CapturedPacket, Ipv4Header, TcpHeader, TcpFlags parsing
│       └── tls.rs                 # ClientHelloBuilder — Chrome-fingerprint TLS generator
│
├── core/                          # Transport engine — the heart of the system
│   ├── Cargo.toml
│   └── src/
│       ├── lib.rs
│       ├── state.rs               # ConnectionState machine (8 states) + unit tests
│       ├── connection.rs          # ManagedConnection — thread-safe state + handshake channels
│       ├── bypass.rs              # BypassHandler trait + BypassRegistry dispatcher
│       ├── bypass/implementations/
│       │   └── wrong_seq.rs       # WrongSeqHandler — packet classification + fake injection
│       ├── interceptor.rs         # PacketInterceptor + PacketHandler traits
│       ├── engine.rs              # TransportEngine — listener, handshake, relay orchestration
│       ├── relay.rs               # RelayEngine — bidirectional async socket forwarding (raw + TLS)
│       ├── raw.rs                 # build_ipv4_tcp_packet, IP/TCP checksums
│       ├── trojan.rs              # Trojan protocol handler (SOCKS auth, TLS+WS relay)
│       └── tls/                   # TLS connector system
│           ├── mod.rs             # TlsConnector trait, TlsStream type, TlsBufferIo wrapper
│           ├── connector.rs       # RustlsConnector — production-safe TLS via rustls
│           └── custom.rs          # CustomClientHelloConnector — puts our JA3 on the wire
│
├── api/                           # C ABI / FFI bindings
│   ├── Cargo.toml                 # Builds as cdylib + staticlib
│   └── src/lib.rs                 # Extended C API: init, start, stop, shutdown, update_config,
│                                  #   parse_trojan_url, get_stats, get_status, get_logs, set_tun_fd
│
├── platforms/
│   ├── linux/
│   │   ├── Cargo.toml
│   │   └── src/lib.rs             # NfqueueInterceptor (FULL) — NFQUEUE + raw socket injection
│   ├── android/
│   │   ├── Cargo.toml             # Builds as cdylib for JNI
│   │   └── src/lib.rs             # TunInterceptor + JNI bridge functions (stubs)
│   └── windows/
│       ├── Cargo.toml
│       └── src/lib.rs             # WinDivertInterceptor (stub)
│
├── app/                           # Flutter Android application
│   ├── pubspec.yaml               # Flutter + ffi dependency
│   ├── lib/
│   │   ├── main.dart              # App entry point with dark theme
│   │   ├── models/
│   │   │   └── app_state.dart     # AppConfig + enums matching Rust + SNI_SNAKE_CASE compat
│   │   ├── ffi/
│   │   │   └── native_bridge.dart # dart:ffi bindings to Rust C API
│   │   ├── services/
│   │   │   └── app_service.dart   # Business logic: start/stop/stats/config
│   │   ├── screens/
│   │   │   ├── dashboard_screen.dart  # Power button, stats, connection info
│   │   │   ├── config_screen.dart     # Mode selector + per-mode settings + Trojan URL import
│   │   │   └── logs_screen.dart       # Color-coded log viewer
│   │   └── widgets/
│   │       └── stats_card.dart    # Reusable stat card widget
│   ├── android/
│   │   └── app/src/main/
│   │       ├── AndroidManifest.xml # VPN permission, VpnService declaration, network security
│   │       ├── kotlin/.../
│   │       │   ├── MainActivity.kt   # MethodChannel: requestVpn, stopVpn, saveConfig
│   │       │   └── vpn/
│   │       │       └── VpnService.kt # TUN interface, foreground service, fd passthrough
│   │       └── res/xml/
│   │           └── network_security_config.xml
│   └── assets/
│       └── config.json            # Default config matching user's JSON
│
├── tests/
│   ├── Cargo.toml
│   └── src/lib.rs                 # Packet helpers + integration tests
│
├── examples/
│   ├── Cargo.toml
│   └── src/
│       ├── standalone.rs          # Full CLI binary (clap args + env vars)
│       └── demo_config.rs         # Config generation example
│
├── scripts/
│   └── build-android.sh           # cargo-ndk cross-compilation to 4 Android ABIs
│
└── STATUS.md                      # This file
```

---

## ✅ What's Fully Implemented

### TCP Connection State Machine (`core/src/state.rs`)

```
Initial → SynSent → SynAckReceived → AckSent → FakeSent → FakeAcked → Relaying → Closed
```

- Strongly-typed `ConnectionState` enum with 8 variants
- `transition()` method validates every sequence/ACK number against expected values
- Wrapping arithmetic for TCP 32-bit sequence numbers
- `UnexpectedEvent` error type
- **Unit tests:** happy path, wrong ack rejection, unexpected inbound, FakeAcked→Relaying

### ✅ WrongSeq Bypass Handler (`core/src/bypass/implementations/wrong_seq.rs`)

- **Packet classification:** SYN, SYN-ACK, ACK (handshake), ACK (fake data), Unexpected
- **SYN ack_num validation** — rejects SYN with non-zero ack_num
- **sch_fake_sent guard** — blocks subsequent outbound after fake scheduling
- **Fake packet construction:**
  - PSH flag set, IP ident incremented, total_length adjusted
  - `seq_num = syn_seq + 1 - len(fake_data)`
- **Configurable inject delay** with ±500μs random jitter (default: 1ms base)

### ✅ TLS ClientHello Generator (`common/src/tls.rs`)

- Chrome-fingerprint static fields from hex template
- Configurable SNI, random session ID, random extension ordering
- Padding extension: `219 - sni_len` bytes
- **Tests:** SNI content verification, randomization

### ✅ TLS Connector System (`core/src/tls/`)

**Trait:**
```rust
#[async_trait]
pub trait TlsConnector: Send + Sync {
    async fn connect(&self, domain: &str, stream: TcpStream) -> Result<TlsStream>;
}
```

**`RustlsConnector`** — production-safe:
- ALPN negotiation, cipher filtering, root certs (webpki-roots), verification toggle
- **Tests:** creation, ALPN, verify-disabled, domain parsing

**`CustomClientHelloConnector`** — puts our JA3 on the wire:
1. Generates custom ClientHello via `ClientHelloBuilder::generate(sni)`
2. Wraps stream in `TlsBufferIo` — intercepts rustls's first write
3. Server receives our JA3 fingerprint
- Chrome, Firefox, Android, Random modes
- **Tests:** CH contains SNI, CH is TLS handshake type, TlsBufferIo first-write replacement

### ✅ Configuration System (`common/src/config.rs`)

- `AppConfig` — full multi-mode config (SNI/Trojan/WARP/Psiphon)
- `EngineConfig` — backward-compatible engine-only config
- `DynamicConfig` — hot-reloadable via `Arc<RwLock<>>`
- Trojan URL parser (`trojan://password@host:port?params`)
- Backward-compat with Python SCREAMING_SNAKE_CASE via `#[serde(alias)]`
- TLS defaults: **`tls_connector: Custom`**, **`tls_enabled: true`**
- **Tests:** old/new format parsing, AppConfig, Trojan URL

### ✅ Async Relay Engine (`core/src/relay.rs`)

- Raw TCP relay: two concurrent tasks, graceful shutdown, byte counting
- TLS relay: wraps remote in TLS via `TlsConnector`, forwards between raw local ↔ TLS remote

### ✅ Trojan Protocol Handler (`core/src/trojan.rs`)

- Trojan session: TLS handshake → password auth → SOCKS-style request → bidirectional relay
- SOCKS5 CONNECT request parser (IPv4, IPv6, domain name)
- WebSocket transport — `build_ws_upgrade_request()` helper
- **Tests:** request builder, SOCKS parse, invalid command rejection

### ✅ Timing Jitter

- `inject_delay_with_jitter()` adds **±500μs random jitter**
- Clamped to ≥ 0 microseconds
- Matches Python's less deterministic timing profile

### ✅ Linux NFQUEUE Backend (`platforms/linux/src/lib.rs`) — **FULLY IMPLEMENTED**

| Component | Status | Description |
|---|---|---|
| **NFQUEUE event loop** | ✅ Complete | `nfqueue::Queue` with callback → mpsc bridge to async engine |
| **Raw socket injection** | ✅ Complete | `libc::socket(AF_INET, SOCK_RAW, IPPROTO_RAW)` for Modify/Inject actions |
| **Packet parsing** | ✅ Complete | CapturedPacket → ConnectionId → engine dispatch |
| **Direction heuristic** | ✅ Complete | Inbound/outbound via dst IP (private/public) |
| **Bridge task** | ✅ Complete | `spawn_blocking` with `Handle::block_on()` for sync→async bridge |
| **Graceful stop** | ✅ Complete | Dedicated stop signal channel via `stop_tx: Arc<Mutex<Option<mpsc::Sender<()>>>>` |
| **Unit tests** | ✅ Complete | `infer_direction` outbound/inbound/loopback tests |

### ✅ Extended C API (`api/src/lib.rs`)

| Function | Signature |
|---|---|
| `mamadvpn_init` | `(config_json: *const c_char) -> i32` |
| `mamadvpn_start` | `() -> i32` |
| `mamadvpn_stop` | `() -> i32` |
| `mamadvpn_shutdown` | `()` |
| `mamadvpn_update_config` | `(config_json: *const c_char) -> i32` |
| `mamadvpn_parse_trojan_url` | `(url, out_buf, out_len) -> i32` |
| `mamadvpn_get_stats` | `(out: *mut MamadVPNStats) -> i32` |
| `mamadvpn_get_status` | `(out_json, out_len) -> i32` |
| `mamadvpn_get_logs` | `(out_buf, out_len) -> i32` |
| `mamadvpn_clear_logs` | `() -> i32` |
| `mamadvpn_set_tun_fd` | `(fd: i32) -> i32` |
| `mamadvpn_on_vpn_permission_result` | `(granted: i32) -> i32` |

### ✅ Flutter Android App (`app/`)

**Screens:**
| Screen | Features |
|---|---|
| **Dashboard** | Connection status with power button, animated status indicator (green/yellow/red), uptime counter, TX/RX stats cards, intercepted/injected counters, local→remote connection info, mode indicator, Trojan info panel |
| **Config** | 4-mode selector (SNI Only / Trojan / WARP / Psiphon), per-mode field editors, Trojan URL import with parse button, TLS toggle + ALPN, proxy port config, save button |
| **Logs** | Color-coded log viewer (green=success, yellow=warn, red=error), auto-scroll, clear button |

**Dart ↔ Rust FFI:**
- `dart:ffi` bindings to all 12 C API functions via `DynamicLibrary`
- `NativeStats` struct with correct memory layout
- Proper UTF-8 string passing with `calloc.free()` cleanup
- MethodChannel bridge for Android VpnService TUN fd pass-through

**Android Native:**
| Component | Features |
|---|---|
| **MainActivity** | `MethodChannel` for VPN permission request/stop, `startActivityForResult` flow, config persistence via SharedPreferences |
| **MamadVpnService** | `VpnService.Builder` — TUN `10.0.0.2/32`, route `0.0.0.0/0`, DNS `8.8.8.8` + `1.1.1.1`, split-tunnel for app package, foreground notification with channel |

**Build System:**
| Script | Description |
|---|---|
| `scripts/build-android.sh` | `cargo-ndk` cross-compilation to `arm64-v8a`, `armeabi-v7a`, `x86_64`, `x86` — outputs to `jniLibs/` |
| Gradle hook | `buildNativeLibs` task auto-triggered before `compileSources` |

---

## ⚠️ What's Stubbed

| Component | File | Notes |
|---|---|---|
| **Android TUN backend (Rust)** | `platforms/android/src/lib.rs` | `mamadvpn_set_tun_fd()` is a TODO — TUN fd received but not wired to interceptor |
| **Android JNI Bridge** | `platforms/android/src/lib.rs` | 5 native function signatures defined, body is `// TODO` |
| **Windows WinDivert** | `platforms/windows/src/lib.rs` | Filter string configured, needs `windivert` crate |
| **Other bypass methods** | `core/src/bypass.rs` | BadChecksum, Fragmentation, DelayedAck, FakeRst — all fall back to WrongSeq |

### 🔑 Key Gap: TUN fd ↔ Engine Integration

The TUN fd reaches Dart via MethodChannel and gets passed to `mamadvpn_set_tun_fd()`, but the Rust side doesn't wire it into the engine's packet interceptor. The Android platform backend (`platforms/android/src/lib.rs`) needs:
1. A read loop on the TUN fd
2. Packet parsing (IP header extraction via `common/src/packet.rs`)
3. Engine dispatch via `PacketHandler`
4. Write modified packets back to the TUN fd

Without this, the VPN tunnel opens but no traffic routes through the engine. The app works in **proxy mode** (SOCKS/HTTP → engine listener) but not in full VPN mode.

---

## 📊 Unit Tests Summary

| Crate | Module | Tests | Status |
|---|---|---|---|
| `common` | `config.rs` | Old/new format parsing, AppConfig, Trojan URL parse (4) | ✅ |
| `common` | `tls.rs` | SNI verification, randomization (3) | ✅ |
| `common` | `packet.rs` | SYN packet roundtrip (1) | ✅ |
| `common` | `lib.rs` | Default interface detection (1) | ✅ |
| `core` | `state.rs` | Happy path, wrong ack, unexpected, FakeAcked→Relaying (4) | ✅ |
| `core` | `connector.rs` | Creation, ALPN, verify-disabled, domain parsing (4) | ✅ |
| `core` | `custom.rs` | SNI, CH bytes, TlsBufferIo first/second write (6) | ✅ |
| `core` | `trojan.rs` | Request builder, SOCKS parse, invalid command (3) | ✅ |
| `platforms/linux` | `lib.rs` | infer_direction outbound/inbound/loopback (3) | ✅ |

---

## 🔜 Recommended Next Steps

1. **Build the APK** — Run `./scripts/build-android.sh` then `flutter build apk` to get a working APK
2. **Implement Android TUN backend** — Wire the TUN fd into the Rust packet interceptor pipeline (the biggest functional gap)
3. **Additional bypass methods** — BadChecksum, Fragmentation, FakeRst for more evasion modes
