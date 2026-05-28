//! # MamadVPN Extended C API
//!
//! C-compatible FFI layer for embedding MamadVPN into Flutter/Android.
//!
//! ## API Surface
//!
//! ```c
//! // Lifecycle
//! int32_t mamadvpn_init(const char* config_json);
//! int32_t mamadvpn_start();
//! int32_t mamadvpn_stop();
//! void    mamadvpn_shutdown();
//!
//! // Configuration
//! int32_t mamadvpn_update_config(const char* config_json);
//! int32_t mamadvpn_parse_trojan_url(const char* url, char* out_json, int32_t out_len);
//!
//! // Stats & Status
//! int32_t mamadvpn_get_stats(MamadVPNStats* out_stats);
//! int32_t mamadvpn_get_status(char* out_json, int32_t out_len);
//!
//! // Logs
//! int32_t mamadvpn_get_logs(char* out_buf, int32_t out_len);
//! int32_t mamadvpn_clear_logs();
//!
//! // Platform (Android TUN)
//! int32_t mamadvpn_set_tun_fd(int32_t fd);
//! int32_t mamadvpn_on_vpn_permission_result(int32_t granted);
//! ```

#![allow(non_camel_case_types, clippy::missing_safety_doc)]

use std::ffi::{CStr, CString};
use std::sync::Arc;
use std::sync::atomic::{AtomicI32, Ordering};
use std::sync::Mutex;

use std::net::Ipv4Addr;

use mamadvpn_common::{AppConfig, DynamicConfig, EngineConfig, ConnectionMode};
use mamadvpn_core::engine::TransportEngine;
use mamadvpn_core::trojan::TrojanSession;
use mamadvpn_core::tls::{RustlsConnector, TlsConnector, TlsConnectorConfig};
use mamadvpn_platform_android::TunInterceptor;

// ---------------------------------------------------------------------------
// Global state
// ---------------------------------------------------------------------------

static ENGINE_INITIALIZED: AtomicI32 = AtomicI32::new(0);
static ENGINE_RUNNING: AtomicI32 = AtomicI32::new(0);

static mut ENGINE: Option<Arc<TransportEngine>> = None;
static mut RUNTIME: Option<tokio::runtime::Runtime> = None;
static mut APP_CONFIG: Option<AppConfig> = None;

/// Track whether we have a TUN interceptor attached (vs TCP listener mode).
static mut TUN_INTERCEPTOR_ATTACHED: bool = false;

/// Ring buffer for log messages (accessible from Flutter).
static mut LOG_BUF: Option<Vec<String>> = None;
const MAX_LOG_ENTRIES: usize = 500;

fn with_runtime<F, T>(f: F) -> T
where
    F: FnOnce(&tokio::runtime::Runtime) -> T,
{
    unsafe {
        if RUNTIME.is_none() {
            RUNTIME = Some(
                tokio::runtime::Builder::new_multi_thread()
                    .worker_threads(2)
                    .enable_all()
                    .build()
                    .expect("Failed to create tokio runtime"),
            );
        }
        f(RUNTIME.as_ref().unwrap())
    }
}

fn append_log(msg: String) {
    unsafe {
        let buf = LOG_BUF.get_or_insert_with(|| Vec::with_capacity(MAX_LOG_ENTRIES));
        buf.push(msg);
        if buf.len() > MAX_LOG_ENTRIES {
            buf.remove(0);
        }
    }
}

macro_rules! log_info {
    ($($arg:tt)*) => {
        let msg = format!($($arg)*);
        tracing::info!("{}", &msg);
        append_log(msg);
    };
}

// ---------------------------------------------------------------------------
// FFI-safe stats struct
// ---------------------------------------------------------------------------

#[repr(C)]
#[derive(Debug, Clone, Default)]
pub struct MamadVPNStats {
    pub tx_bytes: u64,
    pub rx_bytes: u64,
    pub packets_intercepted: u64,
    pub packets_injected: u64,
    pub unexpected_packets: u64,
    pub active_connections: u32,
    pub uptime_seconds: u64,
}

// ---------------------------------------------------------------------------
// App status (returned as JSON)
// ---------------------------------------------------------------------------

fn get_status_json() -> String {
    let mode = unsafe {
        APP_CONFIG
            .as_ref()
            .map(|c| format!("{:?}", c.connection_mode))
            .unwrap_or_else(|| "unknown".into())
    };
    let running = ENGINE_RUNNING.load(Ordering::SeqCst) != 0;
    let initialized = ENGINE_INITIALIZED.load(Ordering::SeqCst) != 0;

    format!(
        r#"{{"initialized":{},"running":{},"mode":"{}"}}"#,
        initialized, running, mode
    )
}

// ---------------------------------------------------------------------------
// C API — Lifecycle
// ---------------------------------------------------------------------------

/// Initialize with full AppConfig JSON.
#[no_mangle]
pub extern "C" fn mamadvpn_init(config_json: *const std::os::raw::c_char) -> i32 {
    let config_str = match unsafe { CStr::from_ptr(config_json) }.to_str() {
        Ok(s) => s,
        Err(_) => return -1,
    };

    let app_config = match AppConfig::from_json_str(config_str) {
        Ok(c) => c,
        Err(e) => {
            log_info!("Config parse error: {e}");
            return -1;
        }
    };

    log_info!(
        "Initializing MamadVPN — mode: {:?}, listen: {}:{}",
        app_config.connection_mode,
        app_config.listen_host,
        app_config.listen_port
    );

    unsafe {
        APP_CONFIG = Some(app_config.clone());
    }

    // Convert to engine config and init the transport engine
    let engine_config: EngineConfig = app_config.into();
    let dynamic_config = DynamicConfig::new(engine_config);
    let engine = Arc::new(TransportEngine::new(dynamic_config));

    unsafe {
        ENGINE = Some(engine);
    }

    ENGINE_INITIALIZED.store(1, Ordering::SeqCst);
    0
}

/// Start the engine.
///
/// If a TUN interceptor was attached via `mamadvpn_set_tun_fd()`, it
/// runs in interceptor mode (reads from TUN → bypass → writes to TUN).
/// Otherwise it runs in listener mode (binds TCP listener → relay).
#[no_mangle]
pub extern "C" fn mamadvpn_start() -> i32 {
    if ENGINE_INITIALIZED.load(Ordering::SeqCst) == 0 {
        return -1;
    }

    let engine = unsafe { ENGINE.clone() }.unwrap();
    let app_config = unsafe { APP_CONFIG.clone() }.unwrap();
    let is_tun_mode = unsafe { TUN_INTERCEPTOR_ATTACHED };

    ENGINE_RUNNING.store(1, Ordering::SeqCst);
    if is_tun_mode {
        log_info!("MamadVPN starting in TUN interceptor mode");
    } else {
        log_info!("MamadVPN starting ({:?} mode)", app_config.connection_mode);
    }

    with_runtime(|rt| {
        rt.spawn(async move {
            if let Err(e) = engine.run().await {
                log_info!("Engine exited: {e}");
            }
            ENGINE_RUNNING.store(0, Ordering::SeqCst);
        });
    });

    0
}

/// Stop the engine gracefully.
///
/// Sends the shutdown signal to the engine (which causes the interceptor
/// loop or TCP listener to exit), then cleans up platform state.
#[no_mangle]
pub extern "C" fn mamadvpn_stop() -> i32 {
    if ENGINE_INITIALIZED.load(Ordering::SeqCst) == 0 {
        return 0;
    }

    log_info!("MamadVPN stopping");

    unsafe {
        // Signal the engine loop to exit via its oneshot channel.
        // In interceptor mode this terminates the TUN read/write loop.
        // In listener mode this unwinds the accept loop.
        if let Some(ref engine) = ENGINE {
            if let Some(tx) = engine.shutdown_tx.lock().take() {
                let _ = tx.send(());
            }
        }
        TUN_INTERCEPTOR_ATTACHED = false;
    }

    ENGINE_RUNNING.store(0, Ordering::SeqCst);
    0
}

/// Full shutdown — releases all resources.
#[no_mangle]
pub extern "C" fn mamadvpn_shutdown() {
    ENGINE_INITIALIZED.store(0, Ordering::SeqCst);
    ENGINE_RUNNING.store(0, Ordering::SeqCst);

    unsafe {
        TUN_INTERCEPTOR_ATTACHED = false;
        ENGINE = None;
        RUNTIME = None;
        LOG_BUF = None;
        APP_CONFIG = None;
    }
}

// ---------------------------------------------------------------------------
// C API — Configuration
// ---------------------------------------------------------------------------

/// Update config at runtime.
#[no_mangle]
pub extern "C" fn mamadvpn_update_config(config_json: *const std::os::raw::c_char) -> i32 {
    if ENGINE_INITIALIZED.load(Ordering::SeqCst) == 0 {
        return -1;
    }

    let config_str = match unsafe { CStr::from_ptr(config_json) }.to_str() {
        Ok(s) => s,
        Err(_) => return -1,
    };

    let app_config = match AppConfig::from_json_str(config_str) {
        Ok(c) => c,
        Err(e) => {
            log_info!("Config update error: {e}");
            return -1;
        }
    };

    unsafe {
        APP_CONFIG = Some(app_config.clone());
        if let Some(ref engine) = ENGINE {
            let engine_config: EngineConfig = app_config.into();
            engine.config.swap(engine_config);
        }
    }

    log_info!("Config updated");
    0
}

/// Parse a Trojan share URL and return the config as JSON.
#[no_mangle]
pub extern "C" fn mamadvpn_parse_trojan_url(
    url: *const std::os::raw::c_char,
    out_json: *mut std::os::raw::c_char,
    out_len: i32,
) -> i32 {
    let url_str = match unsafe { CStr::from_ptr(url) }.to_str() {
        Ok(s) => s,
        Err(_) => return -1,
    };

    let config = match AppConfig::from_trojan_url(url_str) {
        Ok(c) => c,
        Err(e) => {
            log_info!("Trojan URL parse error: {e}");
            return -1;
        }
    };

    let json = match config.to_json_string() {
        Ok(j) => j,
        Err(e) => {
            log_info!("Config serialize error: {e}");
            return -1;
        }
    };

    let json_bytes = json.as_bytes();
    let len = json_bytes.len().min(out_len as usize - 1);
    unsafe {
        std::ptr::copy_nonoverlapping(json_bytes.as_ptr(), out_json as *mut u8, len);
        *out_json.add(len) = 0; // null-terminate
    }

    len as i32
}

// ---------------------------------------------------------------------------
// C API — Stats & Status
// ---------------------------------------------------------------------------

/// Get current engine statistics.
#[no_mangle]
pub extern "C" fn mamadvpn_get_stats(out_stats: *mut MamadVPNStats) -> i32 {
    if ENGINE_INITIALIZED.load(Ordering::SeqCst) == 0 {
        return -1;
    }
    if out_stats.is_null() {
        return -1;
    }

    unsafe {
        *out_stats = MamadVPNStats {
            active_connections: 0,
            uptime_seconds: 0,
            ..Default::default()
        };
    }
    0
}

/// Get engine status as JSON string.
#[no_mangle]
pub extern "C" fn mamadvpn_get_status(
    out_json: *mut std::os::raw::c_char,
    out_len: i32,
) -> i32 {
    let status = get_status_json();
    let bytes = status.as_bytes();
    let len = bytes.len().min(out_len as usize - 1);
    unsafe {
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), out_json as *mut u8, len);
        *out_json.add(len) = 0;
    }
    len as i32
}

// ---------------------------------------------------------------------------
// C API — Logs
// ---------------------------------------------------------------------------

/// Retrieve recent log messages as a JSON array.
#[no_mangle]
pub extern "C" fn mamadvpn_get_logs(
    out_buf: *mut std::os::raw::c_char,
    out_len: i32,
) -> i32 {
    let logs = unsafe {
        LOG_BUF
            .as_ref()
            .map(|b| {
                let entries: Vec<String> = b.iter().map(|s| {
                    // Escape for JSON
                    s.replace('\\', "\\\\")
                        .replace('"', "\\\"")
                        .replace('\n', "\\n")
                }).collect();
                format!("[{}]", entries.join(","))
            })
            .unwrap_or_else(|| "[]".into())
    };

    let bytes = logs.as_bytes();
    let len = bytes.len().min(out_len as usize - 1);
    unsafe {
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), out_buf as *mut u8, len);
        *out_buf.add(len) = 0;
    }
    len as i32
}

/// Clear the log buffer.
#[no_mangle]
pub extern "C" fn mamadvpn_clear_logs() -> i32 {
    unsafe {
        LOG_BUF = Some(Vec::with_capacity(MAX_LOG_ENTRIES));
    }
    0
}

// ---------------------------------------------------------------------------
// C API — Android TUN
// ---------------------------------------------------------------------------

/// Set the TUN file descriptor from Android's VpnService.
///
/// Creates a TunInterceptor, attaches it to the engine, and stores
/// the fd.  The engine will use interceptor-mode packet processing
/// (read from TUN → bypass → write to TUN) instead of TCP listener mode.
///
/// Must be called after `mamadvpn_init()` and before `mamadvpn_start()`.
#[no_mangle]
pub extern "C" fn mamadvpn_set_tun_fd(fd: i32) -> i32 {
    if ENGINE_INITIALIZED.load(Ordering::SeqCst) == 0 {
        log_info!("TUN fd set called before engine init");
        return -1;
    }

    log_info!("Creating TUN interceptor for fd {}", fd);

    unsafe {
        let engine = match ENGINE.as_ref() {
            Some(e) => e,
            None => return -1,
        };

        let config = match APP_CONFIG.as_ref() {
            Some(c) => c.clone(),
            None => return -1,
        };

        let engine_config: EngineConfig = config.clone().into();
        let dynamic_config = DynamicConfig::new(engine_config);

        // Determine the TUN interface IP (from config or default)
        let tun_ip = config.interface_ipv4.map(|ip| match ip {
            std::net::IpAddr::V4(v4) => v4,
            std::net::IpAddr::V6(_) => Ipv4Addr::new(10, 0, 0, 2),
        }).unwrap_or(Ipv4Addr::new(10, 0, 0, 2));

        // Create and configure the TUN interceptor
        let mut interceptor = TunInterceptor::new(dynamic_config, Some(tun_ip));
        interceptor.set_tun_fd(fd);

        // Attach to engine
        engine.attach_interceptor(Box::new(interceptor));

        TUN_INTERCEPTOR_ATTACHED = true;
        log_info!("TUN interceptor attached to engine");
    }

    0
}

/// Called when Android VpnService permission result is available.
#[no_mangle]
pub extern "C" fn mamadvpn_on_vpn_permission_result(granted: i32) -> i32 {
    if granted != 0 {
        log_info!("VPN permission granted");
    } else {
        log_info!("VPN permission denied");
    }
    0
}

// ---------------------------------------------------------------------------
// Rust-side helpers for Flutter
// ---------------------------------------------------------------------------

/// Rust-friendly init.
pub fn initialize(config: AppConfig) -> Result<(), String> {
    let json = config.to_json_string().map_err(|e| e.to_string())?;
    let c_str = CString::new(json).map_err(|e| e.to_string())?;
    if mamadvpn_init(c_str.as_ptr()) == 0 {
        Ok(())
    } else {
        Err("Init failed".into())
    }
}

pub fn start() -> Result<(), String> {
    if mamadvpn_start() == 0 {
        Ok(())
    } else {
        Err("Start failed".into())
    }
}

pub fn stop() -> Result<(), String> {
    mamadvpn_stop();
    Ok(())
}

pub fn get_status() -> String {
    get_status_json()
}
