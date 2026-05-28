//! # MamadVPN Core Transport Engine
//!
//! This crate implements the core TCP desynchronization-based censorship
//! circumvention transport.  It contains:
//!
//! * **`state`** — Strongly-typed TCP connection state machine.
//! * **`connection`** — Managed connection tracking with thread-safe state.
//! * **`bypass`** — The `BypassMethod` trait and built-in implementations.
//! * **`relay`** — Bidirectional async byte-stream relay.
//! * **`engine`** — The top-level `TransportEngine`.
//! * **`interceptor`** — The abstract `PacketInterceptor` trait.
//! * **`raw`** — Raw packet construction utilities.
//! * **`tls`** — TLS connector system (RustlsConnector + CustomClientHelloConnector).

pub mod bypass;
pub mod connection;
pub mod engine;
pub mod interceptor;
pub mod raw;
pub mod relay;
pub mod state;
pub mod tls;
pub mod trojan;

pub use bypass::*;
pub use connection::*;
pub use engine::*;
pub use interceptor::*;
pub use relay::*;
pub use state::*;
pub use trojan::*;
