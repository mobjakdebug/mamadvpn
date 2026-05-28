use thiserror::Error;

/// Top-level error type for the MamadVPN common crate.
///
/// Individual platform backends may define their own error types and
/// convert them into `CommonError` or `anyhow::Error` at the boundary.
#[derive(Error, Debug)]
pub enum CommonError {
    /// Configuration parsing or loading error.
    #[error("Configuration error: {0}")]
    Config(String),

    /// Invalid packet data (malformed header, unexpected length, etc.).
    #[error("Packet error: {0}")]
    Packet(String),

    /// TLS template manipulation error.
    #[error("TLS error: {0}")]
    Tls(String),

    /// I/O error from the platform layer.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// Parsing error (e.g. invalid IP address).
    #[error("Parse error: {0}")]
    Parse(String),
}
