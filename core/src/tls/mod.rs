//! # TLS Connector System
//!
//! Bridges the gap between the `ClientHelloBuilder` (which generates TLS
//! fingerprint byte buffers) and real outbound TLS connections.  Provides
//! two connector implementations:
//!
//! * **`RustlsConnector`** — Production-safe TLS via the `rustls` crate.
//!   Configurable SNI, ALPN, and cipher suites.  This is the default path.
//!
//! * **`CustomClientHelloConnector`** — Sends a custom ClientHello generated
//!   by our `ClientHelloBuilder` on the wire, then uses a `RustlsConnector`
//!   internally for the cryptographic handshake.  This puts our exact JA3
//!   fingerprint on the wire.
//!
//! ## Architecture
//!
//! ```text
//! TransportEngine
//!   │
//!   ▼
//! RelayEngine::start_tls(upstream, downstream, tls_connector)
//!   │
//!   ├── RustlsConnector::connect(domain, tcp_stream) ───► TlsStream
//!   │       │
//!   │       └── rustls::ClientConnection + tokio_rustls::TlsStream
//!   │
//!   └── CustomClientHelloConnector::connect(domain, tcp_stream)
//!           │
//!           ├── 1. ClientHelloBuilder::generate(fingerprint, sni) → raw CH bytes
//!           ├── 2. Write raw CH to TCP stream (on the wire)
//!           ├── 3. RustlsConnector::connect() on same stream via TlsBufferIo
//!           └── 4. Return wrapped TlsStream
//! ```

mod connector;
mod custom;

pub use connector::*;
pub use custom::*;

use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use anyhow::Result;
use bytes::Bytes;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;

// ---------------------------------------------------------------------------
// Boxed stream type for TLS connector return values
// ---------------------------------------------------------------------------

/// Convenience super-trait so we can box `AsyncRead + AsyncWrite + Unpin + Send`.
pub trait BoxedIo: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> BoxedIo for T {}

/// A pinned, boxed, async-read-write stream returned by TLS connectors.
///
/// Using `Box<dyn ...>` allows both `RustlsConnector` and
/// `CustomClientHelloConnector` to return different underlying TLS stream
/// types through the same `TlsConnector` trait.
pub type BoxedStream = Pin<Box<dyn BoxedIo>>;

// ---------------------------------------------------------------------------
// TlsConnector trait
// ---------------------------------------------------------------------------

/// Abstract TLS connector that wraps a `TcpStream` into a `BoxedStream`.
///
/// Two implementations are provided:
///
/// * `RustlsConnector` — standard TLS via the `rustls` crate.
/// * `CustomClientHelloConnector` — uses our `ClientHelloBuilder` to place a
///   specific JA3 fingerprint on the wire before completing the handshake.
#[async_trait::async_trait]
pub trait TlsConnector: Send + Sync {
    /// Perform a TLS handshake over an existing TCP stream.
    ///
    /// * `domain` — The SNI hostname to present (e.g. `"www.cloudflare.com"`).
    /// * `stream` — An already-connected TCP stream.
    ///
    /// Returns a boxed stream that implements `AsyncRead + AsyncWrite`.
    async fn connect(&self, domain: &str, stream: TcpStream) -> Result<BoxedStream>;
}

// ---------------------------------------------------------------------------
// TlsConnectorConfig
// ---------------------------------------------------------------------------

/// Configuration passed to TLS connectors.
#[derive(Debug, Clone)]
pub struct TlsConnectorConfig {
    /// ALPN protocol list (e.g. `["h2", "http/1.1"]`).
    pub alpn: Vec<String>,
    /// Whether to verify server certificates.
    pub verify_certs: bool,
    /// Custom root CA certificates (PEM-encoded).  Empty = use webpki roots.
    pub root_certs: Vec<String>,
    /// Optional cipher suite filter (empty = rustls defaults).
    pub cipher_suites: Vec<String>,
    /// If true, enable early data (0-RTT).
    pub enable_early_data: bool,
    /// Fingerprint mode for the `CustomClientHelloConnector`.
    pub fingerprint: FingerprintKind,
}

impl Default for TlsConnectorConfig {
    fn default() -> Self {
        Self {
            alpn: vec!["h2".into(), "http/1.1".into()],
            verify_certs: true,
            root_certs: Vec::new(),
            cipher_suites: Vec::new(),
            enable_early_data: false,
            fingerprint: FingerprintKind::Chrome,
        }
    }
}

/// TLS fingerprint kind used by `ClientHelloBuilder`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FingerprintKind {
    Chrome,
    Firefox,
    Android,
    Random,
}

impl Default for FingerprintKind {
    fn default() -> Self {
        Self::Chrome
    }
}

// ---------------------------------------------------------------------------
// TlsBufferIo — forward I/O wrapper that intercepts the first write
// ---------------------------------------------------------------------------

/// An I/O wrapper that, on the first write, sends `initial_data` instead of
/// what the writer actually writes.  All subsequent reads and writes pass
/// through to the inner stream transparently.
///
/// This is used by `CustomClientHelloConnector` to replace rustls's own
/// ClientHello with our custom one on the wire.
pub struct TlsBufferIo<T> {
    inner: T,
    initial_data: Option<Bytes>,
    first_write_done: bool,
}

impl<T> TlsBufferIo<T> {
    pub fn new(inner: T, initial_data: Bytes) -> Self {
        Self {
            inner,
            initial_data: Some(initial_data),
            first_write_done: false,
        }
    }
}

impl<T: AsyncRead + Unpin> AsyncRead for TlsBufferIo<T> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

// ---------------------------------------------------------------------------
// PermissiveVerifier — accepts all server certificates (testing only)
// ---------------------------------------------------------------------------

/// A `ServerCertVerifier` that accepts any server certificate.
///
/// **WARNING**: Do NOT use this in production. It disables all certificate
/// validation, making the connection vulnerable to MITM attacks.
#[derive(Debug)]
pub struct PermissiveVerifier;

impl rustls::client::danger::ServerCertVerifier for PermissiveVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::RSA_PKCS1_SHA384,
            rustls::SignatureScheme::RSA_PKCS1_SHA512,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA512,
            rustls::SignatureScheme::ED25519,
        ]
    }
}

impl<T: AsyncWrite + Unpin> AsyncWrite for TlsBufferIo<T> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, std::io::Error>> {
        if !self.first_write_done {
            self.first_write_done = true;
            if let Some(initial) = self.initial_data.take() {
                // Write our custom data instead
                let len = initial.len();
                return Pin::new(&mut self.inner).poll_write(cx, &initial);
            }
        }
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), std::io::Error>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), std::io::Error>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}
