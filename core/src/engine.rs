//! # Transport Engine
//!
//! Top-level orchestrator. Wires together listening socket, packet interceptor,
//! bypass registry, connection tracker, relay engine, and TLS connector.

use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::Ordering;
use std::sync::Arc;

use anyhow::{Context, Result};
use bytes::Bytes;
use mamadvpn_common::config::{
    DynamicConfig, TlsConnectorBackend, TlsFingerprintKind,
};
use mamadvpn_common::connection_id::ConnectionId;
use mamadvpn_common::tls::ClientHelloBuilder;
use parking_lot::Mutex as ParkingMutex;
use tokio::net::TcpStream;
use tokio::sync::{oneshot, Semaphore};
use tokio::time::{sleep, Duration};
use tracing::{error, info, warn};

use rand::Rng;

use crate::bypass::{BypassAction, BypassContext, BypassRegistry};
use crate::connection::{ConnectionEvent, HandshakeResult, ManagedConnection};
use crate::interceptor::{PacketAction, PacketHandler, PacketInterceptor};
use crate::relay::RelayEngine;
use crate::tls::{
    CustomClientHelloConnector, FingerprintKind, RustlsConnector, TlsConnector, TlsConnectorConfig,
};

type ConnectionMap = std::collections::HashMap<ConnectionId, Arc<ManagedConnection>>;

/// The main transport engine.
pub struct TransportEngine {
    pub config: DynamicConfig,
    connections: Arc<ParkingMutex<ConnectionMap>>,
    bypass_registry: Arc<BypassRegistry>,
    connection_semaphore: Arc<Semaphore>,
    pub shutdown_tx: ParkingMutex<Option<oneshot::Sender<()>>>,
    interceptor: ParkingMutex<Option<Box<dyn PacketInterceptor>>>,
    tls_connector: Option<Arc<dyn TlsConnector>>,
}

impl TransportEngine {
    pub fn new(config: DynamicConfig) -> Self {
        let cfg = config.read();
        let bypass_method = cfg.bypass_mode.clone();

        let bypass_registry = Arc::new(BypassRegistry::new(&bypass_method));

        // Build TLS connector from config
        let tls_connector = if cfg.tls_enabled {
            match Self::build_tls_connector(&cfg) {
                Ok(connector) => {
                    info!("TLS connector initialized: {:?}", cfg.tls_connector);
                    Some(connector)
                }
                Err(e) => {
                    warn!("Failed to initialize TLS connector, TLS disabled: {e}");
                    None
                }
            }
        } else {
            None
        };

        Self {
            config,
            connections: Arc::new(ParkingMutex::new(ConnectionMap::new())),
            bypass_registry,
            connection_semaphore: Arc::new(Semaphore::new(1000)),
            shutdown_tx: ParkingMutex::new(None),
            interceptor: ParkingMutex::new(None),
            tls_connector,
        }
    }

    /// Build a TLS connector from engine configuration.
    fn build_tls_connector(cfg: &mamadvpn_common::EngineConfig) -> Result<Arc<dyn TlsConnector>> {
        let alpn: Vec<String> = cfg
            .tls_alpn
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();

        let fingerprint = match cfg.tls_fingerprint {
            TlsFingerprintKind::Chrome => FingerprintKind::Chrome,
            TlsFingerprintKind::Firefox => FingerprintKind::Firefox,
            TlsFingerprintKind::Android => FingerprintKind::Android,
            TlsFingerprintKind::Random => FingerprintKind::Random,
        };

        let tls_config = TlsConnectorConfig {
            alpn,
            verify_certs: cfg.tls_verify_certs,
            root_certs: Vec::new(),
            cipher_suites: Vec::new(),
            enable_early_data: false,
            fingerprint,
        };

        match cfg.tls_connector {
            TlsConnectorBackend::Rustls => {
                let connector = RustlsConnector::new(tls_config)
                    .context("Failed to create RustlsConnector")?;
                Ok(Arc::new(connector))
            }
            TlsConnectorBackend::Custom => {
                let mut connector = CustomClientHelloConnector::new(tls_config)
                    .context("Failed to create CustomClientHelloConnector")?;
                // Use the TLS SNI if set, otherwise fall back to fake_sni
                if let Some(ref sni) = cfg.tls_sni {
                    connector = connector.with_custom_sni(sni.clone());
                } else {
                    connector = connector.with_custom_sni(cfg.fake_sni.clone());
                }
                Ok(Arc::new(connector))
            }
        }
    }

    /// Attach a platform packet interceptor.
    pub fn attach_interceptor(&self, interceptor: Box<dyn PacketInterceptor>) {
        *self.interceptor.lock() = Some(interceptor);
    }

    /// Start the engine.
    ///
    /// Two modes:
    /// 1. **Interceptor mode** — If a `PacketInterceptor` is attached, it
    ///    is started and runs as the sole processing loop (e.g. Android TUN).
    ///    No TCP listener is bound.
    /// 2. **Listener mode** (default) — Binds a TCP listener and accepts
    ///    incoming connections, handling each through bypass + relay.
    pub async fn run(&self) -> Result<()> {
        let inject_delay_us: u64;
        let listen_host: IpAddr;
        let listen_port: u16;
        {
            let cfg = self.config.read();
            inject_delay_us = cfg.inject_delay_us;
            listen_host = cfg.listen_host;
            listen_port = cfg.listen_port;
        }

        // ── Attempt to use an attached packet interceptor ────────
        let interceptor = {
            let mut guard = self.interceptor.lock();
            guard.take()
        };
        if let Some(interceptor) = interceptor {
            info!("Transport engine running in interceptor mode");
            let (shutdown_tx, shutdown_rx) = oneshot::channel();
            *self.shutdown_tx.lock() = Some(shutdown_tx);

            let packet_handler: Arc<dyn PacketHandler> = Arc::new(EnginePacketHandler {
                connections: self.connections.clone(),
                bypass_registry: self.bypass_registry.clone(),
                config: self.config.clone(),
                inject_delay_us,
            });

            // Run the interceptor in the current task (it IS the engine loop)
            tokio::select! {
                result = interceptor.start(packet_handler) => {
                    if let Err(e) = result {
                        error!("Packet interceptor exited with error: {e}");
                        return Err(e);
                    }
                    info!("Packet interceptor completed");
                }
                _ = shutdown_rx => {
                    info!("Shutdown signal received, stopping interceptor");
                }
            }

            return Ok(());
        }

        // ── Listener mode (default) ─────────────────────────────
        let listen_addr: SocketAddr = (listen_host, listen_port).into();

        let (shutdown_tx, mut shutdown_rx) = oneshot::channel();
        *self.shutdown_tx.lock() = Some(shutdown_tx);

        // Clone connectors for spawned tasks
        let tls_connector = self.tls_connector.clone();

        let listener = tokio::net::TcpListener::bind(listen_addr)
            .await
            .with_context(|| format!("Failed to bind to {listen_addr}"))?;

        info!(%listen_addr, "Transport engine listening");

        loop {
            tokio::select! {
                accept_result = listener.accept() => {
                    match accept_result {
                        Ok((incoming_sock, peer_addr)) => {
                            info!(%peer_addr, "New incoming connection");
                            let engine = Arc::new(self.clone());
                            let tls = tls_connector.clone();
                            tokio::spawn(async move {
                                engine.handle_connection(incoming_sock, peer_addr, tls).await;
                            });
                        }
                        Err(e) => {
                            warn!("Accept error: {e}");
                        }
                    }
                }
                _ = &mut shutdown_rx => {
                    info!("Shutdown signal received, stopping engine");
                    break;
                }
            }
        }

        Ok(())
    }

    /// Handle a single incoming connection through the full lifecycle:
    /// bypass handshake → relay (raw or TLS).
    async fn handle_connection(
        self: Arc<Self>,
        incoming_sock: TcpStream,
        peer_addr: SocketAddr,
        tls_connector: Option<Arc<dyn TlsConnector>>,
    ) {
        let _permit = match self.connection_semaphore.acquire().await {
            Ok(p) => p,
            Err(_) => {
                warn!("Connection limit reached, dropping connection from {peer_addr}");
                return;
            }
        };

        let cfg = self.config.read();

        // Generate fake TLS ClientHello for the bypass phase
        let fake_data = ClientHelloBuilder::generate(cfg.fake_sni.as_bytes());

        // Async connect to remote
        let remote_addr: SocketAddr = (cfg.connect_host, cfg.connect_port).into();

        let interface_ip: IpAddr = cfg.interface_ipv4.unwrap_or_else(|| {
            mamadvpn_common::get_default_interface_ipv4()
                .map(std::net::IpAddr::V4)
                .unwrap_or(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED))
        });

        let outgoing_sock = match TcpStream::connect(remote_addr).await {
            Ok(s) => s,
            Err(e) => {
                warn!(%peer_addr, %remote_addr, "Failed to connect to remote: {e}");
                return;
            }
        };

        let local_port = outgoing_sock.local_addr().unwrap().port();
        let connect_ip = match cfg.connect_host {
            IpAddr::V4(v4) => v4,
            IpAddr::V6(_) => {
                warn!("IPv6 connect host not fully supported, using 0.0.0.0");
                std::net::Ipv4Addr::UNSPECIFIED
            }
        };
        let interface_v4 = match interface_ip {
            IpAddr::V4(v4) => v4,
            IpAddr::V6(_) => std::net::Ipv4Addr::UNSPECIFIED,
        };

        let conn_id = ConnectionId::new(interface_v4, local_port, connect_ip, cfg.connect_port);

        let conn = Arc::new(ManagedConnection::new(
            conn_id,
            fake_data,
            cfg.clone(),
            peer_addr,
            remote_addr,
            interface_v4,
        ));

        let (handshake_tx, handshake_rx) = oneshot::channel();
        conn.set_handshake_channel(handshake_tx);

        {
            let mut conns = self.connections.lock();
            conns.insert(conn_id, conn.clone());
        }

        // Wait for bypass handshake
        let handshake_result = tokio::time::timeout(
            Duration::from_secs(cfg.handshake_timeout_secs),
            handshake_rx,
        )
        .await;

        match handshake_result {
            Ok(Ok(HandshakeResult::FakeDataAcked)) => {
                info!(%conn_id, "Handshake complete, starting relay");
            }
            Ok(Ok(HandshakeResult::UnexpectedClose(reason))) => {
                warn!(%conn_id, %reason, "Handshake failed");
                conn.close();
                let mut conns = self.connections.lock();
                conns.remove(&conn_id);
                return;
            }
            Ok(Ok(HandshakeResult::Timeout)) | Ok(Err(_)) | Err(_) => {
                warn!(%conn_id, "Handshake timed out");
                conn.close();
                let mut conns = self.connections.lock();
                conns.remove(&conn_id);
                return;
            }
        }

        conn.scheduled_fake_sent.store(false, Ordering::SeqCst);
        conn.fake_sent.store(true, Ordering::SeqCst);
        {
            let mut conns = self.connections.lock();
            conns.remove(&conn_id);
        }

        let _ = conn.handle_event(ConnectionEvent::StartRelay);

        let (_, shutdown_rx) = oneshot::channel::<()>();

        // Decide: raw TCP relay or TLS-wrapped relay?
        if let Some(ref tls) = tls_connector {
            // Use the TLS SNI from config, or fall back to fake_sni
            let tls_domain = cfg
                .tls_sni
                .clone()
                .unwrap_or_else(|| cfg.fake_sni.clone());

            if let Err(e) = RelayEngine::start_tls(
                incoming_sock,
                outgoing_sock,
                &tls_domain,
                tls.as_ref(),
                conn,
                Bytes::new(),
                shutdown_rx,
            )
            .await
            {
                warn!(%conn_id, "TLS relay error: {e}");
            }
        } else {
            if let Err(e) = RelayEngine::start(
                incoming_sock,
                outgoing_sock,
                conn,
                Bytes::new(),
                shutdown_rx,
            )
            .await
            {
                warn!(%conn_id, "Relay error: {e}");
            }
        }

        info!(%conn_id, "Connection closed");
    }
}

impl Clone for TransportEngine {
    fn clone(&self) -> Self {
        Self {
            config: self.config.clone(),
            connections: self.connections.clone(),
            bypass_registry: self.bypass_registry.clone(),
            connection_semaphore: self.connection_semaphore.clone(),
            shutdown_tx: ParkingMutex::new(None),
            interceptor: ParkingMutex::new(None),
            tls_connector: self.tls_connector.clone(),
        }
    }
}

// ---------------------------------------------------------------------------
// PacketHandler implementation
// ---------------------------------------------------------------------------

struct EnginePacketHandler {
    connections: Arc<ParkingMutex<ConnectionMap>>,
    bypass_registry: Arc<BypassRegistry>,
    config: DynamicConfig,
    inject_delay_us: u64,
}

impl EnginePacketHandler {
    /// Inject delay with ±500μs random jitter to match Python's interpreter
    /// timing profile.  DPI middleboxes can sometimes detect deterministic
    /// timing (too-consistent delays are a fingerprint).
    fn inject_delay_with_jitter(&self) -> u64 {
        if self.inject_delay_us == 0 {
            return 0;
        }
        let mut rng = rand::thread_rng();
        // ±500μs jitter, clamped so we never underflow below 0
        let jitter: i64 = rng.gen_range(-500i64..=500);
        let delay = self.inject_delay_us as i64 + jitter;
        delay.max(0) as u64
    }
}

#[async_trait::async_trait]
impl PacketHandler for EnginePacketHandler {
    async fn handle_inbound(
        &self,
        conn: Arc<ManagedConnection>,
        raw_packet: Bytes,
    ) -> PacketAction {
        let ctx = BypassContext {
            raw_packet: raw_packet.clone(),
            is_inbound: true,
            connection: conn,
        };
        match self.bypass_registry.process(&ctx) {
            BypassAction::Forward => PacketAction::Forward,
            BypassAction::Drop => PacketAction::Drop,
            BypassAction::Modify(data) => PacketAction::Modify(data),
            BypassAction::Inject(data) => {
                let delay = self.inject_delay_with_jitter();
                if delay > 0 {
                    sleep(Duration::from_micros(delay)).await;
                }
                PacketAction::Inject(data)
            }
            BypassAction::PassThrough => PacketAction::Forward,
        }
    }

    async fn handle_outbound(
        &self,
        conn: Arc<ManagedConnection>,
        raw_packet: Bytes,
    ) -> PacketAction {
        let ctx = BypassContext {
            raw_packet: raw_packet.clone(),
            is_inbound: false,
            connection: conn,
        };
        match self.bypass_registry.process(&ctx) {
            BypassAction::Forward => PacketAction::Forward,
            BypassAction::Drop => PacketAction::Drop,
            BypassAction::Modify(data) => PacketAction::Modify(data),
            BypassAction::Inject(data) => {
                let delay = self.inject_delay_with_jitter();
                if delay > 0 {
                    sleep(Duration::from_micros(delay)).await;
                }
                PacketAction::Inject(data)
            }
            BypassAction::PassThrough => PacketAction::Forward,
        }
    }

    fn lookup_connection(&self, id: &ConnectionId) -> Option<Arc<ManagedConnection>> {
        self.connections.lock().get(id).cloned()
    }

    fn handle_unknown_packet(&self, _raw_packet: Bytes) -> PacketAction {
        PacketAction::Forward
    }
}
