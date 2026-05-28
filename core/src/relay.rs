//! # Bidirectional Async Relay
//!
//! Forwards bytes between two TCP sockets (local client ↔ remote server)
//! after the bypass handshake completes.
//!
//! Supports both raw TCP forwarding and TLS-wrapped forwarding.
//!
//! This mirrors Python's `relay_main_loop` which reads from one socket and
//! writes to the other (and vice versa on the peer task).

use std::sync::Arc;

use anyhow::Result;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::oneshot;

use mamadvpn_common::bytes::Bytes;

use crate::connection::{ConnectionEvent, ManagedConnection};
use crate::tls::{BoxedStream, TlsConnector};

/// Bidirectional relay between two TCP sockets.
///
/// Creates two tasks:
/// - `local_to_remote`: reads from `local_sock`, writes to `remote_sock`
/// - `remote_to_local`: reads from `remote_sock`, writes to `local_sock`
///
/// Both tasks run concurrently.  When one side closes, the other is
/// cancelled gracefully.
pub struct RelayEngine;

impl RelayEngine {
    /// Start relaying between the local and remote sockets.
    ///
    /// `first_prefix_data` matches Python's `first_prefix_data` parameter
    /// — if non-empty, it is prepended to the first read from the source.
    ///
    /// Returns when both directions have finished.
    pub async fn start(
        local_sock: TcpStream,
        remote_sock: TcpStream,
        conn: Arc<ManagedConnection>,
        first_prefix_data: Bytes,
        shutdown_rx: oneshot::Receiver<()>,
    ) -> Result<()> {
        let (mut local_rx, mut local_tx) = tokio::io::split(local_sock);
        let (mut remote_rx, mut remote_tx) = tokio::io::split(remote_sock);

        // Send prefix data if any
        if !first_prefix_data.is_empty() {
            remote_tx.write_all(&first_prefix_data).await?;
            remote_tx.flush().await?;
            {
                let mut stats = conn.stats.lock();
                stats.tx_bytes += first_prefix_data.len() as u64;
            }
        }

        // Create two tasks for bidirectional forwarding
        let conn_local = conn.clone();
        let forward_handle = tokio::spawn(async move {
            let mut buf = vec![0u8; 65575];
            Self::forward_internal(&mut local_rx, &mut remote_tx, &mut buf, conn_local).await;
        });

        let conn_remote = conn.clone();
        let backward_handle = tokio::spawn(async move {
            let mut buf = vec![0u8; 65575];
            loop {
                match remote_rx.read(&mut buf).await {
                    Ok(0) => break,
                    Ok(n) => {
                        if let Err(e) = local_tx.write_all(&buf[..n]).await {
                            tracing::warn!("Relay write to local failed: {e}");
                            break;
                        }
                        if let Err(e) = local_tx.flush().await {
                            tracing::warn!("Relay flush to local failed: {e}");
                            break;
                        }
                        conn_remote.stats.lock().rx_bytes += n as u64;
                    }
                    Err(e) => {
                        tracing::warn!("Relay read from remote failed: {e}");
                        break;
                    }
                }
            }
        });

        // Wait for either direction to finish, then clean up
        let _ = tokio::join!(forward_handle, backward_handle);

        let _ = conn.handle_event(ConnectionEvent::Close);
        tracing::info!(conn_id = %conn.id, "Relay finished");
        Ok(())
    }

    /// Start relaying with TLS wrapping on the remote (outbound) side.
    ///
    /// 1. Wraps `remote_sock` in a TLS stream using the given connector.
    /// 2. Spawns the forward and backward tasks with the TLS stream.
    ///
    /// The local (inbound) side remains raw TCP (the client connects
    /// locally without TLS — the TLS is only on the outbound leg to the
    /// remote server).
    pub async fn start_tls(
        local_sock: TcpStream,
        remote_sock: TcpStream,
        domain: &str,
        tls_connector: &dyn TlsConnector,
        conn: Arc<ManagedConnection>,
        first_prefix_data: Bytes,
        shutdown_rx: oneshot::Receiver<()>,
    ) -> Result<()> {
        tracing::info!(%domain, conn_id = %conn.id, "Wrapping remote connection in TLS");

        let tls_remote = tls_connector
            .connect(domain, remote_sock)
            .await
            .map_err(|e| anyhow::anyhow!("TLS connect to {domain} failed: {e}"))?;

        tracing::info!(%domain, conn_id = %conn.id, "TLS handshake complete, starting relay");

        // Now relay between raw local and TLS remote
        Self::start_tls_raw_relay(local_sock, tls_remote, conn, first_prefix_data, shutdown_rx).await
    }

    /// Relay between a raw TCP stream (local) and a TLS stream (remote).
    pub async fn start_tls_raw_relay(
        local_sock: TcpStream,
        tls_remote: BoxedStream,
        conn: Arc<ManagedConnection>,
        first_prefix_data: Bytes,
        mut shutdown_rx: oneshot::Receiver<()>,
    ) -> Result<()> {
        let (mut local_rx, mut local_tx) = tokio::io::split(local_sock);
        let (mut tls_rx, mut tls_tx) = tokio::io::split(tls_remote);

        // Send prefix data if any
        if !first_prefix_data.is_empty() {
            tls_tx.write_all(&first_prefix_data).await?;
            tls_tx.flush().await?;
            {
                let mut stats = conn.stats.lock();
                stats.tx_bytes += first_prefix_data.len() as u64;
            }
        }

        let conn_local = conn.clone();
        let forward_handle = tokio::spawn(async move {
            let mut buf = vec![0u8; 65575];
            loop {
                tokio::select! {
                    result = local_rx.read(&mut buf) => {
                        match result {
                            Ok(0) => break,
                            Ok(n) => {
                                if let Err(e) = tls_tx.write_all(&buf[..n]).await {
                                    tracing::warn!("Relay write to TLS remote failed: {e}");
                                    break;
                                }
                                if let Err(e) = tls_tx.flush().await {
                                    tracing::warn!("Relay flush to TLS remote failed: {e}");
                                    break;
                                }
                                conn_local.stats.lock().tx_bytes += n as u64;
                            }
                            Err(e) => {
                                tracing::warn!("Relay read from local failed: {e}");
                                break;
                            }
                        }
                    }
                    _ = &mut shutdown_rx => {
                        tracing::info!("Relay TLS shutdown signal received");
                        break;
                    }
                }
            }
        });

        let conn_remote = conn.clone();
        let backward_handle = tokio::spawn(async move {
            let mut buf = vec![0u8; 65575];
            loop {
                match tls_rx.read(&mut buf).await {
                    Ok(0) => break,
                    Ok(n) => {
                        if let Err(e) = local_tx.write_all(&buf[..n]).await {
                            tracing::warn!("Relay write from TLS to local failed: {e}");
                            break;
                        }
                        if let Err(e) = local_tx.flush().await {
                            tracing::warn!("Relay flush to local failed: {e}");
                            break;
                        }
                        conn_remote.stats.lock().rx_bytes += n as u64;
                    }
                    Err(e) => {
                        tracing::warn!("Relay read from TLS remote failed: {e}");
                        break;
                    }
                }
            }
        });

        let _ = tokio::join!(forward_handle, backward_handle);
        let _ = conn.handle_event(ConnectionEvent::Close);
        tracing::info!(conn_id = %conn.id, "TLS relay finished");
        Ok(())
    }

    /// Internal helper for the forward (local→remote) direction.
    async fn forward_internal<R, W>(
        local_rx: &mut R,
        remote_tx: &mut W,
        buf: &mut [u8],
        conn: Arc<ManagedConnection>,
    ) where
        R: AsyncRead + Unpin,
        W: AsyncWrite + Unpin,
    {
        loop {
            match local_rx.read(buf).await {
                Ok(0) => break,
                Ok(n) => {
                    if let Err(e) = remote_tx.write_all(&buf[..n]).await {
                        tracing::warn!("Relay write to remote failed: {e}");
                        break;
                    }
                    if let Err(e) = remote_tx.flush().await {
                        tracing::warn!("Relay flush to remote failed: {e}");
                        break;
                    }
                    conn.stats.lock().tx_bytes += n as u64;
                }
                Err(e) => {
                    tracing::warn!("Relay read from local failed: {e}");
                    break;
                }
            }
        }
    }
}
