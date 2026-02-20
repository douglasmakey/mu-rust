use anyhow::{Context, Result};
use futures_util::{SinkExt, StreamExt};
use mu_protocol::{codecs::PacketCodec, error::ProtocolError, packet::RawPacket};
use std::{net::SocketAddr, time::Duration};
use thiserror::Error;
use tokio::net::{TcpListener, TcpStream};
use tokio_util::codec::Framed;
use tracing::{info, warn};

/// Transport-level errors for an active client connection.
///
/// Separates protocol framing errors ([`ProtocolError`]) from timeout errors
/// that are purely a runtime/transport concern.
#[derive(Debug, Error)]
pub enum ConnectionError {
    #[error("protocol error: {0}")]
    Protocol(#[from] ProtocolError),

    #[error("read timed out")]
    ReadTimeout,

    #[error("write timed out")]
    WriteTimeout,
}

/// A framed TCP stream that reads/writes [`RawPacket`]s with per-operation timeouts.
pub struct PacketStream {
    inner: Framed<TcpStream, PacketCodec>,
    read_timeout: Duration,
    write_timeout: Duration,
}

impl PacketStream {
    pub(crate) fn new(
        socket: TcpStream,
        max_packet_size: usize,
        read_timeout: Duration,
        write_timeout: Duration,
    ) -> Self {
        Self {
            inner: Framed::new(socket, PacketCodec::new(max_packet_size)),
            read_timeout,
            write_timeout,
        }
    }

    pub async fn recv(&mut self) -> Option<Result<RawPacket, ConnectionError>> {
        match tokio::time::timeout(self.read_timeout, self.inner.next()).await {
            Ok(result) => result.map(|r| r.map_err(ConnectionError::from)),
            Err(_) => Some(Err(ConnectionError::ReadTimeout)),
        }
    }

    pub async fn send(&mut self, packet: RawPacket) -> Result<(), ConnectionError> {
        tokio::time::timeout(self.write_timeout, self.inner.send(packet))
            .await
            .map_err(|_| ConnectionError::WriteTimeout)?
            .map_err(ConnectionError::from)
    }
}

/// Configuration for a [`Server`].
pub struct ServerConfig {
    pub name: String,
    pub bind_addr: SocketAddr,
    pub read_timeout: Duration,
    pub write_timeout: Duration,
    pub max_packet_size: usize,
}

pub struct Server {
    config: ServerConfig,
}

impl Server {
    pub fn new(config: ServerConfig) -> Self {
        Self { config }
    }

    pub async fn run_tcp_listener<H, F>(&self, handler: H) -> Result<()>
    where
        H: Fn(PacketStream, SocketAddr) -> F + Send + 'static,
        F: Future<Output = Result<()>> + Send + 'static,
    {
        let bind_addr = self.config.bind_addr;
        let listener = TcpListener::bind(bind_addr)
            .await
            .with_context(|| format!("failed to bind to {bind_addr}"))?;

        info!(bind_addr = %bind_addr, "{} listening", self.config.name);
        let mut shutdown = Box::pin(tokio::signal::ctrl_c());
        loop {
            tokio::select! {
                _ = &mut shutdown => {
                    info!("shutting down server");
                    break;
                }
                accepted = listener.accept() => {
                    let (socket, peer_addr) = match accepted {
                        Ok(conn) => conn,
                        Err(e) => {
                            warn!(error = %e, "failed to accept connection");
                            continue;
                        }
                    };

                    info!(peer = %peer_addr, "client connected");
                    let stream = PacketStream::new(
                        socket,
                        self.config.max_packet_size,
                        self.config.read_timeout,
                        self.config.write_timeout,
                    );

                    let h = handler(stream, peer_addr);
                    tokio::spawn(async move {
                        if let Err(e) = h.await {
                            warn!(peer = %peer_addr, error = %e, "client handling failed");
                        }
                    });
                }
            }
        }

        Ok(())
    }
}
