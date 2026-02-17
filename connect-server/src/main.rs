mod config;
mod handlers;
mod packet;

use crate::config::{ConfiguredGameServer, ConnectConfig};
use anyhow::{Context, Result};
use futures_util::{SinkExt, StreamExt};
use mu_protocol::{codecs::PacketCodec, packet::RawPacket, protocol_constants::C1};
use std::{net::SocketAddr, sync::Arc};
use tokio::net::{TcpListener, TcpStream};
use tokio_util::codec::Framed;
use tracing::{debug, info, warn};

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    let config = ConnectConfig {
        bind_addr: "0.0.0.0:44405".parse().unwrap(),
        servers: vec![
            ConfiguredGameServer {
                id: 1,
                load_percentage: 0,
                ip_address: "127.0.0.1".parse().unwrap(),
                port: 55901,
            },
            ConfiguredGameServer {
                id: 2,
                load_percentage: 0,
                ip_address: "127.0.0.1".parse().unwrap(),
                port: 55902,
            },
        ],
    };

    info!(
        bind_addr = %config.bind_addr,
        server_count = config.servers.len(),
        "starting connect server"
    );

    run_server(config).await
}

async fn run_server(config: ConnectConfig) -> Result<()> {
    let listener = TcpListener::bind(&config.bind_addr)
        .await
        .with_context(|| format!("failed to bind to {}", &config.bind_addr))?;

    info!("Connect Server is listening");
    let config = Arc::new(config);
    // Pin the future so we can poll it repeatedly across select! iterations.
    let mut shutdown = Box::pin(tokio::signal::ctrl_c());
    loop {
        tokio::select! {
            _ = &mut shutdown => {
                info!("shutting down server");
                break;
            }
            accepted = listener.accept() => {
                let (socket, peer_addr) = accepted.context("failed to accept client connection")?;
                info!(peer = %peer_addr, "Client connected");

                let client_config = Arc::clone(&config);
                tokio::spawn(async move {
                    if let Err(e) = handle_client(socket, peer_addr, client_config).await {
                        warn!(peer = %peer_addr, error = %e, "client handling failed");
                    }
                });
            }
        }
    }

    Ok(())
}

async fn handle_client(
    stream: TcpStream,
    peer_addr: SocketAddr,
    config: Arc<ConnectConfig>,
) -> Result<()> {
    let mut framed = Framed::new(stream, PacketCodec);

    // The MU protocol requires the server to send a hello packet upon connection.
    // This is a hardcoded constant — expect is acceptable here since it can
    // only fail if the literal bytes above are wrong.
    let hello_packet =
        RawPacket::try_from_vec(vec![C1, 0x04, 0x00, 0x01]).expect("invalid hello packet");
    framed
        .send(hello_packet)
        .await
        .context("failed to send hello packet")?;
    debug!(%peer_addr, "sent hello packet");

    while let Some(next_packet) = framed.next().await {
        let packet = match next_packet {
            Ok(packet) => packet,
            Err(e) => {
                warn!(error = %e, "Packet read error");
                break;
            }
        };

        debug!(packet = ?packet, "received packet");
        let action = handlers::handle_packet(&config, &packet, peer_addr);
        match action {
            handlers::PacketHandling::Reply(response) => {
                if let Err(e) = framed.send(response).await {
                    warn!(error = %e, "failed to send response");
                    break;
                }
            }
            handlers::PacketHandling::Ignore => {
                debug!(packet = ?packet, "ignored packet")
            }
            handlers::PacketHandling::Disconnect => {
                warn!(data = ?packet, "disconnecting after malformed packet");
                break;
            }
        }
    }
    info!(peer = %peer_addr, "connect-server client disconnected");
    Ok(())
}
