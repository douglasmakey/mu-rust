mod context;
mod handlers;
mod packet;

use crate::context::{ConfiguredGameServer, ConnectCtx};
use anyhow::{Context, Result};
use mu_protocol::{
    packet::RawPacket,
    protocol_constants::{C1, SMALL_PACKET_MAX_SIZE},
};
use mu_runtime::{PacketStream, Server, ServerConfig};
use std::{net::SocketAddr, sync::Arc, time::Duration};
use tracing::{debug, info, warn};

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    let ctx = ConnectCtx {
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

    let server = Server::new(ServerConfig {
        name: "ConnectServer".to_string(),
        bind_addr: "0.0.0.0:44405".parse().unwrap(),
        read_timeout: Duration::from_secs(120),
        write_timeout: Duration::from_secs(120),
        max_packet_size: SMALL_PACKET_MAX_SIZE, // C1 only — no need for larger packets
    });
    let ctx = Arc::new(ctx);
    server
        .run_tcp_listener(move |socket, peer_addr| {
            let ctx = Arc::clone(&ctx);
            async move { handle_client(socket, peer_addr, ctx).await }
        })
        .await
}

async fn handle_client(
    mut stream: PacketStream,
    peer_addr: SocketAddr,
    ctx: Arc<ConnectCtx>,
) -> Result<()> {
    // The MU protocol requires the server to send a hello packet upon connection.
    // This is a hardcoded constant — expect is acceptable here since it can
    // only fail if the literal bytes above are wrong.
    let hello_packet =
        RawPacket::try_from_vec(vec![C1, 0x04, 0x00, 0x01]).expect("invalid hello packet");
    stream
        .send(hello_packet)
        .await
        .context("failed to send hello packet")?;
    debug!(%peer_addr, "sent hello packet");

    while let Some(next_packet) = stream.recv().await {
        let packet = match next_packet {
            Ok(packet) => packet,
            Err(e) => {
                warn!(error = %e, "Packet read error");
                break;
            }
        };

        debug!(packet = ?packet, "received packet");
        let action = handlers::handle_packet(&ctx, &packet, peer_addr);
        match action {
            handlers::PacketHandling::Reply(response) => {
                if let Err(e) = stream.send(response).await {
                    warn!(error = %e, "failed to send response");
                    break;
                }
            }
            handlers::PacketHandling::Ignore => {
                debug!(packet = ?packet, "ignored packet");
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
