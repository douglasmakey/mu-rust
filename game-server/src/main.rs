use anyhow::{Context, Result};
use futures_util::{SinkExt, StreamExt};
use mu_protocol::{codecs::PacketCodec, packet::RawPacket, protocol_constants::C1};
use std::net::SocketAddr;
use tokio::net::{TcpListener, TcpStream};
use tokio_util::{
    bytes::{BufMut, BytesMut},
    codec::Framed,
};
use tracing::{debug, info, warn};

#[derive(Debug, Clone)]
struct GameConfig {
    bind_addr: SocketAddr,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();
    let config = GameConfig {
        bind_addr: "0.0.0.0:55901".parse().unwrap(),
    };

    info!(bind_addr = %config.bind_addr, "starting game server");
    run_server(config).await
}

async fn run_server(config: GameConfig) -> Result<()> {
    let listener = TcpListener::bind(&config.bind_addr)
        .await
        .with_context(|| format!("failed to bind to {}", &config.bind_addr))?;

    info!("Game Server is listening");
    let mut shutdown = Box::pin(tokio::signal::ctrl_c());
    loop {
        tokio::select! {
            _ = &mut shutdown => {
                info!("shutting down server");
                break;
            }
            accepted = listener.accept() => {
                let (socket, peer_addr) = accepted.context("failed to accept client connection")?;
                info!(peer = %peer_addr, "client connected");
                tokio::spawn(async move {
                    if let Err(e) = handle_client(socket, peer_addr).await {
                        warn!(peer = %peer_addr, error = %e, "client handling failed");
                    }
                });

            }
        }
    }

    Ok(())
}

async fn handle_client(stream: TcpStream, peer_addr: SocketAddr) -> Result<()> {
    debug!(peer = %peer_addr, "client handler has started.");
    let mut framed = Framed::new(stream, PacketCodec);

    // MU protocol: server must send GameServerEntered immediately on connect.
    // expect is acceptable — build_hello_packet uses hardcoded bytes that are
    // validated at construction. A failure here is a programming error.
    let hello_packet = build_hello_packet().expect("invalid hello packet");
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

        info!(packet = ?packet, "received packet");
    }
    info!(peer = %peer_addr, "game-server client disconnected");
    Ok(())
}

/// Builds the C1-F1-00 GameServerEntered hello packet.
///
/// Wire layout (12 bytes):
///   [0]     C1 header
///   [1]     length (0x0C = 12)
///   [2]     code   (0xF1)
///   [3]     sub    (0x00)
///   [4]     success flag (1 = ok)
///   [5..7]  player id (big-endian u16, placeholder 0x0200)
///   [7..12] version string as ASCII bytes ("10404")
fn build_hello_packet() -> Result<RawPacket> {
    let mut buf = BytesMut::with_capacity(12);
    buf.put_u8(C1);
    buf.put_u8(0x0C);
    buf.put_u8(0xF1);
    buf.put_u8(0x00);
    buf.put_u8(1);
    buf.put_u16(0x0200);
    buf.put_slice(&[0x31, 0x30, 0x34, 0x30, 0x34]); // "10404"

    RawPacket::try_new(buf.freeze()).context("invalid game server entered packet")
}
