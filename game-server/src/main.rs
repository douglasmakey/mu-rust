use anyhow::{Context, Result};
use mu_protocol::{
    packet::RawPacket,
    protocol_constants::{BIG_PACKET_MAX_SIZE, C1},
};
use mu_runtime::{PacketStream, Server, ServerConfig};
use std::{net::SocketAddr, time::Duration};
use tokio_util::bytes::{BufMut, BytesMut};
use tracing::{debug, info, warn};

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();
    let default_timeout = Duration::from_secs(120);
    let server = Server::new(ServerConfig {
        name: "GameServer".to_string(),
        bind_addr: "0.0.0.0:55901".parse().unwrap(),
        read_timeout: default_timeout,
        write_timeout: default_timeout,
        max_packet_size: BIG_PACKET_MAX_SIZE,
    });

    server
        .run_tcp_listener(
            move |stream, peer_addr| async move { handle_client(stream, peer_addr).await },
        )
        .await
}

async fn handle_client(mut stream: PacketStream, peer_addr: SocketAddr) -> Result<()> {
    debug!(peer = %peer_addr, "client handler has started.");

    // MU protocol: server must send GameServerEntered immediately on connect.
    // expect is acceptable — build_hello_packet uses hardcoded bytes that are
    // validated at construction. A failure here is a programming error.
    let hello_packet = build_hello_packet().expect("invalid hello packet");
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
    }
    info!(peer = %peer_addr, "game-server client disconnected");
    Ok(())
}

/// Builds the C1-F1-00 `GameServerEntered` hello packet.
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
