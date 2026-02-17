use crate::{
    config::ConnectConfig,
    packet::{build_connection_info, build_server_list_response},
};
use anyhow::Result;
use mu_protocol::{error::ProtocolError, packet::RawPacket};
use std::net::SocketAddr;
use tracing::{info, warn};

/// Parsed form of a connect-server client request.
#[derive(Debug)]
pub enum ConnectServerPacket {
    ServerListRequest,
    ConnectionInfoRequest {
        server_id: u16,
    },
    Unknown {
        code: Option<u8>,
        sub_code: Option<u8>,
    },
}

impl ConnectServerPacket {
    pub fn parse(packet: &RawPacket) -> Result<Self, ProtocolError> {
        let (code, sub_code) = packet.header_codes();
        match (code, sub_code) {
            (Some(0xF4), Some(0x06)) => Ok(Self::ServerListRequest),
            (Some(0xF4), Some(0x03)) => {
                // C1-F4-03 ConnectionInfoRequest (by client).
                // See: docs/OpenMU/Packets/C1-F4-03-ConnectionInfoRequest_by-client.md
                // Layout: [C1(0), len(1), code(2), sub(3), server_id_lo(4), server_id_hi(5)]
                let data = packet.as_slice();
                if data.len() < 6 {
                    return Err(ProtocolError::PacketTooShort {
                        expected: 6,
                        actual: data.len(),
                    });
                }
                let server_id = u16::from_le_bytes([data[4], data[5]]);
                Ok(Self::ConnectionInfoRequest { server_id })
            }
            _ => Ok(Self::Unknown { code, sub_code }),
        }
    }
}

#[derive(Debug)]
pub enum PacketHandling {
    Reply(RawPacket),
    Ignore,
    Disconnect,
}

pub fn handle_packet(
    config: &ConnectConfig,
    packet: &RawPacket,
    peer: SocketAddr,
) -> PacketHandling {
    let parsed = match ConnectServerPacket::parse(packet) {
        Ok(p) => p,
        Err(e) => {
            warn!(error = %e, "Failed to parse packet");
            return PacketHandling::Disconnect;
        }
    };

    match parsed {
        ConnectServerPacket::ServerListRequest => {
            info!(peer = %peer, server_count = config.servers.len(), "Server list requested");
            let response = build_server_list_response(&config.servers);
            match response {
                Ok(packet) => PacketHandling::Reply(packet),
                Err(e) => {
                    warn!(error = %e, "Failed to build server list response");
                    PacketHandling::Disconnect
                }
            }
        }
        ConnectServerPacket::ConnectionInfoRequest { server_id } => {
            let server = config.servers.iter().find(|s| s.id == server_id);
            match server {
                Some(server) => {
                    info!(peer = %peer, server_id = server.id, "Connection info requested");
                    let response = build_connection_info(server.ip_address, server.port);
                    match response {
                        Ok(packet) => PacketHandling::Reply(packet),
                        Err(e) => {
                            warn!(error = %e, "Failed to build connection info response");
                            PacketHandling::Disconnect
                        }
                    }
                }
                None => {
                    warn!(peer = %peer, server_id = server_id, "Server not found");
                    PacketHandling::Ignore
                }
            }
        }
        ConnectServerPacket::Unknown { code, sub_code } => {
            warn!(peer = %peer, code = code, sub_code = sub_code, "Unknown packet");
            PacketHandling::Ignore
        }
    }
}
