use crate::{
    context::ConnectCtx,
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

pub fn handle_packet(ctx: &ConnectCtx, packet: &RawPacket, peer: SocketAddr) -> PacketHandling {
    let parsed = match ConnectServerPacket::parse(packet) {
        Ok(p) => p,
        Err(e) => {
            warn!(error = %e, "Failed to parse packet");
            return PacketHandling::Disconnect;
        }
    };

    match parsed {
        ConnectServerPacket::ServerListRequest => {
            info!(peer = %peer, server_count = ctx.servers.len(), "Server list requested");
            let response = build_server_list_response(&ctx.servers);
            match response {
                Ok(packet) => PacketHandling::Reply(packet),
                Err(e) => {
                    warn!(error = %e, "Failed to build server list response");
                    PacketHandling::Disconnect
                }
            }
        }
        ConnectServerPacket::ConnectionInfoRequest { server_id } => {
            let server = ctx.servers.iter().find(|s| s.id == server_id);
            if let Some(server) = server {
                info!(peer = %peer, server_id = server.id, "Connection info requested");
                let response = build_connection_info(server.ip_address, server.port);
                match response {
                    Ok(packet) => PacketHandling::Reply(packet),
                    Err(e) => {
                        warn!(error = %e, "Failed to build connection info response");
                        PacketHandling::Disconnect
                    }
                }
            } else {
                warn!(peer = %peer, server_id = server_id, "Server not found");
                PacketHandling::Ignore
            }
        }
        ConnectServerPacket::Unknown { code, sub_code } => {
            warn!(peer = %peer, code = code, sub_code = sub_code, "Unknown packet");
            PacketHandling::Ignore
        }
    }
}

#[cfg(test)]
mod tests {
    use mu_protocol::protocol_constants::C1;

    use crate::context::ConfiguredGameServer;

    use super::*;

    fn peer() -> SocketAddr {
        "127.0.0.1:12345".parse().expect("addr")
    }

    fn test_config() -> ConnectCtx {
        ConnectCtx {
            servers: vec![ConfiguredGameServer {
                id: 1,
                load_percentage: 0,
                ip_address: "127.0.0.1".parse().expect("addr"),
                port: 55901,
            }],
        }
    }

    #[test]
    fn unknown_packet_is_ignored() {
        let packet = RawPacket::try_from_vec(vec![C1, 0x04, 0xAA, 0xBB]).expect("valid packet");
        let action = handle_packet(&test_config(), &packet, peer());
        assert!(matches!(action, PacketHandling::Ignore))
    }

    #[test]
    fn malformed_connection_info_request_disconnects() {
        let packet =
            RawPacket::try_from_vec(vec![C1, 0x05, 0xF4, 0x03, 0x00]).expect("valid packet");
        let action = handle_packet(&test_config(), &packet, peer());
        assert!(matches!(action, PacketHandling::Disconnect))
    }

    #[test]
    fn parse_connection_info_request_reads_server_id_as_little_endian() {
        // server_id = 0x0305 stored as [0x05, 0x03] on the wire.
        let packet = RawPacket::try_from_vec(vec![C1, 0x06, 0xF4, 0x03, 0x05, 0x03]).unwrap();
        match ConnectServerPacket::parse(&packet).unwrap() {
            ConnectServerPacket::ConnectionInfoRequest { server_id } => {
                assert_eq!(server_id, 0x0305);
            }
            _ => panic!("expected ConnectionInfoRequest"),
        }
    }

    #[test]
    fn server_list_request_replies_with_correct_payload() {
        let packet = RawPacket::try_from_vec(vec![C1, 0x04, 0xF4, 0x06]).unwrap();
        if let PacketHandling::Reply(reply) = handle_packet(&test_config(), &packet, peer()) {
            // 1 configured server → 7-byte header + 4-byte entry = 11 bytes.
            assert_eq!(reply.len(), 11);
        } else {
            panic!("expected Reply");
        }
    }

    #[test]
    fn connection_info_request_replies_with_server_address() {
        // server_id = 1, LE: [0x01, 0x00].
        let packet = RawPacket::try_from_vec(vec![C1, 0x06, 0xF4, 0x03, 0x01, 0x00]).unwrap();
        if let PacketHandling::Reply(reply) = handle_packet(&test_config(), &packet, peer()) {
            let data = reply.as_slice();
            assert_eq!(&data[4..13], b"127.0.0.1");
            assert_eq!(u16::from_le_bytes([data[20], data[21]]), 55901);
        } else {
            panic!("expected Reply");
        }
    }

    #[test]
    fn connection_info_request_unknown_server_ignores() {
        // server_id 99 is not in the config.
        let packet = RawPacket::try_from_vec(vec![C1, 0x06, 0xF4, 0x03, 0x63, 0x00]).unwrap();
        assert!(matches!(
            handle_packet(&test_config(), &packet, peer()),
            PacketHandling::Ignore
        ));
    }
}
