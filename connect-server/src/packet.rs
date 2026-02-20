use crate::context::ConfiguredGameServer;
use anyhow::{Context, Result};
use bytes::{BufMut, BytesMut};
use mu_protocol::{
    packet::RawPacket,
    protocol_constants::{C1, C2},
};
use std::net::Ipv4Addr;
use tracing::debug;

// Wire layout constants for C2-F4-06 ServerListResponse.
// See: docs/OpenMU/Packets/C2-F4-06-ServerListResponse_by-server.md
const HEADER_SIZE: usize = 3 + 1 + 1 + 2; // C2 framing(3) + code(1) + sub_code(1) + server_count(2)
const ENTRY_SIZE: usize = 4; // server_id(2) + load_percentage(1) + padding(1)

/// Builds a C1-F4-03 `ConnectionInfo` response packet.
/// See: docs/OpenMU/Packets/C1-F4-03-ConnectionInfo_by-server.md
///
/// Wire layout (22 bytes total):
///   [0]    C1 header
///   [1]    length (22)
///   [2]    code   (0xF4)
///   [3]    sub    (0x03)
///   [4..20] IP address as a null-terminated ASCII string in a 16-byte field
///   [20..22] port as little-endian u16
pub fn build_connection_info(ip: Ipv4Addr, port: u16) -> Result<RawPacket> {
    debug!(ip = %ip, port = port, "Building connection info");
    let ip_str = ip.to_string();
    let mut buf = BytesMut::with_capacity(22);
    buf.put_u8(C1);
    buf.put_u8(22);
    buf.put_u8(0xF4);
    buf.put_u8(0x03);

    // IPv4 max string is "255.255.255.255" (15 chars), which fits in the
    // 16-byte protocol field. Remaining bytes are null-padded.
    let ip_bytes = ip_str.as_bytes();
    buf.put_slice(ip_bytes);
    for _ in ip_bytes.len()..16 {
        buf.put_u8(0x00);
    }

    buf.put_u16_le(port);
    RawPacket::try_new(buf.freeze()).context("invalid connection info packet")
}

/// Builds a C2-F4-06 `ServerListResponse` packet.
/// See: docs/OpenMU/Packets/C2-F4-06-ServerListResponse_by-server.md
///
/// Wire layout:
///   [0]      C2 header
///   [1..3]   total length (big-endian u16) — uses C2 because the list can exceed 255 bytes
///   [3]      code   (0xF4)
///   [4]      sub    (0x06)
///   [5..7]   server count (big-endian u16)
///   [7..]    N × 4-byte `ServerLoadInfo` entries
pub fn build_server_list_response(servers: &[ConfiguredGameServer]) -> anyhow::Result<RawPacket> {
    let payload_len = HEADER_SIZE + servers.len() * ENTRY_SIZE;
    let packet_len: u16 = payload_len
        .try_into()
        .map_err(|_| anyhow::anyhow!("packet length overflow"))?;

    let mut buf = BytesMut::with_capacity(payload_len);
    buf.put_u8(C2);
    buf.put_u16(packet_len);
    buf.put_u8(0xF4);
    buf.put_u8(0x06);

    let server_count: u16 = servers
        .len()
        .try_into()
        .map_err(|_| anyhow::anyhow!("too many servers for u16 count field"))?;

    buf.put_u16(server_count);

    for server in servers {
        buf.put_u16_le(server.id);
        buf.put_u8(server.load_percentage);
        buf.put_u8(0); // padding byte defined by protocol
    }

    RawPacket::try_new(buf.freeze()).context("invalid list response packet")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_connection_info_packets() {
        let port = 55901;
        let packet =
            build_connection_info("127.0.0.1".parse().expect("addr"), port).expect("packet");
        let packet_slice = packet.as_slice();
        assert_eq!(packet_slice[0], C1);
        assert_eq!(packet_slice[1], 22);
        assert_eq!(packet_slice[2], 0xF4);
        assert_eq!(packet_slice[3], 0x03);
        assert_eq!(&packet_slice[4..13], b"127.0.0.1");
        assert_eq!(&packet_slice[13..20], &[0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(&packet_slice[20..], port.to_le_bytes());
    }

    #[test]
    fn build_connection_info_max_length_ip_fits_in_16_byte_field() {
        // "255.255.255.255" is 15 chars — the tightest fit; one null padding byte remains.
        let packet = build_connection_info("255.255.255.255".parse().unwrap(), 55901).unwrap();
        let data = packet.as_slice();
        assert_eq!(&data[4..19], b"255.255.255.255");
        assert_eq!(data[19], 0x00);
    }

    // --- build_server_list_response ---

    #[test]
    fn build_server_list_response_wire_layout() {
        let servers = vec![
            ConfiguredGameServer {
                id: 1,
                load_percentage: 50,
                ip_address: "127.0.0.1".parse().unwrap(),
                port: 55901,
            },
            ConfiguredGameServer {
                id: 2,
                load_percentage: 75,
                ip_address: "127.0.0.2".parse().unwrap(),
                port: 55902,
            },
        ];
        let packet = build_server_list_response(&servers).unwrap();
        let data = packet.as_slice();

        assert_eq!(data.len(), HEADER_SIZE + 2 * ENTRY_SIZE);

        // C2 big-endian length must match actual buffer size.
        assert_eq!(u16::from_be_bytes([data[1], data[2]]) as usize, data.len());

        let server_count = u16::from_be_bytes([data[5], data[6]]);
        assert_eq!(server_count, 2);

        // First entry at offset 7 — server_id is little-endian.
        assert_eq!(u16::from_le_bytes([data[7], data[8]]), 1);
        assert_eq!(data[9], 50);

        // Second entry at offset 11.
        assert_eq!(u16::from_le_bytes([data[11], data[12]]), 2);
        assert_eq!(data[13], 75);
    }
}
