/// MU Online packet type markers — the first byte of every packet on the wire.
/// See `RawPacketType` for the semantic breakdown (header size, encryption).
pub const C1: u8 = 0xC1;
pub const C2: u8 = 0xC2;
pub const C3: u8 = 0xC3;
pub const C4: u8 = 0xC4;

/// Maximum size of a C1/C3 packet (1-byte length field → 255 bytes).
pub const SMALL_PACKET_MAX_SIZE: usize = 255;

/// Maximum size of a C2/C4 packet (2-byte length field → 65535 bytes).
pub const BIG_PACKET_MAX_SIZE: usize = 65535;
