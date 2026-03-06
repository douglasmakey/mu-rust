/// Errors that can occur while parsing or framing MU protocol packets.
///
/// `Io` is included because `tokio_util::codec::Decoder::Error` must implement
/// `From<std::io::Error>`. The remaining variants are pure protocol-level
/// issues that don't depend on the transport.
#[derive(Debug, thiserror::Error)]
pub enum ProtocolError {
    /// Returned when the buffer doesn't contain enough bytes to form a packet
    /// (e.g., empty input to `RawPacket::try_new`).
    #[error("packet is incomplete")]
    Incomplete,

    /// The packet is malformed — e.g., invalid UTF-8 in a string field.
    #[error("packet is malformed")]
    Malformed,

    /// The first byte is not a recognized packet type (C1/C2/C3/C4).
    #[error("invalid packet header byte: 0x{0:02X}")]
    InvalidHeader(u8),

    /// The packet's own length field is smaller than its header — structurally impossible.
    #[error("packet length field is invalid: declared={declared}, min={minimum}")]
    InvalidLength { declared: usize, minimum: usize },

    /// The packet is shorter than the minimum required by its specific message type.
    /// (e.g., a `ConnectionInfoRequest` that lacks the `server_id` bytes).
    #[error("packet too short: need {expected} bytes, got {actual}")]
    PacketTooShort { expected: usize, actual: usize },

    /// The declared length exceeds the configured per-connection maximum.
    #[error("packet too large: max {max} bytes, got {actual}")]
    PacketTooLarge { max: usize, actual: usize },

    /// The declared length field doesn't match the actual buffer size.
    #[error("packet length does not match declared length: declared={declared}, actual={actual}")]
    LengthMismatch { declared: usize, actual: usize },

    /// A SimpleModulus block failed to decrypt (bad checksum, counter, or block size).
    #[error("decryption failed: {0}")]
    Decryption(String),

    #[error("i/o error: {0}")]
    Io(#[from] std::io::Error),
}
