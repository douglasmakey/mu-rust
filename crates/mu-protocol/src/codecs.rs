use bytes::BytesMut;
use tokio_util::codec::{Decoder, Encoder};

use crate::{
    error::ProtocolError,
    packet::{RawPacket, declared_length_from_prefix},
};

/// Stateless codec that frames a TCP byte stream into validated `RawPacket`s.
///
/// Responsibilities are split:
/// - **This codec**: stream framing — wait until enough bytes are buffered for a complete frame.
/// - **`RawPacket::try_new`**: structural validation — header type, declared vs actual length.
pub struct PacketCodec;

impl Decoder for PacketCodec {
    type Item = RawPacket;
    type Error = ProtocolError;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        let Some(declared_len) = declared_length_from_prefix(src.as_ref())? else {
            return Ok(None);
        };

        if src.len() < declared_len {
            // Tell tokio-util how many bytes we still need so it can size
            // the next read syscall appropriately.
            src.reserve(declared_len - src.len());
            return Ok(None);
        }

        // split_to advances the buffer past this frame; freeze yields an
        // immutable Bytes (zero-copy, Arc-backed) for RawPacket to own.
        let packet = src.split_to(declared_len).freeze();
        Ok(Some(RawPacket::try_new(packet)?))
    }
}

impl Encoder<RawPacket> for PacketCodec {
    type Error = ProtocolError;

    fn encode(&mut self, item: RawPacket, dst: &mut BytesMut) -> Result<(), Self::Error> {
        dst.extend_from_slice(item.as_slice());
        Ok(())
    }
}
