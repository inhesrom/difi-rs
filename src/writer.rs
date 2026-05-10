use thiserror::Error;

use crate::Packet;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum WriteError {
    #[error("packet writer is not implemented for borrowed parsed packets")]
    UnsupportedParsedPacket,
}

pub fn encoded_len(packet: &Packet<'_>) -> usize {
    packet.prologue().header.packet_size_words as usize * 4
}

pub fn write_packet(
    _packet: &Packet<'_>,
    _out: &mut [u8],
) -> core::result::Result<usize, WriteError> {
    Err(WriteError::UnsupportedParsedPacket)
}
