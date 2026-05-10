use crate::error::{ParseError, Result};
use crate::{InformationClassCode, PacketClassCode};

pub const DIFI_CID: u32 = 0x6A_621E;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ClassId {
    pub pad_bit_count: u8,
    pub oui: u32,
    pub information_class: InformationClassCode,
    pub packet_class: PacketClassCode,
}

impl ClassId {
    pub(crate) fn parse(word0: u32, word1: u32) -> Result<Self> {
        let pad_bit_count = ((word0 >> 27) & 0x1F) as u8;
        let reserved = (word0 >> 24) & 0x7;
        if reserved != 0 {
            return Err(ParseError::ReservedBitsNonZero {
                field: "class identifier",
                bits: reserved,
            });
        }

        let oui = word0 & 0x00FF_FFFF;
        if oui != DIFI_CID {
            return Err(ParseError::InvalidOui { actual: oui });
        }

        let information_class = InformationClassCode::try_from((word1 >> 16) as u16)?;
        let packet_class = PacketClassCode::try_from((word1 & 0xFFFF) as u16)?;

        Ok(Self {
            pad_bit_count,
            oui,
            information_class,
            packet_class,
        })
    }
}
