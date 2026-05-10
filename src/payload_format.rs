use crate::error::{ParseError, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum PayloadSampleFormat {
    ComplexSignedCartesian,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct PayloadFormat {
    pub raw_word0: u32,
    pub raw_word1: u32,
    pub sample_format: PayloadSampleFormat,
    pub data_item_size_bits: u8,
    pub item_packing_field_size_bits: u8,
}

impl PayloadFormat {
    pub(crate) fn parse(word0: u32, word1: u32) -> Result<Self> {
        let data_item_size_minus_one = (word0 & 0x3F) as u8;
        let item_packing_minus_one = ((word0 >> 6) & 0x3F) as u8;
        let fixed = word0 & !0x0FFF;
        let data_item_size_bits = data_item_size_minus_one + 1;
        let item_packing_field_size_bits = item_packing_minus_one + 1;

        if fixed != 0xA000_0000
            || word1 != 0
            || data_item_size_minus_one != item_packing_minus_one
            || !(4..=16).contains(&data_item_size_bits)
        {
            return Err(ParseError::InvalidPayloadFormat { word0, word1 });
        }

        Ok(Self {
            raw_word0: word0,
            raw_word1: word1,
            sample_format: PayloadSampleFormat::ComplexSignedCartesian,
            data_item_size_bits,
            item_packing_field_size_bits,
        })
    }
}
