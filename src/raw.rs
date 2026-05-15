use crate::error::{ParseError, Result};

pub(crate) const WORD_BYTES: usize = 4;
pub(crate) const PROLOGUE_WORDS: u16 = 7;
pub(crate) const PROLOGUE_BYTES: usize = PROLOGUE_WORDS as usize * WORD_BYTES;

pub(crate) fn read_u32_be(input: &[u8], word_index: usize) -> Result<u32> {
    let start = word_index * WORD_BYTES;
    let end = start + WORD_BYTES;
    let bytes = input.get(start..end).ok_or(ParseError::InputTooShort {
        min: end,
        actual: input.len(),
    })?;
    Ok(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

pub(crate) fn read_u64_be(input: &[u8], word_index: usize) -> Result<u64> {
    let high = read_u32_be(input, word_index)? as u64;
    let low = read_u32_be(input, word_index + 1)? as u64;
    Ok((high << 32) | low)
}

pub(crate) fn read_i64_be(input: &[u8], word_index: usize) -> Result<i64> {
    Ok(read_u64_be(input, word_index)? as i64)
}

#[cfg(feature = "write")]
pub(crate) fn write_u32_be(output: &mut [u8], word_index: usize, value: u32) {
    let start = word_index * WORD_BYTES;
    let end = start + WORD_BYTES;
    output[start..end].copy_from_slice(&value.to_be_bytes());
}

#[cfg(feature = "write")]
pub(crate) fn write_u64_be(output: &mut [u8], word_index: usize, value: u64) {
    write_u32_be(output, word_index, (value >> 32) as u32);
    write_u32_be(output, word_index + 1, value as u32);
}

#[cfg(feature = "write")]
pub(crate) fn write_i64_be(output: &mut [u8], word_index: usize, value: i64) {
    write_u64_be(output, word_index, value as u64);
}
