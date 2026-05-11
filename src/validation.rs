use crate::error::{ParseError, Result};

pub(crate) fn validate_fixed_integer_hz(field: &'static str, raw: u64) -> Result<()> {
    if raw & ((1 << 20) - 1) == 0 {
        Ok(())
    } else {
        Err(ParseError::FractionalHzNotAllowed { field, raw })
    }
}

pub(crate) fn expect_word(field: &'static str, expected: u32, actual: u32) -> Result<()> {
    if actual == expected {
        Ok(())
    } else {
        Err(ParseError::InvalidFieldValue {
            field,
            expected,
            actual,
        })
    }
}

pub(crate) fn expect_word_one_of(field: &'static str, actual: u32, allowed: &[u32]) -> Result<()> {
    if allowed.contains(&actual) {
        Ok(())
    } else {
        Err(ParseError::InvalidFieldValueSet { field, actual })
    }
}

pub(crate) fn expect_bits(field: &'static str, expected: u8, actual: u8) -> Result<()> {
    if actual == expected {
        Ok(())
    } else {
        Err(ParseError::InvalidHeaderBits {
            field,
            expected,
            actual,
        })
    }
}
