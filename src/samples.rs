use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ComplexI8 {
    pub i: i8,
    pub q: i8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ComplexI16 {
    pub i: i16,
    pub q: i16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum SampleError {
    #[error("payload length {len} is not a multiple of {sample_bytes} bytes")]
    MisalignedPayload { len: usize, sample_bytes: usize },
}

#[derive(Debug, Clone)]
pub struct IqI8Samples<'a> {
    chunks: core::slice::ChunksExact<'a, u8>,
}

impl Iterator for IqI8Samples<'_> {
    type Item = ComplexI8;

    fn next(&mut self) -> Option<Self::Item> {
        let chunk = self.chunks.next()?;
        Some(ComplexI8 {
            i: chunk[0] as i8,
            q: chunk[1] as i8,
        })
    }
}

impl ExactSizeIterator for IqI8Samples<'_> {}

#[derive(Debug, Clone)]
pub struct IqI16Samples<'a> {
    chunks: core::slice::ChunksExact<'a, u8>,
}

impl Iterator for IqI16Samples<'_> {
    type Item = ComplexI16;

    fn next(&mut self) -> Option<Self::Item> {
        let chunk = self.chunks.next()?;
        Some(ComplexI16 {
            i: i16::from_be_bytes([chunk[0], chunk[1]]),
            q: i16::from_be_bytes([chunk[2], chunk[3]]),
        })
    }
}

impl ExactSizeIterator for IqI16Samples<'_> {}

pub fn iq_i8_samples(payload: &[u8]) -> core::result::Result<IqI8Samples<'_>, SampleError> {
    let chunks = payload.chunks_exact(2);
    if chunks.remainder().is_empty() {
        Ok(IqI8Samples { chunks })
    } else {
        Err(SampleError::MisalignedPayload {
            len: payload.len(),
            sample_bytes: 2,
        })
    }
}

pub fn iq_i16_samples(payload: &[u8]) -> core::result::Result<IqI16Samples<'_>, SampleError> {
    let chunks = payload.chunks_exact(4);
    if chunks.remainder().is_empty() {
        Ok(IqI16Samples { chunks })
    } else {
        Err(SampleError::MisalignedPayload {
            len: payload.len(),
            sample_bytes: 4,
        })
    }
}
