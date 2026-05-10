use crate::payload_format::PayloadFormat;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[repr(transparent)]
pub struct FixedU64(pub u64);

impl FixedU64 {
    pub const fn raw(self) -> u64 {
        self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[repr(transparent)]
pub struct FixedI64(pub i64);

impl FixedI64 {
    pub const fn raw(self) -> i64 {
        self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct SignalContextPacket {
    pub prologue: crate::Prologue,
    pub cif0: u32,
    pub context_changed: bool,
    pub reference_point: u32,
    pub bandwidth: FixedU64,
    pub if_reference_frequency: FixedI64,
    pub rf_reference_frequency: FixedI64,
    pub if_band_offset: FixedI64,
    pub scaling_level: i16,
    pub reference_level: i16,
    pub gain2: u16,
    pub gain1: u16,
    pub sample_rate: FixedU64,
    pub timestamp_adjustment: FixedI64,
    pub timestamp_calibration_time: u32,
    pub state_and_event_indicators: u32,
    pub payload_format: PayloadFormat,
}
