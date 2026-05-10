use crate::context::{FixedI64, FixedU64};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum CapabilityForm {
    Long,
    Short,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct CommandCommon {
    pub cam: u32,
    pub message_id: u32,
    pub controllee_id: u32,
    pub controller_id: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct BufferStatus {
    pub raw: u32,
    pub buffer_level: u16,
    pub overflow: bool,
    pub nearly_full: bool,
    pub nearly_empty: bool,
    pub underflow: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct TimingFlowControlPacket {
    pub prologue: crate::Prologue,
    pub common: CommandCommon,
    pub cif0: u32,
    pub cif1: u32,
    pub reference_point: u32,
    pub sample_rate: FixedU64,
    pub timestamp_adjustment: FixedI64,
    pub buffer_size_bytes: u64,
    pub buffer_status: BufferStatus,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct SinkCapabilitiesQueryPacket {
    pub prologue: crate::Prologue,
    pub common: CommandCommon,
    pub form: CapabilityForm,
    pub cif0: u32,
    pub cif1: Option<u32>,
    pub sink_time_calibration_integer: Option<u32>,
    pub sink_time_calibration_fractional: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SinkCapabilitiesResponsePacket<'a> {
    pub prologue: crate::Prologue,
    pub common: CommandCommon,
    pub form: CapabilityForm,
    pub cif0: u32,
    pub cif1: Option<u32>,
    pub control_packet_integer_timestamp: Option<u32>,
    pub control_packet_fractional_timestamp: Option<u64>,
    pub sink_reception_integer_timestamp: Option<u32>,
    pub sink_reception_fractional_timestamp: Option<u64>,
    pub capability_table: &'a [u8],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ReferenceLevelLimit {
    pub raw_min_max: u32,
    pub raw_resolution_reserved: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct StatusReportPacket {
    pub prologue: crate::Prologue,
    pub common: CommandCommon,
    pub cif0: u32,
    pub cif1: u32,
    pub packet_errors: u32,
    pub sink_errors_warnings: u32,
    pub reference_level_limit: Option<ReferenceLevelLimit>,
    pub sample_rate_limit: Option<FixedU64>,
    pub bandwidth_limit: Option<FixedU64>,
}
