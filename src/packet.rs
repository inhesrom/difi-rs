use crate::{ClassId, PacketHeader};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Prologue {
    pub header: PacketHeader,
    pub stream_id: u32,
    pub class_id: ClassId,
    pub integer_seconds_timestamp: u32,
    pub fractional_seconds_timestamp: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Packet<'a> {
    SignalData(crate::data::SignalDataPacket<'a>),
    SignalContext(crate::SignalContextPacket),
    VersionContext(crate::VersionContextPacket),
    TimingFlowControl(crate::TimingFlowControlPacket),
    SinkCapabilitiesQuery(crate::SinkCapabilitiesQueryPacket),
    SinkCapabilitiesResponse(crate::SinkCapabilitiesResponsePacket<'a>),
    StatusReport(crate::StatusReportPacket),
}

impl Packet<'_> {
    pub const fn prologue(&self) -> &Prologue {
        match self {
            Self::SignalData(packet) => &packet.prologue,
            Self::SignalContext(packet) => &packet.prologue,
            Self::VersionContext(packet) => &packet.prologue,
            Self::TimingFlowControl(packet) => &packet.prologue,
            Self::SinkCapabilitiesQuery(packet) => &packet.prologue,
            Self::SinkCapabilitiesResponse(packet) => &packet.prologue,
            Self::StatusReport(packet) => &packet.prologue,
        }
    }
}
