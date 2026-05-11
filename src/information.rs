use crate::error::{ParseError, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[repr(u16)]
pub enum InformationClassCode {
    BasicDataPlane = 0x0000,
    VersionFlow = 0x0001,
    DataPlaneUpstreamFlowControlSampleCount = 0x0002,
    DataPlaneUpstreamFlowControlRealTime = 0x0003,
    BasicDataPlaneSampleCount = 0x0004,
    DataPlaneDownstreamFlowControlSampleCount = 0x0005,
    DataPlaneDownstreamFlowControlRealTime = 0x0006,
    BasicDataPlaneWithLinkEstablishment = 0x0100,
    StandaloneLinkEstablishment = 0x0101,
    DataPlaneUpstreamFlowControlSampleCountWithLinkEstablishment = 0x0102,
    DataPlaneUpstreamFlowControlRealTimeWithLinkEstablishment = 0x0103,
    BasicDataPlaneSampleCountWithLinkEstablishment = 0x0104,
    DataPlaneDownstreamFlowControlSampleCountWithLinkEstablishment = 0x0105,
    DataPlaneDownstreamFlowControlRealTimeWithLinkEstablishment = 0x0106,
}

impl TryFrom<u16> for InformationClassCode {
    type Error = ParseError;

    fn try_from(value: u16) -> Result<Self> {
        match value {
            0x0000 => Ok(Self::BasicDataPlane),
            0x0001 => Ok(Self::VersionFlow),
            0x0002 => Ok(Self::DataPlaneUpstreamFlowControlSampleCount),
            0x0003 => Ok(Self::DataPlaneUpstreamFlowControlRealTime),
            0x0004 => Ok(Self::BasicDataPlaneSampleCount),
            0x0005 => Ok(Self::DataPlaneDownstreamFlowControlSampleCount),
            0x0006 => Ok(Self::DataPlaneDownstreamFlowControlRealTime),
            0x0100 => Ok(Self::BasicDataPlaneWithLinkEstablishment),
            0x0101 => Ok(Self::StandaloneLinkEstablishment),
            0x0102 => Ok(Self::DataPlaneUpstreamFlowControlSampleCountWithLinkEstablishment),
            0x0103 => Ok(Self::DataPlaneUpstreamFlowControlRealTimeWithLinkEstablishment),
            0x0104 => Ok(Self::BasicDataPlaneSampleCountWithLinkEstablishment),
            0x0105 => Ok(Self::DataPlaneDownstreamFlowControlSampleCountWithLinkEstablishment),
            0x0106 => Ok(Self::DataPlaneDownstreamFlowControlRealTimeWithLinkEstablishment),
            value => Err(ParseError::UnknownInformationClass { value }),
        }
    }
}

impl InformationClassCode {
    pub const fn raw(self) -> u16 {
        self as u16
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[repr(u16)]
pub enum PacketClassCode {
    StandardFlowSignalData = 0x0000,
    StandardFlowSignalContext = 0x0001,
    SampleCountSignalData = 0x0002,
    SampleCountSignalContext = 0x0003,
    VersionFlowSignalContext = 0x0004,
    SampleCountTimingFlowControl = 0x0005,
    RealTimeTimingFlowControl = 0x0006,
    SinkCapabilitiesQuery = 0x0007,
    SinkCapabilitiesResponse = 0x0008,
    StatusReport = 0x0009,
}

impl TryFrom<u16> for PacketClassCode {
    type Error = ParseError;

    fn try_from(value: u16) -> Result<Self> {
        match value {
            0x0000 => Ok(Self::StandardFlowSignalData),
            0x0001 => Ok(Self::StandardFlowSignalContext),
            0x0002 => Ok(Self::SampleCountSignalData),
            0x0003 => Ok(Self::SampleCountSignalContext),
            0x0004 => Ok(Self::VersionFlowSignalContext),
            0x0005 => Ok(Self::SampleCountTimingFlowControl),
            0x0006 => Ok(Self::RealTimeTimingFlowControl),
            0x0007 => Ok(Self::SinkCapabilitiesQuery),
            0x0008 => Ok(Self::SinkCapabilitiesResponse),
            0x0009 => Ok(Self::StatusReport),
            value => Err(ParseError::UnknownPacketClass { value }),
        }
    }
}

impl PacketClassCode {
    pub const fn raw(self) -> u16 {
        self as u16
    }
}
