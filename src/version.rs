#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[repr(u8)]
pub enum DifiVersionCode {
    Version1 = 0,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct VersionContextPacket {
    pub prologue: crate::Prologue,
    pub cif0: u32,
    pub context_changed: bool,
    pub cif1: u32,
    pub vita49_spec_version: u32,
    pub year: u8,
    pub day: u16,
    pub revision: u8,
    pub device_type: u8,
    pub icd_version: DifiVersionCode,
}
