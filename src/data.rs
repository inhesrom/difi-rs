#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SignalDataPacket<'a> {
    pub prologue: crate::Prologue,
    pub payload: &'a [u8],
}
