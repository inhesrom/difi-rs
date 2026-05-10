#![allow(dead_code)]

pub const CID_WORD: u32 = 0x006A_621E;
pub const CAM_CONTROL_EXECUTE: u32 = 0xA100_0000;
pub const CAM_EXTENSION_CONTROL_VALIDATE: u32 = 0xA110_0000;
pub const CAM_EXTENSION_ACK_VALIDATE: u32 = 0xA110_0400;
pub const CIF_COMMAND_LONG: u32 = 0x7BB9_8002;
pub const CIF_COMMAND_SHORT: u32 = 0x8000_0000;
pub const CIF_CONTROL_FLOW_0: u32 = 0x4030_0002;
pub const CIF_CONTROL_FLOW_1: u32 = 0x0000_0002;

pub fn bytes(words: &[u32]) -> Vec<u8> {
    let mut out = Vec::with_capacity(words.len() * 4);
    for word in words {
        out.extend_from_slice(&word.to_be_bytes());
    }
    out
}

pub fn header(
    packet_type: u8,
    type_specific: u8,
    tsi: u8,
    tsf: u8,
    sequence: u8,
    words: u16,
) -> u32 {
    ((packet_type as u32) << 28)
        | (1 << 27)
        | (((type_specific & 0x7) as u32) << 24)
        | (((tsi & 0x3) as u32) << 22)
        | (((tsf & 0x3) as u32) << 20)
        | (((sequence & 0xF) as u32) << 16)
        | words as u32
}

pub fn class_id(info: u16, packet: u16, pad_bits: u8) -> [u32; 2] {
    [
        ((pad_bits as u32) << 27) | CID_WORD,
        ((info as u32) << 16) | packet as u32,
    ]
}

pub fn payload_format(bit_depth: u8) -> [u32; 2] {
    let minus_one = (bit_depth - 1) as u32;
    [0xA000_0000 | (minus_one << 6) | minus_one, 0]
}

pub fn fixed_hz(hz: u64) -> [u32; 2] {
    let raw = hz << 20;
    [(raw >> 32) as u32, raw as u32]
}

pub fn signed_words(value: i64) -> [u32; 2] {
    let raw = value as u64;
    [(raw >> 32) as u32, raw as u32]
}
