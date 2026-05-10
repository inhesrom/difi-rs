use std::hint::black_box;

use criterion::{Criterion, criterion_group, criterion_main};

fn bytes(words: &[u32]) -> Vec<u8> {
    let mut out = Vec::with_capacity(words.len() * 4);
    for word in words {
        out.extend_from_slice(&word.to_be_bytes());
    }
    out
}

fn header(packet_type: u8, type_specific: u8, tsi: u8, tsf: u8, sequence: u8, words: u16) -> u32 {
    ((packet_type as u32) << 28)
        | (1 << 27)
        | (((type_specific & 0x7) as u32) << 24)
        | (((tsi & 0x3) as u32) << 22)
        | (((tsf & 0x3) as u32) << 20)
        | (((sequence & 0xF) as u32) << 16)
        | words as u32
}

fn class_id(info: u16, packet: u16) -> [u32; 2] {
    [0x006A_621E, ((info as u32) << 16) | packet as u32]
}

fn fixed_hz(hz: u64) -> [u32; 2] {
    let raw = hz << 20;
    [(raw >> 32) as u32, raw as u32]
}

fn signal_data_packet() -> Vec<u8> {
    let [cid0, cid1] = class_id(0x0000, 0x0000);
    bytes(&[
        header(0x1, 0, 0x1, 0x2, 0, 9),
        0x0102_0304,
        cid0,
        cid1,
        0,
        0,
        0,
        0x0102_0304,
        0x0506_0708,
    ])
}

fn signal_context_packet() -> Vec<u8> {
    let [cid0, cid1] = class_id(0x0000, 0x0001);
    let bandwidth = fixed_hz(20_000_000);
    let sample_rate = fixed_hz(40_000_000);
    bytes(&[
        header(0x4, 1, 0x1, 0x2, 0, 27),
        0x0102_0304,
        cid0,
        cid1,
        0,
        0,
        0,
        0x7BB9_8000,
        100,
        bandwidth[0],
        bandwidth[1],
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        sample_rate[0],
        sample_rate[1],
        0,
        0,
        0,
        0,
        0xA000_03CF,
        0,
    ])
}

fn sink_capabilities_response_long_packet() -> Vec<u8> {
    let [cid0, cid1] = class_id(0x0101, 0x0008);
    bytes(&[
        header(0x7, 4, 0x1, 0x2, 0, 14),
        0,
        cid0,
        cid1,
        0,
        0,
        0,
        0xA110_0400,
        1,
        0,
        0,
        0x7BB9_8002,
        0x0000_0002,
        0xDEAD_BEEF,
    ])
}

fn bench_parser(c: &mut Criterion) {
    let data = signal_data_packet();
    c.bench_function("parse signal data exact", |b| {
        b.iter(|| difi::parse_packet_exact(black_box(&data)).unwrap())
    });

    let context = signal_context_packet();
    c.bench_function("parse signal context exact", |b| {
        b.iter(|| difi::parse_packet_exact(black_box(&context)).unwrap())
    });

    let response = sink_capabilities_response_long_packet();
    c.bench_function("parse sink capabilities response long exact", |b| {
        b.iter(|| difi::parse_packet_exact(black_box(&response)).unwrap())
    });
}

criterion_group!(benches, bench_parser);
criterion_main!(benches);
