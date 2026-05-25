use std::collections::HashMap;
use std::net::{SocketAddr, UdpSocket};

use difi::{
    FixedU64, Packet, PacketStreamParser, PayloadFormat, SequenceStatus, SignalContextPacket,
    SignalDataPacket, iq_i16_samples,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let socket = UdpSocket::bind("0.0.0.0:4991")?;
    let mut parser = PacketStreamParser::new();
    let mut payload_formats: HashMap<(SocketAddr, u32), PayloadFormat> = HashMap::new();
    let mut buffer = [0_u8; 9000];

    loop {
        let (len, source) = socket.recv_from(&mut buffer)?;
        let parsed = parser.parse_datagram(&buffer[..len])?;
        let status = parsed.sequence_status;

        match parsed.packet {
            Packet::SignalContext(packet) => {
                payload_formats.insert((source, packet.prologue.stream_id), packet.payload_format);
                print_context_packet(source, &packet, status);
            }
            Packet::SignalData(packet) => {
                let stream_id = packet.prologue.stream_id;
                let (sample_label, sample_count) =
                    match payload_formats.get(&(source, stream_id)).copied() {
                        Some(payload_format) => (
                            "samples",
                            sample_count_from_context(
                                packet.payload.len(),
                                packet.prologue.class_id.pad_bit_count,
                                payload_format,
                            ),
                        ),
                        None => ("samples_i16_assumed", iq_i16_samples(packet.payload)?.len()),
                    };

                print_data_packet(source, len, &packet, status, sample_label, sample_count);
            }
            _ => {}
        }
    }
}

fn print_context_packet(source: SocketAddr, packet: &SignalContextPacket, status: SequenceStatus) {
    println!(
        "context source={source} stream=0x{:08X} sequence={} status={}",
        packet.prologue.stream_id,
        packet.prologue.header.sequence,
        sequence_status(status)
    );
    println!(
        "format sample_format={:?} data_item_bits={} packing_bits={}",
        packet.payload_format.sample_format,
        packet.payload_format.data_item_size_bits,
        packet.payload_format.item_packing_field_size_bits
    );
    println!(
        "rates sample_rate_hz={} bandwidth_hz={}",
        fixed_hz(packet.sample_rate),
        fixed_hz(packet.bandwidth)
    );
    println!(
        "time tsi={:?} tsf={:?} integer_seconds_timestamp={} fractional_seconds_timestamp={}",
        packet.prologue.header.tsi,
        packet.prologue.header.tsf,
        packet.prologue.integer_seconds_timestamp,
        packet.prologue.fractional_seconds_timestamp
    );
    println!();
}

fn print_data_packet(
    source: SocketAddr,
    datagram_bytes: usize,
    packet: &SignalDataPacket<'_>,
    status: SequenceStatus,
    sample_label: &str,
    sample_count: usize,
) {
    println!(
        "data source={source} stream=0x{:08X} sequence={} status={}",
        packet.prologue.stream_id,
        packet.prologue.header.sequence,
        sequence_status(status)
    );
    println!(
        "sizes datagram_bytes={datagram_bytes} payload_bytes={} {sample_label}={sample_count}",
        packet.payload.len()
    );
    println!(
        "time tsi={:?} tsf={:?} integer_seconds_timestamp={} fractional_seconds_timestamp={}",
        packet.prologue.header.tsi,
        packet.prologue.header.tsf,
        packet.prologue.integer_seconds_timestamp,
        packet.prologue.fractional_seconds_timestamp
    );
    println!();
}

fn sample_count_from_context(
    payload_bytes: usize,
    pad_bit_count: u8,
    payload_format: PayloadFormat,
) -> usize {
    let payload_bits_without_padding = payload_bytes
        .saturating_mul(8)
        .saturating_sub(usize::from(pad_bit_count));
    let bits_per_complex_sample = usize::from(payload_format.item_packing_field_size_bits) * 2;

    payload_bits_without_padding / bits_per_complex_sample
}

fn fixed_hz(value: FixedU64) -> u64 {
    value.raw() >> 20
}

fn sequence_status(status: SequenceStatus) -> String {
    match status {
        SequenceStatus::First => "first".to_owned(),
        SequenceStatus::InOrder => "in_order".to_owned(),
        SequenceStatus::Duplicate => "duplicate".to_owned(),
        SequenceStatus::Gap { expected, actual } => {
            format!("gap(expected={expected},actual={actual})")
        }
    }
}
