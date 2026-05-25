//! UDP Signal Data sender for `examples/udp_stream.rs`.
//!
//! Run the receiver in one terminal:
//!
//! ```sh
//! cargo run --example udp_stream
//! ```
//!
//! Then run this sender in another terminal. It sends 9000-byte UDP datagrams by default:
//!
//! ```sh
//! cargo run --features write --example udp_sender
//! ```
//!
//! Pass an optional destination and send interval in milliseconds:
//!
//! ```sh
//! cargo run --features write --example udp_sender -- 127.0.0.1:4991 250
//! ```

use std::net::{SocketAddr, UdpSocket};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use difi::writer::{SignalDataWriteSpec, write_iq_data_i16, write_packet};
use difi::{
    ClassId, ComplexI16, DIFI_CID, FixedI64, FixedU64, InformationClassCode, Packet,
    PacketClassCode, PacketHeader, PacketType, PayloadFormat, PayloadSampleFormat, Prologue,
    SignalContextPacket, TimestampMode, Tsf, Tsi,
};

const DEFAULT_DESTINATION: &str = "127.0.0.1:4991";
const DEFAULT_INTERVAL: Duration = Duration::from_millis(1_000);
const UDP_DATAGRAM_BYTES: usize = 9000;
const SIGNAL_DATA_PROLOGUE_BYTES: usize = 7 * 4;
const COMPLEX_I16_SAMPLE_BYTES: usize = 4;
const SIGNAL_CONTEXT_WORDS: u16 = 27;
const STREAM_ID: u32 = 0x0102_0304;
const SAMPLES_PER_PACKET: usize =
    (UDP_DATAGRAM_BYTES - SIGNAL_DATA_PROLOGUE_BYTES) / COMPLEX_I16_SAMPLE_BYTES;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let destination = destination_arg()?;
    let interval = interval_arg()?;

    let socket = UdpSocket::bind("0.0.0.0:0")?;
    socket.connect(destination)?;

    let mut data_sequence = 0_u8;
    let mut context_sequence = 0_u8;
    let mut packet_count = 0_u64;
    let mut buffer = [0_u8; UDP_DATAGRAM_BYTES];

    send_signal_context(&socket, destination, context_sequence, &mut buffer)?;
    context_sequence = next_sequence(context_sequence);

    loop {
        let spec = signal_data_spec(data_sequence)?;
        let samples = samples_for_packet(packet_count);
        let len = write_iq_data_i16(spec, &samples, &mut buffer)?;
        debug_assert_eq!(len, UDP_DATAGRAM_BYTES);

        socket.send(&buffer[..len])?;
        println!(
            "sent signal data stream=0x{STREAM_ID:08X} sequence={data_sequence} samples={} bytes={len} to {destination}",
            samples.len()
        );

        data_sequence = next_sequence(data_sequence);
        packet_count = packet_count.wrapping_add(1);
        if packet_count.is_multiple_of(5) {
            send_signal_context(&socket, destination, context_sequence, &mut buffer)?;
            context_sequence = next_sequence(context_sequence);
        }

        thread::sleep(interval);
    }
}

fn destination_arg() -> Result<SocketAddr, Box<dyn std::error::Error>> {
    match std::env::args().nth(1) {
        Some(value) => Ok(value.parse()?),
        None => Ok(DEFAULT_DESTINATION.parse()?),
    }
}

fn interval_arg() -> Result<Duration, Box<dyn std::error::Error>> {
    match std::env::args().nth(2) {
        Some(value) => Ok(Duration::from_millis(value.parse()?)),
        None => Ok(DEFAULT_INTERVAL),
    }
}

fn signal_data_spec(sequence: u8) -> Result<SignalDataWriteSpec, Box<dyn std::error::Error>> {
    let (integer_seconds_timestamp, fractional_seconds_timestamp) = current_timestamp()?;

    Ok(SignalDataWriteSpec {
        stream_id: STREAM_ID,
        information_class: InformationClassCode::BasicDataPlane,
        packet_class: PacketClassCode::StandardFlowSignalData,
        tsi: Tsi::Utc,
        tsf: Tsf::RealTimePicoseconds,
        sequence,
        integer_seconds_timestamp,
        fractional_seconds_timestamp,
    })
}

fn send_signal_context(
    socket: &UdpSocket,
    destination: SocketAddr,
    sequence: u8,
    buffer: &mut [u8],
) -> Result<(), Box<dyn std::error::Error>> {
    let packet = signal_context_packet(sequence)?;
    let len = write_packet(&Packet::SignalContext(packet), buffer)?;

    socket.send(&buffer[..len])?;
    println!(
        "sent signal context stream=0x{STREAM_ID:08X} sequence={sequence} bytes={len} to {destination}"
    );

    Ok(())
}

fn signal_context_packet(sequence: u8) -> Result<SignalContextPacket, Box<dyn std::error::Error>> {
    let (integer_seconds_timestamp, fractional_seconds_timestamp) = current_timestamp()?;
    let tsi = Tsi::Utc;
    let tsf = Tsf::RealTimePicoseconds;
    let type_specific_bits = 1;

    Ok(SignalContextPacket {
        prologue: Prologue {
            header: PacketHeader {
                raw: header_word(
                    PacketType::ContextWithStreamId,
                    type_specific_bits,
                    tsi,
                    tsf,
                    sequence,
                    SIGNAL_CONTEXT_WORDS,
                ),
                packet_type: PacketType::ContextWithStreamId,
                class_id_indicator: true,
                type_specific_bits,
                tsm: Some(TimestampMode::Coarse),
                tsi,
                tsf,
                sequence,
                packet_size_words: SIGNAL_CONTEXT_WORDS,
            },
            stream_id: STREAM_ID,
            class_id: ClassId {
                pad_bit_count: 0,
                oui: DIFI_CID,
                information_class: InformationClassCode::BasicDataPlane,
                packet_class: PacketClassCode::StandardFlowSignalContext,
            },
            integer_seconds_timestamp,
            fractional_seconds_timestamp,
        },
        cif0: 0xFBB9_8000,
        context_changed: true,
        reference_point: 0,
        bandwidth: FixedU64(20_000_000_u64 << 20),
        if_reference_frequency: FixedI64(0),
        rf_reference_frequency: FixedI64(1_500_000_000_i64 << 20),
        if_band_offset: FixedI64(0),
        scaling_level: 0,
        reference_level: 0,
        gain2: 0,
        gain1: 0,
        sample_rate: FixedU64(40_000_000_u64 << 20),
        timestamp_adjustment: FixedI64(0),
        timestamp_calibration_time: 0,
        state_and_event_indicators: 0,
        payload_format: PayloadFormat {
            raw_word0: 0xA000_0000 | (15 << 6) | 15,
            raw_word1: 0,
            sample_format: PayloadSampleFormat::ComplexSignedCartesian,
            data_item_size_bits: 16,
            item_packing_field_size_bits: 16,
        },
    })
}

fn current_timestamp() -> Result<(u32, u64), Box<dyn std::error::Error>> {
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?;
    let integer_seconds_timestamp = u32::try_from(now.as_secs())?;
    let fractional_seconds_timestamp = u64::from(now.subsec_nanos()) * 1_000;

    Ok((integer_seconds_timestamp, fractional_seconds_timestamp))
}

fn header_word(
    packet_type: PacketType,
    type_specific_bits: u8,
    tsi: Tsi,
    tsf: Tsf,
    sequence: u8,
    packet_size_words: u16,
) -> u32 {
    ((packet_type as u32) << 28)
        | (1 << 27)
        | ((type_specific_bits as u32) << 24)
        | ((tsi as u32) << 22)
        | ((tsf as u32) << 20)
        | ((sequence as u32) << 16)
        | packet_size_words as u32
}

fn next_sequence(sequence: u8) -> u8 {
    (sequence + 1) & 0x0F
}

fn samples_for_packet(packet_count: u64) -> [ComplexI16; SAMPLES_PER_PACKET] {
    std::array::from_fn(|index| {
        let ramp = ((packet_count.wrapping_add(index as u64) % 64) as i32 - 32) * 512;

        ComplexI16 {
            i: ramp as i16,
            q: (-ramp) as i16,
        }
    })
}
