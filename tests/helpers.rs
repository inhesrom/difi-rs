mod common;

use difi::{
    ComplexI8, ComplexI16, PacketClassCode, PacketType, SampleError, SequenceStatus,
    SequenceTracker, iq_i8_samples, iq_i16_samples, parse_packet_exact,
};

use common::{bytes, class_id, header};

#[test]
fn iq_i8_helper_decodes_complex_signed_cartesian_pairs() {
    let samples: Vec<_> = iq_i8_samples(&[0x01, 0xFF, 0x80, 0x7F])
        .expect("aligned 8-bit IQ")
        .collect();

    assert_eq!(
        samples,
        vec![ComplexI8 { i: 1, q: -1 }, ComplexI8 { i: -128, q: 127 }]
    );
}

#[test]
fn iq_i16_helper_decodes_big_endian_complex_signed_cartesian_pairs() {
    let samples: Vec<_> = iq_i16_samples(&[0x00, 0x01, 0xFF, 0xFE, 0x80, 0x00, 0x7F, 0xFF])
        .expect("aligned 16-bit IQ")
        .collect();

    assert_eq!(
        samples,
        vec![
            ComplexI16 { i: 1, q: -2 },
            ComplexI16 {
                i: -32768,
                q: 32767
            }
        ]
    );
}

#[test]
fn iq_helpers_reject_misaligned_payloads() {
    assert_eq!(
        iq_i8_samples(&[1]).unwrap_err(),
        SampleError::MisalignedPayload {
            len: 1,
            sample_bytes: 2
        }
    );
    assert_eq!(
        iq_i16_samples(&[1, 2]).unwrap_err(),
        SampleError::MisalignedPayload {
            len: 2,
            sample_bytes: 4
        }
    );
}

#[test]
fn sequence_tracker_tracks_stream_type_class_and_modulo_wraparound() {
    let mut tracker = SequenceTracker::new();

    assert_eq!(
        tracker.observe_fields(
            PacketType::SignalDataWithStreamId,
            PacketClassCode::StandardFlowSignalData,
            10,
            14
        ),
        SequenceStatus::First
    );
    assert_eq!(
        tracker.observe_fields(
            PacketType::SignalDataWithStreamId,
            PacketClassCode::StandardFlowSignalData,
            10,
            15
        ),
        SequenceStatus::InOrder
    );
    assert_eq!(
        tracker.observe_fields(
            PacketType::SignalDataWithStreamId,
            PacketClassCode::StandardFlowSignalData,
            10,
            0
        ),
        SequenceStatus::InOrder
    );
    assert_eq!(
        tracker.observe_fields(
            PacketType::SignalDataWithStreamId,
            PacketClassCode::StandardFlowSignalData,
            10,
            0
        ),
        SequenceStatus::Duplicate
    );
    assert_eq!(
        tracker.observe_fields(
            PacketType::SignalDataWithStreamId,
            PacketClassCode::StandardFlowSignalData,
            10,
            2
        ),
        SequenceStatus::Gap {
            expected: 1,
            actual: 2
        }
    );
}

fn signal_data_packet(sequence: u8) -> Vec<u8> {
    let [cid0, cid1] = class_id(0x0000, 0x0000, 0);
    bytes(&[
        header(0x1, 0, 0x1, 0x2, sequence, 8),
        0x0102_0304,
        cid0,
        cid1,
        7,
        0,
        42,
        0xABCD_EF01,
    ])
}

#[test]
fn sequence_tracker_observes_parsed_packets_and_can_reset() {
    let first_input = signal_data_packet(3);
    let second_input = signal_data_packet(4);
    let first = parse_packet_exact(&first_input).expect("valid first packet");
    let second = parse_packet_exact(&second_input).expect("valid second packet");
    let mut tracker = SequenceTracker::new();

    assert_eq!(tracker.observe(&first), SequenceStatus::First);
    assert_eq!(tracker.observe(&second), SequenceStatus::InOrder);

    tracker.reset();
    assert_eq!(tracker.observe(&second), SequenceStatus::First);
}
