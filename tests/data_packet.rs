use difi::{
    InformationClassCode, Packet, PacketClassCode, PacketType, Tsf, Tsi, parse_packet_exact,
};

fn bytes(words: &[u32]) -> Vec<u8> {
    let mut out = Vec::with_capacity(words.len() * 4);
    for word in words {
        out.extend_from_slice(&word.to_be_bytes());
    }
    out
}

#[test]
fn exact_parse_returns_borrowed_standard_signal_data_payload() {
    let input = bytes(&[
        0x1860_0009, // data, class id, UTC, real-time TSF, seq 0, 9 words
        0x0102_0304, // stream id
        0x006A_621E, // zero pad/reserved + DIFI CID
        0x0000_0000, // information class 0, packet class 0
        0x0000_0007, // integer timestamp
        0x0000_0000,
        0x0000_002A, // fractional timestamp
        0x0102_0304,
        0x0506_0708,
    ]);

    let Packet::SignalData(packet) = parse_packet_exact(&input).expect("valid data packet") else {
        panic!("expected signal data packet");
    };

    assert_eq!(
        packet.prologue.header.packet_type,
        PacketType::SignalDataWithStreamId
    );
    assert_eq!(packet.prologue.header.tsi, Tsi::Utc);
    assert_eq!(packet.prologue.header.tsf, Tsf::RealTimePicoseconds);
    assert_eq!(packet.prologue.header.sequence, 0);
    assert_eq!(packet.prologue.stream_id, 0x0102_0304);
    assert_eq!(
        packet.prologue.class_id.information_class,
        InformationClassCode::BasicDataPlane
    );
    assert_eq!(
        packet.prologue.class_id.packet_class,
        PacketClassCode::StandardFlowSignalData
    );
    assert_eq!(packet.prologue.integer_seconds_timestamp, 7);
    assert_eq!(packet.prologue.fractional_seconds_timestamp, 42);
    assert_eq!(packet.payload, &input[28..]);

    let payload_start = packet.payload.as_ptr() as usize;
    let input_start = input.as_ptr() as usize;
    assert!(payload_start >= input_start);
    assert!(payload_start + packet.payload.len() <= input_start + input.len());
}
