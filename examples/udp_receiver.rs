use std::net::UdpSocket;

use difi::{Packet, PacketStreamParser, SequenceStatus};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let socket = UdpSocket::bind("0.0.0.0:4991")?;
    let mut parser = PacketStreamParser::new();
    let mut buffer = [0_u8; 9000];

    loop {
        let (len, source) = socket.recv_from(&mut buffer)?;
        let parsed = parser.parse_datagram(&buffer[..len])?;

        match parsed.sequence_status {
            SequenceStatus::First | SequenceStatus::InOrder => {}
            SequenceStatus::Duplicate => {
                eprintln!("duplicate DIFI sequence from {source}");
            }
            SequenceStatus::Gap { expected, actual } => {
                eprintln!("DIFI sequence gap from {source}: expected {expected}, got {actual}");
            }
        }

        if let Packet::SignalData(packet) = parsed.packet {
            println!(
                "signal data stream=0x{:08X} payload_bytes={}",
                packet.prologue.stream_id,
                packet.payload.len()
            );
        }
    }
}
