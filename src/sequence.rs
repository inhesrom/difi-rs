use std::collections::HashMap;

use crate::{Packet, PacketClassCode, PacketType};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SequenceKey {
    pub packet_type: PacketType,
    pub packet_class: PacketClassCode,
    pub stream_id: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SequenceStatus {
    First,
    InOrder,
    Duplicate,
    Gap { expected: u8, actual: u8 },
}

#[derive(Debug, Default, Clone)]
pub struct SequenceTracker {
    last_seen: HashMap<SequenceKey, u8>,
}

impl SequenceTracker {
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates a sequence tracker with capacity for observed stream keys.
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            last_seen: HashMap::with_capacity(capacity),
        }
    }

    pub fn observe(&mut self, packet: &Packet<'_>) -> SequenceStatus {
        let prologue = packet.prologue();
        self.observe_fields(
            prologue.header.packet_type,
            prologue.class_id.packet_class,
            prologue.stream_id,
            prologue.header.sequence,
        )
    }

    pub fn observe_fields(
        &mut self,
        packet_type: PacketType,
        packet_class: PacketClassCode,
        stream_id: u32,
        sequence: u8,
    ) -> SequenceStatus {
        let sequence = sequence & 0x0F;
        let key = SequenceKey {
            packet_type,
            packet_class,
            stream_id,
        };

        match self.last_seen.insert(key, sequence) {
            None => SequenceStatus::First,
            Some(previous) if previous == sequence => SequenceStatus::Duplicate,
            Some(previous) => {
                let expected = (previous + 1) & 0x0F;
                if expected == sequence {
                    SequenceStatus::InOrder
                } else {
                    SequenceStatus::Gap {
                        expected,
                        actual: sequence,
                    }
                }
            }
        }
    }

    pub fn reset(&mut self) {
        self.last_seen.clear();
    }
}
