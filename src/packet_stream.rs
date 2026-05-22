use crate::{
    Packet, ParseOptions, Result, SequenceStatus, SequenceTracker, parse_packet_exact_with_options,
};

/// A parsed UDP datagram payload and its sequence-tracking result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ParsedDatagram<'a> {
    /// The DIFI packet parsed from the datagram payload.
    pub packet: Packet<'a>,
    /// Sequence status reported after observing this packet.
    pub sequence_status: SequenceStatus,
}

/// Stateful parser for one DIFI packet per UDP datagram payload.
///
/// This type does not own sockets or receive buffers. Callers pass one UDP datagram payload at a
/// time, and any borrowed payload slices in the returned packet remain tied to that input buffer.
#[derive(Debug, Clone)]
pub struct PacketStreamParser {
    options: ParseOptions,
    sequences: SequenceTracker,
}

impl PacketStreamParser {
    /// Creates a stream parser using the default strict DIFI 1.3.0 profile.
    pub fn new() -> Self {
        Self::with_options(ParseOptions::default())
    }

    /// Creates a stream parser using an explicit standard profile.
    pub fn with_options(options: ParseOptions) -> Self {
        Self {
            options,
            sequences: SequenceTracker::new(),
        }
    }

    /// Creates a stream parser with pre-sized sequence-tracker state.
    ///
    /// Use this when the expected number of independent packet type/class/stream ID combinations
    /// is known and first-observation allocations should be avoided.
    pub fn with_options_and_sequence_capacity(
        options: ParseOptions,
        sequence_capacity: usize,
    ) -> Self {
        Self {
            options,
            sequences: SequenceTracker::with_capacity(sequence_capacity),
        }
    }

    /// Parses exactly one DIFI packet from a UDP datagram payload and reports sequence status.
    ///
    /// This uses [`parse_packet_exact_with_options`], so trailing bytes and concatenated DIFI
    /// packets are rejected.
    pub fn parse_datagram<'a>(&mut self, datagram: &'a [u8]) -> Result<ParsedDatagram<'a>> {
        let packet = parse_packet_exact_with_options(datagram, self.options)?;
        let sequence_status = self.sequences.observe(&packet);
        Ok(ParsedDatagram {
            packet,
            sequence_status,
        })
    }

    /// Clears all observed sequence state.
    pub fn reset_sequences(&mut self) {
        self.sequences.reset();
    }
}

impl Default for PacketStreamParser {
    fn default() -> Self {
        Self::new()
    }
}
