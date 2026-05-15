#![cfg(feature = "pcap-tests")]

use std::fs;
use std::path::{Path, PathBuf};

use difi::{
    CompatibilityMode, DIFI_CID, DifiStandardVersion, ParseOptions, parse_packet_exact_with_options,
};

const MAX_FAILURES: usize = 16;
const MIN_DIFI_PACKET_BYTES: usize = 28;

#[test]
fn certification_example_pcaps_contain_parseable_difi_udp_payloads() {
    let Some(root) = certification_dir() else {
        eprintln!("skipping DIFI certification pcap tests: DIFI_CERTIFICATION_DIR is not set");
        return;
    };

    let captures = certification_captures(&root).unwrap_or_else(|err| panic!("{err}"));

    let mut udp_payloads_total = 0usize;
    let mut parsed_payloads = 0usize;
    let mut failed_payloads = 0usize;
    let mut failures = Vec::new();

    for capture in &captures {
        let input = fs::read(capture).unwrap_or_else(|err| {
            panic!("read {}: {err}", capture.display());
        });
        let udp_payloads = capture_udp_payloads(&input).unwrap_or_else(|err| {
            panic!("read UDP payloads from {}: {err}", capture.display());
        });

        assert!(
            !udp_payloads.is_empty(),
            "{} contains no UDP payloads",
            capture.display()
        );
        udp_payloads_total += udp_payloads.len();

        for (payload_index, payload) in udp_payloads.into_iter().enumerate() {
            if let Err(err) = validate_strict_difi_payload(payload) {
                failed_payloads += 1;
                record_failure(
                    &mut failures,
                    payload_failure(capture, payload_index, payload, &err),
                );
                continue;
            }

            match parse_with_supported_profiles(payload) {
                Ok(()) => parsed_payloads += 1,
                Err(err) => {
                    failed_payloads += 1;
                    record_failure(
                        &mut failures,
                        payload_failure(
                            capture,
                            payload_index,
                            payload,
                            &format!("parse failed for supported profiles: {err}"),
                        ),
                    );
                }
            }
        }
    }

    assert!(udp_payloads_total > 0, "no UDP payloads found");
    assert_eq!(
        failed_payloads,
        0,
        "{failed_payloads} UDP payload(s) failed strict DIFI certification checks; first {}:\n{}",
        failures.len(),
        failures.join("\n")
    );
    assert_eq!(parsed_payloads, udp_payloads_total);
    eprintln!(
        "parsed {parsed_payloads} DIFI UDP payloads from {} certification example captures",
        captures.len()
    );
}

fn certification_dir() -> Option<PathBuf> {
    let dir = std::env::var_os("DIFI_CERTIFICATION_DIR")?;
    let path = PathBuf::from(dir);
    path.is_dir().then_some(path)
}

fn certification_captures(root: &Path) -> Result<Vec<PathBuf>, String> {
    let example_pcaps = root.join("example_pcaps");
    if !example_pcaps.is_dir() {
        return Err(format!(
            "missing certification example pcap directory: {}",
            example_pcaps.display()
        ));
    }

    let mut captures = Vec::new();
    collect_pcapng_files(&example_pcaps, &mut captures)
        .map_err(|err| format!("list {}: {err}", example_pcaps.display()))?;
    captures.sort();

    if captures.is_empty() {
        return Err(format!(
            "no certification example .pcapng captures found under {}",
            example_pcaps.display()
        ));
    }

    Ok(captures)
}

fn collect_pcapng_files(dir: &Path, captures: &mut Vec<PathBuf>) -> Result<(), std::io::Error> {
    for entry in fs::read_dir(dir)? {
        let path = entry?.path();
        if path.extension().is_some_and(|ext| ext == "pcapng") {
            captures.push(path);
        }
    }
    Ok(())
}

fn validate_strict_difi_payload(payload: &[u8]) -> Result<(), String> {
    if payload.len() < MIN_DIFI_PACKET_BYTES {
        return Err(format!(
            "DIFI packet is too short: need at least {MIN_DIFI_PACKET_BYTES} bytes"
        ));
    }

    if !payload.len().is_multiple_of(4) {
        return Err("DIFI packet length is not a multiple of 4 bytes".to_string());
    }

    let header = header_word(payload).expect("minimum DIFI packet length includes header word");
    let packet_type = header >> 28;
    let class_id_indicator = (header & 0x0800_0000) != 0;
    let packet_size_words = (header & 0x0000_FFFF) as usize;
    let packet_size_bytes = packet_size_words * 4;
    let oui = payload_oui(payload).expect("minimum DIFI packet length includes class ID word");

    if !matches!(packet_type, 0x1 | 0x4 | 0x5 | 0x6 | 0x7) {
        return Err(format!("unsupported DIFI packet type 0x{packet_type:X}"));
    }
    if !class_id_indicator {
        return Err("class identifier indicator is not set".to_string());
    }
    if packet_size_bytes != payload.len() {
        return Err(format!(
            "DIFI header packet size is {packet_size_bytes} bytes, UDP payload is {} bytes",
            payload.len()
        ));
    }
    if oui != DIFI_CID {
        return Err(format!(
            "invalid DIFI CID/OUI: expected 0x{DIFI_CID:06X}, got 0x{oui:06X}"
        ));
    }

    Ok(())
}

fn record_failure(failures: &mut Vec<String>, failure: String) {
    if failures.len() < MAX_FAILURES {
        failures.push(failure);
    }
}

fn payload_failure(capture: &Path, payload_index: usize, payload: &[u8], err: &str) -> String {
    let header = header_word(payload)
        .map(|word| format!("0x{word:08X}"))
        .unwrap_or_else(|| "n/a".to_string());
    let oui = payload_oui(payload)
        .map(|oui| format!("0x{oui:06X}"))
        .unwrap_or_else(|| "n/a".to_string());

    format!(
        "{} payload #{payload_index} len={} header={header} CID/OUI={oui}: {err}",
        capture.display(),
        payload.len()
    )
}

fn header_word(payload: &[u8]) -> Option<u32> {
    Some(u32::from_be_bytes(payload.get(0..4)?.try_into().ok()?))
}

fn payload_oui(payload: &[u8]) -> Option<u32> {
    Some(u32::from_be_bytes(payload.get(8..12)?.try_into().ok()?) & 0x00FF_FFFF)
}

fn parse_with_supported_profiles(payload: &[u8]) -> Result<(), String> {
    let profiles = [
        ("DIFI 1.3.0 strict", ParseOptions::default()),
        (
            "DIFI 1.2.1 strict",
            ParseOptions {
                standard: DifiStandardVersion::V1_2_1,
                compatibility: CompatibilityMode::Strict,
            },
        ),
        (
            "DIFI 1.2.1 legacy version packet type",
            ParseOptions {
                standard: DifiStandardVersion::V1_2_1,
                compatibility: CompatibilityMode::LegacyVersionPacketType,
            },
        ),
        (
            "DIFI 1.1 strict",
            ParseOptions {
                standard: DifiStandardVersion::V1_1,
                compatibility: CompatibilityMode::Strict,
            },
        ),
    ];

    let mut errors = Vec::new();
    for (label, options) in profiles {
        match parse_packet_exact_with_options(payload, options) {
            Ok(_) => return Ok(()),
            Err(err) => errors.push(format!("{label}: {err}")),
        }
    }

    Err(errors.join(" | "))
}

fn capture_udp_payloads(input: &[u8]) -> Result<Vec<&[u8]>, String> {
    if input.starts_with(&[0x0A, 0x0D, 0x0D, 0x0A]) {
        return pcapng_udp_payloads(input);
    }

    if pcap_byte_order(input).is_some() {
        return pcap_udp_payloads(input);
    }

    Err("unsupported capture file magic".to_string())
}

fn pcap_byte_order(input: &[u8]) -> Option<ByteOrder> {
    match input.get(0..4)? {
        [0xD4, 0xC3, 0xB2, 0xA1] | [0x4D, 0x3C, 0xB2, 0xA1] => Some(ByteOrder::Little),
        [0xA1, 0xB2, 0xC3, 0xD4] | [0xA1, 0xB2, 0x3C, 0x4D] => Some(ByteOrder::Big),
        _ => None,
    }
}

fn pcap_udp_payloads(input: &[u8]) -> Result<Vec<&[u8]>, String> {
    if input.len() < 24 {
        return Err("truncated pcap global header".to_string());
    }

    let order = pcap_byte_order(input).ok_or_else(|| "unsupported pcap magic".to_string())?;
    let link_type = order.read_u32(input, 20)?;
    let link_type =
        u16::try_from(link_type).map_err(|_| format!("unsupported pcap link type {link_type}"))?;

    let mut offset = 24usize;
    let mut payloads = Vec::new();

    while offset < input.len() {
        if input.len() - offset < 16 {
            return Err(format!("truncated pcap packet header at offset {offset}"));
        }

        let captured_len = order.read_u32(input, offset + 8)? as usize;
        let packet_start = offset + 16;
        let packet_end = packet_start
            .checked_add(captured_len)
            .ok_or_else(|| "pcap packet length overflow".to_string())?;
        if packet_end > input.len() {
            return Err(format!(
                "pcap packet at offset {offset} extends past input: {packet_end} > {}",
                input.len()
            ));
        }

        if let Some(payload) = udp_payload(link_type, &input[packet_start..packet_end]) {
            payloads.push(payload);
        }
        offset = packet_end;
    }

    Ok(payloads)
}

fn pcapng_udp_payloads(input: &[u8]) -> Result<Vec<&[u8]>, String> {
    let mut offset = 0usize;
    let mut byte_order = None;
    let mut link_types = Vec::new();
    let mut payloads = Vec::new();

    while offset < input.len() {
        if input.len() - offset < 12 {
            return Err(format!("truncated block header at offset {offset}"));
        }

        let section_order = section_byte_order(input, offset);
        if let Some(order) = section_order {
            byte_order = Some(order);
            link_types.clear();
        }

        let order =
            byte_order.ok_or_else(|| format!("pcapng data before section header at {offset}"))?;
        let block_type = order.read_u32(input, offset)?;
        let block_len = order.read_u32(input, offset + 4)? as usize;
        if block_len < 12 || !block_len.is_multiple_of(4) {
            return Err(format!(
                "invalid block length {block_len} at offset {offset}"
            ));
        }
        let block_end = offset
            .checked_add(block_len)
            .ok_or_else(|| "pcapng block length overflow".to_string())?;
        if block_end > input.len() {
            return Err(format!(
                "block at offset {offset} extends past input: {block_end} > {}",
                input.len()
            ));
        }
        let trailing_len = order.read_u32(input, block_end - 4)? as usize;
        if trailing_len != block_len {
            return Err(format!(
                "block length trailer mismatch at offset {offset}: {trailing_len} != {block_len}"
            ));
        }

        match block_type {
            0x0A0D_0D0A => {}
            0x0000_0001 => {
                let body = &input[offset + 8..block_end - 4];
                if body.len() < 8 {
                    return Err(format!(
                        "truncated pcapng interface description block at offset {offset}"
                    ));
                }
                link_types.push(order.read_u16(body, 0)?);
            }
            0x0000_0006 => {
                let body = &input[offset + 8..block_end - 4];
                if body.len() < 20 {
                    return Err(format!(
                        "truncated pcapng enhanced packet block at offset {offset}"
                    ));
                }

                let interface_id = order.read_u32(body, 0)? as usize;
                let link_type = link_types.get(interface_id).copied().ok_or_else(|| {
                    format!(
                        "pcapng enhanced packet block at offset {offset} references unknown interface {interface_id}"
                    )
                })?;
                let captured_len = order.read_u32(body, 12)? as usize;
                let packet_start = 20usize;
                let packet_end = packet_start
                    .checked_add(captured_len)
                    .ok_or_else(|| "captured packet length overflow".to_string())?;
                if packet_end > body.len() {
                    return Err(format!(
                        "pcapng enhanced packet block at offset {offset} extends past block body"
                    ));
                }

                if let Some(payload) = udp_payload(link_type, &body[packet_start..packet_end]) {
                    payloads.push(payload);
                }
            }
            _ => {}
        }

        offset = block_end;
    }

    Ok(payloads)
}

fn section_byte_order(input: &[u8], offset: usize) -> Option<ByteOrder> {
    let block_type = u32::from_le_bytes(input.get(offset..offset + 4)?.try_into().ok()?);
    if block_type != 0x0A0D_0D0A {
        return None;
    }

    match input.get(offset + 8..offset + 12)? {
        [0x4D, 0x3C, 0x2B, 0x1A] => Some(ByteOrder::Little),
        [0x1A, 0x2B, 0x3C, 0x4D] => Some(ByteOrder::Big),
        _ => None,
    }
}

#[derive(Debug, Clone, Copy)]
enum ByteOrder {
    Little,
    Big,
}

impl ByteOrder {
    fn read_u16(self, input: &[u8], offset: usize) -> Result<u16, String> {
        let bytes = input
            .get(offset..offset + 2)
            .ok_or_else(|| format!("truncated u16 at offset {offset}"))?;
        let bytes = [bytes[0], bytes[1]];
        Ok(match self {
            Self::Little => u16::from_le_bytes(bytes),
            Self::Big => u16::from_be_bytes(bytes),
        })
    }

    fn read_u32(self, input: &[u8], offset: usize) -> Result<u32, String> {
        let bytes = input
            .get(offset..offset + 4)
            .ok_or_else(|| format!("truncated u32 at offset {offset}"))?;
        let bytes = [bytes[0], bytes[1], bytes[2], bytes[3]];
        Ok(match self {
            Self::Little => u32::from_le_bytes(bytes),
            Self::Big => u32::from_be_bytes(bytes),
        })
    }
}

fn udp_payload(link_type: u16, packet: &[u8]) -> Option<&[u8]> {
    match link_type {
        1 => ethernet_udp_payload(packet),
        101 => ipv4_udp_payload(packet),
        113 => linux_cooked_udp_payload(packet),
        147 => Some(packet),
        _ => None,
    }
}

fn ethernet_udp_payload(frame: &[u8]) -> Option<&[u8]> {
    if frame.len() < 14 {
        return None;
    }

    let mut ethertype = u16::from_be_bytes([frame[12], frame[13]]);
    let mut payload_offset = 14usize;
    while matches!(ethertype, 0x8100 | 0x88A8 | 0x9100) {
        if frame.len() < payload_offset + 4 {
            return None;
        }
        ethertype = u16::from_be_bytes([frame[payload_offset + 2], frame[payload_offset + 3]]);
        payload_offset += 4;
    }

    (ethertype == 0x0800).then(|| ipv4_udp_payload(&frame[payload_offset..]))?
}

fn linux_cooked_udp_payload(frame: &[u8]) -> Option<&[u8]> {
    if frame.len() < 16 {
        return None;
    }

    let protocol = u16::from_be_bytes([frame[14], frame[15]]);
    (protocol == 0x0800).then(|| ipv4_udp_payload(&frame[16..]))?
}

fn ipv4_udp_payload(packet: &[u8]) -> Option<&[u8]> {
    if packet.len() < 20 || packet[0] >> 4 != 4 {
        return None;
    }

    let header_len = usize::from(packet[0] & 0x0F) * 4;
    if header_len < 20 || packet.len() < header_len {
        return None;
    }

    let total_len = usize::from(u16::from_be_bytes([packet[2], packet[3]]));
    if total_len < header_len + 8 || packet.len() < total_len || packet[9] != 17 {
        return None;
    }

    let fragment = u16::from_be_bytes([packet[6], packet[7]]) & 0x3FFF;
    if fragment != 0 {
        return None;
    }

    let udp = &packet[header_len..total_len];
    let udp_len = usize::from(u16::from_be_bytes([udp[4], udp[5]]));
    if udp_len < 8 || udp_len > udp.len() {
        return None;
    }

    Some(&udp[8..udp_len])
}
