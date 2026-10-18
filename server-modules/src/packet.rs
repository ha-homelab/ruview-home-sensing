use serde::Serialize;

pub const MAGIC: u32 = 0xc511_0001;
pub const HEADER: usize = 20;
pub const MAX_PACKET: usize = 1044;
pub const SUBCARRIERS: usize = 64;
pub const SYNC_VALID_METADATA: u8 = 0x10;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct Grid {
    pub antennas: u8,
    pub subcarriers: u16,
    pub frequency_mhz: u32,
    pub ppdu_type: u8,
    pub flags: u8,
}

impl Grid {
    /// ADR018 bit 4 reports sync validity, not a different sampled symbol grid.
    /// Preserve it on the packet; this worker never derives device time from it.
    pub fn same_physical_grid(&self, other: &Self) -> bool {
        self.antennas == other.antennas
            && self.subcarriers == other.subcarriers
            && self.frequency_mhz == other.frequency_mhz
            && self.ppdu_type == other.ppdu_type
            && (self.flags & !SYNC_VALID_METADATA) == (other.flags & !SYNC_VALID_METADATA)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Packet {
    pub node_id: u8,
    pub sequence: u32,
    pub rssi_dbm: i8,
    pub noise_floor_dbm: i8,
    pub grid: Grid,
    pub iq: [i8; SUBCARRIERS * 2],
}

pub fn parse(data: &[u8], allowed_nodes: &[u8]) -> Result<Packet, &'static str> {
    if data.len() < HEADER || data.len() > MAX_PACKET {
        return Err("invalid_length");
    }
    let u32_at = |p| u32::from_le_bytes(data[p..p + 4].try_into().unwrap());
    if u32_at(0) != MAGIC {
        return Err("unsupported_magic");
    }
    if !allowed_nodes.contains(&data[4]) {
        return Err("node_not_allowed");
    }
    let grid = Grid {
        antennas: data[5],
        subcarriers: u16::from_le_bytes([data[6], data[7]]),
        frequency_mhz: u32_at(8),
        ppdu_type: data[18],
        flags: data[19],
    };
    if grid.antennas != 1 || grid.subcarriers != 64 {
        return Err("unsupported_grid");
    }
    if data.len() != HEADER + usize::from(grid.antennas) * usize::from(grid.subcarriers) * 2 {
        return Err("invalid_payload_length");
    }
    if !(2412..=2472).contains(&grid.frequency_mhz) || (grid.frequency_mhz - 2412) % 5 != 0 {
        return Err("unsupported_frequency");
    }
    // Pinned sender csi_collector.c ADR018/ADR110: bit 4 is sync-valid metadata;
    // bit 0 changes bandwidth and bit 2 denotes STBC. Admit only the observed
    // 0/0x10 profiles, without treating that flag as a verified device clock.
    if grid.ppdu_type != 0 || grid.flags & !SYNC_VALID_METADATA != 0 {
        return Err("unqualified_ppdu_or_flags");
    }
    let mut iq = [0; SUBCARRIERS * 2];
    for (out, byte) in iq.iter_mut().zip(&data[HEADER..]) {
        *out = *byte as i8;
    }
    Ok(Packet {
        node_id: data[4],
        sequence: u32_at(12),
        rssi_dbm: data[16] as i8,
        noise_floor_dbm: data[17] as i8,
        grid,
        iq,
    })
}

#[cfg(test)]
pub fn fixture(node: u8, sequence: u32) -> Vec<u8> {
    let mut bytes = vec![0u8; 148];
    bytes[0..4].copy_from_slice(&MAGIC.to_le_bytes());
    bytes[4] = node;
    bytes[5] = 1;
    bytes[6..8].copy_from_slice(&64u16.to_le_bytes());
    bytes[8..12].copy_from_slice(&2462u32.to_le_bytes());
    bytes[12..16].copy_from_slice(&sequence.to_le_bytes());
    bytes[16] = (-50i8) as u8;
    for pair in bytes[20..].chunks_mut(2) {
        pair[0] = 15;
        pair[1] = (-3i8) as u8;
    }
    bytes
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn signed_payload_and_full_u32_sequence_are_preserved() {
        let p = parse(&fixture(3, u32::MAX), &[1, 2, 3]).unwrap();
        assert_eq!(p.sequence, u32::MAX);
        assert_eq!(p.iq[1], -3);
        assert_eq!(p.rssi_dbm, -50);
    }
    #[test]
    fn shape_magic_node_length_and_grid_fail_closed() {
        let base = fixture(2, 1);
        for (offset, value) in [(0, 0), (4, 9), (5, 3), (6, 128), (18, 1), (19, 1)] {
            let mut b = base.clone();
            b[offset] = value;
            assert!(parse(&b, &[1, 2, 3]).is_err());
        }
        assert!(parse(&base[..147], &[2]).is_err());
        let mut b = base;
        b.push(0);
        assert!(parse(&b, &[2]).is_err());
    }

    #[test]
    fn captured_headers_accept_sync_metadata_without_reinterpreting_payload() {
        // First headers for nodes 1/2/3 in the historical baseline PCAP:
        // SHA256 cde52cc16e6a43eab3208f769d9455ad7b99ef6e64a46f1de5f9d425373e52ac.
        // The capture is truncated: payload below is explicitly synthetic.
        for header in [
            "010011c5010140009e090000867b1000e9a00010",
            "010011c5020140009e090000dc590000ca9f0010",
            "010011c5030140009e090000bd791500cc9f0010",
        ] {
            let mut bytes = fixture(1, 0);
            for (index, offset) in (0..40).step_by(2).enumerate() {
                bytes[index] = u8::from_str_radix(&header[offset..offset + 2], 16).unwrap();
            }
            let packet = parse(&bytes, &[1, 2, 3]).unwrap();
            assert_eq!(packet.grid.flags, SYNC_VALID_METADATA);
            assert_eq!(packet.grid.frequency_mhz, 2462);
            assert_eq!(packet.iq[0..2], [15, -3]);
            assert!(parse(&bytes[..147], &[1, 2, 3]).is_err());
            bytes.push(0);
            assert!(parse(&bytes, &[1, 2, 3]).is_err());
        }
        let mut bytes = fixture(2, 1);
        for flags in 0..=u8::MAX {
            bytes[19] = flags;
            assert_eq!(parse(&bytes, &[2]).is_ok(), flags == 0 || flags == 0x10);
        }
        bytes[19] = SYNC_VALID_METADATA;
        for ppdu in [1, 2, 3, 255] {
            bytes[18] = ppdu;
            assert!(parse(&bytes, &[2]).is_err());
        }
    }
}
