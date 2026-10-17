//! Optional, bounded raw CSI copy for the separate home module worker.
//!
//! This socket never replaces primary ingestion, blocks on a downstream worker,
//! retries a datagram, rewrites its identity or buffers application-level data.
use std::collections::BTreeSet;
use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::time::{Duration, Instant};

const HEADER_BYTES: usize = 20;
const MAX_DATAGRAM_BYTES: usize = 4116;

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Counters {
    pub eligible: u64,
    pub sent: u64,
    pub dropped: u64,
}

pub struct RawCsiMirror {
    socket: UdpSocket,
    destination: SocketAddr,
    nodes: BTreeSet<u8>,
    counters: Counters,
    last_report: Instant,
}

fn configuration(
    destination: &str,
    node_ids: &str,
) -> Result<(SocketAddr, BTreeSet<u8>), &'static str> {
    // Literal addresses only: no DNS work can enter the packet receive loop.
    let destination: SocketAddr = destination
        .parse()
        .map_err(|_| "invalid mirror socket address")?;
    let private = match destination.ip() {
        IpAddr::V4(ip) => ip.is_private() || ip.is_loopback(),
        IpAddr::V6(ip) => ip.is_unique_local() || ip.is_loopback(),
    };
    if !private || destination.port() == 0 {
        return Err("mirror destination must be a private or loopback address with a nonzero port");
    }
    let mut nodes = BTreeSet::new();
    for item in node_ids.split(',') {
        let node: u8 = item.trim().parse().map_err(|_| "invalid mirror node ID")?;
        if node == 0 || !nodes.insert(node) || nodes.len() > 16 {
            return Err("mirror needs one to sixteen unique nonzero node IDs");
        }
    }
    Ok((destination, nodes))
}

fn eligible(packet: &[u8], nodes: &BTreeSet<u8>) -> bool {
    if !(HEADER_BYTES..=MAX_DATAGRAM_BYTES).contains(&packet.len())
        || packet[..4] != 0xC511_0001u32.to_le_bytes()
        || !nodes.contains(&packet[4])
    {
        return false;
    }
    let antennas = usize::from(packet[5]);
    let subcarriers = usize::from(u16::from_le_bytes([packet[6], packet[7]]));
    antennas > 0 && subcarriers > 0 && HEADER_BYTES + 2 * antennas * subcarriers == packet.len()
}

impl RawCsiMirror {
    pub fn from_environment() -> Result<Option<Self>, String> {
        let destination = match std::env::var("RUVIEW_RAW_CSI_MIRROR") {
            Ok(value) => value,
            Err(std::env::VarError::NotPresent) => return Ok(None),
            Err(_) => return Err("invalid mirror destination environment".into()),
        };
        let ids = std::env::var("RUVIEW_RAW_CSI_MIRROR_NODE_IDS")
            .map_err(|_| "mirror requires an explicit node allowlist")?;
        let (destination, nodes) = configuration(&destination, &ids)?;
        Self::new(destination, nodes)
            .map(Some)
            .map_err(|_| "mirror socket initialization failed".into())
    }

    fn new(destination: SocketAddr, nodes: BTreeSet<u8>) -> std::io::Result<Self> {
        let bind = if destination.is_ipv4() {
            "0.0.0.0:0"
        } else {
            "[::]:0"
        };
        let socket = UdpSocket::bind(bind)?;
        socket.set_nonblocking(true)?;
        Ok(Self {
            socket,
            destination,
            nodes,
            counters: Counters::default(),
            last_report: Instant::now(),
        })
    }

    pub fn forward(&mut self, packet: &[u8]) {
        if !eligible(packet, &self.nodes) {
            return;
        }
        self.counters.eligible = self.counters.eligible.saturating_add(1);
        match self.socket.send_to(packet, self.destination) {
            Ok(bytes) if bytes == packet.len() => {
                self.counters.sent = self.counters.sent.saturating_add(1)
            }
            _ => self.counters.dropped = self.counters.dropped.saturating_add(1),
        }
    }

    pub fn report_due(&mut self) -> Option<Counters> {
        if self.last_report.elapsed() < Duration::from_secs(10) {
            return None;
        }
        self.last_report = Instant::now();
        Some(self.counters)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn packet(node: u8, antennas: u8, subcarriers: u16) -> Vec<u8> {
        let mut packet = vec![0x81; HEADER_BYTES + 2 * antennas as usize * subcarriers as usize];
        packet[..4].copy_from_slice(&0xC511_0001u32.to_le_bytes());
        packet[4] = node;
        packet[5] = antennas;
        packet[6..8].copy_from_slice(&subcarriers.to_le_bytes());
        packet
    }

    #[test]
    fn refuses_public_dns_zero_ports_and_ambiguous_node_allowlists() {
        for (address, ids) in [
            ("example.com:5015", "1"),
            ("8.8.8.8:5015", "1"),
            ("10.42.1.2:0", "1"),
            ("10.42.1.2:5015", ""),
            ("10.42.1.2:5015", "1,1"),
            ("10.42.1.2:5015", "0"),
            ("10.42.1.2:5015", "256"),
            ("10.42.1.2:5015", "1,"),
            ("[2001:4860:4860::8888]:5015", "1"),
        ] {
            assert!(configuration(address, ids).is_err());
        }
        assert!(configuration("10.43.12.3:5015", "1,2,3").is_ok());
    }

    #[test]
    fn exact_raw_grid_bytes_only_and_no_silent_u16_truncation() {
        let nodes = BTreeSet::from([1, 2, 3]);
        assert!(eligible(&packet(1, 1, 64), &nodes));
        assert!(eligible(&packet(3, 1, 256), &nodes));
        assert!(!eligible(&packet(4, 1, 64), &nodes));
        assert!(!eligible(&packet(1, 0, 64), &nodes));
        assert!(!eligible(&packet(1, 1, 0), &nodes));
        assert!(!eligible(&packet(1, 8, 512), &nodes));
        let original = packet(2, 1, 64);
        for size in 0..original.len() {
            assert!(!eligible(&original[..size], &nodes));
        }
        let mut extra = original.clone();
        extra.push(0);
        assert!(!eligible(&extra, &nodes));
        let mut non_raw = original;
        non_raw[..4].copy_from_slice(&0xC511_0007u32.to_le_bytes());
        assert!(!eligible(&non_raw, &nodes));
    }

    #[test]
    fn loopback_copy_preserves_every_byte_without_mutating_source() {
        let receiver = UdpSocket::bind("127.0.0.1:0").unwrap();
        receiver
            .set_read_timeout(Some(Duration::from_millis(200)))
            .unwrap();
        let mut mirror =
            RawCsiMirror::new(receiver.local_addr().unwrap(), BTreeSet::from([2])).unwrap();
        let original = packet(2, 1, 64);
        mirror.forward(&original);
        let mut received = [0u8; MAX_DATAGRAM_BYTES];
        let (size, _) = receiver.recv_from(&mut received).unwrap();
        assert_eq!(&received[..size], &original);
        assert_eq!(
            mirror.counters,
            Counters {
                eligible: 1,
                sent: 1,
                dropped: 0
            }
        );
        mirror.forward(&packet(3, 1, 64));
        assert_eq!(mirror.counters.eligible, 1);
    }
}
