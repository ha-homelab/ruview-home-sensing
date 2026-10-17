//! Recent-evidence admission for interleaved CSI grids.
//!
//! Keys include both subcarrier count and PPDU type. Only headers enter this
//! selector; rejected frames must never refresh accepted-CSI freshness or enter
//! an amplitude window. Calibration owns a separate, immutable grid binding.

use std::collections::VecDeque;
use std::time::{Duration, Instant};

const EVIDENCE_WINDOW: Duration = Duration::from_secs(3);
const ACTIVE_EXPIRY: Duration = Duration::from_secs(3);
const MIN_SPAN: Duration = Duration::from_secs(2);
const MAX_GAP: Duration = Duration::from_secs(1);
const MIN_SAMPLES: usize = 5;
const MIN_RATE_HZ: f64 = 2.0;
// Sample each grid independently so high-rate traffic cannot evict the two
// seconds of evidence needed to qualify a less frequent candidate.
const EVIDENCE_SAMPLE_SPACING: Duration = Duration::from_millis(50);
const MAX_GRIDS: usize = 16;
const MAX_SAMPLES_PER_GRID: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Admission {
    Reject,
    Continue,
    /// First admission or a change of identity: clear inference buffers before
    /// inserting this frame, including equal-width changes of PPDU type.
    Switch,
}

struct GridEvidence<K> {
    key: K,
    last_seen: Instant,
    samples: VecDeque<Instant>,
}

pub(crate) struct GridGate<K> {
    active: Option<(K, u16)>,
    active_last_seen: Option<Instant>,
    evidence: Vec<GridEvidence<K>>,
}

impl<K: Copy + Eq> GridGate<K> {
    pub(crate) fn new() -> Self {
        Self {
            active: None,
            active_last_seen: None,
            evidence: Vec::new(),
        }
    }

    pub(crate) fn active(&self) -> Option<K> {
        self.active.map(|(key, _)| key)
    }

    pub(crate) fn admit(&mut self, key: K, density: u16, now: Instant) -> Admission {
        self.observe(key, now);

        let Some((active, active_density)) = self.active else {
            self.activate(key, density, now);
            return Admission::Switch;
        };
        if active == key {
            self.active_last_seen = Some(now);
            return Admission::Continue;
        }

        // A single wider packet is not evidence of a sustainable stream.
        // While the active stream is alive, only a qualified denser stream
        // may replace it. Equal-width and smaller grids require expiry.
        let expired = self
            .active_last_seen
            .is_none_or(|seen| now.saturating_duration_since(seen) >= ACTIVE_EXPIRY);
        if (density > active_density || expired) && self.qualifies(key) {
            self.activate(key, density, now);
            Admission::Switch
        } else {
            Admission::Reject
        }
    }

    fn activate(&mut self, key: K, density: u16, now: Instant) {
        self.active = Some((key, density));
        self.active_last_seen = Some(now);
    }

    fn observe(&mut self, key: K, now: Instant) {
        self.evidence
            .retain(|stream| now.saturating_duration_since(stream.last_seen) <= EVIDENCE_WINDOW);
        let index = self.evidence.iter().position(|stream| stream.key == key);
        let index = index.unwrap_or_else(|| {
            if self.evidence.len() == MAX_GRIDS {
                let oldest = self
                    .evidence
                    .iter()
                    .enumerate()
                    .min_by_key(|(_, stream)| stream.last_seen)
                    .map(|(i, _)| i)
                    .expect("nonempty evidence");
                self.evidence.swap_remove(oldest);
            }
            self.evidence.push(GridEvidence {
                key,
                last_seen: now,
                samples: VecDeque::new(),
            });
            self.evidence.len() - 1
        });
        let stream = &mut self.evidence[index];
        stream.last_seen = now;
        while stream
            .samples
            .front()
            .is_some_and(|seen| now.saturating_duration_since(*seen) > EVIDENCE_WINDOW)
        {
            stream.samples.pop_front();
        }
        if stream
            .samples
            .back()
            .is_none_or(|seen| now.saturating_duration_since(*seen) >= EVIDENCE_SAMPLE_SPACING)
        {
            if stream.samples.len() == MAX_SAMPLES_PER_GRID {
                stream.samples.pop_front();
            }
            stream.samples.push_back(now);
        }
    }

    fn qualifies(&self, key: K) -> bool {
        let Some(stream) = self.evidence.iter().find(|stream| stream.key == key) else {
            return false;
        };
        let mut arrivals = stream.samples.iter().copied();
        let Some(first) = arrivals.next() else {
            return false;
        };
        let mut previous = first;
        let mut count = 1;
        for seen in arrivals {
            if seen.saturating_duration_since(previous) > MAX_GAP {
                return false;
            }
            previous = seen;
            count += 1;
        }
        let span = previous.saturating_duration_since(first);
        count >= MIN_SAMPLES
            && span >= MIN_SPAN
            && (count - 1) as f64 / span.as_secs_f64() >= MIN_RATE_HZ
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    type Key = (u16, u8);

    fn feed(gate: &mut GridGate<Key>, key: Key, start: Instant, ms: u64) -> Admission {
        gate.admit(key, key.0, start + Duration::from_millis(ms))
    }

    #[test]
    fn rare_wide_packet_does_not_capture_a_continuous_64_bin_stream() {
        let mut gate = GridGate::new();
        let t = Instant::now();
        for i in 0..3_000 {
            let ms = i * 100;
            assert_ne!(feed(&mut gate, (64, 0), t, ms), Admission::Reject);
            if i % 1570 == 0 {
                assert_eq!(feed(&mut gate, (128, 1), t, ms), Admission::Reject);
            }
            assert_eq!(gate.active(), Some((64, 0)));
        }
    }

    #[test]
    fn rare_wide_first_packet_expires_and_continuous_64_recovers() {
        let mut gate = GridGate::new();
        let t = Instant::now();
        assert_eq!(feed(&mut gate, (128, 1), t, 0), Admission::Switch);
        for i in 1..30 {
            assert_eq!(feed(&mut gate, (64, 0), t, i * 100), Admission::Reject);
        }
        assert_eq!(feed(&mut gate, (64, 0), t, 3000), Admission::Switch);
        assert_eq!(gate.active(), Some((64, 0)));
    }

    #[test]
    fn sustained_dense_stream_promotes_and_sparse_minority_cannot_flap_it() {
        let mut gate = GridGate::new();
        let t = Instant::now();
        feed(&mut gate, (64, 0), t, 0);
        for i in 0..20 {
            feed(&mut gate, (64, 0), t, i * 100);
            assert_eq!(feed(&mut gate, (256, 3), t, i * 100), Admission::Reject);
        }
        assert_eq!(feed(&mut gate, (256, 3), t, 2000), Admission::Switch);
        for i in 21..200 {
            assert_eq!(feed(&mut gate, (256, 3), t, i * 100), Admission::Continue);
            assert_eq!(feed(&mut gate, (64, 0), t, i * 100), Admission::Reject);
        }
    }

    #[test]
    fn stale_active_grid_needs_sustained_replacement_not_one_packet() {
        let mut gate = GridGate::new();
        let t = Instant::now();
        feed(&mut gate, (128, 1), t, 0);
        assert_eq!(feed(&mut gate, (64, 0), t, 60_000), Admission::Reject);
        for i in 1..20 {
            assert_eq!(
                feed(&mut gate, (64, 0), t, 60_000 + i * 100),
                Admission::Reject
            );
        }
        assert_eq!(feed(&mut gate, (64, 0), t, 62_000), Admission::Switch);
    }

    #[test]
    fn same_width_ppdu_change_is_a_switch_only_after_expiry() {
        let mut gate = GridGate::new();
        let t = Instant::now();
        feed(&mut gate, (64, 0), t, 0);
        for i in 1..30 {
            assert_eq!(feed(&mut gate, (64, 1), t, i * 100), Admission::Reject);
        }
        assert_eq!(feed(&mut gate, (64, 1), t, 3000), Admission::Switch);
        assert_eq!(gate.active(), Some((64, 1)));
    }

    #[test]
    fn dense_bursts_with_long_holes_do_not_qualify() {
        let mut gate = GridGate::new();
        let t = Instant::now();
        feed(&mut gate, (64, 0), t, 0);
        for ms in [0, 10, 20, 2100, 2110, 2120] {
            feed(&mut gate, (64, 0), t, ms);
            assert_eq!(feed(&mut gate, (128, 1), t, ms), Admission::Reject);
        }
    }

    #[test]
    fn low_rate_and_duplicate_timestamp_bursts_cannot_promote() {
        let mut gate = GridGate::new();
        let t = Instant::now();
        feed(&mut gate, (64, 0), t, 0);
        for ms in (0..=9000).step_by(1000) {
            feed(&mut gate, (64, 0), t, ms);
            assert_eq!(feed(&mut gate, (128, 1), t, ms), Admission::Reject);
        }
        for _ in 0..1024 {
            assert_eq!(feed(&mut gate, (128, 1), t, 9000), Admission::Reject);
        }
        assert!(gate
            .evidence
            .iter()
            .all(|stream| stream.samples.len() <= MAX_SAMPLES_PER_GRID));
    }

    #[test]
    fn high_rate_mixed_streams_do_not_evict_qualification_span() {
        let mut gate = GridGate::new();
        let t = Instant::now();
        feed(&mut gate, (64, 0), t, 0);
        let mut promoted = false;
        // 500 Hz total, including a 100 Hz candidate. A global 256-frame
        // ring held only 512 ms and could never prove a two-second span.
        for i in 1..=2000 {
            let key = if i % 5 == 0 { (128, 1) } else { (64, 0) };
            if feed(&mut gate, key, t, i * 2) == Admission::Switch {
                promoted = true;
            }
        }
        assert!(promoted);
        assert_eq!(gate.active(), Some((128, 1)));
        assert!(gate
            .evidence
            .iter()
            .all(|stream| stream.samples.len() <= MAX_SAMPLES_PER_GRID));
    }

    #[test]
    fn high_rate_replacement_recovers_after_wide_startup_packet() {
        let mut gate = GridGate::new();
        let t = Instant::now();
        feed(&mut gate, (128, 1), t, 0);
        for i in 1..1000 {
            assert_eq!(feed(&mut gate, (64, 0), t, i * 3), Admission::Reject);
        }
        assert_eq!(feed(&mut gate, (64, 0), t, 3000), Admission::Switch);
        assert_eq!(gate.active(), Some((64, 0)));
    }

    #[test]
    fn arbitrary_grid_flood_has_bounded_memory() {
        let mut gate = GridGate::new();
        let t = Instant::now();
        for width in 1..=2048 {
            feed(&mut gate, (width, 0), t, u64::from(width));
            assert!(gate.evidence.len() <= MAX_GRIDS);
            assert!(gate
                .evidence
                .iter()
                .all(|stream| stream.samples.len() <= MAX_SAMPLES_PER_GRID));
        }
    }

    #[test]
    fn recovered_wider_stream_must_requalify_after_evidence_expires() {
        let mut gate = GridGate::new();
        let t = Instant::now();
        feed(&mut gate, (128, 1), t, 0);
        for i in 1..=30 {
            feed(&mut gate, (64, 0), t, i * 100);
        }
        assert_eq!(gate.active(), Some((64, 0)));
        assert_eq!(feed(&mut gate, (128, 1), t, 3100), Admission::Reject);
        assert_eq!(gate.active(), Some((64, 0)));
    }
}
