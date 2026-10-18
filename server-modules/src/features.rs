use crate::packet::{Packet, SUBCARRIERS};
use std::collections::VecDeque;
use wifi_densepose_wasm_edge::pipeline_all::CsiFrameView;

/// Public, versioned worker feature contract: unwrapped phase, linear amplitude,
/// 64-frame amplitude variance, 20-frame variance of the most variable phase.
/// These are signal features, not estimated presence, vital signs or people.
/// Compatibility intentionally follows pinned RuView atan2(byte1, byte0).
/// ESP-IDF transmits imaginary,real; this legacy transform reflects mathematical
/// phase. It must never be interpreted as calibrated physical direction.
pub struct Features {
    pub phases: [f32; SUBCARRIERS],
    pub previous: [f32; SUBCARRIERS],
    pub amplitudes: [f32; SUBCARRIERS],
    pub variances: [f32; SUBCARRIERS],
    pub motion: f32,
    pub frames: u64,
    amplitude_history: VecDeque<[f32; SUBCARRIERS]>,
    phase_history: VecDeque<[f32; SUBCARRIERS]>,
    last_wrapped: [f32; SUBCARRIERS],
}

impl Default for Features {
    fn default() -> Self {
        Self {
            phases: [0.; 64],
            previous: [0.; 64],
            amplitudes: [0.; 64],
            variances: [0.; 64],
            motion: 0.,
            frames: 0,
            amplitude_history: VecDeque::with_capacity(64),
            phase_history: VecDeque::with_capacity(20),
            last_wrapped: [0.; 64],
        }
    }
}

fn variance(values: impl Iterator<Item = f32> + Clone, n: usize) -> f32 {
    if n < 2 {
        return 0.;
    }
    let mean = values.clone().map(f64::from).sum::<f64>() / n as f64;
    (values.map(|x| (f64::from(x) - mean).powi(2)).sum::<f64>() / (n - 1) as f64) as f32
}

impl Features {
    pub fn update(&mut self, packet: &Packet) {
        self.previous = self.phases;
        for k in 0..64 {
            let i = f32::from(packet.iq[k * 2]);
            let q = f32::from(packet.iq[k * 2 + 1]);
            self.amplitudes[k] = i.hypot(q);
            let wrapped = q.atan2(i);
            self.phases[k] = if self.frames == 0 {
                wrapped
            } else {
                self.phases[k]
                    + (wrapped - self.last_wrapped[k] + std::f32::consts::PI)
                        .rem_euclid(std::f32::consts::TAU)
                    - std::f32::consts::PI
            };
            self.last_wrapped[k] = wrapped;
        }
        if self.frames == 0 {
            self.previous = self.phases;
        }
        if self.amplitude_history.len() == 64 {
            self.amplitude_history.pop_front();
        }
        if self.phase_history.len() == 20 {
            self.phase_history.pop_front();
        }
        self.amplitude_history.push_back(self.amplitudes);
        self.phase_history.push_back(self.phases);
        let mut phase_variance = [0f32; 64];
        for k in 0..64 {
            self.variances[k] = variance(
                self.amplitude_history.iter().map(|v| v[k]),
                self.amplitude_history.len(),
            );
            phase_variance[k] = variance(
                self.phase_history.iter().map(|v| v[k]),
                self.phase_history.len(),
            );
        }
        self.motion = phase_variance.into_iter().fold(0., f32::max);
        self.frames += 1;
    }

    pub fn view(&self) -> CsiFrameView<'_> {
        CsiFrameView {
            phases: &self.phases,
            amplitudes: &self.amplitudes,
            variances: &self.variances,
            prev_phases: &self.previous,
            // Audited selected adapters never read these unavailable inputs.
            // Poison values catch accidental floating-point use in new wiring.
            presence: -1,
            n_persons: -1,
            breathing_bpm: f32::NAN,
            heartrate_bpm: f32::NAN,
            coherence: f32::NAN,
            motion_energy: self.motion,
            variance_mean: self.variances.iter().sum::<f32>() / 64.,
        }
    }
}

#[derive(Default)]
pub struct Cadence {
    intervals: VecDeque<u64>,
}
impl Cadence {
    pub fn push(&mut self, ns: u64) {
        if self.intervals.len() == 60 {
            self.intervals.pop_front();
        }
        self.intervals.push_back(ns);
    }
    pub fn rate(&self) -> Option<f64> {
        let sum = self.intervals.iter().copied().sum::<u64>();
        (sum > 0).then(|| self.intervals.len() as f64 * 1e9 / sum as f64)
    }
    pub fn qualifies(&self, hz: u32) -> bool {
        if hz == 0 {
            return true;
        }
        if self.intervals.len() < 40 {
            return false;
        }
        let period = 1e9 / f64::from(hz);
        let mean =
            self.intervals.iter().map(|v| *v as f64).sum::<f64>() / self.intervals.len() as f64;
        let sd = (self
            .intervals
            .iter()
            .map(|v| (*v as f64 - mean).powi(2))
            .sum::<f64>()
            / self.intervals.len() as f64)
            .sqrt();
        (mean - period).abs() <= period * 0.1
            && sd / mean <= 0.2
            && self
                .intervals
                .iter()
                .all(|v| *v as f64 <= period * 1.5 && *v as f64 >= period * 0.5)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn cadence_requires_real_stable_observations() {
        let mut c = Cadence::default();
        for _ in 0..39 {
            c.push(50_000_000);
        }
        assert!(!c.qualifies(20));
        c.push(50_000_000);
        assert!(c.qualifies(20));
        assert!(!c.qualifies(50));
        c.push(200_000_000);
        assert!(!c.qualifies(20));
        for _ in 0..60 {
            c.push(32_000_000);
        }
        assert!(!c.qualifies(20));
        assert!(!c.qualifies(50));
    }
    #[test]
    fn phase_unwrap_and_bounded_features() {
        let mut f = Features::default();
        let mut p = crate::packet::parse(&crate::packet::fixture(1, 1), &[1]).unwrap();
        p.iq.fill(-100);
        for k in 0..64 {
            p.iq[k * 2 + 1] = 1;
        }
        f.update(&p);
        let phase = f.phases[0];
        for k in 0..64 {
            p.iq[k * 2 + 1] = -1;
        }
        f.update(&p);
        assert!((f.phases[0] - phase).abs() < 0.1);
        for _ in 0..1000 {
            f.update(&p);
        }
        assert_eq!(f.amplitude_history.len(), 64);
        assert_eq!(f.phase_history.len(), 20);
        assert_eq!(f.motion, 0.);
        assert!(f.view().breathing_bpm.is_nan());
    }
    #[test]
    fn asymmetric_pair_locks_explicit_legacy_ruview_convention() {
        let mut f = Features::default();
        let mut p = crate::packet::parse(&crate::packet::fixture(1, 1), &[1]).unwrap();
        p.iq[0] = 3;
        p.iq[1] = 4;
        f.update(&p);
        assert_eq!(f.amplitudes[0], 5.);
        assert!((f.phases[0] - 4f32.atan2(3.)).abs() < 1e-6);
        assert_eq!(p.iq[0..2], [3, 4]);
    }
}
