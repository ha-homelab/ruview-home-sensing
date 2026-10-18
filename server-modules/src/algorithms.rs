use wifi_densepose_wasm_edge::sig_temporal_compress::TemporalCompressor;
use wifi_densepose_wasm_edge::{
    pipeline_all::{CsiFrameView, EdgeSkill},
    skill_registry::*,
};

pub enum Algorithm {
    Native(Box<dyn EdgeSkill>),
    Compression(Box<TemporalCompressor>, u64),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::features::Features;

    #[test]
    fn tailgate_adapter_counts_300_peaks_without_reading_unavailable_inputs() {
        let mut algorithm = Algorithm::create("sec_tailgating");
        let features = Features::default();
        let mut view = features.view();
        assert_eq!(view.presence, -1);
        assert_eq!(view.n_persons, -1);
        assert!(view.breathing_bpm.is_nan());
        view.variance_mean = 0.1;
        for _ in 0..300 {
            // The real native debounce sees a rise, sustained peak and valley.
            for energy in [5.0, 5.0, 0.0] {
                view.motion_energy = energy;
                assert!(algorithm.process(&view, 0).is_empty());
            }
        }
        view.motion_energy = 0.0;
        let events: Vec<_> = (0..60).flat_map(|_| algorithm.process(&view, 0)).collect();
        assert_eq!(events, vec![(230, 300.0), (232, 300.0)]);
        assert!(algorithm.process(&view, 0).is_empty());
    }
}
impl Algorithm {
    pub fn create(name: &str) -> Self {
        macro_rules! boxed {
            ($ty:ty) => {
                Self::Native(Box::new(<$ty>::new()))
            };
        }
        match name {
            "gesture" => boxed!(GestureAdapter),
            "coherence" => boxed!(CoherenceAdapter),
            "adversarial" => boxed!(AdversarialAdapter),
            "occupancy" => boxed!(OccupancyAdapter),
            "intrusion" => boxed!(IntrusionAdapter),
            "sec_perimeter_breach" => boxed!(SecPerimeterAdapter),
            // This adapter ignores unavailable presence/count inputs. The host
            // supplies genuine motion/variance features and enforces 20 Hz.
            "sec_tailgating" => boxed!(SecTailgateAdapter),
            "bld_lighting_zones" => boxed!(BldLightingAdapter),
            "ret_customer_flow" => boxed!(RetFlowAdapter),
            "exo_time_crystal" => boxed!(ExoTimeCrystalAdapter),
            "exo_music_conductor" => boxed!(ExoMusicAdapter),
            "sig_coherence_gate" => boxed!(SigCoherenceGateAdapter),
            "sig_flash_attention" => boxed!(SigFlashAttnAdapter),
            "sig_sparse_recovery" => boxed!(SparseRecoveryAdapter),
            "sig_optimal_transport" => boxed!(SigTransportAdapter),
            "lrn_dtw_gesture_learn" => boxed!(LrnDtwAdapter),
            "lrn_anomaly_attractor" => boxed!(LrnAttractorAdapter),
            "spt_spiking_tracker" => boxed!(SptSpikingAdapter),
            "ais_prompt_shield" => boxed!(AisPromptShieldAdapter),
            "qnt_quantum_coherence" => boxed!(QntCoherenceAdapter),
            "sig_temporal_compress" => Self::Compression(Box::new(TemporalCompressor::new()), 0),
            _ => panic!("unreviewed selected algorithm"),
        }
    }
    pub fn process(&mut self, view: &CsiFrameView<'_>, mono_ns: u64) -> Vec<(i32, f32)> {
        match self {
            Self::Native(skill) => skill.on_frame(view).to_vec(),
            Self::Compression(compressor, last_timer) => {
                // The upstream registry drives only on_timer(), losing actual CSI.
                // Feed real features and actual receipt cadence; no fabricated 20Hz.
                let mut events = compressor
                    .push_frame(view.phases, view.amplitudes, (mono_ns / 1_000_000) as u32)
                    .to_vec();
                if mono_ns.saturating_sub(*last_timer) >= 1_000_000_000 {
                    *last_timer = mono_ns;
                    events.extend_from_slice(compressor.on_timer());
                }
                // Its history-hours estimator starts with a nominal rate. Suppress
                // that estimate until 200 actual timing observations have displaced it.
                if compressor.total_written() < 200 {
                    events.retain(|v| v.0 != 707);
                }
                events
            }
        }
    }
}
