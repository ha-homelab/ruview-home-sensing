use crate::{
    algorithms::Algorithm,
    features::{Cadence, Features},
    fleet::{Fleet, QualityInput},
    packet::Packet,
};
use serde_json::{json, Value};
use std::{
    collections::{BTreeMap, VecDeque},
    panic::{catch_unwind, AssertUnwindSafe},
    time::Instant,
};

pub const FRESH_NS: u64 = 2_000_000_000;
const EPOCH_MAX_FRAMES: u64 = 1_000_000;
const CALLBACK_MAX_US: u64 = 50_000;
const FEATURE_WARMUP: u64 = 64;
const RECENT_PACKET_LIMIT: usize = 64;
pub const MAX_PUBLISHED_EVENTS_PER_NODE: usize = 64;
// Next source revision; the frozen r4/r5 releases retain 20 selections.
pub const SELECTED_ALGORITHM_COUNT: usize = 21;

#[derive(Clone, Copy, Debug)]
pub struct Stamp {
    pub utc_ns: u64,
    pub mono_ns: u64,
}

struct Slot {
    meta: Value,
    algorithm: Option<Algorithm>,
    frames: u64,
    events: u64,
    max_us: u64,
    active: bool,
    fault: Option<&'static str>,
}
impl Slot {
    fn new(meta: Value) -> Self {
        let algorithm = meta["selected"]
            .as_bool()
            .unwrap()
            .then(|| Algorithm::create(meta["algorithm"].as_str().unwrap()));
        Self {
            meta,
            algorithm,
            frames: 0,
            events: 0,
            max_us: 0,
            active: false,
            fault: None,
        }
    }
    fn reset(&mut self) {
        if self.algorithm.is_some() {
            self.algorithm = Some(Algorithm::create(self.meta["algorithm"].as_str().unwrap()));
        }
        self.active = false;
        self.frames = 0;
        self.events = 0;
        self.max_us = 0;
        self.fault = None;
    }
}

struct Node {
    id: u8,
    epoch: u64,
    epoch_reason: &'static str,
    packet: Option<Packet>,
    stamp: Option<Stamp>,
    recent_packets: VecDeque<(Packet, Stamp)>,
    frames: u64,
    duplicates: u64,
    missing_sequences: u64,
    discontinuities: u64,
    cadence: Cadence,
    features: Features,
    slots: Vec<Slot>,
    events: BTreeMap<(String, String), Vec<Value>>,
    occurrence: u64,
}
impl Node {
    fn new(id: u8, catalog: &[Value]) -> Self {
        Self {
            id,
            epoch: 0,
            epoch_reason: "awaiting_csi",
            packet: None,
            stamp: None,
            recent_packets: VecDeque::with_capacity(RECENT_PACKET_LIMIT),
            frames: 0,
            duplicates: 0,
            missing_sequences: 0,
            discontinuities: 0,
            cadence: Cadence::default(),
            features: Features::default(),
            slots: catalog.iter().cloned().map(Slot::new).collect(),
            events: BTreeMap::new(),
            occurrence: 0,
        }
    }
    fn reset(&mut self, reason: &'static str) {
        self.epoch += 1;
        self.epoch_reason = reason;
        self.features = Features::default();
        self.cadence = Cadence::default();
        self.recent_packets.clear();
        self.events.clear();
        for slot in &mut self.slots {
            slot.reset();
        }
    }
    fn process(&mut self, packet: Packet, stamp: Stamp, run_id: &str) -> bool {
        // Keep original receipt times: repeated traffic cannot renew this cache.
        self.recent_packets.retain(|(_, original)| {
            stamp
                .mono_ns
                .checked_sub(original.mono_ns)
                .is_some_and(|age| age <= FRESH_NS)
        });
        let mut reason = None;
        if let (Some(old), Some(last)) = (&self.packet, self.stamp) {
            let delta = packet.sequence.wrapping_sub(old.sequence);
            // Even after cache expiry, replaying the current packet must not
            // turn its old measurement into fresh evidence.
            if packet == *old {
                self.duplicates += 1;
                return false;
            }
            let elapsed = stamp.mono_ns.saturating_sub(last.mono_ns);
            let clock_error =
                (i128::from(stamp.utc_ns) - i128::from(last.utc_ns) - i128::from(elapsed)).abs();
            if delta == 0 {
                reason = Some("sequence_conflict_boot_unknown");
                self.discontinuities += 1;
            } else if stamp.mono_ns <= last.mono_ns || clock_error > 250_000_000 {
                reason = Some("receipt_clock_discontinuity");
            } else if !old.grid.same_physical_grid(&packet.grid) {
                reason = Some("grid_changed");
            } else if delta >= 0x8000_0000 {
                // Recognize only complete packet content already accepted in
                // this epoch. An unseen/changed old sequence is still unknown.
                if self.recent_packets.iter().any(|(seen, _)| *seen == packet) {
                    self.duplicates += 1;
                    return false;
                }
                reason = Some("sequence_backwards_boot_unknown");
                self.discontinuities += 1;
            } else if delta > 1 {
                reason = Some("sequence_gap");
                self.missing_sequences += u64::from(delta - 1);
            } else if elapsed > FRESH_NS {
                reason = Some("receipt_gap");
            } else if self.features.frames >= EPOCH_MAX_FRAMES {
                reason = Some("bounded_history_renewal");
            } else {
                self.cadence.push(elapsed);
            }
        } else {
            reason = Some("first_frame");
        }
        if let Some(reason) = reason {
            self.reset(reason);
        }
        self.features.update(&packet);
        self.frames += 1;
        self.stamp = Some(stamp);
        for slot in &mut self.slots {
            if slot.algorithm.is_none() || slot.fault.is_some() {
                continue;
            }
            let hz = slot.meta["required_cadence_hz"].as_u64().unwrap() as u32;
            let eligible = self.features.frames >= FEATURE_WARMUP && self.cadence.qualifies(hz);
            if !eligible {
                if slot.active {
                    slot.reset();
                    self.events
                        .retain(|(name, _), _| name != slot.meta["algorithm"].as_str().unwrap());
                }
                continue;
            }
            slot.active = true;
            let started = Instant::now();
            let output = catch_unwind(AssertUnwindSafe(|| {
                slot.algorithm
                    .as_mut()
                    .unwrap()
                    .process(&self.features.view(), stamp.mono_ns)
            }));
            let elapsed = started.elapsed().as_micros().min(u128::from(u64::MAX)) as u64;
            slot.max_us = slot.max_us.max(elapsed);
            slot.frames += 1;
            let events = match output {
                Ok(events) if elapsed <= CALLBACK_MAX_US => events,
                Ok(_) => {
                    slot.fault = Some("host_callback_budget_exceeded");
                    Vec::new()
                }
                Err(_) => {
                    slot.fault = Some("algorithm_panicked");
                    Vec::new()
                }
            };
            // A callback with invalid/undeclared outputs fails as a whole.
            if events.len() > 16
                || events.iter().any(|(id, v)| {
                    *id < 0 || !v.is_finite() || slot.meta["events"].get(id.to_string()).is_none()
                })
            {
                slot.fault = Some("invalid_algorithm_output");
            }
            if slot.fault.is_some() {
                self.events
                    .retain(|(name, _), _| name != slot.meta["algorithm"].as_str().unwrap());
                continue;
            }
            // Replace a type's previous callback batch, keeping every same-ID
            // group occurrence from this callback (upstream emits several).
            for (id, _) in &events {
                self.events.remove(&(
                    slot.meta["algorithm"].as_str().unwrap().to_owned(),
                    id.to_string(),
                ));
            }
            for (id, value) in events {
                self.occurrence += 1;
                slot.events += 1;
                let event_id = (id as u32).to_string();
                let details = &slot.meta["events"][&event_id];
                let name = slot.meta["algorithm"].as_str().unwrap();
                let event = json!({"worker_run_id":run_id,"node_id":self.id,"node_epoch":self.epoch,
                    "occurrence_seq":self.occurrence.to_string(),"algorithm":name,
                    "algorithm_version":slot.meta["algorithm_version"],"source_sha256":slot.meta["source_sha256"],
                    "event_id":event_id,"event_name":details["event_name"],"meaning":details["meaning"],
                    "value_type":details["value_type"],"units":details["units"],"value":value,
                    "observed_at_ns":stamp.utc_ns.to_string(),"observed_monotonic_ns":stamp.mono_ns.to_string(),
                    "source_sequence":packet.sequence,"age_ms":0,"fresh":true,
                    "classification":"experimental","recognition_validated":false,"source":"esp32","execution":"server"});
                self.events
                    .entry((name.to_owned(), event_id))
                    .or_default()
                    .push(event);
            }
        }
        if self.recent_packets.len() == RECENT_PACKET_LIMIT {
            self.recent_packets.pop_front();
        }
        self.recent_packets.push_back((packet.clone(), stamp));
        self.packet = Some(packet);
        true
    }
    fn coherence_input(&self) -> Option<QualityInput> {
        let slot = self
            .slots
            .iter()
            .find(|slot| slot.meta["algorithm"] == "coherence")?;
        // The native coherence constructor returns1.0 without a phase delta.
        // Only subsequent successful callbacks provide measured quality.
        if !slot.active || slot.fault.is_some() || slot.frames < 2 {
            return None;
        }
        let event = self
            .events
            .get(&("coherence".to_owned(), "2".to_owned()))?
            .last()?;
        let stamp = self.stamp?;
        let packet = self.packet.as_ref()?;
        if event["node_epoch"] != self.epoch || event["source_sequence"] != packet.sequence {
            return None;
        }
        Some(QualityInput {
            node_id: self.id,
            node_epoch: self.epoch,
            sequence: packet.sequence,
            stamp,
            quality: event["value"].as_f64()? as f32,
            occurrence_seq: event["occurrence_seq"].as_str()?.to_owned(),
            algorithm_version: event["algorithm_version"].as_str()?.to_owned(),
            source_sha256: event["source_sha256"].as_str()?.to_owned(),
        })
    }
    fn snapshot(&self) -> Value {
        let algorithms:Vec<_>=self.slots.iter().map(|slot| {
            let (availability,reason)=if slot.algorithm.is_none() { ("unavailable",slot.meta["reason"].as_str().unwrap()) }
                else if let Some(reason)=slot.fault { ("faulted",reason) }
                else if self.features.frames<FEATURE_WARMUP { ("warming_up","requires_64_contiguous_frames") }
                else if !self.cadence.qualifies(slot.meta["required_cadence_hz"].as_u64().unwrap() as u32) { ("ineligible","measured_cadence_does_not_qualify") }
                else { ("running","raw_csi_experimental") };
            json!({"algorithm":slot.meta["algorithm"],"algorithm_version":slot.meta["algorithm_version"],
                "source_sha256":slot.meta["source_sha256"],"availability":availability,"reason":reason,
                "required_cadence_hz":slot.meta["required_cadence_hz"],"processed_frames":slot.frames,
                "emitted_events":slot.events,"max_execution_us":slot.max_us,"recognition_validated":false})
        }).collect();
        json!({"node_id":self.id,"node_epoch":self.epoch,"epoch_reason":self.epoch_reason,
            "sequence":self.packet.as_ref().map(|p|p.sequence),"grid":self.packet.as_ref().map(|p|p.grid),
            "last_received_at_ns":self.stamp.map(|s|s.utc_ns.to_string()),
            "last_received_monotonic_ns":self.stamp.map(|s|s.mono_ns.to_string()),
            "age_ms":Value::Null,"fresh":false,"cadence_hz":self.cadence.rate(),
            "cadence_qualified_20hz":self.cadence.qualifies(20),"cadence_qualified_50hz":self.cadence.qualifies(50),
            "frames":self.frames,"epoch_frames":self.features.frames,"duplicates":self.duplicates,
            "missing_sequences":self.missing_sequences,"sequence_discontinuities":self.discontinuities,
            "algorithms":algorithms,"physical_position":Value::Null,"pose":Value::Null,
            "physical_inference_reason":"requires_commissioned_geometry_and_validated_model"})
    }
}

pub struct Engine {
    nodes: BTreeMap<u8, Node>,
    run_id: String,
    clock_id: String,
    configuration_sha256: String,
    fleet: Fleet,
}
impl Engine {
    pub fn new(
        nodes: &[u8],
        run_id: &str,
        clock_id: &str,
        config_sha: &str,
        provenance: &Value,
    ) -> Self {
        let mut catalog: Vec<Value> =
            serde_json::from_str(include_str!("../algorithms.json")).unwrap();
        assert_eq!(catalog.len(), 64);
        assert_eq!(
            catalog.iter().filter(|v| v["selected"] == true).count(),
            SELECTED_ALGORITHM_COUNT
        );
        for entry in &mut catalog {
            let path = entry["source_path"].as_str().unwrap();
            let hash = provenance["upstream_files_sha256"][path]
                .as_str()
                .expect("missing exact algorithm hash")
                .to_owned();
            assert_eq!(hash.len(), 64);
            entry["source_sha256"] = json!(hash);
        }
        Self {
            fleet: Fleet::new(
                catalog
                    .iter()
                    .find(|meta| meta["fleet_selected"] == true)
                    .expect("fleet catalog entry")
                    .clone(),
                run_id,
                nodes,
            ),
            nodes: nodes
                .iter()
                .map(|id| (*id, Node::new(*id, &catalog)))
                .collect(),
            run_id: run_id.to_owned(),
            clock_id: clock_id.to_owned(),
            configuration_sha256: config_sha.to_owned(),
        }
    }
    pub fn process(&mut self, packet: Packet, stamp: Stamp) -> bool {
        let accepted = self
            .nodes
            .get_mut(&packet.node_id)
            .expect("parser node allowlist")
            .process(packet, stamp, &self.run_id);
        if accepted {
            let members = self
                .nodes
                .values()
                .map(|node| (node.id, node.epoch, node.coherence_input()))
                .collect();
            self.fleet.update(members, stamp);
        }
        accepted
    }
    pub fn snapshot(&self) -> Value {
        let mut nodes = Vec::with_capacity(self.nodes.len());
        let mut events = Vec::new();
        for node in self.nodes.values() {
            let mut recent: Vec<_> = node.events.values().flatten().cloned().collect();
            recent.sort_by_key(|event| {
                std::cmp::Reverse(
                    event["occurrence_seq"]
                        .as_str()
                        .unwrap()
                        .parse::<u64>()
                        .unwrap(),
                )
            });
            let omitted = recent.len().saturating_sub(MAX_PUBLISHED_EVENTS_PER_NODE);
            recent.truncate(MAX_PUBLISHED_EVENTS_PER_NODE);
            events.extend(recent);
            let mut state = node.snapshot();
            state["omitted_events"] = json!(omitted);
            nodes.push(state);
        }
        let mut fleet = self.fleet.snapshot();
        fleet["clock_id"] = json!(self.clock_id);
        fleet["configuration_sha256"] = json!(self.configuration_sha256);
        json!({"schema":"ruview.server-modules.v1","worker_run_id":self.run_id,"clock_id":self.clock_id,
            "monotonic_origin":"worker_start","configuration_sha256":self.configuration_sha256,
            "recognition_validated":false,"freshness_limit_ms":FRESH_NS/1_000_000,"catalog_count":64,"selected_algorithm_count":SELECTED_ALGORITHM_COUNT,
            "selected_fleet_algorithm_count":1,"fleet":fleet,
            "events_per_node_limit":MAX_PUBLISHED_EVENTS_PER_NODE,"nodes":nodes,"events":events})
    }
}

/// Called at each HTTP response, including when the processing thread is idle.
/// Publication never advances the original timestamps or occurrence identity.
pub fn age_snapshot(snapshot: &mut Value, now: Stamp) {
    snapshot["generated_at_ns"] = json!(now.utc_ns.to_string());
    crate::fleet::age_snapshot(&mut snapshot["fleet"], now);
    if let Some(nodes) = snapshot["nodes"].as_array_mut() {
        for node in nodes {
            let observed = node["last_received_monotonic_ns"]
                .as_str()
                .and_then(|v| v.parse::<u64>().ok());
            let age = observed.and_then(|v| now.mono_ns.checked_sub(v));
            let fresh = age.is_some_and(|a| a <= FRESH_NS);
            node["age_ms"] = age.map(|v| json!(v / 1_000_000)).unwrap_or(Value::Null);
            node["fresh"] = json!(fresh);
            if !fresh {
                for algorithm in node["algorithms"].as_array_mut().unwrap() {
                    if algorithm["availability"] == "running" {
                        algorithm["availability"] = json!("stale");
                        algorithm["reason"] = json!("csi_receipt_expired");
                    }
                }
            }
        }
    }
    if let Some(events) = snapshot["events"].as_array_mut() {
        for event in events {
            let observed = event["observed_monotonic_ns"]
                .as_str()
                .and_then(|v| v.parse::<u64>().ok());
            let age = observed.and_then(|v| now.mono_ns.checked_sub(v));
            event["age_ms"] = age.map(|v| json!(v / 1_000_000)).unwrap_or(Value::Null);
            event["fresh"] = json!(age.is_some_and(|a| a <= FRESH_NS));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn engine() -> Engine {
        let catalog: Vec<Value> = serde_json::from_str(include_str!("../algorithms.json")).unwrap();
        let files = catalog
            .iter()
            .map(|v| {
                (
                    v["source_path"].as_str().unwrap().to_owned(),
                    json!("a".repeat(64)),
                )
            })
            .collect::<serde_json::Map<_, _>>();
        Engine::new(
            &[1, 2, 3],
            "run-test",
            "clock-test",
            &"b".repeat(64),
            &json!({"upstream_files_sha256":files}),
        )
    }
    fn feed(engine: &mut Engine, node: u8, seq: u32, mono: u64) {
        engine.process(
            crate::packet::parse(&crate::packet::fixture(node, seq), &[1, 2, 3]).unwrap(),
            Stamp {
                utc_ns: 1_000_000_000_000 + mono,
                mono_ns: mono,
            },
        );
    }
    #[test]
    fn real_native_algorithms_are_isolated_and_cadence_gated() {
        let mut e = engine();
        for seq in 0..300 {
            feed(&mut e, 1, seq, u64::from(seq) * 32_000_000);
            feed(&mut e, 2, seq, u64::from(seq) * 50_000_000);
        }
        let s = e.snapshot();
        let n = &s["nodes"][0];
        assert_eq!(n["algorithms"].as_array().unwrap().len(), 64);
        assert_eq!(
            n["algorithms"]
                .as_array()
                .unwrap()
                .iter()
                .filter(|a| a["availability"] == "unavailable")
                .count(),
            43
        );
        assert!(n["algorithms"]
            .as_array()
            .unwrap()
            .iter()
            .any(|a| a["algorithm"] == "gesture" && a["availability"] == "ineligible"));
        assert!(s["nodes"][1]["algorithms"]
            .as_array()
            .unwrap()
            .iter()
            .any(|a| a["algorithm"] == "gesture" && a["availability"] == "running"));
        assert_eq!(s["nodes"][2]["frames"], 0);
        assert!(s["events"]
            .as_array()
            .unwrap()
            .iter()
            .any(|a| a["event_id"] == "850"));
        assert!(s["nodes"]
            .as_array()
            .unwrap()
            .iter()
            .flat_map(|n| n["algorithms"].as_array().unwrap())
            .all(|a| a["availability"] != "faulted"));
    }

    fn feed_iq(e: &mut Engine, seq: &mut u32, mono: &mut u64, pair: [i8; 2]) {
        let mut packet = crate::packet::parse(&crate::packet::fixture(1, *seq), &[1]).unwrap();
        for iq in packet.iq.chunks_mut(2) {
            iq.copy_from_slice(&pair);
        }
        assert!(e.process(
            packet,
            Stamp {
                utc_ns: 1_000_000_000_000 + *mono,
                mono_ns: *mono
            }
        ));
        *seq += 1;
        *mono += 50_000_000;
    }

    fn tailgate_events(snapshot: &Value) -> Vec<Value> {
        snapshot["events"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|v| v["algorithm"] == "sec_tailgating")
            .cloned()
            .collect()
    }

    fn tailgate_status(snapshot: &Value) -> &Value {
        snapshot["nodes"][0]["algorithms"]
            .as_array()
            .unwrap()
            .iter()
            .find(|v| v["algorithm"] == "sec_tailgating")
            .unwrap()
    }

    fn two_raw_rotation_bursts() -> (Engine, u32, u64) {
        fn step(e: &mut Engine, seq: &mut u32, mono: &mut u64, pair: [i8; 2]) {
            feed_iq(e, seq, mono, pair);
            // Independently calculated 20-sample phase-variance landmarks for
            // this unit-circle input. They expose the descending-tail re-arm:
            // the first peak ends below 30% of its ~77.50 maximum, then the next
            // frame is still above the absolute 2.0 start threshold.
            let bounds = match *seq - 1 {
                83 | 110 | 134 | 161 => Some((3.0, 3.5)),
                106 | 157 => Some((17.5, 18.5)),
                107 | 158 => Some((12.5, 13.5)),
                _ => None,
            };
            if let Some((low, high)) = bounds {
                let motion = e.nodes[&1].features.motion;
                assert!(motion > low && motion < high, "raw fixture phase variance");
            }
        }
        let mut e = engine();
        let (mut seq, mut mono) = (0, 0);
        for _ in 0..80 {
            step(&mut e, &mut seq, &mut mono, [64, 0]);
        }
        // Equal-amplitude signed IQ rotating through four quadrants produces
        // two rotation bursts through the real Features pipeline, not injected
        // presence/count or motion fields. A burst is NOT one native peak:
        // Watching immediately re-arms on a descending tail still above 2.0.
        for burst in 0..2 {
            for k in 0..16 {
                let pair = [[0, 64], [-64, 0], [0, -64], [64, 0]][k % 4];
                step(&mut e, &mut seq, &mut mono, pair);
            }
            if burst == 0 {
                for _ in 0..35 {
                    step(&mut e, &mut seq, &mut mono, [64, 0]);
                }
            }
        }
        for _ in 0..100 {
            step(&mut e, &mut seq, &mut mono, [64, 0]);
            if !tailgate_events(&e.snapshot()).is_empty() {
                return (e, seq, mono);
            }
        }
        panic!("raw IQ rotation bursts did not produce a native cluster");
    }

    #[test]
    fn tailgate_real_features_emit_peak_counts_and_expire_without_refresh() {
        let (e, _seq, mono) = two_raw_rotation_bursts();
        let mut s = e.snapshot();
        let original = tailgate_events(&s);
        assert_eq!(original.len(), 2);
        for event in &original {
            // Peak ends are at source sequences 106, 110, 157, 161. The last
            // is followed by 60 quiet frames; both correlated events carry 4.
            assert_eq!(event["value"], 4.0);
            assert_eq!(event["source_sequence"], 221);
            assert_eq!(event["units"], "motion_peaks");
            assert_eq!(event["recognition_validated"], false);
            assert_eq!(event["algorithm_version"], "0.3.0+home-server.2");
        }
        assert_eq!(tailgate_status(&s)["availability"], "running");
        age_snapshot(
            &mut s,
            Stamp {
                utc_ns: 1_000_000_000_000 + mono + FRESH_NS,
                mono_ns: mono + FRESH_NS,
            },
        );
        assert_eq!(tailgate_status(&s)["availability"], "stale");
        let expired = tailgate_events(&s);
        for (old, new) in original.iter().zip(&expired) {
            assert_eq!(old["occurrence_seq"], new["occurrence_seq"]);
            assert_eq!(old["observed_monotonic_ns"], new["observed_monotonic_ns"]);
            assert_eq!(new["fresh"], false);
        }
    }

    #[test]
    fn tailgate_cadence_loss_and_sequence_gap_clear_events_and_native_state() {
        let (mut e, mut seq, mut mono) = two_raw_rotation_bursts();
        mono += 450_000_000; // 500ms interval, below the receipt-gap boundary.
        feed_iq(&mut e, &mut seq, &mut mono, [64, 0]);
        let s = e.snapshot();
        assert_eq!(s["nodes"][0]["node_epoch"], 1);
        assert_eq!(tailgate_status(&s)["availability"], "ineligible");
        assert_eq!(tailgate_status(&s)["processed_frames"], 0);
        assert!(tailgate_events(&s).is_empty());
        for _ in 0..80 {
            feed_iq(&mut e, &mut seq, &mut mono, [64, 0]);
        }
        assert_eq!(tailgate_status(&e.snapshot())["availability"], "running");
        assert!(tailgate_events(&e.snapshot()).is_empty());
        seq += 1; // A missing original sequence starts a new node epoch.
        feed_iq(&mut e, &mut seq, &mut mono, [64, 0]);
        let s = e.snapshot();
        assert_eq!(s["nodes"][0]["node_epoch"], 2);
        assert_eq!(tailgate_status(&s)["availability"], "warming_up");
        assert_eq!(tailgate_status(&s)["processed_frames"], 0);
        assert!(tailgate_events(&s).is_empty());
    }
    #[test]
    fn duplicate_and_polling_never_refresh_evidence() {
        let mut e = engine();
        for s in 0..80 {
            feed(&mut e, 1, s, u64::from(s) * 32_000_000);
        }
        let before = e.snapshot();
        feed(&mut e, 1, 79, 5_000_000_000);
        let mut after = e.snapshot();
        assert_eq!(before["events"], after["events"]);
        age_snapshot(
            &mut after,
            Stamp {
                utc_ns: 0,
                mono_ns: 5_000_000_000,
            },
        );
        assert_eq!(after["nodes"][0]["fresh"], false);
        assert!(after["events"]
            .as_array()
            .unwrap()
            .iter()
            .all(|e| e["fresh"] == false && e["age_ms"].as_u64().unwrap() > 2000));
    }
    #[test]
    fn exact_late_duplicate_preserves_analysis_fleet_and_original_times() {
        let mut e = engine();
        for seq in 0..80 {
            for node in 1..=3 {
                feed(&mut e, node, seq, u64::from(seq) * 32_000_000);
            }
        }
        let mut expected = e.snapshot();
        expected["nodes"][0]["duplicates"] = json!(1);
        feed(&mut e, 1, 77, 2_550_000_000);
        assert_eq!(e.snapshot(), expected);
        feed(&mut e, 1, 80, 2_560_000_000);
        let after = e.snapshot();
        assert_eq!(after["nodes"][0]["node_epoch"], 1);
        assert_eq!(after["nodes"][0]["frames"], 81);
        assert_eq!(after["nodes"][0]["missing_sequences"], 0);
        assert_eq!(after["nodes"][0]["sequence_discontinuities"], 0);
        assert_eq!(after["nodes"][0]["sequence"], 80);
        assert_eq!(after["nodes"][1], expected["nodes"][1]);
    }
    #[test]
    fn changed_content_at_the_same_sequence_is_not_a_duplicate() {
        for changed_field in ["iq", "rssi", "noise", "flags", "frequency"] {
            let mut e = engine();
            for seq in 0..80 {
                feed(&mut e, 1, seq, u64::from(seq) * 32_000_000);
            }
            let mut packet = crate::packet::parse(&crate::packet::fixture(1, 79), &[1]).unwrap();
            match changed_field {
                "iq" => packet.iq[127] += 1,
                "rssi" => packet.rssi_dbm += 1,
                "noise" => packet.noise_floor_dbm -= 1,
                "flags" => packet.grid.flags = 0x10,
                "frequency" => packet.grid.frequency_mhz = 2412,
                _ => unreachable!(),
            }
            assert!(e.process(
                packet,
                Stamp {
                    mono_ns: 2_560_000_000,
                    utc_ns: 1_002_560_000_000
                }
            ));
            let after = e.snapshot();
            let node = &after["nodes"][0];
            assert_eq!(node["node_epoch"], 2, "{changed_field}");
            assert_eq!(node["epoch_reason"], "sequence_conflict_boot_unknown");
            assert_eq!(node["sequence_discontinuities"], 1);
            assert_eq!(node["duplicates"], 0);
            assert_eq!(node["epoch_frames"], 1);
            assert!(after["events"].as_array().unwrap().is_empty());
        }
    }
    #[test]
    fn changed_or_unseen_late_packets_still_reset_unknown_history() {
        let mut e = engine();
        for seq in 0..4 {
            feed(&mut e, 1, seq, u64::from(seq) * 32_000_000);
        }
        let mut changed = crate::packet::parse(&crate::packet::fixture(1, 2), &[1]).unwrap();
        changed.iq[0] += 1;
        assert!(e.process(
            changed,
            Stamp {
                mono_ns: 128_000_000,
                utc_ns: 1_000_128_000_000
            }
        ));
        assert_eq!(
            e.snapshot()["nodes"][0]["epoch_reason"],
            "sequence_backwards_boot_unknown"
        );
        assert_eq!(e.snapshot()["nodes"][0]["duplicates"], 0);
        // A genuine gap ends the old epoch, including its duplicate cache.
        let mut e = engine();
        feed(&mut e, 1, 0, 0);
        feed(&mut e, 1, 2, 32_000_000);
        assert_eq!(e.nodes[&1].recent_packets.len(), 1);
        assert_eq!(e.nodes[&1].recent_packets[0].0.sequence, 2);
        feed(&mut e, 1, 1, 64_000_000);
        assert_eq!(e.snapshot()["nodes"][0]["node_epoch"], 3);
        assert_eq!(e.snapshot()["nodes"][0]["sequence_discontinuities"], 1);
        assert_eq!(e.snapshot()["nodes"][0]["missing_sequences"], 1);
        assert_eq!(e.snapshot()["nodes"][0]["duplicates"], 0);
    }
    #[test]
    fn late_duplicate_history_is_bounded_and_never_renewed_by_replay() {
        let mut e = engine();
        for seq in 0..70 {
            feed(&mut e, 1, seq, u64::from(seq) * 1_000_000);
        }
        assert_eq!(e.nodes[&1].recent_packets.len(), 64);
        feed(&mut e, 1, 6, 70_000_000);
        assert_eq!(e.snapshot()["nodes"][0]["duplicates"], 1);
        feed(&mut e, 1, 5, 71_000_000);
        assert_eq!(e.snapshot()["nodes"][0]["sequence_discontinuities"], 1);
        assert_eq!(e.snapshot()["nodes"][0]["node_epoch"], 2);

        let mut e = engine();
        feed(&mut e, 1, 0, 0);
        feed(&mut e, 1, 1, 500_000_000);
        feed(&mut e, 1, 2, 1_000_000_000);
        feed(&mut e, 1, 0, FRESH_NS);
        assert_eq!(e.snapshot()["nodes"][0]["duplicates"], 1);
        assert_eq!(e.nodes[&1].recent_packets[0].1.mono_ns, 0);
        feed(&mut e, 1, 0, FRESH_NS + 1);
        assert_eq!(e.snapshot()["nodes"][0]["duplicates"], 1);
        assert_eq!(e.snapshot()["nodes"][0]["sequence_discontinuities"], 1);
        assert_eq!(e.snapshot()["nodes"][0]["node_epoch"], 2);
    }
    #[test]
    fn matching_prior_epoch_packet_and_bad_receipt_clock_are_not_late_duplicates() {
        let mut e = engine();
        feed(&mut e, 1, 0, 0);
        feed(&mut e, 1, 2, 32_000_000);
        feed(&mut e, 1, 0, 64_000_000);
        assert_eq!(e.snapshot()["nodes"][0]["duplicates"], 0);
        assert_eq!(e.snapshot()["nodes"][0]["node_epoch"], 3);
        for bad_stamp in [
            Stamp {
                mono_ns: 20_000_000,
                utc_ns: 1_000_020_000_000,
            },
            Stamp {
                mono_ns: 128_000_000,
                utc_ns: 1_000_628_000_000,
            },
        ] {
            let mut e = engine();
            for seq in 0..4 {
                feed(&mut e, 1, seq, u64::from(seq) * 32_000_000);
            }
            let packet = crate::packet::parse(&crate::packet::fixture(1, 2), &[1]).unwrap();
            assert!(e.process(packet, bad_stamp));
            assert_eq!(
                e.snapshot()["nodes"][0]["epoch_reason"],
                "receipt_clock_discontinuity"
            );
            assert_eq!(e.snapshot()["nodes"][0]["duplicates"], 0);
            assert_eq!(e.nodes[&1].recent_packets.len(), 1);
        }
    }
    #[test]
    fn late_duplicate_across_u32_wrap_does_not_roll_back_the_baseline() {
        let mut e = engine();
        for (index, seq) in [u32::MAX - 2, u32::MAX - 1, u32::MAX, 0, 1]
            .into_iter()
            .enumerate()
        {
            feed(&mut e, 1, seq, index as u64 * 32_000_000);
        }
        feed(&mut e, 1, u32::MAX, 144_000_000);
        assert_eq!(e.snapshot()["nodes"][0]["sequence"], 1);
        feed(&mut e, 1, 2, 160_000_000);
        let after = e.snapshot();
        assert_eq!(after["nodes"][0]["node_epoch"], 1);
        assert_eq!(after["nodes"][0]["frames"], 6);
        assert_eq!(after["nodes"][0]["duplicates"], 1);
        assert_eq!(after["nodes"][0]["missing_sequences"], 0);
        assert_eq!(after["nodes"][0]["sequence_discontinuities"], 0);
    }
    #[test]
    fn complete_variance_window_precedes_any_algorithm_input() {
        let mut e = engine();
        for seq in 0..63 {
            feed(&mut e, 1, seq, u64::from(seq) * 32_000_000);
        }
        assert!(e.snapshot()["events"].as_array().unwrap().is_empty());
        assert!(e.snapshot()["nodes"][0]["algorithms"]
            .as_array()
            .unwrap()
            .iter()
            .all(|a| a["processed_frames"] == 0));
        feed(&mut e, 1, 63, 63 * 32_000_000);
        assert!(!e.snapshot()["events"].as_array().unwrap().is_empty());
    }
    #[test]
    fn fleet_uses_measured_coherence_events_not_initialization_or_variances() {
        let mut e = engine();
        for seq in 0..64 {
            for id in 1..=3 {
                feed(
                    &mut e,
                    id,
                    seq,
                    u64::from(seq) * 32_000_000 + u64::from(id) * 1_000_000,
                );
            }
        }
        let first = e.snapshot();
        assert_eq!(first["fleet"]["processed_cohorts"], 0);
        assert!(first["fleet"]["events"].as_array().unwrap().is_empty());
        for id in 1..=3 {
            feed(&mut e, id, 64, 64 * 32_000_000 + u64::from(id) * 1_000_000);
        }
        let s = e.snapshot();
        assert_eq!(s["catalog_count"], 64);
        assert_eq!(s["selected_algorithm_count"], SELECTED_ALGORITHM_COUNT);
        assert_eq!(s["selected_fleet_algorithm_count"], 1);
        assert_eq!(s["fleet"]["availability"], "running");
        assert_eq!(s["fleet"]["processed_cohorts"], 1);
        assert_eq!(s["fleet"]["worker_run_id"], s["worker_run_id"]);
        assert_eq!(s["fleet"]["clock_id"], s["clock_id"]);
        assert_eq!(
            s["fleet"]["configuration_sha256"],
            s["configuration_sha256"]
        );
        for input in s["fleet"]["member_inputs"].as_array().unwrap() {
            let event = s["events"]
                .as_array()
                .unwrap()
                .iter()
                .find(|v| v["algorithm"] == "coherence" && v["node_id"] == input["node_id"])
                .unwrap();
            assert_eq!(input["quality"], event["value"]);
            assert_eq!(input["occurrence_seq"], event["occurrence_seq"]);
            assert_eq!(input["source_sequence"], event["source_sequence"]);
            assert_eq!(
                input["observed_monotonic_ns"],
                event["observed_monotonic_ns"]
            );
        }
        assert!(s["events"]
            .as_array()
            .unwrap()
            .iter()
            .all(|v| v["algorithm"] != "aut_self_healing_mesh"));
        assert!(s["nodes"]
            .as_array()
            .unwrap()
            .iter()
            .all(|node| node["algorithms"]
                .as_array()
                .unwrap()
                .iter()
                .any(|a| a["algorithm"] == "aut_self_healing_mesh"
                    && a["availability"] == "unavailable")));
    }
    #[test]
    fn duplicate_node_input_does_not_republish_fleet_and_gap_clears_it() {
        let mut e = engine();
        for seq in 0..66 {
            for id in 1..=3 {
                feed(
                    &mut e,
                    id,
                    seq,
                    u64::from(seq) * 32_000_000 + u64::from(id) * 1_000_000,
                );
            }
        }
        let before = e.snapshot()["fleet"].clone();
        feed(&mut e, 1, 65, 2200_000_000);
        assert_eq!(e.snapshot()["fleet"], before);
        feed(&mut e, 1, 67, 2201_000_000);
        assert_eq!(e.snapshot()["fleet"]["availability"], "warming_up");
        assert!(e.snapshot()["fleet"]["events"]
            .as_array()
            .unwrap()
            .is_empty());
        assert_ne!(e.snapshot()["fleet"]["fleet_epoch"], before["fleet_epoch"]);
    }
    #[test]
    fn sync_valid_metadata_toggle_preserves_physical_feature_history() {
        let mut e = engine();
        for seq in 0..90 {
            let mut bytes = crate::packet::fixture(1, seq);
            bytes[19] = if seq % 2 == 0 {
                0
            } else {
                crate::packet::SYNC_VALID_METADATA
            };
            let p = crate::packet::parse(&bytes, &[1]).unwrap();
            let mono_ns = u64::from(seq) * 32_000_000;
            e.process(
                p,
                Stamp {
                    utc_ns: 1_000_000_000_000 + mono_ns,
                    mono_ns,
                },
            );
        }
        let snapshot = e.snapshot();
        assert_eq!(snapshot["nodes"][0]["node_epoch"], 1);
        assert_eq!(snapshot["nodes"][0]["epoch_frames"], 90);
        assert_eq!(snapshot["nodes"][0]["grid"]["flags"], 16);
        assert!(!snapshot["events"].as_array().unwrap().is_empty());
        let mut p = crate::packet::parse(&crate::packet::fixture(1, 90), &[1]).unwrap();
        p.grid.frequency_mhz = 2412;
        e.process(
            p,
            Stamp {
                utc_ns: 1_002_880_000_000,
                mono_ns: 2_880_000_000,
            },
        );
        assert_eq!(e.snapshot()["nodes"][0]["node_epoch"], 2);
        assert_eq!(e.snapshot()["nodes"][0]["epoch_reason"], "grid_changed");
        assert!(e.snapshot()["events"].as_array().unwrap().is_empty());
    }
    #[test]
    fn real_occupancy_adapter_preserves_all_same_id_group_occurrences() {
        let mut e = engine();
        for seq in 0..300 {
            feed(&mut e, 1, seq, u64::from(seq) * 32_000_000);
        }
        for seq in 300..330 {
            let mut p = crate::packet::parse(&crate::packet::fixture(1, seq), &[1]).unwrap();
            for k in 0..64 {
                p.iq[k * 2] = if k % 2 == 0 { 60 } else { 5 };
            }
            let mono_ns = u64::from(seq) * 32_000_000;
            e.process(
                p,
                Stamp {
                    utc_ns: 1_000_000_000_000 + mono_ns,
                    mono_ns,
                },
            );
        }
        let snapshot = e.snapshot();
        let mut groups: Vec<_> = snapshot["events"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|e| e["algorithm"] == "occupancy" && e["event_id"] == "300")
            .collect();
        groups.sort_by_key(|event| event["value"].as_f64().unwrap().floor() as usize);
        assert_eq!(groups.len(), 8);
        for (index, event) in groups.iter().enumerate() {
            assert_eq!(event["value"].as_f64().unwrap().floor() as usize, index);
            if index > 0 {
                assert_ne!(event["occurrence_seq"], groups[index - 1]["occurrence_seq"]);
            }
        }
        assert!(serde_json::to_vec(&snapshot).unwrap().len() < 1_048_576);
    }
    #[test]
    fn fifty_hz_spiking_path_runs_only_after_measured_qualification() {
        let mut e = engine();
        for seq in 0..150 {
            feed(&mut e, 3, seq, u64::from(seq) * 20_000_000);
        }
        let snapshot = e.snapshot();
        let algorithm = snapshot["nodes"][2]["algorithms"]
            .as_array()
            .unwrap()
            .iter()
            .find(|a| a["algorithm"] == "spt_spiking_tracker")
            .unwrap();
        assert_eq!(algorithm["availability"], "running");
        assert!(algorithm["processed_frames"].as_u64().unwrap() > 50);
        assert!(snapshot["events"]
            .as_array()
            .unwrap()
            .iter()
            .any(|e| e["algorithm"] == "spt_spiking_tracker"));
    }
    #[test]
    fn ten_nodes_have_bounded_http_publication_and_explicit_omissions() {
        let mut e = engine();
        e.run_id = "f".repeat(36);
        e.clock_id = "f".repeat(73);
        for seq in 0..80 {
            feed(&mut e, 1, seq, u64::from(seq) * 32_000_000);
        }
        let base = e.snapshot()["events"][0].clone();
        let catalog: Vec<_> = e.nodes[&1].slots.iter().map(|s| s.meta.clone()).collect();
        // Reviewed catalog: 63 prior IDs plus 3 tailgating IDs. The stress fixture
        // retains 16 same-ID occurrences, so 66*16=1056 cached per node; only 64
        // are published and 992 must be explicitly reported as omitted.
        assert_eq!(
            catalog
                .iter()
                .map(|meta| meta["events"].as_object().unwrap().len())
                .sum::<usize>(),
            66
        );
        for id in 4..=10 {
            e.nodes.insert(id, Node::new(id, &catalog));
        }
        for node in e.nodes.values_mut() {
            node.frames = u64::MAX;
            node.epoch = u64::MAX;
            node.features.frames = u64::MAX;
            node.duplicates = u64::MAX;
            node.missing_sequences = u64::MAX;
            node.discontinuities = u64::MAX;
            node.epoch_reason = "sequence_backwards_boot_unknown";
            node.packet = Some(
                crate::packet::parse(&crate::packet::fixture(node.id, u32::MAX), &[node.id])
                    .unwrap(),
            );
            node.stamp = Some(Stamp {
                utc_ns: u64::MAX,
                mono_ns: u64::MAX,
            });
            node.events.clear();
            let mut index = 0;
            for slot in &mut node.slots {
                slot.frames = u64::MAX;
                slot.events = u64::MAX;
                slot.max_us = u64::MAX;
                for (id, details) in slot.meta["events"].as_object().unwrap() {
                    for _ in 0..16 {
                        let mut event = base.clone();
                        for (key, value) in details.as_object().unwrap() {
                            event[key] = value.clone();
                        }
                        event["algorithm"] = slot.meta["algorithm"].clone();
                        event["source_sha256"] = slot.meta["source_sha256"].clone();
                        event["worker_run_id"] = json!(e.run_id);
                        event["node_id"] = json!(node.id);
                        event["node_epoch"] = json!(u64::MAX);
                        event["event_id"] = json!(id);
                        event["occurrence_seq"] = json!((u64::MAX - index).to_string());
                        event["observed_at_ns"] = json!(u64::MAX.to_string());
                        event["observed_monotonic_ns"] = json!(u64::MAX.to_string());
                        event["source_sequence"] = json!(u32::MAX);
                        event["value"] = json!(-3.4028234663852886e38f64);
                        event["age_ms"] = json!(u64::MAX);
                        event["fresh"] = json!(false);
                        node.events
                            .entry((
                                slot.meta["algorithm"].as_str().unwrap().to_owned(),
                                id.clone(),
                            ))
                            .or_default()
                            .push(event);
                        index += 1;
                    }
                }
            }
            assert_eq!(node.events.values().map(Vec::len).sum::<usize>(), 1056);
        }
        let mut snapshot = e.snapshot();
        snapshot["generated_at_ns"] = json!(u64::MAX.to_string());
        snapshot["counters"] = json!({"received":u64::MAX,"rejected":u64::MAX,"source_rejected":u64::MAX,"queue_dropped":u64::MAX,
            "processing_stale":u64::MAX,"record_dropped":u64::MAX,"record_written":u64::MAX,"record_error":u64::MAX,"record_limit_reached":u64::MAX});
        assert_eq!(snapshot["events"].as_array().unwrap().len(), 640);
        assert!(snapshot["nodes"]
            .as_array()
            .unwrap()
            .iter()
            .all(|n| n["omitted_events"] == 992));
        assert!(serde_json::to_vec(&snapshot).unwrap().len() < 1_048_576);
        // Publication truncation never destroys the bounded per-type batch cache.
        assert_eq!(
            e.nodes[&1].events.values().map(Vec::len).sum::<usize>(),
            1056
        );
    }
    #[test]
    fn invalid_callback_faults_only_its_algorithm_and_clears_cached_events() {
        use wifi_densepose_wasm_edge::pipeline_all::{CsiFrameView, EdgeSkill};
        struct Broken;
        impl EdgeSkill for Broken {
            fn name(&self) -> &'static str {
                "coherence"
            }
            fn event_ids(&self) -> &'static [i32] {
                &[2]
            }
            fn on_frame(&mut self, _: &CsiFrameView) -> &[(i32, f32)] {
                &[(2, f32::NAN)]
            }
        }
        let mut e = engine();
        for seq in 0..80 {
            feed(&mut e, 1, seq, u64::from(seq) * 32_000_000);
        }
        e.nodes
            .get_mut(&1)
            .unwrap()
            .slots
            .iter_mut()
            .find(|s| s.meta["algorithm"] == "coherence")
            .unwrap()
            .algorithm = Some(Algorithm::Native(Box::new(Broken)));
        feed(&mut e, 1, 80, 80 * 32_000_000);
        let snapshot = e.snapshot();
        assert!(snapshot["nodes"][0]["algorithms"]
            .as_array()
            .unwrap()
            .iter()
            .any(|a| a["algorithm"] == "coherence" && a["availability"] == "faulted"));
        assert!(snapshot["events"]
            .as_array()
            .unwrap()
            .iter()
            .all(|e| e["algorithm"] != "coherence"));
        assert!(snapshot["events"]
            .as_array()
            .unwrap()
            .iter()
            .any(|e| e["algorithm"] == "qnt_quantum_coherence"));
    }
    #[test]
    fn sequence_gap_reset_grid_clock_and_wrap_contract() {
        let mut e = engine();
        for s in 0..30 {
            feed(&mut e, 1, s, u64::from(s) * 50_000_000);
        }
        let epoch = e.snapshot()["nodes"][0]["node_epoch"].as_u64().unwrap();
        feed(&mut e, 1, 31, 1_550_000_000);
        assert_eq!(e.snapshot()["nodes"][0]["node_epoch"], epoch + 1);
        assert!(e.snapshot()["events"].as_array().unwrap().is_empty());
        feed(&mut e, 1, 0, 1_600_000_000);
        assert_eq!(
            e.snapshot()["nodes"][0]["epoch_reason"],
            "sequence_backwards_boot_unknown"
        );
        feed(&mut e, 2, u32::MAX, 0);
        feed(&mut e, 2, 0, 50_000_000);
        assert_eq!(e.snapshot()["nodes"][1]["node_epoch"], 1);
        let mut p = crate::packet::parse(&crate::packet::fixture(1, 1), &[1]).unwrap();
        p.grid.frequency_mhz = 2412;
        e.process(
            p.clone(),
            Stamp {
                utc_ns: 1_001_650_000_000,
                mono_ns: 1_650_000_000,
            },
        );
        assert_eq!(e.snapshot()["nodes"][0]["epoch_reason"], "grid_changed");
        p.sequence = 2;
        e.process(
            p,
            Stamp {
                utc_ns: 9_001_700_000_000,
                mono_ns: 1_700_000_000,
            },
        );
        assert_eq!(
            e.snapshot()["nodes"][0]["epoch_reason"],
            "receipt_clock_discontinuity"
        );
    }
}
