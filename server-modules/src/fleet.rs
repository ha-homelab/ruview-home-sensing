//! Fleet-scoped diagnostics over genuine per-node coherence observations.
//! The native graph is a quality-derived complete graph, not measured links.
use crate::engine::{Stamp, FRESH_NS};
use serde_json::{json, Value};
use std::{
    collections::BTreeMap,
    panic::{catch_unwind, AssertUnwindSafe},
    time::Instant,
};
use wifi_densepose_wasm_edge::aut_self_healing_mesh::SelfHealingMesh;

pub const INPUT_WINDOW_NS: u64 = 500_000_000;
const CALLBACK_MAX_US: u64 = 50_000;

#[derive(Clone, Debug)]
pub struct QualityInput {
    pub node_id: u8,
    pub node_epoch: u64,
    pub sequence: u32,
    pub stamp: Stamp,
    pub quality: f32,
    pub occurrence_seq: String,
    pub algorithm_version: String,
    pub source_sha256: String,
}
impl QualityInput {
    fn json(&self, index: usize) -> Value {
        json!({"index":index,"node_id":self.node_id,"node_epoch":self.node_epoch,
            "source_sequence":self.sequence,"quality":self.quality,
            "observed_at_ns":self.stamp.utc_ns.to_string(),
            "observed_monotonic_ns":self.stamp.mono_ns.to_string(),
            "algorithm":"coherence","algorithm_version":self.algorithm_version,
            "source_sha256":self.source_sha256,"occurrence_seq":self.occurrence_seq})
    }
}

pub struct Fleet {
    meta: Value,
    run_id: String,
    membership: Vec<(u8, u64)>,
    epoch: u64,
    epoch_reason: &'static str,
    algorithm: SelfHealingMesh,
    consumed: Vec<(u8, u64, u32)>,
    inputs: Vec<QualityInput>,
    events: BTreeMap<i32, Value>,
    occurrence: u64,
    analyses: u64,
    max_us: u64,
    availability: &'static str,
    reason: &'static str,
    fault: Option<&'static str>,
    last_update: Option<Stamp>,
}
impl Fleet {
    pub fn new(meta: Value, run_id: &str, nodes: &[u8]) -> Self {
        let mut membership: Vec<_> = nodes.iter().map(|id| (*id, 0)).collect();
        membership.sort_unstable();
        let cohort_valid = (2..=8).contains(&membership.len());
        Self {
            meta,
            run_id: run_id.to_owned(),
            membership,
            epoch: 0,
            epoch_reason: "awaiting_complete_cohort",
            algorithm: SelfHealingMesh::new(),
            consumed: Vec::new(),
            inputs: Vec::new(),
            events: BTreeMap::new(),
            occurrence: 0,
            analyses: 0,
            max_us: 0,
            availability: if cohort_valid {
                "warming_up"
            } else {
                "ineligible"
            },
            reason: if cohort_valid {
                "requires_complete_cohort_coherence"
            } else {
                "requires_complete_cohort_of_2_to_8_nodes"
            },
            fault: None,
            last_update: None,
        }
    }
    fn reset(&mut self, reason: &'static str) {
        self.epoch += 1;
        self.epoch_reason = reason;
        self.algorithm = SelfHealingMesh::new();
        self.consumed.clear();
        self.inputs.clear();
        self.events.clear();
        self.analyses = 0;
        self.max_us = 0;
        self.fault = None;
    }
    fn unavailable(&mut self, availability: &'static str, reason: &'static str) {
        if !self.inputs.is_empty() || !self.events.is_empty() {
            self.reset(reason);
        }
        self.availability = availability;
        self.reason = reason;
    }

    /// `members` is the complete configured cohort, including unseen nodes.
    /// A slow or missing member is never silently removed or assigned zero.
    pub fn update(&mut self, members: Vec<(u8, u64, Option<QualityInput>)>, now: Stamp) {
        let membership: Vec<_> = members.iter().map(|(id, epoch, _)| (*id, *epoch)).collect();
        if membership != self.membership {
            self.reset("member_epoch_or_membership_changed");
            self.membership = membership;
        }
        if let Some(last) = self.last_update {
            let elapsed = now.mono_ns.saturating_sub(last.mono_ns);
            let residual =
                (i128::from(now.utc_ns) - i128::from(last.utc_ns) - i128::from(elapsed)).abs();
            if now.mono_ns < last.mono_ns || residual > 250_000_000 {
                self.reset("receipt_clock_discontinuity");
            }
        }
        self.last_update = Some(now);
        if !(2..=8).contains(&members.len()) {
            self.unavailable("ineligible", "requires_complete_cohort_of_2_to_8_nodes");
            return;
        }
        if self
            .membership
            .windows(2)
            .any(|pair| pair[0].0 >= pair[1].0)
            || self.membership.iter().any(|(id, _)| !(1..=16).contains(id))
        {
            self.unavailable("ineligible", "invalid_cohort_node_identity");
            return;
        }
        if self.fault.is_some() {
            return;
        }
        let Some(inputs): Option<Vec<_>> = members.into_iter().map(|(_, _, input)| input).collect()
        else {
            self.unavailable("warming_up", "requires_complete_cohort_coherence");
            return;
        };
        if inputs
            .iter()
            .zip(&self.membership)
            .any(|(input, (id, epoch))| {
                input.node_id != *id
                    || input.node_epoch != *epoch
                    || !input.quality.is_finite()
                    || !(0.0..=1.0).contains(&input.quality)
            })
        {
            self.unavailable("ineligible", "invalid_member_coherence");
            return;
        }
        if inputs.iter().any(|input| {
            now.mono_ns
                .checked_sub(input.stamp.mono_ns)
                .is_none_or(|age| age > FRESH_NS)
        }) {
            self.unavailable("stale", "member_coherence_expired_or_future");
            return;
        }
        let oldest = inputs.iter().min_by_key(|v| v.stamp.mono_ns).unwrap().stamp;
        let newest = inputs.iter().max_by_key(|v| v.stamp.mono_ns).unwrap().stamp;
        if newest.mono_ns - oldest.mono_ns > INPUT_WINDOW_NS {
            self.unavailable("ineligible", "member_observation_window_exceeded");
            return;
        }
        if inputs.iter().any(|input| {
            (i128::from(input.stamp.utc_ns)
                - i128::from(oldest.utc_ns)
                - i128::from(input.stamp.mono_ns - oldest.mono_ns))
            .abs()
                > 250_000_000
        }) {
            self.unavailable("ineligible", "member_clock_discontinuity");
            return;
        }
        // Idle HTTP expiry does not mutate this object. Renew native state on
        // the next observation if the last complete analysis has expired.
        if self.inputs.iter().any(|input| {
            now.mono_ns
                .checked_sub(input.stamp.mono_ns)
                .is_none_or(|age| age > FRESH_NS)
        }) {
            self.reset("previous_cohort_expired");
        }
        let identities: Vec<_> = inputs
            .iter()
            .map(|v| (v.node_id, v.node_epoch, v.sequence))
            .collect();
        if identities
            .iter()
            .zip(&self.consumed)
            .any(|(new, old)| new == old)
        {
            return; // Every member must contribute a new real observation.
        }
        let qualities: Vec<_> = inputs.iter().map(|v| v.quality).collect();
        let started = Instant::now();
        let output = catch_unwind(AssertUnwindSafe(|| {
            self.algorithm.process_frame(&qualities).to_vec()
        }));
        let elapsed = started.elapsed().as_micros().min(u128::from(u64::MAX)) as u64;
        self.max_us = self.max_us.max(elapsed);
        let events = match output {
            Ok(events) if elapsed <= CALLBACK_MAX_US => events,
            Ok(_) => {
                self.fail("host_callback_budget_exceeded");
                return;
            }
            Err(_) => {
                self.fail("algorithm_panicked");
                return;
            }
        };
        if events.len() > 6
            || events.iter().any(|(id, value)| {
                !value.is_finite()
                    || self.meta["fleet_events"].get(id.to_string()).is_none()
                    || (*id == 885
                        && (*value < 0. || value.fract() != 0. || *value as usize >= inputs.len()))
            })
        {
            self.fail("invalid_algorithm_output");
            return;
        }
        self.analyses += 1;
        self.availability = "running";
        self.reason = "quality_graph_advisory_only";
        self.consumed = identities;
        self.inputs = inputs;
        let member_inputs: Vec<_> = self
            .inputs
            .iter()
            .enumerate()
            .map(|(i, v)| v.json(i))
            .collect();
        let member_node_ids: Vec<_> = self.inputs.iter().map(|v| v.node_id).collect();
        for (id, value) in events {
            self.occurrence += 1;
            let details = &self.meta["fleet_events"][id.to_string()];
            self.events.insert(id,json!({"worker_run_id":self.run_id,"fleet_epoch":self.epoch,
                "occurrence_seq":self.occurrence.to_string(),"scope":"fleet",
                "algorithm":self.meta["algorithm"],"algorithm_version":self.meta["algorithm_version"],
                "source_sha256":self.meta["source_sha256"],"event_id":id.to_string(),
                "event_name":details["event_name"],"meaning":details["meaning"],
                "value_type":details["value_type"],"units":details["units"],"value":value,
                "subject_node_id":if id==885 { Some(member_node_ids[value as usize]) } else { None },
                "member_node_ids":member_node_ids,"member_inputs":member_inputs,
                "observed_at_ns":oldest.utc_ns.to_string(),"observed_monotonic_ns":oldest.mono_ns.to_string(),
                "input_window_end_at_ns":newest.utc_ns.to_string(),"input_window_end_monotonic_ns":newest.mono_ns.to_string(),
                "trigger_received_at_ns":now.utc_ns.to_string(),"trigger_received_monotonic_ns":now.mono_ns.to_string(),
                "age_ms":Value::Null,"fresh":false,
                "advisory_only":true,"classification":"experimental","recognition_validated":false,
                "source":"esp32_cohort","execution":"server"}));
        }
    }
    fn fail(&mut self, reason: &'static str) {
        self.events.clear();
        self.inputs.clear();
        self.fault = Some(reason);
        self.availability = "faulted";
        self.reason = reason;
    }
    pub fn snapshot(&self) -> Value {
        let inputs: Vec<_> = self
            .inputs
            .iter()
            .enumerate()
            .map(|(i, v)| v.json(i))
            .collect();
        let ids: Vec<_> = self.membership.iter().map(|(id, _)| *id).collect();
        let oldest = self.inputs.iter().min_by_key(|v| v.stamp.mono_ns);
        json!({"schema":"ruview.server-modules.fleet.v1","scope":"fleet","worker_run_id":self.run_id,
            "fleet_epoch":self.epoch,"epoch_reason":self.epoch_reason,"configured_node_ids":ids,
            "algorithm":self.meta["algorithm"],"algorithm_version":self.meta["algorithm_version"],
            "source_sha256":self.meta["source_sha256"],"availability":self.availability,"reason":self.reason,
            "processed_cohorts":self.analyses,"emitted_events":self.occurrence,"max_execution_us":self.max_us,
            "freshness_limit_ms":FRESH_NS/1_000_000,"input_window_limit_ms":INPUT_WINDOW_NS/1_000_000,
            "minimum_members":2,"maximum_members":8,"member_inputs":inputs,
            "observed_at_ns":oldest.map(|v|v.stamp.utc_ns.to_string()),
            "observed_monotonic_ns":oldest.map(|v|v.stamp.mono_ns.to_string()),
            "age_ms":Value::Null,"fresh":false,"advisory_only":true,"recognition_validated":false,
            "events":self.events.values().collect::<Vec<_>>()})
    }
}

/// HTTP expiry retains original cohort timestamps and occurrence identities.
pub fn age_snapshot(fleet: &mut Value, now: Stamp) {
    if !fleet.is_object() {
        return;
    }
    fn age(value: &mut Value, now: Stamp) -> bool {
        let age = value["observed_monotonic_ns"]
            .as_str()
            .and_then(|v| v.parse::<u64>().ok())
            .and_then(|v| now.mono_ns.checked_sub(v));
        let fresh = age.is_some_and(|age| age <= FRESH_NS);
        value["age_ms"] = age.map(|v| json!(v / 1_000_000)).unwrap_or(Value::Null);
        value["fresh"] = json!(fresh);
        fresh
    }
    if !age(fleet, now) && fleet["availability"] == "running" {
        fleet["availability"] = json!("stale");
        fleet["reason"] = json!("member_coherence_expired_or_future");
    }
    if let Some(events) = fleet["events"].as_array_mut() {
        for event in events {
            age(event, now);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn stamp(ms: u64) -> Stamp {
        Stamp {
            mono_ns: ms * 1_000_000,
            utc_ns: 1_000_000_000_000 + ms * 1_000_000,
        }
    }
    fn input(
        id: u8,
        epoch: u64,
        seq: u32,
        ms: u64,
        quality: f32,
    ) -> (u8, u64, Option<QualityInput>) {
        (
            id,
            epoch,
            Some(QualityInput {
                node_id: id,
                node_epoch: epoch,
                sequence: seq,
                stamp: stamp(ms),
                quality,
                occurrence_seq: seq.to_string(),
                algorithm_version: "0.3.0+home-server.1".into(),
                source_sha256: "a".repeat(64),
            }),
        )
    }
    fn fleet(ids: &[u8]) -> Fleet {
        let catalog: Vec<Value> = serde_json::from_str(include_str!("../algorithms.json")).unwrap();
        let mut meta = catalog
            .into_iter()
            .find(|v| v["fleet_selected"] == true)
            .unwrap();
        meta["source_sha256"] = json!("b".repeat(64));
        Fleet::new(meta, "test-run", ids)
    }
    #[test]
    fn actual_native_graph_maps_sparse_ids_and_preserves_every_input() {
        let mut f = fleet(&[3, 11]);
        f.update(
            vec![input(3, 1, 70, 100, 0.1), input(11, 4, 900, 120, 0.2)],
            stamp(120),
        );
        let mut s = f.snapshot();
        age_snapshot(&mut s, stamp(130));
        assert_eq!(s["configured_node_ids"], json!([3, 11]));
        assert_eq!(s["availability"], "running");
        assert_eq!(s["age_ms"], 30);
        let events = s["events"].as_array().unwrap();
        assert_eq!(events.len(), 3);
        let mean = events.iter().find(|v| v["event_id"] == "887").unwrap();
        assert!((mean["value"].as_f64().unwrap() - 0.15).abs() < 1e-6);
        let degraded = events.iter().find(|v| v["event_id"] == "885").unwrap();
        let index = degraded["value"].as_f64().unwrap() as usize;
        assert_eq!(degraded["subject_node_id"], json!([3, 11][index]));
        for event in events {
            assert!(event.get("node_id").is_none());
            assert!(event.get("node_epoch").is_none());
            assert_eq!(event["member_inputs"][1]["source_sequence"], 900);
            assert_eq!(event["member_inputs"][1]["node_epoch"], 4);
            assert_eq!(event["observed_at_ns"], stamp(100).utc_ns.to_string());
            assert_eq!(
                event["observed_monotonic_ns"],
                stamp(100).mono_ns.to_string()
            );
            assert_eq!(
                event["input_window_end_monotonic_ns"],
                stamp(120).mono_ns.to_string()
            );
            assert_eq!(event["advisory_only"], true);
            assert_eq!(event["recognition_validated"], false);
        }
    }
    #[test]
    fn faster_members_and_http_polling_cannot_rearm_a_cohort() {
        let mut f = fleet(&[1, 2]);
        f.update(
            vec![input(1, 1, 70, 100, 0.2), input(2, 1, 70, 110, 0.4)],
            stamp(110),
        );
        let before = f.snapshot();
        f.update(
            vec![input(1, 1, 71, 120, 0.3), input(2, 1, 70, 110, 0.4)],
            stamp(120),
        );
        assert_eq!(f.snapshot(), before);
        let mut polled = f.snapshot();
        age_snapshot(&mut polled, stamp(150));
        assert_eq!(
            polled["events"][0]["occurrence_seq"],
            before["events"][0]["occurrence_seq"]
        );
        assert_eq!(polled["age_ms"], 50);
        f.update(
            vec![input(1, 1, 71, 120, 0.3), input(2, 1, 71, 140, 0.4)],
            stamp(140),
        );
        assert_eq!(f.snapshot()["processed_cohorts"], 2);
    }
    #[test]
    fn missing_member_never_shrinks_cohort_or_fabricates_zero_quality() {
        let mut f = fleet(&[1, 2, 3]);
        f.update(
            vec![
                input(1, 1, 70, 100, 0.1),
                input(2, 1, 70, 110, 0.2),
                (3, 0, None),
            ],
            stamp(110),
        );
        let s = f.snapshot();
        assert_eq!(s["configured_node_ids"], json!([1, 2, 3]));
        assert_eq!(s["processed_cohorts"], 0);
        assert!(s["events"].as_array().unwrap().is_empty());
        assert_eq!(s["availability"], "warming_up");
    }
    #[test]
    fn input_age_spread_identity_and_clock_checks_fail_closed() {
        let cases = vec![
            (
                vec![input(1, 1, 70, 0, 0.1), input(2, 1, 70, 2001, 0.2)],
                2001,
                "member_coherence_expired_or_future",
            ),
            (
                vec![input(1, 1, 70, 100, 0.1), input(2, 1, 70, 99, 0.2)],
                99,
                "member_coherence_expired_or_future",
            ),
            (
                vec![input(1, 1, 70, 0, 0.1), input(2, 1, 70, 501, 0.2)],
                501,
                "member_observation_window_exceeded",
            ),
            (
                vec![input(1, 1, 70, 100, f32::NAN), input(2, 1, 70, 100, 0.2)],
                100,
                "invalid_member_coherence",
            ),
            (
                vec![input(1, 1, 70, 100, 1.01), input(2, 1, 70, 100, 0.2)],
                100,
                "invalid_member_coherence",
            ),
            (
                vec![input(1, 1, 70, 100, 0.1), input(1, 1, 70, 100, 0.2)],
                100,
                "invalid_cohort_node_identity",
            ),
        ];
        for (inputs, ms, reason) in cases {
            let mut f = fleet(&[1, 2]);
            f.update(inputs, stamp(ms));
            let s = f.snapshot();
            assert_eq!(s["reason"], reason);
            assert_eq!(s["processed_cohorts"], 0);
            assert!(s["events"].as_array().unwrap().is_empty());
        }
        let mut f = fleet(&[1, 2]);
        let mut bad = input(2, 1, 70, 100, 0.2);
        bad.2.as_mut().unwrap().stamp.utc_ns += 300_000_000;
        f.update(vec![input(1, 1, 70, 100, 0.1), bad], stamp(100));
        assert_eq!(f.snapshot()["reason"], "member_clock_discontinuity");
    }
    #[test]
    fn node_epochs_membership_and_expiry_reset_native_memory() {
        let mut f = fleet(&[1, 2]);
        f.update(
            vec![input(1, 1, 70, 100, 0.1), input(2, 1, 70, 100, 0.1)],
            stamp(100),
        );
        let old = f.snapshot();
        let old_epoch = old["fleet_epoch"].as_u64().unwrap();
        f.update(
            vec![input(1, 2, 80, 110, 1.0), input(2, 1, 71, 110, 1.0)],
            stamp(110),
        );
        let s = f.snapshot();
        assert!(s["fleet_epoch"].as_u64().unwrap() > old_epoch);
        assert_eq!(s["processed_cohorts"], 1);
        assert_eq!(s["events"].as_array().unwrap().len(), 1);
        assert_eq!(s["events"][0]["value"], 1.0); // no low-quality EMA retained
        assert_ne!(
            s["events"][0]["occurrence_seq"],
            old["events"][0]["occurrence_seq"]
        );
        let epoch = s["fleet_epoch"].clone();
        f.update(
            vec![input(1, 2, 81, 120, 0.5), input(3, 1, 70, 120, 0.5)],
            stamp(120),
        );
        assert_ne!(f.snapshot()["fleet_epoch"], epoch);
        assert_eq!(f.snapshot()["configured_node_ids"], json!([1, 3]));
        let mut expired = f.snapshot();
        age_snapshot(&mut expired, stamp(2121));
        assert_eq!(expired["availability"], "stale");
        assert!(expired["events"]
            .as_array()
            .unwrap()
            .iter()
            .all(|e| e["fresh"] == false));
        let epoch = f.snapshot()["fleet_epoch"].clone();
        f.update(
            vec![input(1, 2, 82, 2130, 1.0), input(3, 1, 71, 2130, 1.0)],
            stamp(2130),
        );
        assert_ne!(f.snapshot()["fleet_epoch"], epoch);
        assert_eq!(f.snapshot()["events"][0]["value"], 1.0);
    }
    #[test]
    fn clock_step_and_loss_of_one_member_clear_prior_events() {
        let mut f = fleet(&[1, 2]);
        f.update(
            vec![input(1, 1, 70, 100, 0.1), input(2, 1, 70, 100, 0.1)],
            stamp(100),
        );
        let epoch = f.snapshot()["fleet_epoch"].clone();
        f.update(
            vec![input(1, 1, 71, 90, 1.0), input(2, 1, 71, 90, 1.0)],
            stamp(90),
        );
        assert_ne!(f.snapshot()["fleet_epoch"], epoch);
        assert_eq!(f.snapshot()["events"][0]["value"], 1.0);
        f.update(vec![input(1, 1, 72, 100, 1.0), (2, 1, None)], stamp(100));
        assert!(f.snapshot()["events"].as_array().unwrap().is_empty());
        assert_eq!(f.snapshot()["availability"], "warming_up");
    }
    #[test]
    fn cohort_bounds_are_explicit_and_eight_member_evidence_is_bounded() {
        for ids in [vec![1], (1..=9).collect(), (1..=10).collect()] {
            let mut f = fleet(&ids);
            assert_eq!(f.snapshot()["availability"], "ineligible");
            f.update(
                ids.iter().map(|id| input(*id, 1, 70, 100, 0.1)).collect(),
                stamp(100),
            );
            assert_eq!(
                f.snapshot()["reason"],
                "requires_complete_cohort_of_2_to_8_nodes"
            );
            assert_eq!(
                f.snapshot()["configured_node_ids"]
                    .as_array()
                    .unwrap()
                    .len(),
                ids.len()
            );
            assert!(f.snapshot()["events"].as_array().unwrap().is_empty());
        }
        let mut f = fleet(&(1..=8).collect::<Vec<_>>());
        for seq in 70..90 {
            f.update(
                (1..=8)
                    .map(|id| input(id, 1, seq, 100 + u64::from(seq), 0.01))
                    .collect(),
                stamp(100 + u64::from(seq)),
            );
        }
        assert_eq!(f.snapshot()["availability"], "running");
        assert!(f.snapshot()["events"].as_array().unwrap().len() <= 4);
        assert!(serde_json::to_vec(&f.snapshot()).unwrap().len() < 32_768);
        assert!(fleet(&[1, 2]).snapshot()["events"]
            .as_array()
            .unwrap()
            .is_empty());
    }
}
