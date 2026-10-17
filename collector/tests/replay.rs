//! Offline header replay. Input CSV: elapsed_us,node_id,n_subcarriers,ppdu_type.
//! Does not send packets or read credentials. Compare old admission with the
//! exact new selector, not with a reimplementation of its constants.
#[path = "../src/grid_gate.rs"]
mod grid_gate;

use grid_gate::{Admission, GridGate};
use std::collections::BTreeMap;
use std::io::{self, BufRead};
use std::time::{Duration, Instant};

struct Node {
    gate: GridGate<(u16, u8)>,
    old_active: Option<(u16, u8)>,
    raw: usize,
    old_accepted: usize,
    new_accepted: usize,
    old_last: u64,
    new_last: u64,
    old_max_gap: u64,
    new_max_gap: u64,
    switches: usize,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let start = Instant::now();
    let mut end = 0;
    let mut nodes = BTreeMap::new();
    for line in io::stdin().lock().lines() {
        let line = line?;
        if line.starts_with("elapsed_us") || line.trim().is_empty() {
            continue;
        }
        let fields: Vec<&str> = line.split(',').collect();
        if fields.len() != 4 {
            return Err("expected four CSV fields".into());
        }
        let us: u64 = fields[0].parse()?;
        if us < end {
            return Err("input is not in monotonic arrival order".into());
        }
        end = us;
        let id: u8 = fields[1].parse()?;
        let grid: (u16, u8) = (fields[2].parse()?, fields[3].parse()?);
        let node = nodes.entry(id).or_insert_with(|| Node {
            gate: GridGate::new(),
            old_active: None,
            raw: 0,
            old_accepted: 0,
            new_accepted: 0,
            old_last: us,
            new_last: us,
            old_max_gap: 0,
            new_max_gap: 0,
            switches: 0,
        });
        node.raw += 1;
        // Original NodeState::accept_grid policy from the pinned main.rs:
        let old_admitted = match node.old_active {
            None => true,
            Some(active) if active == grid => true,
            Some((width, _)) if grid.0 > width => true,
            _ => false,
        };
        if old_admitted {
            node.old_active = Some(grid);
            node.old_accepted += 1;
            node.old_max_gap = node.old_max_gap.max(us - node.old_last);
            node.old_last = us;
        }
        let admitted = node
            .gate
            .admit(grid, grid.0, start + Duration::from_micros(us));
        if admitted != Admission::Reject {
            node.new_accepted += 1;
            node.new_max_gap = node.new_max_gap.max(us - node.new_last);
            node.new_last = us;
            node.switches += usize::from(admitted == Admission::Switch);
        }
    }
    println!("node,raw,upstream_accepted,patched_accepted,upstream_max_gap_s,patched_max_gap_s,patched_switches,patched_grid");
    for (id, node) in nodes {
        let old_gap = node.old_max_gap.max(end - node.old_last) as f64 / 1_000_000.0;
        let new_gap = node.new_max_gap.max(end - node.new_last) as f64 / 1_000_000.0;
        println!(
            "{id},{},{},{},{old_gap:.3},{new_gap:.3},{},{:?}",
            node.raw,
            node.old_accepted,
            node.new_accepted,
            node.switches,
            node.gate.active()
        );
    }
    Ok(())
}
