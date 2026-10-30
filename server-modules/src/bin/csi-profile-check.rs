//! Bounded offline decoder check. No sockets, recording sessions or model updates.
use ruview_server_modules::{
    admission::{Policy, MAX_MANIFEST_BYTES},
    features::Features,
    packet, sha256,
};
use serde_json::json;
use std::{env, fs::OpenOptions, io::Read, net::IpAddr, os::unix::fs::OpenOptionsExt, path::Path};

fn read_bounded(path: &Path, limit: usize) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK)
        .open(path)?;
    if !file.metadata()?.is_file() {
        return Err("expected regular file".into());
    }
    let mut bytes = Vec::new();
    file.take((limit + 1) as u64).read_to_end(&mut bytes)?;
    if bytes.len() > limit {
        return Err("file exceeds offline check limit".into());
    }
    Ok(bytes)
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_> = env::args().skip(1).collect();
    if args.len() < 5 || args.len() > 68 {
        return Err("usage: csi-profile-check NODE_IDS SOURCE_IP MANIFEST MANIFEST_SHA256 PACKET [PACKET...]; maximum64 packets".into());
    }
    let nodes: Vec<u8> = args[0]
        .split(',')
        .map(str::parse)
        .collect::<Result<_, _>>()?;
    if nodes.is_empty()
        || nodes.len() > 10
        || nodes.iter().any(|n| !(1..=16).contains(n))
        || nodes
            .iter()
            .enumerate()
            .any(|(i, n)| nodes[..i].contains(n))
    {
        return Err("invalid node allowlist".into());
    }
    let source: IpAddr = args[1].parse()?;
    let manifest = read_bounded(Path::new(&args[2]), MAX_MANIFEST_BYTES)?;
    let policy = Policy::from_bytes(&manifest, &args[3], &nodes)?;
    let mut results = Vec::new();
    let mut accepted = 0;
    for path in &args[4..] {
        let raw = read_bounded(Path::new(path), packet::MAX_PACKET)?;
        let default = packet::parse(&raw, &nodes);
        let mut result = json!({"raw_sha256":sha256(&raw),"raw_bytes":raw.len(),
            "default_accepted":default.is_ok(),"default_rejection":default.err(),
            "profile_accepted":false});
        match policy.parse(&raw, &nodes, source) {
            Err(reason) => result["profile_rejection"] = json!(reason),
            Ok(packet) => {
                let mut features = Features::default();
                features.update(&packet);
                let feature_mask: Vec<bool> = (0..packet::SUBCARRIERS)
                    .map(|k| {
                        !packet
                            .admission
                            .as_ref()
                            .is_some_and(|a| a.masked_wire_pairs.contains(&k))
                    })
                    .collect();
                result["profile_accepted"] = json!(true);
                result["node_id"] = json!(packet.node_id);
                result["grid"] = json!(packet.grid);
                result["admission"] = json!(packet.admission);
                result["raw_payload_preserved"] = json!(packet
                    .iq
                    .iter()
                    .zip(&raw[packet::HEADER..])
                    .all(|(a, b)| *a == *b as i8));
                result["derived_first_two_amplitudes"] = json!(&features.amplitudes[..2]);
                result["conservative_feature_mask"] = json!(feature_mask);
                result["mask_meaning"] =
                    json!("included_in_derived_array_not_proof_of_physical_validity");
                accepted += 1;
            }
        }
        results.push(result);
    }
    println!(
        "{}",
        json!({"schema":"ruview.offline-csi-profile-check.v1",
        "manifest_sha256":sha256(&manifest),"packet_count":results.len(),"accepted":accepted,
        "recognition_validated":false,"network_used":false,"packets":results})
    );
    if accepted != args.len() - 4 {
        std::process::exit(1);
    }
    Ok(())
}
