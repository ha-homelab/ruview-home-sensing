//! Opt-in, operator-reviewed sender provenance. This is not packet authentication.
use crate::{
    packet::{self, Packet},
    sha256,
};
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, Ipv4Addr};

pub const MAX_MANIFEST_BYTES: usize = 16_384;
pub const PROFILE: &str = "esp32s3-associated-lltf64-mask2-v1";

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Binding {
    node_id: u8,
    source_ipv4: Ipv4Addr,
    profile: String,
    firmware_sha256: String,
    build_config_sha256: String,
    qualification_receipt_sha256: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    schema: String,
    nodes: Vec<Binding>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Admission {
    pub profile: String,
    pub feature_contract: &'static str,
    pub manifest_sha256: String,
    pub firmware_sha256: String,
    pub build_config_sha256: String,
    pub qualification_receipt_sha256: String,
    pub first_word_invalid: Option<bool>,
    pub masked_wire_pairs: [usize; 2],
    pub provenance_basis: &'static str,
}

#[derive(Clone, Default)]
pub struct Policy {
    manifest: Option<Manifest>,
    digest: String,
}

fn digest_valid(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        && value.bytes().any(|b| b != b'0')
}

impl Policy {
    pub fn from_bytes(
        bytes: &[u8],
        expected_sha256: &str,
        allowed_nodes: &[u8],
    ) -> Result<Self, &'static str> {
        if bytes.len() > MAX_MANIFEST_BYTES
            || !digest_valid(expected_sha256)
            || sha256(bytes) != expected_sha256
        {
            return Err("admission_manifest_hash_or_size");
        }
        let manifest: Manifest =
            serde_json::from_slice(bytes).map_err(|_| "admission_manifest_schema")?;
        if manifest.schema != "ruview.csi-admission.v1"
            || manifest.nodes.is_empty()
            || manifest.nodes.len() > 10
        {
            return Err("admission_manifest_schema");
        }
        for (index, binding) in manifest.nodes.iter().enumerate() {
            if !allowed_nodes.contains(&binding.node_id)
                || !(1..=16).contains(&binding.node_id)
                || manifest.nodes[..index]
                    .iter()
                    .any(|b| b.node_id == binding.node_id)
                || !(binding.source_ipv4.is_private() || binding.source_ipv4.is_loopback())
                || binding.profile != PROFILE
                || !digest_valid(&binding.firmware_sha256)
                || !digest_valid(&binding.build_config_sha256)
                || !digest_valid(&binding.qualification_receipt_sha256)
            {
                return Err("admission_binding_invalid");
            }
        }
        Ok(Self {
            manifest: Some(manifest),
            digest: expected_sha256.to_owned(),
        })
    }

    pub fn configuration(&self) -> Option<serde_json::Value> {
        self.manifest.as_ref().map(|manifest| {
            serde_json::json!({
                "manifest":manifest,"manifest_sha256":self.digest,
                "provenance_basis":"operator_reviewed_build_and_capture_not_packet_authentication",
                "allowed_profile_flags":[0,4,16,20],"masked_wire_pairs":[0,1],
                "first_word_invalid":null,"recognition_validated":false
            })
        })
    }

    pub fn parse(
        &self,
        data: &[u8],
        allowed_nodes: &[u8],
        source: IpAddr,
    ) -> Result<Packet, &'static str> {
        let binding = self
            .manifest
            .as_ref()
            .and_then(|m| m.nodes.iter().find(|b| Some(&b.node_id) == data.get(4)));
        if let Some(binding) = binding {
            if source != IpAddr::V4(binding.source_ipv4) {
                return Err("admission_source_mismatch");
            }
            let admission = Admission {
                profile: binding.profile.clone(),
                feature_contract: "lltf64-mask2-v1",
                manifest_sha256: self.digest.clone(),
                firmware_sha256: binding.firmware_sha256.clone(),
                build_config_sha256: binding.build_config_sha256.clone(),
                qualification_receipt_sha256: binding.qualification_receipt_sha256.clone(),
                first_word_invalid: None,
                masked_wire_pairs: [0, 1],
                provenance_basis: "operator_reviewed_build_and_capture_not_packet_authentication",
            };
            packet::parse_with_admission(data, allowed_nodes, Some(admission))
        } else {
            packet::parse(data, allowed_nodes)
        }
    }
}

#[cfg(test)]
pub(crate) fn fixture_policy(node: u8, evidence: char) -> Policy {
    let bytes = serde_json::to_vec(
        &serde_json::json!({"schema":"ruview.csi-admission.v1","nodes":[{
            "node_id":node,"source_ipv4":"127.0.0.1","profile":PROFILE,
            "firmware_sha256":"a".repeat(64),"build_config_sha256":"b".repeat(64),
            "qualification_receipt_sha256":evidence.to_string().repeat(64)
        }]}),
    )
    .unwrap();
    Policy::from_bytes(&bytes, &sha256(&bytes), &[node]).unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;
    fn source() -> IpAddr {
        "127.0.0.1".parse().unwrap()
    }

    #[test]
    fn explicit_profile_admits_only_exact_flags_without_changing_raw() {
        let policy = fixture_policy(2, 'c');
        for flags in 0..=255 {
            let mut bytes = packet::fixture(2, 1);
            bytes[19] = flags;
            let result = policy.parse(&bytes, &[2], source());
            assert_eq!(result.is_ok(), [0, 4, 16, 20].contains(&flags));
            if let Ok(packet) = result {
                assert_eq!(packet.grid.flags, flags);
                assert_eq!(packet.iq[0..2], [15, -3]);
                assert_eq!(packet.admission.unwrap().first_word_invalid, None);
            }
        }
        let mut bytes = packet::fixture(2, 1);
        bytes[19] = 20;
        assert!(Policy::default().parse(&bytes, &[2], source()).is_err());
        assert!(policy
            .parse(&bytes, &[2], "127.0.0.2".parse().unwrap())
            .is_err());
        assert!(policy.parse(&bytes, &[1], source()).is_err());
        bytes[4] = 1;
        assert!(policy.parse(&bytes, &[1, 2], source()).is_err());
    }

    #[test]
    fn profile_rejects_mixed_ltf_truncation_unknown_ppdu_and_bandwidth() {
        let policy = fixture_policy(2, 'c');
        let mut base = packet::fixture(2, 1);
        base[19] = 4;
        for (offset, value) in [(5, 2), (6, 192), (18, 1), (19, 5), (8, 0)] {
            let mut bytes = base.clone();
            bytes[offset] = value;
            assert!(policy.parse(&bytes, &[2], source()).is_err());
        }
        assert!(policy.parse(&base[..147], &[2], source()).is_err());
        for pairs in [128u16, 192u16] {
            let mut mixed = base.clone();
            mixed[6..8].copy_from_slice(&pairs.to_le_bytes());
            mixed.resize(packet::HEADER + usize::from(pairs) * 2, 0);
            assert_eq!(
                policy.parse(&mixed, &[2], source()).unwrap_err(),
                "unsupported_grid"
            );
        }
        base.extend([0; 256]);
        assert!(policy.parse(&base, &[2], source()).is_err());
    }

    #[test]
    fn reviewed_manifest_is_bounded_pinned_and_strictly_validated() {
        let original = fixture_policy(2, 'c').manifest.unwrap();
        let bytes = serde_json::to_vec(&original).unwrap();
        assert!(Policy::from_bytes(&bytes, &"d".repeat(64), &[2]).is_err());
        assert!(Policy::from_bytes(&bytes, &sha256(&bytes), &[1]).is_err());
        for field in [
            "profile",
            "firmware_sha256",
            "build_config_sha256",
            "qualification_receipt_sha256",
            "source_ipv4",
        ] {
            let mut value = serde_json::to_value(&original).unwrap();
            value["nodes"][0][field] = serde_json::json!("unknown");
            let bytes = serde_json::to_vec(&value).unwrap();
            assert!(Policy::from_bytes(&bytes, &sha256(&bytes), &[2]).is_err());
        }
        let mut value = serde_json::to_value(&original).unwrap();
        let node = value["nodes"][0].clone();
        value["nodes"].as_array_mut().unwrap().push(node);
        let bytes = serde_json::to_vec(&value).unwrap();
        assert!(Policy::from_bytes(&bytes, &sha256(&bytes), &[2]).is_err());
        let bytes = vec![b' '; MAX_MANIFEST_BYTES + 1];
        assert!(Policy::from_bytes(&bytes, &sha256(&bytes), &[2]).is_err());
    }
}
