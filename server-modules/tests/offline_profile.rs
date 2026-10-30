use ruview_server_modules::sha256;
use serde_json::json;
use std::{
    ffi::CString,
    fs,
    path::PathBuf,
    process::{Command, Stdio},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

struct Temp(PathBuf);
impl Drop for Temp {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn offline_binary_checks_binding_raw_preservation_and_mask_without_network() {
    let dir = Temp(std::env::temp_dir().join(format!(
            "ruview-profile-test-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        )));
    fs::create_dir(&dir.0).unwrap();
    let manifest=serde_json::to_vec(&json!({"schema":"ruview.csi-admission.v1","nodes":[{
        "node_id":7,"source_ipv4":"127.0.0.1","profile":"esp32s3-associated-lltf64-mask2-v1",
        "firmware_sha256":"a".repeat(64),"build_config_sha256":"b".repeat(64),"qualification_receipt_sha256":"c".repeat(64)
    }]})).unwrap();
    fs::write(dir.0.join("manifest.json"), &manifest).unwrap();
    let mut raw = vec![0u8; 148];
    raw[..4].copy_from_slice(&0xc5110001u32.to_le_bytes());
    raw[4] = 7;
    raw[5] = 1;
    raw[6] = 64;
    raw[8..12].copy_from_slice(&2412u32.to_le_bytes());
    raw[19] = 4;
    raw[20..24].copy_from_slice(&[3, 4, 5, 12]);
    fs::write(dir.0.join("packet.bin"), &raw).unwrap();
    let run = |hash: &str, source: &str| {
        let mut child = Command::new(env!("CARGO_BIN_EXE_csi-profile-check"))
            .args(["7", source])
            .arg(dir.0.join("manifest.json"))
            .arg(hash)
            .arg(dir.0.join("packet.bin"))
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let start = Instant::now();
        while child.try_wait().unwrap().is_none() {
            if start.elapsed() > Duration::from_secs(5) {
                let _ = child.kill();
                let _ = child.wait();
                panic!("offline checker exceeded five-second test deadline");
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        child.wait_with_output().unwrap()
    };
    let result = run(&sha256(&manifest), "127.0.0.1");
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let value: serde_json::Value = serde_json::from_slice(&result.stdout).unwrap();
    assert_eq!(value["network_used"], false);
    assert_eq!(value["accepted"], 1);
    assert_eq!(value["packets"][0]["default_accepted"], false);
    assert_eq!(value["packets"][0]["raw_sha256"], sha256(&raw));
    assert_eq!(value["packets"][0]["raw_payload_preserved"], true);
    assert_eq!(
        value["packets"][0]["derived_first_two_amplitudes"],
        json!([0., 0.])
    );
    let mask = value["packets"][0]["conservative_feature_mask"]
        .as_array()
        .unwrap();
    assert_eq!(mask.len(), 64);
    assert!(mask[..2].iter().all(|x| x == false));
    assert!(mask[2..].iter().all(|x| x == true));
    assert!(!run(&sha256(&manifest), "127.0.0.2").status.success());
    assert!(!run(&"d".repeat(64), "127.0.0.1").status.success());
    assert_eq!(fs::read(dir.0.join("packet.bin")).unwrap(), raw);
    fs::remove_file(dir.0.join("packet.bin")).unwrap();
    let fifo = CString::new(dir.0.join("packet.bin").to_str().unwrap()).unwrap();
    assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);
    assert!(!run(&sha256(&manifest), "127.0.0.1").status.success());
}
