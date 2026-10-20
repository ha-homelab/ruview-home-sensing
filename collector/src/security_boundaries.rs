//! Small, dependency-free boundaries used by the actual collector entrypoints.
use std::fs::{File, OpenOptions};
use std::io;
use std::path::{Path, PathBuf};

pub fn valid_recording_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 128
        && id != "."
        && id != ".."
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
}

/// The parent is an operator-owned directory, not an attacker-writable path.
/// create_new rejects existing files, symlinks and concurrent replacement.
pub fn create_recording(directory: &Path, id: &str) -> io::Result<(PathBuf, File)> {
    if !valid_recording_id(id) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid recording id",
        ));
    }
    let path = directory.join(format!("{id}.jsonl"));
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let file = options.open(&path)?;
    Ok((path, file))
}

/// Explicit configuration is never silently replaced by a different identity.
/// The caller supplies the OS RNG, which is invoked only for absent configuration.
pub fn signing_seed<E>(
    configured: Option<&str>,
    random: impl FnOnce(&mut [u8; 32]) -> Result<(), E>,
) -> Result<[u8; 32], &'static str> {
    let mut seed = [0u8; 32];
    if let Some(value) = configured {
        let value = value.trim();
        if value.len() == 64 && value.bytes().all(|b| b.is_ascii_hexdigit()) {
            for (byte, pair) in seed.iter_mut().zip(value.as_bytes().chunks_exact(2)) {
                let digit = |b: u8| (b as char).to_digit(16).unwrap_or(0) as u8;
                *byte = (digit(pair[0]) << 4) | digit(pair[1]);
            }
        } else if value.len() == 32 {
            seed.copy_from_slice(value.as_bytes());
        } else {
            return Err("invalid configured RuField signing seed");
        }
    } else {
        random(&mut seed).map_err(|_| "OS randomness unavailable for RuField signing")?;
    }
    if seed == [0; 32] || seed == *b"adr262-ruview-rufield-dev-seed!!" {
        return Err("insecure RuField signing seed");
    }
    Ok(seed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static NEXT: AtomicUsize = AtomicUsize::new(0);

    struct Scratch(PathBuf);
    impl Scratch {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "ruview-boundary-test-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            std::fs::create_dir(&path).unwrap();
            Self(path)
        }
    }
    impl Drop for Scratch {
        fn drop(&mut self) {
            std::fs::remove_dir_all(&self.0).unwrap();
        }
    }

    #[test]
    fn invalid_recording_names_create_nothing() {
        let scratch = Scratch::new();
        for id in [
            "",
            ".",
            "..",
            "../outside",
            "/absolute",
            r"..\outside",
            "a/b",
            "a\\b",
            "a\0b",
            "line\nbreak",
            "?",
            "x:y",
            "nonascii-é",
        ] {
            assert_eq!(
                create_recording(&scratch.0, id).unwrap_err().kind(),
                io::ErrorKind::InvalidInput
            );
        }
        assert!(!valid_recording_id(&"x".repeat(129)));
        assert_eq!(std::fs::read_dir(&scratch.0).unwrap().count(), 0);
    }

    #[test]
    fn normal_names_are_private_and_existing_records_are_preserved() {
        let scratch = Scratch::new();
        let (path, mut file) = create_recording(&scratch.0, "rec_2026-10.19").unwrap();
        file.write_all(b"existing data").unwrap();
        drop(file);
        assert_eq!(
            create_recording(&scratch.0, "rec_2026-10.19")
                .unwrap_err()
                .kind(),
            io::ErrorKind::AlreadyExists
        );
        assert_eq!(std::fs::read(&path).unwrap(), b"existing data");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        assert!(valid_recording_id(&"x".repeat(128)));
    }

    #[cfg(unix)]
    #[test]
    fn existing_symlink_cannot_overwrite_its_target() {
        let scratch = Scratch::new();
        let target = scratch.0.join("protected");
        std::fs::write(&target, b"keep").unwrap();
        std::os::unix::fs::symlink(&target, scratch.0.join("record.jsonl")).unwrap();
        assert!(create_recording(&scratch.0, "record").is_err());
        assert_eq!(std::fs::read(target).unwrap(), b"keep");
    }

    #[test]
    fn missing_seed_uses_randomness_and_rng_failure_is_closed() {
        let seed = signing_seed(None, |out| {
            out.fill(0x5a);
            Ok::<_, ()>(())
        })
        .unwrap();
        assert_eq!(seed, [0x5a; 32]);
        assert!(signing_seed(None, |_| Err(())).is_err());
        assert!(signing_seed(None, |_| Ok::<_, ()>(())).is_err());
    }

    #[test]
    fn explicit_seed_is_exact_and_does_not_call_rng() {
        let configured = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
        let seed = signing_seed(Some(configured), |_| -> Result<(), ()> {
            panic!("configured identity must not use RNG")
        })
        .unwrap();
        assert_eq!(seed[0], 0);
        assert_eq!(seed[31], 255);
        let raw = "0123456789abcdef0123456789abcdef";
        assert_eq!(
            signing_seed(Some(raw), |_| Ok::<_, ()>(())).unwrap(),
            *raw.as_bytes()
        );
    }

    #[test]
    fn invalid_or_known_seed_cannot_fall_back_or_truncate() {
        for value in [
            "",
            "short",
            "adr262-ruview-rufield-dev-seed!!",
            "0123456789abcdef0123456789abcdefextra",
            "0000000000000000000000000000000000000000000000000000000000000000",
        ] {
            assert!(signing_seed(Some(value), |_| -> Result<(), ()> {
                panic!("invalid explicit seed must not use RNG")
            })
            .is_err());
        }
    }
}
