//! Bounded response encoding; decoding and observation semantics are unchanged.
use flate2::{write::GzEncoder, Compression};
use std::io::{self, Write};

pub const MAX_HTTP: usize = 1_048_576;
const MIN_GZIP_BYTES: usize = 1024;
const MIN_SAVING_BYTES: usize = 128;

pub struct EncodedBody {
    pub bytes: Vec<u8>,
    pub gzip: bool,
}

#[derive(Default)]
struct Preferences {
    gzip: Option<u16>,
    identity: Option<u16>,
    wildcard: Option<u16>,
}

fn quality(value: &str) -> Option<u16> {
    let (whole, fraction) = value.split_once('.').unwrap_or((value, ""));
    if !matches!(whole, "0" | "1")
        || fraction.len() > 3
        || !fraction.bytes().all(|byte| byte.is_ascii_digit())
        || (whole == "1" && fraction.bytes().any(|byte| byte != b'0'))
    {
        return None;
    }
    if whole == "1" {
        return Some(1000);
    }
    Some(
        fraction
            .bytes()
            .fold(0, |q, byte| q * 10 + u16::from(byte - b'0'))
            * 10u16.pow((3 - fraction.len()) as u32),
    )
}

fn trim(value: &str) -> &str {
    value.trim_matches([' ', '\t'])
}

impl Preferences {
    fn parse(request: &str) -> Self {
        let mut preferences = Self::default();
        // Inspect only complete header lines, never a request body or pipeline.
        for line in request
            .split("\r\n")
            .skip(1)
            .take_while(|line| !line.is_empty())
        {
            let Some((name, value)) = line.split_once(':') else {
                continue;
            };
            if !name.eq_ignore_ascii_case("accept-encoding") {
                continue;
            }
            for coding in value.split(',') {
                let mut parts = coding.split(';');
                let name = trim(parts.next().unwrap_or(""));
                let slot = if name.eq_ignore_ascii_case("gzip") {
                    &mut preferences.gzip
                } else if name.eq_ignore_ascii_case("identity") {
                    &mut preferences.identity
                } else if name == "*" {
                    &mut preferences.wildcard
                } else {
                    continue;
                };
                let q = match (parts.next(), parts.next()) {
                    (None, None) => 1000,
                    (Some(parameter), None) => parameter
                        .split_once('=')
                        .filter(|(key, _)| trim(key).eq_ignore_ascii_case("q"))
                        .and_then(|(_, value)| quality(trim(value)))
                        .unwrap_or(0),
                    _ => 0,
                };
                // Conflicting duplicate entries cannot override a refusal.
                *slot = Some(slot.map_or(q, |previous| previous.min(q)));
            }
        }
        preferences
    }

    fn qualities(&self) -> (u16, u16) {
        let gzip = self.gzip.or(self.wildcard).unwrap_or(0);
        let identity = self
            .identity
            .unwrap_or(if self.wildcard == Some(0) { 0 } else { 1000 });
        (gzip, identity)
    }
}

struct BoundedOutput {
    bytes: Vec<u8>,
    limit: usize,
}

impl Write for BoundedOutput {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() > self.limit - self.bytes.len() {
            return Err(io::Error::other("compressed response exceeds bound"));
        }
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn gzip(bytes: &[u8], limit: usize) -> io::Result<Vec<u8>> {
    let output = BoundedOutput {
        bytes: Vec::with_capacity(limit),
        limit,
    };
    let mut encoder = GzEncoder::new(output, Compression::fast());
    encoder.write_all(bytes)?;
    Ok(encoder.finish()?.bytes)
}

/// None means no representation is acceptable within the existing wire bound.
pub fn encode(bytes: Vec<u8>, request: &str) -> Option<EncodedBody> {
    if bytes.len() > MAX_HTTP {
        return None;
    }
    let (gzip_quality, identity_quality) = Preferences::parse(request).qualities();
    let require_gzip = identity_quality == 0;
    if gzip_quality > 0
        && gzip_quality >= identity_quality
        && (require_gzip || bytes.len() >= MIN_GZIP_BYTES)
    {
        let limit = if require_gzip {
            MAX_HTTP
        } else {
            bytes.len() - MIN_SAVING_BYTES
        };
        if let Ok(compressed) = gzip(&bytes, limit) {
            return Some(EncodedBody {
                bytes: compressed,
                gzip: true,
            });
        }
    }
    (identity_quality > 0).then_some(EncodedBody { bytes, gzip: false })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;

    fn request(headers: &str) -> String {
        format!("GET /v1/latest HTTP/1.1\r\n{headers}\r\n")
    }

    #[test]
    fn qvalues_and_explicit_refusals_are_respected() {
        for (header, expected) in [
            ("", (0, 1000)),
            ("Accept-Encoding:\r\n", (0, 1000)),
            ("Accept-Encoding: gzip\r\n", (1000, 1000)),
            (
                "aCcEpT-EnCoDiNg: GZIP;Q=0.123, identity;q=0.1\r\n",
                (123, 100),
            ),
            ("Accept-Encoding: *;q=0.8\r\n", (800, 1000)),
            ("Accept-Encoding: gzip;q=0, *;q=1\r\n", (0, 1000)),
            ("Accept-Encoding: *;q=0, gzip\r\n", (1000, 0)),
            ("Accept-Encoding: *;q=0, identity;q=0.5\r\n", (0, 500)),
            (
                "Accept-Encoding: gzip;q=0\r\nAccept-Encoding: gzip\r\n",
                (0, 1000),
            ),
            ("Accept-Encoding: gzip, gzip;q=0\r\n", (0, 1000)),
            ("Accept-Encoding: br, deflate\r\n", (0, 1000)),
        ] {
            assert_eq!(
                Preferences::parse(&request(header)).qualities(),
                expected,
                "{header}"
            );
        }
    }

    #[test]
    fn malformed_preferences_cannot_enable_gzip() {
        for value in [
            "-1",
            "2",
            "1.001",
            "0.0001",
            ".5",
            "NaN",
            "",
            "0.5;q=1",
            "0.5;level=1",
        ] {
            let header = format!("Accept-Encoding: gzip;q={value}, *\r\n");
            assert_eq!(
                Preferences::parse(&request(&header)).qualities().0,
                0,
                "{value}"
            );
        }
        assert_eq!(
            Preferences::parse("GET / HTTP/1.1\r\n\r\nAccept-Encoding: gzip\r\n")
                .qualities()
                .0,
            0
        );
    }

    #[test]
    fn compression_preserves_bytes_and_only_wins_when_worthwhile() {
        let payload = vec![b'x'; 8192];
        let encoded = encode(payload.clone(), &request("Accept-Encoding: gzip\r\n")).unwrap();
        assert!(encoded.gzip && encoded.bytes.len() <= payload.len() - MIN_SAVING_BYTES);
        let mut decoded = Vec::new();
        flate2::read::GzDecoder::new(encoded.bytes.as_slice())
            .read_to_end(&mut decoded)
            .unwrap();
        assert_eq!(decoded, payload);
        for header in [
            "",
            "Accept-Encoding: gzip;q=0\r\n",
            "Accept-Encoding: gzip;q=0.1\r\n",
        ] {
            let encoded = encode(payload.clone(), &request(header)).unwrap();
            assert!(!encoded.gzip);
            assert_eq!(encoded.bytes, payload);
        }
        let tiny = encode(b"{}".to_vec(), &request("Accept-Encoding: gzip\r\n")).unwrap();
        assert!(!tiny.gzip);
        let forced = encode(
            b"{}".to_vec(),
            &request("Accept-Encoding: gzip, identity;q=0\r\n"),
        )
        .unwrap();
        assert!(forced.gzip);
    }

    #[test]
    fn output_is_bounded_and_unacceptable_representations_are_rejected() {
        assert!(gzip(&vec![b'x'; 8192], 5).is_err());
        let mut state = 0x1234_5678u32;
        let noise: Vec<u8> = (0..MAX_HTTP)
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 17;
                state ^= state << 5;
                state as u8
            })
            .collect();
        let result = encode(noise.clone(), &request("Accept-Encoding: gzip\r\n")).unwrap();
        assert!(!result.gzip);
        assert_eq!(result.bytes, noise);
        assert!(encode(noise, &request("Accept-Encoding: gzip, identity;q=0\r\n")).is_none());
        assert!(encode(vec![0; MAX_HTTP + 1], &request("Accept-Encoding: gzip\r\n")).is_none());
        assert!(encode(b"{}".to_vec(), &request("Accept-Encoding: *;q=0\r\n")).is_none());
        assert!(encode(
            b"{}".to_vec(),
            &request("Accept-Encoding: br, identity;q=0\r\n")
        )
        .is_none());
    }
}
