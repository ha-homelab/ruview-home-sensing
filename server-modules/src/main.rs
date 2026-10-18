mod capture;
mod http_encoding;
mod snapshot_cache;

use http_encoding::MAX_HTTP;
use ruview_server_modules::{
    engine::{self, age_snapshot, Engine, Stamp, FRESH_NS},
    packet, sha256,
};
use serde_json::{json, Value};
use snapshot_cache::{PublicationSchedule, SnapshotCache};
use std::{
    env,
    fs::{self, OpenOptions},
    io::{Read, Write},
    net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener, TcpStream, UdpSocket},
    os::unix::fs::OpenOptionsExt,
    path::PathBuf,
    sync::{
        atomic::{AtomicU64, Ordering},
        mpsc::{self, TrySendError},
        Arc,
    },
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

const PROVENANCE: &str = include_str!("../provenance.json");
const QUEUE: usize = 64;
#[derive(Clone)]
struct Clock {
    start: Instant,
}
impl Clock {
    fn now(&self) -> Stamp {
        Stamp {
            utc_ns: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos() as u64,
            mono_ns: self.start.elapsed().as_nanos() as u64,
        }
    }
}

#[derive(Clone, Debug)]
struct Network {
    network: u32,
    mask: u32,
}
impl Network {
    fn parse(s: &str) -> Result<Self, String> {
        let (ip, prefix) = s.split_once('/').unwrap_or((s, "32"));
        let ip: Ipv4Addr = ip
            .parse()
            .map_err(|_| "source must be literal private IPv4/CIDR")?;
        let prefix: u32 = prefix.parse().map_err(|_| "invalid source CIDR")?;
        if prefix > 32 || prefix == 0 {
            return Err("invalid source CIDR".into());
        }
        let mask = u32::MAX.checked_shl(32 - prefix).unwrap_or(0);
        let network = u32::from(ip) & mask;
        let permitted = |ip: Ipv4Addr| ip.is_private() || ip.is_loopback();
        if !permitted(Ipv4Addr::from(network)) || !permitted(Ipv4Addr::from(network | !mask)) {
            return Err("source CIDR must be confined to private IPv4".into());
        }
        Ok(Self { network, mask })
    }
    fn contains(&self, ip: IpAddr) -> bool {
        match ip {
            IpAddr::V4(ip) => (u32::from(ip) & self.mask) == self.network,
            _ => false,
        }
    }
}

struct Options {
    udp: SocketAddr,
    http: SocketAddr,
    nodes: Vec<u8>,
    sources: Vec<Network>,
    source_text: Vec<String>,
    record: Option<PathBuf>,
    capture_dir: Option<PathBuf>,
    capture_socket: Option<PathBuf>,
    record_seconds: u64,
    record_bytes: u64,
}
impl Options {
    fn read() -> Result<Self, String> {
        let mut udp = "0.0.0.0:5015".to_owned();
        let mut http = "0.0.0.0:5016".to_owned();
        let mut nodes = "1,2,3".to_owned();
        let mut source_text = Vec::new();
        let mut record = None;
        let mut capture_dir = None;
        let mut capture_socket = None;
        let mut record_seconds = 600;
        let mut record_bytes = 100_000_000;
        let mut args = env::args().skip(1);
        while let Some(arg) = args.next() {
            if arg == "--help" {
                println!("ruview-server-modules --allow-source PRIVATE_IP_OR_CIDR [--nodes 1,2,3] [--listen-udp 0.0.0.0:5015] [--listen-http 0.0.0.0:5016] [--record-jsonl EXCLUSIVE_PATH --record-seconds 600 --record-max-bytes 100000000] [--capture-directory PRIVATE_SESSION_DIR --capture-admin-socket PRIVATE_NEW_SOCKET]");
                println!("ruview-server-modules capture-control SOCKET JSON\nruview-server-modules capture-export DIRECTORY SESSION opening|terminal|raw");
                std::process::exit(0);
            }
            let value = args.next().ok_or("missing argument value")?;
            match arg.as_str() {
                "--listen-udp" => udp = value,
                "--listen-http" => http = value,
                "--nodes" => nodes = value,
                "--allow-source" => source_text.push(value),
                "--record-jsonl" => record = Some(PathBuf::from(value)),
                "--capture-directory" => capture_dir = Some(PathBuf::from(value)),
                "--capture-admin-socket" => capture_socket = Some(PathBuf::from(value)),
                "--record-seconds" => {
                    record_seconds = value.parse().map_err(|_| "invalid recording duration")?
                }
                "--record-max-bytes" => {
                    record_bytes = value.parse().map_err(|_| "invalid recording limit")?
                }
                _ => return Err("unknown argument".into()),
            }
        }
        let nodes: Vec<u8> = nodes
            .split(',')
            .map(str::parse)
            .collect::<Result<_, _>>()
            .map_err(|_| "invalid node IDs")?;
        if nodes.is_empty()
            || nodes.len() > 10
            || nodes.iter().any(|v| !(1..=16).contains(v))
            || nodes
                .iter()
                .enumerate()
                .any(|(i, n)| nodes[..i].contains(n))
        {
            return Err("need 1..10 unique nodes in 1..16".into());
        }
        if source_text.is_empty() || source_text.len() > 16 {
            return Err("explicit source allowlist required (maximum16)".into());
        }
        let sources = source_text
            .iter()
            .map(|s| Network::parse(s))
            .collect::<Result<_, _>>()?;
        if !(1..=3600).contains(&record_seconds) || !(1024..=1_000_000_000).contains(&record_bytes)
        {
            return Err("recording limits out of bounds".into());
        }
        if capture_dir.is_some() != capture_socket.is_some() {
            return Err("both capture directory and Unix admin socket are required".into());
        }
        Ok(Self {
            udp: udp.parse().map_err(|_| "invalid UDP address")?,
            http: http.parse().map_err(|_| "invalid HTTP address")?,
            nodes,
            sources,
            source_text,
            record,
            capture_dir,
            capture_socket,
            record_seconds,
            record_bytes,
        })
    }
}
#[derive(Default)]
struct Counters {
    received: AtomicU64,
    rejected: AtomicU64,
    source_rejected: AtomicU64,
    queue_dropped: AtomicU64,
    processing_stale: AtomicU64,
    record_dropped: AtomicU64,
    record_written: AtomicU64,
    record_error: AtomicU64,
    record_limit_reached: AtomicU64,
    main_loop_progress_ns: AtomicU64,
}
impl Counters {
    fn json(&self) -> Value {
        macro_rules! get {
            ($name:ident) => {
                self.$name.load(Ordering::Relaxed)
            };
        }
        json!({"received":get!(received),"rejected":get!(rejected),"source_rejected":get!(source_rejected),
            "queue_dropped":get!(queue_dropped),"processing_stale":get!(processing_stale),
            "record_dropped":get!(record_dropped),"record_written":get!(record_written),"record_error":get!(record_error),"record_limit_reached":get!(record_limit_reached)})
    }
}
struct Received {
    packet: packet::Packet,
    stamp: Stamp,
    raw_sha: String,
}

fn healthy(counters: &Counters, now: impl FnOnce() -> Stamp) -> bool {
    // Acquire keeps the clock read after this sample. The processor may
    // advance while HTTP samples time; that must not look like future progress.
    let progress = counters.main_loop_progress_ns.load(Ordering::Acquire);
    now()
        .mono_ns
        .checked_sub(progress)
        .is_some_and(|age| age <= 10_000_000_000)
}

fn response(
    mut stream: TcpStream,
    shared: &SnapshotCache<Value>,
    clock: &Clock,
    counters: &Counters,
) {
    let _ = stream.set_write_timeout(Some(Duration::from_millis(750)));
    let deadline = Instant::now() + Duration::from_millis(750);
    let mut buffer = [0u8; 2048];
    let mut total = 0;
    loop {
        if total == buffer.len() {
            return;
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return;
        }
        let _ = stream.set_read_timeout(Some(remaining));
        match stream.read(&mut buffer[total..]) {
            Ok(0) | Err(_) => return,
            Ok(n) => total += n,
        }
        if buffer[..total].windows(4).any(|v| v == b"\r\n\r\n") {
            break;
        }
    }
    let request = match std::str::from_utf8(&buffer[..total]) {
        Ok(v) => v,
        Err(_) => return,
    };
    let first = request.lines().next().unwrap_or("");
    let (status, body) = match first {
        "GET /health HTTP/1.1" | "GET /health HTTP/1.0" => {
            if healthy(counters, || clock.now()) {
                (
                    "200 OK",
                    json!({"status":"ok","recognition_validated":false}),
                )
            } else {
                (
                    "503 Service Unavailable",
                    json!({"status":"processor_unresponsive"}),
                )
            }
        }
        "GET /v1/latest HTTP/1.1"
        | "GET /v1/latest HTTP/1.0"
        | "GET /v1/events HTTP/1.1"
        | "GET /v1/events HTTP/1.0" => {
            let cached = shared.load();
            let mut value = cached.as_ref().clone();
            age_snapshot(&mut value, clock.now());
            value["counters"] = counters.json();
            ("200 OK", value)
        }
        _ => (
            "404 Not Found",
            json!({"error":"read_only_endpoint_not_found"}),
        ),
    };
    let mut bytes = serde_json::to_vec(&body).unwrap();
    let mut status = status;
    if bytes.len() > MAX_HTTP {
        status = "503 Service Unavailable";
        bytes = b"{\"error\":\"snapshot_limit\"}".to_vec();
    }
    let (bytes, encoding) = match http_encoding::encode(bytes, request) {
        Some(body) => (
            body.bytes,
            if body.gzip {
                "Content-Encoding: gzip\r\n"
            } else {
                ""
            },
        ),
        None => {
            status = "406 Not Acceptable";
            (Vec::new(), "")
        }
    };
    let header=format!("HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n{encoding}Vary: Accept-Encoding\r\nConnection: close\r\nCache-Control: no-store\r\n\r\n",bytes.len());
    let _ = stream
        .write_all(header.as_bytes())
        .and_then(|_| stream.write_all(&bytes));
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    if capture::cli(&env::args().skip(1).collect::<Vec<_>>())? {
        return Ok(());
    }
    let options = Options::read().map_err(std::io::Error::other)?;
    let clock = Clock {
        start: Instant::now(),
    };
    let initial = clock.now();
    let run_id = fs::read_to_string("/proc/sys/kernel/random/uuid")?
        .trim()
        .to_owned();
    let boot_id = fs::read_to_string("/proc/sys/kernel/random/boot_id")?
        .trim()
        .to_owned();
    let clock_id = format!("{boot_id}/{run_id}");
    let provenance: Value = serde_json::from_str(PROVENANCE)?;
    let mut configuration = json!({"schema":"ruview.server-modules.config.v1","provenance":provenance,
        "nodes":options.nodes,"allowed_sources":options.source_text,"feature_contract":"home-raw64-v1",
        "source_pair_order":"esp_idf_imaginary_real","phase_convention":"ruview_legacy_atan2_byte1_byte0",
        "allowed_adr018_flags":[0,16],"sync_valid_flag_interpretation":"preserved_metadata_not_device_clock",
        "udp_address":options.udp.to_string(),"http_address":options.http.to_string(),
        "fresh_ns":FRESH_NS,"queue_capacity":QUEUE,"recognition_validated":false});
    if options.capture_dir.is_some() {
        configuration["capture_protocol"] = json!("ruview.capture.control.v2");
    }
    let configuration_sha256 = sha256(&serde_json::to_vec(&configuration)?);
    let mut engine = Engine::new(
        &options.nodes,
        &run_id,
        &clock_id,
        &configuration_sha256,
        &provenance,
    );
    let shared = Arc::new(SnapshotCache::new(engine.snapshot()));
    let counters = Arc::new(Counters::default());
    // Bind both ports and exclusively open any recording before spawning threads.
    let udp = UdpSocket::bind(options.udp)?;
    let http = TcpListener::bind(options.http)?;
    let record = if let Some(path) = &options.record {
        Some(
            OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(path)?,
        )
    } else {
        None
    };
    let mut capture_ingress =
        if let (Some(directory), Some(socket)) = (&options.capture_dir, &options.capture_socket) {
            let capture_clock = clock.clone();
            let ingress = capture::start(
                directory.clone(),
                socket.clone(),
                capture::Identity {
                    worker_run_id: run_id.clone(),
                    clock_id: clock_id.clone(),
                    configuration_sha256: configuration_sha256.clone(),
                    worker_start: initial,
                    nodes: options.nodes.clone(),
                },
                Arc::new(move || capture_clock.now()),
            );
            // Only opt-in local capture needs idle command barriers; no extra listener or CSI.
            match ingress {
                Ok(ingress) => {
                    udp.set_read_timeout(Some(Duration::from_millis(20)))?;
                    Some(ingress)
                }
                Err(error) => {
                    eprintln!(
                        "capture control unavailable: {}; CSI continues",
                        capture::setup_failure_reason(error.as_ref())
                    );
                    None
                }
            }
        } else {
            None
        };
    let (send, receive) = mpsc::sync_channel(QUEUE);
    let recv_clock = clock.clone();
    let recv_counters = counters.clone();
    let nodes = options.nodes.clone();
    let sources = options.sources.clone();
    thread::Builder::new()
        .name("csi-receiver".into())
        .spawn(move || {
            let mut buffer = [0u8; 8192];
            loop {
                if let Some(capture) = &mut capture_ingress {
                    capture.poll(recv_clock.now());
                }
                let (length, source) = match udp.recv_from(&mut buffer) {
                    Ok(v) => v,
                    Err(_) => {
                        thread::sleep(Duration::from_millis(10));
                        continue;
                    }
                };
                let stamp = recv_clock.now();
                recv_counters.received.fetch_add(1, Ordering::Relaxed);
                if !sources.iter().any(|n| n.contains(source.ip())) {
                    recv_counters
                        .source_rejected
                        .fetch_add(1, Ordering::Relaxed);
                    continue;
                }
                let packet = match packet::parse(&buffer[..length], &nodes) {
                    Ok(v) => v,
                    Err(_) => {
                        recv_counters.rejected.fetch_add(1, Ordering::Relaxed);
                        continue;
                    }
                };
                if let Some(capture) = &mut capture_ingress {
                    capture.frame(&packet, stamp, &buffer[..length]);
                }
                let item = Received {
                    packet,
                    stamp,
                    raw_sha: sha256(&buffer[..length]),
                };
                match send.try_send(item) {
                    Ok(()) => {}
                    Err(TrySendError::Full(_)) => {
                        recv_counters.queue_dropped.fetch_add(1, Ordering::Relaxed);
                    }
                    Err(TrySendError::Disconnected(_)) => return,
                }
            }
        })?;
    let http_shared = shared.clone();
    let http_clock = clock.clone();
    let http_counters = counters.clone();
    thread::Builder::new()
        .name("http-status".into())
        .spawn(move || {
            for stream in http.incoming().flatten() {
                response(stream, &http_shared, &http_clock, &http_counters);
            }
        })?;
    let recorder = if let Some(mut file) = record {
        let (tx, rx) = mpsc::sync_channel::<Value>(QUEUE);
        let stats = counters.clone();
        let max_bytes = options.record_bytes;
        let deadline = options.record_seconds * 1_000_000_000;
        let record_clock = clock.clone();
        thread::Builder::new()
            .name("bounded-recorder".into())
            .spawn(move || {
                let mut written = 0;
                loop {
                    if record_clock.now().mono_ns > deadline {
                        stats.record_limit_reached.store(1, Ordering::Relaxed);
                        break;
                    }
                    let row = match rx.recv_timeout(Duration::from_millis(100)) {
                        Ok(v) => v,
                        Err(mpsc::RecvTimeoutError::Timeout) => continue,
                        Err(_) => break,
                    };
                    let mut bytes = serde_json::to_vec(&row).unwrap();
                    bytes.push(b'\n');
                    if written + bytes.len() as u64 > max_bytes {
                        stats.record_limit_reached.store(1, Ordering::Relaxed);
                        break;
                    }
                    if file.write_all(&bytes).is_err() {
                        stats.record_error.store(1, Ordering::Relaxed);
                        break;
                    }
                    written += bytes.len() as u64;
                    stats.record_written.fetch_add(1, Ordering::Relaxed);
                }
                if file.sync_all().is_err() {
                    stats.record_error.store(1, Ordering::Relaxed);
                }
            })?;
        Some(tx)
    } else {
        None
    };
    eprintln!(
        "{}",
        json!({"status":"started","worker_run_id":run_id,"clock_id":clock_id,"configuration_sha256":configuration_sha256,"catalog_count":64,"selected_algorithm_count":engine::SELECTED_ALGORITHM_COUNT})
    );
    let mut publication = PublicationSchedule::new(initial.mono_ns);
    loop {
        counters
            .main_loop_progress_ns
            .store(clock.now().mono_ns, Ordering::Relaxed);
        match receive.recv_timeout(Duration::from_millis(100)) {
            Ok(item) => {
                if let Some(tx) = &recorder {
                    let p = &item.packet;
                    let raw = json!({"schema":"ruview.csi.frame.v1","session_id":run_id,"node_id":p.node_id,
                        "received_at_ns":item.stamp.utc_ns,"received_monotonic_ns":item.stamp.mono_ns,
                        "clock_id":clock_id,"monotonic_origin":"worker_start","sequence":p.sequence,
                        "antennas":p.grid.antennas,"subcarriers":p.grid.subcarriers,"frequency_mhz":p.grid.frequency_mhz,
                        "ppdu_type":p.grid.ppdu_type,"flags":p.grid.flags,"iq":p.iq.as_slice(),"iq_order":"wire_byte_order",
                        "source_pair_order":"esp_idf_imaginary_real","worker_phase_convention":"ruview_legacy_atan2_byte1_byte0",
                        "configuration_sha256":configuration_sha256,"device_boot_id":Value::Null,"device_timestamp":Value::Null,
                        "rssi_dbm":p.rssi_dbm,"noise_floor_dbm":p.noise_floor_dbm,"raw_datagram_sha256":item.raw_sha});
                    if tx.try_send(raw).is_err() {
                        counters.record_dropped.fetch_add(1, Ordering::Relaxed);
                    }
                }
                if clock.now().mono_ns.saturating_sub(item.stamp.mono_ns) > FRESH_NS {
                    counters.processing_stale.fetch_add(1, Ordering::Relaxed);
                } else {
                    engine.process(item.packet, item.stamp);
                }
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => return Err("receiver stopped".into()),
        }
        publication.publish_if_due(
            clock.now().mono_ns,
            || shared.publish(engine.snapshot()),
            || clock.now().mono_ns,
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn socket_response(request: &[u8], value: Value, elapsed: Duration) -> Vec<u8> {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let clock = Clock {
            start: Instant::now() - elapsed,
        };
        let shared = SnapshotCache::new(value);
        let counters = Counters::default();
        counters.received.store(23, Ordering::Relaxed);
        thread::scope(|scope| {
            scope.spawn(|| {
                let (stream, _) = listener.accept().unwrap();
                response(stream, &shared, &clock, &counters);
            });
            let mut stream = TcpStream::connect(address).unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            stream.write_all(request).unwrap();
            let mut reply = Vec::new();
            if let Err(error) = stream.read_to_end(&mut reply) {
                assert_eq!(error.kind(), std::io::ErrorKind::ConnectionReset);
            }
            reply
        })
    }

    fn decode_response(reply: &[u8]) -> (String, Vec<u8>) {
        let end = reply
            .windows(4)
            .position(|part| part == b"\r\n\r\n")
            .unwrap()
            + 4;
        let headers = String::from_utf8(reply[..end].to_vec()).unwrap();
        let length: usize = headers
            .lines()
            .find_map(|line| line.strip_prefix("Content-Length: "))
            .unwrap()
            .parse()
            .unwrap();
        let wire = &reply[end..];
        assert_eq!(wire.len(), length);
        assert!(headers.contains("\r\nVary: Accept-Encoding\r\n"));
        let mut decoded = Vec::new();
        if headers.contains("Content-Encoding: gzip\r\n") {
            flate2::read::GzDecoder::new(wire)
                .read_to_end(&mut decoded)
                .unwrap();
        } else {
            decoded.extend_from_slice(wire);
        }
        (headers, decoded)
    }

    #[test]
    fn real_http_gzip_preserves_observations_and_ages_expired_input() {
        let value = json!({"payload":"x".repeat(4096), "worker_run_id":"original-run",
            "nodes":[{"last_received_monotonic_ns":"1", "last_received_at_ns":"123", "sequence":7,
                "algorithms":[{"availability":"running"}]}],
            "events":[{"observed_monotonic_ns":"1", "observed_at_ns":"123", "occurrence_seq":9}]});
        for endpoint in ["/v1/latest", "/v1/events"] {
            let request = format!("GET {endpoint} HTTP/1.1\r\nAccept-Encoding: gzip\r\n\r\n");
            let (headers, decoded) = decode_response(&socket_response(
                request.as_bytes(),
                value.clone(),
                Duration::from_secs(3),
            ));
            assert!(headers.starts_with("HTTP/1.1 200 OK\r\n"));
            assert!(headers.contains("Content-Encoding: gzip\r\n"));
            let result: Value = serde_json::from_slice(&decoded).unwrap();
            assert_eq!(result["payload"], value["payload"]);
            assert_eq!(result["worker_run_id"], "original-run");
            assert_eq!(result["nodes"][0]["sequence"], 7);
            assert_eq!(result["nodes"][0]["last_received_at_ns"], "123");
            assert_eq!(result["nodes"][0]["last_received_monotonic_ns"], "1");
            assert_eq!(result["nodes"][0]["fresh"], false);
            assert_eq!(result["nodes"][0]["algorithms"][0]["availability"], "stale");
            assert_eq!(result["events"][0]["observed_at_ns"], "123");
            assert_eq!(result["events"][0]["occurrence_seq"], 9);
            assert_eq!(result["events"][0]["fresh"], false);
            assert_eq!(result["counters"]["received"], 23);
        }
    }

    #[test]
    fn real_http_limits_apply_before_compression_and_negotiation() {
        let request = b"GET /v1/latest HTTP/1.1\r\nAccept-Encoding: gzip\r\n\r\n";
        let (headers, decoded) = decode_response(&socket_response(
            request,
            json!({"oversize":"x".repeat(MAX_HTTP)}),
            Duration::ZERO,
        ));
        assert!(headers.starts_with("HTTP/1.1 503 Service Unavailable\r\n"));
        assert!(!headers.contains("Content-Encoding:"));
        assert_eq!(decoded, b"{\"error\":\"snapshot_limit\"}");
        for headers in ["", "Accept-Encoding: gzip;q=0, *\r\n"] {
            let request = format!("GET /v1/latest HTTP/1.1\r\n{headers}\r\n");
            let (reply, _) = decode_response(&socket_response(
                request.as_bytes(),
                json!({"payload":"x".repeat(4096)}),
                Duration::ZERO,
            ));
            assert!(!reply.contains("Content-Encoding:"));
        }
        let (headers, decoded) = decode_response(&socket_response(
            b"GET /health HTTP/1.1\r\nAccept-Encoding: *;q=0\r\n\r\n",
            json!({}),
            Duration::ZERO,
        ));
        assert!(headers.starts_with("HTTP/1.1 406 Not Acceptable\r\n"));
        assert!(decoded.is_empty());
        let oversized = format!("GET /health HTTP/1.1\r\nX-Fill: {}", "x".repeat(2048));
        assert!(socket_response(oversized.as_bytes(), json!({}), Duration::ZERO).is_empty());
        assert!(socket_response(b"GET /health HTTP/1.1\r\n", json!({}), Duration::ZERO).is_empty());
    }
    #[test]
    fn health_requires_processor_progress_not_csi_or_http_activity() {
        let counters = Counters::default();
        assert!(healthy(&counters, || Stamp {
            utc_ns: 0,
            mono_ns: 1_000_000_000
        }));
        assert!(!healthy(&counters, || Stamp {
            utc_ns: 0,
            mono_ns: 11_000_000_000
        }));
        counters
            .main_loop_progress_ns
            .store(11_000_000_000, Ordering::Relaxed);
        assert!(healthy(&counters, || Stamp {
            utc_ns: 0,
            mono_ns: 11_500_000_000
        }));
        assert!(!healthy(&counters, || Stamp {
            utc_ns: 0,
            mono_ns: 10_000_000_000
        }));
    }
    #[test]
    fn health_does_not_reject_progress_published_while_sampling_the_clock() {
        let counters = Counters::default();
        counters
            .main_loop_progress_ns
            .store(20_000_000_000, Ordering::Relaxed);
        assert!(healthy(&counters, || {
            // The clock was sampled, then the HTTP thread was preempted by
            // the processor before it could use that earlier timestamp.
            let sampled = Stamp {
                utc_ns: 0,
                mono_ns: 20_500_000_000,
            };
            counters
                .main_loop_progress_ns
                .store(20_500_000_001, Ordering::Relaxed);
            sampled
        }));
    }
    #[test]
    fn health_keeps_exact_stall_deadline_and_rejects_future_progress() {
        let counters = Counters::default();
        counters
            .main_loop_progress_ns
            .store(20_000_000_000, Ordering::Relaxed);
        for (now, expected) in [
            (30_000_000_000, true),
            (30_000_000_001, false),
            (19_999_999_999, false),
        ] {
            assert_eq!(
                healthy(&counters, || Stamp {
                    utc_ns: 0,
                    mono_ns: now,
                }),
                expected
            );
        }
    }
    #[test]
    fn network_allowlist_is_literal_confined_and_exact() {
        let net = Network::parse("10.42.0.0/24").unwrap();
        assert!(net.contains("10.42.0.3".parse().unwrap()));
        assert!(!net.contains("10.42.1.3".parse().unwrap()));
        assert!(!net.contains("::1".parse().unwrap()));
        for bad in [
            "host.invalid",
            "0.0.0.0/0",
            "10.0.0.0/7",
            "192.168.1.1/33",
            "8.8.8.8",
        ] {
            assert!(Network::parse(bad).is_err());
        }
    }
}
