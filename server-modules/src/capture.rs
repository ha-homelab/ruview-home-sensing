//! Optional local capture control. Recorder backpressure never blocks CSI ingestion.
use ruview_server_modules::{engine::Stamp, packet::Packet, sha256};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::unix::{
        fs::{DirBuilderExt, FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt},
        net::{UnixListener, UnixStream},
    },
    path::{Component, Path, PathBuf},
    sync::{
        mpsc::{self, Receiver, SyncSender, TryRecvError, TrySendError},
        Arc,
    },
    thread,
    time::{Duration, Instant},
};

const QUEUE: usize = 64;
const MAX_COMMAND: usize = 4096;
const MAX_REPLY: usize = 16384;
const MAX_SESSIONS: usize = 8;
const MAX_TOTAL_BYTES: u64 = 256 * 1024 * 1024;
const MAX_SESSION_BYTES: u64 = 100 * 1024 * 1024;
const DRAIN_TIMEOUT_NS: u64 = 5_000_000_000;
const CONTROL_SCHEMA: &str = "ruview.capture.control.v2";
type Clock = Arc<dyn Fn() -> Stamp + Send + Sync>;

#[derive(Clone)]
pub struct Identity {
    pub worker_run_id: String,
    pub clock_id: String,
    pub configuration_sha256: String,
    pub worker_start: Stamp,
    pub nodes: Vec<u8>,
}
impl Identity {
    fn fields(&self, session: &str) -> Value {
        json!({"session_id":session,"capture_id":session,"worker_run_id":self.worker_run_id,
            "clock_id":self.clock_id,"configuration_sha256":self.configuration_sha256})
    }
}
fn stamp(s: Stamp) -> Value {
    json!({"utc_ns":s.utc_ns,"monotonic_ns":s.mono_ns})
}
fn with_identity(mut value: Value, identity: &Identity, session: &str) -> Value {
    value
        .as_object_mut()
        .unwrap()
        .extend(identity.fields(session).as_object().unwrap().clone());
    value
}
fn canonical_uuid(s: &str) -> bool {
    s.len() == 36
        && s.bytes().enumerate().all(|(i, b)| {
            if [8, 13, 18, 23].contains(&i) {
                b == b'-'
            } else {
                b.is_ascii_digit() || (b'a'..=b'f').contains(&b)
            }
        })
}
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct StrictCommand {
    schema: String,
    op: String,
    session_id: String,
    node_ids: Option<Vec<u8>>,
    duration_ms: Option<u64>,
    max_bytes: Option<u64>,
}
#[derive(Clone, Debug)]
struct Request {
    op: String,
    session: String,
    nodes: Vec<u8>,
    duration_ms: u64,
    max_bytes: u64,
}
fn request(raw: &[u8], identity: &Identity) -> Result<Request, &'static str> {
    if raw.len() > MAX_COMMAND {
        return Err("command_limit");
    }
    // Derived deserialization rejects duplicate keys as well as unknown fields.
    let checked: StrictCommand = serde_json::from_slice(raw).map_err(|_| "invalid_json")?;
    let _ = (
        checked.schema,
        checked.op,
        checked.session_id,
        checked.node_ids,
        checked.duration_ms,
        checked.max_bytes,
    );
    let v: Value = serde_json::from_slice(raw).map_err(|_| "invalid_json")?;
    let obj = v.as_object().ok_or("command_object")?;
    if v["schema"] != CONTROL_SCHEMA {
        return Err("command_schema");
    }
    let op = v["op"].as_str().ok_or("command_op")?;
    let wanted: BTreeSet<&str> = if op == "start" {
        [
            "schema",
            "op",
            "session_id",
            "node_ids",
            "duration_ms",
            "max_bytes",
        ]
        .into_iter()
        .collect()
    } else if op == "stop" || op == "status" {
        ["schema", "op", "session_id"].into_iter().collect()
    } else {
        return Err("command_op");
    };
    if obj.keys().map(String::as_str).collect::<BTreeSet<_>>() != wanted {
        return Err("command_fields");
    }
    let session = v["session_id"].as_str().ok_or("session_id")?;
    if !canonical_uuid(session) || session == identity.worker_run_id {
        return Err("session_id");
    }
    let mut r = Request {
        op: op.into(),
        session: session.into(),
        nodes: vec![],
        duration_ms: 0,
        max_bytes: 0,
    };
    if op == "start" {
        r.duration_ms = v["duration_ms"]
            .as_u64()
            .filter(|n| (1..=3_600_000).contains(n))
            .ok_or("duration_limit")?;
        r.max_bytes = v["max_bytes"]
            .as_u64()
            .filter(|n| (1024..=MAX_SESSION_BYTES).contains(n))
            .ok_or("byte_limit")?;
        for n in v["node_ids"].as_array().ok_or("node_ids")? {
            let n = n
                .as_u64()
                .and_then(|n| u8::try_from(n).ok())
                .ok_or("node_ids")?;
            if !identity.nodes.contains(&n) || r.nodes.last().is_some_and(|old| *old >= n) {
                return Err("node_ids");
            }
            r.nodes.push(n);
        }
        if r.nodes.is_empty() {
            return Err("node_ids");
        }
    }
    Ok(r)
}
#[derive(Clone, Copy, Debug)]
struct Boundary {
    clock: Stamp,
    ingress: u64,
}
impl Boundary {
    fn json(&self) -> Value {
        json!({"clock":stamp(self.clock),"ingress_sequence":self.ingress})
    }
}
#[derive(Clone, Default, Debug)]
struct Counts {
    admitted: u64,
    enqueued: u64,
    dropped: u64,
    disconnected: u64,
}
#[derive(Clone, Debug)]
struct Cut {
    boundary: Boundary,
    reason: &'static str,
    counts: Counts,
}
#[derive(Debug)]
struct Frame {
    packet: Packet,
    stamp: Stamp,
    raw: Vec<u8>,
    ingress: u64,
    capture: u64,
}
#[derive(Debug)]
enum Command {
    Start {
        session: String,
        nodes: Vec<u8>,
        duration_ms: u64,
        writer: SyncSender<Frame>,
        started: SyncSender<Boundary>,
        ended: SyncSender<Cut>,
    },
    Stop {
        session: String,
        reason: &'static str,
    },
}
struct Active {
    session: String,
    nodes: Vec<u8>,
    deadline: u64,
    writer: SyncSender<Frame>,
    ended: SyncSender<Cut>,
    counts: Counts,
}
pub struct Ingress {
    commands: Receiver<Command>,
    active: Option<Active>,
    ordinal: u64,
}
impl Ingress {
    /// Called by the sole UDP receiver before every bounded receive. No I/O or blocking send.
    pub fn poll(&mut self, now: Stamp) {
        for _ in 0..8 {
            let Ok(command) = self.commands.try_recv() else {
                break;
            };
            match command {
                Command::Start {
                    session,
                    nodes,
                    duration_ms,
                    writer,
                    started,
                    ended,
                } => {
                    if self.active.is_some() {
                        continue;
                    } // Controller never issues overlapping starts.
                    let boundary = Boundary {
                        clock: now,
                        ingress: self.ordinal,
                    };
                    self.active = Some(Active {
                        session,
                        nodes,
                        deadline: now.mono_ns + duration_ms * 1_000_000,
                        writer,
                        ended,
                        counts: Counts::default(),
                    });
                    let _ = started.try_send(boundary);
                }
                Command::Stop { session, reason } => {
                    if self.active.as_ref().is_some_and(|s| s.session == session) {
                        self.cut(now, reason);
                    }
                }
            }
        }
        if self
            .active
            .as_ref()
            .is_some_and(|s| now.mono_ns >= s.deadline)
        {
            self.cut(now, "duration_elapsed");
        }
    }
    fn cut(&mut self, now: Stamp, reason: &'static str) {
        if let Some(active) = self.active.take() {
            let cut = Cut {
                boundary: Boundary {
                    clock: now,
                    ingress: self.ordinal,
                },
                reason,
                counts: active.counts,
            };
            // Closing this sole sender is the FIFO drain barrier, independent of queue fullness.
            drop(active.writer);
            let _ = active.ended.try_send(cut);
        }
    }
    /// Actual receiver admission, before the independent engine queue. No serialization.
    pub fn frame(&mut self, packet: &Packet, received: Stamp, raw: &[u8]) {
        if self
            .active
            .as_ref()
            .is_some_and(|s| received.mono_ns >= s.deadline)
        {
            self.cut(received, "duration_elapsed");
        }
        self.ordinal += 1;
        if let Some(active) = &mut self.active {
            if !active.nodes.contains(&packet.node_id) {
                return;
            }
            active.counts.admitted += 1;
            let frame = Frame {
                packet: packet.clone(),
                stamp: received,
                raw: raw.to_vec(),
                ingress: self.ordinal,
                capture: active.counts.admitted,
            };
            match active.writer.try_send(frame) {
                Ok(()) => active.counts.enqueued += 1,
                Err(TrySendError::Full(_)) => active.counts.dropped += 1,
                Err(TrySendError::Disconnected(_)) => active.counts.disconnected += 1,
            }
        }
    }
}
impl Drop for Ingress {
    fn drop(&mut self) {
        if let Some(active) = self.active.take() {
            drop(active.writer);
        }
    }
}
fn row(frame: &Frame, identity: &Identity, session: &str) -> Value {
    let p = &frame.packet;
    with_identity(
        json!({"schema":"ruview.csi.frame.v2","capture_sequence":frame.capture,"ingress_sequence":frame.ingress,
        "node_id":p.node_id,"received_at_ns":frame.stamp.utc_ns,"received_monotonic_ns":frame.stamp.mono_ns,
        "monotonic_origin":"worker_start","sequence":p.sequence,"antennas":p.grid.antennas,"subcarriers":p.grid.subcarriers,
        "frequency_mhz":p.grid.frequency_mhz,"ppdu_type":p.grid.ppdu_type,"flags":p.grid.flags,"iq":p.iq.as_slice(),
        "admission":p.admission,
        "iq_order":"wire_byte_order","source_pair_order":"esp_idf_imaginary_real","worker_phase_convention":"ruview_legacy_atan2_byte1_byte0",
        "device_boot_id":Value::Null,"device_timestamp":Value::Null,"rssi_dbm":p.rssi_dbm,"noise_floor_dbm":p.noise_floor_dbm,
        "raw_datagram_sha256":sha256(&frame.raw),"raw_datagram_hex":frame.raw.iter().map(|b|format!("{b:02x}")).collect::<String>()}),
        identity,
        session,
    )
}
#[derive(Debug)]
struct Written {
    bytes: u64,
    frames: u64,
    sha: String,
    write_errors: u64,
    byte_limit: u64,
    fsynced: bool,
    finished: Stamp,
}
trait DurableWrite: Write {
    fn sync_capture(&self) -> std::io::Result<()>;
}
impl DurableWrite for File {
    fn sync_capture(&self) -> std::io::Result<()> {
        self.sync_all()
    }
}
fn writer<F: DurableWrite>(
    mut file: F,
    frames: Receiver<Frame>,
    identity: Identity,
    session: String,
    max_bytes: u64,
    clock: Clock,
) -> Written {
    let mut digest = Sha256::new();
    let mut bytes = 0u64;
    let mut written = 0u64;
    let mut write_errors = 0;
    let mut byte_limit = 0;
    'rows: while let Ok(frame) = frames.recv() {
        let mut data = serde_json::to_vec(&row(&frame, &identity, &session)).unwrap();
        data.push(b'\n');
        if bytes + data.len() as u64 > max_bytes {
            byte_limit = 1;
            break;
        }
        let mut offset = 0;
        while offset < data.len() {
            match file.write(&data[offset..]) {
                Ok(0) | Err(_) => {
                    write_errors += 1;
                    break 'rows;
                }
                Ok(n) => {
                    digest.update(&data[offset..offset + n]);
                    bytes += n as u64;
                    offset += n;
                }
            }
        }
        written += 1;
    }
    let fsynced = file.sync_capture().is_ok();
    if !fsynced {
        write_errors += 1;
    }
    drop(file); // Terminal receipt is never emitted while the raw writer owns this descriptor.
    Written {
        bytes,
        frames: written,
        sha: format!("{:x}", digest.finalize()),
        write_errors,
        byte_limit,
        fsynced,
        finished: clock(),
    }
}
fn fail_once(failures: &mut Vec<&'static str>, reason: &'static str) {
    if !failures.contains(&reason) {
        failures.push(reason);
    }
}
fn save_json(path: &Path, value: &Value) -> std::io::Result<String> {
    save_json_with_sync(
        path,
        value,
        |file| file.sync_all(),
        |directory| File::open(directory)?.sync_all(),
    )
}
fn save_json_with_sync(
    path: &Path,
    value: &Value,
    sync_file: impl FnOnce(&File) -> std::io::Result<()>,
    sync_directory: impl FnOnce(&Path) -> std::io::Result<()>,
) -> std::io::Result<String> {
    let mut data = serde_json::to_vec_pretty(value)?;
    data.push(b'\n');
    let parent = path.parent().unwrap();
    let pending = parent.join(format!(
        ".{}.pending",
        path.file_name().unwrap().to_str().unwrap()
    ));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&pending)?;
    file.write_all(&data)?;
    sync_file(&file)?;
    drop(file);
    // hard_link is exclusive and makes no replace window. During publication,
    // nlink==2 makes both exports and persisted-storage reuse fail closed.
    fs::hard_link(&pending, path)?;
    sync_directory(parent)?;
    // terminal.json and its contents are durable BEFORE this removal. If crash
    // restores the pending link, export conservatively refuses nlink==2. A
    // failed removal also leaves evidence non-exportable; never claim closure.
    fs::remove_file(&pending)?;
    Ok(sha256(&data))
}
unsafe extern "C" {
    fn geteuid() -> u32;
}
fn private_dir(path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    if !path.is_absolute() {
        return Err("capture path must be absolute".into());
    }
    let mut walk = PathBuf::new();
    for part in path.components() {
        match part {
            Component::RootDir | Component::Normal(_) => walk.push(part),
            _ => return Err("capture path component".into()),
        }
        let m = fs::symlink_metadata(&walk)?;
        if m.file_type().is_symlink() || !m.is_dir() {
            return Err("capture path must contain only real directories".into());
        }
    }
    let m = fs::symlink_metadata(path)?;
    if m.uid() != unsafe { geteuid() } || m.mode() & 0o777 != 0o700 {
        return Err("capture directory must be owned0700".into());
    }
    Ok(())
}
#[cfg(target_os = "linux")]
fn peer_allowed(stream: &UnixStream) -> bool {
    use std::os::fd::AsRawFd;
    #[repr(C)]
    struct Cred {
        pid: i32,
        uid: u32,
        gid: u32,
    }
    unsafe extern "C" {
        fn getsockopt(
            fd: i32,
            level: i32,
            name: i32,
            value: *mut std::ffi::c_void,
            length: *mut u32,
        ) -> i32;
    }
    let mut cred = Cred {
        pid: 0,
        uid: u32::MAX,
        gid: u32::MAX,
    };
    let mut len = std::mem::size_of::<Cred>() as u32;
    unsafe {
        getsockopt(
            stream.as_raw_fd(),
            1,
            17,
            (&mut cred as *mut Cred).cast(),
            &mut len,
        ) == 0
            && len as usize == std::mem::size_of::<Cred>()
            && cred.uid == geteuid()
    }
}
#[cfg(not(target_os = "linux"))]
fn peer_allowed(_stream: &UnixStream) -> bool {
    false
}

struct Session {
    request: Request,
    path: PathBuf,
    started: Receiver<Boundary>,
    ended: Receiver<Cut>,
    written: Receiver<Written>,
    start: Option<Boundary>,
    cut: Option<Cut>,
    output: Option<Written>,
    opening: Option<Value>,
    opening_sha: Option<String>,
    terminal: Option<Value>,
    terminal_attempted: bool,
    failures: Vec<&'static str>,
    stop_sent: bool,
    closing_at: Option<u64>,
}
struct Controller {
    directory: PathBuf,
    identity: Identity,
    clock: Clock,
    commands: SyncSender<Command>,
    sessions: BTreeMap<String, Session>,
    reserved: u64,
    attempts: usize,
    admission_error: Option<&'static str>,
    _storage_lock: Option<File>,
}
impl Controller {
    fn monitor(&mut self) {
        for s in self.sessions.values_mut() {
            if s.terminal.is_some() {
                continue;
            }
            if s.start.is_none() {
                match s.started.try_recv() {
                    Ok(boundary) => {
                        s.start = Some(boundary);
                        let opening = with_identity(
                            json!({"schema":"ruview.capture.opening.v2","worker_start_clock":stamp(self.identity.worker_start),
                        "frame_schema":"ruview.csi.frame.v2","source":"esp32","execution":"server","recognition_validated":false,
                        "node_ids":s.request.nodes,"limits":{"duration_ms":s.request.duration_ms,"max_bytes":s.request.max_bytes},
                        "start_boundary":boundary.json(),"deadline_monotonic_ns":boundary.clock.mono_ns+s.request.duration_ms*1_000_000,
                        "raw_file":"raw.jsonl","scope":"selected admitted native1x64 packets; not lossless RF capture"}),
                            &self.identity,
                            &s.request.session,
                        );
                        match save_json(&s.path.join("opening.json"), &opening) {
                            Ok(hash) => {
                                s.opening = Some(opening);
                                s.opening_sha = Some(hash);
                            }
                            Err(_) => {
                                s.failures.push("opening_write_error");
                            }
                        }
                    }
                    Err(TryRecvError::Disconnected) => {
                        fail_once(&mut s.failures, "receiver_start_disconnected")
                    }
                    Err(TryRecvError::Empty) => {}
                }
            }
            if s.cut.is_none() {
                match s.ended.try_recv() {
                    Ok(cut) => {
                        s.cut = Some(cut);
                        s.closing_at = Some((self.clock)().mono_ns);
                    }
                    Err(TryRecvError::Disconnected) => {
                        fail_once(&mut s.failures, "receiver_end_disconnected")
                    }
                    Err(TryRecvError::Empty) => {}
                }
            }
            if s.output.is_none() {
                match s.written.try_recv() {
                    Ok(output) => s.output = Some(output),
                    Err(TryRecvError::Disconnected) => {
                        fail_once(&mut s.failures, "writer_result_disconnected")
                    }
                    Err(TryRecvError::Empty) => {}
                }
            }
            if (s.output.is_some() || !s.failures.is_empty()) && s.cut.is_none() && !s.stop_sent {
                if self
                    .commands
                    .try_send(Command::Stop {
                        session: s.request.session.clone(),
                        reason: "writer_error",
                    })
                    .is_ok()
                {
                    s.stop_sent = true;
                }
            }
            if s.closing_at
                .is_some_and(|t| (self.clock)().mono_ns.saturating_sub(t) > DRAIN_TIMEOUT_NS)
                && s.output.is_none()
                && !s.failures.contains(&"drain_timeout")
            {
                s.failures.push("drain_timeout"); // Keep pending; never claim the still-open raw file is stable.
            }
            if s.terminal_attempted {
                continue;
            }
            if let (Some(start), Some(cut), Some(w)) = (s.start, s.cut.as_ref(), s.output.as_ref())
            {
                if cut.counts.dropped > 0 {
                    s.failures.push("queue_dropped");
                }
                if cut.counts.disconnected > 0 {
                    s.failures.push("writer_disconnected");
                }
                if w.write_errors > 0 {
                    s.failures.push("write_error");
                }
                if w.byte_limit > 0 {
                    s.failures.push("byte_limit");
                }
                if w.frames != cut.counts.enqueued {
                    s.failures.push("drain_count_mismatch");
                }
                let complete = s.failures.is_empty()
                    && w.fsynced
                    && s.opening_sha.is_some()
                    && cut.counts.admitted == w.frames;
                let terminal = with_identity(
                    json!({"schema":"ruview.capture.terminal.v2","worker_start_clock":stamp(self.identity.worker_start),"frame_schema":"ruview.csi.frame.v2",
                    "node_ids":s.request.nodes,"limits":{"duration_ms":s.request.duration_ms,"max_bytes":s.request.max_bytes},
                    "start_boundary":start.json(),"end_boundary":cut.boundary.json(),"deadline_monotonic_ns":start.clock.mono_ns+s.request.duration_ms*1_000_000,
                    "end_reason":if w.byte_limit>0{"byte_limit"}else{cut.reason},"complete":complete,
                    "counters":{"admitted":cut.counts.admitted,"enqueued":cut.counts.enqueued,"written":w.frames,
                        "queue_dropped":cut.counts.dropped,"writer_disconnected":cut.counts.disconnected,"write_errors":w.write_errors,"byte_limit_rejected":w.byte_limit},
                    "raw":{"file":"raw.jsonl","bytes":w.bytes,"sha256":w.sha,"frames":w.frames,"fsynced":w.fsynced,"closed":true},
                    "opening_sha256":s.opening_sha,"writer_finished_clock":stamp(w.finished),"failures":s.failures}),
                    &self.identity,
                    &s.request.session,
                );
                s.terminal_attempted = true;
                match save_json(&s.path.join("terminal.json"), &terminal) {
                    Ok(_) => s.terminal = Some(terminal),
                    Err(_) => {
                        if !s.failures.contains(&"terminal_write_error") {
                            s.failures.push("terminal_write_error");
                        }
                    }
                }
            }
        }
    }
    fn handle(&mut self, r: Request) -> Result<Value, &'static str> {
        self.monitor();
        if r.op == "start" {
            if let Some(reason) = self.admission_error {
                return Err(reason);
            }
            if self.sessions.contains_key(&r.session) || self.directory.join(&r.session).exists() {
                return Err("session_id_already_used");
            }
            if self.attempts >= MAX_SESSIONS {
                return Err("session_count_limit");
            }
            if self.sessions.values().any(|s| s.terminal.is_none()) {
                return Err("capture_busy");
            }
            if self.reserved + r.max_bytes > MAX_TOTAL_BYTES {
                return Err("storage_reservation_limit");
            }
            let path = self.directory.join(&r.session);
            fs::DirBuilder::new()
                .mode(0o700)
                .create(&path)
                .map_err(|_| "session_directory")?;
            self.reserved += r.max_bytes;
            self.attempts += 1;
            let file = OpenOptions::new()
                .create_new(true)
                .write(true)
                .mode(0o600)
                .open(path.join("raw.jsonl"))
                .map_err(|_| "raw_open")?;
            File::open(&path)
                .and_then(|f| f.sync_all())
                .map_err(|_| "session_directory_sync")?;
            File::open(&self.directory)
                .and_then(|f| f.sync_all())
                .map_err(|_| "session_root_sync")?;
            let (tx, rx) = mpsc::sync_channel(QUEUE);
            let (stx, srx) = mpsc::sync_channel(1);
            let (etx, erx) = mpsc::sync_channel(1);
            let (wtx, wrx) = mpsc::sync_channel(1);
            let identity = self.identity.clone();
            let session = r.session.clone();
            let max = r.max_bytes;
            let clock = self.clock.clone();
            thread::Builder::new()
                .name("capture-writer".into())
                .spawn(move || {
                    let result = writer(file, rx, identity, session, max, clock);
                    let _ = wtx.try_send(result);
                })
                .map_err(|_| "writer_start")?;
            self.sessions.insert(
                r.session.clone(),
                Session {
                    request: r.clone(),
                    path,
                    started: srx,
                    ended: erx,
                    written: wrx,
                    start: None,
                    cut: None,
                    output: None,
                    opening: None,
                    opening_sha: None,
                    terminal: None,
                    terminal_attempted: false,
                    failures: vec![],
                    stop_sent: false,
                    closing_at: None,
                },
            );
            if self
                .commands
                .try_send(Command::Start {
                    session: r.session.clone(),
                    nodes: r.nodes.clone(),
                    duration_ms: r.duration_ms,
                    writer: tx,
                    started: stx,
                    ended: etx,
                })
                .is_err()
            {
                self.sessions
                    .get_mut(&r.session)
                    .unwrap()
                    .failures
                    .push("control_unavailable");
                return Err("control_unavailable");
            }
        } else if r.op == "stop" {
            let s = self.sessions.get_mut(&r.session).ok_or("unknown_session")?;
            if s.terminal.is_none() && !s.stop_sent && s.cut.is_none() {
                self.commands
                    .try_send(Command::Stop {
                        session: r.session.clone(),
                        reason: "manual_stop",
                    })
                    .map_err(|_| "control_unavailable")?;
                s.stop_sent = true;
            }
        }
        self.monitor();
        let s = self.sessions.get(&r.session).ok_or("unknown_session")?;
        Ok(with_identity(
            json!({"schema":"ruview.capture.reply.v2","op":r.op,
            "status":if s.terminal.is_some(){"closed"}else if s.cut.is_some()||s.stop_sent{"closing"}else if s.start.is_some(){"active"}else{"starting"},
            "opening":s.opening,"terminal":s.terminal,"failures":s.failures,"server_clock":stamp((self.clock)())}),
            &self.identity,
            &r.session,
        ))
    }
}
fn serve(mut stream: UnixStream, controller: &mut Controller) {
    if !peer_allowed(&stream) {
        return;
    }
    let deadline = Instant::now() + Duration::from_millis(750);
    let mut raw = Vec::new();
    let mut byte = [0u8; 1];
    let response = (|| -> Result<Value, &'static str> {
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return Err("command_deadline");
            }
            stream
                .set_read_timeout(Some(left))
                .map_err(|_| "command_io")?;
            match stream.read(&mut byte) {
                Ok(1) if byte[0] == b'\n' => break,
                Ok(1) => raw.push(byte[0]),
                _ => return Err("command_io"),
            }
            if raw.len() > MAX_COMMAND {
                return Err("command_limit");
            }
        }
        let r = request(&raw, &controller.identity)?;
        controller.handle(r)
    })();
    let value = response.unwrap_or_else(
        |reason| json!({"schema":"ruview.capture.reply.v2","status":"error","error":reason}),
    );
    let Ok(mut data) = serde_json::to_vec(&value) else {
        return;
    };
    data.push(b'\n');
    if data.len() > MAX_REPLY {
        return;
    }
    if stream
        .set_write_timeout(Some(Duration::from_millis(750)))
        .is_err()
    {
        return;
    }
    let _ = stream.write_all(&data);
}
// One serial connection at a time; admission renews independently of worker lifetime.
struct ControlWindow {
    started_ns: u64,
    admitted: u8,
}
impl ControlWindow {
    fn admit(&mut self, now_ns: u64) -> bool {
        if now_ns < self.started_ns {
            return false;
        }
        if now_ns - self.started_ns >= 1_000_000_000 {
            self.started_ns = now_ns;
            self.admitted = 0;
        }
        if self.admitted >= 32 {
            return false;
        }
        self.admitted += 1;
        true
    }
}

/// Paths are configured locally; no command accepts a filesystem path.
pub fn start(
    directory: PathBuf,
    socket: PathBuf,
    identity: Identity,
    clock: Clock,
) -> Result<Ingress, Box<dyn std::error::Error>> {
    create_private_dir(&directory)?;
    create_private_dir(socket.parent().ok_or("socket_parent")?)?;
    let storage_lock = lock_storage(&directory)?;
    // Reclaim only a proven abandoned owned socket after storage ownership is exclusive.
    // A same-Pod container restart retains its emptyDir and the dead Unix socket name.
    prepare_socket(&socket)?;
    // Every old attempt consumes its UUID/count and conservative storage reservation.
    // Unsafe/full storage disables START only; the primary receiver still runs.
    let (attempts, reserved, admission_error) = match inventory(&directory) {
        Ok((attempts, reserved)) => (attempts, reserved, None),
        Err(_) => (
            MAX_SESSIONS,
            MAX_TOTAL_BYTES,
            Some("capture_storage_unsafe"),
        ),
    };
    let listener = UnixListener::bind(&socket)?;
    fs::set_permissions(&socket, fs::Permissions::from_mode(0o600))?;
    listener.set_nonblocking(true)?;
    let (tx, rx) = mpsc::sync_channel(8);
    let mut controller = Controller {
        directory,
        identity,
        clock,
        commands: tx,
        sessions: BTreeMap::new(),
        reserved,
        attempts,
        admission_error,
        _storage_lock: Some(storage_lock),
    };
    thread::Builder::new()
        .name("capture-admin".into())
        .spawn(move || {
            let control_start = Instant::now();
            let mut window = ControlWindow {
                started_ns: 0,
                admitted: 0,
            };
            loop {
                controller.monitor();
                match listener.accept() {
                    Ok((stream, _)) => {
                        if window.admit(control_start.elapsed().as_nanos() as u64) {
                            serve(stream, &mut controller);
                        } else {
                            drop(stream);
                            thread::sleep(Duration::from_millis(10));
                        }
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(10))
                    }
                    Err(_) => return,
                }
            }
        })?;
    Ok(Ingress {
        commands: rx,
        active: None,
        ordinal: 0,
    })
}

// O_NOFOLLOW differs even between Linux x86-64 and Linux AArch64.
// Use the target ABI constants so a symlink can never become an ordinary open.
const NONBLOCK: i32 = libc::O_NONBLOCK;
const NOFOLLOW: i32 = libc::O_NOFOLLOW;
fn read_private_file(path: &Path, maximum: u64) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(NOFOLLOW | NONBLOCK)
        .open(path)?;
    let before = file.metadata()?;
    if !before.is_file()
        || before.uid() != unsafe { geteuid() }
        || before.mode() & 0o777 != 0o600
        || before.nlink() != 1
        || before.len() > maximum
    {
        return Err("capture file type, ownership, mode, links or size".into());
    }
    let mut bytes = Vec::new();
    (&file).take(maximum + 1).read_to_end(&mut bytes)?;
    let after = file.metadata()?;
    if bytes.len() as u64 != before.len()
        || after.len() != before.len()
        || after.mtime() != before.mtime()
        || after.mtime_nsec() != before.mtime_nsec()
    {
        return Err("capture file changed or exceeded bound".into());
    }
    Ok(bytes)
}
fn create_private_dir(path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    // Inspect ancestors before creation too; never traverse a symlink to make a child.
    let mut walk = PathBuf::new();
    if !path.is_absolute() {
        return Err("capture path must be absolute".into());
    }
    for part in path.parent().ok_or("capture parent")?.components() {
        match part {
            Component::RootDir | Component::Normal(_) => walk.push(part),
            _ => return Err("capture path component".into()),
        }
        let m = fs::symlink_metadata(&walk)?;
        if !m.is_dir() || m.file_type().is_symlink() {
            return Err("capture ancestor type".into());
        }
    }
    match fs::symlink_metadata(path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            fs::DirBuilder::new().mode(0o700).create(path)?;
            File::open(path.parent().unwrap())?.sync_all()?;
        }
        Err(e) => return Err(e.into()),
        Ok(_) => {}
    }
    private_dir(path)
}
const STORAGE_LOCK_WAIT: Duration = Duration::from_secs(45);
const STORAGE_LOCK_POLL: Duration = Duration::from_millis(100);
#[derive(Debug, PartialEq, Eq)]
enum StorageLockFailure {
    BusyTimeout,
    Unsafe,
    Io,
}
impl std::fmt::Display for StorageLockFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::BusyTimeout => "capture_storage_lock_busy_timeout",
            Self::Unsafe => "capture_storage_lock_identity_or_metadata_unsafe",
            Self::Io => "capture_storage_lock_io_failure",
        })
    }
}
impl std::error::Error for StorageLockFailure {}
/// Only fixed reason classes reach logs: never an input path, session or file content.
pub fn setup_failure_reason(error: &(dyn std::error::Error + 'static)) -> &'static str {
    match error.downcast_ref::<StorageLockFailure>() {
        Some(StorageLockFailure::BusyTimeout) => "capture_storage_lock_busy_timeout",
        Some(StorageLockFailure::Unsafe) => "capture_storage_lock_identity_or_metadata_unsafe",
        Some(StorageLockFailure::Io) => "capture_storage_lock_io_failure",
        None if error.is::<std::io::Error>() => "private_storage_or_socket_io_failure",
        None => "private_storage_or_socket_setup_rejected",
    }
}
fn lock_identity(
    directory: &Path,
    path: &Path,
    file: &File,
    original_dir: &fs::Metadata,
) -> Result<(), StorageLockFailure> {
    private_dir(directory).map_err(|_| StorageLockFailure::Unsafe)?;
    let directory_now = fs::symlink_metadata(directory).map_err(|_| StorageLockFailure::Io)?;
    let named = fs::symlink_metadata(path).map_err(|_| StorageLockFailure::Io)?;
    let opened = file.metadata().map_err(|_| StorageLockFailure::Io)?;
    if (directory_now.dev(), directory_now.ino()) != (original_dir.dev(), original_dir.ino())
        || (named.dev(), named.ino()) != (opened.dev(), opened.ino())
        || [&named, &opened].iter().any(|m| {
            !m.is_file()
                || m.file_type().is_symlink()
                || m.uid() != unsafe { geteuid() }
                || m.mode() & 0o777 != 0o600
                || m.nlink() != 1
                || m.len() != 0
        })
    {
        return Err(StorageLockFailure::Unsafe);
    }
    Ok(())
}
fn lock_storage_for(directory: &Path, maximum_wait: Duration) -> Result<File, StorageLockFailure> {
    use std::os::fd::AsRawFd;
    unsafe extern "C" {
        fn flock(fd: i32, operation: i32) -> i32;
    }
    // Keep the one validated descriptor throughout overlap with an exiting owner.
    // Never reopen, unlink, chmod, or bypass a still-owned storage lock.
    private_dir(directory).map_err(|_| StorageLockFailure::Unsafe)?;
    let original_dir = fs::symlink_metadata(directory).map_err(|_| StorageLockFailure::Io)?;
    let path = directory.join(".capture.lock");
    let file = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .mode(0o600)
        .custom_flags(NOFOLLOW | NONBLOCK)
        .open(&path)
        .map_err(|_| StorageLockFailure::Io)?;
    let deadline = Instant::now() + maximum_wait;
    let mut waiting = false;
    loop {
        lock_identity(directory, &path, &file, &original_dir)?;
        if waiting && Instant::now() >= deadline {
            return Err(StorageLockFailure::BusyTimeout);
        }
        if unsafe { flock(file.as_raw_fd(), 2 | 4) } == 0 {
            lock_identity(directory, &path, &file, &original_dir)?;
            if waiting {
                eprintln!("capture storage lock acquired after bounded owner wait");
            }
            return Ok(file);
        }
        // EINTR, EIO and permission failures are not contention and are never retried.
        if std::io::Error::last_os_error().kind() != std::io::ErrorKind::WouldBlock {
            return Err(StorageLockFailure::Io);
        }
        if !waiting {
            eprintln!("capture storage lock busy: bounded owner wait");
            waiting = true;
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(StorageLockFailure::BusyTimeout);
        }
        thread::sleep(STORAGE_LOCK_POLL.min(remaining));
    }
}
fn lock_storage(directory: &Path) -> Result<File, Box<dyn std::error::Error>> {
    Ok(lock_storage_for(directory, STORAGE_LOCK_WAIT)?)
}

#[cfg(target_os = "linux")]
fn socket_definitely_abandoned(path: &Path) -> Result<bool, Box<dyn std::error::Error>> {
    use std::os::{
        fd::{AsRawFd, FromRawFd, OwnedFd},
        unix::ffi::OsStrExt,
    };
    #[repr(C)]
    struct Address {
        family: u16,
        path: [u8; 108],
    }
    unsafe extern "C" {
        fn socket(domain: i32, kind: i32, protocol: i32) -> i32;
        fn connect(fd: i32, address: *const std::ffi::c_void, length: u32) -> i32;
    }
    let bytes = path.as_os_str().as_bytes();
    if bytes.len() >= 108 || bytes.contains(&0) {
        return Err("capture socket path length".into());
    }
    let raw = unsafe { socket(1, 1 | 0x800 | 0x80000, 0) }; // AF_UNIX, STREAM|NONBLOCK|CLOEXEC.
    if raw < 0 {
        return Err("capture socket probe creation failed".into());
    }
    let fd = unsafe { OwnedFd::from_raw_fd(raw) };
    let mut address = Address {
        family: 1,
        path: [0; 108],
    };
    address.path[..bytes.len()].copy_from_slice(bytes);
    let result = unsafe {
        connect(
            fd.as_raw_fd(),
            (&address as *const Address).cast(),
            (std::mem::size_of::<u16>() + bytes.len() + 1) as u32,
        )
    };
    // Only immediate Linux ECONNREFUSED is evidence of a stale name. A live
    // endpoint, full backlog (EAGAIN), in-progress connection or any other error
    // is ambiguous and is never unlinked. OwnedFd closes only our probe socket.
    Ok(result != 0 && std::io::Error::last_os_error().raw_os_error() == Some(111))
}
#[cfg(not(target_os = "linux"))]
fn socket_definitely_abandoned(_path: &Path) -> Result<bool, Box<dyn std::error::Error>> {
    Ok(false) // This capture admin's UID authentication and reclamation are Linux-only.
}
fn socket_metadata_safe(m: &fs::Metadata) -> bool {
    m.file_type().is_socket()
        && m.uid() == unsafe { geteuid() }
        && m.mode() & 0o777 == 0o600
        && m.nlink() == 1
}
fn prepare_socket(path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    if !path.is_absolute() || path.file_name().is_none() {
        return Err("capture socket path".into());
    }
    let parent = path.parent().ok_or("capture socket parent")?;
    private_dir(parent)?;
    let directory = fs::symlink_metadata(parent)?;
    let old = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(_) => return Err("capture socket metadata unavailable".into()),
    };
    if !socket_metadata_safe(&old) || !socket_definitely_abandoned(path)? {
        return Err("capture socket active, ambiguous or unsafe".into());
    }
    private_dir(parent)?;
    let directory_now = fs::symlink_metadata(parent)?;
    let now = fs::symlink_metadata(path)?;
    if (directory.dev(), directory.ino()) != (directory_now.dev(), directory_now.ino())
        || (old.dev(), old.ino()) != (now.dev(), now.ino())
        || !socket_metadata_safe(&now)
    {
        return Err("capture socket identity changed".into());
    }
    fs::remove_file(path)?;
    eprintln!("capture abandoned owned socket reclaimed after exclusive storage lock");
    Ok(())
}

fn inventory(directory: &Path) -> Result<(usize, u64), Box<dyn std::error::Error>> {
    let mut count = 0;
    let mut reserved = 0;
    for entry in fs::read_dir(directory)?.take(MAX_SESSIONS + 2) {
        let entry = entry?;
        if entry.file_name() == ".capture.lock" {
            if read_private_file(&entry.path(), 0)?.len() != 0 {
                return Err("storage lock size".into());
            }
            continue;
        }
        count += 1;
        if count > MAX_SESSIONS {
            return Err("session count".into());
        }
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| "session name")?;
        if !canonical_uuid(&name) {
            return Err("session name".into());
        }
        private_dir(&entry.path())?;
        let mut names = BTreeSet::new();
        for child in fs::read_dir(entry.path())?.take(4) {
            let child = child?;
            let file = child
                .file_name()
                .into_string()
                .map_err(|_| "capture filename")?;
            if !["opening.json", "terminal.json", "raw.jsonl"].contains(&file.as_str()) {
                return Err("capture filename".into());
            }
            let m = fs::symlink_metadata(child.path())?;
            if !m.is_file()
                || m.file_type().is_symlink()
                || m.uid() != unsafe { geteuid() }
                || m.mode() & 0o777 != 0o600
                || m.nlink() != 1
                || m.len()
                    > if file == "raw.jsonl" {
                        MAX_SESSION_BYTES
                    } else {
                        MAX_REPLY as u64
                    }
            {
                return Err("capture file metadata".into());
            }
            names.insert(file);
        }
        // If creation was interrupted before opening.json, retain the whole maximum reservation.
        let mut quota = MAX_SESSION_BYTES;
        let mut raw_limit = MAX_SESSION_BYTES;
        if names.contains("opening.json") {
            let bytes = read_private_file(&entry.path().join("opening.json"), MAX_REPLY as u64)?;
            let opening: Value = serde_json::from_slice(&bytes)?;
            if opening["schema"] != "ruview.capture.opening.v2"
                || opening["session_id"] != name
                || opening["capture_id"] != name
            {
                return Err("old opening identity".into());
            }
            raw_limit = opening["limits"]["max_bytes"]
                .as_u64()
                .filter(|n| (1024..=MAX_SESSION_BYTES).contains(n))
                .ok_or("old limit")?;
            quota = raw_limit;
            if names.contains("terminal.json") {
                let bytes =
                    read_private_file(&entry.path().join("terminal.json"), MAX_REPLY as u64)?;
                let terminal: Value = serde_json::from_slice(&bytes)?;
                if terminal["schema"] != "ruview.capture.terminal.v2"
                    || terminal["session_id"] != name
                    || terminal["capture_id"] != name
                    || terminal["worker_run_id"] != opening["worker_run_id"]
                    || terminal["limits"] != opening["limits"]
                    || terminal["opening_sha256"]
                        != sha256(&read_private_file(
                            &entry.path().join("opening.json"),
                            MAX_REPLY as u64,
                        )?)
                    || terminal["raw"]["closed"] != true
                    || !names.contains("raw.jsonl")
                {
                    return Err("old terminal identity".into());
                }
                let length = fs::symlink_metadata(entry.path().join("raw.jsonl"))?.len();
                if terminal["raw"]["bytes"].as_u64() != Some(length) {
                    return Err("old raw size".into());
                }
                // Closed files cannot grow through this API; account actual retained bytes.
                quota = length;
            }
        } else if names.contains("terminal.json") {
            return Err("terminal without opening".into());
        }
        if names.contains("raw.jsonl")
            && fs::symlink_metadata(entry.path().join("raw.jsonl"))?.len() > raw_limit
        {
            return Err("old raw limit".into());
        }
        reserved += quota;
        if reserved > MAX_TOTAL_BYTES {
            return Err("retained reservation limit".into());
        }
    }
    Ok((count, reserved))
}
fn export(
    directory: &Path,
    session: &str,
    kind: &str,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    if !canonical_uuid(session) || !["opening", "terminal", "raw"].contains(&kind) {
        return Err("capture export requires canonical UUID and opening|terminal|raw".into());
    }
    private_dir(directory)?;
    let path = directory.join(session);
    private_dir(&path)?;
    if kind == "opening" {
        let bytes = read_private_file(&path.join("opening.json"), MAX_REPLY as u64)?;
        let v: Value = serde_json::from_slice(&bytes)?;
        if v["schema"] != "ruview.capture.opening.v2"
            || v["session_id"] != session
            || v["capture_id"] != session
        {
            return Err("opening identity".into());
        }
        return Ok(bytes);
    }
    let terminal_bytes = read_private_file(&path.join("terminal.json"), MAX_REPLY as u64)?;
    let terminal: Value = serde_json::from_slice(&terminal_bytes)?;
    if terminal["schema"] != "ruview.capture.terminal.v2"
        || terminal["session_id"] != session
        || terminal["capture_id"] != session
        || terminal["raw"]["closed"] != true
    {
        return Err("closed terminal identity required".into());
    }
    if kind == "terminal" {
        return Ok(terminal_bytes);
    }
    let bytes = read_private_file(&path.join("raw.jsonl"), MAX_SESSION_BYTES)?;
    if terminal["raw"]["bytes"].as_u64() != Some(bytes.len() as u64)
        || terminal["raw"]["sha256"].as_str() != Some(sha256(&bytes).as_str())
    {
        return Err("closed raw hash or size mismatch".into());
    }
    Ok(bytes)
}
fn control(socket: &Path, command: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    private_dir(socket.parent().ok_or("socket parent")?)?;
    let m = fs::symlink_metadata(socket)?;
    use std::os::unix::fs::FileTypeExt;
    if !m.file_type().is_socket()
        || m.uid() != unsafe { geteuid() }
        || m.mode() & 0o777 != 0o600
        || command.len() > MAX_COMMAND
        || command.contains(['\n', '\r'])
    {
        return Err("capture socket or command bound".into());
    }
    // Bound a local connect even if an unresponsive listener's backlog is full.
    let (tx, rx) = mpsc::sync_channel(1);
    let path = socket.to_owned();
    thread::spawn(move || {
        let _ = tx.send(UnixStream::connect(path));
    });
    let mut stream = rx.recv_timeout(Duration::from_secs(2))??;
    if !peer_allowed(&stream) {
        return Err("capture server UID".into());
    }
    stream.set_write_timeout(Some(Duration::from_secs(2)))?;
    stream.write_all(format!("{command}\n").as_bytes())?;
    let until = Instant::now() + Duration::from_secs(2);
    let mut data = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        let left = until.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err("capture reply deadline".into());
        }
        stream.set_read_timeout(Some(left))?;
        if stream.read(&mut byte)? != 1 {
            return Err("capture reply incomplete".into());
        }
        data.push(byte[0]);
        if data.len() > MAX_REPLY {
            return Err("capture reply limit".into());
        }
        if byte[0] == b'\n' {
            break;
        }
    }
    let reply: Value = serde_json::from_slice(&data)?;
    if reply["schema"] != "ruview.capture.reply.v2" {
        return Err("capture reply schema".into());
    }
    Ok(data)
}
/// Same executable works in the minimal runtime image, without Python, a shell or tar.
/// Client modes neither initialize the worker nor open a CSI socket.
pub fn cli(args: &[String]) -> Result<bool, Box<dyn std::error::Error>> {
    match args.first().map(String::as_str) {
        Some("capture-control") => {
            if args.len() != 3 {
                return Err("capture-control SOCKET JSON".into());
            }
            let bytes = control(Path::new(&args[1]), &args[2])?;
            std::io::stdout().lock().write_all(&bytes)?;
            Ok(true)
        }
        Some("capture-export") => {
            if args.len() != 4 {
                return Err("capture-export DIRECTORY SESSION opening|terminal|raw".into());
            }
            let bytes = export(Path::new(&args[1]), &args[2], &args[3])?;
            std::io::stdout().lock().write_all(&bytes)?;
            Ok(true)
        }
        _ => Ok(false),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};
    const SESSION: &str = "11111111-1111-4111-8111-111111111111";
    fn at(n: u64) -> Stamp {
        Stamp {
            utc_ns: 1_790_000_000_000_000_000 + n,
            mono_ns: n,
        }
    }
    fn identity() -> Identity {
        Identity {
            worker_run_id: "22222222-2222-4222-8222-222222222222".into(),
            clock_id: "boot/worker".into(),
            configuration_sha256: "0".repeat(64),
            worker_start: at(3),
            nodes: vec![1, 2, 3],
        }
    }
    fn raw(node: u8, seq: u32) -> Vec<u8> {
        let mut b = vec![0; 148];
        b[..4].copy_from_slice(&crate::packet::MAGIC.to_le_bytes());
        b[4] = node;
        b[5] = 1;
        b[6..8].copy_from_slice(&64u16.to_le_bytes());
        b[8..12].copy_from_slice(&2462u32.to_le_bytes());
        b[12..16].copy_from_slice(&seq.to_le_bytes());
        b[16] = (-50i8) as u8;
        b[19] = 16;
        b[20] = (-128i8) as u8;
        b[21] = 127;
        b
    }
    fn frame(node: u8, seq: u32, time: u64) -> Frame {
        let bytes = raw(node, seq);
        Frame {
            packet: crate::packet::parse(&bytes, &[1, 2, 3]).unwrap(),
            stamp: at(time),
            raw: bytes,
            ingress: 1,
            capture: 1,
        }
    }
    fn admit(i: &mut Ingress, node: u8, seq: u32, time: u64) {
        let f = frame(node, seq, time);
        i.frame(&f.packet, f.stamp, &f.raw);
    }
    fn start_request() -> Request {
        request(
            serde_json::to_string(
                &json!({"schema":CONTROL_SCHEMA,"op":"start","session_id":SESSION,
        "node_ids":[2],"duration_ms":1000,"max_bytes":1048576}),
            )
            .unwrap()
            .as_bytes(),
            &identity(),
        )
        .unwrap()
    }
    struct Dir(PathBuf);
    impl Dir {
        fn new() -> Self {
            static COUNT: AtomicU64 = AtomicU64::new(0);
            let p = std::env::temp_dir().join(format!(
                "ruview-capture-{}-{}",
                std::process::id(),
                COUNT.fetch_add(1, Ordering::Relaxed)
            ));
            fs::DirBuilder::new().mode(0o700).create(&p).unwrap();
            Self(p)
        }
    }
    impl Drop for Dir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
    fn controller(path: &Path) -> (Controller, Ingress, Arc<AtomicU64>) {
        let (tx, rx) = mpsc::sync_channel(8);
        let time = Arc::new(AtomicU64::new(10));
        let t = time.clone();
        (
            Controller {
                directory: path.to_owned(),
                identity: identity(),
                clock: Arc::new(move || at(t.load(Ordering::Relaxed))),
                commands: tx,
                sessions: BTreeMap::new(),
                reserved: 0,
                attempts: 0,
                admission_error: None,
                _storage_lock: None,
            },
            Ingress {
                commands: rx,
                active: None,
                ordinal: 0,
            },
            time,
        )
    }
    fn wait_terminal(c: &mut Controller) -> Value {
        let until = Instant::now() + Duration::from_secs(5);
        loop {
            c.monitor();
            if let Some(v) = c.sessions[SESSION].terminal.as_ref() {
                return v.clone();
            }
            assert!(Instant::now() < until, "terminal did not close");
            thread::sleep(Duration::from_millis(1));
        }
    }
    #[test]
    fn strict_control_rejects_duplicate_unknown_bool_and_bad_identity() {
        let base = json!({"schema":CONTROL_SCHEMA,"op":"start","session_id":SESSION,"node_ids":[2],"duration_ms":1000,"max_bytes":1048576});
        for (key, value) in [
            ("session_id", json!("../raw")),
            ("session_id", json!(identity().worker_run_id)),
            ("duration_ms", json!(true)),
            ("duration_ms", json!(0)),
            ("duration_ms", json!(3600001)),
            ("max_bytes", json!(MAX_SESSION_BYTES + 1)),
            ("node_ids", json!([2, 2])),
            ("node_ids", json!([4])),
            ("node_ids", json!([2, 1])),
            ("unknown", json!(1)),
        ] {
            let mut v = base.clone();
            v[key] = value;
            assert!(
                request(&serde_json::to_vec(&v).unwrap(), &identity()).is_err(),
                "{v}"
            );
        }
        let dup = serde_json::to_string(&base)
            .unwrap()
            .replacen('{', "{\"op\":\"start\",", 1);
        assert!(request(dup.as_bytes(), &identity()).is_err());
    }
    #[test]
    fn receiver_cut_is_independent_of_full_data_queue_and_engine_history() {
        let (tx, rx) = mpsc::sync_channel(8);
        let mut i = Ingress {
            commands: rx,
            active: None,
            ordinal: 0,
        };
        admit(&mut i, 2, 0, 1); // Processed pre-start, excluded even if still queued for the engine.
        let (frames, rows) = mpsc::sync_channel(1);
        let (stx, srx) = mpsc::sync_channel(1);
        let (etx, erx) = mpsc::sync_channel(1);
        tx.send(Command::Start {
            session: SESSION.into(),
            nodes: vec![2],
            duration_ms: 1000,
            writer: frames,
            started: stx,
            ended: etx,
        })
        .unwrap();
        i.poll(at(10));
        assert_eq!(srx.recv().unwrap().ingress, 1);
        admit(&mut i, 1, 1, 11);
        admit(&mut i, 2, 2, 12);
        admit(&mut i, 2, 3, 13);
        tx.send(Command::Stop {
            session: SESSION.into(),
            reason: "manual_stop",
        })
        .unwrap();
        i.poll(at(14));
        admit(&mut i, 2, 4, 15);
        let cut = erx.recv().unwrap();
        assert_eq!(cut.counts.admitted, 2);
        assert_eq!(cut.counts.enqueued, 1);
        assert_eq!(cut.counts.dropped, 1);
        let f = rows.recv().unwrap();
        assert_eq!((f.ingress, f.capture, f.packet.sequence), (3, 1, 2));
        assert!(rows.recv().is_err());
    }
    #[test]
    fn duration_boundary_excludes_exact_deadline_and_later_packets() {
        let dir = Dir::new();
        let (mut c, mut i, time) = controller(&dir.0);
        c.handle(start_request()).unwrap();
        i.poll(at(10));
        c.monitor();
        admit(&mut i, 2, 1, 1_000_000_009);
        time.store(1_000_000_020, Ordering::Relaxed);
        admit(&mut i, 2, 2, 1_000_000_010);
        let terminal = wait_terminal(&mut c);
        assert_eq!(terminal["complete"], true);
        assert_eq!(terminal["end_reason"], "duration_elapsed");
        assert_eq!(terminal["counters"]["written"], 1);
        assert_eq!(terminal["end_boundary"]["ingress_sequence"], 1);
    }
    #[test]
    fn complete_stop_durably_binds_original_rows_identity_hash_and_export() {
        let dir = Dir::new();
        let (mut c, mut i, time) = controller(&dir.0);
        c.handle(start_request()).unwrap();
        i.poll(at(10));
        c.monitor();
        assert!(export(&dir.0, SESSION, "opening").is_ok());
        assert!(export(&dir.0, SESSION, "raw").is_err());
        admit(&mut i, 2, 123, 11);
        admit(&mut i, 1, 123, 12);
        admit(&mut i, 2, 124, 13);
        let mut stop = start_request();
        stop.op = "stop".into();
        time.store(14, Ordering::Relaxed);
        c.handle(stop).unwrap();
        i.poll(at(14));
        let t = wait_terminal(&mut c);
        assert_eq!(t["complete"], true);
        assert_eq!(t["worker_start_clock"], stamp(at(3)));
        assert_eq!(
            c.sessions[SESSION].opening.as_ref().unwrap()["worker_start_clock"],
            stamp(at(3))
        );
        assert_eq!(t["raw"]["closed"], true);
        assert_eq!(t["counters"]["admitted"], 2);
        let bytes = export(&dir.0, SESSION, "raw").unwrap();
        assert_eq!(t["raw"]["sha256"], sha256(&bytes));
        let rows: Vec<Value> = std::str::from_utf8(&bytes)
            .unwrap()
            .lines()
            .map(|s| serde_json::from_str(s).unwrap())
            .collect();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[1]["ingress_sequence"], 3);
        assert_eq!(rows[1]["capture_sequence"], 2);
        assert_eq!(rows[0]["session_id"], SESSION);
        assert_eq!(rows[0]["worker_run_id"], identity().worker_run_id);
        assert_eq!(rows[0]["raw_datagram_sha256"], sha256(&raw(2, 123)));
        assert_eq!(rows[0]["iq"][0], -128);
        assert_eq!(rows[0]["iq"][1], 127);
        assert_eq!(
            t["opening_sha256"],
            sha256(&export(&dir.0, SESSION, "opening").unwrap())
        );
        assert_eq!(
            c.handle(start_request()).unwrap_err(),
            "session_id_already_used"
        );
        fs::write(dir.0.join(SESSION).join("raw.jsonl"), b"changed").unwrap();
        assert!(export(&dir.0, SESSION, "raw").is_err());
    }
    #[test]
    fn hard_byte_cap_is_incomplete_and_never_writes_oversize_row() {
        let dir = Dir::new();
        let (mut c, mut i, _) = controller(&dir.0);
        let mut r = start_request();
        r.max_bytes = 1024;
        c.handle(r).unwrap();
        i.poll(at(10));
        c.monitor();
        admit(&mut i, 2, 1, 11);
        let until = Instant::now() + Duration::from_secs(5);
        loop {
            c.monitor();
            i.poll(at(12));
            if c.sessions[SESSION].terminal.is_some() {
                break;
            }
            assert!(Instant::now() < until);
            thread::sleep(Duration::from_millis(1));
        }
        let t = &c.sessions[SESSION].terminal.as_ref().unwrap();
        assert_eq!(t["complete"], false);
        assert_eq!(t["end_reason"], "byte_limit");
        assert_eq!(t["raw"]["bytes"], 0);
        assert_eq!(t["counters"]["byte_limit_rejected"], 1);
    }
    struct FailingSink {
        written: Arc<std::sync::Mutex<Vec<u8>>>,
        sync_fail: bool,
    }
    impl Write for FailingSink {
        fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
            let mut w = self.written.lock().unwrap();
            if w.len() >= 17 {
                return Err(std::io::Error::other("injected"));
            }
            let n = (17 - w.len()).min(b.len());
            w.extend_from_slice(&b[..n]);
            Ok(n)
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    impl DurableWrite for FailingSink {
        fn sync_capture(&self) -> std::io::Result<()> {
            if self.sync_fail {
                Err(std::io::Error::other("injected sync"))
            } else {
                Ok(())
            }
        }
    }
    #[test]
    fn partial_write_and_sync_failure_preserve_actual_bytes_and_failures() {
        let data = Arc::new(std::sync::Mutex::new(vec![]));
        let (tx, rx) = mpsc::sync_channel(1);
        tx.send(frame(2, 1, 11)).unwrap();
        drop(tx);
        let w = writer(
            FailingSink {
                written: data.clone(),
                sync_fail: true,
            },
            rx,
            identity(),
            SESSION.into(),
            10000,
            Arc::new(|| at(12)),
        );
        assert_eq!(w.frames, 0);
        assert_eq!(w.bytes, 17);
        assert_eq!(w.write_errors, 2);
        assert!(!w.fsynced);
        assert_eq!(w.sha, sha256(&data.lock().unwrap()));
    }
    #[test]
    fn receiver_loss_is_explicit_and_cannot_manufacture_terminal() {
        let dir = Dir::new();
        let (mut c, i, _) = controller(&dir.0);
        c.handle(start_request()).unwrap();
        drop(i);
        c.monitor();
        assert!(c.sessions[SESSION]
            .failures
            .contains(&"receiver_start_disconnected"));
        assert!(c.sessions[SESSION].terminal.is_none());
        let mut other = start_request();
        other.session = "33333333-3333-4333-8333-333333333333".into();
        assert_eq!(c.handle(other).unwrap_err(), "capture_busy");
    }
    #[test]
    fn private_paths_and_export_reject_symlinks_and_unknown_kinds() {
        use std::os::unix::fs::symlink;
        let dir = Dir::new();
        private_dir(&dir.0).unwrap();
        let child = dir.0.join("real");
        fs::create_dir(&child).unwrap();
        assert!(private_dir(&child).is_err());
        fs::set_permissions(&child, fs::Permissions::from_mode(0o700)).unwrap();
        symlink(&child, dir.0.join("link")).unwrap();
        assert!(private_dir(&dir.0.join("link")).is_err());
        let f = child.join("f");
        fs::write(&f, b"secret").unwrap();
        fs::set_permissions(&f, fs::Permissions::from_mode(0o600)).unwrap();
        symlink(&f, child.join("alias")).unwrap();
        assert!(read_private_file(&child.join("alias"), 100).is_err());
        assert!(export(&dir.0, "../x", "raw").is_err());
        assert!(export(&dir.0, SESSION, "../../x").is_err());
    }
    #[test]
    fn drain_timeout_and_terminal_write_failure_never_report_complete() {
        let dir = Dir::new();
        let (mut c, mut i, time) = controller(&dir.0);
        c.handle(start_request()).unwrap();
        i.poll(at(10));
        c.monitor();
        let (hold_tx, hold_rx) = mpsc::sync_channel(1);
        c.sessions.get_mut(SESSION).unwrap().written = hold_rx;
        let mut stop = start_request();
        stop.op = "stop".into();
        c.handle(stop).unwrap();
        i.poll(at(11));
        c.monitor();
        time.store(6_000_000_020, Ordering::Relaxed);
        c.monitor();
        assert!(c.sessions[SESSION].failures.contains(&"drain_timeout"));
        assert!(c.sessions[SESSION].terminal.is_none());
        fs::write(dir.0.join(SESSION).join("terminal.json"), b"must preserve").unwrap();
        hold_tx
            .send(Written {
                bytes: 0,
                frames: 0,
                sha: sha256(b""),
                write_errors: 0,
                byte_limit: 0,
                fsynced: true,
                finished: at(6_000_000_020),
            })
            .unwrap();
        c.monitor();
        assert!(c.sessions[SESSION]
            .failures
            .contains(&"terminal_write_error"));
        assert!(c.sessions[SESSION].terminal.is_none());
        assert_eq!(
            fs::read(dir.0.join(SESSION).join("terminal.json")).unwrap(),
            b"must preserve"
        );
    }
    #[test]
    fn eight_closed_sessions_are_retained_and_a_ninth_is_refused() {
        let dir = Dir::new();
        let (mut c, mut i, time) = controller(&dir.0);
        let mut originals = BTreeMap::new();
        for index in 1..=8u64 {
            let mut start = start_request();
            start.session = format!("00000000-0000-4000-8000-{index:012}");
            let id = start.session.clone();
            let now = index * 10_000_000;
            time.store(now, Ordering::Relaxed);
            c.handle(start.clone()).unwrap();
            i.poll(at(now));
            c.monitor();
            admit(&mut i, 2, index as u32, now + 1);
            let mut stop = start;
            stop.op = "stop".into();
            time.store(now + 2, Ordering::Relaxed);
            c.handle(stop).unwrap();
            i.poll(at(now + 2));
            let deadline = Instant::now() + Duration::from_secs(5);
            loop {
                c.monitor();
                if let Some(terminal) = &c.sessions[&id].terminal {
                    assert_eq!(terminal["complete"], true);
                    break;
                }
                assert!(Instant::now() < deadline, "capture did not close");
                thread::sleep(Duration::from_millis(1));
            }
            for kind in ["opening", "terminal", "raw"] {
                originals.insert((id.clone(), kind), export(&dir.0, &id, kind).unwrap());
            }
        }
        let (attempts, reserved) = inventory(&dir.0).unwrap();
        assert_eq!(attempts, 8);
        assert!(reserved < 8 * 1_048_576); // Restart inventories actual closed bytes.
        for ((id, kind), original) in &originals {
            assert_eq!(&export(&dir.0, id, kind).unwrap(), original);
        }
        let mut ninth = start_request();
        ninth.session = "00000000-0000-4000-8000-000000000009".into();
        assert_eq!(c.handle(ninth.clone()).unwrap_err(), "session_count_limit");
        let (mut restarted, _, _) = controller(&dir.0);
        restarted.attempts = attempts;
        restarted.reserved = reserved;
        assert_eq!(restarted.handle(ninth.clone()).unwrap_err(), "session_count_limit");
        assert!(!dir.0.join(&ninth.session).exists());
        for ((id, kind), original) in originals {
            assert_eq!(export(&dir.0, &id, kind).unwrap(), original);
        }
    }
    #[test]
    fn limits_refuse_before_creating_another_session() {
        let dir = Dir::new();
        let (mut c, _, _) = controller(&dir.0);
        c.attempts = MAX_SESSIONS;
        assert_eq!(
            c.handle(start_request()).unwrap_err(),
            "session_count_limit"
        );
        assert_eq!(fs::read_dir(&dir.0).unwrap().count(), 0);
        c.attempts = 0;
        c.reserved = MAX_TOTAL_BYTES;
        assert_eq!(
            c.handle(start_request()).unwrap_err(),
            "storage_reservation_limit"
        );
    }
}

#[cfg(test)]
mod persistence_tests {
    use super::*;
    #[test]
    fn control_rate_window_recovers_after_saturation_and_long_history() {
        let mut window = ControlWindow {
            started_ns: 0,
            admitted: 0,
        };
        for second in 0..150u64 {
            let now = second * 1_000_000_000;
            for _ in 0..32 {
                assert!(window.admit(now));
            }
            assert!(!window.admit(now));
            assert!(!window.admit(now + 999_999_999));
        }
        // 4800 prior admitted requests never permanently disable a later STOP/STATUS.
        assert!(window.admit(150_000_000_000));
        assert!(!window.admit(149_999_999_999)); // A reversed supplied clock cannot rearm budget.
        assert_eq!(window.admitted, 1);
    }
    #[test]
    fn nofollow_nonblock_rejects_writerless_fifo_before_read() {
        unsafe extern "C" {
            fn mkfifo(path: *const std::ffi::c_char, mode: u32) -> i32;
        }
        let root = std::env::temp_dir().join(format!("ruview-fifo-{}", std::process::id()));
        let name = std::ffi::CString::new(root.to_str().unwrap()).unwrap();
        assert_eq!(unsafe { mkfifo(name.as_ptr(), 0o600) }, 0);
        let before = Instant::now();
        let result = read_private_file(&root, 1024);
        let _ = fs::remove_file(root);
        assert!(result.is_err());
        assert!(before.elapsed() < Duration::from_secs(1));
    }
    #[test]
    fn staged_publication_rejects_post_write_file_and_parent_sync_failure() {
        let root = std::env::temp_dir().join(format!("ruview-publication-{}", std::process::id()));
        create_private_dir(&root).unwrap();
        let opening = root.join("opening.json");
        assert!(save_json_with_sync(
            &opening,
            &json!({"complete":true}),
            |_| Err(std::io::Error::other("file sync")),
            |_| Ok(())
        )
        .is_err());
        assert!(!opening.exists());
        assert!(root.join(".opening.json.pending").exists());
        let terminal = root.join("terminal.json");
        assert!(save_json_with_sync(
            &terminal,
            &json!({"complete":true}),
            |file| file.sync_all(),
            |_| Err(std::io::Error::other("parent sync"))
        )
        .is_err());
        assert!(terminal.exists());
        assert_eq!(fs::metadata(&terminal).unwrap().nlink(), 2);
        assert!(read_private_file(&terminal, MAX_REPLY as u64).is_err());
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn reusable_storage_counts_incomplete_attempts_and_rejects_unsafe_entries() {
        let root = std::env::temp_dir().join(format!("ruview-reuse-{}", std::process::id()));
        create_private_dir(&root).unwrap();
        assert_eq!(inventory(&root).unwrap(), (0, 0));
        let session = root.join("11111111-1111-4111-8111-111111111111");
        create_private_dir(&session).unwrap();
        let f = OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(session.join("raw.jsonl"))
            .unwrap();
        drop(f);
        assert_eq!(inventory(&root).unwrap(), (1, MAX_SESSION_BYTES));
        create_private_dir(&root).unwrap(); // Retained originals survive restart preparation.
        assert_eq!(inventory(&root).unwrap(), (1, MAX_SESSION_BYTES));
        fs::write(session.join("unknown"), b"preserve").unwrap();
        assert!(inventory(&root).is_err());
        assert!(session.join("unknown").exists());
        fs::remove_dir_all(root).unwrap();
    }
}

#[cfg(test)]
mod lock_tests {
    use super::*;
    struct PrivateDir(PathBuf);
    impl PrivateDir {
        fn new(name: &str) -> Self {
            let path = std::env::temp_dir()
                .join(format!("ruview-storage-lock-{}-{name}", std::process::id()));
            create_private_dir(&path).unwrap();
            Self(path)
        }
    }
    impl Drop for PrivateDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
    #[test]
    fn temporary_owner_overlap_acquires_the_same_inode_after_release() {
        let directory = PrivateDir::new("release");
        let owner = lock_storage_for(&directory.0, Duration::ZERO).unwrap();
        let original = owner.metadata().unwrap();
        let path = directory.0.clone();
        let (tx, rx) = mpsc::sync_channel(1);
        let waiting = thread::spawn(move || {
            tx.send(lock_storage_for(&path, Duration::from_secs(3)))
                .unwrap();
        });
        // The existing owner must exclude the independently opened contender.
        assert!(matches!(
            rx.recv_timeout(Duration::from_millis(150)),
            Err(mpsc::RecvTimeoutError::Timeout)
        ));
        drop(owner);
        let acquired = rx.recv_timeout(Duration::from_secs(3)).unwrap().unwrap();
        waiting.join().unwrap();
        let current = acquired.metadata().unwrap();
        assert_eq!(
            (current.dev(), current.ino()),
            (original.dev(), original.ino())
        );
        assert_eq!(current.nlink(), 1);
        assert_eq!(current.mode() & 0o777, 0o600);
    }
    #[test]
    fn permanent_busy_owner_times_out_without_replacing_or_unlocking_it() {
        let directory = PrivateDir::new("timeout");
        let owner = lock_storage_for(&directory.0, Duration::ZERO).unwrap();
        let before = Instant::now();
        assert_eq!(
            lock_storage_for(&directory.0, Duration::from_millis(60)).unwrap_err(),
            StorageLockFailure::BusyTimeout
        );
        assert!(before.elapsed() >= Duration::from_millis(60));
        assert_eq!(
            lock_storage_for(&directory.0, Duration::ZERO).unwrap_err(),
            StorageLockFailure::BusyTimeout
        );
        let named = fs::metadata(directory.0.join(".capture.lock")).unwrap();
        assert_eq!(named.ino(), owner.metadata().unwrap().ino());
        assert_eq!(named.len(), 0);
    }
    #[test]
    fn unsafe_metadata_is_rejected_before_waiting_for_a_busy_owner() {
        let directory = PrivateDir::new("metadata");
        let _owner = lock_storage_for(&directory.0, Duration::ZERO).unwrap();
        let path = directory.0.join(".capture.lock");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        // A zero wait would return BusyTimeout if unsafe metadata reached flock.
        assert_eq!(
            lock_storage_for(&directory.0, Duration::ZERO).unwrap_err(),
            StorageLockFailure::Unsafe
        );
        assert_eq!(fs::metadata(&path).unwrap().mode() & 0o777, 0o644);
    }
    #[test]
    fn lock_path_replacement_cannot_redirect_the_original_descriptor() {
        let directory = PrivateDir::new("identity");
        let owner = lock_storage_for(&directory.0, Duration::ZERO).unwrap();
        let original_dir = fs::symlink_metadata(&directory.0).unwrap();
        let path = directory.0.join(".capture.lock");
        fs::rename(&path, directory.0.join("retained-original-lock")).unwrap();
        let _replacement = OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(&path)
            .unwrap();
        assert_eq!(
            lock_identity(&directory.0, &path, &owner, &original_dir),
            Err(StorageLockFailure::Unsafe)
        );
        assert!(directory.0.join("retained-original-lock").exists());
    }
}

#[cfg(all(test, target_os = "linux"))]
mod socket_restart_tests {
    use super::*;
    struct Directory(PathBuf);
    impl Directory {
        fn new(name: &str) -> Self {
            let path =
                std::env::temp_dir().join(format!("ruview-socket-{}-{name}", std::process::id()));
            create_private_dir(&path).unwrap();
            Self(path)
        }
    }
    impl Drop for Directory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
    fn bind_private(path: &Path) -> UnixListener {
        let listener = UnixListener::bind(path).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
        listener
    }
    #[test]
    fn stale_owned_socket_is_reclaimed_only_after_exclusive_storage_ownership() {
        let directory = Directory::new("stale");
        let owner = lock_storage_for(&directory.0, Duration::ZERO).unwrap();
        let path = directory.0.join("control.sock");
        drop(bind_private(&path));
        let lock_inode = owner.metadata().unwrap().ino();
        prepare_socket(&path).unwrap();
        assert!(!path.exists());
        let _new = bind_private(&path);
        assert_eq!(
            fs::metadata(directory.0.join(".capture.lock"))
                .unwrap()
                .ino(),
            lock_inode
        );
    }
    #[test]
    fn active_socket_is_not_removed_even_with_a_different_storage_lock() {
        let directory = Directory::new("live");
        let other_storage = Directory::new("other-storage");
        let _original_owner = lock_storage_for(&directory.0, Duration::ZERO).unwrap();
        let _different_owner = lock_storage_for(&other_storage.0, Duration::ZERO).unwrap();
        let path = directory.0.join("control.sock");
        let _listener = bind_private(&path);
        let inode = fs::symlink_metadata(&path).unwrap().ino();
        assert!(prepare_socket(&path).is_err());
        assert_eq!(fs::symlink_metadata(&path).unwrap().ino(), inode);
    }
    #[test]
    fn full_live_unix_backlog_is_nonblocking_and_never_reclaimed() {
        use std::os::fd::AsRawFd;
        unsafe extern "C" {
            fn listen(fd: i32, backlog: i32) -> i32;
        }
        let directory = Directory::new("backlog");
        let path = directory.0.join("control.sock");
        let listener = bind_private(&path);
        assert_eq!(unsafe { listen(listener.as_raw_fd(), 0) }, 0);
        let _occupied = UnixStream::connect(&path).unwrap();
        let before = Instant::now();
        assert!(prepare_socket(&path).is_err());
        assert!(before.elapsed() < Duration::from_secs(2));
        assert!(path.exists());
    }
    #[test]
    fn wrong_mode_type_links_and_symlinks_are_preserved_unchanged() {
        use std::os::unix::fs::symlink;
        let directory = Directory::new("unsafe");
        let path = directory.0.join("control.sock");
        drop(bind_private(&path));
        fs::set_permissions(&path, fs::Permissions::from_mode(0o666)).unwrap();
        let inode = fs::symlink_metadata(&path).unwrap().ino();
        assert!(prepare_socket(&path).is_err());
        assert_eq!(fs::symlink_metadata(&path).unwrap().ino(), inode);
        assert_eq!(fs::metadata(&path).unwrap().mode() & 0o777, 0o666);
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        fs::hard_link(&path, directory.0.join("another-link")).unwrap();
        assert!(prepare_socket(&path).is_err());
        assert_eq!(fs::metadata(&path).unwrap().nlink(), 2);
        let alias = directory.0.join("alias.sock");
        symlink(&path, &alias).unwrap();
        assert!(prepare_socket(&alias).is_err());
        assert!(fs::symlink_metadata(&alias)
            .unwrap()
            .file_type()
            .is_symlink());
        let regular = directory.0.join("regular.sock");
        fs::write(&regular, b"preserve").unwrap();
        fs::set_permissions(&regular, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(prepare_socket(&regular).is_err());
        assert_eq!(fs::read(&regular).unwrap(), b"preserve");
    }
}
