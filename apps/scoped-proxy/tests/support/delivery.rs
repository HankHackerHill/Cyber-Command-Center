//! Process-boundary delivery fixtures. All dependencies bind loopback sockets.
use std::{
    collections::{HashMap, HashSet},
    fs,
    net::SocketAddr,
    path::PathBuf,
    process::Stdio,
    sync::{Arc, Mutex},
    time::Duration,
};

use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader},
    net::{TcpListener, TcpStream},
    process::{Child, Command},
    task::JoinHandle,
    time::timeout,
};
use uuid::Uuid;

pub const ID: &str = "fb66cc64-81d2-4a0e-94db-324575c967c1";
pub const LIMIT: Duration = Duration::from_secs(15);
pub const REQUEST: &[u8] = b"\x00\xffrequest\r\n\x80";
pub const RESPONSE: &[u8] = b"\x00\xferesponse\r\n\x81";

#[derive(Clone, Debug)]
pub struct Wire {
    pub line: String,
    pub headers: Vec<(String, Vec<u8>)>,
    pub body: Vec<u8>,
}
impl Wire {
    pub fn header(&self, name: &str) -> Option<&[u8]> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_slice())
    }
}
pub async fn read_wire(stream: &mut BufReader<TcpStream>) -> Wire {
    try_read_wire(stream)
        .await
        .expect("peer closed before a complete HTTP message")
}
async fn try_read_wire(stream: &mut BufReader<TcpStream>) -> Option<Wire> {
    let mut line = Vec::new();
    if stream.read_until(b'\n', &mut line).await.ok()? == 0 || !line.ends_with(b"\r\n") {
        return None;
    }
    let first = String::from_utf8(line[..line.len() - 2].to_vec()).unwrap();
    let mut headers = Vec::new();
    loop {
        line.clear();
        if stream.read_until(b'\n', &mut line).await.ok()? == 0 || !line.ends_with(b"\r\n") {
            return None;
        }
        if line == b"\r\n" {
            break;
        }
        let colon = line.iter().position(|b| *b == b':').unwrap();
        let name = String::from_utf8(line[..colon].to_vec()).unwrap();
        let value = line[colon + 1..line.len() - 2]
            .strip_prefix(b" ")
            .unwrap_or(&line[colon + 1..line.len() - 2])
            .to_vec();
        headers.push((name, value));
    }
    let length = headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("content-length"))
        .map(|(_, v)| std::str::from_utf8(v).unwrap().parse().unwrap())
        .unwrap_or(0);
    let mut body = vec![0; length];
    stream.read_exact(&mut body).await.ok()?;
    Some(Wire {
        line: first,
        headers,
        body,
    })
}
async fn reply(stream: &mut TcpStream, status: u16, headers: &[(&str, String)], body: &[u8]) {
    let mut head = format!(
        "HTTP/1.1 {status} Fixture\r\nContent-Length: {}\r\nConnection: close\r\n",
        body.len()
    );
    for (name, value) in headers {
        head.push_str(&format!("{name}: {value}\r\n"));
    }
    head.push_str("\r\n");
    // Peers deliberately disconnect in crash/lost-ack tests.
    let _ = stream.write_all(head.as_bytes()).await;
    let _ = stream.write_all(body).await;
    let _ = stream.shutdown().await;
}

pub struct Observed {
    pub origins: Vec<Wire>,
    pub origin_connections: usize,
    pub intent_at_origin: Vec<Value>,
    pub artifacts: Vec<Vec<u8>>,
    pub audit_attempts: Vec<(String, Value)>,
    pub ledger: HashMap<String, Value>,
    pub receipts: HashSet<String>,
    pub evaluations: usize,
    pub completed: HashSet<String>,
    pub errors_5xx: usize,
    pub settlement_attempts: Vec<Value>,
    pub evidence_status: u16,
    pub settlement_status: u16,
    pub settlement_result: &'static str,
    pub audit_status: u16,
    pub audit_ack_event_id: Option<String>,
    pub lose_audit_ack: bool,
    pub hold_evidence: bool,
    pub hold_first_evidence: bool,
    pub hold_all_evidence: bool,
    pub evidence_gates: HashMap<String, Arc<tokio::sync::Notify>>,
    pub origin_status: u16,
    pub stall_origin: bool,
    pub hold_origin_response: bool,
    pub origin_release: Arc<tokio::sync::Notify>,
    pub stop_sender: Option<tokio::sync::mpsc::UnboundedSender<()>>,
    outbox: PathBuf,
}
impl Default for Observed {
    fn default() -> Self {
        Self {
            origins: Vec::new(),
            origin_connections: 0,
            intent_at_origin: Vec::new(),
            artifacts: Vec::new(),
            audit_attempts: Vec::new(),
            ledger: HashMap::new(),
            receipts: HashSet::new(),
            evaluations: 0,
            completed: HashSet::new(),
            errors_5xx: 0,
            settlement_attempts: Vec::new(),
            evidence_status: 201,
            settlement_status: 200,
            settlement_result: "committed",
            audit_status: 201,
            audit_ack_event_id: None,
            lose_audit_ack: false,
            hold_evidence: false,
            hold_first_evidence: false,
            hold_all_evidence: false,
            evidence_gates: HashMap::new(),
            origin_status: 200,
            stall_origin: false,
            hold_origin_response: false,
            origin_release: Arc::new(tokio::sync::Notify::new()),
            stop_sender: None,
            outbox: PathBuf::new(),
        }
    }
}
pub type Seen = Arc<Mutex<Observed>>;

async fn control(listener: TcpListener, kind: &'static str, seen: Seen) {
    loop {
        let (socket, _) = listener.accept().await.unwrap();
        let seen = seen.clone();
        tokio::spawn(async move {
            let mut stream = BufReader::new(socket);
            let Some(wire) = try_read_wire(&mut stream).await else {
                return;
            };
            let mut headers = Vec::new();
            let mut evidence_gate = None;
            let (status, body, drop_ack, hold) = {
                let mut state = seen.lock().unwrap();
                match kind {
                    "state" if wire.line.contains("/state ") => (
                        200,
                        json!({"state":"CONTROLLED_VALIDATION"})
                            .to_string()
                            .into_bytes(),
                        false,
                        false,
                    ),
                    "state" => {
                        assert!(wire.line.contains("/audit-events "));
                        assert_eq!(
                            wire.header("Authorization"),
                            Some(b"Bearer delivery-fixture".as_slice())
                        );
                        let key = std::str::from_utf8(wire.header("Idempotency-Key").unwrap())
                            .unwrap()
                            .to_owned();
                        let data: Value = serde_json::from_slice(&wire.body).unwrap();
                        state.audit_attempts.push((key.clone(), data.clone()));
                        if (state.audit_status == 201 || state.lose_audit_ack)
                            && let Some(previous) = state.ledger.insert(key.clone(), data.clone())
                        {
                            assert_eq!(previous, data, "event ID reused with changed payload");
                        }
                        let mut event = data;
                        event["event_id"] = json!(key);
                        event["engagement_id"] = json!(ID);
                        let receipt = if state.audit_status == 202 {
                            assert_eq!(wire.header("Prefer"), Some(b"respond-async".as_slice()));
                            json!({"status":"queued","event_id":state.audit_ack_event_id.as_ref().map_or(event["event_id"].as_str().unwrap(), String::as_str),"engagement_id":ID})
                        } else {
                            json!({"seq_id":1,"record_hash":"a".repeat(64),"event":event})
                        };
                        (
                            state.audit_status,
                            receipt.to_string().into_bytes(),
                            state.lose_audit_ack,
                            false,
                        )
                    }
                    "policy" if wire.line.contains("/settlements ") => {
                        assert_eq!(
                            wire.header("Authorization"),
                            Some(b"Bearer delivery-fixture".as_slice())
                        );
                        let data: Value = serde_json::from_slice(&wire.body).unwrap();
                        assert_eq!(data["engagement_id"], ID);
                        state.settlement_attempts.push(data.clone());
                        let completions: Vec<_> = data["completions"].as_array().unwrap().iter().map(|item| {
                            let receipt = item["reservation_id"].as_str().unwrap();
                            let status = item["status_code"].as_u64().unwrap();
                            assert!((200..=599).contains(&status), "settled absent/nonfinal status");
                            if state.settlement_status == 200 && state.settlement_result == "committed" && state.completed.insert(receipt.to_owned()) {
                                assert!(state.receipts.remove(receipt), "unknown completion");
                                if status >= 500 { state.errors_5xx += 1; }
                            }
                            json!({"reservation_id":receipt,"status":if state.settlement_status == 200 {state.settlement_result} else {"queued"}})
                        }).collect();
                        (
                            state.settlement_status,
                            json!({"engagement_id":ID,"completions":completions})
                                .to_string()
                                .into_bytes(),
                            false,
                            false,
                        )
                    }
                    "policy" => {
                        assert_eq!(wire.line, "POST /evaluate HTTP/1.1");
                        state.evaluations += 1;
                        let receipt = Uuid::new_v4().to_string();
                        state.receipts.insert(receipt.clone());
                        headers.push(("X-Policy-Reservation", receipt));
                        (
                            200,
                            br#"{"allow":true,"reason":"ALLOWED"}"#.to_vec(),
                            false,
                            false,
                        )
                    }
                    "evidence" => {
                        assert_eq!(wire.line, "PUT /artifacts HTTP/1.1");
                        let artifact: Value = serde_json::from_slice(&wire.body).unwrap();
                        let id = artifact["event_id"].as_str().unwrap().to_owned();
                        if state.hold_all_evidence
                            || state.evidence_gates.contains_key(&id)
                            || (state.hold_first_evidence && state.evidence_gates.is_empty())
                        {
                            evidence_gate =
                                Some(state.evidence_gates.entry(id).or_default().clone());
                        }
                        state.artifacts.push(wire.body);
                        (
                            state.evidence_status,
                            Vec::new(),
                            false,
                            state.hold_evidence,
                        )
                    }
                    _ => unreachable!(),
                }
            };
            if let Some(gate) = evidence_gate {
                gate.notified().await;
            }
            if hold {
                std::future::pending::<()>().await;
            }
            if !drop_ack {
                reply(stream.get_mut(), status, &headers, &body).await;
            }
        });
    }
}

async fn resp_command(stream: &mut BufReader<TcpStream>) -> Option<Vec<String>> {
    let mut line = String::new();
    if stream.read_line(&mut line).await.ok()? == 0 {
        return None;
    }
    let count: usize = line.trim().strip_prefix('*')?.parse().ok()?;
    let mut args = Vec::new();
    for _ in 0..count {
        line.clear();
        stream.read_line(&mut line).await.ok()?;
        let n: usize = line.trim().strip_prefix('$')?.parse().ok()?;
        let mut bytes = vec![0; n + 2];
        stream.read_exact(&mut bytes).await.ok()?;
        assert_eq!(&bytes[n..], b"\r\n");
        bytes.truncate(n);
        args.push(String::from_utf8(bytes).unwrap());
    }
    Some(args)
}
async fn redis_service(listener: TcpListener, seen: Seen) {
    loop {
        let (socket, _) = listener.accept().await.unwrap();
        let seen = seen.clone();
        tokio::spawn(async move {
            let mut stream = BufReader::new(socket);
            while let Some(args) = resp_command(&mut stream).await {
                let response = match args[0].as_str() {
                    "CLIENT" => "+OK\r\n",
                    "PING" => "+PONG\r\n",
                    "SUBSCRIBE" => {
                        assert_eq!(args[1], "redops:killswitch");
                        "*3\r\n$9\r\nsubscribe\r\n$17\r\nredops:killswitch\r\n:1\r\n"
                    }
                    other => {
                        panic!("async delivery must not silently settle Redis directly: {other}")
                    }
                };
                if stream
                    .get_mut()
                    .write_all(response.as_bytes())
                    .await
                    .is_err()
                {
                    break;
                }
                if args[0] == "SUBSCRIBE" {
                    let (sender, mut receiver) = tokio::sync::mpsc::unbounded_channel();
                    seen.lock().unwrap().stop_sender = Some(sender);
                    while receiver.recv().await.is_some() {
                        let body =
                            json!({"engagement_id":ID,"state":"HALTED_KILLSWITCH"}).to_string();
                        let message = format!(
                            "*3\r\n$7\r\nmessage\r\n$17\r\nredops:killswitch\r\n${}\r\n{body}\r\n",
                            body.len()
                        );
                        if stream
                            .get_mut()
                            .write_all(message.as_bytes())
                            .await
                            .is_err()
                        {
                            break;
                        }
                    }
                    break;
                }
            }
        });
    }
}

pub fn records(path: &std::path::Path) -> Vec<Value> {
    let Ok(entries) = fs::read_dir(path) else {
        return Vec::new();
    };
    entries
        .filter_map(Result::ok)
        .filter(|entry| entry.path().extension().is_some_and(|x| x == "json"))
        .filter_map(|entry| fs::read(entry.path()).ok())
        .map(|bytes| serde_json::from_slice(&bytes).unwrap())
        .collect()
}
pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

pub struct Fixture {
    pub child: Child,
    tasks: Vec<JoinHandle<()>>,
    pub root: PathBuf,
    pub outbox: PathBuf,
    pub proxy: SocketAddr,
    pub origin: SocketAddr,
    pub seen: Seen,
    addresses: HashMap<&'static str, SocketAddr>,
    max_records: usize,
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = self.child.start_kill();
        for task in &self.tasks {
            task.abort();
        }
        let _ = fs::remove_dir_all(&self.root);
    }
}
impl Fixture {
    pub async fn start(max_records: usize) -> Self {
        let root = std::env::temp_dir().join(format!("redops-delivery-{}", Uuid::new_v4()));
        let outbox = root.join("outbox");
        let directory = root.join(ID);
        fs::create_dir_all(&directory).unwrap();
        let manifest =
            json!({"engagement_id":ID,"traffic_constraints":{"circuit_breaker_5xx_threshold":100}})
                .to_string();
        fs::write(directory.join("manifest.json"), &manifest).unwrap();
        fs::write(
            directory.join("manifest.sha256"),
            format!("{:x}", Sha256::digest(manifest.as_bytes())),
        )
        .unwrap();
        let seen = Arc::new(Mutex::new(Observed {
            outbox: outbox.clone(),
            ..Observed::default()
        }));
        let mut tasks = Vec::new();
        let mut addresses = HashMap::new();
        for kind in ["state", "policy", "evidence", "redis"] {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            addresses.insert(kind, listener.local_addr().unwrap());
            tasks.push(if kind == "redis" {
                tokio::spawn(redis_service(listener, seen.clone()))
            } else {
                tokio::spawn(control(listener, kind, seen.clone()))
            });
        }
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin = listener.local_addr().unwrap();
        let origin_seen = seen.clone();
        tasks.push(tokio::spawn(async move {
            loop {
                let (socket, _) = listener.accept().await.unwrap();
                {
                    let mut state = origin_seen.lock().unwrap();
                    state.origin_connections += 1;
                    let intents = records(&state.outbox);
                    assert!(
                        !intents.is_empty(),
                        "origin socket opened before durable intent exists"
                    );
                    state.intent_at_origin.extend(intents);
                }
                let seen = origin_seen.clone();
                tokio::spawn(async move {
                    let mut stream = BufReader::new(socket);
                    let Some(wire) = try_read_wire(&mut stream).await else {
                        return;
                    };
                    let (status, stall, hold, release) = {
                        let mut state = seen.lock().unwrap();
                        state.origins.push(wire);
                        (
                            state.origin_status,
                            state.stall_origin,
                            state.hold_origin_response,
                            state.origin_release.clone(),
                        )
                    };
                    if stall {
                        let _ = stream.read(&mut [0]).await;
                        return;
                    }
                    if hold {
                        release.notified().await;
                    }
                    let head = format!(
                        "HTTP/1.1 {status} Fixture\r\nContent-Length: {}\r\nX-Binary: ",
                        RESPONSE.len()
                    );
                    let mut bytes = head.into_bytes();
                    bytes.extend_from_slice(b"\x80\xff\r\nConnection: close\r\n\r\n");
                    bytes.extend_from_slice(RESPONSE);
                    let _ = stream.get_mut().write_all(&bytes).await;
                    let _ = stream.get_mut().shutdown().await;
                });
            }
        }));
        let (child, proxy) = Self::spawn(&root, &outbox, &addresses, max_records).await;
        let mut fixture = Self {
            child,
            tasks,
            root,
            outbox,
            proxy,
            origin,
            seen,
            addresses,
            max_records,
        };
        fixture.ready().await;
        fixture
    }
    fn command(
        root: &std::path::Path,
        outbox: &std::path::Path,
        addresses: &HashMap<&str, SocketAddr>,
        max_records: usize,
    ) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_scoped-proxy"));
        command
            .env("SCOPED_PROXY_LISTEN", "127.0.0.1:0")
            .env("SCOPED_PROXY_WORKSPACE_DIR", root)
            .env("SCOPED_PROXY_OUTBOX_DIR", outbox)
            .env("SCOPED_PROXY_OUTBOX_MAX_RECORDS", max_records.to_string())
            .env(
                "SCOPED_PROXY_OUTBOX_MAX_BYTES",
                (256 * 1024 * 1024).to_string(),
            )
            .env("ORCHESTRATOR_URL", format!("http://{}", addresses["state"]))
            .env("POLICY_URL", format!("http://{}", addresses["policy"]))
            .env("EVIDENCE_URL", format!("http://{}", addresses["evidence"]))
            .env("REDIS_URL", format!("redis://{}", addresses["redis"]))
            .env("M4_AUDIT_TOKEN", "delivery-fixture")
            .env("TOKIO_WORKER_THREADS", "2")
            .env_remove("SCOPED_PROXY_ORIGIN_CA_FILE")
            .stdout(Stdio::piped())
            .kill_on_drop(true);
        command
    }
    async fn spawn(
        root: &std::path::Path,
        outbox: &std::path::Path,
        addresses: &HashMap<&str, SocketAddr>,
        max_records: usize,
    ) -> (Child, SocketAddr) {
        let mut child = Self::command(root, outbox, addresses, max_records)
            .spawn()
            .unwrap();
        let mut lines = BufReader::new(child.stdout.take().unwrap()).lines();
        let line = timeout(LIMIT, lines.next_line())
            .await
            .unwrap()
            .unwrap()
            .expect("proxy exited before binding");
        let proxy = line.strip_prefix("Listening on ").unwrap().parse().unwrap();
        (child, proxy)
    }
    async fn ready(&mut self) {
        eventually(|| self.seen.lock().unwrap().stop_sender.is_some()).await;
    }
    pub async fn crash(&mut self) {
        self.child.kill().await.unwrap();
        self.child.wait().await.unwrap();
        self.seen.lock().unwrap().stop_sender = None;
    }
    pub async fn restart(&mut self) {
        let (child, proxy) =
            Self::spawn(&self.root, &self.outbox, &self.addresses, self.max_records).await;
        self.child = child;
        self.proxy = proxy;
        self.ready().await;
    }
    pub async fn rejected_restart(&self) -> std::process::Output {
        timeout(
            LIMIT,
            Self::command(&self.root, &self.outbox, &self.addresses, self.max_records)
                .stderr(Stdio::piped())
                .output(),
        )
        .await
        .unwrap()
        .unwrap()
    }
    pub async fn send(&self) -> TcpStream {
        let mut stream = TcpStream::connect(self.proxy).await.unwrap();
        let head = format!(
            "POST http://{}/binary?exact=1 HTTP/1.1\r\nHost: {}\r\nX-Security-Assessment-ID: {ID}\r\nX-Binary: ",
            self.origin, self.origin
        );
        let mut bytes = head.into_bytes();
        bytes.extend_from_slice(b"\x81\xfe\r\n");
        bytes.extend_from_slice(
            format!(
                "Content-Length: {}\r\nConnection: close\r\n\r\n",
                REQUEST.len()
            )
            .as_bytes(),
        );
        bytes.extend_from_slice(REQUEST);
        stream.write_all(&bytes).await.unwrap();
        stream
    }
    pub async fn request(&self) -> Wire {
        read_wire(&mut BufReader::new(self.send().await)).await
    }
    pub async fn wait_stopped(&self) {
        timeout(LIMIT, async {
            loop {
                let mut stream = TcpStream::connect(self.proxy).await.unwrap();
                // Relative-form targets are rejected before M3 or any target
                // socket, so readiness polling cannot itself cause egress.
                stream.write_all(format!("GET / HTTP/1.1\r\nHost: invalid\r\nX-Security-Assessment-ID: {ID}\r\nConnection: close\r\n\r\n").as_bytes()).await.unwrap();
                let response = read_wire(&mut BufReader::new(stream)).await;
                if response.line.contains("412") { break; }
                assert!(response.line.contains("400"), "unexpected stop probe: {response:?}");
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        }).await.expect("killswitch did not become active");
    }
}
pub async fn eventually(mut condition: impl FnMut() -> bool) {
    timeout(LIMIT, async {
        while !condition() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("delivery condition did not become true");
}
