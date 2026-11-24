//! Real listener round trips against local HTTP/TLS origins. Control services
//! are explicit fixtures; Redis's actual completion commands are checked by a
//! small RESP server, including receipt consumption and worker/error counts.
use std::{
    collections::{HashMap, HashSet},
    fs,
    net::SocketAddr,
    path::PathBuf,
    process::Stdio,
    sync::{Arc, Mutex},
    time::Duration,
};

use rcgen::{BasicConstraints, CertificateParams, IsCa, KeyPair, KeyUsagePurpose};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tokio::{
    io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader},
    net::{TcpListener, TcpStream},
    process::{Child, Command},
    task::JoinHandle,
    time::timeout,
};
use tokio_rustls::{
    TlsAcceptor, TlsConnector,
    rustls::{
        ClientConfig, RootCertStore, ServerConfig,
        pki_types::{CertificateDer, PrivatePkcs8KeyDer, ServerName},
    },
};
use uuid::Uuid;

const ID: &str = "fb66cc64-81d2-4a0e-94db-324575c967c1";
const LIMIT: Duration = Duration::from_secs(10);

#[derive(Clone, Debug)]
struct Wire {
    line: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}
impl Wire {
    fn header(&self, key: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(key))
            .map(|(_, v)| v.as_str())
    }
}
async fn read_wire<S: AsyncRead + Unpin>(stream: &mut BufReader<S>) -> Wire {
    let mut line = String::new();
    assert_ne!(stream.read_line(&mut line).await.unwrap(), 0);
    let first = line.trim_end().to_owned();
    let mut headers = Vec::new();
    loop {
        line.clear();
        assert_ne!(stream.read_line(&mut line).await.unwrap(), 0);
        if line == "\r\n" {
            break;
        }
        let (key, value) = line.split_once(':').unwrap();
        headers.push((key.to_owned(), value.trim().to_owned()));
    }
    let length = headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("content-length"))
        .map(|(_, v)| v.parse().unwrap())
        .unwrap_or(0);
    let mut body = vec![0; length];
    stream.read_exact(&mut body).await.unwrap();
    Wire {
        line: first,
        headers,
        body,
    }
}
async fn reply<S: AsyncWrite + Unpin>(
    stream: &mut S,
    status: u16,
    headers: &[(&str, String)],
    body: &[u8],
) {
    let mut head = format!(
        "HTTP/1.1 {status} Fixture\r\nContent-Length: {}\r\nConnection: close\r\n",
        body.len()
    );
    for (k, v) in headers {
        head.push_str(&format!("{k}: {v}\r\n"));
    }
    head.push_str("\r\n");
    stream.write_all(head.as_bytes()).await.unwrap();
    stream.write_all(body).await.unwrap();
    stream.shutdown().await.unwrap();
}

#[derive(Default)]
struct Observed {
    origins: Vec<Wire>,
    evaluations: Vec<Value>,
    artifacts: Vec<Vec<u8>>,
    audits: Vec<Value>,
    receipts: HashSet<String>,
    bucket: Value,
    completions: usize,
    origin_connections: usize,
    origin_status: Option<u16>,
    evidence_status: Option<u16>,
    audit_status: Option<u16>,
    stop_sender: Option<tokio::sync::mpsc::UnboundedSender<Uuid>>,
    stall_origin: bool,
    origin_closed: bool,
}
type Seen = Arc<Mutex<Observed>>;

async fn control(listener: TcpListener, kind: &'static str, seen: Seen) {
    loop {
        let (socket, _) = listener.accept().await.unwrap();
        let seen = seen.clone();
        tokio::spawn(async move {
            let mut stream = BufReader::new(socket);
            let wire = read_wire(&mut stream).await;
            let mut headers = Vec::new();
            let (status, body) = {
                let mut state = seen.lock().unwrap();
                match kind {
                    "state" if wire.line.contains("/state ") => (
                        200,
                        json!({"state":"CONTROLLED_VALIDATION"})
                            .to_string()
                            .into_bytes(),
                    ),
                    "state" => {
                        assert!(wire.line.contains("/audit-events "));
                        assert_eq!(
                            wire.header("Authorization"),
                            Some("Bearer forwarding-fixture")
                        );
                        let data: Value = serde_json::from_slice(&wire.body).unwrap();
                        state.audits.push(data.clone());
                        let mut event = data;
                        event["event_id"] = json!(wire.header("Idempotency-Key").unwrap());
                        event["engagement_id"] = json!(ID);
                        (
                            state.audit_status.unwrap_or(201),
                            json!({"seq_id":1,"record_hash":"a".repeat(64),"event":event})
                                .to_string()
                                .into_bytes(),
                        )
                    }
                    "policy" => {
                        assert_eq!(wire.line, "POST /evaluate HTTP/1.1");
                        state
                            .evaluations
                            .push(serde_json::from_slice(&wire.body).unwrap());
                        let receipt = Uuid::new_v4().to_string();
                        state.receipts.insert(receipt.clone());
                        let active = state.receipts.len();
                        state.bucket["active_workers"] = json!(active);
                        headers.push(("X-Policy-Reservation", receipt));
                        (200, br#"{"allow":true,"reason":"ALLOWED"}"#.to_vec())
                    }
                    "evidence" => {
                        assert_eq!(wire.line, "PUT /artifacts HTTP/1.1");
                        state.artifacts.push(wire.body);
                        (state.evidence_status.unwrap_or(201), Vec::new())
                    }
                    _ => unreachable!(),
                }
            };
            reply(stream.get_mut(), status, &headers, &body).await;
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
                    "CLIENT" => "+OK\r\n".to_owned(),
                    "PING" => "+PONG\r\n".to_owned(),
                    "SUBSCRIBE" => {
                        assert_eq!(args[1], "redops:killswitch");
                        "*3\r\n$9\r\nsubscribe\r\n$17\r\nredops:killswitch\r\n:1\r\n".to_owned()
                    }
                    "EVAL" => {
                        assert_eq!(args[3], format!("redops:policy:v1:{ID}"));
                        let mut state = seen.lock().unwrap();
                        if args.len() == 4 {
                            let raw = state.bucket.to_string();
                            format!(
                                "*2\r\n${}\r\n{raw}\r\n:{}\r\n",
                                raw.len(),
                                state.receipts.len()
                            )
                        } else {
                            assert_eq!(args.len(), 7);
                            assert_eq!(
                                serde_json::from_str::<Value>(&args[4]).unwrap(),
                                state.bucket
                            );
                            assert!(
                                state.receipts.remove(&args[6]),
                                "completion used an unknown/already-consumed reservation"
                            );
                            state.bucket = serde_json::from_str(&args[5]).unwrap();
                            state.completions += 1;
                            "$2\r\nok\r\n".to_owned()
                        }
                    }
                    other => panic!("unexpected Redis command {other}"),
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
                    let (sender, mut receiver) = tokio::sync::mpsc::unbounded_channel::<Uuid>();
                    seen.lock().unwrap().stop_sender = Some(sender);
                    while let Some(id) = receiver.recv().await {
                        let payload =
                            json!({"engagement_id":id,"state":"HALTED_KILLSWITCH"}).to_string();
                        let message = format!(
                            "*3\r\n$7\r\nmessage\r\n$17\r\nredops:killswitch\r\n${}\r\n{payload}\r\n",
                            payload.len()
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

fn ca() -> (rcgen::Certificate, KeyPair) {
    let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    let key = KeyPair::generate().unwrap();
    (params.self_signed(&key).unwrap(), key)
}
fn tls_config(ca: &rcgen::Certificate, issuer: &KeyPair, name: &str) -> Arc<ServerConfig> {
    let key = KeyPair::generate().unwrap();
    let cert = CertificateParams::new(vec![name.to_owned()])
        .unwrap()
        .signed_by(&key, ca, issuer)
        .unwrap();
    Arc::new(
        ServerConfig::builder_with_provider(Arc::new(
            tokio_rustls::rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![cert.der().clone()],
            PrivatePkcs8KeyDer::from(key.serialize_der()).into(),
        )
        .unwrap(),
    )
}

struct Fixture {
    child: Child,
    tasks: Vec<JoinHandle<()>>,
    root: PathBuf,
    proxy: SocketAddr,
    origin: SocketAddr,
    seen: Seen,
    client_ca: CertificateDer<'static>,
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
    async fn start(tls_name: Option<&str>, trust_origin: bool) -> Self {
        let seen = Arc::new(Mutex::new(Observed {
            bucket: json!({"credit":1000000,"at_us":1,"rate":10,"active_workers":0,"errors_5xx":0}),
            ..Observed::default()
        }));
        let root = std::env::temp_dir().join(format!("redops-forwarding-{}", Uuid::new_v4()));
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
        let (inspection_ca, inspection_key) = ca();
        fs::write(directory.join("ca.pem"), inspection_ca.pem()).unwrap();
        fs::write(directory.join("ca-key.pem"), inspection_key.serialize_pem()).unwrap();
        let (origin_ca, origin_key) = ca();
        if trust_origin {
            fs::write(directory.join("origin-ca.pem"), origin_ca.pem()).unwrap();
        }
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
        let config = tls_name.map(|name| tls_config(&origin_ca, &origin_key, name));
        tasks.push(tokio::spawn(async move {
            loop {
                let (socket, _) = listener.accept().await.unwrap();
                origin_seen.lock().unwrap().origin_connections += 1;
                let seen = origin_seen.clone();
                let config = config.clone();
                tokio::spawn(async move {
                    async fn exchange<S: AsyncRead + AsyncWrite + Unpin>(stream: S, seen: Seen) {
                        let mut stream = BufReader::new(stream);
                        let request = read_wire(&mut stream).await;
                        let (status, stall) = {
                            let mut state = seen.lock().unwrap();
                            state.origins.push(request);
                            (state.origin_status.unwrap_or(200), state.stall_origin)
                        };
                        if stall {
                            let mut byte = [0];
                            let _ = stream.read(&mut byte).await;
                            seen.lock().unwrap().origin_closed = true;
                            return;
                        }
                        reply(
                            stream.get_mut(),
                            status,
                            &[
                                ("X-Origin", "fixture".into()),
                                ("Location", "/redirected".into()),
                            ],
                            b"origin-response",
                        )
                        .await;
                    }
                    if let Some(config) = config {
                        if let Ok(stream) = TlsAcceptor::from(config).accept(socket).await {
                            exchange(stream, seen).await;
                        }
                    } else {
                        exchange(socket, seen).await;
                    }
                });
            }
        }));
        let mut child = Command::new(env!("CARGO_BIN_EXE_scoped-proxy"))
            .env("SCOPED_PROXY_LISTEN", "127.0.0.1:0")
            .env("SCOPED_PROXY_WORKSPACE_DIR", &root)
            .env("ORCHESTRATOR_URL", format!("http://{}", addresses["state"]))
            .env("POLICY_URL", format!("http://{}", addresses["policy"]))
            .env("EVIDENCE_URL", format!("http://{}", addresses["evidence"]))
            .env("REDIS_URL", format!("redis://{}", addresses["redis"]))
            .env("M4_AUDIT_TOKEN", "forwarding-fixture")
            .env("TOKIO_WORKER_THREADS", "2")
            .env_remove("SCOPED_PROXY_ORIGIN_CA_FILE")
            .stdout(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .unwrap();
        let mut lines = BufReader::new(child.stdout.take().unwrap()).lines();
        let line = lines.next_line().await.unwrap().unwrap();
        let proxy = line.strip_prefix("Listening on ").unwrap().parse().unwrap();
        let fixture = Self {
            child,
            tasks,
            root,
            proxy,
            origin,
            seen,
            client_ca: inspection_ca.der().clone(),
        };
        loop {
            let mut socket = TcpStream::connect(proxy).await.unwrap();
            socket
                .write_all(b"GET / HTTP/1.1\r\nHost: invalid\r\nConnection: close\r\n\r\n")
                .await
                .unwrap();
            let response = read_wire(&mut BufReader::new(socket)).await;
            if response.line.contains("400") {
                break;
            }
            tokio::task::yield_now().await;
        }
        fixture
    }
    async fn tunnel(&self) -> TcpStream {
        let mut socket = TcpStream::connect(self.proxy).await.unwrap();
        socket
            .write_all(
                format!(
                    "CONNECT {} HTTP/1.1\r\nHost: {}\r\nX-Security-Assessment-ID: {ID}\r\n\r\n",
                    self.origin, self.origin
                )
                .as_bytes(),
            )
            .await
            .unwrap();
        let response = read_wire(&mut BufReader::new(&mut socket)).await;
        assert!(
            response.line.contains("200"),
            "CONNECT failed: {response:?}"
        );
        socket
    }
    async fn https(&self, inner: &str) -> Wire {
        let socket = self.tunnel().await;
        let mut roots = RootCertStore::empty();
        roots.add(self.client_ca.clone()).unwrap();
        let config = ClientConfig::builder_with_provider(Arc::new(
            tokio_rustls::rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
        let mut stream = TlsConnector::from(Arc::new(config))
            .connect(ServerName::try_from("127.0.0.1").unwrap(), socket)
            .await
            .unwrap();
        stream.write_all(inner.as_bytes()).await.unwrap();
        read_wire(&mut BufReader::new(stream)).await
    }
    fn assert_forwarded(&self, path: &str) {
        let state = self.seen.lock().unwrap();
        assert_eq!(state.origins.len(), 1);
        assert_eq!(state.origins[0].line, format!("POST {path} HTTP/1.1"));
        assert_eq!(
            state.origins[0].header("X-Security-Assessment-ID"),
            Some(ID)
        );
        assert_eq!(
            state.origins[0]
                .headers
                .iter()
                .filter(|(k, _)| k.eq_ignore_ascii_case("X-Security-Assessment-ID"))
                .count(),
            1
        );
        assert_eq!(state.origins[0].body, b"payload");
        assert_eq!(state.evaluations.len(), 1);
        assert_eq!(
            state.evaluations[0]["request"]["path"],
            path.split('?').next().unwrap()
        );
        assert_eq!(state.completions, 1);
        assert!(state.receipts.is_empty());
        assert_eq!(state.bucket["active_workers"], 0);
        assert_eq!(state.bucket["errors_5xx"], 0);
        assert!(
            !state.artifacts.is_empty(),
            "forwarded response preceded evidence upload"
        );
        assert!(
            !state.audits.is_empty(),
            "forwarded response preceded audit acknowledgment"
        );
        let artifact: Value = serde_json::from_slice(&state.artifacts[0]).unwrap();
        assert_eq!(artifact["engagement_id"], ID);
        assert_eq!(state.audits[0]["event_type"], "PROXY_REQUEST_COMPLETED");
        assert_eq!(
            state.audits[0]["payload"]["reservation"],
            artifact["reservation"]
        );
        assert!(artifact["request"]["uri"].as_str().unwrap().ends_with(path));
        let evidence: Vec<String> = state
            .artifacts
            .iter()
            .map(|v| format!("{:x}", Sha256::digest(v)))
            .collect();
        assert!(
            state.audits.iter().any(|audit| evidence
                .iter()
                .any(|digest| audit.to_string().contains(digest))),
            "audit did not bind the request/response evidence digest"
        );
    }
}

#[tokio::test]
async fn plain_http_roundtrip_injects_attribution_and_confirms_evidence_and_completion() {
    timeout(LIMIT,async {
        let fixture = Fixture::start(None,false).await;
        let path = "/forward/path?mode=exact";
        let mut stream = TcpStream::connect(fixture.proxy).await.unwrap();
        stream.write_all(format!("POST http://{}{path} HTTP/1.1\r\nHost: {}\r\nX-Security-Assessment-ID: {ID}\r\nContent-Length: 7\r\nConnection: close\r\n\r\npayload",fixture.origin,fixture.origin).as_bytes()).await.unwrap();
        let response = read_wire(&mut BufReader::new(stream)).await;
        assert!(response.line.contains("200"),"{response:?}"); assert_eq!(response.body,b"origin-response");
        fixture.assert_forwarded(path);
    }).await.unwrap();
}

#[tokio::test]
async fn intercepted_https_uses_same_governance_and_inherits_connect_engagement() {
    timeout(LIMIT,async {
        let fixture = Fixture::start(Some("127.0.0.1"),true).await;
        let path = "/secure/path?x=1";
        let response = fixture.https(&format!("POST {path} HTTP/1.1\r\nHost: {}\r\nContent-Length: 7\r\nConnection: close\r\n\r\npayload",fixture.origin)).await;
        assert!(response.line.contains("200"),"{response:?}"); assert_eq!(response.body,b"origin-response");
        fixture.assert_forwarded(path);
    }).await.unwrap();
}

#[tokio::test]
async fn intercepted_https_rejects_wrong_host_and_untrusted_origin_certificates() {
    timeout(LIMIT, async {
        for (name, trust) in [("different.invalid", true), ("127.0.0.1", false)] {
            let fixture = Fixture::start(Some(name), trust).await;
            let response = fixture
                .https(&format!(
                    "GET / HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
                    fixture.origin
                ))
                .await;
            assert!(
                response.line.contains("502"),
                "origin certificate failure must fail closed: {response:?}"
            );
            let state = fixture.seen.lock().unwrap();
            assert!(state.origins.is_empty());
            assert_eq!(state.completions, 0);
            assert_eq!(
                state.receipts.len(),
                1,
                "no final origin status may consume the receipt"
            );
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn intercepted_https_rejects_forged_engagement_and_changed_authority_before_admission() {
    timeout(LIMIT, async {
        let fixture = Fixture::start(Some("127.0.0.1"), true).await;
        for headers in [
            format!(
                "Host: {}\r\nX-Security-Assessment-ID: {}",
                fixture.origin,
                Uuid::nil()
            ),
            format!(
                "Host: {}\r\nX-Security-Assessment-ID: {ID}\r\nX-Security-Assessment-ID: {ID}",
                fixture.origin
            ),
            "Host: 127.0.0.1:1".to_owned(),
        ] {
            let response = fixture
                .https(&format!(
                    "GET / HTTP/1.1\r\n{headers}\r\nConnection: close\r\n\r\n"
                ))
                .await;
            assert!(
                response.line.contains("400") || response.line.contains("403"),
                "{response:?}"
            );
        }
        let state = fixture.seen.lock().unwrap();
        assert!(state.origins.is_empty());
        assert!(state.evaluations.is_empty());
        assert_eq!(state.origin_connections, 0);
        assert_eq!(state.completions, 0);
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn candidate_clienthello_does_not_open_origin_before_a_valid_tls_handshake() {
    timeout(LIMIT, async {
        let fixture = Fixture::start(Some("127.0.0.1"), true).await;
        let mut tunnel = fixture.tunnel().await;
        // A syntactically classified TLS handshake record containing a malformed
        // ClientHello must never reach the destination or policy reservation.
        tunnel
            .write_all(&[0x16, 0x03, 0x03, 0x00, 0x04, 0x01, 0xff, 0xff, 0xff])
            .await
            .unwrap();
        tunnel.shutdown().await.unwrap();
        let mut bytes = Vec::new();
        let _ = tunnel.read_to_end(&mut bytes).await;
        let state = fixture.seen.lock().unwrap();
        assert_eq!(state.origin_connections, 0);
        assert!(state.evaluations.is_empty());
        assert!(state.receipts.is_empty());
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn redirects_preserve_origin_status_and_connection_tokens_cannot_remove_attribution() {
    timeout(LIMIT, async {
        let fixture = Fixture::start(None, false).await;
        fixture.seen.lock().unwrap().origin_status = Some(302);
        let mut stream = TcpStream::connect(fixture.proxy).await.unwrap();
        stream.write_all(format!("POST http://{}/redirect HTTP/1.1\r\nHost: {}\r\nX-Security-Assessment-ID: {ID}\r\nX-Drop-Me: hop\r\nContent-Length: 7\r\nConnection: X-Security-Assessment-ID, X-Drop-Me, close\r\n\r\npayload",fixture.origin,fixture.origin).as_bytes()).await.unwrap();
        let response = read_wire(&mut BufReader::new(stream)).await;
        assert!(response.line.contains("302"));
        assert_eq!(response.header("Location"), Some("/redirected"));
        fixture.assert_forwarded("/redirect");
        let state = fixture.seen.lock().unwrap();
        assert_eq!(state.origins[0].header("X-Drop-Me"), None);
        assert_eq!(state.origin_connections, 1, "proxy followed an origin redirect");
        let artifact: Value = serde_json::from_slice(&state.artifacts[0]).unwrap();
        assert_eq!(artifact["response"]["status"], 302);
        assert_eq!(state.audits[0]["payload"]["status"], 302);
    }).await.unwrap();
}

#[tokio::test]
async fn evidence_or_audit_failure_with_final_origin_status_still_settles_exactly_once() {
    timeout(LIMIT, async {
        for evidence_failure in [true, false] {
            let fixture = Fixture::start(None, false).await;
            {
                let mut state = fixture.seen.lock().unwrap();
                state.origin_status = Some(503);
                if evidence_failure { state.evidence_status = Some(500); }
                else { state.audit_status = Some(500); }
            }
            let mut stream = TcpStream::connect(fixture.proxy).await.unwrap();
            stream.write_all(format!("GET http://{}/failure HTTP/1.1\r\nHost: {}\r\nX-Security-Assessment-ID: {ID}\r\nConnection: close\r\n\r\n",fixture.origin,fixture.origin).as_bytes()).await.unwrap();
            let response = read_wire(&mut BufReader::new(stream)).await;
            assert!(response.line.contains("503"));
            assert_eq!(serde_json::from_slice::<Value>(&response.body).unwrap()["reason"], "EVIDENCE_UNAVAILABLE");
            let state = fixture.seen.lock().unwrap();
            assert_eq!(state.completions, 1); assert!(state.receipts.is_empty());
            assert_eq!(state.bucket["active_workers"], 0);
            assert_eq!(state.bucket["errors_5xx"], 1, "proxy-generated error changed origin accounting");
            assert_eq!(state.origins.len(), 1);
        }
    }).await.unwrap();
}

#[tokio::test]
async fn killswitch_interrupts_a_waiting_origin_and_closes_its_socket() {
    timeout(LIMIT, async {
        let fixture = Fixture::start(None, false).await;
        fixture.seen.lock().unwrap().stall_origin = true;
        let mut stream = TcpStream::connect(fixture.proxy).await.unwrap();
        stream.write_all(format!("GET http://{}/waiting HTTP/1.1\r\nHost: {}\r\nX-Security-Assessment-ID: {ID}\r\nConnection: close\r\n\r\n",fixture.origin,fixture.origin).as_bytes()).await.unwrap();
        loop {
            let ready = {
                let state = fixture.seen.lock().unwrap();
                !state.origins.is_empty() && state.stop_sender.is_some()
            };
            if ready { break; }
            tokio::task::yield_now().await;
        }
        fixture.seen.lock().unwrap().stop_sender.as_ref().unwrap()
            .send(Uuid::parse_str(ID).unwrap()).unwrap();
        let response = timeout(Duration::from_millis(100), read_wire(&mut BufReader::new(stream)))
            .await.expect("killswitch did not interrupt waiting origin within 100ms");
        assert!(response.line.contains("412"), "{response:?}");
        loop {
            if fixture.seen.lock().unwrap().origin_closed { break; }
            tokio::task::yield_now().await;
        }
        let state = fixture.seen.lock().unwrap();
        assert_eq!(state.completions, 0, "no final origin status was received");
        assert_eq!(state.receipts.len(), 1);
    }).await.unwrap();
}
