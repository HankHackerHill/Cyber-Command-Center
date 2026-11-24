//! Governed origin transport. A destination is parsed once, resolved once,
//! evaluated with that address, and connected only through that pinned address.
use std::{
    collections::HashMap,
    env, fs,
    net::{IpAddr, SocketAddr},
    num::NonZeroUsize,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use bytes::Bytes;
use http_body_util::BodyExt;
use hyper::{
    Method, Request, Response, StatusCode,
    body::Incoming,
    header::{self, HeaderMap, HeaderValue},
};
use hyper_util::rt::TokioIo;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::{TcpStream, lookup_host},
    time::{Instant, timeout},
};
use tokio_rustls::{
    TlsConnector,
    rustls::{
        ClientConfig, RootCertStore,
        pki_types::{CertificateDer, ServerName},
    },
};
use uuid::Uuid;

use crate::{
    Reply,
    breaker::Breaker,
    deny,
    evidence_client::EvidenceClient,
    policy_client::{BoundManifest, EvaluationError, PolicyClient, PolicyRequest},
    stop_response,
};

const MAX_BODY: usize = 1024 * 1024;
const MAX_HEADERS: usize = 64 * 1024;
const IO_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_MANIFEST: u64 = 1024 * 1024;

/// Opt-in bounded phase diagnostics: timings and sample numbers only.
#[derive(Clone)]
pub struct Timing {
    sample: usize,
    started: Instant,
}
impl Timing {
    pub fn start() -> Option<Self> {
        use std::sync::{
            OnceLock,
            atomic::{AtomicUsize, Ordering},
        };
        static ENABLED: OnceLock<bool> = OnceLock::new();
        static SAMPLES: AtomicUsize = AtomicUsize::new(0);
        if !*ENABLED.get_or_init(|| env::var("SCOPED_PROXY_TRACE_TIMING").as_deref() == Ok("1")) {
            return None;
        }
        let sample = SAMPLES.fetch_add(1, Ordering::Relaxed);
        (sample < 64).then(|| Self {
            sample,
            started: Instant::now(),
        })
    }
    pub fn record(timing: &Option<Self>, phase: &str, started: Instant) {
        if let Some(timing) = timing {
            eprintln!(
                "{}",
                json!({"event":"scoped_proxy_timing","sample":timing.sample,"phase":phase,"duration_us":started.elapsed().as_micros()})
            );
        }
    }
    fn finish(timing: &Option<Self>) {
        if let Some(value) = timing {
            Self::record(timing, "total", value.started);
        }
    }
}

#[derive(Clone, Debug)]
pub struct TunnelTarget {
    pub host: String,
    pub port: u16,
}

struct Workspace {
    manifest: BoundManifest,
    origin_roots: Vec<CertificateDer<'static>>,
    // M3 admission and observer completion both CAS the same account state.
    // Serialize only these short phases within this replica; origin/evidence
    // work retains its own reservation and remains concurrently bounded by M3.
    accounting: tokio::sync::Mutex<()>,
}

#[derive(Clone)]
pub struct Transport {
    policy: PolicyClient,
    breaker: Breaker,
    redis: redis::Client,
    evidence: Option<EvidenceClient>,
    workspaces: Arc<HashMap<Uuid, Workspace>>,
    root: Option<PathBuf>,
    tls_sessions: Arc<tokio::sync::Semaphore>,
}

#[derive(Debug)]
struct Destination {
    host: String,
    port: u16,
    path: String,
    url: reqwest::Url,
}

fn bounded_file(path: &Path, limit: u64) -> Result<Vec<u8>, &'static str> {
    // Provisioning is operator-controlled; reject links as an additional guard
    // against accidentally crossing workspace boundaries.
    let meta = fs::symlink_metadata(path).map_err(|_| "missing workspace file")?;
    if !meta.is_file() || meta.len() > limit {
        return Err("invalid workspace file");
    }
    fs::read(path).map_err(|_| "unreadable workspace file")
}

fn certificates(path: &Path) -> Result<Vec<CertificateDer<'static>>, &'static str> {
    let bytes = bounded_file(path, MAX_MANIFEST)?;
    let certs = rustls_pemfile::certs(&mut bytes.as_slice())
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| "invalid origin CA")?;
    if certs.is_empty() {
        return Err("empty origin CA");
    }
    Ok(certs)
}

impl Transport {
    pub fn from_environment(
        policy: PolicyClient,
        breaker: Breaker,
        redis: redis::Client,
    ) -> Result<Self, &'static str> {
        let root = env::var_os("SCOPED_PROXY_WORKSPACE_DIR").map(PathBuf::from);
        let evidence = env::var("EVIDENCE_URL")
            .ok()
            .map(|url| EvidenceClient::new(&url, NonZeroUsize::new(5 * MAX_BODY).unwrap()))
            .transpose()
            .map_err(|_| "invalid evidence configuration")?;
        let global_roots = env::var_os("SCOPED_PROXY_ORIGIN_CA_FILE")
            .map(PathBuf::from)
            .map(|p| certificates(&p))
            .transpose()?
            .unwrap_or_default();
        let mut workspaces = HashMap::new();
        if let Some(root) = &root {
            for entry in fs::read_dir(root).map_err(|_| "invalid workspace root")? {
                let entry = entry.map_err(|_| "unreadable workspace entry")?;
                let name = entry.file_name();
                let Some(name) = name.to_str() else { continue };
                let Ok(id) = Uuid::parse_str(name) else {
                    continue;
                };
                if name != id.to_string()
                    || !entry.file_type().map_err(|_| "invalid workspace")?.is_dir()
                {
                    continue;
                }
                let loaded = (|| {
                    let document = bounded_file(&entry.path().join("manifest.json"), MAX_MANIFEST)?;
                    let digest = bounded_file(&entry.path().join("manifest.sha256"), 128)?;
                    let digest = std::str::from_utf8(&digest)
                        .map_err(|_| "invalid manifest digest")?
                        .trim();
                    let manifest = BoundManifest::from_provisioned(id, digest, &document)?;
                    let mut origin_roots = global_roots.clone();
                    let ca = entry.path().join("origin-ca.pem");
                    if ca.exists() {
                        origin_roots.extend(certificates(&ca)?);
                    }
                    Ok::<_, &'static str>(Workspace {
                        manifest,
                        origin_roots,
                        accounting: tokio::sync::Mutex::new(()),
                    })
                })();
                match loaded {
                    Ok(workspace) => {
                        workspaces.insert(id, workspace);
                    }
                    Err(reason) => eprintln!("Workspace {id} unavailable: {reason}"),
                }
            }
        }
        Ok(Self {
            policy,
            breaker,
            redis,
            evidence,
            workspaces: Arc::new(workspaces),
            root,
            tls_sessions: Arc::new(tokio::sync::Semaphore::new(256)),
        })
    }

    pub fn try_tls_permit(&self) -> Option<tokio::sync::OwnedSemaphorePermit> {
        self.tls_sessions.clone().try_acquire_owned().ok()
    }

    pub fn workspace_root(&self) -> Option<&Path> {
        self.root.as_deref()
    }
    pub fn provisioned(&self, id: Uuid) -> bool {
        self.workspaces.contains_key(&id) && self.evidence.is_some()
    }
    pub fn evidence(&self) -> Option<&EvidenceClient> {
        self.evidence.as_ref()
    }

    /// State has already been checked by the listener; TLS inner requests use
    /// the same listener precheck before invoking this method.
    pub async fn forward(
        &self,
        req: Request<Incoming>,
        id: Uuid,
        tunnel: Option<TunnelTarget>,
    ) -> Reply {
        self.forward_traced(req, id, tunnel, Timing::start()).await
    }

    pub async fn forward_traced(
        &self,
        req: Request<Incoming>,
        id: Uuid,
        tunnel: Option<TunnelTarget>,
        timing: Option<Timing>,
    ) -> Reply {
        if self.breaker.blocked(id) {
            return stop_response(&self.breaker);
        }
        if tunnel.is_some() {
            let mut ids = req.headers().get_all("x-security-assessment-id").iter();
            if let Some(value) = ids.next()
                && (value
                    .to_str()
                    .ok()
                    .and_then(|value| Uuid::parse_str(value).ok())
                    != Some(id)
                    || ids.next().is_some())
            {
                return deny(StatusCode::BAD_REQUEST, "INVALID_ASSESSMENT_ID");
            }
            let phase_started = Instant::now();
            let state = tokio::select! {
                biased;
                () = self.breaker.wait_blocked(id) => return stop_response(&self.breaker),
                result = self.policy.check_state(id) => result,
            };
            Timing::record(&timing, "state", phase_started);
            match state {
                Ok(()) => (),
                Err(crate::policy_client::StateError::PreconditionFailed) => {
                    return deny(StatusCode::PRECONDITION_FAILED, "PRECONDITION_FAILED");
                }
                Err(crate::policy_client::StateError::Unavailable) => {
                    return deny(StatusCode::SERVICE_UNAVAILABLE, "STATE_UNAVAILABLE");
                }
            }
        }
        if !self.provisioned(id) {
            return deny(StatusCode::SERVICE_UNAVAILABLE, "MANIFEST_UNAVAILABLE");
        }
        let destination = match destination(&req, tunnel.as_ref()) {
            Ok(value) => value,
            Err(reason) => return deny(StatusCode::BAD_REQUEST, reason),
        };
        if req.method() == Method::CONNECT
            || req.headers().contains_key(header::UPGRADE)
            || connection_has(req.headers(), "upgrade")
        {
            return deny(StatusCode::BAD_REQUEST, "UPGRADE_NOT_ALLOWED");
        }
        if headers_size(req.headers()) > MAX_HEADERS {
            return deny(
                StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE,
                "HEADERS_TOO_LARGE",
            );
        }
        let (mut parts, mut incoming) = req.into_parts();
        let body = tokio::select! {
            biased;
            () = self.breaker.wait_blocked(id) => return stop_response(&self.breaker),
            result = timeout(IO_TIMEOUT, async {
                let mut bytes = Vec::new();
                while let Some(frame) = incoming.frame().await {
                    let frame = frame.map_err(|_| "REQUEST_BODY_UNAVAILABLE")?;
                    if let Ok(data) = frame.into_data() {
                        if data.len() > MAX_BODY - bytes.len() { return Err("REQUEST_BODY_TOO_LARGE"); }
                        bytes.extend_from_slice(&data);
                    } else { return Err("TRAILERS_NOT_ALLOWED"); }
                }
                Ok(bytes)
            }) => match result {
                Ok(Ok(bytes)) => bytes,
                Ok(Err(reason)) => return deny(StatusCode::BAD_REQUEST, reason),
                Err(_) => return deny(StatusCode::REQUEST_TIMEOUT, "REQUEST_BODY_TIMEOUT"),
            }
        };
        strip_hop_headers(&mut parts.headers);
        parts.headers.remove(header::HOST);
        parts.headers.remove(header::CONTENT_LENGTH);
        parts.headers.insert(
            "x-security-assessment-id",
            HeaderValue::from_str(&id.to_string()).unwrap(),
        );
        let ip = tokio::select! {
            biased;
            () = self.breaker.wait_blocked(id) => return stop_response(&self.breaker),
            result = timeout(Duration::from_secs(2), resolve(&destination)) => match result {
                Ok(Ok(ip)) => ip,
                _ => return deny(StatusCode::BAD_GATEWAY, "ORIGIN_RESOLUTION_UNAVAILABLE"),
            }
        };
        let workspace = &self.workspaces[&id];
        let phase_started = Instant::now();
        let admission_lock = tokio::select! {
            biased;
            () = self.breaker.wait_blocked(id) => return stop_response(&self.breaker),
            result = timeout(IO_TIMEOUT, workspace.accounting.lock()) => match result {
                Ok(guard) => guard,
                Err(_) => return deny(StatusCode::SERVICE_UNAVAILABLE, "POLICY_UNAVAILABLE"),
            },
        };
        Timing::record(&timing, "admission_lock", phase_started);
        let timestamp = OffsetDateTime::now_utc()
            .format(&Rfc3339)
            .expect("UTC timestamp");
        let policy_request = PolicyRequest {
            method: parts.method.as_str(),
            host: &destination.host,
            ip,
            path: &destination.path,
            ts: &timestamp,
        };
        let phase_started = Instant::now();
        let reservation = tokio::select! {
            biased;
            () = self.breaker.wait_blocked(id) => return stop_response(&self.breaker),
            result = self.policy.evaluate(&workspace.manifest, &policy_request) => match result {
                Ok(receipt) => receipt,
                Err(EvaluationError::Denied(reason)) => return deny(StatusCode::FORBIDDEN, reason),
                Err(EvaluationError::Unavailable) => return deny(StatusCode::SERVICE_UNAVAILABLE, "POLICY_UNAVAILABLE"),
            }
        };
        Timing::record(&timing, "evaluate", phase_started);
        drop(admission_lock);
        // Own all work from reservation onward. Dropping the client response
        // future cannot cancel evidence/accounting after an origin status.
        let transport = self.clone();
        let task = tokio::spawn(async move {
            transport
                .execute(
                    id,
                    reservation,
                    parts.method,
                    parts.headers,
                    body,
                    destination,
                    ip,
                    timestamp,
                    timing,
                )
                .await
        });
        tokio::select! {
            biased;
            () = self.breaker.wait_blocked(id) => stop_response(&self.breaker),
            result = task => result.unwrap_or_else(|_| deny(StatusCode::BAD_GATEWAY, "ORIGIN_UNAVAILABLE")),
        }
    }

    // No final status exists. Record the admitted attempt, but leave its
    // reservation outstanding; an unavailable origin cannot be invented as 502.
    async fn record_incomplete(&self, id: Uuid, reservation: Uuid, request: Value, error: &str) {
        let event_id = Uuid::new_v4();
        let artifact = serde_json::to_vec(&json!({"engagement_id":id,"event_id":event_id,"reservation":reservation,"request":request,"response":{"status":null,"headers":[],"headers_hex":[],"body_hex":"","complete":false},"error":error})).expect("bounded evidence serializes");
        let evidence_sha256 = format!("{:x}", Sha256::digest(&artifact));
        let acknowledged = self
            .evidence
            .as_ref()
            .expect("provisioned evidence")
            .put(Bytes::from(artifact))
            .await
            .is_ok();
        if let Err(error) = self.policy.audit_event(id, event_id, "PROXY_REQUEST_INCOMPLETE", json!({"evidence_sha256":evidence_sha256,"evidence_acknowledged":acknowledged,"status":null,"reservation":reservation,"error":error})).await {
            eprintln!("Incomplete origin attempt {event_id} audit append unconfirmed: {error:?}");
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn execute(
        &self,
        id: Uuid,
        reservation: Uuid,
        method: Method,
        mut headers: HeaderMap,
        body: Vec<u8>,
        destination: Destination,
        ip: IpAddr,
        timestamp: String,
        timing: Option<Timing>,
    ) -> Reply {
        let workspace = &self.workspaces[&id];
        let authority = if destination.host.contains(':') {
            format!("[{}]:{}", destination.host, destination.port)
        } else {
            format!("{}:{}", destination.host, destination.port)
        };
        headers.insert(header::HOST, HeaderValue::from_str(&authority).unwrap());
        headers.insert(header::CONNECTION, HeaderValue::from_static("close"));
        headers.insert(
            header::CONTENT_LENGTH,
            HeaderValue::from_str(&body.len().to_string()).unwrap(),
        );
        let request_record = json!({"method":method.as_str(),"host":destination.host,"ip":ip,"port":destination.port,"path":destination.path,"uri":destination.url.as_str(),"timestamp":timestamp,"headers":record_headers(&headers),"headers_hex":record_headers_hex(&headers),"body_hex":hex(&body)});
        let deadline = Instant::now() + IO_TIMEOUT;
        let phase_started = Instant::now();
        let origin = tokio::select! {
            biased;
            () = self.breaker.wait_blocked(id) => None,
            result = timeout(IO_TIMEOUT, origin_request(&destination, ip, &workspace.origin_roots, method.clone(), headers, body)) => Some(result),
        };
        Timing::record(&timing, "origin_status", phase_started);
        let (mut origin, connection) = match origin {
            Some(Ok(Ok((origin, connection))))
                if (200..=599).contains(&origin.status().as_u16()) =>
            {
                (origin, connection)
            }
            // A proxy-generated 502 is never an origin completion. Leave the
            // ambiguous receipt outstanding for operator reconciliation.
            _ => {
                self.record_incomplete(id, reservation, request_record, "ORIGIN_UNAVAILABLE")
                    .await;
                if self.breaker.blocked(id) {
                    return stop_response(&self.breaker);
                }
                return deny(StatusCode::BAD_GATEWAY, "ORIGIN_UNAVAILABLE");
            }
        };
        let status = origin.status();
        let mut response_headers = origin.headers().clone();
        let phase_started = Instant::now();
        let mut response_body = Vec::new();
        let mut error = None;
        if headers_size(&response_headers) > MAX_HEADERS {
            error = Some("RESPONSE_HEADERS_TOO_LARGE");
            response_headers.clear();
        } else if method != Method::HEAD && !matches!(status.as_u16(), 204 | 304) {
            loop {
                let chunk = tokio::select! {
                    biased;
                    () = self.breaker.wait_blocked(id) => { error = Some("PRECONDITION_FAILED"); break; },
                    result = tokio::time::timeout_at(deadline, origin.body_mut().frame()) => result,
                };
                match chunk {
                    Ok(Some(Ok(frame))) => match frame.into_data() {
                        Ok(chunk) if chunk.len() <= MAX_BODY - response_body.len() => {
                            response_body.extend_from_slice(&chunk)
                        }
                        Ok(chunk) => {
                            response_body
                                .extend_from_slice(&chunk[..MAX_BODY - response_body.len()]);
                            error = Some("RESPONSE_BODY_TOO_LARGE");
                            break;
                        }
                        Err(_) => {
                            error = Some("TRAILERS_NOT_ALLOWED");
                            break;
                        }
                    },
                    Ok(None) => break,
                    _ => {
                        error = Some("RESPONSE_BODY_UNAVAILABLE");
                        break;
                    }
                }
            }
        }
        Timing::record(&timing, "body", phase_started);
        // Drop the origin connection before the independent durable work.
        drop(origin);
        drop(connection);
        let response_headers_record = record_headers(&response_headers);
        let response_headers_hex = record_headers_hex(&response_headers);
        strip_hop_headers(&mut response_headers);
        if method != Method::HEAD && status.as_u16() != 304 {
            response_headers.remove(header::CONTENT_LENGTH);
        }
        let event_id = Uuid::new_v4();
        let artifact = serde_json::to_vec(&json!({"engagement_id":id,"event_id":event_id,"reservation":reservation,"request":request_record,"response":{"status":status.as_u16(),"headers":response_headers_record,"headers_hex":response_headers_hex,"body_hex":hex(&response_body),"complete":error.is_none()},"error":error})).expect("bounded evidence serializes");
        let evidence_sha256 = format!("{:x}", Sha256::digest(&artifact));
        let phase_started = Instant::now();
        let evidence_ok = self
            .evidence
            .as_ref()
            .expect("provisioned evidence")
            .put(Bytes::from(artifact))
            .await
            .is_ok();
        Timing::record(&timing, "evidence", phase_started);
        let phase_started = Instant::now();
        let audit_ok = self.policy.audit_event(id, event_id, "PROXY_REQUEST_COMPLETED", json!({"evidence_sha256":evidence_sha256,"evidence_acknowledged":evidence_ok,"status":status.as_u16(),"reservation":reservation,"method":method.as_str(),"host":destination.host,"ip":ip,"port":destination.port,"path":destination.path})).await.is_ok();
        Timing::record(&timing, "audit", phase_started);
        // A confirmed final status must complete even after a stop or client
        // disconnect. This fair lock is shared with admission across clones,
        // preventing our own evaluations from invalidating completion snapshots.
        let phase_started = Instant::now();
        let settlement_lock = workspace.accounting.lock().await;
        Timing::record(&timing, "settlement_lock", phase_started);
        let phase_started = Instant::now();
        let settled = self
            .breaker
            .settle(
                &self.redis,
                &self.policy,
                id,
                reservation,
                status.as_u16(),
                workspace.manifest.breaker_threshold(),
            )
            .await
            .is_ok();
        Timing::record(&timing, "settle", phase_started);
        Timing::finish(&timing);
        drop(settlement_lock);
        if self.breaker.blocked(id) {
            return stop_response(&self.breaker);
        }
        if !evidence_ok || !audit_ok {
            return deny(StatusCode::SERVICE_UNAVAILABLE, "EVIDENCE_UNAVAILABLE");
        }
        if !settled {
            return deny(
                StatusCode::SERVICE_UNAVAILABLE,
                "POLICY_COMPLETION_UNAVAILABLE",
            );
        }
        if let Some(reason) = error {
            return deny(StatusCode::BAD_GATEWAY, reason);
        }
        let mut response = Response::new(http_body_util::Full::new(Bytes::from(response_body)));
        *response.status_mut() = status;
        *response.headers_mut() = response_headers;
        response
    }
}

trait OriginIo: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> OriginIo for T {}
struct OriginConnection(tokio::task::JoinHandle<()>);
impl Drop for OriginConnection {
    fn drop(&mut self) {
        self.0.abort();
    }
}

async fn origin_request(
    destination: &Destination,
    ip: IpAddr,
    roots: &[CertificateDer<'static>],
    method: Method,
    mut headers: HeaderMap,
    body: Vec<u8>,
) -> Result<(Response<Incoming>, OriginConnection), ()> {
    let socket = timeout(
        Duration::from_secs(3),
        TcpStream::connect(SocketAddr::new(ip, destination.port)),
    )
    .await
    .map_err(|_| ())?
    .map_err(|_| ())?;
    socket.set_nodelay(true).map_err(|_| ())?;
    let io: Box<dyn OriginIo> = if destination.url.scheme() == "https" {
        let mut store = RootCertStore::empty();
        store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        for root in roots {
            store.add(root.clone()).map_err(|_| ())?;
        }
        let config = ClientConfig::builder_with_provider(Arc::new(
            tokio_rustls::rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .map_err(|_| ())?
        .with_root_certificates(store)
        .with_no_client_auth();
        let server_name = ServerName::try_from(destination.host.clone()).map_err(|_| ())?;
        Box::new(
            TlsConnector::from(Arc::new(config))
                .connect(server_name, socket)
                .await
                .map_err(|_| ())?,
        )
    } else {
        Box::new(socket)
    };
    let (mut sender, connection) = hyper::client::conn::http1::Builder::new()
        .max_buf_size(MAX_HEADERS)
        .handshake(TokioIo::new(io))
        .await
        .map_err(|_| ())?;
    let connection = OriginConnection(tokio::spawn(async move {
        let _ = connection.await;
    }));
    let host = if destination.host.contains(':') {
        format!("[{}]:{}", destination.host, destination.port)
    } else {
        format!("{}:{}", destination.host, destination.port)
    };
    headers.insert(header::HOST, HeaderValue::from_str(&host).map_err(|_| ())?);
    // Closing the owned connection forbids reuse across admissions/engagements.
    headers.insert(header::CONNECTION, HeaderValue::from_static("close"));
    let mut request = Request::builder()
        .method(method)
        .uri(format!(
            "{}{}",
            destination.url.path(),
            destination
                .url
                .query()
                .map(|query| format!("?{query}"))
                .unwrap_or_default()
        ))
        .body(http_body_util::Full::new(Bytes::from(body)))
        .map_err(|_| ())?;
    *request.headers_mut() = headers;
    let response = sender.send_request(request).await.map_err(|_| ())?;
    Ok((response, connection))
}

async fn resolve(destination: &Destination) -> Result<IpAddr, ()> {
    if let Ok(ip) = destination.host.parse() {
        return Ok(ip);
    }
    lookup_host((destination.host.as_str(), destination.port))
        .await
        .map_err(|_| ())?
        .next()
        .map(|socket| socket.ip())
        .ok_or(())
}

pub fn target(authority: &str, default_port: u16) -> Result<TunnelTarget, &'static str> {
    if authority.contains('@') || !authority.is_ascii() {
        return Err("INVALID_DESTINATION");
    }
    let authority: hyper::http::uri::Authority =
        authority.parse().map_err(|_| "INVALID_DESTINATION")?;
    let host = authority
        .host()
        .trim_start_matches('[')
        .trim_end_matches(']')
        .to_ascii_lowercase();
    if host.parse::<IpAddr>().is_err()
        && (host.len() > 253
            || host.trim_end_matches('.').split('.').any(|label| {
                label.is_empty()
                    || label.len() > 63
                    || label.starts_with('-')
                    || label.ends_with('-')
                    || !label
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'-')
            }))
    {
        return Err("INVALID_DESTINATION");
    }
    let raw_authority = authority.as_str();
    let raw_port = if raw_authority.starts_with('[') {
        let (_, remainder) = raw_authority.split_once(']').ok_or("INVALID_DESTINATION")?;
        if remainder.is_empty() {
            None
        } else {
            Some(remainder.strip_prefix(':').ok_or("INVALID_DESTINATION")?)
        }
    } else {
        raw_authority.rsplit_once(':').map(|(_, port)| port)
    };
    let port = match raw_port {
        Some(value) if !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit()) => {
            value.parse::<u16>().map_err(|_| "INVALID_DESTINATION")?
        }
        Some(_) => return Err("INVALID_DESTINATION"),
        None => default_port,
    };
    if port == 0 {
        return Err("INVALID_DESTINATION");
    }
    Ok(TunnelTarget { host, port })
}

fn destination<B>(
    req: &Request<B>,
    tunnel: Option<&TunnelTarget>,
) -> Result<Destination, &'static str> {
    let uri = req.uri();
    let mut hosts = req.headers().get_all(header::HOST).iter();
    let host = hosts
        .next()
        .and_then(|h| h.to_str().ok())
        .ok_or("INVALID_DESTINATION")?;
    if hosts.next().is_some() {
        return Err("INVALID_DESTINATION");
    }
    let default_port = if tunnel.is_some() { 443 } else { 80 };
    let host_header = target(host, default_port)?;
    let parsed = match uri.authority() {
        Some(authority) => target(authority.as_str(), default_port)?,
        None if tunnel.is_some() => host_header.clone(),
        None => return Err("ABSOLUTE_FORM_REQUIRED"),
    };
    if parsed.host != host_header.host || parsed.port != host_header.port {
        return Err("DESTINATION_MISMATCH");
    }
    let scheme = if let Some(tunnel) = tunnel {
        if parsed.host != tunnel.host || parsed.port != tunnel.port {
            return Err("TUNNEL_DESTINATION_MISMATCH");
        }
        if uri.scheme_str().is_some_and(|scheme| scheme != "https") {
            return Err("INVALID_DESTINATION");
        }
        "https"
    } else {
        if uri.scheme_str() != Some("http") {
            return Err("INVALID_DESTINATION");
        }
        "http"
    };
    let path = uri.path();
    let path_and_query = uri.path_and_query().map(|p| p.as_str()).unwrap_or("/");
    if path_and_query.len() > 8 * 1024 {
        return Err("REQUEST_TARGET_TOO_LARGE");
    }
    if !path.starts_with('/') {
        return Err("INVALID_PATH");
    }
    // Match M3's unambiguous path grammar before Url can normalize anything.
    // Compute once so adversarial long paths stay linear before admission.
    let segment_count = path[1..].split('/').count();
    if path[1..].split('/').enumerate().any(|(index, segment)| {
        segment == "."
            || segment == ".."
            || (segment.is_empty() && index + 1 != segment_count)
            || !segment
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"._~-".contains(&b))
    }) {
        return Err("INVALID_PATH");
    }
    let authority = if parsed.host.contains(':') {
        format!("[{}]:{}", parsed.host, parsed.port)
    } else {
        format!("{}:{}", parsed.host, parsed.port)
    };
    let url = reqwest::Url::parse(&format!("{scheme}://{authority}{path_and_query}"))
        .map_err(|_| "INVALID_DESTINATION")?;
    if url.path() != path || url.query() != uri.query() {
        return Err("INVALID_PATH");
    }
    Ok(Destination {
        host: parsed.host,
        port: parsed.port,
        path: path.to_owned(),
        url,
    })
}

fn connection_has(headers: &HeaderMap, name: &str) -> bool {
    headers
        .get_all(header::CONNECTION)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .any(|token| token.trim().eq_ignore_ascii_case(name))
}

pub fn strip_hop_headers(headers: &mut HeaderMap) {
    let nominated: Vec<_> = headers
        .get_all(header::CONNECTION)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .filter_map(|token| header::HeaderName::from_bytes(token.trim().as_bytes()).ok())
        .collect();
    for name in nominated {
        headers.remove(name);
    }
    for name in [
        "connection",
        "proxy-connection",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "te",
        "trailer",
        "transfer-encoding",
        "upgrade",
    ] {
        headers.remove(name);
    }
}

fn headers_size(headers: &HeaderMap) -> usize {
    headers
        .iter()
        .map(|(name, value)| name.as_str().len() + value.as_bytes().len())
        .sum()
}
fn record_headers_hex(headers: &HeaderMap) -> Value {
    json!(
        headers
            .iter()
            .map(|(name, value)| [name.as_str().to_owned(), hex(value.as_bytes())])
            .collect::<Vec<_>>()
    )
}

fn record_headers(headers: &HeaderMap) -> Value {
    json!(
        headers
            .iter()
            .map(|(name, value)| [
                name.as_str().to_owned(),
                String::from_utf8_lossy(value.as_bytes()).into_owned()
            ])
            .collect::<Vec<_>>()
    )
}
fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(output, "{byte:02x}").unwrap();
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(uri: &str, host: &str) -> Request<()> {
        Request::builder()
            .uri(uri)
            .header(header::HOST, host)
            .body(())
            .unwrap()
    }

    #[test]
    fn validates_raw_path_before_url_normalization_and_preserves_query() {
        for path in [
            "/x/../admin",
            "/./admin",
            "/a/%2e",
            "/a%2fb",
            "/x//y",
            "//admin",
            "/a;b",
        ] {
            let req = request(&format!("http://localhost{path}"), "localhost");
            assert_eq!(destination(&req, None).unwrap_err(), "INVALID_PATH");
        }
        let parsed = destination(
            &request("http://localhost/safe?sample=1%202", "localhost"),
            None,
        )
        .unwrap();
        assert_eq!(parsed.path, "/safe");
        assert_eq!(parsed.url.query(), Some("sample=1%202"));
    }

    #[test]
    fn binds_authority_and_port_to_the_inspected_tunnel() {
        let bound = TunnelTarget {
            host: "localhost".into(),
            port: 8443,
        };
        assert!(destination(&request("/safe", "localhost:8443"), Some(&bound)).is_ok());
        assert_eq!(
            destination(&request("/safe", "localhost:443"), Some(&bound)).unwrap_err(),
            "TUNNEL_DESTINATION_MISMATCH"
        );
        assert_eq!(
            destination(
                &request("http://localhost:8443/safe", "localhost:8443"),
                Some(&bound)
            )
            .unwrap_err(),
            "INVALID_DESTINATION"
        );
        assert_eq!(
            destination(&request("http://localhost/safe", "elsewhere"), None).unwrap_err(),
            "DESTINATION_MISMATCH"
        );
        for authority in ["localhost:65536", "localhost:", "[::1]:65536", "[::1]:"] {
            assert!(target(authority, 80).is_err(), "{authority}");
        }
        assert!(target("localhost:abc", 80).is_err());
        assert!(target("user@localhost:80", 80).is_err());
    }

    #[test]
    fn evidence_preserves_distinct_non_utf8_header_bytes() {
        let mut first = HeaderMap::new();
        let mut second = HeaderMap::new();
        first.insert("x-observed", HeaderValue::from_bytes(&[0x80]).unwrap());
        second.insert("x-observed", HeaderValue::from_bytes(&[0x81]).unwrap());
        assert_eq!(record_headers(&first), record_headers(&second));
        assert_ne!(record_headers_hex(&first), record_headers_hex(&second));
    }

    #[test]
    fn removes_every_hop_header_and_connection_nominated_field() {
        let mut headers = HeaderMap::new();
        headers.append(
            header::CONNECTION,
            HeaderValue::from_static("x-remove, X-Security-Assessment-ID"),
        );
        headers.append(header::CONNECTION, HeaderValue::from_static("keep-alive"));
        for name in [
            "x-remove",
            "x-security-assessment-id",
            "keep-alive",
            "proxy-authorization",
            "proxy-connection",
            "transfer-encoding",
            "upgrade",
            "trailer",
            "te",
        ] {
            headers.insert(name, HeaderValue::from_static("secret"));
        }
        headers.insert("x-retain", HeaderValue::from_static("retained"));
        strip_hop_headers(&mut headers);
        assert_eq!(headers.len(), 1);
        assert_eq!(headers["x-retain"], "retained");
    }
}
