//! Governed-path acceptance against provisioned, real M2/M3/M4/M7 services.
//! Four closed-loop workers consume each entire response. For HTTP and inspected
//! HTTPS independently, report 64 warmup and three 1,000-request nearest-rank p99s.
//! Gate the median measured E2E p99 <50 ms and EVERY measured trusted proxy-
//! internal p99 <15 ms.
//! E2E is absolute client request-to-full-body elapsed time, never a direct-path
//! subtraction. Connection pooling is enabled; any CONNECT/TLS establishment is
//! included in the transaction establishing that connection. Internal timing is
//! the proxy wall-time residual after removing named suspended backend, client,
//! and origin waits and adding back active future-poll work (including TLS
//! crypto). It includes local durable-spool fsync waits; CONNECT CA/leaf setup
//! and TLS accept processing are charged to the first decrypted request. It is
//! a server-exclusive phase measurement, not an operating-system CPU metric.
//! Set M4_LOAD_PROXY_ADDR, M4_LOAD_ENGAGEMENT_ID, M4_LOAD_CA_PEM,
//! M4_LOAD_ORIGIN_CERT_PEM, M4_LOAD_ORIGIN_KEY_PEM, SCOPED_PROXY_TIMING_PATH,
//! and a new M4_LOAD_PROOF_PATH for post-measurement exact evidence verification.
//! Run `cargo test --release --test load -- --ignored --nocapture`.

use bytes::Bytes;
use futures_util::{StreamExt, TryStreamExt, stream};
use http_body_util::Full;
use hyper::{
    Request, Response, StatusCode, body::Incoming, server::conn::http1, service::service_fn,
};
use hyper_util::rt::TokioIo;
use reqwest::{
    Client, Proxy,
    header::{HeaderMap, HeaderValue},
    redirect::Policy,
};
use serde::Deserialize;
use std::{
    collections::{HashMap, hash_map::RandomState},
    convert::Infallible,
    env,
    error::Error,
    fs,
    hash::BuildHasher,
    io,
    net::{Ipv4Addr, SocketAddr},
    path::PathBuf,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::TcpListener,
};
use tokio_rustls::{TlsAcceptor, rustls::ServerConfig};
use uuid::Uuid;

type Failure = Box<dyn Error + Send + Sync>;
const ATTRIBUTION: &str = "X-Security-Assessment-ID";
const WARMUP: usize = 64;
const SAMPLES: usize = 1_000;
const CONCURRENCY: usize = 4;

struct Benchmark {
    origin: SocketAddr,
    proxy: SocketAddr,
    client: Client,
    engagement: String,
    proof: RandomState,
    protocol: &'static str,
    prefix: String,
    timing_path: PathBuf,
}

async fn serve<S>(socket: S, key: RandomState, id: String) -> Result<(), Failure>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let service = service_fn(move |req: Request<Incoming>| {
        let mut response = Response::new(Full::new(Bytes::new()));
        let mut attribution = req.headers().get_all(ATTRIBUTION).iter();
        if req.method() == hyper::Method::GET
            && req.uri().path().starts_with("/m4-load/")
            && attribution.next().map(|v| v.as_bytes()) == Some(id.as_bytes())
            && attribution.next().is_none()
        {
            let tag = key.hash_one(req.uri().path()).to_be_bytes();
            *response.body_mut() = Full::new(Bytes::copy_from_slice(&tag));
        } else {
            *response.status_mut() = StatusCode::BAD_REQUEST;
        }
        async move { Ok::<_, Infallible>(response) }
    });
    http1::Builder::new()
        .serve_connection(TokioIo::new(socket), service)
        .await?;
    Ok(())
}

impl Benchmark {
    async fn set_up(protocol: &'static str) -> Result<Self, Failure> {
        let proxy: SocketAddr = env::var("M4_LOAD_PROXY_ADDR")?.parse()?;
        if !proxy.ip().is_loopback() || proxy.port() == 0 {
            return Err("M4_LOAD_PROXY_ADDR must be a loopback socket with a nonzero port".into());
        }
        let engagement = Uuid::parse_str(&env::var("M4_LOAD_ENGAGEMENT_ID")?)?.to_string();
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let origin = listener.local_addr()?;
        let proof = RandomState::new();
        let acceptor = if protocol == "https" {
            let certificates = fs::read(env::var("M4_LOAD_ORIGIN_CERT_PEM")?)?;
            let private = fs::read(env::var("M4_LOAD_ORIGIN_KEY_PEM")?)?;
            let certs = rustls_pemfile::certs(&mut certificates.as_slice())
                .collect::<Result<Vec<_>, _>>()?;
            let key = rustls_pemfile::private_key(&mut private.as_slice())?
                .ok_or("missing origin fixture key")?;
            Some(TlsAcceptor::from(Arc::new(
                ServerConfig::builder()
                    .with_no_client_auth()
                    .with_single_cert(certs, key)?,
            )))
        } else {
            None
        };
        let server_key = proof.clone();
        let expected_id = engagement.clone();
        tokio::spawn(async move {
            while let Ok((socket, _)) = listener.accept().await {
                let key = server_key.clone();
                let id = expected_id.clone();
                let acceptor = acceptor.clone();
                tokio::spawn(async move {
                    socket.set_nodelay(true)?;
                    if let Some(acceptor) = acceptor {
                        serve(acceptor.accept(socket).await?, key, id).await
                    } else {
                        serve(socket, key, id).await
                    }
                });
            }
        });
        let ca = fs::read(env::var("M4_LOAD_CA_PEM")?)?;
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-security-assessment-id",
            HeaderValue::from_str(&engagement)?,
        );
        let client = Client::builder()
            .no_proxy()
            .redirect(Policy::none())
            .retry(reqwest::retry::never())
            .timeout(Duration::from_secs(10))
            .tls_built_in_root_certs(false)
            .add_root_certificate(reqwest::Certificate::from_pem(&ca)?)
            .proxy(Proxy::all(format!("http://{proxy}"))?.headers(headers))
            .build()?;
        Ok(Self {
            origin,
            proxy,
            client,
            engagement,
            proof,
            protocol,
            prefix: format!("/m4-load/{}", Uuid::new_v4()),
            timing_path: env::var("SCOPED_PROXY_TIMING_PATH")?.into(),
        })
    }

    fn path(&self, sequence: usize) -> String {
        format!("{}/{sequence}", self.prefix)
    }

    async fn duration_ns(&self, sequence: usize) -> Result<u64, Failure> {
        let path = self.path(sequence);
        let url = format!("{}://{}{path}", self.protocol, self.origin);
        let expected = self.proof.hash_one(path.as_str()).to_be_bytes();
        let request = self.client.get(url).header(ATTRIBUTION, &self.engagement);
        let start = Instant::now();
        let mut response = request.send().await?;
        if response.remote_addr() != Some(self.proxy) {
            return Err(format!(
                "unexpected TCP peer for sample {sequence}: {:?}",
                response.remote_addr()
            )
            .into());
        }
        if !response.status().is_success() {
            return Err(io::Error::other(format!(
                "{} sample {sequence} returned {}: {}",
                self.protocol,
                response.status(),
                response.text().await?
            ))
            .into());
        }
        let mut received = Vec::new();
        while let Some(chunk) = response.chunk().await? {
            if received.len() + chunk.len() > expected.len() {
                return Err("oversized origin proof".into());
            }
            received.extend_from_slice(&chunk);
        }
        let elapsed = u64::try_from(start.elapsed().as_nanos())?;
        if received != expected {
            return Err("response did not match the exact loopback origin proof".into());
        }
        Ok(elapsed)
    }

    async fn measure(&self, first: usize, count: usize) -> Result<(u64, u64), Failure> {
        let mut elapsed: Vec<u64> = stream::iter(first..first + count)
            .map(|index| self.duration_ns(index))
            .buffer_unordered(CONCURRENCY)
            .try_collect()
            .await?;
        // The file is trusted server instrumentation, never a client-controlled header.
        // Wait for a final append if recording runs immediately after response completion.
        let deadline = Instant::now() + Duration::from_secs(10);
        let mut internal = loop {
            let samples = self.internal_samples(first, count)?;
            if samples.len() == count {
                break samples;
            }
            if Instant::now() >= deadline {
                return Err(format!(
                    "{} internal timing cardinality {}, expected {count}",
                    self.protocol,
                    samples.len()
                )
                .into());
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        };
        Ok((
            nearest_rank_p99(&mut elapsed),
            nearest_rank_p99(&mut internal),
        ))
    }

    fn internal_samples(&self, first: usize, count: usize) -> Result<Vec<u64>, Failure> {
        #[derive(Deserialize)]
        struct Sample {
            uri: String,
            protocol: String,
            internal_ns: u64,
            total_ns: u64,
        }
        let contents = fs::read_to_string(&self.timing_path)?;
        let mut samples = HashMap::new();
        for line in contents.lines() {
            // Concurrent final line may still be being appended; it will be reread.
            let Ok(sample) = serde_json::from_str::<Sample>(line) else {
                continue;
            };
            let path = if sample.uri.starts_with('/') {
                sample.uri.clone()
            } else {
                reqwest::Url::parse(&sample.uri)?.path().to_owned()
            };
            let Some(index) = path.strip_prefix(&format!("{}/", self.prefix)) else {
                continue;
            };
            let index: usize = index.parse()?;
            if !(first..first + count).contains(&index) {
                continue;
            }
            if sample.protocol != self.protocol || sample.internal_ns > sample.total_ns {
                return Err("invalid trusted internal timing protocol or duration".into());
            }
            if samples.insert(index, sample.internal_ns).is_some() {
                return Err("duplicate trusted timing sample".into());
            }
        }
        Ok(samples.into_values().collect())
    }
}

fn nearest_rank_p99(values: &mut [u64]) -> u64 {
    assert!(!values.is_empty(), "p99 requires at least one sample");
    values.sort_unstable();
    values[(99 * values.len()).div_ceil(100) - 1]
}
fn median_of_three(mut values: [u64; 3]) -> u64 {
    values.sort_unstable();
    values[1]
}

#[test]
fn percentile_is_actual_nearest_rank_not_a_median() {
    let mut values: Vec<_> = (1..=1_000).rev().collect();
    assert_eq!(nearest_rank_p99(&mut values), 990);
    assert_eq!(nearest_rank_p99(&mut [7]), 7);
    assert_eq!(median_of_three([30_000_000, 500, 9_000_000]), 9_000_000);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires provisioned real M2/M3/M4/M7 services and engagement TLS material"]
async fn governed_http_and_inspected_https_latency_gates() -> Result<(), Failure> {
    use std::io::Write;
    let mut proofs = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(env::var("M4_LOAD_PROOF_PATH")?)?;
    let mut failures = Vec::new();
    for protocol in ["http", "https"] {
        let benchmark = Benchmark::set_up(protocol).await?;
        let mut e2e = [0; 3];
        let mut internal = [0; 3];
        let mut report = Vec::new();
        for phase in 0..4 {
            let (first, count) = if phase == 0 {
                (0, WARMUP)
            } else {
                (WARMUP + (phase - 1) * SAMPLES, SAMPLES)
            };
            let (end_to_end_ns, internal_ns) = benchmark
                .measure(first, count)
                .await
                .map_err(|error| format!("{protocol} phase {phase} incomplete: {error}"))?;
            let row = serde_json::json!({"phase":if phase == 0 {"warmup".to_owned()} else {format!("measured_{phase}")},
                "requests":count,"e2e_p99_ms":end_to_end_ns as f64 / 1e6,"internal_p99_ms":internal_ns as f64 / 1e6});
            println!("{protocol} {row}");
            report.push(row);
            if phase != 0 {
                e2e[phase - 1] = end_to_end_ns;
                internal[phase - 1] = internal_ns;
            }
        }
        // Export exact fixture responses only after this protocol's measurements;
        // fixture-output filesystem I/O is outside every measured transaction.
        for sequence in 0..WARMUP + 3 * SAMPLES {
            let path = benchmark.path(sequence);
            let tag = benchmark.proof.hash_one(path.as_str());
            writeln!(
                proofs,
                "{}",
                serde_json::json!({
                "uri":format!("{protocol}://{}{path}", benchmark.origin),
                "body_hex":format!("{tag:016x}")})
            )?;
        }
        proofs.flush()?;
        let e2e = median_of_three(e2e);
        let internal = *internal.iter().max().expect("three measured internal p99s");
        println!(
            "M4_LOAD_RESULT {}",
            serde_json::json!({"protocol":protocol,"concurrency":CONCURRENCY,
            "phases":report,"e2e_median_measured_p99_ms":e2e as f64 / 1e6,
            "internal_max_measured_p99_ms":internal as f64 / 1e6,
            "e2e_gate_ms":50,"internal_gate_ms":15,"passed":e2e < 50_000_000 && internal < 15_000_000})
        );
        if e2e >= 50_000_000 || internal >= 15_000_000 {
            failures.push(format!(
                "{protocol}: median measured E2E p99 {} ms, maximum measured internal p99 {} ms",
                e2e as f64 / 1e6,
                internal as f64 / 1e6
            ));
        }
    }
    assert!(
        failures.is_empty(),
        "latency gates failed: {}",
        failures.join("; ")
    );
    Ok(())
}
