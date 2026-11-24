//! End-to-end HTTP acceptance benchmark using a provisioned loopback proxy.
//! Set M4_LOAD_PROXY_ADDR to its literal loopback IP:port and M4_LOAD_ENGAGEMENT_ID
//! to a locked local test engagement. Allow GET /m4-load on 127.0.0.1 and provide
//! enough rate budget for 1,064 proxied requests. Set M4_LOAD_ORIGIN_PORT when
//! the policy needs a fixed port (default: an ephemeral port).
//! Run `cargo test --release --test load -- --ignored --nocapture`.
//!
//! Four closed-loop workers alternate the order of direct/proxied transactions.
//! Each measurement includes consumption of the entire body. After 64 warm-up
//! pairs, compute the nearest-rank p99 of 1,000 signed, paired latency deltas.

use std::{
    collections::hash_map::RandomState,
    convert::Infallible,
    env,
    error::Error,
    hash::BuildHasher,
    io,
    net::{Ipv4Addr, SocketAddr},
    time::{Duration, Instant},
};

use bytes::Bytes;
use futures_util::{StreamExt, TryStreamExt, stream};
use http_body_util::Full;
use hyper::{
    Request, Response, StatusCode, body::Incoming, server::conn::http1, service::service_fn,
};
use hyper_util::rt::TokioIo;
use reqwest::{Client, Proxy, redirect::Policy};
use tokio::net::TcpListener;
use uuid::Uuid;

type Failure = Box<dyn Error + Send + Sync>;
const ATTRIBUTION: &str = "X-Security-Assessment-ID";
const WARMUP: usize = 64;
const SAMPLES: usize = 1_000;
const CONCURRENCY: usize = 4;

struct Route {
    client: Client,
    peer: SocketAddr,
}

struct Benchmark {
    origin: SocketAddr,
    direct: Route,
    proxied: Route,
    engagement: String,
    proof: RandomState,
}

impl Benchmark {
    async fn set_up() -> Result<Self, Failure> {
        let proxy: SocketAddr = env::var("M4_LOAD_PROXY_ADDR")?.parse()?;
        if !proxy.ip().is_loopback() || proxy.port() == 0 {
            return Err("M4_LOAD_PROXY_ADDR must be a loopback socket with a nonzero port".into());
        }
        let engagement = Uuid::parse_str(&env::var("M4_LOAD_ENGAGEMENT_ID")?)?.to_string();
        let port: u16 = match env::var("M4_LOAD_ORIGIN_PORT") {
            Ok(s) => s.parse()?,
            Err(env::VarError::NotPresent) => 0,
            Err(e) => return Err(e.into()),
        };
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, port)).await?;
        let origin = listener.local_addr()?;
        if origin == proxy {
            return Err("origin and proxy must have distinct sockets".into());
        }
        let proof = RandomState::new();
        let server_key = proof.clone();
        let expected_id = engagement.clone();
        tokio::spawn(async move {
            while let Ok((socket, _)) = listener.accept().await {
                let key = server_key.clone();
                let id = expected_id.clone();
                tokio::spawn(async move {
                    socket.set_nodelay(true)?;
                    let service = service_fn(|req: Request<Incoming>| {
                        let mut response = Response::new(Full::new(Bytes::new()));
                        if req.uri().path() == "/m4-load"
                            && req.headers().get(ATTRIBUTION).map(|v| v.as_bytes())
                                == Some(id.as_bytes())
                        {
                            let tag = key.hash_one(req.uri().query()).to_be_bytes();
                            *response.body_mut() = Full::new(Bytes::copy_from_slice(&tag));
                        } else {
                            *response.status_mut() = StatusCode::BAD_REQUEST;
                        }
                        async move { Ok::<_, Infallible>(response) }
                    });
                    http1::Builder::new()
                        .serve_connection(TokioIo::new(socket), service)
                        .await?;
                    Ok::<_, Failure>(())
                });
            }
        });
        let builder = || {
            Client::builder()
                .no_proxy()
                .redirect(Policy::none())
                .timeout(Duration::from_secs(3))
        };
        Ok(Self {
            origin,
            direct: Route {
                client: builder().build()?,
                peer: origin,
            },
            proxied: Route {
                client: builder()
                    .proxy(Proxy::http(format!("http://{proxy}"))?)
                    .build()?,
                peer: proxy,
            },
            engagement,
            proof,
        })
    }

    async fn duration_ns(&self, route: &Route, sequence: usize) -> Result<i128, Failure> {
        let query = format!("sample={sequence}");
        let url = format!("http://{}/m4-load?{query}", self.origin);
        let expected = self.proof.hash_one(Some(query.as_str())).to_be_bytes();
        let request = route.client.get(url).header(ATTRIBUTION, &self.engagement);
        let start = Instant::now();
        let mut response = request.send().await?;
        if response.remote_addr() != Some(route.peer) {
            return Err(format!("unexpected TCP peer for sample {sequence}").into());
        }
        if !response.status().is_success() {
            let status = response.status();
            return Err(io::Error::other(format!(
                "sample {sequence} via {} returned {status}",
                route.peer
            ))
            .into());
        }
        let mut received = 0;
        while let Some(chunk) = response.chunk().await? {
            if !expected[received..].starts_with(&chunk) {
                return Err("response did not match the loopback origin proof".into());
            }
            received += chunk.len();
        }
        let elapsed = start.elapsed().as_nanos() as i128;
        if received != expected.len() {
            return Err("incomplete loopback origin response".into());
        }
        Ok(elapsed)
    }

    async fn pair(&self, index: usize) -> Result<i128, Failure> {
        let direct = self.duration_ns(&self.direct, index * 2);
        let proxied = self.duration_ns(&self.proxied, index * 2 + 1);
        let (direct, proxied) = if index.is_multiple_of(2) {
            (direct.await?, proxied.await?)
        } else {
            let proxied = proxied.await?;
            (direct.await?, proxied)
        };
        Ok(proxied - direct)
    }

    async fn pairs(&self, first: usize, count: usize) -> Result<Vec<i128>, Failure> {
        stream::iter(first..first + count)
            .map(|index| self.pair(index))
            .buffer_unordered(CONCURRENCY)
            .try_collect()
            .await
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires a provisioned, running M4 proxy on loopback"]
async fn proxied_http_overhead_p99_under_15ms() -> Result<(), Failure> {
    let benchmark = Benchmark::set_up().await?;
    benchmark.pairs(0, WARMUP).await?;
    let mut deltas = benchmark.pairs(WARMUP, SAMPLES).await?;
    deltas.sort_unstable();
    let rank = (99 * deltas.len()).div_ceil(100);
    let p99_ns = deltas[rank - 1];
    let p99_ms = p99_ns as f64 / 1_000_000.0;
    println!(
        "p99 paired HTTP overhead {p99_ms:.6} ms ({SAMPLES} pairs, concurrency {CONCURRENCY})"
    );
    assert!(p99_ns < 15_000_000, "p99 overhead reached {p99_ms:.6} ms");
    Ok(())
}
