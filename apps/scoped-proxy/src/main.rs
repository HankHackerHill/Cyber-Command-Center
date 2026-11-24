pub mod breaker;
pub mod evidence_client;
pub mod policy_client;
pub mod tls;

use std::{convert::Infallible, env, error::Error, io, net::SocketAddr, sync::Arc, time::Duration};

use breaker::Breaker;
use bytes::Bytes;
use http_body_util::Full;
use hyper::{
    Method, Request, Response, StatusCode, body::Incoming, header, server::conn::http1,
    service::service_fn,
};
use hyper_util::rt::{TokioIo, TokioTimer};
use policy_client::{PolicyClient, StateError};
use serde::Serialize;
use tokio::{net::TcpListener, sync::Semaphore};
use uuid::Uuid;

type Reply = Response<Full<Bytes>>;

fn deny(status: StatusCode, reason: impl Serialize) -> Reply {
    #[derive(Serialize)]
    struct Rejection<T> {
        reason: T,
    }
    let body = serde_json::to_vec(&Rejection { reason }).expect("fixed reason serializes to JSON");
    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::CACHE_CONTROL, "no-store")
        .header(header::CONNECTION, "close")
        .body(Full::new(Bytes::from(body)))
        .expect("static response headers")
}

fn stop_response(breaker: &Breaker) -> Reply {
    if breaker.ready() {
        deny(StatusCode::PRECONDITION_FAILED, "PRECONDITION_FAILED")
    } else {
        deny(StatusCode::SERVICE_UNAVAILABLE, "KILLSWITCH_UNAVAILABLE")
    }
}

async fn handle(req: Request<Incoming>, policy: &PolicyClient, breaker: &Breaker) -> Reply {
    if !breaker.ready() {
        return stop_response(breaker);
    }
    let mut ids = req.headers().get_all("X-Security-Assessment-ID").iter();
    let id = ids
        .next()
        .and_then(|v| v.to_str().ok())
        .and_then(|v| Uuid::parse_str(v).ok());
    let Some(id) = id.filter(|_| ids.next().is_none()) else {
        return deny(StatusCode::BAD_REQUEST, "INVALID_ASSESSMENT_ID");
    };
    let state = tokio::select! {
        biased;
        () = breaker.wait_blocked(id) => return stop_response(breaker),
        result = policy.check_state(id) => result,
    };
    if breaker.blocked(id) {
        return stop_response(breaker);
    }
    match state {
        Err(StateError::PreconditionFailed) => {
            deny(StatusCode::PRECONDITION_FAILED, "PRECONDITION_FAILED")
        }
        Err(StateError::Unavailable) => deny(StatusCode::SERVICE_UNAVAILABLE, "STATE_UNAVAILABLE"),
        // Opaque tunnels cannot enforce the per-request attribution and
        // evidence requirements of invariant 4.
        Ok(()) if req.method() == Method::CONNECT => deny(
            StatusCode::FORBIDDEN,
            tls::RejectionReason::OpaqueTunnelNotAllowed,
        ),
        // /evaluate mutates M3 accounting on allow. M3 on this branch has no
        // service endpoint for releasing that reservation. Fail before reserve.
        Ok(()) => deny(
            StatusCode::SERVICE_UNAVAILABLE,
            "POLICY_COMPLETION_UNAVAILABLE",
        ),
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let policy = PolicyClient::new(&env::var("ORCHESTRATOR_URL")?, &env::var("POLICY_URL")?)?;
    let redis = redis::Client::open(env::var("REDIS_URL")?)?;
    let listen: SocketAddr = env::var("SCOPED_PROXY_LISTEN")
        .unwrap_or_else(|_| "127.0.0.1:8080".into())
        .parse()?;
    let listener = TcpListener::bind(listen).await?;
    let breaker = Breaker::default();
    let subscriber = breaker.clone();
    tokio::spawn(async move {
        if subscriber.listen(redis).await.is_err() {
            eprintln!("Killswitch subscription unavailable. Ingress will receive a denial.");
        }
    });
    println!("Listening on {}", listener.local_addr()?);
    let connections = Arc::new(Semaphore::new(256));
    loop {
        let permit = connections.clone().acquire_owned().await?;
        let (stream, _) = match listener.accept().await {
            Ok(connection) => connection,
            Err(err) if err.kind() == io::ErrorKind::Interrupted => continue,
            Err(err) => return Err(err.into()),
        };
        let policy = policy.clone();
        let breaker = breaker.clone();
        tokio::spawn(async move {
            let _permit = permit;
            let service = service_fn(|req| async {
                Ok::<_, Infallible>(handle(req, &policy, &breaker).await)
            });
            let _ = http1::Builder::new()
                .timer(TokioTimer::new())
                .header_read_timeout(Duration::from_secs(5))
                .serve_connection(TokioIo::new(stream), service)
                .await;
        });
    }
}
