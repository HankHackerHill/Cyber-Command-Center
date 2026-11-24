pub mod breaker;
pub mod evidence_client;
pub mod inspection;
pub mod policy_client;
pub mod tls;
pub mod transport;

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

async fn handle(
    mut req: Request<Incoming>,
    policy: &PolicyClient,
    breaker: &Breaker,
    transport: &transport::Transport,
) -> Reply {
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
    let timing = transport::Timing::start();
    let phase_started = tokio::time::Instant::now();
    let state = tokio::select! {
        biased;
        () = breaker.wait_blocked(id) => return stop_response(breaker),
        result = policy.check_state(id) => result,
    };
    transport::Timing::record(&timing, "state", phase_started);
    if breaker.blocked(id) {
        return stop_response(breaker);
    }
    match state {
        Err(StateError::PreconditionFailed) => {
            deny(StatusCode::PRECONDITION_FAILED, "PRECONDITION_FAILED")
        }
        Err(StateError::Unavailable) => deny(StatusCode::SERVICE_UNAVAILABLE, "STATE_UNAVAILABLE"),
        Ok(()) if req.method() == Method::CONNECT => {
            let inspection = transport
                .workspace_root()
                .filter(|_| transport.provisioned(id))
                .and_then(|root| {
                    let target = transport::target(req.uri().authority()?.as_str(), 443).ok()?;
                    // CONNECT requires explicit authority form, including a port.
                    if req.uri().scheme().is_some()
                        || req.uri().path_and_query().is_some()
                        || req.uri().authority()?.port_u16().is_none()
                    {
                        return None;
                    }
                    let mut hosts = req.headers().get_all(header::HOST).iter();
                    let host = transport::target(hosts.next()?.to_str().ok()?, 443).ok()?;
                    if hosts.next().is_some()
                        || host.host != target.host
                        || host.port != target.port
                    {
                        return None;
                    }
                    let ca = inspection::WorkspaceCa::load(root, id).ok()?;
                    Some((target.clone(), ca.server_config(&target.host).ok()?))
                });
            if let Some((target, config)) = inspection {
                let Some(session_permit) = transport.try_tls_permit() else {
                    return deny(
                        StatusCode::SERVICE_UNAVAILABLE,
                        "INSPECTION_CAPACITY_UNAVAILABLE",
                    );
                };
                let upgrade = hyper::upgrade::on(&mut req);
                let transport = transport.clone();
                let breaker = breaker.clone();
                let policy = policy.clone();
                tokio::spawn(async move {
                    let _session_permit = session_permit;
                    let upgraded = tokio::select! {
                        biased;
                        () = breaker.wait_blocked(id) => return,
                        result = tokio::time::timeout(Duration::from_secs(5), upgrade) => match result { Ok(Ok(upgraded)) => upgraded, _ => return },
                    };
                    let ingress = tokio::select! {
                        biased;
                        () = breaker.wait_blocked(id) => return,
                        result = tls::classify_ingress(TokioIo::new(upgraded), id, Uuid::new_v4(), Duration::from_millis(250), transport.evidence().expect("configured evidence"), &policy) => result,
                    };
                    if let tls::Ingress::Candidate { prefix, client } = ingress {
                        tokio::select! {
                            biased;
                            () = breaker.wait_blocked(id) => (),
                            _ = inspection::serve(client, prefix, config, id, target, transport) => (),
                        }
                    }
                });
                return Response::builder()
                    .status(StatusCode::OK)
                    .body(Full::new(Bytes::new()))
                    .expect("CONNECT response");
            }
            let reason = tls::RejectionReason::OpaqueTunnelNotAllowed;
            let event_id = Uuid::new_v4();
            let payload =
                serde_json::json!({"reason":reason, "phase":"before_200", "prefix_hex":""});
            let policy = policy.clone();
            let append = tokio::spawn(async move {
                if let Err(error) = policy
                    .audit_event(id, event_id, "TUNNEL_REJECTED", payload)
                    .await
                {
                    eprintln!("Tunnel rejection {event_id} audit append unconfirmed: {error:?}");
                }
            });
            tokio::select! {
                biased;
                () = breaker.wait_blocked(id) => stop_response(breaker),
                _ = append => deny(StatusCode::FORBIDDEN, reason),
            }
        }
        Ok(()) => transport.forward_traced(req, id, None, timing).await,
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let policy = PolicyClient::new(&env::var("ORCHESTRATOR_URL")?, &env::var("POLICY_URL")?)?
        .with_audit_token(&env::var("M4_AUDIT_TOKEN")?)?;
    let redis = redis::Client::open(env::var("REDIS_URL")?)?;
    let listen: SocketAddr = env::var("SCOPED_PROXY_LISTEN")
        .unwrap_or_else(|_| "127.0.0.1:8080".into())
        .parse()?;
    let listener = TcpListener::bind(listen).await?;
    let breaker = Breaker::default();
    let transport =
        transport::Transport::from_environment(policy.clone(), breaker.clone(), redis.clone())?;
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
        stream.set_nodelay(true)?;
        let policy = policy.clone();
        let breaker = breaker.clone();
        let transport = transport.clone();
        tokio::spawn(async move {
            let _permit = permit;
            let service = service_fn(|req| async {
                Ok::<_, Infallible>(handle(req, &policy, &breaker, &transport).await)
            });
            let _ = http1::Builder::new()
                .timer(TokioTimer::new())
                .header_read_timeout(Duration::from_secs(5))
                .serve_connection(TokioIo::new(stream), service)
                .with_upgrades()
                .await;
        });
    }
}
