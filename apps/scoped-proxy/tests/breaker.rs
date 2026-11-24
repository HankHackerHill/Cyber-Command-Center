#[path = "../src/breaker.rs"]
mod breaker;
#[path = "support/redis.rs"]
mod mock_redis;
#[path = "../src/policy_client.rs"]
pub mod policy_client;

use std::num::NonZeroU64;
use std::time::{Duration, Instant};

use breaker::Breaker;
use mock_redis::{MockRedis, Subscription};
use policy_client::{CompletionError, CompletionOutcome, PolicyClient};
use serde_json::json;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::{AbortHandle, JoinHandle};
use tokio::time::timeout;
use uuid::Uuid;

const SETUP_TIMEOUT: Duration = Duration::from_secs(3);
const STOP_DEADLINE: Duration = Duration::from_millis(100);

async fn subscribe(
    redis: &MockRedis,
    breaker: &Breaker,
) -> (Subscription, JoinHandle<Result<(), String>>) {
    let client = redis::Client::open(format!("redis://{}/", redis.address())).unwrap();
    let task_breaker = breaker.clone();
    let task = tokio::spawn(async move { task_breaker.listen(client).await });
    let subscription = redis.accept_subscription().await;
    timeout(SETUP_TIMEOUT, async {
        while !breaker.ready() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("subscription acknowledgement did not enable admission");
    (subscription, task)
}

#[tokio::test]
async fn killswitch_latches_within_100ms_and_subscription_loss_denies_all() {
    let redis = MockRedis::start().await;
    let breaker = Breaker::default();
    let first = Uuid::from_u128(1);
    let second = Uuid::from_u128(2);
    let third = Uuid::from_u128(3);
    assert!(breaker.blocked(first));
    let (mut subscriber, task) = subscribe(&redis, &breaker).await;
    let start = Instant::now();
    subscriber.send_halt(first).await;
    timeout(STOP_DEADLINE, breaker.wait_blocked(first))
        .await
        .unwrap();
    let elapsed = start.elapsed();
    println!("Mock Redis stop delivery to local admission denial took {elapsed:?}");
    assert!(elapsed < STOP_DEADLINE, "Redis stop took {elapsed:?}");
    assert!(breaker.blocked(first));
    assert!(!breaker.blocked(second));

    // The second engagement's stop proves the duplicate ahead of it was consumed.
    subscriber.send_halt(first).await;
    subscriber.send_halt(second).await;
    timeout(SETUP_TIMEOUT, breaker.wait_blocked(second))
        .await
        .unwrap();
    assert!(breaker.blocked(first));
    assert!(!breaker.blocked(third));

    drop(subscriber);
    timeout(SETUP_TIMEOUT, breaker.wait_blocked(third))
        .await
        .unwrap();
    assert!(
        timeout(SETUP_TIMEOUT, task)
            .await
            .unwrap()
            .unwrap()
            .is_err()
    );
}

struct MockM2(TcpListener);

impl MockM2 {
    async fn start() -> (Self, PolicyClient) {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let origin = format!("http://{}", listener.local_addr().unwrap());
        let client = PolicyClient::new(&origin, &origin).unwrap();
        (Self(listener), client)
    }

    async fn accept_stop(&self, id: Uuid, breaker: &Breaker) -> TcpStream {
        timeout(SETUP_TIMEOUT, async {
            let (socket, _) = self.0.accept().await.unwrap();
            assert!(
                breaker.blocked(id),
                "local latch must precede the M2 connection"
            );
            let mut conn = BufReader::new(socket);
            let mut line = String::new();
            conn.read_line(&mut line).await.unwrap();
            assert_eq!(
                line,
                format!("POST /engagements/{id}/killswitch HTTP/1.1\r\n")
            );
            loop {
                line.clear();
                assert!(conn.read_line(&mut line).await.unwrap() > 0);
                if line == "\r\n" {
                    break;
                }
            }
            conn.into_inner()
        })
        .await
        .expect("missing M2 stop request")
    }
}

// M2 publishes the notice after committing the stop, then reports whether
// publication succeeded. A false acknowledgement leaves delivery pending.
async fn finish_stop(mut socket: TcpStream, id: Uuid, subscriber: Option<&mut Subscription>) {
    let published = subscriber.is_some();
    if let Some(subscriber) = subscriber {
        subscriber.send_halt(id).await;
    }
    let body = json!({
        "status": "halted", "next_state": "HALTED_KILLSWITCH",
        "ledger_hash": null, "notification_published": published
    })
    .to_string();
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    socket.write_all(response.as_bytes()).await.unwrap();
}

#[tokio::test]
async fn consecutive_5xx_trips_local_breaker_before_m2_delivers_redis_stop() {
    let (m2, client) = MockM2::start().await;
    let redis = MockRedis::start().await;
    let breaker = Breaker::default();
    let replica = Breaker::default();
    let (_subscription, local_task) = subscribe(&redis, &breaker).await;
    let (mut replica_subscription, replica_task) = subscribe(&redis, &replica).await;
    let id = Uuid::from_u128(1);
    let other = Uuid::from_u128(2);
    let threshold = NonZeroU64::new(2).unwrap();
    for (engagement, status) in [(id, 500), (id, 200), (id, 500), (other, 500), (other, 200)] {
        breaker
            .record_final_status(engagement, status, threshold, &client)
            .await
            .unwrap();
        assert!(!breaker.blocked(id));
        assert!(!breaker.blocked(other));
    }

    let (outcome, ()) = tokio::join!(
        breaker.record_final_status(id, 503, threshold, &client),
        async {
            let socket = m2.accept_stop(id, &breaker).await;
            finish_stop(socket, id, Some(&mut replica_subscription)).await;
        }
    );
    outcome.unwrap();
    timeout(SETUP_TIMEOUT, replica.wait_blocked(id))
        .await
        .unwrap();
    assert!(breaker.blocked(id));
    assert!(replica.blocked(id));
    assert!(!breaker.blocked(other));
    assert!(!replica.blocked(other));
    local_task.abort();
    replica_task.abort();
}

async fn check_automatic_retry(cancel_caller: bool) {
    let (m2, client) = MockM2::start().await;
    let redis = MockRedis::start().await;
    let breaker = Breaker::default();
    let replica = Breaker::default();
    let (_subscriber, task) = subscribe(&redis, &breaker).await;
    let (mut subscriber, replica_task) = subscribe(&redis, &replica).await;
    let id = Uuid::from_u128(1);
    let threshold = NonZeroU64::new(1).unwrap();

    let caller_breaker = breaker.clone();
    let caller_policy = client.clone();
    let caller = tokio::spawn(async move {
        caller_breaker
            .record_final_status(id, 502, threshold, &caller_policy)
            .await
    });
    let first = m2.accept_stop(id, &breaker).await;
    if cancel_caller {
        caller.abort();
        assert!(caller.await.unwrap_err().is_cancelled());
        finish_stop(first, id, None).await;
    } else {
        finish_stop(first, id, None).await;
        assert!(
            timeout(SETUP_TIMEOUT, caller)
                .await
                .unwrap()
                .unwrap()
                .is_err()
        );
    }
    assert!(breaker.blocked(id));
    assert!(!replica.blocked(id));

    // No second response observation or manual retry triggers this POST.
    let second = m2.accept_stop(id, &breaker).await;
    finish_stop(second, id, Some(&mut subscriber)).await;
    timeout(SETUP_TIMEOUT, replica.wait_blocked(id))
        .await
        .unwrap();
    assert!(replica.blocked(id));
    breaker
        .record_final_status(id, 503, threshold, &client)
        .await
        .unwrap();
    assert!(breaker.blocked(id));
    // Successful acknowledgement stops the retry loop, including after a duplicate 5xx.
    assert!(
        timeout(Duration::from_millis(200), m2.0.accept())
            .await
            .is_err()
    );
    task.abort();
    replica_task.abort();
}

#[tokio::test]
async fn unpublished_m2_stop_is_retried_automatically() {
    check_automatic_retry(false).await;
}

#[tokio::test]
async fn unpublished_m2_stop_is_retried_after_the_caller_is_cancelled() {
    check_automatic_retry(true).await;
}

// This mock implements the proposed M3 completion response only.
async fn acknowledge_settlement(
    m3: &TcpListener,
    id: Uuid,
    receipt: Uuid,
    reply: &'static str,
    abort_before_reply: Option<&AbortHandle>,
) {
    use bytes::Bytes;
    use http_body_util::{BodyExt, Full};
    use hyper::{
        Method, Request, Response, body::Incoming, server::conn::http1, service::service_fn,
    };
    use hyper_util::rt::TokioIo;
    use std::convert::Infallible;

    timeout(SETUP_TIMEOUT, async {
        let (socket, _) = m3.accept().await.unwrap();
        let service = service_fn(|request: Request<Incoming>| async move {
            assert_eq!(request.method(), Method::POST);
            assert_eq!(
                request.uri().path(),
                format!("/engagements/{id}/completions")
            );
            assert_eq!(
                request.headers()["x-policy-reservation"],
                receipt.to_string()
            );
            let bytes = request.into_body().collect().await.unwrap().to_bytes();
            assert_eq!(
                serde_json::from_slice::<serde_json::Value>(&bytes).unwrap(),
                json!({"status_code":503})
            );
            if let Some(caller) = abort_before_reply {
                caller.abort();
                while !caller.is_finished() {
                    tokio::task::yield_now().await;
                }
            }
            Ok::<_, Infallible>(Response::new(Full::new(Bytes::from_static(
                reply.as_bytes(),
            ))))
        });
        http1::Builder::new()
            .keep_alive(false)
            .serve_connection(TokioIo::new(socket), service)
            .await
            .unwrap();
    })
    .await
    .expect("M3 did not receive completion");
}

#[tokio::test]
async fn distributed_trip_latches_on_acknowledgement_and_replay_only_resettles_receipt() {
    let (m2, _) = MockM2::start().await;
    let m3 = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let client = PolicyClient::new(
        &format!("http://{}", m2.0.local_addr().unwrap()),
        &format!("http://{}", m3.local_addr().unwrap()),
    )
    .unwrap();
    let redis = MockRedis::start().await;
    let breaker = Breaker::default();
    let (mut subscription, task) = subscribe(&redis, &breaker).await;
    let id = Uuid::from_u128(1);
    let receipt = Uuid::from_u128(2);
    let outcome = CompletionOutcome::OriginStatus(503);
    let tripped = r#"{"breaker_tripped":true}"#;

    let (unconfirmed, ()) = tokio::join!(
        breaker.settle(&client, id, receipt, outcome),
        acknowledge_settlement(&m3, id, receipt, "{}", None)
    );
    assert_eq!(unconfirmed, Err(CompletionError::Unavailable));
    assert!(!breaker.blocked(id));

    let caller_breaker = breaker.clone();
    let caller_policy = client.clone();
    let caller = tokio::spawn(async move {
        caller_breaker
            .settle(&caller_policy, id, receipt, outcome)
            .await
    });
    let abort = caller.abort_handle();
    tokio::join!(
        acknowledge_settlement(&m3, id, receipt, tripped, Some(&abort)),
        async {
            let stop = m2.accept_stop(id, &breaker).await;
            finish_stop(stop, id, Some(&mut subscription)).await;
        }
    );
    assert!(caller.await.unwrap_err().is_cancelled());
    assert!(breaker.blocked(id));
    let (replay, ()) = tokio::join!(
        breaker.settle(&client, id, receipt, outcome),
        acknowledge_settlement(&m3, id, receipt, tripped, None)
    );
    assert_eq!(replay, Ok(true));
    assert!(
        timeout(Duration::from_millis(200), m2.0.accept())
            .await
            .is_err()
    );
    drop(m3);
    assert_eq!(
        breaker.settle(&client, id, receipt, outcome).await,
        Err(CompletionError::Unavailable)
    );
    task.abort();
}
