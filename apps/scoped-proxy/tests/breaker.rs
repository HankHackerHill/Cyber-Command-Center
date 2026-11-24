#[path = "../src/breaker.rs"]
mod breaker;
#[path = "support/redis.rs"]
mod mock_redis;
#[path = "../src/policy_client.rs"]
pub mod policy_client;

use std::num::NonZeroU64;
use std::time::{Duration, Instant};

use breaker::{AccountingError, Breaker, complete_reservation};
use mock_redis::{MockRedis, Subscription};
use policy_client::PolicyClient;
use serde_json::json;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;
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
async fn redis_eval(conn: &mut BufReader<TcpStream>) -> Vec<String> {
    loop {
        let mut line = String::new();
        conn.read_line(&mut line).await.unwrap();
        let count = line
            .trim_end()
            .strip_prefix('*')
            .unwrap()
            .parse::<usize>()
            .unwrap();
        let mut args = Vec::with_capacity(count);
        for _ in 0..count {
            line.clear();
            conn.read_line(&mut line).await.unwrap();
            let len = line
                .trim_end()
                .strip_prefix('$')
                .unwrap()
                .parse::<usize>()
                .unwrap();
            let mut bytes = vec![0; len + 2];
            conn.read_exact(&mut bytes).await.unwrap();
            assert_eq!(&bytes[len..], b"\r\n");
            bytes.truncate(len);
            args.push(String::from_utf8(bytes).unwrap());
        }
        if args[0] == "CLIENT" {
            assert_eq!(args[1], "SETINFO");
            conn.get_mut().write_all(b"+OK\r\n").await.unwrap();
        } else {
            assert_eq!(args[0], "EVAL");
            return args;
        }
    }
}

async fn reply_snapshot(conn: &mut BufReader<TcpStream>, id: Uuid, raw: &str, receipts: usize) {
    let args = redis_eval(conn).await;
    assert_eq!(&args[2..], &["1", &format!("redops:policy:v1:{id}")]);
    assert!(args[1].contains("HGET") && args[1].contains("HLEN"));
    let reply = format!("*2\r\n${}\r\n{raw}\r\n:{receipts}\r\n", raw.len());
    conn.get_mut().write_all(reply.as_bytes()).await.unwrap();
}

#[tokio::test]
async fn redis_settlement_consumes_a_receipt_before_counting_the_status() {
    let (m2, policy) = MockM2::start().await;
    let redis_pubsub = MockRedis::start().await;
    let breaker = Breaker::default();
    let (mut subscription, listener_task) = subscribe(&redis_pubsub, &breaker).await;
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let account =
        redis::Client::open(format!("redis://{}/", listener.local_addr().unwrap())).unwrap();
    let id = Uuid::from_u128(21);
    let first = Uuid::from_u128(22);
    let second = Uuid::from_u128(23);
    let threshold = NonZeroU64::new(2).unwrap();
    let mut stored = json!({"credit":120021,"at_us":1750000000000017_i64,"rate":2,"active_workers":2,"errors_5xx":7});
    for (receipt, duplicate) in [(first, false), (first, true), (second, false)] {
        let handle_cas = async {
            let mut conn = BufReader::new(listener.accept().await.unwrap().0);
            let workers = stored["active_workers"].as_u64().unwrap();
            // Deliberately retain spaces. CAS must compare M3's exact original bytes.
            let raw = serde_json::to_string_pretty(&stored).unwrap();
            reply_snapshot(&mut conn, id, &raw, workers as usize).await;
            let cas = redis_eval(&mut conn).await;
            assert!(cas[1].contains("HSET") && cas[1].contains("HDEL"));
            assert_eq!(&cas[2..5], &["1", &format!("redops:policy:v1:{id}"), &raw]);
            assert_eq!(cas[6], receipt.to_string());
            if duplicate {
                conn.get_mut().write_all(b"+missing\r\n").await.unwrap();
            } else {
                stored["active_workers"] = json!(workers - 1);
                stored["errors_5xx"] = json!(stored["errors_5xx"].as_u64().unwrap() + 1);
                assert_eq!(
                    serde_json::from_str::<serde_json::Value>(&cas[5]).unwrap(),
                    stored
                );
                conn.get_mut().write_all(b"+ok\r\n").await.unwrap();
            }
        };
        let (settled, ()) = tokio::join!(
            breaker.settle(&account, &policy, id, receipt, 503, threshold),
            handle_cas,
        );
        assert_eq!(
            settled,
            if duplicate {
                Err(AccountingError::MissingReceipt)
            } else {
                Ok(())
            }
        );
        assert_eq!(breaker.blocked(id), receipt == second);
    }
    let halt = m2.accept_stop(id, &breaker).await;
    finish_stop(halt, id, Some(&mut subscription)).await;
    assert_eq!(stored["active_workers"], 0);
    assert_eq!(stored["errors_5xx"], 9);
    listener_task.abort();
}

#[tokio::test]
async fn malformed_accounting_and_invalid_status_never_consume_receipts() {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let client =
        redis::Client::open(format!("redis://{}/", listener.local_addr().unwrap())).unwrap();
    let id = Uuid::from_u128(17);
    let receipt = Uuid::from_u128(19);
    for status in [0, 199, 600] {
        assert_eq!(
            complete_reservation(&client, id, receipt, status).await,
            Err(AccountingError::InvalidStatus)
        );
    }
    let max_counter = format!(
        r#"{{"credit":0,"at_us":1,"rate":1,"active_workers":1,"errors_5xx":{}}}"#,
        "9".repeat(4300)
    );
    for raw in [
        max_counter.as_str(),
        r#"{"credit":0,"at_us":1,"rate":1,"active_workers":2,"errors_5xx":0}"#,
        r#"{"credit":1000001,"at_us":0,"rate":1,"active_workers":1,"errors_5xx":0}"#,
        r#"{"credit":0,"at_us":1,"rate":0,"active_workers":1,"errors_5xx":0}"#,
        r#"{"credit":0,"at_us":1,"rate":1,"active_workers":1,"errors_5xx":0,"x":0}"#,
        r#"{"credit":0,"at_us":1,"rate":1,"active_workers":1,"errors_5xx":0,"errors_5xx":0}"#,
    ] {
        let (result, ()) = tokio::join!(complete_reservation(&client, id, receipt, 503), async {
            let mut conn = BufReader::new(listener.accept().await.unwrap().0);
            reply_snapshot(&mut conn, id, raw, 1).await;
            let mut line = String::new();
            assert_eq!(
                conn.read_line(&mut line).await.unwrap(),
                0,
                "invalid snapshot generated a CAS"
            );
        });
        assert_eq!(result, Err(AccountingError::InvalidState));
    }
}

#[tokio::test]
async fn competing_redis_write_reloads_exact_snapshot_and_preserves_large_integers() {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let client =
        redis::Client::open(format!("redis://{}/", listener.local_addr().unwrap())).unwrap();
    let id = Uuid::from_u128(13);
    let receipt = Uuid::from_u128(15);
    let (result, ()) = tokio::join!(complete_reservation(&client, id, receipt, 599), async {
        let mut conn = BufReader::new(listener.accept().await.unwrap().0);
        let large = "9".repeat(80);
        let incremented = format!("1{}", "0".repeat(80));
        for (attempt, at_us) in ["14", "15"].iter().enumerate() {
            let raw = format!(
                r#"{{"credit":{large},"at_us":{at_us},"rate":{large},"active_workers":1,"errors_5xx":{large}}}"#
            );
            reply_snapshot(&mut conn, id, &raw, 1).await;
            let cas = redis_eval(&mut conn).await;
            assert_eq!(cas[4], raw);
            let updated = format!(
                r#"{{"credit":{large},"at_us":{at_us},"rate":{large},"active_workers":0,"errors_5xx":{incremented}}}"#
            );
            assert_eq!(cas[5], updated);
            assert_eq!(cas[6], receipt.to_string());
            conn.get_mut()
                .write_all(if attempt == 0 {
                    b"+retry\r\n"
                } else {
                    b"+ok\r\n"
                })
                .await
                .unwrap();
        }
    });
    assert_eq!(result, Ok(()));
}
