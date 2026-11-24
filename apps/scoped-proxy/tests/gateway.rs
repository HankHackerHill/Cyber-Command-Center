#[path = "support/audit.rs"]
mod mock_audit;
#[path = "support/redis.rs"]
mod mock_redis;

use std::{net::SocketAddr, process::Stdio, time::Duration};

use mock_redis::{MockRedis, Subscription};
use serde_json::{Value, json};
use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader},
    net::{TcpListener, TcpStream},
    process::{Child, Command},
    time::timeout,
};
use uuid::Uuid;

const ID: &str = "fb66cc64-81d2-4a0e-94db-324575c967c1";
const TEST_TOKEN: &str = "test-only-gateway-audit-token";
const SETUP: Duration = Duration::from_secs(4);

struct Gateway {
    _process: Child,
    proxy: SocketAddr,
    orchestrator: TcpListener,
    policy: TcpListener,
    target: TcpListener,
    redis: Subscription,
}

impl Gateway {
    async fn start() -> Self {
        let redis = MockRedis::start().await;
        let orchestrator = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let policy = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut process = Command::new(env!("CARGO_BIN_EXE_scoped-proxy"))
            .env("SCOPED_PROXY_LISTEN", "127.0.0.1:0")
            .env(
                "ORCHESTRATOR_URL",
                format!("http://{}", orchestrator.local_addr().unwrap()),
            )
            .env(
                "POLICY_URL",
                format!("http://{}", policy.local_addr().unwrap()),
            )
            .env("REDIS_URL", format!("redis://{}", redis.address()))
            .env("M4_AUDIT_TOKEN", TEST_TOKEN)
            .env("TOKIO_WORKER_THREADS", "2")
            .stdout(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .unwrap();
        let mut lines = BufReader::new(process.stdout.take().unwrap()).lines();
        let line = timeout(SETUP, lines.next_line())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        let proxy = line.strip_prefix("Listening on ").unwrap().parse().unwrap();
        let subscription = redis.accept_subscription().await;
        let gateway = Self {
            _process: process,
            proxy,
            orchestrator,
            policy,
            target,
            redis: subscription,
        };
        // A missing ID distinguishes an acknowledged subscription from setup.
        timeout(SETUP, async {
            loop {
                let reply = read_reply(gateway.request(false, &[]).await).await;
                match reply.0 {
                    400 => break,
                    503 => tokio::task::yield_now().await,
                    status => panic!("unexpected readiness response {status}"),
                }
            }
        })
        .await
        .unwrap();
        gateway
    }

    async fn request(&self, connect: bool, ids: &[&str]) -> TcpStream {
        let target = self.target.local_addr().unwrap();
        let line = if connect {
            format!("CONNECT {target}")
        } else {
            format!("GET http://{target}/audit")
        };
        let mut wire = format!("{line} HTTP/1.1\r\nHost: {target}\r\n");
        for id in ids {
            wire.push_str(&format!("X-Security-Assessment-ID: {id}\r\n"));
        }
        wire.push_str("Connection: close\r\n\r\n");
        let mut stream = TcpStream::connect(self.proxy).await.unwrap();
        stream.write_all(wire.as_bytes()).await.unwrap();
        stream
    }

    async fn state_call(&self) -> TcpStream {
        let (stream, _) = self.orchestrator.accept().await.unwrap();
        let mut reader = BufReader::new(stream);
        let mut line = String::new();
        reader.read_line(&mut line).await.unwrap();
        assert_eq!(line, format!("GET /engagements/{ID}/state HTTP/1.1\r\n"));
        loop {
            line.clear();
            assert!(reader.read_line(&mut line).await.unwrap() > 0);
            if line == "\r\n" {
                break;
            }
        }
        reader.into_inner()
    }

    async fn assert_no_egress(&self) {
        for listener in [&self.target, &self.policy] {
            assert!(
                timeout(Duration::from_millis(20), listener.accept())
                    .await
                    .is_err()
            );
        }
    }
}

async fn read_reply(mut stream: TcpStream) -> (u16, Value) {
    let mut wire = String::new();
    stream.read_to_string(&mut wire).await.unwrap();
    let (headers, body) = wire.split_once("\r\n\r\n").unwrap();
    let code = headers
        .split_ascii_whitespace()
        .nth(1)
        .unwrap()
        .parse()
        .unwrap();
    (code, serde_json::from_str(body).unwrap())
}

#[tokio::test]
async fn enforces_state_at_the_listener_before_any_reservation_or_target_connection() {
    timeout(SETUP, async {
        let gateway = Gateway::start().await;
        for invalid_ids in [vec![], vec!["invalid"], vec![ID, ID]] {
            let reply = read_reply(gateway.request(false, &invalid_ids).await).await;
            assert_eq!(reply, (400, json!({"reason": "INVALID_ASSESSMENT_ID"})));
        }
        for (state, connect, code, reason) in [
            ("INIT_SCOPING", false, 412, "PRECONDITION_FAILED"),
            ("HALTED_KILLSWITCH", false, 412, "PRECONDITION_FAILED"),
            ("COMPLETED_ARCHIVED", true, 412, "PRECONDITION_FAILED"),
            ("CONTROLLED_VALIDATION", false, 503, "MANIFEST_UNAVAILABLE"),
            (
                "CONTROLLED_VALIDATION",
                true,
                403,
                "OPAQUE_TUNNEL_NOT_ALLOWED",
            ),
        ] {
            let caller = gateway.request(connect, &[ID]).await;
            let mut upstream = gateway.state_call().await;
            let body = json!({"state":state}).to_string();
            let response = format!(
                "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: {}\r\n\r\n{body}",
                body.len()
            );
            upstream.write_all(response.as_bytes()).await.unwrap();
            if code == 403 {
                let body = mock_audit::acknowledge_audit(
                    &gateway.orchestrator,
                    Uuid::parse_str(ID).unwrap(),
                    TEST_TOKEN,
                )
                .await;
                assert_eq!(body["event_type"], "TUNNEL_REJECTED");
                assert_eq!(
                    body["payload"],
                    json!({"reason":reason,"phase":"before_200","prefix_hex":""})
                );
            }
            assert_eq!(read_reply(caller).await, (code, json!({"reason":reason})));
        }
        gateway.assert_no_egress().await;
    })
    .await
    .expect("gateway denial test timed out");
}

#[tokio::test]
async fn redis_stop_preempts_an_in_flight_state_check() {
    timeout(SETUP, async {
        let mut gateway = Gateway::start().await;
        let caller = gateway.request(false, &[ID]).await;
        let _stalled_state_call = gateway.state_call().await;
        let stop_result = timeout(Duration::from_millis(100), async {
            gateway.redis.send_halt(Uuid::parse_str(ID).unwrap()).await;
            read_reply(caller).await
        })
        .await
        .expect("pending request did not close within 100 ms of the Redis stop");
        let denied = (412, json!({"reason":"PRECONDITION_FAILED"}));
        assert_eq!(stop_result, denied);
        let caller = gateway.request(false, &[ID]).await;
        assert_eq!(read_reply(caller).await, denied);
        assert!(
            timeout(Duration::from_millis(20), gateway.orchestrator.accept())
                .await
                .is_err()
        );
        gateway.assert_no_egress().await;
    })
    .await
    .expect("gateway stop test timed out");
}

#[tokio::test]
async fn redis_stop_preempts_a_slow_audit_append() {
    timeout(SETUP, async {
        let mut gateway = Gateway::start().await;
        let caller = gateway.request(true, &[ID]).await;
        let mut state = gateway.state_call().await;
        let body = br#"{"state":"CONTROLLED_VALIDATION"}"#;
        let head = format!(
            "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: {}\r\n\r\n",
            body.len()
        );
        state.write_all(head.as_bytes()).await.unwrap();
        state.write_all(body).await.unwrap();
        let (mut pending, _) = gateway.orchestrator.accept().await.unwrap();
        let mut first = String::new();
        BufReader::new(&mut pending)
            .read_line(&mut first)
            .await
            .unwrap();
        assert_eq!(
            first,
            format!("POST /engagements/{ID}/audit-events HTTP/1.1\r\n")
        );
        let reply = timeout(Duration::from_millis(100), async {
            gateway.redis.send_halt(Uuid::parse_str(ID).unwrap()).await;
            read_reply(caller).await
        })
        .await
        .expect("stop waited for the audit acknowledgement");
        assert_eq!(reply, (412, json!({"reason":"PRECONDITION_FAILED"})));
        gateway.assert_no_egress().await;
    })
    .await
    .expect("audit preemption test timed out");
}
