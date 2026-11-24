#[path = "../src/policy_client.rs"]
pub mod policy_client;

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::{
    Request, Response, StatusCode, body::Incoming, server::conn::http1, service::service_fn,
};
use hyper_util::rt::TokioIo;
use policy_client::{
    BoundManifest, CompletionError,
    CompletionOutcome::{self, NoOriginResponse, OriginStatus},
    EvaluationError, PolicyClient, PolicyRequest, StateError,
};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    convert::Infallible,
    sync::{Arc, Mutex},
};
use tokio::{net::TcpListener, sync::mpsc};
use uuid::Uuid;

const ID: &str = "93939393-3232-4242-8181-121212121212";
const RECEIPT: &str = "301a8a70-da65-4c3a-a8e9-b1483cd3bd81";

struct Received {
    method: hyper::Method,
    path: String,
    headers: hyper::HeaderMap,
    body: Bytes,
}

async fn mock_service(
    handle: impl Fn(Received) -> Response<Full<Bytes>> + Send + Sync + 'static,
) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let handle = Arc::new(handle);
    tokio::spawn(async move {
        while let Ok((socket, _)) = listener.accept().await {
            let handle = handle.clone();
            let serve = service_fn(move |req: Request<Incoming>| {
                let handle = handle.clone();
                async move {
                    let (parts, body) = req.into_parts();
                    Ok::<_, Infallible>(handle(Received {
                        method: parts.method,
                        path: parts.uri.to_string(),
                        headers: parts.headers,
                        body: body.collect().await.unwrap().to_bytes(),
                    }))
                }
            });
            let _ = http1::Builder::new()
                .keep_alive(false)
                .serve_connection(TokioIo::new(socket), serve)
                .await;
        }
    });
    origin
}

async fn service(
    status: StatusCode,
    body: String,
    receipts: &[&str],
) -> (String, mpsc::Receiver<Received>) {
    let (tx, rx) = mpsc::channel(1);
    let receipts: Vec<_> = receipts.iter().map(|s| s.to_string()).collect();
    let origin = mock_service(move |call| {
        let mut response = Response::builder()
            .status(status)
            .header("content-type", "application/json");
        for receipt in &receipts {
            response = response.header("X-Policy-Reservation", receipt);
        }
        let _ = tx.try_send(call);
        response.body(Full::new(Bytes::from(body.clone()))).unwrap()
    })
    .await;
    (origin, rx)
}

fn fixture_manifest() -> (String, Vec<u8>) {
    let raw = include_str!("../../../tests/fixtures/roe_sample.json")
        .replace("eng_9f82a1c4", ID)
        .into_bytes();
    (format!("{:x}", Sha256::digest(&raw)), raw)
}

fn request() -> PolicyRequest<'static> {
    PolicyRequest {
        method: "GET",
        host: "api.staging.example.com",
        ip: "198.51.100.21".parse().unwrap(),
        path: "/public",
        ts: "2026-12-02T12:00:00Z",
    }
}

#[tokio::test]
async fn sends_exact_evaluation_and_returns_reservation() {
    let (origin, mut calls) = service(
        StatusCode::OK,
        json!({"allow":true,"reason":"ALLOWED"}).to_string(),
        &[RECEIPT],
    )
    .await;
    let client = PolicyClient::new(&origin, &origin).unwrap();
    let (digest, raw) = fixture_manifest();
    let id = Uuid::parse_str(ID).unwrap();
    let bound = BoundManifest::from_provisioned(id, &digest, &raw).unwrap();
    assert_eq!(bound.engagement_id(), id);
    assert_eq!(bound.breaker_threshold().get(), 5);
    assert_eq!(
        client.evaluate(&bound, &request()).await,
        Ok(Uuid::parse_str(RECEIPT).unwrap())
    );
    let call = calls.recv().await.unwrap();
    assert_eq!(call.method, hyper::Method::POST);
    assert_eq!(call.path, "/evaluate");
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&call.body).unwrap(),
        json!({
            "manifest_hash": digest,
            "request": {"method":"GET","host":"api.staging.example.com","ip":"198.51.100.21","path":"/public","ts":"2026-12-02T12:00:00Z"}
        })
    );
}

#[test]
fn rejects_wrong_manifest_owner_and_mutated_content() {
    let (digest, mut raw) = fixture_manifest();
    assert!(BoundManifest::from_provisioned(Uuid::nil(), &digest, &raw).is_err());
    raw.push(b' ');
    assert!(BoundManifest::from_provisioned(Uuid::parse_str(ID).unwrap(), &digest, &raw).is_err());
}

#[tokio::test]
async fn denies_on_policy_reason_or_invalid_allow_response() {
    let (digest, raw) = fixture_manifest();
    let bound =
        BoundManifest::from_provisioned(Uuid::parse_str(ID).unwrap(), &digest, &raw).unwrap();
    let allowed = r#"{"allow":true,"reason":"ALLOWED"}"#;
    let denied = r#"{"allow":false,"reason":"SCOPE_DENIED"}"#;
    let cases: Vec<(_, _, &[&str], _)> = vec![
        (
            StatusCode::OK,
            denied,
            &[],
            EvaluationError::Denied("SCOPE_DENIED".into()),
        ),
        (
            StatusCode::FORBIDDEN,
            denied,
            &[],
            EvaluationError::Denied("SCOPE_DENIED".into()),
        ),
        (StatusCode::OK, allowed, &[], EvaluationError::Unavailable),
        (
            StatusCode::OK,
            allowed,
            &["bogus"],
            EvaluationError::Unavailable,
        ),
        (
            StatusCode::OK,
            allowed,
            &[RECEIPT, RECEIPT],
            EvaluationError::Unavailable,
        ),
        (
            StatusCode::FORBIDDEN,
            allowed,
            &[RECEIPT],
            EvaluationError::Unavailable,
        ),
        (
            StatusCode::SERVICE_UNAVAILABLE,
            allowed,
            &[RECEIPT],
            EvaluationError::Unavailable,
        ),
        (
            StatusCode::OK,
            r#"{"allow":false,"allow":true,"reason":"ALLOWED"}"#,
            &[RECEIPT],
            EvaluationError::Unavailable,
        ),
    ];
    for (status, body, receipts, expected) in cases {
        let (origin, _) = service(status, body.into(), receipts).await;
        let client = PolicyClient::new(&origin, &origin).unwrap();
        assert_eq!(
            client.evaluate(&bound, &request()).await,
            Err(expected),
            "{status} {body}"
        );
    }
}

#[tokio::test]
async fn gates_before_lock_and_after_halt_or_closure() {
    for (state, expected) in [
        ("INIT_SCOPING", Err(StateError::PreconditionFailed)),
        ("HALTED_KILLSWITCH", Err(StateError::PreconditionFailed)),
        ("COMPLETED_ARCHIVED", Err(StateError::PreconditionFailed)),
        ("ROE_LOCKED", Ok(())),
        ("CONTROLLED_VALIDATION", Ok(())),
        ("UNKNOWN", Err(StateError::Unavailable)),
    ] {
        let (origin, mut calls) =
            service(StatusCode::OK, json!({"state":state}).to_string(), &[]).await;
        let client = PolicyClient::new(&origin, &origin).unwrap();
        assert_eq!(
            client.check_state(Uuid::parse_str(ID).unwrap()).await,
            expected
        );
        let call = calls.recv().await.unwrap();
        assert_eq!(call.method, hyper::Method::GET);
        assert_eq!(call.path, format!("/engagements/{ID}/state"));
    }
}

#[tokio::test]
async fn unknown_engagement_and_missing_orchestrator_route_are_distinct() {
    for (status, body, expected) in [
        (
            StatusCode::NOT_FOUND,
            json!({"reason":"ENGAGEMENT_NOT_FOUND"}),
            StateError::PreconditionFailed,
        ),
        (
            StatusCode::NOT_FOUND,
            json!({"detail":"Not Found"}),
            StateError::Unavailable,
        ),
        (
            StatusCode::SERVICE_UNAVAILABLE,
            json!({"reason":"ENGAGEMENT_NOT_FOUND"}),
            StateError::Unavailable,
        ),
    ] {
        let (origin, _) = service(status, body.to_string(), &[]).await;
        let client = PolicyClient::new(&origin, &origin).unwrap();
        assert_eq!(
            client.check_state(Uuid::parse_str(ID).unwrap()).await,
            Err(expected)
        );
    }
}

#[tokio::test]
async fn stop_requires_publication_acknowledgement() {
    for published in [false, true] {
        let (origin, mut calls) = service(StatusCode::OK, json!({
            "next_state":"HALTED_KILLSWITCH","status":"halted","ledger_hash":null,"notification_published":published
        }).to_string(), &[]).await;
        let client = PolicyClient::new(&origin, &origin).unwrap();
        assert_eq!(
            client.halt(Uuid::parse_str(ID).unwrap()).await.is_ok(),
            published
        );
        let call = calls.recv().await.unwrap();
        assert_eq!(call.method, hyper::Method::POST);
        assert_eq!(call.path, format!("/engagements/{ID}/killswitch"));
        assert!(call.body.is_empty());
    }
}

#[derive(Default)]
struct MockAccounting {
    reservations: HashMap<Uuid, Option<(CompletionOutcome, bool)>>,
    streak: usize,
    cumulative: usize,
}

impl MockAccounting {
    fn active_workers(&self) -> usize {
        self.reservations
            .values()
            .filter(|slot| slot.is_none())
            .count()
    }

    fn handle(
        &mut self,
        call: Received,
        manifest_digest: &str,
        threshold: usize,
    ) -> Response<Full<Bytes>> {
        let mut response = Response::builder().header("content-type", "application/json");
        assert_eq!(call.method, hyper::Method::POST);
        let document: serde_json::Value = serde_json::from_slice(&call.body).unwrap();
        let (status, body) = if call.path == "/evaluate" {
            assert_eq!(document["manifest_hash"], manifest_digest);
            if self.cumulative >= threshold {
                (
                    StatusCode::OK,
                    json!({"allow":false,"reason":"BREAKER_DENIED"}),
                )
            } else {
                let reservation = Uuid::from_u128(self.reservations.len() as u128 + 1);
                self.reservations.insert(reservation, None);
                response = response.header("X-Policy-Reservation", reservation.to_string());
                (StatusCode::OK, json!({"allow":true,"reason":"ALLOWED"}))
            }
        } else if call.path == format!("/engagements/{ID}/completions") {
            let mut receipts = call.headers.get_all("X-Policy-Reservation").iter();
            let reservation = Uuid::parse_str(receipts.next().unwrap().to_str().unwrap()).unwrap();
            assert!(receipts.next().is_none());
            assert_eq!(call.headers["content-type"], "application/json");
            assert_eq!(document.as_object().unwrap().len(), 1);
            let outcome = if document == json!({"outcome":"no_origin_response"}) {
                NoOriginResponse
            } else {
                let status = u16::try_from(document["status_code"].as_u64().unwrap()).unwrap();
                assert!((200..=599).contains(&status));
                OriginStatus(status)
            };
            match self.reservations.get_mut(&reservation) {
                None => (StatusCode::NOT_FOUND, json!({})),
                Some(Some((previous, _))) if *previous != outcome => {
                    (StatusCode::CONFLICT, json!({}))
                }
                Some(Some((_, tripped))) => (StatusCode::OK, json!({"breaker_tripped":tripped})),
                Some(slot) => {
                    if let OriginStatus(status) = outcome {
                        self.cumulative += usize::from(status >= 500);
                        self.streak = if status >= 500 { self.streak + 1 } else { 0 };
                    }
                    let tripped = self.streak >= threshold;
                    *slot = Some((outcome, tripped));
                    (StatusCode::OK, json!({"breaker_tripped":tripped}))
                }
            }
        } else {
            (StatusCode::NOT_FOUND, json!({}))
        };
        response
            .status(status)
            .body(Full::new(Bytes::from(body.to_string())))
            .unwrap()
    }
}

#[tokio::test]
async fn proposed_completion_releases_mock_worker_once_and_returns_recorded_breaker_state() {
    let id = Uuid::parse_str(ID).unwrap();
    let (_, raw) = fixture_manifest();
    // All five requests can be in flight before any final response arrives.
    let mut document: serde_json::Value = serde_json::from_slice(&raw).unwrap();
    document["traffic_constraints"]["circuit_breaker_5xx_threshold"] = json!(2);
    document["traffic_constraints"]["max_concurrent_workers"] = json!(5);
    let raw = serde_json::to_vec(&document).unwrap();
    let mock_digest = format!("{:x}", Sha256::digest(&raw));
    let bound = BoundManifest::from_provisioned(id, &mock_digest, &raw).unwrap();
    let state = Arc::new(Mutex::new(MockAccounting::default()));
    let observer = state.clone();
    let threshold = usize::try_from(bound.breaker_threshold().get()).unwrap();
    let origin = mock_service(move |call| {
        observer
            .lock()
            .unwrap()
            .handle(call, &mock_digest, threshold)
    })
    .await;
    let client = PolicyClient::new(&origin, &origin).unwrap();
    let outcomes = [
        (OriginStatus(503), 1, 1, false),
        (OriginStatus(429), 0, 1, false),
        (OriginStatus(500), 1, 2, false),
        (NoOriginResponse, 1, 2, false),
        (OriginStatus(502), 2, 3, true),
    ];
    let mut receipts = Vec::new();
    for _ in &outcomes {
        receipts.push(client.evaluate(&bound, &request()).await.unwrap());
    }
    for (index, (outcome, streak, cumulative, tripped)) in outcomes.into_iter().enumerate() {
        let receipt = receipts[index];
        let outstanding = receipts.len() - index;
        assert_eq!(state.lock().unwrap().active_workers(), outstanding);
        assert_eq!(
            client.complete(Uuid::nil(), receipt, outcome).await,
            Err(CompletionError::Rejected(StatusCode::NOT_FOUND))
        );
        assert_eq!(state.lock().unwrap().active_workers(), outstanding);
        assert_eq!(client.complete(id, receipt, outcome).await, Ok(tripped));
        assert_eq!(client.complete(id, receipt, outcome).await, Ok(tripped));
        assert_eq!(
            client.complete(id, receipt, OriginStatus(200)).await,
            Err(CompletionError::Rejected(StatusCode::CONFLICT))
        );
        if cumulative >= threshold {
            assert_eq!(
                client.evaluate(&bound, &request()).await,
                Err(EvaluationError::Denied("BREAKER_DENIED".into()))
            );
        }
        let account = state.lock().unwrap();
        assert_eq!(account.active_workers(), outstanding - 1);
        assert_eq!(account.streak, streak);
        assert_eq!(account.cumulative, cumulative);
    }
    // Even after a later trip, the first completion's recorded answer is stable.
    assert_eq!(
        client.complete(id, receipts[0], OriginStatus(503)).await,
        Ok(false)
    );
    assert_eq!(
        client.complete(id, Uuid::nil(), OriginStatus(200)).await,
        Err(CompletionError::Rejected(StatusCode::NOT_FOUND))
    );
    assert_eq!(state.lock().unwrap().streak, 2);
}

#[tokio::test]
async fn completion_requires_final_origin_status_and_an_unambiguous_acknowledgement() {
    let id = Uuid::parse_str(ID).unwrap();
    let receipt = Uuid::parse_str(RECEIPT).unwrap();
    for (status, body, expected) in [
        (
            StatusCode::UNPROCESSABLE_ENTITY,
            "{}",
            CompletionError::Rejected(StatusCode::UNPROCESSABLE_ENTITY),
        ),
        (
            StatusCode::SERVICE_UNAVAILABLE,
            "{}",
            CompletionError::Unavailable,
        ),
        (
            StatusCode::ACCEPTED,
            r#"{"breaker_tripped":false}"#,
            CompletionError::Unavailable,
        ),
        (
            StatusCode::OK,
            r#"{"breaker_tripped":"false"}"#,
            CompletionError::Unavailable,
        ),
        (
            StatusCode::OK,
            r#"{"breaker_tripped":false,"extra":0}"#,
            CompletionError::Unavailable,
        ),
        (
            StatusCode::OK,
            r#"{"breaker_tripped":true,"breaker_tripped":false}"#,
            CompletionError::Unavailable,
        ),
    ] {
        let (origin, mut calls) = service(status, body.into(), &[]).await;
        let client = PolicyClient::new(&origin, &origin).unwrap();
        for invalid in [0, 199, 600] {
            assert_eq!(
                client.complete(id, receipt, OriginStatus(invalid)).await,
                Err(CompletionError::InvalidStatus)
            );
        }
        assert!(calls.try_recv().is_err());
        assert_eq!(
            client.complete(id, receipt, OriginStatus(599)).await,
            Err(expected)
        );
        assert!(calls.try_recv().is_ok());
    }
}
