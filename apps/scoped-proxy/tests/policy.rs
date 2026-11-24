#[path = "support/audit.rs"]
mod mock_audit;
#[path = "../src/policy_client.rs"]
pub mod policy_client;

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::{
    Request, Response, StatusCode, body::Incoming, server::conn::http1, service::service_fn,
};
use hyper_util::rt::TokioIo;
use policy_client::{BoundManifest, EvaluationError, PolicyClient, PolicyRequest, StateError};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::convert::Infallible;
use tokio::{net::TcpListener, sync::mpsc};
use uuid::Uuid;

const ID: &str = "93939393-3232-4242-8181-121212121212";
const RECEIPT: &str = "301a8a70-da65-4c3a-a8e9-b1483cd3bd81";

#[tokio::test]
async fn records_policy_denial_for_the_bound_engagement() {
    let audit = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let (service, _calls) = service(
        StatusCode::OK,
        json!({"allow":false,"reason":"SCOPE_DENIED"}).to_string(),
        &[],
    )
    .await;
    let token = "loopback-test-only";
    let client = PolicyClient::new(&format!("http://{}", audit.local_addr().unwrap()), &service)
        .unwrap()
        .with_audit_token(token)
        .unwrap();
    let (digest, raw) = fixture_manifest();
    let id = Uuid::parse_str(ID).unwrap();
    let manifest = BoundManifest::from_provisioned(id, &digest, &raw).unwrap();
    let input = request();
    let (decision, audit) = tokio::time::timeout(std::time::Duration::from_secs(4), async {
        tokio::join!(
            client.evaluate(&manifest, &input),
            mock_audit::acknowledge_audit(&audit, id, token)
        )
    })
    .await
    .unwrap();
    assert_eq!(
        decision,
        Err(EvaluationError::Denied("SCOPE_DENIED".into()))
    );
    assert_eq!(audit["event_type"], "POLICY_DENIED");
    assert_eq!(
        audit["payload"],
        json!({
            "manifest_hash":digest, "reason":"SCOPE_DENIED", "method":input.method, "host":input.host
        })
    );
}

struct Received {
    method: hyper::Method,
    path: String,
    body: Bytes,
}

async fn service(
    status: StatusCode,
    body: String,
    receipts: &[&str],
) -> (String, mpsc::Receiver<Received>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let (tx, rx) = mpsc::channel(1);
    let receipts: Vec<_> = receipts.iter().map(|s| s.to_string()).collect();
    tokio::spawn(async move {
        let (socket, _) = listener.accept().await.unwrap();
        let serve = service_fn(move |req: Request<Incoming>| {
            let tx = tx.clone();
            let mut response = Response::builder()
                .status(status)
                .header("content-type", "application/json");
            for receipt in &receipts {
                response = response.header("X-Policy-Reservation", receipt);
            }
            let response = response.body(Full::new(Bytes::from(body.clone()))).unwrap();
            async move {
                let (parts, body) = req.into_parts();
                let call = Received {
                    method: parts.method,
                    path: parts.uri.to_string(),
                    body: body.collect().await.unwrap().to_bytes(),
                };
                let _ = tx.send(call).await;
                Ok::<_, Infallible>(response)
            }
        });
        let _ = http1::Builder::new()
            .keep_alive(false)
            .serve_connection(TokioIo::new(socket), serve)
            .await;
    });
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
