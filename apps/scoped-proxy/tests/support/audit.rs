use std::{convert::Infallible, sync::OnceLock};

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::{
    HeaderMap, Method, Request, Response, body::Incoming, server::conn::http1, service::service_fn,
};
use hyper_util::rt::TokioIo;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tokio::net::TcpListener;
use uuid::Uuid;

fn single_header<'a>(headers: &'a HeaderMap, name: &str) -> &'a str {
    let mut values = headers.get_all(name).iter();
    let value = values.next().expect("missing mock service header");
    assert!(values.next().is_none(), "duplicate {name}");
    value.to_str().unwrap()
}

/// Verify the M4 service request, then reply with a loopback ledger fixture.
pub async fn acknowledge_audit(listener: &TcpListener, engagement_id: Uuid, token: &str) -> Value {
    respond_to_audit(listener, engagement_id, token, 201)
        .await
        .1
}

pub async fn respond_to_audit(
    listener: &TcpListener,
    engagement_id: Uuid,
    token: &str,
    status: u16,
) -> (Uuid, Value, String) {
    let (socket, _) = listener.accept().await.unwrap();
    let received = OnceLock::new();
    let service = service_fn(|request: Request<Incoming>| async {
        assert_eq!(request.method(), Method::POST);
        assert_eq!(
            request.uri().path_and_query().unwrap().as_str(),
            format!("/engagements/{engagement_id}/audit-events")
        );
        assert_eq!(
            single_header(request.headers(), "authorization"),
            format!("Bearer {token}")
        );
        let key = Uuid::parse_str(single_header(request.headers(), "idempotency-key")).unwrap();
        let bytes = request.into_body().collect().await.unwrap().to_bytes();
        let body: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(body["actor_kind"], "SYSTEM");
        assert_eq!(body["actor_id"], "scoped-proxy");
        assert!(body["payload"].is_object());

        let mut event = body.clone();
        event["engagement_id"] = json!(engagement_id);
        event["event_id"] = json!(key);
        event["occurred_at"] = json!("2026-01-01T00:00:00Z");
        event.sort_all_objects();
        let mut hash = Sha256::new();
        hash.update([0; 32]);
        hash.update(serde_json::to_vec(&event).unwrap());
        let record_hash = format!("{:x}", hash.finalize());
        let response = if (200..300).contains(&status) {
            json!({"seq_id":1,"event":event,"prev_record_hash":"0".repeat(64),"record_hash":record_hash})
        } else {
            json!({"detail":"mock ledger rejected append"})
        };
        received.set((key, body, record_hash)).unwrap();
        Ok::<_, Infallible>(
            Response::builder()
                .status(status)
                .header("Content-Type", "application/json")
                .body(Full::new(Bytes::from(
                    serde_json::to_vec(&response).unwrap(),
                )))
                .unwrap(),
        )
    });
    http1::Builder::new()
        .keep_alive(false)
        .serve_connection(TokioIo::new(socket), service)
        .await
        .unwrap();
    received.into_inner().unwrap()
}
