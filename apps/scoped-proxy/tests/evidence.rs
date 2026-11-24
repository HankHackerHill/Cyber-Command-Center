#[path = "../src/evidence_client.rs"]
mod evidence_client;

use std::{convert::Infallible, num::NonZeroUsize};

use bytes::Bytes;
use evidence_client::{EvidenceClient, EvidenceError};
use http_body_util::{BodyExt, Empty};
use hyper::{Method, Request, Response, StatusCode};
use hyper::{body::Incoming, header, server::conn::http1, service::service_fn};
use hyper_util::rt::TokioIo;
use tokio::{net::TcpListener, task::JoinHandle};

const ARTIFACT: &[u8] = include_bytes!("../../../tests/fixtures/har_sample.har");

async fn mock_evidence(status: StatusCode) -> (EvidenceClient, JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let client = EvidenceClient::new(&origin, NonZeroUsize::new(ARTIFACT.len()).unwrap()).unwrap();
    let server = tokio::spawn(async move {
        let (socket, _) = listener.accept().await.unwrap();
        let handler = service_fn(move |request: Request<Incoming>| async move {
            assert_eq!(request.method(), Method::PUT);
            assert_eq!(
                request.uri().path_and_query().unwrap().as_str(),
                "/artifacts"
            );
            assert_eq!(
                request.headers()[header::CONTENT_TYPE],
                "application/octet-stream"
            );
            let bytes = request.into_body().collect().await.unwrap().to_bytes();
            assert_eq!(bytes.as_ref(), ARTIFACT);
            let mut reply = Response::builder().status(status);
            if status.is_redirection() {
                reply = reply.header(header::LOCATION, "/somewhere-else");
            }
            Ok::<_, Infallible>(reply.body(Empty::<Bytes>::new()).unwrap())
        });
        http1::Builder::new()
            .keep_alive(false)
            .serve_connection(TokioIo::new(socket), handler)
            .await
            .unwrap();
    });
    (client, server)
}

#[tokio::test]
async fn preserves_artifact_for_acknowledged_put() {
    for status in [StatusCode::OK, StatusCode::CREATED, StatusCode::NO_CONTENT] {
        let (client, server) = mock_evidence(status).await;
        client.put(Bytes::from_static(ARTIFACT)).await.unwrap();
        server.await.unwrap();
    }
}

#[tokio::test]
async fn rejects_pending_redirected_and_failed_uploads() {
    for status in [
        StatusCode::ACCEPTED,
        StatusCode::TEMPORARY_REDIRECT,
        StatusCode::SERVICE_UNAVAILABLE,
    ] {
        let (client, server) = mock_evidence(status).await;
        let error = client.put(Bytes::from_static(ARTIFACT)).await.unwrap_err();
        assert!(matches!(error, EvidenceError::Unacknowledged(s) if s == status));
        server.await.unwrap();
    }
}

#[tokio::test]
async fn rejects_oversized_artifact_before_upload() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let client = EvidenceClient::new(&origin, NonZeroUsize::MIN).unwrap();
    let error = client.put(Bytes::from_static(ARTIFACT)).await.unwrap_err();
    assert!(matches!(error, EvidenceError::ArtifactTooLarge));
}

#[test]
fn requires_a_trusted_http_origin_without_path_or_credentials() {
    for invalid_origin in [
        "file:///artifacts",
        "http://localhost/other-service",
        "https://localhost/?tenant=2",
        "https://localhost/#artifact",
        "https://secret@localhost/",
    ] {
        assert!(matches!(
            EvidenceClient::new(invalid_origin, NonZeroUsize::MIN),
            Err(EvidenceError::InvalidOrigin)
        ));
    }
}
