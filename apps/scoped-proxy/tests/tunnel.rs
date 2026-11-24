#[path = "../src/evidence_client.rs"]
mod evidence_client;
#[path = "../src/tls.rs"]
mod tls;

use std::{num::NonZeroUsize, time::Duration};

use evidence_client::{EvidenceClient, EvidenceError};
use serde_json::{Value, json};
use tls::{Ingress, RejectionReason, classify_ingress};
use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader},
    net::{TcpListener, TcpStream},
    time::{sleep, timeout},
};
use uuid::Uuid;

const ENGAGEMENT: Uuid = Uuid::from_u128(42);
const DIAGNOSTIC: Uuid = Uuid::from_u128(123);
const LIMIT: Duration = Duration::from_secs(4);
const PEEK: Duration = Duration::from_millis(150);

async fn mock_handshake() -> (TcpStream, TcpStream) {
    const REQUEST: &[u8] =
        b"CONNECT fixture.invalid:443 HTTP/1.1\r\nHost: fixture.invalid:443\r\n\r\n";
    const RESPONSE: &[u8] = b"HTTP/1.1 200 Connection Established\r\n\r\n";
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mut client = TcpStream::connect(listener.local_addr().unwrap())
        .await
        .unwrap();
    let (mut server, _) = listener.accept().await.unwrap();
    client.set_nodelay(true).unwrap();
    client.write_all(REQUEST).await.unwrap();
    let mut request = [0; REQUEST.len()];
    server.read_exact(&mut request).await.unwrap();
    assert_eq!(&request[..], REQUEST);
    server.write_all(RESPONSE).await.unwrap();
    server.flush().await.unwrap();
    let mut response = [0; RESPONSE.len()];
    client.read_exact(&mut response).await.unwrap();
    assert_eq!(&response[..], RESPONSE);
    (client, server)
}

async fn evidence_service() -> (EvidenceClient, TcpListener) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let client = EvidenceClient::new(&origin, NonZeroUsize::new(1024).unwrap()).unwrap();
    (client, listener)
}

async fn receive_artifact(listener: TcpListener, status: u16) -> Value {
    let (socket, _) = listener.accept().await.unwrap();
    let mut reader = BufReader::new(socket);
    let mut line = String::new();
    reader.read_line(&mut line).await.unwrap();
    assert_eq!(line, "PUT /artifacts HTTP/1.1\r\n");
    let mut length = None;
    loop {
        line.clear();
        assert_ne!(reader.read_line(&mut line).await.unwrap(), 0);
        if line == "\r\n" {
            break;
        }
        let (header, value) = line.split_once(':').unwrap();
        if header.eq_ignore_ascii_case("content-length") {
            length = Some(value.trim().parse::<usize>().unwrap());
        }
    }
    let mut body = vec![0; length.unwrap()];
    reader.read_exact(&mut body).await.unwrap();
    let response =
        format!("HTTP/1.1 {status} Test\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
    reader
        .get_mut()
        .write_all(response.as_bytes())
        .await
        .unwrap();
    serde_json::from_slice(&body).unwrap()
}

async fn assert_rejection(
    chunks: &[&[u8]],
    half_close: bool,
    reason: RejectionReason,
    expected_hex: &str,
    evidence_status: u16,
) {
    timeout(LIMIT, async {
        let (mut caller, ingress) = mock_handshake().await;
        let (evidence, listener) = evidence_service().await;
        let upload = tokio::spawn(receive_artifact(listener, evidence_status));
        let classification = tokio::spawn(async move {
            classify_ingress(ingress, ENGAGEMENT, DIAGNOSTIC, PEEK, &evidence).await
        });
        for (i, chunk) in chunks.iter().enumerate() {
            if i > 0 {
                sleep(Duration::from_millis(5)).await;
            }
            caller.write_all(chunk).await.unwrap();
        }
        if half_close {
            caller.shutdown().await.unwrap();
        }
        let mut reply = Vec::new();
        caller
            .read_to_end(&mut reply)
            .await
            .expect("expected clean EOF");
        assert!(reply.is_empty(), "unexpected bytes after CONNECT 200");
        let Ingress::RejectedPendingAudit(outcome) = classification.await.unwrap() else {
            panic!("unexpected candidate");
        };
        outcome.close_result.unwrap();
        assert!(outcome.read_error.is_none());
        assert_eq!(outcome.record.reason, reason);
        if evidence_status == 201 {
            outcome.evidence_result.unwrap();
        } else {
            assert!(matches!(
                outcome.evidence_result,
                Err(EvidenceError::Unacknowledged(s)) if s.as_u16() == evidence_status
            ));
        }
        let artifact = upload.await.unwrap();
        assert_eq!(artifact, serde_json::to_value(outcome.record).unwrap());
        let wire_reason = match reason {
            RejectionReason::OpaqueTunnelNotAllowed => "OPAQUE_TUNNEL_NOT_ALLOWED",
            RejectionReason::TunnelIdleTimeout => "TUNNEL_IDLE_TIMEOUT",
        };
        assert_eq!(
            artifact,
            json!({
                "diagnostic_id": DIAGNOSTIC, "engagement_id": ENGAGEMENT,
                "prefix_hex": expected_hex, "reason": wire_reason
            })
        );
    })
    .await
    .expect("tunnel rejection timed out");
}

#[tokio::test]
async fn fragmented_opaque_input_closes_cleanly_and_records_only_first_16_bytes() {
    assert_rejection(
        &[b"\x00", b"\xff12345", b"6789abcdefghijk"],
        false,
        RejectionReason::OpaqueTunnelNotAllowed,
        "00ff3132333435363738396162636465",
        201,
    )
    .await;
}

#[tokio::test]
async fn no_bytes_before_deadline_records_idle() {
    assert_rejection(&[], false, RejectionReason::TunnelIdleTimeout, "", 201).await;
}

#[tokio::test]
async fn partial_prefix_at_deadline_records_observed_byte() {
    assert_rejection(
        &[b"\x16"],
        false,
        RejectionReason::OpaqueTunnelNotAllowed,
        "16",
        201,
    )
    .await;
}

#[tokio::test]
async fn truncated_or_inapplicable_tls_records_require_rejection() {
    let opaque = RejectionReason::OpaqueTunnelNotAllowed;
    for (prefix, hex) in [
        (&b"\x16\x03"[..], "1603"),
        (&b"\x16\x03\x03\x00\x01\x02"[..], "160303000102"), // ServerHello
        (&b"\x16\x03\x03\x00\x00\x01"[..], "160303000001"), // empty record
        (&b"\x16\x03\x03\x40\x01\x01"[..], "160303400101"), // > 2^14
        (&b"\x16\x03\x04\x00\x01\x01"[..], "160304000101"), // legacy version
    ] {
        assert_rejection(&[prefix], true, opaque, hex, 201).await;
    }
}

#[tokio::test]
async fn eof_records_opaque_and_preserves_record_on_evidence_failure() {
    assert_rejection(&[], true, RejectionReason::OpaqueTunnelNotAllowed, "", 503).await;
}

#[tokio::test]
async fn candidate_retains_fragmented_client_hello_for_inspection() {
    timeout(LIMIT, async {
        let (mut caller, ingress) = mock_handshake().await;
        let (evidence, _listener) = evidence_service().await;
        // TLS 1.2 ClientHello with a single suite and null compression.
        let mut hello = vec![0x16, 0x03, 0x01, 0x00, 0x2d, 0x01, 0, 0, 0x29, 0x03, 0x03];
        hello.extend_from_slice(&[0xa5; 32]);
        hello.extend_from_slice(&[0, 0, 2, 0xc0, 0x2f, 1, 0]);
        let classify = tokio::spawn(async move {
            classify_ingress(ingress, ENGAGEMENT, DIAGNOSTIC, PEEK, &evidence).await
        });
        caller.write_all(&hello[..1]).await.unwrap();
        sleep(Duration::from_millis(5)).await;
        caller.write_all(&hello[1..]).await.unwrap();
        caller.shutdown().await.unwrap();
        let Ingress::Candidate { prefix, mut client } = classify.await.unwrap() else {
            panic!("expected a TLS candidate");
        };
        assert!(prefix.len() <= 16);
        assert!(prefix.starts_with(&[0x16, 0x03]));
        let mut replay = prefix.to_vec();
        client.read_to_end(&mut replay).await.unwrap();
        assert_eq!(replay, hello);
    })
    .await
    .expect("candidate classification timed out");
}
