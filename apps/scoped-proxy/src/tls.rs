//! Ingress diagnostic for an already acknowledged CONNECT. The listener keeps
//! denying before 200 while TLS inspection and durable audit append are unavailable.

use std::{fmt::Write as _, io, time::Duration};

use bytes::Bytes;
use serde::Serialize;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    time::{Instant, timeout, timeout_at},
};
use uuid::Uuid;

use crate::evidence_client::{EvidenceClient, EvidenceError};

const MAX_PREFIX: usize = 16;
const MAX_WAIT: Duration = Duration::from_millis(250);

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RejectionReason {
    OpaqueTunnelNotAllowed,
    TunnelIdleTimeout,
}

#[derive(Debug, Serialize)]
pub struct RejectionRecord {
    pub diagnostic_id: Uuid,
    pub engagement_id: Uuid,
    pub reason: RejectionReason,
    pub prefix_hex: String,
}

#[derive(Debug)]
pub struct PendingAudit {
    pub record: RejectionRecord,
    pub evidence_result: Result<(), EvidenceError>,
    pub read_error: Option<io::Error>,
    pub close_result: io::Result<()>,
}

#[must_use = "TLS candidates require handshake validation and rejections require durable audit"]
pub enum Ingress<S> {
    /// Replay the complete prefix, then continue reading the client stream.
    /// The plaintext record header and first handshake type identify a candidate.
    Candidate {
        prefix: Bytes,
        client: S,
    },
    RejectedPendingAudit(PendingAudit),
}

/// Inspect at most sixteen client bytes under one deadline across all reads.
/// The caller supplies a unique diagnostic ID and a trusted evidence endpoint.
pub async fn classify_ingress<S: AsyncRead + AsyncWrite + Unpin>(
    mut client: S,
    engagement_id: Uuid,
    diagnostic_id: Uuid,
    peek_timeout: Duration,
    evidence: &EvidenceClient,
) -> Ingress<S> {
    let deadline = Instant::now() + peek_timeout.min(MAX_WAIT);
    let mut prefix = [0_u8; MAX_PREFIX];
    let mut len = 0;
    let mut read_error = None;
    let reason = loop {
        match timeout_at(deadline, client.read(&mut prefix[len..])).await {
            Ok(Ok(0)) => break RejectionReason::OpaqueTunnelNotAllowed,
            Ok(Ok(n)) => {
                len += n;
                // ClientHello can span multiple TLSPlaintext records. The first
                // record needs to hold only the handshake type byte (RFC 8446 §5).
                let candidate = matches!(
                    &prefix[..len],
                    [0x16, 0x03, 0x01..=0x03, hi, lo, 0x01, ..]
                    if (1..=16_384).contains(&u16::from_be_bytes([*hi, *lo]))
                );
                if candidate {
                    return Ingress::Candidate {
                        prefix: Bytes::copy_from_slice(&prefix[..len]),
                        client,
                    };
                }
                if len == MAX_PREFIX {
                    break RejectionReason::OpaqueTunnelNotAllowed;
                }
            }
            Ok(Err(err)) => {
                read_error = Some(err);
                break RejectionReason::OpaqueTunnelNotAllowed;
            }
            Err(_) if len == 0 => break RejectionReason::TunnelIdleTimeout,
            Err(_) => break RejectionReason::OpaqueTunnelNotAllowed,
        }
    };

    let close_result = timeout(MAX_WAIT, async {
        let flush = client.flush().await;
        let shutdown = client.shutdown().await;
        flush.and(shutdown)
    })
    .await
    .unwrap_or_else(|_| Err(io::ErrorKind::TimedOut.into()));
    let mut prefix_hex = String::with_capacity(len * 2);
    for byte in &prefix[..len] {
        write!(prefix_hex, "{byte:02x}").expect("writing to a String is infallible");
    }
    let record = RejectionRecord {
        engagement_id,
        diagnostic_id,
        reason,
        prefix_hex,
    };
    let artifact = serde_json::to_vec(&record).expect("UUIDs, strings and unit variants serialize");
    let evidence_result = evidence.put(Bytes::from(artifact)).await;
    Ingress::RejectedPendingAudit(PendingAudit {
        record,
        evidence_result,
        read_error,
        close_result,
    })
}
