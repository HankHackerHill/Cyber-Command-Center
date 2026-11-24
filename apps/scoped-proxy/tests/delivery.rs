//! Durable async mode accepts responsibility locally before returning an origin
//! response. Process crashes, remote outages and ambiguous remote ACKs must not
//! turn that responsibility into an in-memory, best-effort queue.
#[path = "support/delivery.rs"]
mod support;

use std::{fs, time::Duration};

use serde_json::Value;
use sha2::{Digest, Sha256};
use support::{Fixture, ID, LIMIT, REQUEST, RESPONSE, eventually, hex, records};
use tokio::{io::BufReader, time::timeout};

fn assert_binary_artifact(bytes: &[u8]) -> Value {
    let artifact: Value = serde_json::from_slice(bytes).unwrap();
    assert_eq!(artifact["engagement_id"], ID);
    assert_eq!(artifact["request"]["body_hex"], hex(REQUEST));
    assert_eq!(artifact["response"]["body_hex"], hex(RESPONSE));
    for (part, expected) in [("request", "81fe"), ("response", "80ff")] {
        assert!(
            artifact[part]["headers_hex"]
                .as_array()
                .unwrap()
                .iter()
                .any(|header| { header[0] == "x-binary" && header[1] == expected }),
            "raw {part} header bytes were lost"
        );
    }
    artifact
}

#[tokio::test]
async fn blocked_remote_evidence_does_not_delay_locally_durable_origin_response() {
    timeout(LIMIT, async {
        let fixture = Fixture::start(128).await;
        fixture.seen.lock().unwrap().hold_evidence = true;
        let response = timeout(Duration::from_secs(1), fixture.request())
            .await
            .expect("origin response waited for blocked remote evidence");
        assert!(response.line.contains("200"), "{response:?}");
        assert_eq!(response.body, RESPONSE);
        let pending = records(&fixture.outbox);
        assert_eq!(
            pending.len(),
            1,
            "origin response escaped before a durable finalized record"
        );
        assert_eq!(pending[0]["status"], 200);
        let artifact = pending[0]["artifact"]
            .as_str()
            .expect("finalized record lost evidence bytes");
        assert_binary_artifact(artifact.as_bytes());
        let seen = fixture.seen.lock().unwrap();
        assert_eq!(seen.origins[0].body, REQUEST);
        assert_eq!(
            seen.origins[0].header("x-binary"),
            Some(b"\x81\xfe".as_slice())
        );
        assert!(
            seen.intent_at_origin
                .iter()
                .any(|record| record["status"].is_null() && record["artifact"].is_null()),
            "origin connection preceded the durable request intent"
        );
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn restart_replays_exact_binary_evidence_with_stable_digest_and_event_id() {
    timeout(LIMIT, async {
        let mut fixture = Fixture::start(128).await;
        {
            let mut seen = fixture.seen.lock().unwrap();
            seen.evidence_status = 503;
            seen.settlement_status = 503;
        }
        let response = fixture.request().await;
        assert_eq!(response.body, RESPONSE);
        let before = records(&fixture.outbox);
        assert_eq!(before.len(), 1);
        let raw = before[0]["artifact"].as_str().unwrap().as_bytes().to_vec();
        let artifact = assert_binary_artifact(&raw);
        let event_id = artifact["event_id"].as_str().unwrap().to_owned();
        assert_eq!(before[0]["event_id"], event_id);
        let digest = format!("{:x}", Sha256::digest(&raw));
        fixture.crash().await;
        {
            let mut seen = fixture.seen.lock().unwrap();
            seen.evidence_status = 201;
            seen.settlement_status = 200;
        }
        fixture.restart().await;
        eventually(|| records(&fixture.outbox).is_empty()).await;
        let seen = fixture.seen.lock().unwrap();
        assert_eq!(
            seen.origin_connections, 1,
            "restart repeated target traffic"
        );
        assert!(!seen.artifacts.is_empty());
        assert!(
            seen.artifacts.iter().all(|bytes| bytes == &raw),
            "replay regenerated or truncated artifact bytes"
        );
        assert_eq!(seen.ledger.len(), 1);
        let audit = &seen.ledger[&event_id];
        assert_eq!(audit["payload"]["evidence_sha256"], digest);
        assert_eq!(audit["payload"]["reservation"], artifact["reservation"]);
        assert_eq!(seen.completed.len(), 1);
        assert!(seen.receipts.is_empty());
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn crash_after_remote_append_before_local_ack_reuses_the_same_event() {
    timeout(LIMIT, async {
        let mut fixture = Fixture::start(128).await;
        fixture.seen.lock().unwrap().lose_audit_ack = true;
        assert_eq!(fixture.request().await.body, RESPONSE);
        eventually(|| !fixture.seen.lock().unwrap().ledger.is_empty()).await;
        let before = records(&fixture.outbox);
        assert_eq!(
            before.len(),
            1,
            "ambiguous remote append acknowledgment discarded local delivery job"
        );
        let stable_id = before[0]["event_id"].as_str().unwrap().to_owned();
        fixture.crash().await;
        fixture.seen.lock().unwrap().lose_audit_ack = false;
        fixture.restart().await;
        eventually(|| records(&fixture.outbox).is_empty()).await;
        let seen = fixture.seen.lock().unwrap();
        assert_eq!(
            seen.ledger.len(),
            1,
            "replayed audit created a second logical ledger event"
        );
        assert!(
            seen.audit_attempts.len() >= 2,
            "test did not replay an unacknowledged append"
        );
        assert!(
            seen.audit_attempts
                .iter()
                .all(|(id, event)| id == &stable_id && event == &seen.ledger[&stable_id])
        );
        assert_eq!(seen.completed.len(), 1);
        assert_eq!(seen.origin_connections, 1);
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn full_outbox_denies_before_origin_without_discarding_the_pending_record() {
    timeout(LIMIT, async {
        let fixture = Fixture::start(1).await;
        {
            let mut seen = fixture.seen.lock().unwrap();
            seen.evidence_status = 503;
            seen.settlement_status = 503;
        }
        assert_eq!(fixture.request().await.body, RESPONSE);
        let before = records(&fixture.outbox);
        assert_eq!(before.len(), 1);
        let denied = fixture.request().await;
        assert!(denied.line.contains("503"), "{denied:?}");
        assert!(
            String::from_utf8_lossy(&denied.body).contains("OUTBOX"),
            "{denied:?}"
        );
        assert_eq!(
            records(&fixture.outbox),
            before,
            "capacity denial mutated/lost an accepted job"
        );
        let seen = fixture.seen.lock().unwrap();
        assert_eq!(
            seen.origin_connections, 1,
            "capacity failure occurred after opening the origin socket"
        );
        assert_eq!(seen.origins.len(), 1);
        assert_eq!(
            seen.receipts.len(),
            1,
            "capacity denial leaked an additional M3 reservation"
        );
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn concurrent_capacity_denials_do_not_leak_policy_reservations() {
    timeout(LIMIT, async {
        let fixture = Fixture::start(1).await;
        {
            let mut seen = fixture.seen.lock().unwrap();
            seen.evidence_status = 503;
            seen.settlement_status = 503;
        }
        let responses = futures_util::future::join_all((0..8).map(|_| fixture.request())).await;
        assert_eq!(
            responses
                .iter()
                .filter(|response| response.body == RESPONSE)
                .count(),
            1
        );
        assert!(responses.iter().all(|response| response.body == RESPONSE
            || (response.line.contains("503")
                && String::from_utf8_lossy(&response.body).contains("OUTBOX"))));
        assert_eq!(records(&fixture.outbox).len(), 1);
        let seen = fixture.seen.lock().unwrap();
        assert_eq!(seen.origin_connections, 1);
        assert_eq!(
            seen.receipts.len(),
            1,
            "capacity failures reserved workers without durable intents"
        );
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn local_outbox_write_failure_denies_before_origin() {
    timeout(LIMIT, async {
        let fixture = Fixture::start(128).await;
        let moved = fixture.root.join("held-outbox");
        fs::rename(&fixture.outbox, &moved).unwrap();
        fs::write(&fixture.outbox, b"not a directory").unwrap();
        let denied = fixture.request().await;
        assert!(denied.line.contains("503"), "{denied:?}");
        assert!(
            String::from_utf8_lossy(&denied.body).contains("OUTBOX"),
            "{denied:?}"
        );
        let seen = fixture.seen.lock().unwrap();
        assert_eq!(
            seen.origin_connections, 0,
            "local durability failure allowed target egress"
        );
        assert!(seen.origins.is_empty());
        assert!(seen.completed.is_empty());
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn finalization_write_failure_holds_client_response_until_local_durability_recovers() {
    timeout(LIMIT, async {
        let fixture = Fixture::start(128).await;
        {
            let mut seen = fixture.seen.lock().unwrap();
            seen.hold_origin_response = true;
            seen.evidence_status = 503;
            seen.settlement_status = 503;
        }
        let mut foreground = BufReader::new(fixture.send().await);
        eventually(|| !fixture.seen.lock().unwrap().origins.is_empty()).await;
        let moved = fixture.root.join("held-outbox");
        fs::rename(&fixture.outbox, &moved).unwrap();
        fs::write(&fixture.outbox, b"not a directory").unwrap();
        fixture.seen.lock().unwrap().origin_release.notify_one();
        // Read a byte instead of parsing a full response: even response headers
        // must remain withheld until the final evidence record is durable.
        use tokio::io::AsyncReadExt;
        assert!(
            timeout(Duration::from_millis(200), foreground.read_u8())
                .await
                .is_err(),
            "client received bytes while local finalization could not be written"
        );
        let intent = records(&moved);
        assert_eq!(intent.len(), 1);
        assert!(intent[0]["artifact"].is_null());
        fs::remove_file(&fixture.outbox).unwrap();
        fs::rename(&moved, &fixture.outbox).unwrap();
        let response = support::read_wire(&mut foreground).await;
        assert_eq!(response.body, RESPONSE);
        let final_record = records(&fixture.outbox);
        assert_eq!(final_record.len(), 1);
        assert_eq!(final_record[0]["status"], 200);
        assert_binary_artifact(final_record[0]["artifact"].as_str().unwrap().as_bytes());
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn queued_settlement_does_not_release_worker_or_lose_final_5xx() {
    timeout(LIMIT, async {
        let fixture = Fixture::start(128).await;
        {
            let mut seen = fixture.seen.lock().unwrap();
            seen.origin_status = 503;
            seen.settlement_status = 202;
            seen.evidence_status = 503;
        }
        let response = fixture.request().await;
        assert!(response.line.contains("503"));
        assert_eq!(
            response.body, RESPONSE,
            "origin 5xx replaced by background settlement failure"
        );
        eventually(|| !fixture.seen.lock().unwrap().settlement_attempts.is_empty()).await;
        {
            let seen = fixture.seen.lock().unwrap();
            assert_eq!(
                seen.receipts.len(),
                1,
                "queued settlement released the active worker early"
            );
            assert!(seen.completed.is_empty());
            assert_eq!(seen.errors_5xx, 0);
        }
        let pending = records(&fixture.outbox);
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0]["status"], 503);
        assert_eq!(pending[0]["settled"], false);
        let denied = fixture.request().await;
        assert!(denied.line.contains("503"), "{denied:?}");
        assert!(
            String::from_utf8_lossy(&denied.body).contains("OUTBOX_UNAVAILABLE"),
            "{denied:?}"
        );
        {
            let seen = fixture.seen.lock().unwrap();
            assert_eq!(
                seen.evaluations, 1,
                "pending confirmed 5xx admitted another M3 evaluation"
            );
            assert_eq!(seen.receipts.len(), 1);
            assert_eq!(
                seen.origin_connections, 1,
                "pending confirmed 5xx allowed further target egress"
            );
        }
        {
            let mut seen = fixture.seen.lock().unwrap();
            seen.settlement_status = 200;
            seen.evidence_status = 201;
        }
        eventually(|| records(&fixture.outbox).is_empty()).await;
        {
            let seen = fixture.seen.lock().unwrap();
            assert!(seen.receipts.is_empty());
            assert_eq!(seen.completed.len(), 1);
            assert_eq!(seen.errors_5xx, 1);
            assert!(
                seen.settlement_attempts
                    .iter()
                    .all(|attempt| attempt["completions"][0]["status_code"] == 503)
            );
        }
        fixture.seen.lock().unwrap().origin_status = 200;
        let resumed = fixture.request().await;
        assert!(
            resumed.line.contains("200"),
            "committed 5xx settlement did not resume admission: {resumed:?}"
        );
        assert_eq!(resumed.body, RESPONSE);
        eventually(|| records(&fixture.outbox).is_empty()).await;
        let seen = fixture.seen.lock().unwrap();
        assert_eq!(seen.evaluations, 2);
        assert_eq!(seen.origin_connections, 2);
        assert_eq!(seen.completed.len(), 2);
        assert!(seen.receipts.is_empty());
        assert_eq!(seen.errors_5xx, 1);
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn missing_or_conflicting_settlement_proof_never_dequeues_a_final_status() {
    timeout(LIMIT, async {
        for result in ["missing", "conflict"] {
            let fixture = Fixture::start(128).await;
            {
                let mut seen = fixture.seen.lock().unwrap();
                seen.origin_status = 503;
                seen.settlement_result = result;
            }
            assert_eq!(fixture.request().await.body, RESPONSE);
            eventually(|| !fixture.seen.lock().unwrap().settlement_attempts.is_empty()).await;
            let pending = records(&fixture.outbox);
            assert_eq!(pending.len(), 1);
            assert_eq!(pending[0]["status"], 503);
            assert_eq!(pending[0]["settled"], false);
            {
                let seen = fixture.seen.lock().unwrap();
                assert_eq!(seen.receipts.len(), 1);
                assert!(seen.completed.is_empty());
                assert_eq!(seen.errors_5xx, 0);
            }
            fixture.seen.lock().unwrap().settlement_result = "committed";
            eventually(|| records(&fixture.outbox).is_empty()).await;
            assert_eq!(fixture.seen.lock().unwrap().errors_5xx, 1);
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn mismatched_queued_audit_identity_retains_local_job_until_verified_handoff() {
    timeout(LIMIT, async {
        let fixture = Fixture::start(128).await;
        {
            let mut seen = fixture.seen.lock().unwrap();
            seen.audit_status = 202;
            seen.audit_ack_event_id = Some(uuid::Uuid::nil().to_string());
        }
        assert_eq!(fixture.request().await.body, RESPONSE);
        eventually(|| !fixture.seen.lock().unwrap().audit_attempts.is_empty()).await;
        let pending = records(&fixture.outbox);
        assert_eq!(
            pending.len(),
            1,
            "mismatched durable handoff discarded the local job"
        );
        let stable_id = pending[0]["event_id"].as_str().unwrap().to_owned();
        fixture.seen.lock().unwrap().audit_ack_event_id = None;
        eventually(|| records(&fixture.outbox).is_empty()).await;
        let seen = fixture.seen.lock().unwrap();
        assert!(seen.audit_attempts.len() >= 2);
        assert!(seen.audit_attempts.iter().all(|(id, _)| id == &stable_id));
        assert_eq!(seen.origin_connections, 1);
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn tampered_pending_artifact_fails_restart_closed_without_losing_record_or_receipt() {
    timeout(LIMIT, async {
        let mut fixture = Fixture::start(128).await;
        {
            let mut seen = fixture.seen.lock().unwrap();
            seen.evidence_status = 503;
            seen.settlement_status = 503;
        }
        assert_eq!(fixture.request().await.body, RESPONSE);
        fixture.crash().await;
        let mut pending = records(&fixture.outbox).pop().unwrap();
        let original = pending["artifact"].as_str().unwrap().to_owned();
        pending["artifact"] = serde_json::json!(original.replace(&hex(RESPONSE), "00"));
        let record_path = fixture
            .outbox
            .join(format!("{}.json", pending["event_id"].as_str().unwrap()));
        fs::write(&record_path, serde_json::to_vec(&pending).unwrap()).unwrap();
        let output = fixture.rejected_restart().await;
        assert!(
            !output.status.success(),
            "corrupt WAL allowed the proxy to start"
        );
        assert!(!String::from_utf8_lossy(&output.stdout).contains("Listening on"));
        assert_eq!(
            records(&fixture.outbox),
            vec![pending],
            "startup discarded corrupt evidence"
        );
        let seen = fixture.seen.lock().unwrap();
        assert_eq!(seen.origin_connections, 1);
        assert_eq!(seen.receipts.len(), 1);
        assert!(seen.completed.is_empty());
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn crash_with_incomplete_intent_preserves_receipt_and_reconciles_without_replaying_origin() {
    timeout(LIMIT, async {
        let mut fixture = Fixture::start(128).await;
        {
            let mut seen = fixture.seen.lock().unwrap();
            seen.stall_origin = true;
            seen.evidence_status = 503;
        }
        let foreground = fixture.send().await;
        eventually(|| !fixture.seen.lock().unwrap().origins.is_empty()).await;
        let pending = records(&fixture.outbox);
        assert_eq!(pending.len(), 1);
        assert!(pending[0]["status"].is_null());
        let id = pending[0]["event_id"].clone();
        fixture.crash().await;
        drop(foreground);
        fixture.seen.lock().unwrap().evidence_status = 201;
        fixture.restart().await;
        eventually(|| !fixture.seen.lock().unwrap().artifacts.is_empty()).await;
        let denied = fixture.request().await;
        assert!(denied.line.contains("503"), "{denied:?}");
        assert!(
            String::from_utf8_lossy(&denied.body).contains("OUTBOX"),
            "{denied:?}"
        );
        let seen = fixture.seen.lock().unwrap();
        assert_eq!(
            seen.origin_connections, 1,
            "incomplete recovery must not re-execute target request"
        );
        assert_eq!(
            seen.receipts.len(),
            1,
            "unknown origin status consumed the worker receipt"
        );
        assert!(seen.completed.is_empty());
        assert!(seen.settlement_attempts.is_empty());
        let artifact: Value = serde_json::from_slice(seen.artifacts.last().unwrap()).unwrap();
        assert_eq!(artifact["event_id"], id);
        assert!(artifact["response"]["status"].is_null());
        assert_eq!(artifact["response"]["complete"], false);
        assert_eq!(artifact["request"]["body_hex"], hex(REQUEST));
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn finalized_delivery_survives_foreground_disconnect_and_killswitch() {
    timeout(LIMIT, async {
        let fixture = Fixture::start(128).await;
        {
            let mut seen = fixture.seen.lock().unwrap();
            seen.evidence_status = 503;
            seen.settlement_status = 503;
        }
        let foreground = fixture.send().await;
        eventually(|| {
            records(&fixture.outbox)
                .iter()
                .any(|record| record["status"] == 200)
        })
        .await;
        // The caller drops its socket without reading any response bytes.
        drop(BufReader::new(foreground));
        fixture
            .seen
            .lock()
            .unwrap()
            .stop_sender
            .as_ref()
            .unwrap()
            .send(())
            .unwrap();
        fixture.wait_stopped().await;
        eventually(|| {
            let records = records(&fixture.outbox);
            records.len() == 1 && records[0]["artifact"].is_string()
        })
        .await;
        {
            let mut seen = fixture.seen.lock().unwrap();
            seen.evidence_status = 201;
            seen.settlement_status = 200;
        }
        eventually(|| records(&fixture.outbox).is_empty()).await;
        let denied = fixture.request().await;
        assert!(
            denied.line.contains("412"),
            "killswitch did not continue to deny egress: {denied:?}"
        );
        let seen = fixture.seen.lock().unwrap();
        assert_eq!(seen.origin_connections, 1);
        assert_eq!(seen.completed.len(), 1);
        assert!(seen.receipts.is_empty());
        assert_eq!(seen.ledger.len(), 1);
        assert_binary_artifact(seen.artifacts.last().unwrap());
    })
    .await
    .unwrap();
}
