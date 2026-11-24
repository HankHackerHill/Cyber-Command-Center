//! Clients for M2 state, M3 admission, and ADR-0012's proposed completion API.
//! Each successful evaluation reserves a worker in M3 and must be settled.

use reqwest::{Client, Response, StatusCode, Url};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use sha2::{Digest, Sha256};
use std::{net::IpAddr, num::NonZeroU64, time::Duration};
use uuid::Uuid;

#[derive(Clone)]
pub struct PolicyClient {
    http: Client,
    orchestrator: Url,
    policy: Url,
}

#[derive(Debug, PartialEq, Eq)]
pub enum StateError {
    PreconditionFailed,
    Unavailable,
}

#[derive(Debug, PartialEq, Eq)]
pub enum EvaluationError {
    Denied(String),
    Unavailable,
}

#[derive(Debug, PartialEq, Eq)]
pub enum CompletionError {
    InvalidStatus,
    Rejected(StatusCode),
    Unavailable,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CompletionOutcome {
    OriginStatus(u16),
    NoOriginResponse,
}

/// These fields refer to the exact raw manifest whose digest selects M3's
/// provisioned file. The caller supplies only its assessment ID.
pub struct BoundManifest {
    digest: String,
    engagement_id: Uuid,
    breaker_threshold: NonZeroU64,
}

impl BoundManifest {
    /// `expected_digest` and `document` must come from operator provisioning.
    /// M3 validates the complete frozen schema before granting a reservation.
    pub fn from_provisioned(
        engagement_id: Uuid,
        expected_digest: &str,
        document: &[u8],
    ) -> Result<Self, &'static str> {
        #[derive(Deserialize)]
        struct ManifestFields {
            engagement_id: Uuid,
            traffic_constraints: Constraints,
        }
        #[derive(Deserialize)]
        struct Constraints {
            circuit_breaker_5xx_threshold: NonZeroU64,
        }
        let digest = format!("{:x}", Sha256::digest(document));
        if digest != expected_digest {
            return Err("manifest digest mismatch");
        }
        let fields: ManifestFields =
            serde_json::from_slice(document).map_err(|_| "invalid manifest binding")?;
        if fields.engagement_id != engagement_id {
            return Err("manifest belongs to a different engagement");
        }
        Ok(Self {
            digest,
            engagement_id,
            breaker_threshold: fields.traffic_constraints.circuit_breaker_5xx_threshold,
        })
    }

    pub fn engagement_id(&self) -> Uuid {
        self.engagement_id
    }

    pub fn breaker_threshold(&self) -> NonZeroU64 {
        self.breaker_threshold
    }
}

#[derive(Serialize)]
pub struct PolicyRequest<'a> {
    pub method: &'a str,
    pub host: &'a str,
    pub ip: IpAddr,
    pub path: &'a str,
    pub ts: &'a str,
}

fn service_origin(value: &str) -> Result<Url, &'static str> {
    let url = Url::parse(value).map_err(|_| "invalid service origin")?;
    if !matches!(url.scheme(), "http" | "https")
        || !url.has_host()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.path() != "/"
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err("expected an HTTP(S) service origin");
    }
    Ok(url)
}

async fn read_json<T: DeserializeOwned>(mut response: Response) -> Option<T> {
    const MAX_BODY: usize = 8 * 1024;
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await.ok()? {
        if chunk.len() > MAX_BODY - body.len() {
            return None;
        }
        body.extend_from_slice(&chunk);
    }
    serde_json::from_slice(&body).ok()
}

impl PolicyClient {
    pub fn new(orchestrator_origin: &str, policy_origin: &str) -> Result<Self, &'static str> {
        let orchestrator = service_origin(orchestrator_origin)?;
        let policy = service_origin(policy_origin)?;
        let http = Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .retry(reqwest::retry::never())
            .timeout(Duration::from_secs(2))
            .build()
            .map_err(|_| "could not create service client")?;
        Ok(Self {
            http,
            orchestrator,
            policy,
        })
    }

    /// This checks invariant 3 only. M3 separately enforces active validation.
    pub async fn check_state(&self, id: Uuid) -> Result<(), StateError> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct StateResponse {
            state: String,
        }
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Missing {
            reason: String,
        }
        let mut url = self.orchestrator.clone();
        url.set_path(&format!("/engagements/{id}/state"));
        let response = self
            .http
            .get(url)
            .send()
            .await
            .map_err(|_| StateError::Unavailable)?;
        match response.status() {
            StatusCode::OK => (),
            StatusCode::NOT_FOUND => {
                return match read_json::<Missing>(response).await {
                    Some(error) if error.reason == "ENGAGEMENT_NOT_FOUND" => {
                        Err(StateError::PreconditionFailed)
                    }
                    _ => Err(StateError::Unavailable),
                };
            }
            _ => return Err(StateError::Unavailable),
        }
        let state: StateResponse = read_json(response).await.ok_or(StateError::Unavailable)?;
        match state.state.as_str() {
            "INIT_SCOPING" | "HALTED_KILLSWITCH" | "COMPLETED_ARCHIVED" => {
                Err(StateError::PreconditionFailed)
            }
            "ROE_LOCKED"
            | "DISCOVERY_PASSIVE"
            | "ANALYTICAL_TRIAGE"
            | "AWAITING_HITL_GATE"
            | "CONTROLLED_VALIDATION"
            | "EVIDENCE_VERIFICATION"
            | "REMEDIATION_SYNTHESIS"
            | "RETEST_VERIFICATION" => Ok(()),
            _ => Err(StateError::Unavailable),
        }
    }

    /// M2 records the durable stop and publishes to Redis after commit.
    /// The operation is idempotent, including a retry after publication fails.
    pub async fn halt(&self, id: Uuid) -> Result<(), StateError> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct StopResponse {
            status: String,
            next_state: String,
            #[serde(rename = "ledger_hash")]
            _ledger_hash: Option<String>,
            notification_published: bool,
        }
        let mut url = self.orchestrator.clone();
        url.set_path(&format!("/engagements/{id}/killswitch"));
        let response = self
            .http
            .post(url)
            .send()
            .await
            .map_err(|_| StateError::Unavailable)?;
        if response.status() != StatusCode::OK {
            return Err(StateError::Unavailable);
        }
        let stop: StopResponse = read_json(response).await.ok_or(StateError::Unavailable)?;
        if stop.status == "halted"
            && stop.next_state == "HALTED_KILLSWITCH"
            && stop.notification_published
        {
            Ok(())
        } else {
            Err(StateError::Unavailable)
        }
    }

    /// The returned UUID belongs to exactly one admission. Do not retry this
    /// operation on timeout or use it to probe policy availability.
    pub async fn evaluate(
        &self,
        manifest: &BoundManifest,
        request: &PolicyRequest<'_>,
    ) -> Result<Uuid, EvaluationError> {
        #[derive(Serialize)]
        struct Evaluation<'a> {
            manifest_hash: &'a str,
            request: &'a PolicyRequest<'a>,
        }
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Decision {
            allow: bool,
            reason: String,
        }
        let mut evaluate_url = self.policy.clone();
        evaluate_url.set_path("/evaluate");
        let response = self
            .http
            .post(evaluate_url)
            .json(&Evaluation {
                manifest_hash: &manifest.digest,
                request,
            })
            .send()
            .await
            .map_err(|_| EvaluationError::Unavailable)?;
        let status = response.status();
        if status != StatusCode::OK && status != StatusCode::FORBIDDEN {
            return Err(EvaluationError::Unavailable);
        }
        let mut receipts = response.headers().get_all("X-Policy-Reservation").iter();
        let receipt = receipts
            .next()
            .and_then(|v| v.to_str().ok())
            .and_then(|v| Uuid::parse_str(v).ok());
        let duplicate = receipts.next().is_some();
        let decision: Decision = read_json(response)
            .await
            .ok_or(EvaluationError::Unavailable)?;
        if decision.reason.trim().is_empty() {
            return Err(EvaluationError::Unavailable);
        }
        if !decision.allow {
            return Err(EvaluationError::Denied(decision.reason));
        }
        if status != StatusCode::OK || duplicate {
            return Err(EvaluationError::Unavailable);
        }
        receipt.ok_or(EvaluationError::Unavailable)
    }

    /// Settle one reservation with its observed outcome. A lost or invalid
    /// acknowledgement leaves settlement unconfirmed. ADR-0012 permits a retry
    /// with the same receipt and status.
    pub async fn complete(
        &self,
        id: Uuid,
        reservation: Uuid,
        outcome: CompletionOutcome,
    ) -> Result<bool, CompletionError> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Acknowledgement {
            breaker_tripped: bool,
        }
        let body = match outcome {
            CompletionOutcome::OriginStatus(status @ 200..=599) => {
                serde_json::json!({"status_code":status})
            }
            CompletionOutcome::OriginStatus(_) => return Err(CompletionError::InvalidStatus),
            CompletionOutcome::NoOriginResponse => {
                serde_json::json!({"outcome":"no_origin_response"})
            }
        };
        let mut url = self.policy.clone();
        url.set_path(&format!("/engagements/{id}/completions"));
        let response = self
            .http
            .post(url)
            .header("X-Policy-Reservation", reservation.to_string())
            .json(&body)
            .send()
            .await
            .map_err(|_| CompletionError::Unavailable)?;
        match response.status() {
            StatusCode::OK => read_json::<Acknowledgement>(response)
                .await
                .map(|ack| ack.breaker_tripped)
                .ok_or(CompletionError::Unavailable),
            status @ (StatusCode::NOT_FOUND
            | StatusCode::CONFLICT
            | StatusCode::UNPROCESSABLE_ENTITY) => Err(CompletionError::Rejected(status)),
            _ => Err(CompletionError::Unavailable),
        }
    }
}
