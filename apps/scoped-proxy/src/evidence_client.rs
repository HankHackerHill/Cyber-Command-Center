use std::{error::Error, fmt, num::NonZeroUsize, time::Duration};

use bytes::Bytes;
use reqwest::{Client, StatusCode, Url, header::CONTENT_TYPE, redirect::Policy};

#[derive(Debug)]
pub enum EvidenceError {
    InvalidOrigin,
    ArtifactTooLarge,
    Transport(reqwest::Error),
    Unacknowledged(StatusCode),
}

impl fmt::Display for EvidenceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidOrigin => f.write_str("invalid evidence service origin"),
            Self::ArtifactTooLarge => f.write_str("evidence artifact exceeds the upload limit"),
            Self::Transport(err) => write!(f, "evidence service transport error: {err}"),
            Self::Unacknowledged(status) => write!(f, "evidence upload unacknowledged ({status})"),
        }
    }
}

impl Error for EvidenceError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Transport(err) => Some(err),
            _ => None,
        }
    }
}

#[derive(Clone)]
pub struct EvidenceClient {
    http: Client,
    endpoint: Url,
    max_artifact_bytes: NonZeroUsize,
}

impl EvidenceClient {
    pub fn new(origin: &str, max_artifact_bytes: NonZeroUsize) -> Result<Self, EvidenceError> {
        let mut endpoint = Url::parse(origin).map_err(|_| EvidenceError::InvalidOrigin)?;
        if !matches!(endpoint.scheme(), "http" | "https")
            || !endpoint.has_host()
            || !endpoint.username().is_empty()
            || endpoint.password().is_some()
            || endpoint.query().is_some()
            || endpoint.fragment().is_some()
            || endpoint.path() != "/"
        {
            return Err(EvidenceError::InvalidOrigin);
        }
        endpoint.set_path("/artifacts");
        let http = Client::builder()
            .no_proxy()
            .redirect(Policy::none())
            .timeout(Duration::from_secs(2))
            .build()
            .map_err(EvidenceError::Transport)?;
        Ok(Self {
            http,
            endpoint,
            max_artifact_bytes,
        })
    }

    /// Upload already-serialized artifact bytes. Success means evidence-svc
    /// acknowledged the PUT synchronously. The service owns storage and ledger linkage.
    pub async fn put(&self, artifact: Bytes) -> Result<(), EvidenceError> {
        if artifact.len() > self.max_artifact_bytes.get() {
            return Err(EvidenceError::ArtifactTooLarge);
        }
        let status = self
            .http
            .put(self.endpoint.clone())
            .header(CONTENT_TYPE, "application/octet-stream")
            .body(artifact)
            .send()
            .await
            .map_err(EvidenceError::Transport)?
            .status();
        match status {
            StatusCode::OK | StatusCode::CREATED | StatusCode::NO_CONTENT => Ok(()),
            other => Err(EvidenceError::Unacknowledged(other)),
        }
    }
}
