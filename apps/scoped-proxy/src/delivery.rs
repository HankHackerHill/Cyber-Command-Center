//! Bounded, fsync-backed write-ahead evidence outbox. A socket may only be
//! opened after `begin`; responses require `finish`. Remote outages retain
//! records and reservations rather than silently losing the tee.
use crate::{evidence_client::EvidenceClient, policy_client::PolicyClient};
use bytes::Bytes;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::{HashMap, HashSet},
    env,
    fs::{self, File, OpenOptions},
    io::{self, Write},
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};
use uuid::Uuid;

pub const MAX_RECORD_BYTES: usize = 8 * 1024 * 1024;
#[derive(Debug)]
pub struct OutboxUnavailable;

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Record {
    pub event_id: Uuid,
    pub engagement_id: Uuid,
    pub reservation: Uuid,
    pub request: Value,
    pub artifact: Option<String>,
    pub status: Option<u16>,
    pub settled: bool,
    pub event_type: String,
    pub audit_payload: Value,
}
struct State {
    records: HashMap<Uuid, Arc<Record>>,
    blocked: HashSet<Uuid>,
    recovering: HashSet<Uuid>,
    pending_5xx: HashMap<Uuid, HashSet<Uuid>>,
    delivery: DeliveryState,
}
#[derive(Default)]
struct DeliveryState {
    in_flight: HashSet<Uuid>,
    handed_off: HashSet<Uuid>,
    retries: HashMap<Uuid, (Instant, Duration)>,
}
struct DeliveryClaim {
    record: Arc<Record>,
    handed_off: bool,
}
struct Inner {
    dir: PathBuf,
    _lock: File,
    capacity: usize,
    slots: Arc<tokio::sync::Semaphore>,
    healthy: AtomicBool,
    // Acquired only by spawn_blocking writers. Runtime State readers must
    // never wait for a filesystem operation or this writer lock.
    writer: Mutex<()>,
    state: Mutex<State>,
    changed: tokio::sync::Notify,
}
#[derive(Clone)]
pub struct Outbox(Arc<Inner>);

fn atomic_write(dir: &Path, record: &Record) -> io::Result<()> {
    #[cfg(test)]
    tests::pause_io(dir);
    let bytes = serde_json::to_vec(record)?;
    if bytes.len() > MAX_RECORD_BYTES {
        return Err(io::Error::other("outbox record too large"));
    }
    let temporary = dir.join(format!(".{}.tmp", Uuid::new_v4()));
    let result = (|| {
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(&temporary)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        fs::rename(&temporary, dir.join(format!("{}.json", record.event_id)))?;
        File::open(dir)?.sync_all()
    })();
    if result.is_err() {
        let _ = fs::remove_file(temporary);
    }
    result
}

impl Outbox {
    pub fn from_environment() -> Result<Option<Self>, &'static str> {
        let Some(path) = env::var_os("SCOPED_PROXY_OUTBOX_DIR") else {
            return Ok(None);
        };
        let number = |name: &str, default: usize| -> Result<usize, &'static str> {
            env::var(name)
                .map(|s| s.parse().map_err(|_| "invalid outbox limit"))
                .unwrap_or(Ok(default))
        };
        // Reserve double the maximum record size, covering atomic replacement
        // temporaries as well as accepted records within the configured bound.
        let capacity = number("SCOPED_PROXY_OUTBOX_MAX_RECORDS", 128)?.min(
            number("SCOPED_PROXY_OUTBOX_MAX_BYTES", 256 * 1024 * 1024)? / (2 * MAX_RECORD_BYTES),
        );
        if capacity == 0 {
            return Err("outbox capacity is below one maximum record");
        }
        let dir = PathBuf::from(path);
        if !dir.exists() {
            fs::create_dir_all(&dir).map_err(|_| "cannot create outbox")?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(&dir, fs::Permissions::from_mode(0o700))
                    .map_err(|_| "cannot secure outbox")?;
            }
            for ancestor in dir
                .ancestors()
                .skip(1)
                .filter(|p| !p.as_os_str().is_empty())
            {
                File::open(ancestor)
                    .and_then(|f| f.sync_all())
                    .map_err(|_| "cannot sync outbox parent")?;
            }
        }
        if !fs::symlink_metadata(&dir)
            .map_err(|_| "invalid outbox")?
            .is_dir()
        {
            return Err("outbox must be a directory");
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if fs::metadata(&dir)
                .map_err(|_| "invalid outbox")?
                .permissions()
                .mode()
                & 0o077
                != 0
            {
                return Err("existing outbox directory must be private");
            }
        }
        if let Ok(meta) = fs::symlink_metadata(dir.join(".lock"))
            && !meta.is_file()
        {
            return Err("invalid outbox lock");
        }
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(dir.join(".lock"))
            .map_err(|_| "cannot open outbox lock")?;
        lock.try_lock().map_err(|_| "outbox already owned")?;
        let mut records = HashMap::new();
        let mut blocked = HashSet::new();
        let mut recovering = HashSet::new();
        let mut reservations = HashSet::new();
        let mut pending_5xx: HashMap<Uuid, HashSet<Uuid>> = HashMap::new();
        for entry in fs::read_dir(&dir).map_err(|_| "cannot read outbox")? {
            let entry = entry.map_err(|_| "cannot read outbox entry")?;
            let name = entry.file_name();
            let name = name.to_str().ok_or("invalid outbox filename")?;
            if name == ".lock" {
                continue;
            }
            // Temporary files were never accepted. A previous process cannot
            // still own them because the exclusive directory lock is held.
            if name.starts_with('.') && name.ends_with(".tmp") {
                fs::remove_file(entry.path()).map_err(|_| "cannot clean outbox temporary")?;
                continue;
            }
            let id = name
                .strip_suffix(".json")
                .and_then(|s| Uuid::parse_str(s).ok())
                .ok_or("unexpected outbox entry")?;
            if name != format!("{id}.json") {
                return Err("noncanonical outbox filename");
            }
            let meta = fs::symlink_metadata(entry.path()).map_err(|_| "invalid outbox entry")?;
            if !meta.is_file() || meta.len() > MAX_RECORD_BYTES as u64 {
                return Err("invalid outbox record");
            }
            let mut record: Record = serde_json::from_slice(
                &fs::read(entry.path()).map_err(|_| "unreadable outbox record")?,
            )
            .map_err(|_| "corrupt outbox record")?;
            if record.event_id != id || !record.valid() {
                return Err("invalid outbox identity or status");
            }
            if !reservations.insert((record.engagement_id, record.reservation)) {
                return Err("duplicate outbox reservation");
            }
            if record.artifact.is_none() {
                record.complete(None, None, "CRASH_RECOVERY");
                atomic_write(&dir, &record).map_err(|_| "cannot recover outbox intent")?;
            }
            if record.status.is_none() {
                blocked.insert(record.engagement_id);
            } else if !record.settled {
                recovering.insert(record.engagement_id);
                if record.status.is_some_and(|s| s >= 500) {
                    pending_5xx
                        .entry(record.engagement_id)
                        .or_default()
                        .insert(record.reservation);
                }
            }
            records.insert(id, Arc::new(record));
        }
        if records.len() > capacity {
            return Err("outbox exceeds configured capacity");
        }
        let slots = Arc::new(tokio::sync::Semaphore::new(capacity - records.len()));
        File::open(&dir)
            .and_then(|f| f.sync_all())
            .map_err(|_| "cannot sync outbox directory")?;
        Ok(Some(Self(Arc::new(Inner {
            dir,
            _lock: lock,
            capacity,
            slots,
            healthy: AtomicBool::new(true),
            writer: Mutex::new(()),
            state: Mutex::new(State {
                records,
                blocked,
                recovering,
                pending_5xx,
                delivery: DeliveryState::default(),
            }),
            changed: tokio::sync::Notify::new(),
        }))))
    }

    pub fn available(&self, id: Uuid) -> bool {
        let state = self.0.state.lock().unwrap();
        self.0.healthy.load(Ordering::Acquire)
            && state.records.len() < self.0.capacity
            && !state.blocked.contains(&id)
            && !state.recovering.contains(&id)
            && !state.pending_5xx.contains_key(&id)
    }
    pub fn admission_blocked(&self, id: Uuid) -> bool {
        let state = self.0.state.lock().unwrap();
        !self.0.healthy.load(Ordering::Acquire)
            || state.blocked.contains(&id)
            || state.recovering.contains(&id)
            || state.pending_5xx.contains_key(&id)
    }
    /// Final status observation precedes any await or later admission. A 5xx
    /// remains an admission barrier until shared cumulative accounting proves
    /// its exactly-once commit; a local consecutive streak is insufficient.
    pub fn observe_status(&self, id: Uuid, reservation: Uuid, status: u16) {
        if status >= 500 {
            self.0
                .state
                .lock()
                .unwrap()
                .pending_5xx
                .entry(id)
                .or_default()
                .insert(reservation);
        }
    }
    pub fn try_reserve(&self, id: Uuid) -> Option<tokio::sync::OwnedSemaphorePermit> {
        if !self.available(id) {
            return None;
        }
        self.0.slots.clone().try_acquire_owned().ok()
    }
    pub async fn begin(
        &self,
        engagement_id: Uuid,
        reservation: Uuid,
        request: Value,
        slot: tokio::sync::OwnedSemaphorePermit,
    ) -> Result<Uuid, OutboxUnavailable> {
        let record = Record {
            event_id: Uuid::new_v4(),
            engagement_id,
            reservation,
            request,
            artifact: None,
            status: None,
            settled: false,
            event_type: String::new(),
            audit_payload: Value::Null,
        };
        let id = record.event_id;
        let this = self.clone();
        tokio::task::spawn_blocking(move || {
            let _writer = this.0.writer.lock().unwrap();
            let state = this.0.state.lock().unwrap();
            if !this.0.healthy.load(Ordering::Acquire)
                || state.records.len() >= this.0.capacity
                || state.blocked.contains(&engagement_id)
                || state.recovering.contains(&engagement_id)
            {
                return Err(OutboxUnavailable);
            }
            drop(state);
            atomic_write(&this.0.dir, &record).map_err(|_| {
                this.0.healthy.store(false, Ordering::Release);
                OutboxUnavailable
            })?;
            this.0
                .state
                .lock()
                .unwrap()
                .records
                .insert(id, Arc::new(record));
            slot.forget();
            Ok(id)
        })
        .await
        .map_err(|_| OutboxUnavailable)?
    }
    /// Retain the captured final result in this owned future and stop new
    /// admissions on local storage failure. Never return an undurable result.
    pub async fn finish(
        &self,
        id: Uuid,
        artifact: Option<String>,
        status: Option<u16>,
        error: &str,
    ) {
        let mut record = (*self.0.state.lock().unwrap().records[&id]).clone();
        record.complete(artifact, status, error);
        loop {
            let this = self.clone();
            let record = record.clone();
            let written = tokio::task::spawn_blocking(move || {
                let _writer = this.0.writer.lock().unwrap();
                atomic_write(&this.0.dir, &record)?;
                let mut state = this.0.state.lock().unwrap();
                if record.status.is_none() {
                    state.blocked.insert(record.engagement_id);
                }
                state.records.insert(id, Arc::new(record));
                Ok::<_, io::Error>(())
            })
            .await;
            if matches!(written, Ok(Ok(()))) {
                self.0.changed.notify_waiters();
                return;
            }
            self.0.healthy.store(false, Ordering::Release);
            eprintln!(
                "Outbox finalization failed for {id}; retaining result and denying new admissions"
            );
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }

    fn ready(&self) -> Vec<Arc<Record>> {
        self.0
            .state
            .lock()
            .unwrap()
            .records
            .values()
            .filter(|r| r.artifact.is_some())
            .cloned()
            .collect()
    }

    async fn mark_settled(&self, ids: Vec<Uuid>) {
        let this = self.clone();
        let _ = tokio::task::spawn_blocking(move || {
            let _writer = this.0.writer.lock().unwrap();
            for id in ids {
                let Some(old) = this.0.state.lock().unwrap().records.get(&id).cloned() else {
                    continue;
                };
                let mut record = (*old).clone();
                record.settled = true;
                if atomic_write(&this.0.dir, &record).is_err() {
                    this.0.healthy.store(false, Ordering::Release);
                    continue;
                }
                let mut state = this.0.state.lock().unwrap();
                state.records.insert(id, Arc::new(record));
                let record = state.records[&id].clone();
                if let Some(pending) = state.pending_5xx.get_mut(&record.engagement_id) {
                    pending.remove(&record.reservation);
                    if pending.is_empty() {
                        state.pending_5xx.remove(&record.engagement_id);
                    }
                }
            }
            let mut state = this.0.state.lock().unwrap();
            let pending: HashSet<_> = state
                .records
                .values()
                .filter(|r| r.status.is_some() && !r.settled)
                .map(|r| r.engagement_id)
                .collect();
            state.recovering.retain(|id| pending.contains(id));
        })
        .await;
        self.0.changed.notify_waiters();
    }

    async fn remove(&self, id: Uuid) -> Result<bool, OutboxUnavailable> {
        let this = self.clone();
        tokio::task::spawn_blocking(move || {
            let _writer = this.0.writer.lock().unwrap();
            let Some(record) = this.0.state.lock().unwrap().records.get(&id).cloned() else {
                return Ok(true);
            };
            // Incomplete records are reconciliation receipts: preserve them
            // across restart even after their evidence and audit are durable.
            if record.status.is_none() || !record.settled {
                return Ok(false);
            }
            #[cfg(test)]
            tests::pause_io(&this.0.dir);
            if fs::remove_file(this.0.dir.join(format!("{id}.json")))
                .and_then(|()| File::open(&this.0.dir)?.sync_all())
                .is_ok()
            {
                let mut state = this.0.state.lock().unwrap();
                state.records.remove(&id);
                state.delivery.handed_off.remove(&id);
                state.delivery.retries.remove(&id);
                this.0.slots.add_permits(1);
                Ok(true)
            } else {
                this.0.healthy.store(false, Ordering::Release);
                Err(OutboxUnavailable)
            }
        })
        .await
        .map_err(|_| OutboxUnavailable)?
    }

    fn claim_delivery(&self) -> (Option<DeliveryClaim>, Duration) {
        let mut state = self.0.state.lock().unwrap();
        let now = Instant::now();
        let mut wait = Duration::from_secs(1);
        let candidate = state.records.values().find_map(|record| {
            let id = record.event_id;
            if record.artifact.is_none() || state.delivery.in_flight.contains(&id) {
                return None;
            }
            let handed_off = state.delivery.handed_off.contains(&id);
            if handed_off && (record.status.is_none() || !record.settled) {
                return None;
            }
            if let Some((retry_at, _)) = state.delivery.retries.get(&id)
                && *retry_at > now
            {
                wait = wait.min(retry_at.saturating_duration_since(now));
                return None;
            }
            Some(DeliveryClaim {
                record: record.clone(),
                handed_off,
            })
        });
        if let Some(claim) = &candidate {
            state.delivery.in_flight.insert(claim.record.event_id);
        }
        (candidate, wait)
    }

    fn finish_claim(&self, id: Uuid, failed: bool) {
        let mut state = self.0.state.lock().unwrap();
        state.delivery.in_flight.remove(&id);
        if failed && state.records.contains_key(&id) {
            let delay = state
                .delivery
                .retries
                .get(&id)
                .map_or(Duration::from_millis(20), |(_, previous)| {
                    previous.saturating_mul(2).min(Duration::from_secs(1))
                });
            state
                .delivery
                .retries
                .insert(id, (Instant::now() + delay, delay));
        } else {
            state.delivery.retries.remove(&id);
        }
        drop(state);
        self.0.changed.notify_waiters();
    }

    async fn deliver_claim(
        &self,
        claim: DeliveryClaim,
        evidence: &EvidenceClient,
        policy: &PolicyClient,
    ) {
        let record = claim.record;
        let acknowledged = claim.handed_off
            || (evidence
                .put(Bytes::from(
                    record
                        .artifact
                        .as_ref()
                        .expect("claimed finalized artifact")
                        .clone(),
                ))
                .await
                .is_ok()
                && policy
                    .audit_event_durable(
                        record.engagement_id,
                        record.event_id,
                        &record.event_type,
                        record.audit_payload.clone(),
                    )
                    .await
                    .is_ok());
        let failed = if acknowledged {
            // This memo avoids duplicate uploads while waiting for M3. It is
            // intentionally volatile: restart re-proves the same immutable
            // handoff using the persisted artifact and idempotency key.
            self.0
                .state
                .lock()
                .unwrap()
                .delivery
                .handed_off
                .insert(record.event_id);
            record.status.is_some() && self.remove(record.event_id).await.is_err()
        } else {
            true
        };
        self.finish_claim(record.event_id, failed);
    }

    pub fn start(
        &self,
        evidence: EvidenceClient,
        policy: PolicyClient,
        accounting_gates: HashMap<Uuid, Arc<tokio::sync::Mutex<()>>>,
    ) {
        let accounting = self.clone();
        let accounting_policy = policy.clone();
        tokio::spawn(async move {
            loop {
                let mut groups: HashMap<Uuid, Vec<Arc<Record>>> = HashMap::new();
                for record in accounting
                    .ready()
                    .into_iter()
                    .filter(|r| !r.settled && r.status.is_some())
                {
                    groups.entry(record.engagement_id).or_default().push(record);
                }
                for (id, records) in groups {
                    let Some(gate) = accounting_gates.get(&id) else {
                        continue;
                    };
                    // Keep confirmation bodies inside PolicyClient's 8KiB
                    // bounded JSON parser even though M3 permits 256 items.
                    for batch in records.chunks(64) {
                        let completions: Vec<_> = batch
                            .iter()
                            .map(|r| (r.reservation, r.status.unwrap()))
                            .collect();
                        let confirmation = {
                            let _accounting_guard = gate.lock().await;
                            accounting_policy.settle_batch(id, &completions).await
                        };
                        // M3 has finished its atomic mutation. Local fsync may
                        // wait for the writer without holding admission; 5xx
                        // barriers remain latched until mark_settled persists.
                        if let Ok(committed) = confirmation {
                            accounting
                                .mark_settled(
                                    batch
                                        .iter()
                                        .filter(|r| committed.contains(&r.reservation))
                                        .map(|r| r.event_id)
                                        .collect(),
                                )
                                .await;
                        }
                    }
                }
                tokio::time::sleep(Duration::from_millis(2)).await;
            }
        });
        for _ in 0..8 {
            let delivery = self.clone();
            let evidence = evidence.clone();
            let policy = policy.clone();
            tokio::spawn(async move {
                loop {
                    // Register before checking state so a finish/settlement
                    // notification cannot race the transition to sleeping.
                    let notified = delivery.0.changed.notified();
                    tokio::pin!(notified);
                    notified.as_mut().enable();
                    let (claim, wait) = delivery.claim_delivery();
                    if let Some(claim) = claim {
                        delivery.deliver_claim(claim, &evidence, &policy).await;
                    } else {
                        tokio::select! { () = &mut notified => (), () = tokio::time::sleep(wait) => () }
                    }
                }
            });
        }
    }
}

impl Record {
    fn valid(&self) -> bool {
        if self.status.is_some_and(|s| !(200..=599).contains(&s)) {
            return false;
        }
        let Some(artifact) = &self.artifact else {
            return self.status.is_none()
                && !self.settled
                && self.request.is_object()
                && self.event_type.is_empty()
                && self.audit_payload.is_null();
        };
        let Ok(value) = serde_json::from_str::<Value>(artifact) else {
            return false;
        };
        value["engagement_id"] == json!(self.engagement_id)
            && value["event_id"] == json!(self.event_id)
            && value["reservation"] == json!(self.reservation)
            && value["response"]["status"] == json!(self.status)
            && value["request"] == self.request
            && self.audit_payload["status"] == json!(self.status)
            && self.audit_payload["reservation"] == json!(self.reservation)
            && self.audit_payload["evidence_acknowledged"] == json!(true)
            && self.audit_payload["evidence_sha256"]
                == json!(format!("{:x}", Sha256::digest(artifact.as_bytes())))
            && self.event_type
                == if self.status.is_some() {
                    "PROXY_REQUEST_COMPLETED"
                } else {
                    "PROXY_REQUEST_INCOMPLETE"
                }
            && (self.status.is_some() || !self.settled)
    }
    fn complete(&mut self, artifact: Option<String>, status: Option<u16>, error: &str) {
        self.status = status;
        let artifact = artifact.unwrap_or_else(|| json!({"engagement_id":self.engagement_id,"event_id":self.event_id,"reservation":self.reservation,"request":self.request,"response":{"status":null,"headers":[],"headers_hex":[],"body_hex":"","complete":false},"error":error}).to_string());
        self.event_type = if status.is_some() {
            "PROXY_REQUEST_COMPLETED"
        } else {
            "PROXY_REQUEST_INCOMPLETE"
        }
        .into();
        self.audit_payload = json!({"evidence_sha256":format!("{:x}", Sha256::digest(artifact.as_bytes())),"evidence_acknowledged":true,"status":status,"reservation":self.reservation});
        for key in ["method", "host", "ip", "port", "path"] {
            if let Some(value) = self.request.get(key) {
                self.audit_payload[key] = value.clone();
            }
        }
        if status.is_none() {
            self.audit_payload["error"] = json!(error);
        }
        self.artifact = Some(artifact);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct IoGate {
        entered: Mutex<Option<tokio::sync::oneshot::Sender<()>>>,
        release: Mutex<std::sync::mpsc::Receiver<()>>,
    }
    static IO_GATES: std::sync::LazyLock<Mutex<HashMap<PathBuf, Arc<IoGate>>>> =
        std::sync::LazyLock::new(|| Mutex::new(HashMap::new()));

    pub(super) fn pause_io(dir: &Path) {
        let gate = IO_GATES.lock().unwrap().get(dir).cloned();
        if let Some(gate) = gate {
            if let Some(entered) = gate.entered.lock().unwrap().take() {
                let _ = entered.send(());
            }
            let _ = gate
                .release
                .lock()
                .unwrap()
                .recv_timeout(Duration::from_secs(1));
        }
    }

    fn assert_runtime_state_responsive(outbox: &Outbox) {
        let started = std::time::Instant::now();
        let engagement = Uuid::new_v4();
        assert!(outbox.available(engagement));
        outbox.observe_status(engagement, Uuid::new_v4(), 503);
        assert!(outbox.admission_blocked(engagement));
        assert!(
            started.elapsed() < Duration::from_millis(50),
            "filesystem writer blocked runtime admission/status observation"
        );
    }

    async fn blocked_io<F>(outbox: &Outbox, operation: F) -> F::Output
    where
        F: std::future::Future + Send + 'static,
        F::Output: Send + 'static,
    {
        let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        IO_GATES.lock().unwrap().insert(
            outbox.0.dir.clone(),
            Arc::new(IoGate {
                entered: Mutex::new(Some(entered_tx)),
                release: Mutex::new(release_rx),
            }),
        );
        let operation = tokio::spawn(operation);
        entered_rx.await.unwrap();
        // The operation owns the writer and has reached the actual disk-I/O
        // boundary. Holding State here would reproduce the killswitch stall.
        assert_runtime_state_responsive(outbox);
        IO_GATES.lock().unwrap().remove(&outbox.0.dir);
        release_tx.send(()).unwrap();
        operation.await.unwrap()
    }

    fn outbox() -> Outbox {
        let dir = env::temp_dir().join(format!("m4-writer-{}", Uuid::new_v4()));
        fs::create_dir(&dir).unwrap();
        let lock = File::create(dir.join(".lock")).unwrap();
        Outbox(Arc::new(Inner {
            dir,
            _lock: lock,
            capacity: 4,
            slots: Arc::new(tokio::sync::Semaphore::new(4)),
            healthy: AtomicBool::new(true),
            writer: Mutex::new(()),
            state: Mutex::new(State {
                records: HashMap::new(),
                blocked: HashSet::new(),
                recovering: HashSet::new(),
                pending_5xx: HashMap::new(),
                delivery: DeliveryState::default(),
            }),
            changed: tokio::sync::Notify::new(),
        }))
    }

    async fn blocked_writer<F>(outbox: &Outbox, operation: F) -> F::Output
    where
        F: std::future::Future + Send + 'static,
        F::Output: Send + 'static,
    {
        let (held_tx, held_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let writer = outbox.clone();
        let holder = tokio::task::spawn_blocking(move || {
            let _guard = writer.0.writer.lock().unwrap();
            held_tx.send(()).unwrap();
            // Bounded fallback also makes an accidental State/writer lock
            // inversion fail this test instead of deadlocking its runtime.
            let _ = release_rx.recv_timeout(Duration::from_secs(1));
        });
        held_rx.await.unwrap();
        let operation = tokio::spawn(operation);
        tokio::time::sleep(Duration::from_millis(10)).await;
        assert!(
            !operation.is_finished(),
            "durable writer did not wait for exclusive ownership"
        );
        assert_runtime_state_responsive(outbox);
        release_tx.send(()).unwrap();
        holder.await.unwrap();
        operation.await.unwrap()
    }

    #[tokio::test]
    async fn blocked_durable_writer_never_holds_runtime_state_during_any_write_phase() {
        let outbox = outbox();
        let engagement = Uuid::new_v4();
        let reservation = Uuid::new_v4();
        let slot = outbox.try_reserve(engagement).unwrap();
        let writer = outbox.clone();
        let id = blocked_io(&outbox, async move {
            writer
                .begin(
                    engagement,
                    reservation,
                    json!({"method":"GET","host":"localhost","body_hex":"00ff"}),
                    slot,
                )
                .await
                .unwrap()
        })
        .await;
        let durable: Record =
            serde_json::from_slice(&fs::read(outbox.0.dir.join(format!("{id}.json"))).unwrap())
                .unwrap();
        assert_eq!(durable.reservation, reservation);
        assert!(durable.artifact.is_none());
        let artifact = json!({"engagement_id":engagement,"event_id":id,"reservation":reservation,"request":durable.request,"response":{"status":200,"body_hex":"80ff","complete":true}}).to_string();
        let writer = outbox.clone();
        let expected = artifact.clone();
        blocked_io(&outbox, async move {
            writer.finish(id, Some(artifact), Some(200), "").await
        })
        .await;
        let durable: Record =
            serde_json::from_slice(&fs::read(outbox.0.dir.join(format!("{id}.json"))).unwrap())
                .unwrap();
        assert_eq!(durable.artifact.as_deref(), Some(expected.as_str()));
        assert!(!durable.settled);
        let writer = outbox.clone();
        blocked_io(&outbox, async move { writer.mark_settled(vec![id]).await }).await;
        let durable: Record =
            serde_json::from_slice(&fs::read(outbox.0.dir.join(format!("{id}.json"))).unwrap())
                .unwrap();
        assert!(durable.settled);
        let writer = outbox.clone();
        blocked_io(&outbox, async move { writer.remove(id).await })
            .await
            .unwrap();
        assert!(outbox.0.state.lock().unwrap().records.is_empty());
        assert!(!outbox.0.dir.join(format!("{id}.json")).exists());
        fs::remove_dir_all(&outbox.0.dir).unwrap();
    }

    #[tokio::test]
    async fn queued_writer_does_not_take_runtime_state_while_waiting_for_other_writer() {
        let outbox = outbox();
        let engagement = Uuid::new_v4();
        let slot = outbox.try_reserve(engagement).unwrap();
        let writer = outbox.clone();
        let id = blocked_writer(&outbox, async move {
            writer
                .begin(engagement, Uuid::new_v4(), json!({"method":"GET"}), slot)
                .await
                .unwrap()
        })
        .await;
        assert!(outbox.0.dir.join(format!("{id}.json")).is_file());
        fs::remove_dir_all(&outbox.0.dir).unwrap();
    }
}
