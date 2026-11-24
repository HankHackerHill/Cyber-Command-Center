//! Stop admission locally before attempting to notify any other process.
//! Redis Pub/Sub has no replay. A lost subscription therefore keeps this
//! process closed. The threshold observer asks the orchestrator to persist
//! the halt and publish it on the shared Redis channel.
use std::collections::{HashMap, HashSet};
use std::num::NonZeroU64;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use futures_util::StreamExt;
use num_bigint::BigUint;
use serde::{Deserialize, Serialize};
use tokio::sync::{oneshot, watch};
use tokio::time::{sleep, timeout};
use uuid::Uuid;

use crate::policy_client::{PolicyClient, StateError};

const CHANNEL: &str = "redops:killswitch";
const REDIS_TIMEOUT: Duration = Duration::from_secs(2);
const INITIAL_RETRY_DELAY: Duration = Duration::from_millis(50);
const MAX_RETRY_DELAY: Duration = Duration::from_secs(1);

// These commands mirror AccountStore._read and AccountStore.complete in M3.
// Neither script allocates a bucket or resets an engagement's limits.
const READ_ACCOUNT: &str =
    "return {redis.call('HGET', KEYS[1], 'state'), redis.call('HLEN', KEYS[1]) - 1}";
const COMPLETE_ACCOUNT: &str = "
if redis.call('HGET', KEYS[1], ARGV[3]) ~= '1' then return 'missing' end
if redis.call('HGET', KEYS[1], 'state') ~= ARGV[1] then return 'retry' end
redis.call('HSET', KEYS[1], 'state', ARGV[2])
redis.call('HDEL', KEYS[1], ARGV[3])
return 'ok'";

#[derive(Debug, PartialEq, Eq)]
pub enum AccountingError {
    InvalidStatus,
    InvalidState,
    MissingReceipt,
    Busy,
    Unavailable,
}

// M3's nonnegative Python integers are decimal JSON numbers. Its Pydantic
// JSON parser accepts at most 4300 digits. Do not write an unreadable bucket.
mod integer {
    use num_bigint::BigUint;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use serde_json::value::RawValue;

    const MAX_DIGITS: usize = 4300;

    pub fn deserialize<'de, D: Deserializer<'de>>(input: D) -> Result<BigUint, D::Error> {
        let raw = <&RawValue>::deserialize(input)?;
        match raw.get() {
            "-0" => Ok(BigUint::ZERO),
            text if text.len() > MAX_DIGITS => Err(serde::de::Error::custom("integer too large")),
            text => BigUint::parse_bytes(text.as_bytes(), 10)
                .ok_or_else(|| serde::de::Error::custom("expected a nonnegative integer")),
        }
    }

    pub fn serialize<S: Serializer>(value: &BigUint, output: S) -> Result<S::Ok, S::Error> {
        let digits = value.to_str_radix(10);
        if digits.len() > MAX_DIGITS {
            return Err(serde::ser::Error::custom("integer too large"));
        }
        RawValue::from_string(digits)
            .map_err(serde::ser::Error::custom)?
            .serialize(output)
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Bucket {
    #[serde(with = "integer")]
    credit: BigUint,
    #[serde(with = "integer")]
    at_us: BigUint,
    #[serde(with = "integer")]
    rate: BigUint,
    #[serde(with = "integer")]
    active_workers: BigUint,
    #[serde(with = "integer")]
    errors_5xx: BigUint,
}

/// Release exactly one M3 reservation, retaining its original rate debit.
/// Only a confirmed Redis CAS counts as a completion. A lost acknowledgement
/// can leave an already-consumed receipt indistinguishable from a missing one.
pub async fn complete_reservation(
    redis: &redis::Client,
    id: Uuid,
    reservation: Uuid,
    status: u16,
) -> Result<(), AccountingError> {
    if !(200..=599).contains(&status) {
        return Err(AccountingError::InvalidStatus);
    }
    let key = format!("redops:policy:v1:{id}");
    let receipt = reservation.to_string();
    timeout(REDIS_TIMEOUT, async {
        let mut connection = redis
            .get_multiplexed_async_connection()
            .await
            .map_err(|_| AccountingError::Unavailable)?;
        for _ in 0..12 {
            let (raw, receipts): (Option<String>, i64) = redis::cmd("EVAL")
                .arg(READ_ACCOUNT)
                .arg(1)
                .arg(&key)
                .query_async(&mut connection)
                .await
                .map_err(|_| AccountingError::Unavailable)?;
            let raw = raw.ok_or(AccountingError::InvalidState)?;
            let mut bucket: Bucket =
                serde_json::from_str(&raw).map_err(|_| AccountingError::InvalidState)?;
            let receipts = u64::try_from(receipts).map_err(|_| AccountingError::InvalidState)?;
            if bucket.active_workers != BigUint::from(receipts)
                || bucket.credit > &bucket.rate * 1_000_000_u32
                || (bucket.rate == BigUint::ZERO
                    && (bucket.at_us != BigUint::ZERO
                        || receipts != 0
                        || bucket.errors_5xx != BigUint::ZERO))
            {
                return Err(AccountingError::InvalidState);
            }
            if receipts == 0 {
                return Err(AccountingError::MissingReceipt);
            }
            bucket.active_workers -= 1_u32;
            if status >= 500 {
                bucket.errors_5xx += 1_u32;
            }
            let updated =
                serde_json::to_string(&bucket).map_err(|_| AccountingError::InvalidState)?;
            let answer: String = redis::cmd("EVAL")
                .arg(COMPLETE_ACCOUNT)
                .arg(1)
                .arg(&key)
                .arg(&raw)
                .arg(updated)
                .arg(&receipt)
                .query_async(&mut connection)
                .await
                .map_err(|_| AccountingError::Unavailable)?;
            match answer.as_str() {
                "ok" => return Ok(()),
                "missing" => return Err(AccountingError::MissingReceipt),
                "retry" => continue,
                _ => return Err(AccountingError::Unavailable),
            }
        }
        Err(AccountingError::Busy)
    })
    .await
    .map_err(|_| AccountingError::Unavailable)?
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StopNotice {
    engagement_id: Uuid,
    #[serde(rename = "state")]
    _state: StopState,
}

#[derive(Deserialize)]
enum StopState {
    #[serde(rename = "HALTED_KILLSWITCH")]
    Halted,
}

#[derive(Default, PartialEq)]
enum Subscription {
    #[default]
    New,
    Connecting,
    Ready,
    Lost,
}

#[derive(Default)]
struct State {
    subscription: Subscription,
    stopped: HashSet<Uuid>,
    consecutive: HashMap<Uuid, u64>,
}

impl State {
    fn latch(&mut self, id: Uuid) -> bool {
        self.consecutive.remove(&id);
        self.stopped.insert(id)
    }
}

#[derive(Clone)]
pub struct Breaker {
    state: Arc<Mutex<State>>,
    changes: watch::Sender<()>,
}

impl Default for Breaker {
    fn default() -> Self {
        Self {
            state: Arc::default(),
            changes: watch::channel(()).0,
        }
    }
}

struct ListenerGuard<'a>(&'a Breaker);

impl Drop for ListenerGuard<'_> {
    fn drop(&mut self) {
        self.0.state().subscription = Subscription::Lost;
        self.0.changes.send_replace(());
    }
}

impl Breaker {
    fn state(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|poisoned| {
            let mut state = poisoned.into_inner();
            state.subscription = Subscription::Lost;
            state
        })
    }

    pub fn ready(&self) -> bool {
        self.state().subscription == Subscription::Ready
    }

    pub fn blocked(&self, id: Uuid) -> bool {
        let state = self.state();
        state.subscription != Subscription::Ready || state.stopped.contains(&id)
    }

    pub async fn wait_blocked(&self, id: Uuid) {
        let mut changes = self.changes.subscribe();
        while !self.blocked(id) {
            // Subscribing before reading the latch also covers a stop that
            // arrives between the predicate check and the first poll.
            if changes.changed().await.is_err() {
                return;
            }
        }
    }

    pub async fn listen(&self, client: redis::Client) -> Result<(), String> {
        {
            let mut state = self.state();
            if state.subscription != Subscription::New {
                return Err("killswitch listener already started".into());
            }
            state.subscription = Subscription::Connecting;
        }
        // Includes cancellation of the listener task, setup failures, and EOF.
        let _guard = ListenerGuard(self);
        let mut subscriber = timeout(REDIS_TIMEOUT, async {
            let mut subscriber = client.get_async_pubsub().await?;
            subscriber.subscribe(CHANNEL).await?;
            Ok::<_, redis::RedisError>(subscriber)
        })
        .await
        .map_err(|_| "killswitch subscription timed out")?
        .map_err(|_| "killswitch subscription failed")?;
        self.state().subscription = Subscription::Ready;

        let mut messages = subscriber.on_message();
        while let Some(message) = messages.next().await {
            if message.get_channel_name() != CHANNEL {
                return Err("unexpected killswitch channel".into());
            }
            let notice: StopNotice = serde_json::from_slice(message.get_payload_bytes())
                .map_err(|_| "invalid killswitch notification")?;
            let newly_stopped = self.state().latch(notice.engagement_id);
            if newly_stopped {
                self.changes.send_replace(());
            }
        }
        Err("killswitch subscription lost".into())
    }

    /// Update M3's cumulative accounting, then observe the single confirmed
    /// origin result in this process's consecutive breaker. Outstanding
    /// receipts can still be settled after a stop.
    pub async fn settle(
        &self,
        redis: &redis::Client,
        policy: &PolicyClient,
        id: Uuid,
        reservation: Uuid,
        status: u16,
        threshold: NonZeroU64,
    ) -> Result<(), AccountingError> {
        // A client disconnect after Redis receives the CAS must not discard
        // a confirmed observation or the corresponding M2 halt.
        let breaker = self.clone();
        let redis = redis.clone();
        let policy = policy.clone();
        tokio::spawn(async move {
            complete_reservation(&redis, id, reservation, status).await?;
            if breaker.observe(id, status, threshold) {
                drop(breaker.deliver_stop(id, &policy));
            }
            Ok(())
        })
        .await
        .map_err(|_| AccountingError::Unavailable)?
    }

    /// Process-local observer for a stream of distinct final origin responses.
    /// Receipt-based integrations use settle() alone so retries cannot change
    /// a local streak. The tripper observes the first M2 delivery result;
    /// once latched, delivery proceeds independently of the caller.
    pub async fn record_final_status(
        &self,
        id: Uuid,
        status: u16,
        threshold: NonZeroU64,
        policy: &PolicyClient,
    ) -> Result<(), String> {
        if !(200..=599).contains(&status) {
            return Err("expected a final HTTP response status".into());
        }
        if !self.observe(id, status, threshold) {
            return Ok(());
        }
        self.deliver_stop(id, policy)
            .await
            .map_err(|_| "killswitch delivery task stopped")?
            .map_err(|_| "orchestrator did not confirm killswitch publication")?;
        Ok(())
    }

    fn observe(&self, id: Uuid, status: u16, threshold: NonZeroU64) -> bool {
        let mut state = self.state();
        if state.stopped.contains(&id) {
            return false;
        }
        if status < 500 {
            state.consecutive.remove(&id);
            return false;
        }
        let streak = state.consecutive.entry(id).or_default();
        *streak = streak.saturating_add(1);
        *streak >= threshold.get() && state.latch(id)
    }

    fn deliver_stop(
        &self,
        id: Uuid,
        policy: &PolicyClient,
    ) -> oneshot::Receiver<Result<(), StateError>> {
        self.changes.send_replace(());

        // Exactly the task that sets the permanent latch starts this worker.
        // No await between the latch and spawn can interrupt that handoff.
        let (initial_result, received) = oneshot::channel();
        let policy = policy.clone();
        tokio::spawn(async move {
            let mut initial_result = Some(initial_result);
            let mut delay = INITIAL_RETRY_DELAY;
            loop {
                let result = policy.halt(id).await;
                let confirmed = result.is_ok();
                if let Some(sender) = initial_result.take() {
                    let _ = sender.send(result);
                    if !confirmed {
                        eprintln!("M2 did not confirm killswitch for {id}, retrying");
                    }
                }
                if confirmed {
                    return;
                }
                sleep(delay).await;
                delay = delay.saturating_mul(2).min(MAX_RETRY_DELAY);
            }
        });
        received
    }
}
