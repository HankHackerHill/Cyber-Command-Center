//! Stop admission locally before attempting to notify any other process.
//! Redis Pub/Sub has no replay. A lost subscription therefore keeps this
//! process closed. The threshold observer asks the orchestrator to persist
//! the halt and publish it on the shared Redis channel.
use std::collections::{HashMap, HashSet};
use std::num::NonZeroU64;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use futures_util::StreamExt;
use serde::Deserialize;
use tokio::sync::{oneshot, watch};
use tokio::time::{sleep, timeout};
use uuid::Uuid;

use crate::policy_client::{CompletionError, CompletionOutcome, PolicyClient, StateError};

const CHANNEL: &str = "redops:killswitch";
const REDIS_TIMEOUT: Duration = Duration::from_secs(2);
const INITIAL_RETRY_DELAY: Duration = Duration::from_millis(50);
const MAX_RETRY_DELAY: Duration = Duration::from_secs(1);

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

    /// Settle one receipt under the proposed ADR-0012 M3 contract. M3's
    /// acknowledgement orders consecutive responses across proxy processes.
    /// Replays use the same receipt and outcome, including after a local stop.
    pub async fn settle(
        &self,
        policy: &PolicyClient,
        id: Uuid,
        reservation: Uuid,
        outcome: CompletionOutcome,
    ) -> Result<bool, CompletionError> {
        // A client disconnect while M3 is replying must not discard a trip.
        let breaker = self.clone();
        let policy = policy.clone();
        tokio::spawn(async move {
            let tripped = policy.complete(id, reservation, outcome).await?;
            if tripped && breaker.state().latch(id) {
                // M3 settlement is confirmed. M2's separate, idempotent
                // halt proceeds until it confirms publication.
                drop(breaker.deliver_stop(id, &policy));
            }
            Ok(tripped)
        })
        .await
        .map_err(|_| CompletionError::Unavailable)?
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
        {
            let mut state = self.state();
            if state.stopped.contains(&id) {
                return Ok(());
            }
            if status < 500 {
                state.consecutive.remove(&id);
                return Ok(());
            }
            let streak = state.consecutive.entry(id).or_default();
            *streak = streak.saturating_add(1);
            if *streak < threshold.get() {
                return Ok(());
            }
            state.latch(id);
        }
        self.deliver_stop(id, policy)
            .await
            .map_err(|_| "killswitch delivery task stopped")?
            .map_err(|_| "orchestrator did not confirm killswitch publication")?;
        Ok(())
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
