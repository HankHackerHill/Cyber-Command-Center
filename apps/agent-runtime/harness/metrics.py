"""OpenTelemetry run spans and bounded Prometheus counters."""

from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from threading import Lock

from opentelemetry import trace
from opentelemetry.trace import Span, Status, StatusCode, Tracer
from prometheus_client import CollectorRegistry, Counter


@dataclass(frozen=True)
class RunStats:
    input_tokens: int
    output_tokens: int
    cost_usd: float
    retries: int
    schema_repairs: int
    latency_seconds: float


class RunMetrics:
    def __init__(
        self, registry: CollectorRegistry | None = None, tracer: Tracer | None = None,
    ) -> None:
        self.registry = registry if registry is not None else CollectorRegistry()
        self.tracer = tracer if tracer is not None else trace.get_tracer("redops.agent_runtime")
        self._pairs: set[tuple[str, str]] = set()
        self._lock = Lock()
        labels = ("agent", "skill")
        self._runs = Counter(
            "redops_agent_runs", "Finished agent runs", (*labels, "outcome"), registry=self.registry,
        )
        self._tokens = Counter(
            "redops_agent_tokens", "Token usage and conservative abort charges",
            (*labels, "direction"), registry=self.registry,
        )
        self._cost = Counter(
            "redops_agent_cost_usd", "Cost reported by the model adapter in USD",
            labels, registry=self.registry,
        )
        self._retries = Counter(
            "redops_agent_retries", "Scheduled transient retries", labels, registry=self.registry,
        )
        self._repairs = Counter(
            "redops_agent_schema_repairs", "Scheduled schema repairs", labels, registry=self.registry,
        )

    @contextmanager
    def span(self, agent: str, skill: str) -> Iterator[Span]:
        with self.tracer.start_as_current_span(
            "agent_runtime.run", attributes={"agent": agent, "skill": skill},
            record_exception=False, set_status_on_exception=False,
        ) as span:
            yield span

    def finish(
        self, span: Span, agent: str, skill: str, stats: RunStats, reason: str | None,
    ) -> None:
        outcome = "accepted" if reason is None else "rejected"
        span.set_attributes({
            "outcome": outcome,
            "tokens.input": stats.input_tokens,
            "tokens.output": stats.output_tokens,
            "cost.usd": stats.cost_usd,
            "latency.seconds": stats.latency_seconds,
            "retries": stats.retries,
            "schema_repairs": stats.schema_repairs,
        })
        if reason is not None:
            span.set_status(Status(StatusCode.ERROR, reason))

        pair = (agent, skill)
        with self._lock:
            # Catalog labels are trusted, and the cap also bounds direct users
            # of Runner that provide arbitrary agent/skill labels.
            if pair not in self._pairs and len(self._pairs) >= 128:
                pair = ("other", "other")
            else:
                self._pairs.add(pair)
        self._runs.labels(*pair, outcome).inc()
        self._tokens.labels(*pair, "input").inc(stats.input_tokens)
        self._tokens.labels(*pair, "output").inc(stats.output_tokens)
        self._cost.labels(*pair).inc(stats.cost_usd)
        self._retries.labels(*pair).inc(stats.retries)
        self._repairs.labels(*pair).inc(stats.schema_repairs)
