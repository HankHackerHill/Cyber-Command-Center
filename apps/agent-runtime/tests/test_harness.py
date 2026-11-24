import ctypes
from dataclasses import asdict
import errno
import json
from pathlib import Path
import socket
from time import monotonic, sleep

from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter
from prometheus_client import generate_latest
from pydantic import BaseModel, ConfigDict
import pytest

from harness.metrics import RunMetrics
from harness.runner import (
    FallbackModelError, LocalBackend, ModelReply, ModelRequest, Runner, RunResult,
    TokenBudget, TransientModelError,
)


class Score(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    score: int


def count_tokens(model: str, text: str) -> int:
    del model
    # One UTF-8 byte is one token for this synthetic model.
    if '"context":"slow_tokenizer"' in text:
        sleep(20)
    return len(text.encode("utf-8"))


def generate(request: ModelRequest) -> ModelReply:
    payload = json.loads(request.text)
    case = payload["context"]
    repair = "schema_errors" in payload
    if case in ("repair", "double_failure", "repair_fallback") and not repair:
        return ModelReply('{"score":"secret-string","unknown-secret-key":1}', 0.01)
    if case == "double_failure":
        return ModelReply('{"score":"still invalid"}', 0.02)
    if case == "repair_fallback":
        if request.model == "primary":
            raise FallbackModelError("secret exception message")
        return ModelReply("{}")
    if case == "transient" and request.model == "primary":
        raise TransientModelError("temporary model loading error")
    if case == "slow_model":
        sleep(20)
    if case == "overlong_output":
        return ModelReply(" " * (request.max_output_tokens + 1))
    if case == "allowance":
        return ModelReply(json.dumps({"score": request.max_output_tokens}))
    if case == "duplicate_fields" and not repair:
        return ModelReply('{"score":1,"score":2}')
    if case == "broken_model":
        raise RuntimeError("permanent model failure")
    if case == "wrong_evidence" and not repair:
        return ModelReply('{"score":1}')
    if case == "leaky_agent":
        for family in (socket.AF_UNIX, socket.AF_INET, socket.AF_INET6):
            try:
                with socket.socket(family):
                    raise AssertionError("Network syscall escaped the sandbox")
            except PermissionError as exc:
                if exc.errno != errno.EPERM:
                    raise
        # Native socket syscall through libc is denied too.
        libc = ctypes.CDLL(None, use_errno=True)
        assert libc.socket(socket.AF_INET, socket.SOCK_STREAM, 0) == -1
        assert ctypes.get_errno() == errno.EPERM
    return ModelReply('{"score":7}', 0.02)


def backend() -> LocalBackend:
    return LocalBackend(
        adapter="test_harness:generate", count_tokens="test_harness:count_tokens",
        import_paths=(Path(__file__).parent,),
    )


def run(
    context: str, *, budget: TokenBudget = TokenBudget(), timeout: float = 20.0,
    runner: Runner | None = None,
) -> RunResult[Score]:
    selected_runner = runner if runner is not None else Runner(backend())
    return selected_runner.run(
        task_id="task-1", agent="audit", skill="llm_tool_audit", prompt="Review supplied artifact",
        context=context, output_model=Score, models=("primary", "fallback"),
        budget=budget, timeout=timeout,
    )


def input_length(context: str) -> int:
    return len(json.dumps({"context": context, "prompt": "Review supplied artifact"},
                          separators=(",", ":"), sort_keys=True).encode("utf-8"))


def test_model_and_native_child_sockets_are_denied() -> None:
    # The parent can create the same socket. Linux policy applies to the child.
    with socket.socket(socket.AF_UNIX):
        pass
    result = run("leaky_agent")
    assert result.output == Score(score=7), result.reason


def test_input_budget_denies_before_inference() -> None:
    result = run("broken_model", budget=TokenBudget(input_tokens=input_length("broken_model") - 1))
    assert result.rejected and result.reason == "TOKEN_BUDGET_EXCEEDED"
    assert result.stats.input_tokens == 0
    assert result.stats.output_tokens == 0
    assert result.stats.retries == 0


def test_combined_cap_sets_generation_allowance() -> None:
    length = input_length("allowance")
    result = run("allowance", budget=TokenBudget(total_tokens=length + 40))
    assert result.output == Score(score=40)
    assert result.stats.input_tokens == length
    assert result.stats.output_tokens == len('{"score": 40}')


def test_output_cap_rejects_and_stops() -> None:
    result = run("overlong_output", budget=TokenBudget(output_tokens=6))
    assert result.output is None and result.reason == "TOKEN_BUDGET_EXCEEDED"
    assert result.stats.input_tokens == input_length("overlong_output")
    assert result.stats.output_tokens == 7
    assert len([event for event in result.reasoning_trace if event.kind == "attempt"]) == 1


def test_transient_retry_then_fallback_uses_attempt_ids_and_shared_accounting() -> None:
    result = run("transient")
    attempts = [event for event in result.reasoning_trace if event.kind == "attempt"]
    assert [event.idempotency_key for event in attempts] == [f"task-1:{attempt}" for attempt in range(1, 6)]
    assert [event.model for event in attempts] == ["primary"] * 4 + ["fallback"]
    assert [event.model for event in result.reasoning_trace if event.kind == "fallback"] == ["fallback"]
    assert result.stats.retries == 3
    assert result.stats.input_tokens == input_length("transient") * 5
    assert result.stats.output_tokens == len('{"score":7}')
    assert result.output == Score(score=7)


def test_retry_does_not_reset_budget() -> None:
    result = run("transient", budget=TokenBudget(input_tokens=input_length("transient") + 1))
    assert result.reason == "TOKEN_BUDGET_EXCEEDED"
    assert result.stats.input_tokens == input_length("transient")
    assert result.stats.retries == 1
    assert not any(event.kind == "fallback" for event in result.reasoning_trace)


def test_one_repair_succeeds_without_secret_values_in_feedback_or_trace() -> None:
    result = run("repair")
    assert result.output == Score(score=7)
    assert result.stats.schema_repairs == 1
    assert result.stats.input_tokens > input_length("repair") * 2
    trace = repr([asdict(event) for event in result.reasoning_trace])
    assert "score: int_type" in trace
    assert "secret-string" not in trace
    assert "unknown-secret-key" not in trace
    assert result.stats.cost_usd == pytest.approx(0.03)


def test_schema_repair_shares_input_budget() -> None:
    result = run("repair", budget=TokenBudget(input_tokens=input_length("repair") * 2))
    assert result.reason == "TOKEN_BUDGET_EXCEEDED"
    assert result.output is None
    assert result.stats.input_tokens == input_length("repair")
    assert result.stats.schema_repairs == 1


@pytest.mark.parametrize("case", ("double_failure", "repair_fallback"))
def test_second_schema_failure_rejects_even_across_fallback(case: str) -> None:
    result = run(case)
    assert result.reason == "INVALID_MODEL_OUTPUT"
    assert result.output is None
    assert result.stats.schema_repairs == 1
    assert [event.kind for event in result.reasoning_trace].count("schema_failure") == 2
    assert "secret exception message" not in repr(result.reasoning_trace)


def test_provenance_validation_can_trigger_the_one_repair() -> None:
    def validate(output: Score) -> None:
        if output.score != 7:
            raise ValueError("arbitrary supplied evidence")

    result = Runner(backend()).run(
        task_id="task-1", agent="audit", skill="llm_tool_audit", prompt="Review supplied artifact",
        context="wrong_evidence", output_model=Score, models=("primary",), validate_output=validate,
    )
    assert result.output == Score(score=7)
    assert result.stats.schema_repairs == 1
    assert "arbitrary supplied evidence" not in repr(result.reasoning_trace)


def test_duplicate_json_key_is_a_schema_failure() -> None:
    result = run("duplicate_fields")
    assert result.output == Score(score=7)
    assert result.stats.schema_repairs == 1
    assert "duplicate_field" in repr(result.reasoning_trace)


@pytest.mark.parametrize("case", ("slow_model", "slow_tokenizer"))
def test_deadline_kills_child_without_retries(case: str) -> None:
    started = monotonic()
    result = run(case, timeout=0.5)
    assert monotonic() - started < 3
    assert result.reason == "DEADLINE_EXCEEDED"
    assert result.stats.retries == 0
    assert result.output is None
    assert any(event.kind == "unreported_usage" for event in result.reasoning_trace)


def test_unknown_backend_failure_cannot_retry_or_fallback() -> None:
    result = run("broken_model")
    assert result.rejected and result.reason == "MODEL_PROTOCOL_ERROR"
    assert result.stats.retries == 0
    assert not any(event.kind == "fallback" for event in result.reasoning_trace)


def test_traces_and_counters_account_for_run_without_payload_labels() -> None:
    provider = TracerProvider()
    exporter = InMemorySpanExporter()
    provider.add_span_processor(SimpleSpanProcessor(exporter))
    try:
        metrics = RunMetrics(tracer=provider.get_tracer("harness-test"))
        result = run("repair", runner=Runner(backend(), metrics))
        assert result.output == Score(score=7)
        spans = exporter.get_finished_spans()
        assert len(spans) == 1
        attrs = spans[0].attributes
        assert attrs is not None
        assert attrs["tokens.input"] == result.stats.input_tokens
        assert attrs["tokens.output"] == result.stats.output_tokens
        assert attrs["schema_repairs"] == 1
        assert attrs["retries"] == 0
        assert attrs["cost.usd"] == pytest.approx(0.03)
        assert attrs["latency.seconds"] == result.stats.latency_seconds
        counters = generate_latest(metrics.registry).decode()
        assert 'redops_agent_runs_total{agent="audit",outcome="accepted",skill="llm_tool_audit"} 1.0' in counters
        assert 'redops_agent_schema_repairs_total{agent="audit",skill="llm_tool_audit"} 1.0' in counters
        assert "task-1" not in counters
        assert "secret-string" not in repr(attrs)
    finally:
        provider.shutdown()
