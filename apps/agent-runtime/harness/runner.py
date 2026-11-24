"""Run a trusted local model adapter in a time-bounded, network-denied child.

The adapter and exact tokenizer are installed by the operator. They receive
untrusted text as data and expose no tools. The adapter must apply the supplied
generation cap in its backend before sampling. The child independently meters
the generated text and the parent checks the attempt's complete usage envelope.
The sandbox restricts network and process syscalls, not local file access by
operator-installed Python code. Only the supervisor owns result persistence.
"""

from collections.abc import Callable
from contextlib import redirect_stdout
import ctypes
from dataclasses import dataclass, field
import errno
import importlib
import json
import math
import os
from pathlib import Path
import re
import selectors
from subprocess import DEVNULL, PIPE, Popen, TimeoutExpired
import sys
from threading import Thread
from time import monotonic, sleep
from typing import Generic, Literal, TypeVar, cast

from pydantic import BaseModel, ConfigDict, Field

from .metrics import RunMetrics, RunStats
from .structured_output import InvalidOutput, check_model, parse_output

T = TypeVar("T", bound=BaseModel)
MAX_RETRIES = 3
MAX_REQUEST_BYTES = 1_048_576
MAX_OUTPUT_BYTES = 262_144
# A JSON string can encode each control character as a six-byte escape.
MAX_REPLY_BYTES = 6 * MAX_OUTPUT_BYTES + 1024
MAX_TOKENS = 2**31 - 1
SAFE_LABEL = re.compile(r"[a-z][a-z0-9_-]{0,63}")
BACKEND_REF = re.compile(r"[a-zA-Z_]\w*(?:\.[a-zA-Z_]\w*)*:[a-zA-Z_]\w*")
CHILD = (
    "import sys; sys.path.insert(0, sys.argv[1]); "
    "from harness.runner import _child_main; _child_main(sys.argv[2:])"
)


@dataclass(frozen=True)
class TokenBudget:
    input_tokens: int = 50_000
    output_tokens: int = 8_000
    total_tokens: int | None = None

    def __post_init__(self) -> None:
        values: tuple[int, ...] = (self.input_tokens, self.output_tokens)
        if self.total_tokens is not None:
            values += (self.total_tokens,)
        if any(type(value) is not int or not 1 <= value <= MAX_TOKENS for value in values):
            raise ValueError("Token limits must be positive 32-bit integers")


@dataclass(frozen=True)
class ModelRequest:
    model: str
    text: str
    idempotency_key: str
    max_output_tokens: int


@dataclass(frozen=True)
class ModelReply:
    text: str
    cost_usd: float = 0.0


class TransientModelError(Exception):
    """A retryable model error before generation starts."""


class FallbackModelError(Exception):
    """A model is unavailable and no generation has started."""


@dataclass(frozen=True)
class TraceEvent:
    kind: str
    attempt: int = 0
    model: str | None = None
    idempotency_key: str | None = None
    detail: str | None = None


@dataclass(frozen=True)
class RunResult(Generic[T]):
    output: T | None
    reasoning_trace: tuple[TraceEvent, ...]
    reason: str | None
    stats: RunStats

    @property
    def rejected(self) -> bool:
        return self.reason is not None


class _AttemptInput(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid", strict=True)

    model: str
    text: str
    idempotency_key: str
    max_input_tokens: int = Field(ge=0, le=MAX_TOKENS)
    max_output_tokens: int = Field(ge=0, le=MAX_TOKENS)
    max_total_tokens: int = Field(ge=0, le=2 * MAX_TOKENS)


class _AttemptReply(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid", strict=True)

    status: Literal["ok", "transient", "fallback", "budget", "sandbox_unavailable"]
    input_tokens: int = Field(default=0, ge=0, le=MAX_TOKENS)
    output_tokens: int = Field(default=0, ge=0, le=MAX_TOKENS)
    cost_usd: float = Field(default=0.0, ge=0, le=1e9, allow_inf_nan=False)
    text: str | None = None


class _DeadlineExceeded(TimeoutError):
    pass


class _BackendFailure(RuntimeError):
    pass


def _remaining(deadline: float) -> float:
    remaining = deadline - monotonic()
    if remaining <= 0:
        raise _DeadlineExceeded
    return remaining


def _exchange(child: Popen[bytes], request: bytes, deadline: float) -> bytes:
    assert child.stdin is not None and child.stdout is not None
    sent = 0
    reply = bytearray()
    with selectors.DefaultSelector() as selector:
        os.set_blocking(child.stdin.fileno(), False)
        os.set_blocking(child.stdout.fileno(), False)
        selector.register(child.stdin, selectors.EVENT_WRITE)
        selector.register(child.stdout, selectors.EVENT_READ)
        while selector.get_map():
            ready = selector.select(_remaining(deadline))
            for key, event in ready:
                if event == selectors.EVENT_WRITE:
                    try:
                        sent += os.write(key.fd, request[sent:sent + 65536])
                    except BlockingIOError:
                        continue
                    except BrokenPipeError:
                        sent = len(request)
                    if sent == len(request):
                        selector.unregister(key.fd)
                        child.stdin.close()
                else:
                    try:
                        block = os.read(key.fd, 65536)
                    except BlockingIOError:
                        continue
                    if not block:
                        selector.unregister(key.fd)
                    else:
                        reply.extend(block)
                        if len(reply) > MAX_REPLY_BYTES:
                            raise _BackendFailure
    try:
        returncode = child.wait(timeout=_remaining(deadline))
    except TimeoutExpired as exc:
        raise _DeadlineExceeded from exc
    if returncode != 0 or sent != len(request):
        raise _BackendFailure
    return bytes(reply)


@dataclass(frozen=True)
class LocalBackend:
    """Fixed module references selected by the operator, never by task data."""

    adapter: str
    count_tokens: str
    import_paths: tuple[Path, ...] = ()

    def __post_init__(self) -> None:
        if not BACKEND_REF.fullmatch(self.adapter) or not BACKEND_REF.fullmatch(self.count_tokens):
            raise ValueError("Local model callbacks must be module:attribute references")

    def _attempt(self, request: _AttemptInput, deadline: float) -> _AttemptReply:
        payload = request.model_dump_json().encode("utf-8")
        if len(payload) > MAX_REQUEST_BYTES:
            raise _BackendFailure
        _remaining(deadline)
        child: Popen[bytes] | None = None
        try:
            child = Popen(
                [sys.executable, "-I", "-B", "-c", CHILD, str(Path(__file__).resolve().parents[1]),
                 self.adapter, self.count_tokens, *(str(path.resolve()) for path in self.import_paths)],
                stdin=PIPE, stdout=PIPE, stderr=DEVNULL, close_fds=True,
                start_new_session=True, env={"LANG": "C.UTF-8"},
            )
            reply = _AttemptReply.model_validate_json(_exchange(child, payload, deadline))
            _remaining(deadline)
            _validate_usage(request, reply)
            return reply
        except _DeadlineExceeded:
            raise
        except (OSError, ValueError) as exc:
            raise _BackendFailure from exc
        finally:
            if child is not None:
                _terminate(child)


def _terminate(child: Popen[bytes]) -> None:
    for stream in (child.stdin, child.stdout):
        if stream is not None:
            stream.close()
    if child.poll() is None:
        child.kill()
        # Do not extend the task's deadline waiting for kernel cleanup.
        Thread(target=child.wait, daemon=True, name="agent-model-reaper").start()


def _validate_usage(request: _AttemptInput, reply: _AttemptReply) -> None:
    if reply.input_tokens > request.max_input_tokens:
        raise _BackendFailure
    allowance = min(request.max_output_tokens, request.max_total_tokens - reply.input_tokens)
    if allowance < 0 or (reply.output_tokens > allowance and reply.status != "budget"):
        raise _BackendFailure
    if reply.status == "ok":
        if reply.text is None or reply.input_tokens < 1 or len(reply.text.encode("utf-8")) > MAX_OUTPUT_BYTES:
            raise _BackendFailure
    elif reply.text is not None:
        raise _BackendFailure
    if reply.status in ("transient", "fallback") and (
        reply.input_tokens < 1 or reply.output_tokens != 0 or reply.cost_usd != 0.0
    ):
        raise _BackendFailure


@dataclass
class _RunState:
    trace: list[TraceEvent] = field(default_factory=list)
    input_tokens: int = 0
    output_tokens: int = 0
    cost_usd: float = 0.0
    retries: int = 0
    repairs: int = 0

    def charge_unreported(self, attempt: _AttemptInput) -> None:
        # The adapter may have started generation. Burn the uncertain allowance
        # and stop; retrying could exceed the task's actual budget.
        input_tokens = min(attempt.max_input_tokens, attempt.max_total_tokens)
        self.input_tokens += input_tokens
        self.output_tokens += min(attempt.max_output_tokens, attempt.max_total_tokens - input_tokens)


class Runner:
    def __init__(self, backend: LocalBackend, metrics: RunMetrics | None = None) -> None:
        self.backend = backend
        self.metrics = metrics if metrics is not None else RunMetrics()

    def run(
        self, *, task_id: str, agent: str, skill: str, prompt: str, context: str,
        output_model: type[T], models: tuple[str, ...], budget: TokenBudget = TokenBudget(),
        timeout: float = 30.0, validate_output: Callable[[T], None] | None = None,
    ) -> RunResult[T]:
        started = monotonic()
        if not math.isfinite(timeout) or timeout <= 0:
            raise ValueError("Deadline must be finite and positive")
        if (not task_id or len(task_id) > 512 or not SAFE_LABEL.fullmatch(agent)
                or not SAFE_LABEL.fullmatch(skill)):
            raise ValueError("Invalid run identifiers")
        if (not 1 <= len(models) <= 8 or len(models) != len(set(models))
                or any(not model or len(model) > 128 for model in models)):
            raise ValueError("Invalid model chain")
        check_model(output_model)
        state = _RunState()
        with self.metrics.span(agent, skill) as span:
            output, reason = self._execute(
                task_id, prompt, context, output_model, models, budget, started + timeout,
                validate_output, state,
            )
            state.trace.append(TraceEvent("accepted" if reason is None else "rejected", detail=reason))
            stats = RunStats(
                state.input_tokens, state.output_tokens, state.cost_usd, state.retries,
                state.repairs, monotonic() - started,
            )
            self.metrics.finish(span, agent, skill, stats, reason)
            return RunResult(output, tuple(state.trace), reason, stats)

    def _execute(
        self, task_id: str, prompt: str, context: str, output_model: type[T],
        models: tuple[str, ...], budget: TokenBudget, deadline: float,
        validate_output: Callable[[T], None] | None, state: _RunState,
    ) -> tuple[T | None, str | None]:
        attempt = 0
        errors: tuple[str, ...] = ()
        total = budget.total_tokens if budget.total_tokens is not None else budget.input_tokens + budget.output_tokens
        if len(prompt) + len(context) > MAX_REQUEST_BYTES:
            return None, "INPUT_TOO_LARGE"
        for index, model in enumerate(models):
            state.trace.append(TraceEvent("fallback" if index else "model", attempt, model))
            while True:
                try:
                    _remaining(deadline)
                except _DeadlineExceeded:
                    return None, "DEADLINE_EXCEEDED"
                input_left = budget.input_tokens - state.input_tokens
                output_left = budget.output_tokens - state.output_tokens
                total_left = total - state.input_tokens - state.output_tokens
                if min(input_left, output_left) <= 0 or total_left < 2:
                    return None, "TOKEN_BUDGET_EXCEEDED"

                document: dict[str, str | tuple[str, ...]] = {"prompt": prompt, "context": context}
                if errors:
                    document["schema_errors"] = errors
                text = json.dumps(document, ensure_ascii=True, separators=(",", ":"), sort_keys=True)
                attempt += 1
                key = f"{task_id}:{attempt}"
                request = _AttemptInput(
                    model=model, text=text, idempotency_key=key, max_input_tokens=input_left,
                    max_output_tokens=output_left, max_total_tokens=total_left,
                )
                state.trace.append(TraceEvent("attempt", attempt, model, key))
                try:
                    reply = self.backend._attempt(request, deadline)
                except _DeadlineExceeded:
                    state.charge_unreported(request)
                    state.trace.append(TraceEvent("unreported_usage", attempt, model, key))
                    return None, "DEADLINE_EXCEEDED"
                except _BackendFailure:
                    state.charge_unreported(request)
                    state.trace.append(TraceEvent("unreported_usage", attempt, model, key))
                    return None, "MODEL_PROTOCOL_ERROR"

                state.input_tokens += reply.input_tokens
                state.output_tokens += reply.output_tokens
                state.cost_usd += reply.cost_usd
                state.trace.append(TraceEvent("model_result", attempt, model, key, reply.status))
                if reply.status == "budget":
                    return None, "TOKEN_BUDGET_EXCEEDED"
                if reply.status == "sandbox_unavailable":
                    return None, "SANDBOX_UNAVAILABLE"
                if reply.status == "fallback":
                    break
                if reply.status == "transient":
                    if state.retries == MAX_RETRIES:
                        break
                    delay = 0.05 * 2**state.retries
                    if deadline - monotonic() <= delay:
                        return None, "DEADLINE_EXCEEDED"
                    state.retries += 1
                    state.trace.append(TraceEvent("retry", attempt, model, key))
                    sleep(delay)
                    continue

                assert reply.text is not None
                try:
                    output = parse_output(reply.text, output_model, validate_output)
                except InvalidOutput as exc:
                    state.trace.append(TraceEvent("schema_failure", attempt, model, key, "; ".join(exc.errors)))
                    if state.repairs:
                        return None, "INVALID_MODEL_OUTPUT"
                    state.repairs += 1
                    errors = exc.errors
                    state.trace.append(TraceEvent("schema_repair", attempt, model, key))
                else:
                    if monotonic() >= deadline:
                        return None, "DEADLINE_EXCEEDED"
                    return output, None
        return None, "MODEL_CHAIN_EXHAUSTED"


def _deny_network_and_processes() -> None:
    if sys.platform != "linux":
        raise OSError("Linux seccomp is required")
    lib = ctypes.CDLL("libseccomp.so.2")
    lib.seccomp_init.argtypes = (ctypes.c_uint32,)
    lib.seccomp_init.restype = ctypes.c_void_p
    lib.seccomp_release.argtypes = (ctypes.c_void_p,)
    lib.seccomp_release.restype = None
    lib.seccomp_syscall_resolve_name.argtypes = (ctypes.c_char_p,)
    lib.seccomp_syscall_resolve_name.restype = ctypes.c_int
    lib.seccomp_rule_add.argtypes = (ctypes.c_void_p, ctypes.c_uint32, ctypes.c_int, ctypes.c_uint)
    lib.seccomp_rule_add.restype = ctypes.c_int
    lib.seccomp_load.argtypes = (ctypes.c_void_p,)
    lib.seccomp_load.restype = ctypes.c_int

    policy = lib.seccomp_init(0x7FFF0000)  # SCMP_ACT_ALLOW
    if not policy:
        raise OSError("Unable to initialize seccomp")
    try:
        forbidden = (
            "socket", "socketpair", "socketcall", "connect", "bind", "listen", "accept", "accept4",
            "sendto", "sendmsg", "sendmmsg", "recvfrom", "recvmsg", "recvmmsg", "getsockopt",
            "setsockopt", "getsockname", "getpeername", "shutdown", "io_uring_setup", "bpf",
            "pidfd_getfd", "ptrace", "process_vm_readv", "process_vm_writev", "fork", "vfork",
            "clone", "clone3", "execve", "execveat",
        )
        for name in forbidden:
            number = lib.seccomp_syscall_resolve_name(name.encode("ascii"))
            # libseccomp returns negative pseudo-numbers for multiplexed calls.
            if number == -1:
                continue
            if lib.seccomp_rule_add(policy, 0x00050000 | errno.EPERM, number, 0) != 0:
                raise OSError("Unable to configure seccomp")
        if lib.seccomp_load(policy) != 0:
            raise OSError("Unable to enable seccomp")
    finally:
        lib.seccomp_release(policy)


def _load_callback(reference: str) -> Callable[..., object]:
    module, attribute = reference.split(":", 1)
    callback = getattr(importlib.import_module(module), attribute)
    if not callable(callback):
        raise TypeError("Model callback must be callable")
    return cast(Callable[..., object], callback)


def _token_count(counter: Callable[..., object], model: str, text: str) -> int:
    count = counter(model, text)
    if type(count) is not int or not 0 <= count <= MAX_TOKENS:
        raise ValueError("Invalid tokenizer count")
    return count


def _generate(request: _AttemptInput, adapter_ref: str, tokenizer_ref: str) -> _AttemptReply:
    tokenizer = _load_callback(tokenizer_ref)
    input_tokens = _token_count(tokenizer, request.model, request.text)
    if input_tokens < 1:
        raise ValueError("Empty protocol token count")
    allowance = min(request.max_output_tokens, request.max_total_tokens - input_tokens)
    if input_tokens > request.max_input_tokens or allowance <= 0:
        return _AttemptReply(status="budget")
    adapter = _load_callback(adapter_ref)
    try:
        reply = adapter(ModelRequest(request.model, request.text, request.idempotency_key, allowance))
    except TransientModelError:
        return _AttemptReply(status="transient", input_tokens=input_tokens)
    except FallbackModelError:
        return _AttemptReply(status="fallback", input_tokens=input_tokens)
    if not isinstance(reply, ModelReply) or not isinstance(reply.text, str):
        raise ValueError("Invalid model response")
    if len(reply.text.encode("utf-8")) > MAX_OUTPUT_BYTES:
        raise ValueError("Response too large")
    output_tokens = _token_count(tokenizer, request.model, reply.text)
    if output_tokens > allowance:
        return _AttemptReply(
            status="budget", input_tokens=input_tokens, output_tokens=output_tokens, cost_usd=reply.cost_usd,
        )
    return _AttemptReply(
        status="ok", input_tokens=input_tokens, output_tokens=output_tokens,
        cost_usd=reply.cost_usd, text=reply.text,
    )


def _child_main(arguments: list[str]) -> None:
    try:
        _deny_network_and_processes()
    except (OSError, AttributeError):
        reply = _AttemptReply(status="sandbox_unavailable")
    else:
        adapter_ref, tokenizer_ref, *paths = arguments
        sys.path.extend(paths)
        try:
            wire = sys.stdin.buffer.read(MAX_REQUEST_BYTES + 1)
            if len(wire) > MAX_REQUEST_BYTES:
                raise ValueError("Request too large")
            request = _AttemptInput.model_validate_json(wire)
            with redirect_stdout(sys.stderr):
                reply = _generate(request, adapter_ref, tokenizer_ref)
        except Exception:
            # Unknown post-generation usage means the parent must not retry.
            # Exit without an envelope so it charges the uncertain allowance.
            raise SystemExit(2) from None
    sys.stdout.buffer.write(reply.model_dump_json().encode("utf-8"))
