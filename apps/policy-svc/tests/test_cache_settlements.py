"""Conservative cache proof and atomic, retry-safe trusted settlement protocol."""

import hashlib
import json
import time
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from threading import Barrier, Event, Lock
from typing import cast
from uuid import uuid4

import httpx
import pytest
from contracts.roe import RoeManifest
from fastapi.testclient import TestClient
from pydantic import ValidationError

import main
from main import Decision, DecisionCache, HttpRequest, create_app
from settlements import Completion, ConflictingCompletion, SettlementBatch
from test_evaluate import HEADER, NOW, Sandbox, decision, envelope, opa_url, sandbox


def admit(sandbox: Sandbox, engagement: str, count: int) -> list[str]:
    receipts: list[str] = []
    for _ in range(count):
        result, receipt = sandbox.store.reserve(engagement, 1000, lambda _: Decision(allow=True, reason="ALLOWED"))
        assert result.allow and receipt is not None
        receipts.append(receipt)
    return receipts


def complete(receipt: str, status: int = 200) -> Completion:
    return Completion(reservation_id=receipt, status_code=status)


def test_batch_commit_retry_missing_and_every_5xx(sandbox: Sandbox) -> None:
    engagement, _ = sandbox.provision()
    ids = admit(sandbox, engagement, 4)
    items = [complete(ids[0], 500), complete(ids[1], 599), complete(ids[2], 429)]
    missing = complete(str(uuid4()), 503)
    before = sandbox.store._read(sandbox.store._key(engagement))[1]
    result = sandbox.store.complete_many(engagement, [*items, missing])
    assert [item.status for item in result] == ["committed"] * 3 + ["missing"]
    after = sandbox.store._read(sandbox.store._key(engagement))[1]
    assert after.active_workers == 1 and after.errors_5xx == 2
    assert after.credit == before.credit and after.at_us == before.at_us
    assert sandbox.store.complete_many(engagement, [*items, missing]) == result
    assert sandbox.store._read(sandbox.store._key(engagement))[1] == after
    assert sandbox.store.complete(engagement, ids[3], 200)
    sandbox.store.redis.delete(sandbox.store._key(engagement) + ":settled")


def test_conflicting_retry_rejects_entire_batch(sandbox: Sandbox) -> None:
    engagement, _ = sandbox.provision()
    first, second = admit(sandbox, engagement, 2)
    sandbox.store.complete_many(engagement, [complete(first, 500)])
    before = sandbox.store._read(sandbox.store._key(engagement))[1]
    with pytest.raises(ConflictingCompletion):
        sandbox.store.complete_many(engagement, [complete(second), complete(first, 200)])
    assert sandbox.store._read(sandbox.store._key(engagement))[1] == before
    assert sandbox.store.redis.hget(sandbox.store._key(engagement), second) == "1"
    sandbox.store.redis.delete(sandbox.store._key(engagement) + ":settled")


def test_invalid_batch_never_consumes_and_engagement_is_bound(sandbox: Sandbox) -> None:
    engagement, _ = sandbox.provision()
    other, _ = sandbox.provision()
    receipt = admit(sandbox, engagement, 1)[0]
    for items in ([], [complete(receipt)] * 2):
        with pytest.raises(ValidationError):
            sandbox.store.complete_many(engagement, items)
    for status in (103, 600, True, 200.0):
        with pytest.raises(ValidationError):
            Completion.model_validate({"reservation_id": receipt, "status_code": status})
    assert sandbox.store.complete_many(other, [complete(receipt, 503)])[0].status == "missing"
    assert sandbox.store.redis.hget(sandbox.store._key(engagement), receipt) == "1"
    assert sandbox.store.complete(engagement, receipt, 200)


def test_concurrent_batch_retries_count_once(sandbox: Sandbox) -> None:
    engagement, _ = sandbox.provision()
    ids = admit(sandbox, engagement, 10)
    items = [complete(receipt, 503) for receipt in ids]
    barrier = Barrier(8, timeout=10)

    def finish(_: int) -> list[str]:
        barrier.wait()
        return [result.status for result in sandbox.store.complete_many(engagement, items)]

    with ThreadPoolExecutor(max_workers=8) as executor:
        results = list(executor.map(finish, range(8)))
    assert results == [["committed"] * 10] * 8
    bucket = sandbox.store._read(sandbox.store._key(engagement))[1]
    assert bucket.active_workers == 0 and bucket.errors_5xx == 10
    sandbox.store.redis.delete(sandbox.store._key(engagement) + ":settled")


def test_settlement_endpoint_auth_strictness_and_durable_ack(sandbox: Sandbox, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("M4_AUDIT_TOKEN", "test-only-observer-secret")
    engagement, _ = sandbox.provision()
    receipt = admit(sandbox, engagement, 1)[0]
    wire_completions: list[dict[str, object]] = [{"reservation_id": receipt, "status_code": 503}]
    payload: dict[str, object] = {"engagement_id": engagement, "completions": wire_completions}
    headers = {"authorization": "Bearer test-only-observer-secret"}
    with sandbox.service() as client:
        assert client.post("/settlements", json=payload).status_code == 401
        assert client.post("/settlements", json=payload, headers={"authorization": "Bearer wrong"}).status_code == 401
        for duplicate_headers in (
            [("authorization", "Bearer test-only-observer-secret"), ("authorization", "Bearer wrong")],
            [("authorization", "Bearer test-only-observer-secret")] * 2,
        ):
            assert client.post("/settlements", json=payload, headers=duplicate_headers).status_code == 401
            assert sandbox.store._read(sandbox.store._key(engagement))[1].active_workers == 1
        for bad in (
            {**payload, "unexpected": True},
            {**payload, "completions": [{"reservation_id": receipt, "status_code": "503"}]},
            {**payload, "completions": wire_completions * 2},
        ):
            assert client.post("/settlements", json=bad, headers=headers).status_code == 422
        assert sandbox.store._read(sandbox.store._key(engagement))[1].active_workers == 1
        accepted = client.post("/settlements", json=payload, headers=headers)
        assert accepted.status_code == 200
        assert accepted.json() == {"engagement_id": engagement, "completions": [{"reservation_id": receipt, "status": "committed"}]}
        assert client.post("/settlements", json=payload, headers=headers).json() == accepted.json()
        wire_completions[0]["status_code"] = 200
        assert client.post("/settlements", json=payload, headers=headers).status_code == 409
    sandbox.store.redis.delete(sandbox.store._key(engagement) + ":settled")


def test_cache_scope_denials_only_and_fresh_state_and_redis(sandbox: Sandbox, monkeypatch: pytest.MonkeyPatch) -> None:
    engagement, digest = sandbox.provision()
    calls = 0
    checks = 0
    original = main.check_rules
    state = "CONTROLLED_VALIDATION"

    def counted(opa: httpx.Client, manifest: dict[str, object], request: HttpRequest,
                now: datetime, runtime: main.Runtime) -> Decision:
        nonlocal calls
        calls += 1
        return original(opa, manifest, request, now, runtime)

    def state_request(_: httpx.Request) -> httpx.Response:
        nonlocal checks
        checks += 1
        return httpx.Response(200, json={"state": state})

    monkeypatch.setattr(main, "check_rules", counted)
    with sandbox.service(state=state_request) as client:
        for _ in range(2):
            denied = client.post("/evaluate", json=envelope(digest, host="outside.example.com"))
            assert denied.json() == {"allow": False, "reason": "SCOPE_DENIED"}
        assert calls == 1 and checks == 2
        state = "HALTED_KILLSWITCH"
        assert client.post("/evaluate", json=envelope(digest, host="outside.example.com")).json()["reason"] == "STATE_DENIED"
        assert checks == 3 and calls == 1
        state = "CONTROLLED_VALIDATION"
        sandbox.store.redis.hset(sandbox.store._key(engagement), "state", "{}")
        assert client.post("/evaluate", json=envelope(digest, host="outside.example.com")).json()["reason"] == "ACCOUNTING_UNAVAILABLE"


def test_positive_decisions_always_recheck_opa_state_window_runtime_and_manifest(sandbox: Sandbox, monkeypatch: pytest.MonkeyPatch) -> None:
    engagement, digest = sandbox.provision(circuit_breaker_5xx_threshold=1)
    calls = 0
    original = main.check_rules

    def counted(opa: httpx.Client, manifest: dict[str, object], request: HttpRequest,
                now: datetime, runtime: main.Runtime) -> Decision:
        nonlocal calls
        calls += 1
        return original(opa, manifest, request, now, runtime)

    monkeypatch.setattr(main, "check_rules", counted)
    with sandbox.service() as client:
        first = client.post("/evaluate", json=envelope(digest))
        decision(first, True)
        assert sandbox.store.complete(engagement, first.headers[HEADER], 200)
        second = client.post("/evaluate", json=envelope(digest))
        decision(second, True)
        assert calls == 2
        assert sandbox.store.complete(engagement, second.headers[HEADER], 503)
        assert client.post("/evaluate", json=envelope(digest)).json()["reason"] == "BREAKER_DENIED"
        assert calls == 3
        path = sandbox.directory / f"{digest}.json"
        path.write_bytes(path.read_bytes() + b" ")
        assert client.post("/evaluate", json=envelope(digest)).json()["reason"] == "INVALID_MANIFEST"
        assert digest not in getattr(client.app, "state").decision_cache.manifests
        path.unlink()
        assert client.post("/evaluate", json=envelope(digest)).json()["reason"] == "UNKNOWN_MANIFEST"


def test_cached_manifest_cannot_widen_nanosecond_window(sandbox: Sandbox) -> None:
    engagement, digest = sandbox.provision(not_before="2026-12-01T08:00:00.000000500Z")
    now = NOW
    app = create_app(manifest_dir=sandbox.directory, orchestrator_url="http://m2.invalid", opa_url=sandbox.opa,
                     redis_url=sandbox.redis_url, clock=lambda: now,
                     transport=httpx.MockTransport(lambda _: httpx.Response(200, json={"state": "CONTROLLED_VALIDATION"})))
    with TestClient(app) as client:
        accepted = client.post("/evaluate", json=envelope(digest))
        decision(accepted, True)
        assert sandbox.store.complete(engagement, accepted.headers[HEADER], 200)
        now = datetime(2026, 12, 1, 8, tzinfo=timezone.utc)
        assert client.post("/evaluate", json=envelope(digest)).json()["reason"] == "WINDOW_DENIED"
        now = NOW
        assert client.post("/evaluate", json=envelope(digest, ts="2026-12-01T08:00:00Z")).json()["reason"] == "WINDOW_DENIED"


def test_cache_bounds_expiry_and_forbidden_classes(monkeypatch: pytest.MonkeyPatch) -> None:
    cache = DecisionCache()
    request = HttpRequest(method="GET", host="outside.example.com", ip="198.51.100.7", path="/", ts="2026-12-01T12:00:00Z")
    instant = 1.0
    monkeypatch.setattr(time, "monotonic", lambda: instant)
    for reason in ("ALLOWED", "STATE_DENIED", "RATE_DENIED", "BREAKER_DENIED", "WINDOW_DENIED", "POLICY_UNAVAILABLE"):
        cache.remember("a" * 64, request, Decision(allow=reason == "ALLOWED", reason=reason))
        assert not cache.scope_denied("a" * 64, request)
    cache.remember("a" * 64, request, Decision(reason="SCOPE_DENIED"))
    assert cache.scope_denied("a" * 64, request)
    assert not cache.scope_denied("b" * 64, request)
    instant += 1.0
    assert not cache.scope_denied("a" * 64, request)
    for i in range(2050):
        cache.remember(str(i), request, Decision(reason="SCOPE_DENIED"))
    assert len(cache.denials) == 2048
    assert not cache.scope_denied("0", request)


def test_protocol_models_frozen_and_extra_forbidden() -> None:
    item = complete(str(uuid4()))
    with pytest.raises(ValidationError):
        setattr(item, "status_code", 500)
    with pytest.raises(ValidationError):
        SettlementBatch.model_validate({"engagement_id": "test", "completions": [item], "extra": True})


def test_batch_release_and_breaker_are_visible_before_next_admission(sandbox: Sandbox) -> None:
    engagement, digest = sandbox.provision(max_concurrent_workers=2, circuit_breaker_5xx_threshold=2)
    with sandbox.service() as client:
        grants = [client.post("/evaluate", json=envelope(digest)) for _ in range(2)]
        assert all(grant.json()["allow"] for grant in grants)
        assert client.post("/evaluate", json=envelope(digest)).json()["reason"] == "RATE_DENIED"
        result = sandbox.store.complete_many(engagement, [complete(grant.headers[HEADER], 503) for grant in grants])
        assert all(ack.status == "committed" for ack in result)
        bucket = sandbox.store._read(sandbox.store._key(engagement))[1]
        assert bucket.active_workers == 0 and bucket.errors_5xx == 2
        assert client.post("/evaluate", json=envelope(digest)).json()["reason"] == "BREAKER_DENIED"
    sandbox.store.redis.delete(sandbox.store._key(engagement) + ":settled")


def test_endpoint_unconfigured_and_corrupt_accounting_fail_closed(sandbox: Sandbox, monkeypatch: pytest.MonkeyPatch) -> None:
    engagement, _ = sandbox.provision()
    receipt = admit(sandbox, engagement, 1)[0]
    payload = {"engagement_id": engagement, "completions": [{"reservation_id": receipt, "status_code": 503}]}
    headers = {"authorization": "Bearer observer"}
    monkeypatch.delenv("M4_AUDIT_TOKEN", raising=False)
    with sandbox.service() as client:
        assert client.post("/settlements", json=payload, headers=headers).status_code == 503
        monkeypatch.setenv("M4_AUDIT_TOKEN", "observer")
        sandbox.store.redis.hset(sandbox.store._key(engagement) + ":settled", receipt, "broken")
        assert client.post("/settlements", json=payload, headers=headers).status_code == 503
        assert sandbox.store._read(sandbox.store._key(engagement))[1].active_workers == 1
    sandbox.store.redis.delete(sandbox.store._key(engagement) + ":settled")


def test_batch_size_guard_and_uuid_alias_duplicate_guard() -> None:
    receipt = str(uuid4())
    with pytest.raises(ValidationError):
        SettlementBatch(engagement_id="engagement", completions=[complete(str(uuid4())) for _ in range(257)])
    with pytest.raises(ValidationError):
        SettlementBatch(engagement_id="engagement", completions=[complete(receipt), complete(receipt.replace("-", "").upper())])


def test_fingerprints_survive_store_restart_and_preserve_large_integer_counters(sandbox: Sandbox) -> None:
    engagement, _ = sandbox.provision()
    receipt = admit(sandbox, engagement, 1)[0]
    key = sandbox.store._key(engagement)
    raw, bucket = sandbox.store._read(key)
    huge = 2 ** 100 + 17
    updated = bucket.model_copy(update={"errors_5xx": huge})
    sandbox.store.redis.hset(key, "state", updated.model_dump_json())
    items = [complete(receipt, 503)]
    assert sandbox.store.complete_many(engagement, items)[0].status == "committed"
    restarted = main.AccountStore(sandbox.store.redis)
    assert restarted.complete_many(engagement, items)[0].status == "committed"
    assert restarted._read(key)[1].errors_5xx == huge + 1
    assert restarted._read(key)[1].active_workers == 0
    sandbox.store.redis.delete(key + ":settled")


def test_positive_admission_observes_live_opa_reload(sandbox: Sandbox) -> None:
    engagement, digest = sandbox.provision()
    with httpx.Client(base_url=sandbox.opa, trust_env=False, timeout=2) as opa:
        policies = opa.get("/v1/policies").json()["result"]
        scope = next(policy for policy in policies if policy["id"].endswith("scope.rego"))
        module_url = "/v1/policies/" + scope["id"]
        with sandbox.service() as client:
            accepted = client.post("/evaluate", json=envelope(digest))
            decision(accepted, True)
            assert sandbox.store.complete(engagement, accepted.headers[HEADER], 200)
            try:
                changed = opa.put(module_url, content=b"package redops.scope\nimport rego.v1\ndefault allow := false\n")
                assert changed.is_success, changed.text
                assert client.post("/evaluate", json=envelope(digest)).json() == {"allow": False, "reason": "SCOPE_DENIED"}
            finally:
                restored = opa.put(module_url, content=scope["raw"].encode())
                assert restored.is_success, restored.text


def test_manifest_cache_skips_parsing_but_never_skips_live_hash(sandbox: Sandbox, monkeypatch: pytest.MonkeyPatch) -> None:
    engagement, digest = sandbox.provision()
    original = main.parse_manifest
    parses = 0

    def counted(raw: bytes) -> tuple[RoeManifest, dict[str, object]]:
        nonlocal parses
        parses += 1
        return original(raw)

    monkeypatch.setattr(main, "parse_manifest", counted)
    with sandbox.service() as client:
        for _ in range(2):
            grant = client.post("/evaluate", json=envelope(digest))
            decision(grant, True)
            assert sandbox.store.complete(engagement, grant.headers[HEADER], 200)
        assert parses == 1
        manifest_path = sandbox.directory / f"{digest}.json"
        original_bytes = manifest_path.read_bytes()
        # Same-length replacement must invalidate even if metadata is reused.
        changed_bytes = original_bytes.replace(b'"HYBRID"', b'"MANUAL"')
        assert len(changed_bytes) == len(original_bytes) and changed_bytes != original_bytes
        manifest_path.write_bytes(changed_bytes)
        assert client.post("/evaluate", json=envelope(digest)).json()["reason"] == "INVALID_MANIFEST"
        assert parses == 1


def test_admission_snapshot_removes_separate_time_round_trip(sandbox: Sandbox, monkeypatch: pytest.MonkeyPatch) -> None:
    engagement, _ = sandbox.provision()
    commands: list[tuple[object, ...]] = []
    original = cast(Callable[..., object], sandbox.store.redis.execute_command)

    def spy(*args: object, **kwargs: object) -> object:
        commands.append(args)
        result: object = original(*args, **kwargs)
        return result

    monkeypatch.setattr(sandbox.store.redis, "execute_command", spy)
    result, receipt = sandbox.store.reserve(engagement, 2, lambda _: Decision(allow=True, reason="ALLOWED"))
    assert result.allow and receipt is not None
    assert len(commands) == 2  # One atomic read+TIME, then the reservation CAS.
    assert all(command[0] == "EVAL" for command in commands)
    assert "redis.call('TIME')" in str(commands[0][1])
    assert sandbox.store.complete(engagement, receipt, 200)


def test_atomic_snapshot_matches_legacy_credit_clock_and_counters(sandbox: Sandbox, monkeypatch: pytest.MonkeyPatch) -> None:
    class LegacyStore(main.AccountStore):
        def _admission_snapshot(self, key: str) -> tuple[str, main.Bucket, int]:
            raw, bucket = self._read(key)
            return raw, bucket, self._now_us()

    engagements = [sandbox.provision()[0] for _ in range(2)]
    stores = [main.AccountStore(sandbox.store.redis), LegacyStore(sandbox.store.redis)]
    instant = 1_900_000_000_000_000
    original = sandbox.store.redis.eval

    def clocked_eval(script: str, numkeys: int, *keys_and_args: str) -> object:
        result: object = original(script, numkeys, *keys_and_args)
        if "redis.call('TIME')" in script:
            assert isinstance(result, list) and len(result) == 3
            result[2] = [str(instant // 1_000_000), str(instant % 1_000_000)]
        return result

    monkeypatch.setattr(sandbox.store.redis, "eval", clocked_eval)
    monkeypatch.setattr(sandbox.store.redis, "time", lambda: divmod(instant, 1_000_000))
    histories: list[list[main.Runtime]] = [[], []]
    receipts: list[list[str]] = [[], []]

    def attempt() -> list[Decision]:
        results: list[Decision] = []
        for index, (store, engagement) in enumerate(zip(stores, engagements, strict=True)):
            def judge(runtime: main.Runtime) -> Decision:
                histories[index].append(runtime)
                if runtime["errors_5xx"] >= 1:
                    return Decision(reason="BREAKER_DENIED")
                if runtime["tokens"] < 1:
                    return Decision(reason="RATE_DENIED")
                return Decision(allow=True, reason="ALLOWED")
            result, receipt = store.reserve(engagement, 2, judge)
            results.append(result)
            if receipt is not None:
                receipts[index].append(receipt)
        assert results[0] == results[1]
        assert histories[0] == histories[1]
        assert stores[0]._read(stores[0]._key(engagements[0]))[1] == stores[1]._read(stores[1]._key(engagements[1]))[1]
        return results

    assert attempt()[0].allow
    assert attempt()[0].allow
    assert attempt()[0].reason == "RATE_DENIED"
    instant += 499_999
    assert attempt()[0].reason == "RATE_DENIED"
    instant += 1
    assert attempt()[0].allow
    for index, (store, engagement) in enumerate(zip(stores, engagements, strict=True)):
        assert store.complete(engagement, receipts[index][0], 503)
    assert attempt()[0].reason == "BREAKER_DENIED"
    instant -= 1
    assert attempt()[0].reason == "CLOCK_UNAVAILABLE"


@pytest.mark.parametrize("value", [
    None, [], ["1"], ["1", "0", "0"], [True, "0"], [1, "0"],
    ["-1", "0"], ["+1", "0"], ["1.0", "0"], [" 1", "0"],
    ["1", "1000000"], ["1", "-1"], ["9223372036854775808", "0"],
    ["1" * 100, "0"], ["１", "0"], [b"\xff", b"0"],
])
def test_lua_clock_rejects_malformed_values(value: object) -> None:
    with pytest.raises(ValueError):
        main.AccountStore._lua_time_us(value)


def test_lua_clock_exact_decimal_strings_and_bytes() -> None:
    assert main.AccountStore._lua_time_us(["1900000000", "999999"]) == 1_900_000_000_999_999
    assert main.AccountStore._lua_time_us([b"1900000000", b"000001"]) == 1_900_000_000_000_001
    assert main.AccountStore._lua_time_us(["0", "0"]) == 0
    assert main.AccountStore._lua_time_us([str(2 ** 63 - 1), "999999"]) == (2 ** 63 - 1) * 1_000_000 + 999_999


def test_malformed_atomic_clock_denies_endpoint_without_releasing_workers(sandbox: Sandbox, monkeypatch: pytest.MonkeyPatch) -> None:
    engagement, digest = sandbox.provision()
    original = sandbox.store.redis.eval

    def malformed_clock(script: str, numkeys: int, *keys_and_args: str) -> object:
        result: object = original(script, numkeys, *keys_and_args)
        if "redis.call('TIME')" in script:
            assert isinstance(result, list)
            result[2] = ["1", "1000000"]
        return result

    # Patch the service's accounting Redis client after its lifespan creates it.
    with sandbox.service() as client:
        store: main.AccountStore = getattr(client.app, "state").accounting
        monkeypatch.setattr(store.redis, "eval", malformed_clock)
        response = client.post("/evaluate", json=envelope(digest))
        assert response.status_code == 200
        assert response.json() == {"allow": False, "reason": "ACCOUNTING_UNAVAILABLE"}
        assert sandbox.store._read(sandbox.store._key(engagement))[1].active_workers == 0


def test_fresh_authority_overlaps_judge_but_precedes_reservation_commit(sandbox: Sandbox) -> None:
    engagement, _ = sandbox.provision()
    started = Event()
    judged = Event()
    release = Event()

    def state() -> Decision | None:
        started.set()
        assert release.wait(5)
        return None

    def judge(_: main.Runtime) -> Decision:
        assert started.wait(5)
        judged.set()
        return Decision(allow=True, reason="ALLOWED")

    with ThreadPoolExecutor(max_workers=1) as authority_executor, ThreadPoolExecutor(max_workers=1) as requests:
        authority = main.AuthorityChecks(authority_executor, workers=1)
        future = requests.submit(sandbox.store.reserve, engagement, 2, judge, authority=authority, state_check=state)
        try:
            assert judged.wait(5)  # Policy runs while fresh M2 is still pending.
            assert not future.done()
            assert sandbox.store._read(sandbox.store._key(engagement))[1].active_workers == 0
        finally:
            release.set()
        result, receipt = future.result(timeout=5)
        assert result.allow and receipt is not None
        assert sandbox.store.complete(engagement, receipt, 200)


@pytest.mark.parametrize("policy_reason", ["ALLOWED", "WINDOW_DENIED", "POLICY_UNAVAILABLE"])
def test_authority_denial_keeps_priority_over_overlapped_policy(sandbox: Sandbox, policy_reason: str) -> None:
    engagement, _ = sandbox.provision()
    with ThreadPoolExecutor(max_workers=1) as executor:
        authority = main.AuthorityChecks(executor, workers=1)
        result, receipt = sandbox.store.reserve(
            engagement, 2, lambda _: Decision(allow=policy_reason == "ALLOWED", reason=policy_reason),
            authority=authority, state_check=lambda: Decision(reason="STATE_DENIED"),
        )
    assert result == Decision(reason="STATE_DENIED") and receipt is None
    assert sandbox.store._read(sandbox.store._key(engagement))[1].active_workers == 0


def test_authority_exception_fails_closed(sandbox: Sandbox) -> None:
    engagement, _ = sandbox.provision()

    def unavailable() -> Decision | None:
        raise RuntimeError("test-only authority task failure")

    with ThreadPoolExecutor(max_workers=1) as executor:
        result, receipt = sandbox.store.reserve(
            engagement, 2, lambda _: Decision(allow=True, reason="ALLOWED"),
            authority=main.AuthorityChecks(executor, workers=1), state_check=unavailable,
        )
    assert result == Decision(reason="STATE_UNAVAILABLE") and receipt is None
    assert sandbox.store._read(sandbox.store._key(engagement))[1].active_workers == 0


def test_every_cas_retry_rechecks_authority_and_halt_cannot_commit(sandbox: Sandbox, monkeypatch: pytest.MonkeyPatch) -> None:
    engagement, _ = sandbox.provision()
    states = 0
    judgements = 0
    writes = 0

    def state() -> Decision | None:
        nonlocal states
        states += 1
        return None if states == 1 else Decision(reason="STATE_DENIED")

    def judge(_: main.Runtime) -> Decision:
        nonlocal judgements
        judgements += 1
        return Decision(allow=True, reason="ALLOWED")

    def retry(script: str, key: str, *arguments: str) -> str:
        nonlocal writes
        writes += 1
        return "retry"

    monkeypatch.setattr(sandbox.store, "_update", retry)
    with ThreadPoolExecutor(max_workers=1) as executor:
        result, receipt = sandbox.store.reserve(
            engagement, 2, judge, authority=main.AuthorityChecks(executor, workers=1), state_check=state,
        )
    assert result == Decision(reason="STATE_DENIED") and receipt is None
    assert states == 2 and judgements == 2 and writes == 1
    assert sandbox.store._read(sandbox.store._key(engagement))[1].active_workers == 0


def test_policy_failure_drains_pending_authority_before_return(sandbox: Sandbox) -> None:
    engagement, _ = sandbox.provision()
    started = Event()
    failed = Event()
    release = Event()
    completed = Event()

    def state() -> Decision | None:
        started.set()
        assert release.wait(5)
        completed.set()
        return None

    def unavailable(runtime: main.Runtime) -> Decision:
        assert started.wait(5)
        failed.set()
        raise main.InvalidInput("test-only broken policy query")
    with ThreadPoolExecutor(max_workers=1) as executor, ThreadPoolExecutor(max_workers=1) as requests:
        future = requests.submit(
            sandbox.store.reserve, engagement, 2, unavailable,
            authority=main.AuthorityChecks(executor, workers=1), state_check=state,
        )
        try:
            assert failed.wait(5)
            assert not future.done() and not completed.is_set()
        finally:
            release.set()
        with pytest.raises(main.InvalidInput):
            future.result(timeout=5)
        assert completed.is_set()


def test_authority_pool_bounds_jobs_and_releases_slots() -> None:
    release = Event()
    both_started = Event()
    lock = Lock()
    active = 0
    maximum = 0

    def state() -> Decision | None:
        nonlocal active, maximum
        with lock:
            active += 1
            maximum = max(maximum, active)
            if active == 2:
                both_started.set()
        try:
            assert release.wait(5)
            return None
        finally:
            with lock:
                active -= 1

    with ThreadPoolExecutor(max_workers=4) as executor, ThreadPoolExecutor(max_workers=6) as requests:
        authority = main.AuthorityChecks(executor, workers=2)

        def check() -> Decision | None:
            with authority.pending(state) as future:
                return future.result()

        futures = [requests.submit(check) for _ in range(6)]
        try:
            assert both_started.wait(5)
            with lock:
                assert active == 2
        finally:
            release.set()
        assert [future.result(timeout=5) for future in futures] == [None] * 6
    assert maximum == 2 and active == 0


def test_closed_authority_executor_fails_closed_and_releases_slot() -> None:
    executor = ThreadPoolExecutor(max_workers=1)
    authority = main.AuthorityChecks(executor, workers=1)
    executor.shutdown(wait=True)
    for _ in range(2):
        with pytest.raises(main.InvalidInput):
            with authority.pending(lambda: None):
                pytest.fail("closed executor must never yield an admission proof")


def test_invalid_accounting_and_backwards_clock_precede_authority_launch(sandbox: Sandbox) -> None:
    engagement, _ = sandbox.provision()
    key = sandbox.store._key(engagement)
    states = 0

    def state() -> Decision | None:
        nonlocal states
        states += 1
        return Decision(reason="STATE_DENIED")

    store = main.AccountStore(sandbox.store.redis, time_us=lambda: 9)
    with ThreadPoolExecutor(max_workers=1) as executor:
        authority = main.AuthorityChecks(executor, workers=1)
        sandbox.store.redis.hset(key, "state", "{}")
        with pytest.raises(ValueError):
            store.reserve(engagement, 2, lambda _: Decision(allow=True, reason="ALLOWED"), authority=authority, state_check=state)
        sandbox.store.redis.hset(key, "state", main.Bucket(credit=0, at_us=10, rate=2, active_workers=0, errors_5xx=0).model_dump_json())
        result, receipt = store.reserve(
            engagement, 2, lambda _: Decision(allow=True, reason="ALLOWED"), authority=authority, state_check=state,
        )
        assert result == Decision(reason="CLOCK_UNAVAILABLE") and receipt is None
    assert states == 0


@pytest.mark.parametrize(("initial", "joined", "end", "expected", "reason", "checks"), [
    ("2026-12-01T12:00:00+00:00", "2026-12-01T12:00:00.001000+00:00", "2026-12-10T08:00:00Z", True, "ALLOWED", 1),
    ("2026-12-10T07:59:59.999999+00:00", "2026-12-10T08:00:00+00:00", "2026-12-10T08:00:00Z", False, "WINDOW_DENIED", 2),
    ("2026-12-04T23:59:59.999999+00:00", "2026-12-05T00:00:00+00:00", "2026-12-10T08:00:00Z", False, "WINDOW_DENIED", 2),
    ("2026-12-01T12:00:00+00:00", "2026-12-01T07:59:59.999999+00:00", "2026-12-10T08:00:00Z", False, "WINDOW_DENIED", 2),
    ("2026-12-01T12:00:00+00:00", "2026-12-01T11:59:59+00:00", "2026-12-10T08:00:00Z", True, "ALLOWED", 2),
    ("2026-12-01T11:59:59.999999+00:00", "2026-12-01T12:00:00+00:00", "2026-12-01T12:00:00.000000500Z", True, "ALLOWED", 2),
    ("2026-12-01T11:59:59.999999+00:00", "2026-12-01T12:00:00.000001+00:00", "2026-12-01T12:00:00.000000500Z", False, "WINDOW_DENIED", 2),
    ("2026-12-01T12:00:00+00:00", "2026-12-01T12:00:00", "2026-12-10T08:00:00Z", False, "CLOCK_UNAVAILABLE", 2),
    ("2026-12-01T14:00:00+02:00", "2026-12-01T07:00:00-05:00", "2026-12-10T08:00:00Z", True, "ALLOWED", 1),
])
def test_slow_authority_join_preserves_fresh_opa_window(
    sandbox: Sandbox, monkeypatch: pytest.MonkeyPatch, initial: str, joined: str,
    end: str, expected: bool, reason: str, checks: int,
) -> None:
    engagement, digest = sandbox.provision()
    document = json.loads((sandbox.directory / f"{digest}.json").read_bytes())
    document["valid_window"]["not_after"] = end
    raw = json.dumps(document).encode()
    digest = hashlib.sha256(raw).hexdigest()
    (sandbox.directory / f"{digest}.json").write_bytes(raw)
    now = datetime.fromisoformat(initial)
    first_policy_done = Event()
    original = main.check_rules
    samples: list[datetime] = []

    def rules(opa: httpx.Client, manifest: dict[str, object], request: HttpRequest,
              at: datetime, runtime: main.Runtime) -> Decision:
        samples.append(at)
        result = original(opa, manifest, request, at, runtime)
        if len(samples) == 1:
            assert result.allow
            first_policy_done.set()
        return result

    def state(_: httpx.Request) -> httpx.Response:
        nonlocal now
        assert first_policy_done.wait(5)
        now = datetime.fromisoformat(joined)
        return httpx.Response(200, json={"state": "CONTROLLED_VALIDATION"})

    monkeypatch.setattr(main, "check_rules", rules)
    app = create_app(manifest_dir=sandbox.directory, orchestrator_url="http://m2.invalid", opa_url=sandbox.opa,
                     redis_url=sandbox.redis_url, clock=lambda: now, transport=httpx.MockTransport(state))
    with TestClient(app) as client:
        response = client.post("/evaluate", json=envelope(digest))
        decision(response, expected)
        assert response.json()["reason"] == reason
        assert len(samples) == checks
        if expected:
            assert sandbox.store.complete(engagement, response.headers[HEADER], 200)
        else:
            assert sandbox.store._read(sandbox.store._key(engagement))[1].active_workers == 0
