"""Conservative cache proof and atomic, retry-safe trusted settlement protocol."""

import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from threading import Barrier
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
