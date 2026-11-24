"""Run browser acceptance against disposable, loopback-only M2, M6 and M7.

Use a Python environment with the existing services' dependencies, Docker with
postgres:17-alpine and redis:7-alpine, and `npm ci` in apps/web. Chromium can be
provided via M10_CHROMIUM_EXECUTABLE or installed with Playwright. The runner
never reads an existing database or operator keystore configuration.
"""

from __future__ import annotations

from collections.abc import Callable
from contextlib import ExitStack
from dataclasses import dataclass
from hashlib import sha256
import json
import os
from pathlib import Path
import secrets
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time
from typing import TypeVar
from urllib.request import HTTPRedirectHandler, Request, ProxyHandler, build_opener
from uuid import uuid4

import psycopg
from psycopg.types.json import Jsonb
from redis import Redis
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

WEB = Path(__file__).resolve().parents[1]
REPO = WEB.parents[1]
OPERATOR = "m10-fixture-operator"
FINDING_ID = "m10-finding"
ARTIFACT = b"RedOps synthetic evidence. No client data.\n"
T = TypeVar("T")


@dataclass(frozen=True)
class TestSession:
    work_dir: Path
    postgres: str
    redis: str
    lock_id: str
    stop_id: str
    review_id: str
    signer_path: Path
    audit_token: str
    public_key: str


def available_port() -> int:
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return int(listener.getsockname()[1])


def docker(*args: str) -> str:
    return subprocess.check_output(["docker", *args], text=True, timeout=30).strip()


def ephemeral_container(stack: ExitStack, image: str, port: int, *settings: str) -> int:
    name = f"redops-m10-{uuid4().hex[:12]}"
    docker("run", "--pull=never", "--rm", "--detach", "--name", name,
           "--publish", f"127.0.0.1::{port}", *settings, image)
    stack.callback(subprocess.run, ["docker", "rm", "-f", name],
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=15, check=False)
    host, host_port = docker("port", name, f"{port}/tcp").rsplit(":", 1)
    if host != "127.0.0.1":
        raise RuntimeError("Test container must bind loopback only")
    return int(host_port)


def wait_for(check: Callable[[], T], label: str, *, seconds: float = 20) -> T:
    deadline = time.monotonic() + seconds
    while True:
        try:
            return check()
        except (OSError, RuntimeError, psycopg.OperationalError) as error:
            if time.monotonic() >= deadline:
                raise RuntimeError(f"{label} was not ready") from error
            time.sleep(0.15)


def start_session(stack: ExitStack, work_dir: Path) -> tuple[TestSession, Ed25519PrivateKey]:
    password = secrets.token_hex(20)
    port = ephemeral_container(stack, "postgres:17-alpine", 5432,
                               "-e", "POSTGRES_DB=m10_fixture", "-e", f"POSTGRES_PASSWORD={password}")
    redis_port = ephemeral_container(stack, "redis:7-alpine", 6379)
    key = Ed25519PrivateKey.generate()
    signer_path = work_dir / "fixture-signing-key.pem"
    with os.fdopen(
        os.open(signer_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600), "wb"
    ) as handle:
        handle.write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                       serialization.NoEncryption()))
    stack.callback(signer_path.unlink, missing_ok=True)
    session = TestSession(
        work_dir=work_dir,
        postgres=f"postgresql://postgres:{password}@127.0.0.1:{port}/m10_fixture?connect_timeout=2",
        redis=f"redis://127.0.0.1:{redis_port}/0",
        lock_id=str(uuid4()),
        stop_id=str(uuid4()),
        review_id=str(uuid4()),
        signer_path=signer_path,
        audit_token=secrets.token_urlsafe(24),
        public_key=key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex(),
    )
    with Redis.from_url(session.redis, socket_connect_timeout=2, socket_timeout=2) as redis:
        # The queue is disposable, including all killswitch messages.
        from redis.exceptions import RedisError

        def ready() -> None:
            try:
                redis.ping()
            except RedisError as error:
                raise RuntimeError("Redis is starting") from error

        wait_for(ready, "Fixture Redis")
    return session, key


def canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode()


def provision_fixture(session: TestSession, key: Ed25519PrivateKey) -> Path:
    # Normalize and sign the synthetic RoE like the repository's MS1 capstone.
    sys.path.insert(0, str(REPO / "packages/contracts-py"))
    from contracts.roe import RoeManifest

    document = json.loads((REPO / "tests/fixtures/roe_sample.json").read_bytes())
    document["engagement_id"] = session.lock_id
    # No assessment traffic is enabled by this fixture.
    document["scope_boundaries"]["allowed_identifiers"] = ["fixture.example.test"]
    document["traffic_constraints"]["required_attribution_header"] = (
        f"X-Security-Assessment-ID: {session.lock_id}"
    )
    normalized = RoeManifest.model_validate_json(canonical(document), strict=True)
    unsigned = canonical(normalized.model_dump(mode="json", exclude={"signatures"}))
    manifest_signature = key.sign(unsigned)
    key.public_key().verify(manifest_signature, unsigned)
    document = normalized.model_dump(mode="json")
    document["signatures"]["lead_operator_sig"] = f"ed25519:{manifest_signature.hex()}"
    manifest = RoeManifest.model_validate_json(canonical(document), strict=True)

    # Use IDs from the known graph fixture, with simple synthetic labels and a
    # single documented reachability edge. This is read-only graph review.
    graph_fixture = json.loads((REPO / "tests/fixtures/graph_known.json").read_bytes())
    src = graph_fixture["nodes"][0]["id"]
    dst = graph_fixture["nodes"][1]["id"]
    engagement = session.review_id
    nodes = [
        {"id": src, "engagement_id": engagement, "asset_category": "HOST_SERVICE",
         "canonical_identifier": "gateway.example.test", "metadata": {}, "discovered_by": "SYSTEM"},
        {"id": dst, "engagement_id": engagement, "asset_category": "HOST_SERVICE",
         "canonical_identifier": "inventory.example.test", "metadata": {"tier0": True}, "discovered_by": "SYSTEM"},
    ]
    edge = {"id": "m10-fixture-edge", "engagement_id": engagement, "src_node": src, "dst_node": dst,
            "edge_kind": "NET_REACH", "traversal_cost": 1, "proven_by_finding": FINDING_ID}
    finding = {"id": FINDING_ID, "engagement_id": engagement, "title": "Review maintenance access",
               "status": "HYPOTHESIS", "confidence_score": 0.86}
    task = {"id": "m10-task", "engagement_id": engagement, "status": "PAUSED_HITL",
            "mode": "AI_PROPOSED_HITL_GATED"}
    proposals = [
        {"plan": {"id": "m10-plan-read", "engagement_id": engagement, "blast_radius": "READ_ONLY"},
         "finding_id": FINDING_ID, "title": "Review status response", "score": 0.99,
         "request": "GET /fixture/status HTTP/1.1", "expected_delta": "Read existing status only."},
        {"plan": {"id": "m10-plan-hold", "engagement_id": engagement, "blast_radius": "DESTRUCTIVE"},
         "finding_id": FINDING_ID, "title": "Review archive deletion proposal", "score": 0.35,
         "request": "Fixture archive removal proposal (display only).",
         "expected_delta": "One synthetic archive would be removed."},
    ]
    snapshot = {
        "engagementId": engagement,
        "nodes": nodes, "edges": [edge], "findings": [finding], "proposals": proposals,
        "tasks": [{"task": task, "title": "Review fixture exposure", "confidence": 0.86,
                   "reasoning_trace": ["Review imported evidence and note data provenance."],
                   "proposal_id": "m10-plan-read"}],
    }
    path = session.work_dir / "review-snapshot.json"
    path.write_bytes(canonical(snapshot))

    with wait_for(lambda: psycopg.connect(session.postgres), "Fixture PostgreSQL") as db:
        db.execute((REPO / "db/schema.sql").read_text())
        db.execute("INSERT INTO engagements (id,roe_manifest,roe_signature_hash) VALUES (%s,%s,%s)", (
            session.lock_id, Jsonb(manifest.model_dump(mode="json")), sha256(manifest_signature).hexdigest(),
        ))
        db.execute("INSERT INTO engagements (id) VALUES (%s),(%s)", (session.stop_id, engagement))
        db.execute("INSERT INTO findings (engagement_id,id,title,confidence_score,status) VALUES (%s,%s,%s,%s,%s)", (
            engagement, FINDING_ID, finding["title"], finding["confidence_score"], finding["status"],
        ))
        for node in nodes:
            db.execute("""INSERT INTO asset_nodes (engagement_id,id,asset_category,canonical_identifier,
                          metadata,discovered_by) VALUES (%s,%s,%s,%s,%s,%s)""", (
                engagement, node["id"], node["asset_category"], node["canonical_identifier"],
                Jsonb(node["metadata"]), node["discovered_by"],
            ))
        db.execute("""INSERT INTO asset_edges (engagement_id,id,src_node,dst_node,edge_kind,
                      traversal_cost,proven_by_finding) VALUES (%s,%s,%s,%s,%s,%s,%s)""", (
            engagement, edge["id"], src, dst, edge["edge_kind"], edge["traversal_cost"], FINDING_ID,
        ))
    return path


def stop_process(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is not None:
        return
    os.killpg(process.pid, signal.SIGTERM)
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        os.killpg(process.pid, signal.SIGKILL)
        process.wait(timeout=5)


def start_process(stack: ExitStack, command: list[str], *, cwd: Path,
                  env: dict[str, str], log: Path | None = None) -> subprocess.Popen[bytes]:
    writer = stack.enter_context(log.open("wb")) if log else None
    child = subprocess.Popen(command, cwd=cwd, env=env, stdin=subprocess.DEVNULL,
                             stdout=writer, stderr=subprocess.STDOUT if log else None,
                             start_new_session=True)
    stack.callback(stop_process, child)
    return child


class RejectRedirect(HTTPRedirectHandler):
    def redirect_request(self, *args: object, **kwargs: object) -> None:
        return None


def http(url: str, *, method: str = "GET", data: bytes | None = None,
         headers: dict[str, str] | None = None) -> dict[str, object]:
    opener = build_opener(ProxyHandler({}), RejectRedirect())
    with opener.open(Request(url, method=method, data=data, headers=headers or {}), timeout=3) as response:
        payload = json.load(response)
    if not isinstance(payload, dict):
        raise RuntimeError(f"Unexpected fixture response from {url}")
    return payload


def start_service(stack: ExitStack, session: TestSession, name: str, env: dict[str, str]) -> str:
    port = available_port()
    origin = f"http://127.0.0.1:{port}"
    child = start_process(stack, [sys.executable, "-m", "uvicorn", "main:app", "--host", "127.0.0.1",
                                  "--port", str(port), "--no-access-log"], cwd=REPO / "apps" / name,
                          env=env, log=session.work_dir / f"{name}.log")

    def ready() -> object:
        if child.poll() is not None:
            raise SystemExit(f"{name} exited before startup, see {session.work_dir}")
        return http(f"{origin}/openapi.json")

    wait_for(ready, name)
    return origin


def link_evidence(session: TestSession, orchestrator: str, evidence: str) -> None:
    receipt = http(f"{orchestrator}/engagements/{session.review_id}/audit-events", method="POST", data=canonical({
        "actor_kind": "SYSTEM", "actor_id": "scoped-proxy", "event_type": "EVIDENCE_FIXTURE",
        "payload": {"synthetic": True},
    }), headers={"Content-Type": "application/json", "Authorization": f"Bearer {session.audit_token}"})
    artifact = http(f"{evidence}/artifacts", method="PUT", data=ARTIFACT,
                    headers={"Content-Type": "application/octet-stream"})
    if artifact["sha256"] != sha256(ARTIFACT).hexdigest():
        raise RuntimeError("Synthetic artifact digest diverged")
    http(f"{evidence}/link", method="POST", data=canonical({"engagement_id": session.review_id,
         "finding_id": FINDING_ID, "sha256": artifact["sha256"], "record_hash": receipt["record_hash"]}),
         headers={"Content-Type": "application/json"})


def main() -> int:
    # Environment inheritance is limited to executable discovery and cert files.
    # In particular, imported DB, proxy, service and signing settings are ignored.
    base = {name: os.environ[name] for name in ("PATH", "LANG", "LC_ALL", "SSL_CERT_FILE", "HOME")
            if name in os.environ}
    base["PYTHONDONTWRITEBYTECODE"] = "1"
    log_root = Path(os.environ.get("M10_ARTIFACTS", tempfile.gettempdir())).resolve()
    log_root.mkdir(parents=True, exist_ok=True)
    work_dir = Path(tempfile.mkdtemp(prefix="m10-e2e-", dir=log_root))
    print(f"M10 fixture logs and Playwright results: {work_dir}", flush=True)
    with ExitStack() as stack:
        session, key = start_session(stack, work_dir)
        snapshot = provision_fixture(session, key)
        services = {**base, "PYTHONPATH": str(REPO / "packages/contracts-py"),
                    "DATABASE_URL": session.postgres, "REDIS_URL": session.redis,
                    "M4_AUDIT_TOKEN": session.audit_token,
                    "ORCHESTRATOR_OPERATOR_PUBLIC_KEYS": json.dumps({OPERATOR: session.public_key}),
                    "EVIDENCE_ROOT": str(work_dir / "evidence")}
        orchestrator = start_service(stack, session, "orchestrator", services)
        graph = start_service(stack, session, "graph-svc", services)
        evidence = start_service(stack, session, "evidence-svc", services)
        link_evidence(session, orchestrator, evidence)
        web_port = available_port()
        web = f"http://127.0.0.1:{web_port}"
        vite = start_process(stack, ["npm", "run", "dev", "--", "--host", "127.0.0.1", "--port",
                                     str(web_port), "--strictPort"], cwd=WEB,
                             env={**base, "REDOPS_ORCHESTRATOR_URL": orchestrator, "REDOPS_GRAPH_URL": graph,
                                  "REDOPS_EVIDENCE_URL": evidence}, log=work_dir / "vite.log")

        def ready() -> object:
            if vite.poll() is not None:
                raise SystemExit(f"Vite exited before startup, see {work_dir}")
            return http(f"{web}/api/orchestrator/engagements/{session.lock_id}/state")

        if wait_for(ready, "Vite proxy") != {"state": "INIT_SCOPING"}:
            raise RuntimeError("Configured proxy did not reach the disposable orchestrator")
        test_env = {**base, "M10_WEB_URL": web, "M10_OPERATOR": OPERATOR, "M10_SIGNER_PATH": str(session.signer_path),
                    "M10_LOCK_ID": session.lock_id, "M10_STOP_ID": session.stop_id,
                    "M10_REVIEW_ID": session.review_id, "M10_SNAPSHOT_PATH": str(snapshot),
                    "M10_PLAYWRIGHT_OUTPUT": str(work_dir / "playwright"), "CI": "1"}
        chromium = os.environ.get("M10_CHROMIUM_EXECUTABLE") or shutil.which("chromium")
        if chromium:
            test_env["M10_CHROMIUM_EXECUTABLE"] = chromium
        test = start_process(stack, ["npm", "run", "e2e", "--", *sys.argv[1:]], cwd=WEB, env=test_env)
        return test.wait(timeout=180)


if __name__ == "__main__":
    raise SystemExit(main())
