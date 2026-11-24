#!/usr/bin/env python3
"""Live MS1 acceptance: signed M2 progression -> real M3/OPA -> M4 -> M7.

Run against disposable, schema-initialized PostgreSQL, Redis and OPA with the
repository's policy bundle loaded. No service or authorization dependency is
mocked. Only the loopback practice origin is synthetic. Example:

  python apps/scoped-proxy/tests/ms1_capstone.py \
    --python /path/to/venv/bin/python --proxy-binary target/release/scoped-proxy \
    --database-url postgresql://... --redis-url redis://127.0.0.1:6379/0 \
    --opa-url http://127.0.0.1:8181 --work-dir work/ms1

The Python environment needs the three services' dependencies. --benchmark also
runs the existing ignored release load test on this real stack. --profile runs
diagnostic HTTP requests (64 by default) with four workers and proxy phase traces;
its timings do not substitute for the acceptance benchmark. Process logs,
test-only keys, CAS artifacts and a machine-readable result remain in work-dir.
No current_state updates occur outside M2; setup only inserts INIT_SCOPING.
"""
from __future__ import annotations

import argparse
from contextlib import ExitStack
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta, timezone
import hashlib
import http.client
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import secrets
import shutil
import signal
import socket
import ssl
import subprocess
import sys
import threading
import time
import traceback
import uuid

REPO = Path(__file__).resolve().parents[3]
REQUEST_BODY = b"MS1 authorized synthetic request\x00\xff\n"
RESPONSE_BODY = b"redops-range-web-01: synthetic practice app\x00\xfe\n"
ATTRIBUTION = "X-Security-Assessment-ID"


def require(condition: object, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode()


def free_port() -> int:
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return int(listener.getsockname()[1])


def json_request(url: str, method: str = "GET", value: object = None) -> tuple[int, object]:
    from urllib.parse import urlsplit
    parsed = urlsplit(url)
    connection = http.client.HTTPConnection(parsed.hostname, parsed.port, timeout=5)
    try:
        body = canonical(value) if value is not None else None
        connection.request(method, parsed.path or "/", body,
                           {"Content-Type": "application/json"} if body is not None else {})
        response = connection.getresponse()
        data = response.read()
        return response.status, json.loads(data) if data else None
    finally:
        connection.close()


class Processes:
    def __init__(self, directory: Path) -> None:
        self.directory = directory
        self.children: list[tuple[str, subprocess.Popen[bytes], object, Path]] = []

    def start(self, name: str, command: list[str], env: dict[str, str], cwd: Path) -> None:
        path = self.directory / f"{name}.log"
        log = path.open("wb")
        try:
            child = subprocess.Popen(command, cwd=cwd, env=env, stdout=log,
                                     stderr=subprocess.STDOUT, start_new_session=True)
        except BaseException:
            log.close()
            raise
        self.children.append((name, child, log, path))

    def check(self) -> None:
        for name, child, _, _ in self.children:
            require(child.poll() is None, f"{name} exited with {child.returncode}")

    def ready_http(self, url: str) -> None:
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            self.check()
            try:
                if json_request(url)[0] == 200:
                    return
            except (OSError, ValueError, http.client.HTTPException):
                pass
            time.sleep(0.05)
        raise TimeoutError(f"service startup deadline: {url}")

    def close(self) -> None:
        for _, child, _, _ in reversed(self.children):
            if child.poll() is None:
                try:
                    os.killpg(child.pid, signal.SIGTERM)
                except ProcessLookupError:
                    pass
        for _, child, log, _ in reversed(self.children):
            try:
                child.wait(timeout=5)
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(child.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                child.wait(timeout=5)
            log.close()

    def print_logs(self) -> None:
        for name, _, _, path in self.children:
            print(f"\n{name} log ({path}):", file=sys.stderr)
            print(path.read_text(errors="replace")[-16000:], file=sys.stderr)


class PracticeOrigin(ThreadingHTTPServer):
    daemon_threads = True
    block_on_close = False

    def __init__(self) -> None:
        super().__init__(("127.0.0.1", 0), PracticeHandler)
        self.hits: list[dict[str, object]] = []
        self.lock = threading.Lock()

    def get_request(self) -> tuple[socket.socket, object]:
        accepted, address = super().get_request()
        accepted.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        return accepted, address

    def snapshot(self) -> list[dict[str, object]]:
        with self.lock:
            return list(self.hits)


class PracticeHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_POST(self) -> None:
        body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
        server = self.server
        assert isinstance(server, PracticeOrigin)
        with server.lock:
            server.hits.append({"path": self.path, "body": body,
                                "attribution": self.headers.get_all(ATTRIBUTION, [])})
        self.send_response(200)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Length", str(len(RESPONSE_BODY)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(RESPONSE_BODY)

    def log_message(self, *_: object) -> None:
        pass


def start_origin(stack: ExitStack, cert: Path | None = None, key: Path | None = None) -> PracticeOrigin:
    origin = PracticeOrigin()
    if cert is not None:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cert, key)
        origin.socket = context.wrap_socket(origin.socket, server_side=True)
    thread = threading.Thread(target=origin.serve_forever, daemon=True)
    thread.start()
    def close() -> None:
        origin.shutdown()
        origin.server_close()
        thread.join(timeout=3)
    stack.callback(close)
    return origin


def certificates(workspace: Path) -> tuple[Path, Path]:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID
    now = datetime.now(timezone.utc)
    ca_key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "MS1 disposable engagement CA")])
    ca = (x509.CertificateBuilder().subject_name(subject).issuer_name(subject)
          .public_key(ca_key.public_key()).serial_number(x509.random_serial_number())
          .not_valid_before(now - timedelta(minutes=5)).not_valid_after(now + timedelta(days=1))
          .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
          .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False,
              key_encipherment=False, data_encipherment=False, key_agreement=False,
              key_cert_sign=True, crl_sign=True, encipher_only=None, decipher_only=None), critical=True)
          .sign(ca_key, hashes.SHA256()))
    ca_pem = ca.public_bytes(serialization.Encoding.PEM)
    (workspace / "ca.pem").write_bytes(ca_pem)
    (workspace / "origin-ca.pem").write_bytes(ca_pem)
    (workspace / "ca-key.pem").write_bytes(ca_key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    key = ec.generate_private_key(ec.SECP256R1())
    leaf = (x509.CertificateBuilder().subject_name(x509.Name([
                x509.NameAttribute(NameOID.COMMON_NAME, "127.0.0.1")]))
            .issuer_name(subject).public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=5)).not_valid_after(now + timedelta(hours=2))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.SubjectAlternativeName([
                x509.IPAddress(ipaddress.ip_address("127.0.0.1")), x509.DNSName("localhost")]), critical=False)
            .sign(ca_key, hashes.SHA256()))
    cert_path, key_path = workspace / "fixture-cert.pem", workspace / "fixture-key.pem"
    cert_path.write_bytes(leaf.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM,
                        serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    return cert_path, key_path


def proxied(proxy_port: int, origin_port: int, engagement: str, path: str,
            ca: Path | None = None) -> tuple[int, bytes]:
    headers = {ATTRIBUTION: engagement.upper(), "Content-Type": "application/octet-stream",
               "Content-Length": str(len(REQUEST_BODY)), "Connection": "close"}
    if ca is None:
        connection = http.client.HTTPConnection("127.0.0.1", proxy_port, timeout=10)
        try:
            connection.request("POST", f"http://127.0.0.1:{origin_port}{path}", REQUEST_BODY, headers)
            response = connection.getresponse()
            return response.status, response.read()
        finally:
            connection.close()
    raw = socket.create_connection(("127.0.0.1", proxy_port), timeout=10)
    try:
        raw.sendall((f"CONNECT 127.0.0.1:{origin_port} HTTP/1.1\r\n"
                     f"Host: 127.0.0.1:{origin_port}\r\n{ATTRIBUTION}: {engagement.upper()}\r\n\r\n").encode())
        head = bytearray()
        while not head.endswith(b"\r\n\r\n"):
            chunk = raw.recv(1)
            require(chunk, "CONNECT closed before response")
            head.extend(chunk)
            require(len(head) < 16384, "oversized CONNECT response")
        require(head.split(b"\r\n", 1)[0].split()[1] == b"200", f"CONNECT rejected: {head!r}")
        context = ssl.create_default_context(cafile=str(ca))
        with context.wrap_socket(raw, server_hostname="127.0.0.1") as secured:
            request_head = f"POST {path} HTTP/1.1\r\nHost: 127.0.0.1:{origin_port}\r\n"
            request_head += "".join(f"{name}: {value}\r\n" for name, value in headers.items())
            secured.sendall(request_head.encode() + b"\r\n" + REQUEST_BODY)
            response = http.client.HTTPResponse(secured)
            response.begin()
            return response.status, response.read()
    finally:
        raw.close()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--python", default=sys.executable)
    parser.add_argument("--proxy-binary", required=True, type=Path)
    parser.add_argument("--database-url", default=os.getenv("DATABASE_URL"), required=not bool(os.getenv("DATABASE_URL")))
    parser.add_argument("--redis-url", default=os.getenv("REDIS_URL"), required=not bool(os.getenv("REDIS_URL")))
    parser.add_argument("--opa-url", default=os.getenv("OPA_URL"), required=not bool(os.getenv("OPA_URL")))
    parser.add_argument("--work-dir", required=True, type=Path)
    parser.add_argument("--benchmark", action="store_true")
    parser.add_argument("--profile", action="store_true",
                        help="run diagnostic HTTP requests at concurrency 4 with proxy phase traces")
    parser.add_argument("--profile-count", type=int, default=64, metavar="1..4096",
                        help="diagnostic request count (default: 64; maximum: 4096)")
    args = parser.parse_args()
    if not 1 <= args.profile_count <= 4096:
        parser.error("--profile-count must be between 1 and 4096")
    args.python = os.path.abspath(shutil.which(args.python) or args.python)
    # Honor the selected service interpreter for both the harness and subprocesses.
    if Path(args.python).absolute() != Path(sys.executable).absolute():
        os.execv(args.python, [args.python, str(Path(__file__).resolve()), *sys.argv[1:]])
    sys.path.insert(0, str(REPO / "packages/contracts-py"))
    from contracts.events import ActorType, Ed25519Signature, EngagementState, TransitionEvent
    from contracts.ledger import LedgerRecord
    from contracts.roe import RoeManifest
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    import psycopg
    from redis import Redis

    require(args.proxy_binary.resolve().is_file(), "proxy binary does not exist; build --release first")
    profile_raw = (REPO / "tests/fixtures/metasploitable_target_profile.json").read_bytes()
    profile = json.loads(profile_raw)
    require(profile["safe_for_active_validation"] is True and profile["name"] == "redops-range-web-01",
            "MS1 requires the approved synthetic practice target profile")
    work = args.work_dir.resolve()
    work.mkdir(parents=True, exist_ok=True, mode=0o700)
    # Refuse accidental reuse; preexisting manifests/evidence could mask missing writes.
    run = work / ("run-" + str(uuid.uuid4()))
    run.mkdir(mode=0o700)
    engagement = str(uuid.uuid4())
    workspace = run / "workspaces" / engagement
    workspace.mkdir(parents=True, mode=0o700)
    manifests = run / "manifests"
    manifests.mkdir()
    keys = Ed25519PrivateKey.generate()
    public = keys.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    (run / "operator-test-key.pem").write_bytes(keys.private_bytes(serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    operator = "ms1-test-operator"
    audit_token = secrets.token_urlsafe(32)
    processes = Processes(run)
    result: dict[str, object] = {"engagement_id": engagement, "run_dir": str(run),
        "fixture": profile["fixture_urn"], "fixture_sha256": hashlib.sha256(profile_raw).hexdigest(),
        "status": "running"}
    try:
        with ExitStack() as stack:
            stack.callback(processes.close)
            cert, key = certificates(workspace)
            http_origin = start_origin(stack)
            https_origin = start_origin(stack, cert, key)
            now = datetime.now(timezone.utc)
            document = json.loads((REPO / "tests/fixtures/roe_sample.json").read_bytes())
            document.update(engagement_id=engagement, execution_mode="HYBRID")
            document["valid_window"] = {
                "not_before": (now - timedelta(minutes=5)).isoformat(),
                "not_after": (now + timedelta(hours=2)).isoformat(),
                "allowed_days_utc": ["MON", "TUE", "WED", "THU", "FRI", "SAT", "SUN"]}
            document["scope_boundaries"] = {"allowed_cidrs": ["127.0.0.1/32"],
                "allowed_identifiers": ["127.0.0.1"], "excluded_paths": ["/admin/reset-tenant"],
                "allowed_http_methods": ["GET", "POST"]}
            document["traffic_constraints"] = {"max_requests_per_second": 1000000,
                "max_concurrent_workers": 64, "required_attribution_header": f"{ATTRIBUTION}: {engagement}",
                "circuit_breaker_5xx_threshold": 5}
            policies = sorted((REPO / "packages/policy-bundles").glob("*.rego"))
            document["signatures"] = {"policy_hash_sha256": hashlib.sha256(
                b"".join(path.read_bytes() for path in policies)).hexdigest(),
                "lead_operator_sig": "ed25519:" + "0" * 128}
            # Normalize through the frozen model before signing: timestamp spelling is
            # part of the byte envelope. Sign exactly the persisted manifest fields
            # excluding signatures, then independently verify that persisted envelope.
            normalized = RoeManifest.model_validate_json(canonical(document), strict=True)
            document = normalized.model_dump(mode="json")
            manifest_envelope = canonical(normalized.model_dump(mode="json", exclude={"signatures"}))
            manifest_signature = keys.sign(manifest_envelope)
            document["signatures"]["lead_operator_sig"] = "ed25519:" + manifest_signature.hex()
            manifest = RoeManifest.model_validate_json(canonical(document), strict=True)
            raw = manifest.model_dump_json().encode()
            persisted = RoeManifest.model_validate_json(raw, strict=True)
            keys.public_key().verify(bytes.fromhex(persisted.signatures.lead_operator_sig.removeprefix("ed25519:")),
                canonical(persisted.model_dump(mode="json", exclude={"signatures"})))
            digest = hashlib.sha256(raw).hexdigest()
            (manifests / f"{digest}.json").write_bytes(raw)
            (workspace / "manifest.json").write_bytes(raw)
            (workspace / "manifest.sha256").write_text(digest + "\n")
            with psycopg.connect(args.database_url) as connection:
                connection.execute("INSERT INTO engagements (id, roe_manifest, roe_signature_hash) VALUES (%s,%s::jsonb,%s)",
                                   (engagement, raw.decode(), hashlib.sha256(manifest_signature).hexdigest()))
            spec = importlib.util.spec_from_file_location("ms1_policy_provision", REPO / "apps/policy-svc/main.py")
            assert spec is not None and spec.loader is not None
            policy_module = importlib.util.module_from_spec(spec)
            sys.modules[spec.name] = policy_module
            spec.loader.exec_module(policy_module)
            redis = Redis.from_url(args.redis_url, decode_responses=True, socket_timeout=3)
            stack.callback(redis.close)
            redis.ping()
            policy_module.AccountStore(redis).initialize(engagement)
            require(json_request(args.opa_url.rstrip("/") + "/health")[0] == 200, "OPA unhealthy")
            ports: list[int] = []
            while len(ports) < 4:
                port = free_port()
                if port not in ports:
                    ports.append(port)
            orchestrator_port, policy_port, evidence_port, proxy_port = ports
            env = dict(os.environ)
            env.update(DATABASE_URL=args.database_url, REDIS_URL=args.redis_url,
                ORCHESTRATOR_URL=f"http://127.0.0.1:{orchestrator_port}",
                POLICY_URL=f"http://127.0.0.1:{policy_port}",
                EVIDENCE_URL=f"http://127.0.0.1:{evidence_port}", OPA_URL=args.opa_url,
                POLICY_MANIFEST_DIR=str(manifests), EVIDENCE_ROOT=str(run / "evidence"),
                SCOPED_PROXY_WORKSPACE_DIR=str(workspace.parent),
                SCOPED_PROXY_LISTEN=f"127.0.0.1:{proxy_port}", M4_AUDIT_TOKEN=audit_token,
                ORCHESTRATOR_OPERATOR_PUBLIC_KEYS=json.dumps({operator: public.hex()}),
                PYTHONPATH=str(REPO / "packages/contracts-py"), PYTHONUNBUFFERED="1")
            if args.profile:
                env["SCOPED_PROXY_TRACE_TIMING"] = "1"
            for name, directory, port in [("orchestrator", "orchestrator", orchestrator_port),
                    ("policy", "policy-svc", policy_port), ("evidence", "evidence-svc", evidence_port)]:
                processes.start(name, [args.python, "-m", "uvicorn", "main:app", "--host", "127.0.0.1",
                    "--port", str(port), "--no-access-log"], env, REPO / "apps" / directory)
                processes.ready_http(f"http://127.0.0.1:{port}/openapi.json")
            processes.start("proxy", [str(args.proxy_binary.resolve())], env, REPO)
            # The initial response is itself the readiness proof: listener plus Redis subscription
            # and the real M2 check must all be ready before PRECONDITION_FAILED is possible.
            deadline = time.monotonic() + 30
            while True:
                processes.check()
                try:
                    status, body = proxied(proxy_port, http_origin.server_port, engagement, "/ms1/check")
                    if status == 412:
                        break
                    require(status == 503, f"unexpected startup response: {status} {body!r}")
                except (OSError, http.client.HTTPException):
                    if time.monotonic() >= deadline:
                        raise
                require(time.monotonic() < deadline, "proxy startup deadline")
                time.sleep(0.05)
            require(json.loads(body) == {"reason": "PRECONDITION_FAILED"}, "pre-RoE rejection reason")
            require(not http_origin.snapshot() and not https_origin.snapshot(), "origin hit before RoE")
            state_url = env["ORCHESTRATOR_URL"] + f"/engagements/{engagement}"
            chain = [EngagementState.INIT_SCOPING, EngagementState.ROE_LOCKED,
                     EngagementState.DISCOVERY_PASSIVE, EngagementState.ANALYTICAL_TRIAGE,
                     EngagementState.AWAITING_HITL_GATE, EngagementState.CONTROLLED_VALIDATION]
            transition_hashes: list[str] = []
            for source, target in zip(chain, chain[1:]):
                event = TransitionEvent(event_id=str(uuid.uuid4()), engagement_id=engagement,
                    from_state=source, to_state=target, actor_type=ActorType.HUMAN_OPERATOR,
                    actor_id=operator, occurred_at=datetime.now(timezone.utc))
                signed = event.model_copy(update={"hitl_signature": Ed25519Signature(
                    signer_id=operator, signature=keys.sign(event.canonical_envelope()).hex())})
                if source == EngagementState.INIT_SCOPING:
                    tampered = signed.model_dump(mode="json")
                    signature = tampered["hitl_signature"]["signature"]
                    tampered["hitl_signature"]["signature"] = ("0" if signature[0] != "0" else "1") + signature[1:]
                    denied, _ = json_request(state_url + "/transition", "POST", tampered)
                    require(denied == 403, f"tampered human approval accepted: {denied}")
                    require(json_request(state_url + "/ledger")[1] == [], "denied approval wrote ledger")
                status, answer = json_request(state_url + "/transition", "POST", signed.model_dump(mode="json"))
                require(status == 200 and answer["next_state"] == target, f"signed {source}->{target}: {status} {answer}")
                transition_hashes.append(answer["ledger_hash"])
            require(json_request(state_url + "/state")[1] == {"state": "CONTROLLED_VALIDATION"}, "M2 state")
            for scheme, origin, ca in [("http", http_origin, None), ("https", https_origin, workspace / "ca.pem")]:
                status, body = proxied(proxy_port, origin.server_port, engagement, "/ms1/check", ca)
                require(status == 200 and body == RESPONSE_BODY, f"{scheme} roundtrip failed: {status} {body!r}")
                hits = origin.snapshot()
                require(len(hits) == 1 and hits[0] == {"path": "/ms1/check", "body": REQUEST_BODY,
                    "attribution": [engagement]}, f"{scheme} attribution/body: {hits!r}")
                status, body = proxied(proxy_port, origin.server_port, engagement, "/admin/reset-tenant", ca)
                require(status == 403 and json.loads(body)["reason"] == "SCOPE_DENIED", f"{scheme} excluded path: {status} {body!r}")
                require(len(origin.snapshot()) == 1, f"{scheme} out-of-scope origin hit")
            status, records = json_request(state_url + "/ledger")
            require(status == 200, "ledger read failed")
            previous = "0" * 64
            completed = []
            for index, raw_record in enumerate(records):
                record = LedgerRecord.model_validate(raw_record)
                event = record.event
                require(record.prev_record_hash == previous, f"ledger predecessor at {index}")
                computed = hashlib.sha256(bytes.fromhex(previous) + canonical(event.model_dump(mode="json"))).hexdigest()
                require(record.record_hash == computed, f"ledger hash at {index}")
                previous = computed
                if isinstance(event, TransitionEvent):
                    require(index < 5 and computed == transition_hashes[index], "transition receipt/tail mismatch")
                    require(event.hitl_signature is not None, "unsigned test progression")
                    keys.public_key().verify(bytes.fromhex(event.hitl_signature.signature), event.canonical_envelope())
                elif event.event_type == "PROXY_REQUEST_COMPLETED":
                    completed.append(event)
            require(len(records) >= 7 and len(completed) == 2, "expected two durable completed request audits")
            artifact_digests = []
            evidenced_ports = set()
            for event in completed:
                require(event.actor_id == "scoped-proxy" and event.actor_kind == ActorType.SYSTEM, "audit actor")
                digest = event.payload["evidence_sha256"]
                connection = http.client.HTTPConnection("127.0.0.1", evidence_port, timeout=5)
                connection.request("GET", f"/artifacts/{digest}")
                response = connection.getresponse()
                artifact_bytes = response.read()
                connection.close()
                require(response.status == 200 and hashlib.sha256(artifact_bytes).hexdigest() == digest, "M7 evidence retrieval/hash")
                artifact = json.loads(artifact_bytes)
                require(artifact["engagement_id"] == engagement and artifact["event_id"] == str(event.event_id), "artifact identity")
                require(str(uuid.UUID(artifact["reservation"])) == event.payload["reservation"], "evidence/reservation binding")
                request = artifact["request"]
                require(request["method"] == "POST" and request["host"] == "127.0.0.1" and
                        request["ip"] == "127.0.0.1" and request["path"] == "/ms1/check", "evidence destination")
                require(request["port"] == event.payload["port"], "evidence/audit destination binding")
                evidenced_ports.add(request["port"])
                require(artifact["error"] is None and event.payload["status"] == 200 and
                        event.payload["evidence_acknowledged"] is True, "successful acknowledged evidence")
                require(artifact["request"]["body_hex"] == REQUEST_BODY.hex(), "exact request evidence bytes")
                require(artifact["response"]["body_hex"] == RESPONSE_BODY.hex(), "exact response evidence bytes")
                attribution = [value for name, value in artifact["request"]["headers"] if name.lower() == ATTRIBUTION.lower()]
                require(attribution == [engagement], "evidence canonical attribution")
                require(artifact["response"]["status"] == 200 and artifact["response"]["complete"] is True, "complete response evidence")
                artifact_digests.append(digest)
            require(evidenced_ports == {http_origin.server_port, https_origin.server_port}, "both origin protocols evidenced")
            with psycopg.connect(args.database_url) as connection:
                stored = connection.execute("SELECT payload, prev_record_hash, record_hash FROM immutable_audit_log WHERE engagement_id=%s ORDER BY seq_id", (engagement,)).fetchall()
                require(len(stored) == len(records), "live ledger/API cardinality mismatch")
                for row, record in zip(stored, records):
                    require(row[0] == record["event"] and row[1] == record["prev_record_hash"] and row[2] == record["record_hash"], "durable ledger/API mismatch")
            accounting_key = "redops:policy:v1:" + engagement
            state = json.loads(redis.hget(accounting_key, "state"))
            require(state["active_workers"] == 0 and redis.hlen(accounting_key) == 1, "unsettled M3 receipts after success")
            result.update(status="passed", checks=["pre_roe_412_no_egress", "tampered_signature_denied",
                "five_signed_transitions", "http_and_inspected_https", "canonical_attribution",
                "exact_request_response_evidence", "durable_hash_chain", "m7_retrieval",
                "excluded_path_403_no_egress", "redis_receipts_settled"],
                ledger_rows=len(records), evidence_sha256=artifact_digests, ledger_tail=previous)
            if args.profile:
                # This diagnostic uses the same signed engagement and all real service
                # controls. It intentionally does not change the committed load protocol
                # or claim its client elapsed times measure paired proxy overhead.
                def timed_request(index: int) -> dict[str, object]:
                    start = time.perf_counter_ns()
                    status, body = proxied(proxy_port, http_origin.server_port, engagement, "/ms1/check")
                    return {"index": index, "elapsed_ms": (time.perf_counter_ns() - start) / 1_000_000,
                            "status": status, "body_matches": body == RESPONSE_BODY}
                started = time.perf_counter()
                executor = ThreadPoolExecutor(max_workers=4)
                futures = [executor.submit(timed_request, index) for index in range(args.profile_count)]
                samples = []
                try:
                    for future in as_completed(futures, timeout=max(60, args.profile_count / 16)):
                        samples.append(future.result())
                finally:
                    executor.shutdown(wait=True, cancel_futures=True)
                elapsed = sorted(sample["elapsed_ms"] for sample in samples)
                diagnostic = {"diagnostic_only": True, "protocol": "HTTP POST /ms1/check",
                    "requests": len(samples), "concurrency": 4,
                    "batch_seconds": time.perf_counter() - started,
                    "p50_ms": elapsed[(50 * len(elapsed) + 99) // 100 - 1],
                    "p95_ms": elapsed[(95 * len(elapsed) + 99) // 100 - 1],
                    "p99_ms": elapsed[(99 * len(elapsed) + 99) // 100 - 1],
                    "samples": sorted(samples, key=lambda sample: sample["index"])}
                (run / "profile.json").write_text(json.dumps(diagnostic, indent=2) + "\n")
                require(len(samples) == args.profile_count and all(sample["status"] == 200 and sample["body_matches"]
                        for sample in samples), "diagnostic request failed; see profile.json and proxy.log")
                hits = http_origin.snapshot()
                require(len(hits) == args.profile_count + 1 and all(hit == {"path": "/ms1/check", "body": REQUEST_BODY,
                        "attribution": [engagement]} for hit in hits), "diagnostic origin attribution/body")
                require(json.loads(redis.hget(accounting_key, "state"))["active_workers"] == 0 and
                        redis.hlen(accounting_key) == 1, "diagnostic left M3 reservations")
                status, profiled_records = json_request(state_url + "/ledger")
                require(status == 200 and len(profiled_records) == len(records) + args.profile_count,
                        "diagnostic ledger cardinality")
                tail = "0" * 64
                for raw_record in profiled_records:
                    record = LedgerRecord.model_validate(raw_record)
                    computed = hashlib.sha256(bytes.fromhex(tail) +
                        canonical(record.event.model_dump(mode="json"))).hexdigest()
                    require(record.prev_record_hash == tail and record.record_hash == computed,
                            "diagnostic full ledger hash chain")
                    tail = computed
                result["profile"] = {name: value for name, value in diagnostic.items() if name != "samples"}
                result["profile"]["ledger_rows"] = len(profiled_records)
                result["profile"]["ledger_tail"] = tail
                print("Diagnostic profile: " + json.dumps(result["profile"]), flush=True)
            if args.benchmark:
                benchmark_env = dict(env, M4_LOAD_PROXY_ADDR=f"127.0.0.1:{proxy_port}",
                    M4_LOAD_ENGAGEMENT_ID=engagement, M4_LOAD_ORIGIN_PORT=str(free_port()))
                path = run / "benchmark.log"
                with path.open("wb") as log:
                    benchmark = subprocess.Popen(["cargo", "test", "--release", "--test", "load", "--", "--ignored", "--nocapture"],
                        cwd=REPO / "apps/scoped-proxy", env=benchmark_env, stdout=log,
                        stderr=subprocess.STDOUT, start_new_session=True)
                    try:
                        benchmark.wait(timeout=300)
                    finally:
                        # Cargo may own a test process: terminate the whole group on a
                        # deadline or interruption, including descendants after cargo exits.
                        try:
                            os.killpg(benchmark.pid, signal.SIGKILL)
                        except ProcessLookupError:
                            pass
                        benchmark.wait(timeout=5)
                print(path.read_text())
                require(benchmark.returncode == 0, f"benchmark failed; see {path}")
                require(json.loads(redis.hget(accounting_key, "state"))["active_workers"] == 0 and redis.hlen(accounting_key) == 1, "benchmark left M3 reservations")
                result["benchmark"] = "passed"
            processes.check()
    except BaseException:
        result["status"] = "failed"
        processes.close()
        processes.print_logs()
        raise
    finally:
        (run / "result.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception:
        traceback.print_exc()
        raise SystemExit(1)
