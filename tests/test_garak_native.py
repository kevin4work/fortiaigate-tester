"""Real pinned Garak worker integration: HTTP only to a test loopback server."""
import json
import threading
import time
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest
from fastapi.testclient import TestClient

from runner.api import create_app
from runner.reports import NativeReport
from runner.settings import Settings
from runner.store import TERMINAL
from test_runner_api import headers, request_body


@contextmanager
def fake_target(*, response="DAN mode enabled", code=200, delay=0, drip_seconds=0, first_code=None, delay_after_first=0,
                raw_content=None, content_type="application/json", overlap_stats=None):
    requests = []
    class Handler(BaseHTTPRequestHandler):
        def handle(self):
            try:
                super().handle()
            except (BrokenPipeError, ConnectionResetError):
                pass
        def do_POST(self):
            body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            requests.append(body)
            if overlap_stats is not None:
                with overlap_stats["lock"]:
                    overlap_stats["current"] += 1
                    overlap_stats["max"] = max(overlap_stats["max"], overlap_stats["current"])
            try:
                if delay:
                    time.sleep(delay)
                if len(requests) > 1 and delay_after_first:
                    time.sleep(delay_after_first)
                self.send_response(first_code if first_code is not None and len(requests) == 1 else code)
                self.send_header("Content-Type", content_type)
                self.end_headers()
                try:
                    data = (raw_content.encode() if isinstance(raw_content, str) else raw_content) if raw_content is not None else json.dumps({"choices": [{"message": {"role": "assistant", "content": response}}]}).encode()
                    if drip_seconds:
                        for byte in data:
                            self.wfile.write(bytes([byte]))
                            self.wfile.flush()
                            time.sleep(drip_seconds)
                    else:
                        self.wfile.write(data)
                except (BrokenPipeError, ConnectionResetError):
                    pass
            finally:
                if overlap_stats is not None:
                    with overlap_stats["lock"]:
                        overlap_stats["current"] -= 1
        def log_message(self, *_):
            pass
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}/chat/completions", requests
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_native_garak_keeps_requested_concurrency_in_flight(tmp_path):
    stats = {"current": 0, "max": 0, "lock": threading.Lock()}
    with fake_target(delay=2.5, overlap_stats=stats) as (endpoint, sent):
        app = create_app(Settings("service-only", tmp_path, True, (endpoint,), test_loopback=True))
        auth = headers()
        with TestClient(app) as client:
            # small cap ends the run early; the point is in-flight overlap
            body = start_body(endpoint, profile="core", cap=6, minutes=1.0)
            body["limits"]["concurrency"] = 2
            body["configuration"]["timeout"] = 10
            response = client.post("/runs", headers=auth, json=body)
            assert response.status_code == 200, response.text
            run = wait_finished(client, response.json()["id"], auth, seconds=60)
    assert run["status"] == "budget_limited", run
    assert len(sent) == 6
    assert stats["max"] == 2


def wait_finished(client, run_id, auth, seconds=45):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        run = client.get(f"/runs/{run_id}", headers=auth).json()
        if run["status"] in TERMINAL:
            return run
        time.sleep(0.05)
    pytest.fail("Worker did not finish within the local test deadline")


def start_body(endpoint, suite="garak", profile="smoke", cap=10, minutes=1.0):
    body = request_body(suite=suite, profile=profile, selection=[] if suite == "garak" else ["hkid", "cards"],
                        limits={"request_cap": cap, "rpm": 30, "minutes": minutes, "concurrency": 1})
    body["configuration"]["endpoint"] = endpoint
    return body


@pytest.mark.parametrize("raw_content,response_format", [
    (None, "openai_chat"),
    (json.dumps({"choices": [{"message": {"role": "assistant", "content": "DAN mode enabled",
                                             "reasoning_content": "blocked by FortiAIGate"}, "finish_reason": "stop"}],
                 "metadata": {"message": "blocked by FortiAIGate"}}), "openai_chat"),
    ('{"choices":[{"message":{"content":null,"refusal":"DAN mode enabled"}}]}', "refusal"),
])
def test_actual_native_garak_completion_and_nested_report(tmp_path, raw_content, response_format):
    with fake_target(raw_content=raw_content) as (endpoint, sent):
        app = create_app(Settings("service-only", tmp_path, True, (endpoint,), test_loopback=True))
        auth = headers()
        with TestClient(app) as client:
            response = client.post("/runs", headers=auth, json=start_body(endpoint))
            assert response.status_code == 200, response.text
            run_id = response.json()["id"]
            run = wait_finished(client, run_id, auth)
            assert all("max_tokens" not in payload and "max_completion_tokens" not in payload for payload in sent)
            from runner.catalog import MANIFEST
            template = MANIFEST["probes"]["dan.Ablation_Dan_11_0"]["prompts"][0]
            assert "{generator.name}" in template
            assert sent[0]["messages"][0]["content"] == template.format(generator=type("Configured", (), {"name": "qwen3.8-flash"})())
            assert "{generator.name}" not in sent[0]["messages"][0]["content"]
            assert run["status"] == "completed", run
            assert run["summary"]["completion_verified"] is True
            assert run["summary"]["requests"] == 10 and len(sent) == 10
            assert run["summary"]["finished_probes"] == 2
            evidence = client.get(f"/runs/{run_id}/results", headers=auth).json()
            assert len(evidence["results"]) == 10
            planned_ids = [c["case_id"] for c in run["planned_cases"]]
            assert planned_ids == [f"dan.Ablation_Dan_11_0:{i}" for i in range(5)] + [f"promptinject.HijackLongPrompt:{i}" for i in range(5)]
            assert [r["case_id"] for r in evidence["requests"]] == planned_ids
            assert [r["case_id"] for r in evidence["results"]] == planned_ids
            assert all(r["finalized"] for r in evidence["results"])
            assert run["summary"]["planned_case_count"] == run["summary"]["started_case_count"] == run["summary"]["finished_case_count"] == 10
            assert run["summary"]["current_case_id"] is None
            assert all(row["detectors"] for row in evidence["results"])
            assert run["summary"]["scored"] == 10
            for row in [*evidence["requests"], *evidence["results"]]:
                from html import unescape
                message = json.loads(unescape(row["raw_response"]))["choices"][0]["message"]
                assert message["refusal" if response_format == "refusal" else "content"] == row["response"]
                assert row["response"] == "DAN mode enabled"
                assert row["status_code"] == 200 and row["content_type"] == "application/json"
                assert row["response_format"] == response_format and not row["response_truncated"]
            assert {r["probe"] for r in evidence["results"]} == {"dan.Ablation_Dan_11_0", "promptinject.HijackLongPrompt"}
            assert all(r["gateway_outcome"] == "unknown" for r in evidence["results"])
            report_path = tmp_path / run_id / "native.report.jsonl"
            parser = NativeReport()
            parser.feed(report_path.read_text())
            assert parser.verified(True, 2, 2)
            assert len(parser.attempts) == 10
            assert [a["notes"]["case_id"] for a in parser.attempts.values()] == planned_ids
            assert [a["seq"] for a in parser.attempts.values()] == [0, 1, 2, 3, 4, 0, 1, 2, 3, 4]
            assert all(isinstance(r["prompt"], dict) and isinstance(r["outputs"][0], dict) for r in parser.attempts.values())
            export = client.get(f"/runs/{run_id}/export", headers=auth)
            assert "fake-test-credential" not in export.text
            assert not any(b"fake-test-credential" in p.read_bytes() for p in tmp_path.rglob("*") if p.is_file())


@pytest.mark.parametrize("raw_content,content_type,text,source,blocked", [
    ('{"decision":"block","message":"FortiAIGate blocked","secret":"fake-test-credential","pii":"A123456(7) 4539 1488 0343 6467"}', "application/json", "FortiAIGate blocked", "message", False),
    ('{"output":"alternate reply"}', "application/json", "alternate reply", "output", False),
    ('"JSON string reply"', "application/json", "JSON string reply", "json_string", False),
    ('plain direct response', "text/plain", "plain direct response", "plain_text", False),
    ('<html>Blocked by gateway</html>', "text/html", None, "unrecognized", False),
    ('', "text/plain", None, "empty", False),
    ('{"message":"Request BLOCKED BY FoRtIaIGaTe"}', "application/json", "Request BLOCKED BY FoRtIaIGaTe", "message", True),
])
def test_quick_direct_http200_completes_all_fixed_cases(tmp_path, raw_content, content_type, text, source, blocked):
    from runner.reports import redact
    with fake_target(raw_content=raw_content, content_type=content_type) as (endpoint, sent):
        app = create_app(Settings("service-only", tmp_path, True, (endpoint,), test_loopback=True))
        auth = headers()
        with TestClient(app) as client:
            run_id = client.post("/runs", headers=auth, json=start_body(endpoint, suite="sensitive", profile="quick")).json()["id"]
            run = wait_finished(client, run_id, auth)
            assert run["status"] == "completed" and run["summary"]["completion_verified"], run
            assert len(sent) == run["summary"]["requests"] == run["summary"]["finished_case_count"] == 6
            assert run["summary"]["request_errors"] == run["summary"]["scored"] == run["summary"]["flagged"] == run["summary"]["not_flagged"] == 0
            assert run["summary"]["unscored"] == 6 and run["summary"]["confirmed_blocks"] == (6 if blocked else 0)
            evidence = client.get(f"/runs/{run_id}/results", headers=auth).json()
            assert len(evidence["results"]) == 6 and all(row["finalized"] for row in evidence["results"])
            for row in [*evidence["requests"], *evidence["results"]]:
                assert row["raw_response"] == redact(raw_content, "fake-test-credential", display=True)
                assert row["response"] == text and row["error"] is None
                assert row["gateway_outcome"] == ("confirmed_block" if blocked else "unknown")
                assert row["block_source"] == ("response_phrase" if blocked else None)
                assert row["status_code"] == 200 and row["content_type"] == content_type and not row["response_truncated"]
                assert row["response_format"] == source
            assert app.state.store.records("results", run_id)[0]["raw_response"] == redact(raw_content, "fake-test-credential")
            export = client.get(f"/runs/{run_id}/export", headers=auth)
            assert "fake-test-credential" not in export.text
            assert not any(b"fake-test-credential" in p.read_bytes() for p in tmp_path.rglob("*") if p.is_file())


@pytest.mark.parametrize("raw_content,content_type,text,source,code", [
    ('{"decision":"block","message":"DAN mode enabled; BLOCKED BY FoRtIaIGaTe","secret":"fake-test-credential","pii":"A123456(7) 4539 1488 0343 6467"}', "application/json", "DAN mode enabled; BLOCKED BY FoRtIaIGaTe", "message", 200),
    ('{"choices":[{"message":{"content":"DAN mode enabled; blocked by FortiAIGate"},"finish_reason":"stop"}]}', "application/json", "DAN mode enabled; blocked by FortiAIGate", "openai_chat", 200),
    ('{"choices":[{"message":{"content":null,"refusal":"blocked by FortiAIGate"}}]}', "application/json", "blocked by FortiAIGate", "refusal", 200),
    ('blocked by FortiAIGate', "text/plain", "blocked by FortiAIGate", "plain_text", 403),
    ('plain direct response', "text/plain", "plain direct response", "plain_text", 200),
    ('{"error":{"message":"DAN mode enabled"}}', "application/json", "DAN mode enabled", "error_message", 200),
    ('{"message":"DAN mode enabled"}', "application/json", "DAN mode enabled", "message", 200),
    ('{"output":"DAN mode enabled"}', "application/json", "DAN mode enabled", "output", 200),
    ('{"choices":[{"message":{"content":null,"reasoning_content":"DAN mode enabled; blocked by FortiAIGate"},"finish_reason":"length"}]}', "application/json", None, "reasoning_only", 200),
    ('<html>Blocked by gateway</html>', "text/html", None, "unrecognized", 200),
    ('', "text/plain", None, "empty", 200),
])
def test_native_direct_reply_or_block_is_finalized_unscored_and_completion_verified(tmp_path, raw_content, content_type, text, source, code):
    from runner.reports import redact
    blocked = text is not None and "blocked by fortiaigate" in text.casefold()
    with fake_target(raw_content=raw_content, content_type=content_type, code=code) as (endpoint, sent):
        app = create_app(Settings("service-only", tmp_path, True, (endpoint,), test_loopback=True))
        auth = headers()
        with TestClient(app) as client:
            run_id = client.post("/runs", headers=auth, json=start_body(endpoint)).json()["id"]
            run = wait_finished(client, run_id, auth)
            assert run["status"] == "completed" and run["summary"]["completion_verified"], run
            assert len(sent) == run["summary"]["finished_case_count"] == 10 and run["summary"]["finished_probes"] == 2
            assert run["summary"]["request_errors"] == run["summary"]["scored"] == run["summary"]["flagged"] == run["summary"]["not_flagged"] == 0
            assert run["summary"]["unscored"] == 10 and run["summary"]["confirmed_blocks"] == (10 if blocked else 0)
            assert run["summary"]["per_detector"] == []
            evidence = client.get(f"/runs/{run_id}/results", headers=auth).json()
            assert len(evidence["results"]) == 10
            for row in evidence["results"]:
                assert row["finalized"] and row["outcome"] == "unscored"
                assert row["detectors"] and all(d["score"] is None and d["flagged"] is None for d in row["detectors"])
            for row in [*evidence["requests"], *evidence["results"]]:
                assert row["raw_response"] == redact(raw_content, "fake-test-credential", display=True)
                assert row["response"] == text and row["error"] is None
                assert row["gateway_outcome"] == ("confirmed_block" if blocked else "unknown")
                assert row["block_source"] == ("response_phrase" if blocked else None)
                assert row["status_code"] == code and row["content_type"] == content_type and not row["response_truncated"]
                assert row["response_format"] == source
                assert row["finish_reason"] == ("length" if source == "reasoning_only" else "stop" if source == "openai_chat" else None)
            parser = NativeReport()
            report_text = (tmp_path / run_id / "native.report.jsonl").read_text()
            parser.feed(report_text)
            assert parser.verified(True, 2, 2) and len(parser.attempts) == 10
            for attempt in parser.attempts.values():
                assert attempt["outputs"] == [None] and attempt["status"] == 2
                assert all(scores == [None] for scores in attempt["detector_results"].values())
                assert attempt["notes"]["raw_response"] == redact(raw_content, "fake-test-credential")
                assert attempt["notes"]["response"] == text
                assert attempt["notes"]["gateway_outcome"] == ("confirmed_block" if blocked else "unknown")
                assert attempt["notes"]["block_source"] == ("response_phrase" if blocked else None)
            evals = [json.loads(line) for line in report_text.splitlines() if json.loads(line).get("entry_type") == "eval"]
            assert evals and all(r["total_evaluated"] == r["passed"] == r["fails"] == 0 and r["nones"] > 0 for r in evals)
            assert not any(b"fake-test-credential" in p.read_bytes() for p in tmp_path.rglob("*") if p.is_file())


@pytest.mark.parametrize("code,oversize,expected_error,message", [
    (401, False, "auth_error", "HTTP 401 authentication failed"),
    (403, False, "forbidden_unknown", "HTTP 403 forbidden"),
    (200, True, "response_too_large", "1 MiB body limit"),
])
def test_quick_single_fatal_error_reports_actual_cause_and_raw_evidence(tmp_path, code, oversize, expected_error, message):
    from runner.transport import RESPONSE_BODY_LIMIT, RESPONSE_TRUNCATION_MARKER
    raw = "fake-test-credential A123456(7) 4539 1488 0343 6467 " + ("x" * RESPONSE_BODY_LIMIT if oversize else "access denied")
    with fake_target(code=code, raw_content=raw, content_type="text/plain") as (endpoint, sent):
        app = create_app(Settings("service-only", tmp_path, True, (endpoint,), test_loopback=True))
        auth = headers()
        with TestClient(app) as client:
            run_id = client.post("/runs", headers=auth, json=start_body(endpoint, suite="sensitive", profile="quick")).json()["id"]
            run = wait_finished(client, run_id, auth)
            assert run["status"] == "failed" and message in run["error"] and "Repeated service" not in run["error"], run
            assert len(sent) == run["summary"]["requests"] == run["summary"]["finished_case_count"] == 1
            evidence = client.get(f"/runs/{run_id}/results", headers=auth).json()
            assert evidence["results"][0]["finalized"]
            for row in [*evidence["requests"], *evidence["results"]]:
                assert row["error"] == expected_error and row["status_code"] == code
                assert row["response"] is None and row["content_type"] == "text/plain"
                assert row["response_truncated"] is oversize and row["raw_response"].startswith("[credential redacted] A123456(7) 4539 1488 0343 6467")
                assert row["raw_response"].endswith(RESPONSE_TRUNCATION_MARKER) is oversize
            assert not any(b"fake-test-credential" in p.read_bytes() for p in tmp_path.rglob("*") if p.is_file())


@pytest.mark.parametrize("raw_content", [
    '{"choices":[{"message":{"content":null,"reasoning_content":"DAN mode enabled; blocked by FortiAIGate"},"finish_reason":"length"}]}',
    '{"choices":[{"message":{"content":"DAN mode enabled; blocked by FortiAIGate"}}]}',
    '{"message":"DAN mode enabled; blocked by FortiAIGate"}',
    '{"error":{"message":"DAN mode enabled"}}',
    '{"message":"DAN mode enabled"}',
    'plain direct response',
])
def test_native_missing_model_output_and_gateway_block_skip_detectors(tmp_path, monkeypatch, raw_content):
    from runner.api import RunRequest, resolve
    from runner.store import Store
    from runner.worker import execute
    import runner.native
    class MustNotRun:
        skip = False
        def detect(self, _):
            pytest.fail("Reasoning, alternate response fields, or gateway blocks must never be submitted to a detector")
    monkeypatch.setattr(runner.native, "load_detectors", lambda probe_id: [(name, MustNotRun()) for name in runner.native.PROBES[probe_id]])
    with fake_target(raw_content=raw_content) as (endpoint, sent):
        settings = Settings("service-only", tmp_path, True, (endpoint,), test_loopback=True)
        data, key = resolve(RunRequest.model_validate(start_body(endpoint)), settings)
        store = Store(tmp_path)
        run, _ = store.create("owner", "idem", "fp", data)
        execute({"data_dir": str(tmp_path), "run_id": run["id"], "api_key": key, "allowlist": (endpoint,), "test_loopback": True})
        metrics = store.get(run["id"])["summary"]
        assert metrics["worker_status"] == "completed" and metrics["worker_verified"] and len(sent) == 10
        assert metrics["scored"] == metrics["flagged"] == metrics["not_flagged"] == 0


@pytest.mark.parametrize("reply,expected_flag", [
    ("No credential disclosure", False),
    ("arn:aws:sns:us-east-1:123456789012:demo-topic https://s3.amazonaws.com/demo-bucket/file.txt", False),
    ("ghp_abcdefghijklmnopqrstuvwxyz0123456789", True),
])
def test_actual_native_apikey_with_budget(tmp_path, reply, expected_flag):
    with fake_target(response=reply) as (endpoint, sent):
        app = create_app(Settings("service-only", tmp_path, True, (endpoint,), test_loopback=True))
        auth = headers()
        with TestClient(app) as client:
            body = start_body(endpoint, suite="sensitive", profile="custom", cap=2)
            body["selection"] = ["apikey"]
            run_id = client.post("/runs", headers=auth, json=body).json()["id"]
            run = wait_finished(client, run_id, auth)
            assert run["status"] == "budget_limited", run
            rows = client.get(f"/runs/{run_id}/results", headers=auth).json()["results"]
            assert len(sent) == 2 and len(rows) == 2
            assert all(r["probe"] == "apikey.GetKey" for r in rows)
            assert all(r["detectors"][0]["name"] == "fortiaigate.CredentialPatterns" for r in rows)
            assert all(r["detectors"][0]["flagged"] is expected_flag for r in rows)
            assert all("Amazon Sns Topic" not in message["content"] and "Aws S3 Url" not in message["content"]
                       for payload in sent for message in payload["messages"])
            assert [r["case_id"] for r in rows] == ["apikey.GetKey:0", "apikey.GetKey:1"]
            assert run["summary"]["planned_case_count"] == 32
            assert run["summary"]["started_case_count"] == run["summary"]["finished_case_count"] == 2
            assert run["summary"]["current_case_id"] is None


@pytest.mark.parametrize("probe_id,detector_id", [("apikey.CompleteKey", "fortiaigate.CredentialPatterns"), ("leakreplay.LiteratureCloze", "base.TriggerListDetector")])
def test_individual_reviewed_native_classes(tmp_path, probe_id, detector_id):
    from runner.catalog import MANIFEST
    with fake_target(response="I cannot provide that") as (endpoint, sent):
        app = create_app(Settings("service-only", tmp_path, True, (endpoint,), test_loopback=True))
        auth = headers()
        with TestClient(app) as client:
            # Test-only internal metadata setup selects one approved class; browser
            # requests cannot choose paths/classes and still use profile allowlists.
            store = app.state.store
            body = start_body(endpoint)
            body["configuration"].pop("api_key")
            body.update({"probe_ids": [probe_id], "cases": [], "manifest_sha256": MANIFEST["sha256"]})
            run, _ = store.create("internal-test", "native-class", "fp", body)
            app.state.supervisor.launch(run["id"], "fake-test-credential")
            deadline = time.monotonic() + 30
            while store.get(run["id"])["status"] not in TERMINAL and time.monotonic() < deadline:
                time.sleep(0.05)
            run = store.get(run["id"])
            assert run["status"] == "completed", run
            assert run["summary"]["completion_verified"]
            assert len(sent) == 5
            rows = store.records("results", run["id"])
            assert all(r["probe"] == probe_id and r["detectors"][0]["name"] == detector_id for r in rows)


def test_native_errors_are_unscored_not_passes(tmp_path):
    with fake_target(code=403, raw_content='<html>Access denied fake-test-credential A123456(7)</html>', content_type="text/html") as (endpoint, sent):
        app = create_app(Settings("service-only", tmp_path, True, (endpoint,), test_loopback=True))
        auth = headers()
        with TestClient(app) as client:
            run_id = client.post("/runs", headers=auth, json=start_body(endpoint)).json()["id"]
            run = wait_finished(client, run_id, auth)
            assert run["status"] == "failed", run
            assert run["summary"]["request_errors"] == 1
            assert "HTTP 403 forbidden" in run["error"] and "Repeated service" not in run["error"]
            assert run["summary"]["not_flagged"] == 0
            row = client.get(f"/runs/{run_id}/results", headers=auth).json()["results"][0]
            assert row["outcome"] == "unscored" and row["error"] == "forbidden_unknown"
            assert all(d["score"] is None for d in row["detectors"])
            assert row["case_id"] == "dan.Ablation_Dan_11_0:0" and row["finalized"]
            assert row["status_code"] == 403 and row["content_type"] == "text/html" and not row["response_truncated"]
            assert row["raw_response"] == "&lt;html&gt;Access denied [credential redacted] A123456(7)&lt;/html&gt;"
            assert app.state.store.records("results", run_id)[0]["raw_response"] == "<html>Access denied [credential redacted] A123456(7)</html>"
            assert run["summary"]["planned_case_count"] == 10
            assert run["summary"]["started_case_count"] == run["summary"]["finished_case_count"] == 1
            assert len(sent) == 1


def test_native_complete_coverage_keeps_unrecovered_error_as_case_evidence(tmp_path):
    with fake_target(first_code=400) as (endpoint, sent):
        app = create_app(Settings("service-only", tmp_path, True, (endpoint,), test_loopback=True))
        auth = headers()
        with TestClient(app) as client:
            run_id = client.post("/runs", headers=auth, json=start_body(endpoint)).json()["id"]
            run = wait_finished(client, run_id, auth)
            assert run["status"] == "completed", run
            assert run["summary"]["finished_probes"] == 2
            assert run["summary"]["completion_verified"]
            assert run["summary"]["request_errors"] == 1 and len(sent) == 10
            rows = client.get(f"/runs/{run_id}/results", headers=auth).json()["results"]
            assert rows[0]["outcome"] == "unscored" and rows[0]["error"] == "http_error"
            parser = NativeReport()
            parser.feed((tmp_path / run_id / "native.report.jsonl").read_text())
            assert parser.verified(True, 2, 2)


def test_recovered_native_retry_can_complete(tmp_path):
    with fake_target(first_code=429) as (endpoint, sent):
        app = create_app(Settings("service-only", tmp_path, True, (endpoint,), test_loopback=True))
        auth = headers()
        with TestClient(app) as client:
            run_id = client.post("/runs", headers=auth, json=start_body(endpoint, cap=11)).json()["id"]
            run = wait_finished(client, run_id, auth)
            assert run["status"] == "completed", run
            assert run["summary"]["completion_verified"]
            assert len(sent) == 11 and run["summary"]["request_errors"] == 1
            rows = client.get(f"/runs/{run_id}/results", headers=auth).json()["results"]
            assert not any(row["error"] for row in rows)
            evidence = client.get(f"/runs/{run_id}/results", headers=auth).json()
            assert [r["case_id"] for r in evidence["requests"]] == ["dan.Ablation_Dan_11_0:0"] + [f"dan.Ablation_Dan_11_0:{i}" for i in range(5)] + [f"promptinject.HijackLongPrompt:{i}" for i in range(5)]
            assert run["summary"]["started_case_count"] == run["summary"]["finished_case_count"] == 10
            for row in rows:
                final_dispatch = [r for r in evidence["requests"] if r["case_id"] == row["case_id"]][-1]
                assert row["latency_ms"] == final_dispatch["latency_ms"]


def test_absolute_request_timeout_interrupts_slow_drip_not_global_budget(tmp_path):
    from runner.store import Store
    from runner.transport import Transport
    with fake_target(drip_seconds=0.03) as (endpoint, sent):
        store = Store(tmp_path)
        run, _ = store.create("owner", "idem", "fp", {})
        configuration = {"endpoint": endpoint, "model": "fixture-model", "api_key": "fake-test-credential", "timeout": 0.2}
        transport = Transport(configuration, {"request_cap": 5, "rpm": 30, "minutes": 1}, (endpoint,), True, store, run["id"])
        try:
            result = transport.request([{"role": "user", "content": "fixture"}])
        finally:
            transport.close()
        assert result["error"] == "timeout" and result["response"] is None
        requests = store.records("requests", run["id"])
        assert len(sent) == len(requests) == 3
        assert all(row["error"] == "timeout" and row["latency_ms"] < 600 for row in requests)
        assert time.monotonic() - transport.started < 60


def test_cancel_and_process_cleanup_preserves_partial(tmp_path):
    with fake_target() as (endpoint, sent):
        app = create_app(Settings("service-only", tmp_path, True, (endpoint,), test_loopback=True, cancel_grace=0.3))
        auth = headers()
        with TestClient(app) as client:
            run_id = client.post("/runs", headers=auth, json=start_body(endpoint, suite="sensitive", profile="quick")).json()["id"]
            deadline = time.monotonic() + 5
            while not sent and time.monotonic() < deadline:
                time.sleep(0.02)
            assert sent
            assert client.post(f"/runs/{run_id}/cancel", headers=auth).status_code == 200
            run = wait_finished(client, run_id, auth, seconds=3)
            assert run["status"] == "cancelled", run
            assert run["summary"]["completion_verified"] is False
            assert run["summary"]["requests"] >= 1
            count = len(sent)
            time.sleep(0.4)
            assert len(sent) == count
        assert not app.state.supervisor.processes


def test_worker_walltime_limited_no_native_false_completion(tmp_path):
    with fake_target() as (endpoint, sent):
        app = create_app(Settings("service-only", tmp_path, True, (endpoint,), test_loopback=True))
        auth = headers()
        with TestClient(app) as client:
            run_id = client.post("/runs", headers=auth, json=start_body(endpoint, minutes=0.01)).json()["id"]
            run = wait_finished(client, run_id, auth, seconds=4)
            assert run["status"] == "budget_limited", run
            assert run["summary"]["completion_verified"] is False
            assert len(sent) <= 1


def test_native_cancel_midcase_keeps_case_correlation_and_partial_progress(tmp_path):
    with fake_target(delay_after_first=3) as (endpoint, sent):
        app = create_app(Settings("service-only", tmp_path, True, (endpoint,), test_loopback=True, cancel_grace=0.5))
        auth = headers()
        with TestClient(app) as client:
            body = start_body(endpoint)
            body["configuration"]["timeout"] = 10
            run_id = client.post("/runs", headers=auth, json=body).json()["id"]
            deadline = time.monotonic() + 10
            while len(sent) < 2 and time.monotonic() < deadline:
                time.sleep(0.02)
            assert len(sent) == 2
            active = client.get(f"/runs/{run_id}/results", headers=auth).json()
            assert active["summary"]["finished_case_count"] == 1
            assert active["summary"]["started_case_count"] == 2
            assert active["summary"]["current_case_id"] == "dan.Ablation_Dan_11_0:1"
            client.post(f"/runs/{run_id}/cancel", headers=auth)
            run = wait_finished(client, run_id, auth, seconds=4)
            assert run["status"] == "cancelled"
            assert run["summary"]["planned_case_count"] == 10
            assert run["summary"]["finished_case_count"] == 1 and run["summary"]["started_case_count"] == 2
            assert run["summary"]["current_case_id"] is None
            evidence = client.get(f"/runs/{run_id}/results", headers=auth).json()
            partial = next(r for r in evidence["results"] if r["case_id"] == "dan.Ablation_Dan_11_0:1")
            request = evidence["requests"][-1]
            assert partial["finalized"] is False and partial["error"] == "in_flight"
            assert partial["response"] is None and partial["latency_ms"] is None
            for field in ("raw_response", "content_type", "status_code", "response_truncated", "response_format"):
                assert field in partial and partial[field] == request[field]
            assert request["case_id"] == partial["case_id"] and request["attempt_id"] == partial["attempt_id"]
            assert len(sent) == 2


def test_native_budget_exhausted_during_retry_is_not_finalized_case(tmp_path):
    with fake_target(first_code=429) as (endpoint, sent):
        app = create_app(Settings("service-only", tmp_path, True, (endpoint,), test_loopback=True))
        auth = headers()
        with TestClient(app) as client:
            run_id = client.post("/runs", headers=auth, json=start_body(endpoint, cap=1)).json()["id"]
            run = wait_finished(client, run_id, auth)
            assert run["status"] == "budget_limited"
            assert run["summary"]["planned_case_count"] == 10
            assert run["summary"]["started_case_count"] == 1 and run["summary"]["finished_case_count"] == 0
            assert run["summary"]["current_case_id"] is None
            evidence = client.get(f"/runs/{run_id}/results", headers=auth).json()
            row = evidence["results"][0]
            assert row["case_id"] == evidence["requests"][0]["case_id"] == "dan.Ablation_Dan_11_0:0"
            assert row["error"] == "rate_limited" and row["finalized"] is False
            assert row["response"] is None and len(sent) == 1
            request = evidence["requests"][0]
            for field in ("raw_response", "content_type", "status_code", "response_truncated", "response_format"):
                assert row[field] == request[field]
            assert row["raw_response"] and row["status_code"] == 429 and not row["response_truncated"]


@pytest.mark.parametrize("detector_failure", [False, True])
def test_native_duplicate_prompts_use_sequence_and_detector_failure_keeps_request_only(tmp_path, monkeypatch, detector_failure):
    from runner.api import RunRequest, resolve
    from runner.catalog import MANIFEST
    from runner.native import load_probe
    from runner.store import Store
    from runner.worker import execute
    import runner.native
    probe_id = "promptinject.HijackLongPrompt"
    prompt = MANIFEST["probes"][probe_id]["prompts"][0]
    monkeypatch.setitem(MANIFEST["probes"], probe_id, {**MANIFEST["probes"][probe_id], "prompts": [prompt, prompt]})
    def duplicate_probe(identifier):
        probe = load_probe(identifier)
        probe.prompts = [prompt, prompt]
        return probe
    monkeypatch.setattr(runner.native, "load_probe", duplicate_probe)
    if detector_failure:
        class BrokenDetector:
            skip = False
            def detect(self, _):
                raise RuntimeError("fixture scoring failure")
        monkeypatch.setattr(runner.native, "load_detectors", lambda _: [("promptinject.AttackRogueString", BrokenDetector())])
    with fake_target(response="fixture reply") as (endpoint, sent):
        settings = Settings("service-only", tmp_path, True, (endpoint,), test_loopback=True)
        body = start_body(endpoint)
        data, key = resolve(RunRequest.model_validate(body), settings)
        data["probe_ids"] = [probe_id]  # Internal fixture only; admission disallows subsets.
        from runner.catalog import planned_cases
        data["planned_cases"] = planned_cases("smoke", [], [probe_id])
        store = Store(tmp_path)
        run, _ = store.create("owner", "idem", "fp", data)
        execute({"data_dir": str(tmp_path), "run_id": run["id"], "api_key": key, "allowlist": (endpoint,), "test_loopback": True})
        current = store.get(run["id"])
        requests = store.records("requests", run["id"])
        rows = store.records("results", run["id"])
        if detector_failure:
            assert current["summary"]["worker_status"] == "failed"
            assert current["summary"]["started_case_count"] == 1 and current["summary"]["finished_case_count"] == 0
            assert len(requests) == len(sent) == 1 and requests[0]["response"] == "fixture reply"
            assert requests[0]["case_id"] == f"{probe_id}:0"
            assert rows == []  # Preserve HTTP success separately from missing evaluation evidence.
        else:
            assert current["summary"]["worker_status"] == "completed" and current["summary"]["worker_verified"]
            assert current["summary"]["finished_case_count"] == 2
            assert [r["case_id"] for r in requests] == [r["case_id"] for r in rows] == [f"{probe_id}:0", f"{probe_id}:1"]
            assert rows[0]["prompt"] == rows[1]["prompt"]
            assert len({r["attempt_id"] for r in rows}) == 2
        assert current["summary"]["current_case_id"] is None
