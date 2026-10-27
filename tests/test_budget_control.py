"""Budget Control page and run-engine regression tests."""

import json
import threading
import time
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest
from streamlit.testing.v1 import AppTest

from attack_tester.budget_control import BudgetRun, mask_key, _log_html
from attack_tester.ui import NAVIGATION
from common.fortiaigate_test import send_prompt

BUDGET_BODY = json.dumps({
    "error": {
        "message": "budget exhausted for this API key",
        "type": "payment_required_error",
        "param": None,
        "code": "budget_exceeded",
    }
})
OK_BODY = json.dumps({
    "choices": [{"message": {"content": "ok"}}],
    "usage": {"prompt_tokens": 1750, "completion_tokens": 1024, "total_tokens": 2774},
})
# 1750/1M * $5 + 1024/1M * $50
REQUEST_COST = 1750 / 1e6 * 5.0 + 1024 / 1e6 * 50.0


@contextmanager
def fake_gateway(ok_count, code=402, body=BUDGET_BODY, delay=0.0, echo_key=None, delay_map=None,
                 ok_body=None, status_map=None):
    """Loopback chat endpoint: first ok_count requests succeed, the rest refuse.

    ok_body overrides the 200 payload; status_map overrides the status for
    specific request counts (1-based).
    """
    state = {"count": 0, "lock": threading.Lock()}

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            self.rfile.read(int(self.headers.get("content-length", 0)))
            with state["lock"]:
                state["count"] += 1
                count = state["count"]
            wait = delay_map.get(count, delay) if delay_map else delay
            if wait:
                time.sleep(wait)
            if status_map and count in status_map:
                status = status_map[count]
            else:
                status = 200 if count <= ok_count else code
            if status == 200:
                if ok_body is not None:
                    payload = ok_body.encode()
                else:
                    payload = (OK_BODY.replace("ok", f"echo {echo_key}") if echo_key else OK_BODY).encode()
            else:
                payload = body.encode()
            self.send_response(status)
            self.send_header("content-type", "application/json")
            self.send_header("content-length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def log_message(self, *args):
            pass

    class Server(ThreadingHTTPServer):
        # large listen backlog keeps macOS from dropping connections under the
        # threaded test server (budget control still waves 2 parallel requests;
        # rate limit dispatches sequentially)
        request_queue_size = 128

    server = Server(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}/chat/completions", state
    finally:
        server.shutdown()
        server.server_close()
        thread.join()


def settings(endpoint):
    return {
        "endpoint": endpoint,
        "model": "qwen3.8-flash",
        "api_key": "budget-fixture-key",
        "key_mask": mask_key("budget-fixture-key"),
        "rates": (5.0, 50.0),
        "timeout": 5,
    }


def wait_terminal(run, timeout=20):
    deadline = time.time() + timeout
    while time.time() < deadline:
        snap = run.snapshot()
        if snap["status"] != "running":
            return snap
        time.sleep(0.05)
    raise AssertionError("budget run did not reach a terminal status")


PAGE = (
    "from attack_tester.configuration import initialize_state\n"
    "from attack_tester.budget_control import render_budget_control\n"
    "initialize_state()\n"
    "render_budget_control()\n"
)


def page(**saved):
    test = AppTest.from_string(PAGE, default_timeout=15)
    for key, value in saved.items():
        test.session_state["saved_" + key] = value
    return test


CONFIGURED = {
    "endpoint": "https://test.invalid/v1/chat/completions",
    "model": "qwen3.8-flash",
    "budget_api_key": "faig_8042secret-value",
}


def test_navigation_replaces_model_pricing():
    pages = [name for _, group in NAVIGATION for name, _ in group]
    assert "Budget Control" in pages
    assert "Model Pricing" not in pages


def test_page_gates_on_missing_budget_key():
    test = page(endpoint=CONFIGURED["endpoint"], model=CONFIGURED["model"])
    test.run()
    assert not test.exception
    assert test.warning
    assert not [b for b in test.button if b.label == "Run budget test"]


@pytest.mark.parametrize("model", ["qwen3.8-flash", "faig-deepseek-flash"])
def test_page_uses_shared_budget_and_rates(model):
    test = page(**{**CONFIGURED, "model": model})
    test.run()
    assert not test.exception
    values = {widget.label: widget.value for widget in test.text_input}
    assert values["Model"] == model
    assert values["Rate $/1M in"] == "5"
    assert values["Rate $/1M out"] == "50"
    assert values["Hourly budget"] == "$1.00 / hour"
    assert [b for b in test.button if b.label == "Run budget test"]


def test_page_gates_on_unrated_model():
    test = page(**{**CONFIGURED, "model": "model-without-rate"})
    test.run()
    assert not test.exception
    assert any("No rate configured" in w.value for w in test.warning)
    assert not [b for b in test.button if b.label == "Run budget test"]


def test_settings_are_read_only_and_masked():
    test = page(**CONFIGURED)
    test.run()
    assert not test.exception
    assert test.text_input
    assert all(widget.disabled for widget in test.text_input)
    values = [widget.value for widget in test.text_input]
    assert "faig_804…••••" in values
    assert CONFIGURED["budget_api_key"] not in values
    assert [b for b in test.button if b.label == "Run budget test"]


def test_mask_key_never_shows_short_keys():
    assert mask_key("faig_8042secret") == "faig_804…••••"
    assert mask_key("short") == "••••"
    assert mask_key("") == ""


def test_run_enforces_budget_and_keeps_evidence():
    with fake_gateway(ok_count=3, delay=0.3) as (endpoint, state):
        run = BudgetRun(settings(endpoint))
        started = time.time()
        assert run.start()
        assert not run.start()  # idempotent
        snap = wait_terminal(run)
        elapsed = time.time() - started
    assert snap["status"] == "done"
    assert snap["verdict"][0] == "ok"
    # batches of 2: batch 2 crosses the budget, batches 3-5 are refused at admission and still run
    assert snap["refusals"] == 7
    assert snap["completed"] == 10
    assert state["count"] == 10
    # five parallel batches of 0.3 s: serial would need >= 10 * 0.3 s
    assert elapsed < 2.5
    ok = [r for r in snap["records"] if r["status_code"] == 200]
    hit = [r for r in snap["records"] if r["status_code"] == 402]
    assert len(ok) == 3 and len(hit) == 7
    assert all(r["tokens_in"] == 0 and r["tokens_out"] == 0 for r in hit)
    assert all(r["result"] == "402 Budget Exceeded" for r in hit)
    assert all(r["note"].startswith("Hourly budget reached") for r in hit)
    assert all(r["cost"] == pytest.approx(REQUEST_COST) for r in ok)
    assert snap["added"] == pytest.approx(3 * REQUEST_COST)
    assert snap["tokens_in"] == 3 * 1750
    assert hit[0]["result"] == "402 Budget Exceeded"
    assert "budget_exceeded" in hit[0]["evidence"]
    # each OK record stamps the cumulative total at its completion
    assert sorted(r["running_total"] for r in ok) == pytest.approx([REQUEST_COST, 2 * REQUEST_COST, 3 * REQUEST_COST])


def test_stop_ends_the_run_without_conclusion():
    with fake_gateway(ok_count=1000, delay=0.5) as (endpoint, state):
        run = BudgetRun(settings(endpoint))
        run.start()
        time.sleep(0.2)
        run.stop()
        snap = wait_terminal(run)
    assert snap["status"] == "stopped"
    assert snap["verdict"][0] == "warn"
    # stop lands during batch 1: that batch drains, no further batch starts
    assert snap["completed"] == 2
    assert state["count"] == snap["sent"] == 2


def test_any_402_is_presented_as_budget_exceeded():
    other = json.dumps({"error": {"message": "no credit", "type": "payment_required_error", "code": "insufficient_funds"}})
    with fake_gateway(ok_count=0, body=other) as (endpoint, _):
        run = BudgetRun(settings(endpoint))
        run.start()
        snap = wait_terminal(run)
    assert snap["verdict"][0] == "ok"
    assert snap["completed"] == 10  # refusals bill nothing, so all batches run
    hit = snap["records"][0]
    assert hit["status_code"] == 402
    assert hit["result"] == "402 Budget Exceeded"
    assert hit["note"].startswith("Hourly budget reached")
    assert "insufficient_funds" in hit["evidence"]


def test_log_follows_completion_order_when_responses_race():
    # records arrive in completion order (2 before 1, 4 before 3); the table
    # must keep that order so the running total reads monotonically
    records = []
    total = 0.0
    for idx, cost in ((2, 0.16), (1, 0.16), (4, 0.0), (3, 0.27)):
        total += cost
        records.append({
            "index": idx, "wave": 1, "status_code": 200 if cost else 402,
            "latency_ms": 15000, "tokens_in": 19588, "tokens_out": 1200,
            "cost": cost, "running_total": total, "evidence": None,
            "result": "200 OK" if cost else "402 Budget Exceeded",
            "note": "note",
        })
    table = _log_html(records)
    positions = [table.index(f"<td>{i}</td>") for i in (2, 1, 4, 3)]
    assert positions == sorted(positions)
    totals = [f"${v:.2f}" for v in (0.16, 0.32, 0.32, 0.59)]
    cells = [table.index(t) for t in totals]
    assert cells == sorted(cells)


def test_send_prompt_carries_status_body_and_usage():
    with fake_gateway(ok_count=1) as (endpoint, _):
        sent = send_prompt(endpoint, "fixture-key", "hi", model="qwen3.8-flash", timeout=5)
    assert sent["status"] == "OK"
    assert sent["status_code"] == 200
    assert sent["usage"] == {"prompt_tokens": 1750, "completion_tokens": 1024, "total_tokens": 2774}
    assert "prompt_tokens" in sent["raw_body"]


def test_send_prompt_keeps_402_evidence_and_redacts_key():
    with fake_gateway(ok_count=0, echo_key=None) as (endpoint, _):
        sent = send_prompt(endpoint, "super-secret-fixture-key", "hi", model="qwen3.8-flash", timeout=5)
    assert sent["status"] == "Error"
    assert sent["error"] == "HTTP 402"
    assert sent["status_code"] == 402
    assert "budget_exceeded" in sent["raw_body"]
    assert sent["usage"] is None
    with fake_gateway(ok_count=1, echo_key="super-secret-fixture-key") as (endpoint, _):
        sent = send_prompt(endpoint, "super-secret-fixture-key", "hi", model="qwen3.8-flash", timeout=5)
    assert "super-secret-fixture-key" not in sent["raw_body"]
    assert "[REDACTED]" in sent["raw_body"]


def test_terminal_run_renders_evidence_statically():
    with fake_gateway(ok_count=3) as (endpoint, _):
        run = BudgetRun(settings(endpoint))
        run.start()
        snap = wait_terminal(run)
    test = page(**CONFIGURED)
    test.session_state["_budget_run"] = run
    test.run()
    assert not test.exception
    assert any("Budget-hit response" in s.value for s in test.subheader)
    assert test.success
    log = next(m.value for m in test.markdown if "bc-log" in m.value)
    assert log.count('class="bc-pill') == 10
    assert log.count('bc-pill ok') == 3 and log.count('bc-pill stop') == 7
    assert snap["refusals"] == 7
