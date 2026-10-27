"""Rate Limit page and run-engine regression tests."""

import json
import time

import pytest
from streamlit.testing.v1 import AppTest

from attack_tester.rate_limit import (COOLDOWN_SECONDS, REQUEST_INTERVAL,
                                      RateLimitRun, cooldown_remaining, mask_key, _log_html)
from attack_tester.ui import NAVIGATION
from test_budget_control import fake_gateway

RATE_BODY = json.dumps({
    "error": {
        "message": "rate limit exceeded for this API key",
        "type": "rate_limit_exceeded",
        "param": None,
        "code": "rate_limit_exceeded",
    }
})
FIXTURE_KEY = "faig_rate_fixture_key_value"
# realistic large-request usage: 3 * 39,458 = 118,374 counted tokens > 100,000 TPM
XL_OK_BODY = json.dumps({
    "choices": [{"message": {"content": "ok"}}],
    "usage": {"prompt_tokens": 39088, "completion_tokens": 370, "total_tokens": 39458},
})


def settings(endpoint):
    return {
        "endpoint": endpoint,
        "model": "qwen3.8-flash",
        "api_key": FIXTURE_KEY,
        "key_mask": mask_key(FIXTURE_KEY),
        "timeout": 5,
    }


def wait_terminal(run, timeout=20):
    deadline = time.time() + timeout
    while time.time() < deadline:
        snap = run.snapshot()
        if snap["status"] != "running":
            return snap
        time.sleep(0.05)
    raise AssertionError("rate-limit run did not reach a terminal status")


@pytest.fixture
def fast_engine(monkeypatch):
    """Engine timing for tests: near-zero interval between sequential requests.

    _coordinate reads it from the module at call time, so patching the module
    attribute is enough.
    """
    monkeypatch.setattr("attack_tester.rate_limit.REQUEST_INTERVAL", 0.05)


PAGE = (
    "from attack_tester.configuration import initialize_state\n"
    "from attack_tester.rate_limit import render_rate_limit\n"
    "initialize_state()\n"
    "render_rate_limit()\n"
)


def page(**saved):
    test = AppTest.from_string(PAGE, default_timeout=15)
    for key, value in saved.items():
        test.session_state["saved_" + key] = value
    return test


CONFIGURED = {
    "endpoint": "https://test.invalid/v1/chat/completions",
    "model": "qwen3.8-flash",
    "rate_limit_api_key": FIXTURE_KEY,
}


def test_navigation_moves_rate_limit_into_workspace():
    groups = dict(NAVIGATION)
    workspace = [name for name, _ in groups["WORKSPACE"]]
    planned = [name for name, _ in groups["PLANNED"]]
    assert "Rate Limit" in workspace
    assert "Rate Limit" not in planned
    assert workspace.index("Rate Limit") == workspace.index("Budget Control") + 1
    assert planned == ["Shadow AI"]


def test_page_gates_on_missing_rate_limit_key():
    test = page(endpoint=CONFIGURED["endpoint"], model=CONFIGURED["model"])
    test.run()
    assert not test.exception
    assert test.warning
    assert "API key (Rate Limit)" in test.warning[0].value
    assert not [b for b in test.button if b.label in ("Run RPM test", "Run TPM test")]


def test_settings_are_read_only_and_masked():
    test = page(**CONFIGURED)
    test.run()
    assert not test.exception
    assert test.text_input
    assert all(widget.disabled for widget in test.text_input)
    values = [widget.value for widget in test.text_input]
    assert mask_key(FIXTURE_KEY) in values
    assert FIXTURE_KEY not in values
    assert "5 / minute" in values
    assert "100,000 / minute" in values
    assert "clock-minute bucket" in values
    heads = [s.value for s in test.subheader]
    assert any("Test 1 · Requests per minute (5 RPM)" in h for h in heads)
    assert any("Test 2 · Tokens per minute (100,000 TPM)" in h for h in heads)


def test_both_run_buttons_exist_when_configured():
    test = page(**CONFIGURED)
    test.run()
    assert not test.exception
    rpm = next(b for b in test.button if b.label == "Run RPM test")
    tpm = next(b for b in test.button if b.label == "Run TPM test")
    assert not rpm.disabled
    assert not tpm.disabled


def test_rpm_run_enforces_request_limit(fast_engine):
    with fake_gateway(ok_count=5, code=429, body=RATE_BODY, delay=0.3) as (endpoint, state):
        run = RateLimitRun(settings(endpoint), "rpm")
        started = time.time()
        assert run.start()
        snap = wait_terminal(run)
        elapsed = time.time() - started
    assert snap["status"] == "done"
    assert snap["kind"] == "rpm"
    assert snap["planned"] == 8
    # sequential dispatch: records arrive in send order, one at a time
    assert [r["index"] for r in snap["records"]] == list(range(1, 9))
    assert snap["verdict"][0] == "ok"
    assert "admitted the first 5 of 8 requests sent one at a time" in snap["verdict"][1]
    assert snap["completed"] == 8 == state["count"]
    assert snap["refusals"] == 3
    ok = [r for r in snap["records"] if r["status_code"] == 200]
    hit = [r for r in snap["records"] if r["status_code"] == 429]
    assert len(ok) == 5 and len(hit) == 3
    assert [r["index"] for r in ok] == [1, 2, 3, 4, 5]
    assert [r["index"] for r in hit] == [6, 7, 8]
    assert all(r["result"] == "200 OK" for r in ok)
    assert all(r["tokens_in"] == 1750 and r["tokens_out"] == 1024 for r in ok)
    assert all(r["result"] == "429 Rate Limited" for r in hit)
    assert all(r["tokens_in"] == 0 and r["tokens_out"] == 0 for r in hit)
    assert all("rate_limit_exceeded" in r["evidence"] for r in hit)
    assert all("admission" in r["note"] and "zero tokens" in r["note"] for r in hit)
    # one at a time with a 0.3 s fake delay: parallel would finish in < 8 * 0.3 s
    assert elapsed >= 8 * 0.3
    # running tokens are stamped at completion, so they read monotonically
    running = [r["running_tokens"] for r in snap["records"]]
    assert running == sorted(running)
    assert running[-1] == 5 * 2774
    assert snap["tokens_in"] == 5 * 1750


def test_rpm_boundary_crossing_before_first_refusal_is_explained(fast_engine):
    # crossing shape: 7 admissions can only span two clock-minute buckets, and
    # the refusal lands last, so the "resumed" tail cannot fire
    with fake_gateway(ok_count=7, code=429, body=RATE_BODY) as (endpoint, _):
        run = RateLimitRun(settings(endpoint), "rpm")
        run.start()
        snap = wait_terminal(run)
    assert snap["verdict"][0] == "ok"
    assert "admitted the first 7 of 8" in snap["verdict"][1]
    assert "crossed a clock-minute boundary" in snap["verdict"][1]
    assert "span two buckets of at most 5 each" in snap["verdict"][1]


def test_tpm_run_enforces_token_limit(fast_engine):
    with fake_gateway(ok_count=3, code=429, body=RATE_BODY, ok_body=XL_OK_BODY) as (endpoint, state):
        run = RateLimitRun(settings(endpoint), "tpm")
        assert run.start()
        snap = wait_terminal(run)
    assert snap["status"] == "done"
    assert snap["kind"] == "tpm"
    assert snap["planned"] == 4
    assert snap["completed"] == 4 == state["count"]
    assert snap["refusals"] == 1
    assert snap["verdict"][0] == "ok"
    # sequential dispatch: three XL requests then the confirm, in index order
    assert [r["index"] for r in snap["records"]] == [1, 2, 3, 4]
    first_three, confirm = snap["records"][:3], snap["records"][3]
    assert all(r["status_code"] == 200 for r in first_three)
    assert all(r["note"] == "Completed; tokens counted by gateway" for r in first_three)
    assert confirm["status_code"] == 429
    assert confirm["result"] == "429 Rate Limited"
    assert confirm["note"] == ("Token budget spent — refused at admission with only 3 "
                               "requests sent, below the 5 RPM cap")
    assert snap["tokens_in"] == 3 * 39088
    assert snap["records"][-1]["running_tokens"] == 3 * 39458


def test_tpm_confirm_refusal_below_token_limit_is_inconclusive(fast_engine):
    # default OK_BODY usage totals only 3 * 2,774 = 8,322 counted tokens — far
    # below the 100,000 TPM limit — so a 429 on the confirm cannot be
    # attributed to this test's own token usage
    with fake_gateway(ok_count=3, code=429, body=RATE_BODY) as (endpoint, _):
        run = RateLimitRun(settings(endpoint), "tpm")
        run.start()
        snap = wait_terminal(run)
    assert snap["status"] == "done"
    assert snap["verdict"][0] == "warn"
    assert "cannot be attributed" in snap["verdict"][1]


def test_tpm_confirm_refusal_after_xl_failures_is_inconclusive(fast_engine):
    # the three large requests time out (504); only the confirm sees a 429
    with fake_gateway(ok_count=0, code=429, body=RATE_BODY,
                      status_map={1: 504, 2: 504, 3: 504}) as (endpoint, state):
        run = RateLimitRun(settings(endpoint), "tpm")
        run.start()
        snap = wait_terminal(run)
    assert snap["status"] == "done"
    assert snap["verdict"][0] == "warn"
    assert "0 of 3 completed" in snap["verdict"][1]
    assert snap["refusals"] == 1
    assert state["count"] == 4


def test_tpm_run_without_refusal_is_inconclusive(fast_engine):
    with fake_gateway(ok_count=1000) as (endpoint, state):
        run = RateLimitRun(settings(endpoint), "tpm")
        run.start()
        snap = wait_terminal(run)
    assert snap["status"] == "done"
    assert snap["verdict"][0] == "warn"
    assert snap["completed"] == 4 == state["count"]
    assert snap["refusals"] == 0
    assert "minute boundary" in snap["verdict"][1]


def test_tpm_refusal_in_large_requests_is_attribution_ambiguous(fast_engine):
    with fake_gateway(ok_count=1, code=429, body=RATE_BODY) as (endpoint, _):
        run = RateLimitRun(settings(endpoint), "tpm")
        run.start()
        snap = wait_terminal(run)
    assert snap["verdict"][0] == "warn"
    assert "ambiguous" in snap["verdict"][1]
    hit = next(r for r in snap["records"]
               if r["index"] <= 3 and r["status_code"] == 429)
    assert "already full before this test" in hit["note"]
    confirm = next(r for r in snap["records"] if r["index"] == 4)
    assert confirm["note"].startswith("Token budget spent")


def test_all_refused_rpm_run_is_attribution_ambiguous(fast_engine):
    # a clean run admits the first 5 of 8; if EVERY request is refused the
    # clock minute was already full, so the limit responsible is ambiguous
    with fake_gateway(ok_count=0, code=429, body=RATE_BODY) as (endpoint, _):
        run = RateLimitRun(settings(endpoint), "rpm")
        run.start()
        snap = wait_terminal(run)
    assert snap["verdict"][0] == "warn"
    assert "ambiguous" in snap["verdict"][1]
    assert "clock minute was already full" in snap["verdict"][1]
    assert snap["completed"] == 8  # refusals cost nothing, so the whole run continues
    assert snap["refusals"] == 8
    assert all(r["result"] == "429 Rate Limited" for r in snap["records"])


def test_non_canonical_429_body_still_counts_as_refusal(fast_engine):
    with fake_gateway(ok_count=5, code=429, body='{"error": "slow down"}') as (endpoint, _):
        run = RateLimitRun(settings(endpoint), "rpm")
        run.start()
        snap = wait_terminal(run)
    assert snap["verdict"][0] == "ok"
    assert snap["refusals"] == 3
    assert all(r["result"] == "429 Rate Limited"
               for r in snap["records"] if r["status_code"] == 429)


def test_partial_usage_body_reaches_terminal_status(fast_engine):
    # a 200 whose usage carries prompt_tokens but no completion_tokens must not
    # kill the worker thread: the run still reaches a terminal status
    partial = json.dumps({
        "choices": [{"message": {"content": "ok"}}],
        "usage": {"prompt_tokens": 100, "total_tokens": 130},
    })
    with fake_gateway(ok_count=1000, ok_body=partial) as (endpoint, _):
        run = RateLimitRun(settings(endpoint), "rpm")
        run.start()
        snap = wait_terminal(run)
    assert snap["status"] == "done"
    assert snap["completed"] == 8
    assert all(r["note"] == "Completed; token usage unavailable" for r in snap["records"])
    # aggregation needs both counters, so display totals stay 0
    assert snap["tokens_in"] == 0 and snap["tokens_out"] == 0


def test_rpm_run_without_refusal_is_inconclusive(fast_engine):
    with fake_gateway(ok_count=1000) as (endpoint, state):
        run = RateLimitRun(settings(endpoint), "rpm")
        run.start()
        snap = wait_terminal(run)
    assert snap["verdict"][0] == "warn"
    assert "8 of 8 requests admitted" in snap["verdict"][1]
    assert "no 429 refusal" in snap["verdict"][1]
    assert "split across two clock-minute buckets" in snap["verdict"][1]
    assert snap["refusals"] == 0
    assert state["count"] == 8


def test_rpm_errors_are_not_counted_as_admitted(fast_engine):
    with fake_gateway(ok_count=1000, status_map={1: 500, 2: 500}) as (endpoint, _):
        run = RateLimitRun(settings(endpoint), "rpm")
        run.start()
        snap = wait_terminal(run)
    assert snap["verdict"][0] == "warn"
    assert "6 of 8 requests admitted" in snap["verdict"][1]
    assert "2 failed" in snap["verdict"][1]


def test_stop_during_rpm_sequence(fast_engine):
    with fake_gateway(ok_count=1000, delay=0.5) as (endpoint, state):
        run = RateLimitRun(settings(endpoint), "rpm")
        run.start()
        time.sleep(0.2)
        run.stop()
        snap = wait_terminal(run)
    assert snap["status"] == "stopped"
    assert snap["verdict"][0] == "warn"
    # stop lands mid-sequence: the in-flight request drains, the rest never go out
    assert snap["sent"] < 8
    assert snap["sent"] == snap["completed"] == state["count"]


def test_stop_after_refusal_reports_stopped_not_done(fast_engine):
    # a truncated run must not inherit a full-run verdict, even if it already
    # saw 429s: every enforcement verdict assumes the complete sample
    with fake_gateway(ok_count=1, code=429, body=RATE_BODY, delay=0.5) as (endpoint, _):
        run = RateLimitRun(settings(endpoint), "rpm")
        run.start()
        deadline = time.time() + 10
        while time.time() < deadline and run.snapshot()["refusals"] < 1:
            time.sleep(0.05)
        run.stop()
        snap = wait_terminal(run)
    assert snap["status"] == "stopped"
    assert snap["refusals"] >= 1
    assert snap["completed"] < snap["planned"]
    assert "Stopped by operator" in snap["verdict"][1]


def test_start_is_idempotent(fast_engine):
    with fake_gateway(ok_count=1000, delay=0.5) as (endpoint, state):
        run = RateLimitRun(settings(endpoint), "rpm")
        assert run.start()
        assert not run.start()
        run.stop()
        snap = wait_terminal(run)
    # one coordinator thread only: every sent request reached the gateway once
    assert snap["status"] == "stopped"
    assert snap["sent"] == state["count"]


def test_cooldown_remaining():
    assert cooldown_remaining([]) == 0
    assert cooldown_remaining([None, None]) == 0
    now = 1000.0
    fresh = {"last_request_at": now}
    assert cooldown_remaining([fresh], now=now) == pytest.approx(COOLDOWN_SECONDS)
    assert cooldown_remaining([fresh], now=now) > 60
    assert cooldown_remaining([{"last_request_at": now - 70}], now=now) == 0
    assert cooldown_remaining([{"last_request_at": None}], now=now) == 0
    # the newest stamp among the snapshots wins
    assert cooldown_remaining([{"last_request_at": now - 70}, fresh], now=now) == pytest.approx(COOLDOWN_SECONDS)


def test_sequential_timing_constants_pinned():
    assert REQUEST_INTERVAL == 3.0


def test_first_request_goes_out_immediately(fast_engine):
    # clicking Run must not park the run waiting for a minute boundary: the
    # cooldown between runs already keeps buckets clean
    import attack_tester.rate_limit as rl
    assert not hasattr(rl, "align_wait")
    with fake_gateway(ok_count=1000, delay=0.3) as (endpoint, _):
        run = RateLimitRun(settings(endpoint), "rpm")
        started = time.time()
        run.start()
        while run.snapshot()["sent"] < 1 and time.time() - started < 1.5:
            time.sleep(0.02)
        elapsed = time.time() - started
        run.stop()
        wait_terminal(run)
    assert elapsed < 1.5


def test_log_follows_completion_order_without_cost_column():
    # records arrive in completion order (2 before 1, 4 before 3); the table
    # must keep that order so the running token count reads monotonically
    records = []
    total = 0
    for idx, code in ((2, 200), (1, 200), (4, 429), (3, 200)):
        total += 2774 if code == 200 else 0
        records.append({
            "index": idx, "status_code": code,
            "latency_ms": 15000,
            "tokens_in": 1750 if code == 200 else 0,
            "tokens_out": 1024 if code == 200 else 0,
            "running_tokens": total, "evidence": None,
            "result": "200 OK" if code == 200 else "429 Rate Limited",
            "note": "note",
        })
    table = _log_html(records)
    positions = [table.index(f"<td>{i}</td>") for i in (2, 1, 4, 3)]
    assert positions == sorted(positions)
    cells = [table.index(f"<td class='num'>{v:,}</td>") for v in (2774, 5548, 5548, 8322)]
    assert cells == sorted(cells)
    assert table.count('class="rl-pill') == 4
    assert table.count("rl-pill ok") == 3 and table.count("rl-pill stop") == 1
    # token-focused page: no cost column at all
    assert "Cost" not in table and "$" not in table


def test_terminal_run_renders_evidence_statically(fast_engine):
    with fake_gateway(ok_count=5, code=429, body=RATE_BODY) as (endpoint, _):
        run = RateLimitRun(settings(endpoint), "rpm")
        run.start()
        snap = wait_terminal(run)
    assert snap["refusals"] == 3
    run._last_request_at = time.time() - COOLDOWN_SECONDS - 5  # bucket cooled: static path
    test = page(**CONFIGURED)
    test.session_state["_rate_limit_run_rpm"] = run
    test.run()
    assert not test.exception
    assert test.success
    assert any("Rate-limit refusal" in s.value for s in test.subheader)
    assert any("Navigating away does not cancel" in c.value for c in test.caption)
    log = next(m.value for m in test.markdown if "rl-log" in m.value)
    assert log.count('class="rl-pill') == 8
    assert log.count("rl-pill ok") == 5 and log.count("rl-pill stop") == 3


def test_cooldown_disables_both_run_buttons(fast_engine):
    with fake_gateway(ok_count=5, code=429, body=RATE_BODY) as (endpoint, _):
        run = RateLimitRun(settings(endpoint), "rpm")
        run.start()
        wait_terminal(run)
    run._last_request_at = time.time()  # shared window still busy
    test = page(**CONFIGURED)
    test.session_state["_rate_limit_run_rpm"] = run
    test.run()
    assert not test.exception
    buttons = [b for b in test.button if b.label in ("Run RPM test", "Run TPM test")]
    assert len(buttons) == 2
    assert all(b.disabled for b in buttons)
    assert any("cooling down" in c.value for c in test.caption)
    assert any("Navigating away does not cancel" in c.value for c in test.caption)


def test_timeout_gate_disables_only_the_tpm_button():
    test = page(**{**CONFIGURED, "timeout": 60})
    test.run()
    assert not test.exception
    rpm = next(b for b in test.button if b.label == "Run RPM test")
    tpm = next(b for b in test.button if b.label == "Run TPM test")
    assert not rpm.disabled
    assert tpm.disabled
    assert any("at least 90 s" in w.value for w in test.warning)


def _cooled_rpm_run(frozen_timeout):
    """Terminal rpm run frozen at the given timeout, window already cooled."""
    with fake_gateway(ok_count=1000) as (endpoint, _):
        run = RateLimitRun({**settings(endpoint), "timeout": frozen_timeout}, "rpm")
        run.start()
        wait_terminal(run)
    run._last_request_at = time.time() - COOLDOWN_SECONDS - 5
    return run


def test_live_timeout_reenables_tpm_for_run_frozen_at_low_timeout(fast_engine):
    # the gate reads the LIVE saved timeout, not the stale frozen settings
    run = _cooled_rpm_run(frozen_timeout=5)
    test = page(**{**CONFIGURED, "timeout": 120})
    test.session_state["_rate_limit_run_rpm"] = run
    test.run()
    assert not test.exception
    tpm = next(b for b in test.button if b.label == "Run TPM test")
    assert not tpm.disabled
    assert not any("at least 90 s" in w.value for w in test.warning)


def test_live_low_timeout_gates_tpm_despite_frozen_run(fast_engine):
    run = _cooled_rpm_run(frozen_timeout=120)
    test = page(**{**CONFIGURED, "timeout": 60})
    test.session_state["_rate_limit_run_rpm"] = run
    test.run()
    assert not test.exception
    tpm = next(b for b in test.button if b.label == "Run TPM test")
    assert tpm.disabled
    assert any("Request timeout is 60s" in w.value for w in test.warning)
