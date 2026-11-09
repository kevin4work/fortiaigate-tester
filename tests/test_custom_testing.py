"""Custom Testing: CSV parsers, plan caps, run engine, exports and page rendering."""

import json
import time
from unittest.mock import Mock, patch

import pytest
import requests
from streamlit.testing.v1 import AppTest

from attack_tester import custom_testing
from attack_tester.custom_testing import (
    SAMPLE_SINGLE_CSV,
    SAMPLE_STAGES_CSV,
    CustomRun,
    build_plan,
    custom_rows,
    export_csv,
    export_payload,
    parse_main_csv,
    parse_stage_csv,
    _pg_messages,
    _truncate,
)
from attack_tester.run_views import assessment_metrics
from attack_tester.ui import NAVIGATION
from common.fortiaigate_test import send_messages, send_prompt

SETTINGS = {"endpoint": "https://test.invalid/v1/chat/completions", "model": "test-model",
            "api_key": "fixture-only-test-key", "key_mask": "fixture…••••", "timeout": 5, "delay": 0}
MAIN_CSV = (
    "technique,description,prompt_text\n"
    "test-baseline,first,TESTONLY prompt one\n"
    "test-baseline,second,TESTONLY prompt two\n"
    "test-roleplay,,TESTONLY prompt three\n"
)
STAGE_CSV = (
    "technique,stage_1,stage_2,stage_3,stage_4\n"
    "test-roleplay,TESTONLY stage one,TESTONLY stage two,,\n"
)


def case(case_id, technique, *stages):
    return {"case_id": case_id, "technique": technique, "description": "", "stages": list(stages),
            "multi_stage": len(stages) > 1}


def reply(text):
    body = json.dumps({"choices": [{"message": {"content": text}}], "usage": {"total_tokens": 7}})
    return {"status": "OK", "response_text": text, "latency_ms": 12, "error": "", "status_code": 200,
            "raw_body": body, "usage": {"total_tokens": 7}}


def failure(error="Timeout", status_code=None):
    return {"status": "Error", "response_text": "", "latency_ms": 4, "error": error,
            "status_code": status_code, "raw_body": None, "usage": None}


def sender(replies, calls):
    """send_messages replacement: canned contracts in order, recording each conversation."""
    def send(endpoint, api_key, messages, model=None, timeout=30):
        calls.append({"endpoint": endpoint, "api_key": api_key, "model": model,
                      "messages": [dict(message) for message in messages]})
        item = replies[min(len(calls) - 1, len(replies) - 1)]
        return item if isinstance(item, dict) else reply(item)
    return send


def wait_terminal(run, timeout=20):
    deadline = time.time() + timeout
    while time.time() < deadline:
        snap = run.snapshot()
        if snap["status"] != "running":
            return snap
        time.sleep(0.02)
    raise AssertionError("custom run did not reach a terminal status")


def run_plan(monkeypatch, replies, cases):
    calls = []
    monkeypatch.setattr(custom_testing, "send_messages", sender(replies, calls))
    run = CustomRun(cases, SETTINGS)
    assert run.start()
    assert not run.start()  # idempotent
    return wait_terminal(run), calls


PAGE = (
    "from attack_tester.configuration import initialize_state\n"
    "from attack_tester.custom_testing import render_custom_testing\n"
    "initialize_state()\n"
    "render_custom_testing()\n"
)


def page(**saved):
    test = AppTest.from_string(PAGE, default_timeout=20)
    for key, value in saved.items():
        test.session_state["saved_" + key] = value
    return test


CONFIGURED = {"endpoint": "https://test.invalid/v1/chat/completions", "model": "test-model",
              "api_key": "fixture-only-test-key", "timeout": 5, "delay": 0}


def elements(test):
    values = []
    for name in ("markdown", "text", "code", "caption", "subheader", "error", "warning", "success", "info"):
        values.extend(str(item.value) for item in getattr(test, name, []))
    return "\n".join(values)


# ── Parsers ──

def test_navigation_lists_custom_testing_under_test_suites():
    groups = {group: [name for name, _ in pages] for group, pages in NAVIGATION}
    assert groups["TEST SUITES"][-1] == "Custom Testing"


def test_parse_main_csv_keeps_order_and_generates_ids():
    parsed = parse_main_csv(MAIN_CSV.encode())
    assert parsed["errors"] == [] and parsed["warnings"] == []
    assert [item["case_id"] for item in parsed["cases"]] == ["c-2", "c-3", "c-4"]
    assert parsed["cases"][0] == {"case_id": "c-2", "technique": "test-baseline", "description": "first",
                                  "stages": ["TESTONLY prompt one"]}
    assert all(len(item["stages"]) == 1 for item in parsed["cases"])


def test_parse_main_csv_names_the_expected_header_when_a_column_is_missing():
    parsed = parse_main_csv(b"technique,prompt\nx,TESTONLY\n")
    assert parsed["cases"] == []
    assert parsed["errors"] == ["Expected columns technique, description, prompt_text — found: technique, prompt."
                                " Missing: prompt_text. Unexpected: prompt (did you mean “prompt_text”)."]


def test_parse_main_csv_accepts_the_bundled_attack_type_alias_and_blank_technique():
    parsed = parse_main_csv("attack_type,description,prompt_text\n,note,TESTONLY one\n".encode("utf-8-sig"))
    assert parsed["errors"] == []
    assert parsed["cases"][0]["technique"] == custom_testing.UNCATEGORIZED


def test_parse_accepts_the_plural_techniques_header_in_both_files():
    parsed = parse_main_csv(b"techniques,description,prompt_text\nt,a,TESTONLY one\n")
    assert parsed["errors"] == [] and parsed["warnings"] == []
    assert parsed["cases"][0]["technique"] == "t"
    stages = parse_stage_csv(b"techniques,stage_1,stage_2\nt,TESTONLY a,TESTONLY b\n")
    assert stages["errors"] == []
    assert stages["cases"][0]["technique"] == "t"
    assert stages["cases"][0]["stages"] == ["TESTONLY a", "TESTONLY b"]


def test_parse_main_csv_hint_names_the_exact_difference_and_spares_optional_description():
    parsed = parse_main_csv(b"techniques2,description,prompt_text\nt,a,TESTONLY\n")
    assert parsed["cases"] == []
    error = parsed["errors"][0]
    assert error.startswith("Expected columns technique, description, prompt_text — found:")
    hint = error.split(". ", 1)[1]
    assert hint == "Missing: technique. Unexpected: techniques2 (did you mean “technique”)."


def test_parse_stage_csv_hint_names_a_misspelled_column():
    parsed = parse_stage_csv(b"technique,stage_1,stge_2\nt,a,b\n")
    assert parsed["cases"] == []
    assert parsed["errors"][0].startswith("Unexpected columns: stge_2 (did you mean “stage_2”).")


def test_parse_main_csv_reports_skipped_duplicates_and_unknown_columns():
    parsed = parse_main_csv(
        "technique,description,prompt_text,extra\n"
        "t,a,TESTONLY one,x\n"
        "t,b,,x\n"
        "t,a,TESTONLY one,x\n".encode())
    assert parsed["skipped"] == [3]
    assert parsed["duplicates"] == 1
    assert parsed["warnings"] == ["Ignoring unknown columns: extra."]
    assert len(parsed["cases"]) == 2  # duplicates are sent, never deduped


def test_parse_main_csv_rejects_empty_oversize_long_and_non_utf8_files():
    assert parse_main_csv(b"")["errors"] == ["File is empty."]
    big = b"technique,description,prompt_text\n" + b"t,a,TESTONLY\n" * 200
    with patch.object(custom_testing, "MAX_FILE_BYTES", 64):
        assert "the cap is 64 bytes" in parse_main_csv(big)["errors"][0]
    long_prompt = "technique,description,prompt_text\nt,a," + "x" * 9000 + "\n"
    with patch.object(custom_testing, "MAX_PROMPT_CHARS", 8000):
        assert parse_main_csv(long_prompt.encode())["errors"] == [
            "Row 2: prompt_text is 9000 characters; the cap is 8000."]
    assert parse_main_csv(b"technique,description,prompt_text\nt,a,\xff\xfe\xfa\n")["errors"] == [
        "File is not valid UTF-8 CSV."]


def test_parse_stage_csv_rejects_a_fifth_stage_column():
    parsed = parse_stage_csv(b"technique,stage_1,stage_2,stage_3,stage_4,stage_5\nt,a,,,,b\n")
    assert parsed["cases"] == []
    assert parsed["errors"][0].startswith("Unexpected columns: stage_5")


def test_parse_stage_csv_requires_contiguous_stages_and_skips_blank_rows():
    parsed = parse_stage_csv(
        "technique,stage_1,stage_2,stage_3,stage_4\n"
        "t,TESTONLY one,,TESTONLY three,\n"
        ",,,,\n"
        "t,TESTONLY only,,,,\n".encode())
    assert parsed["errors"] == ["Row 2: stage_3 is filled but stage_2 is empty."]
    assert parsed["skipped"] == [3]
    assert [item["stages"] for item in parsed["cases"]] == [["TESTONLY only"]]
    assert parsed["cases"][0]["case_id"] == "ms-4"


def test_build_plan_counts_every_stage_as_a_request_and_enforces_caps(monkeypatch):
    main = parse_main_csv(MAIN_CSV.encode())
    stages = parse_stage_csv(STAGE_CSV.encode())
    plan = build_plan(main, stages)
    assert plan["errors"] == []
    assert [item["case_id"] for item in plan["cases"]] == ["c-2", "c-3", "c-4", "ms-2"]
    assert plan["requests"] == 5 and plan["multi_stage"] == 1
    assert build_plan(parse_main_csv(b""), parse_main_csv(b""))["errors"] == [
        "No test cases found — check the validation messages above."]
    monkeypatch.setattr(custom_testing, "MAX_CASES", 3)
    assert build_plan(main, stages)["errors"] == ["Plan has 4 cases; the cap is 3."]
    monkeypatch.setattr(custom_testing, "MAX_CASES", 1000)
    monkeypatch.setattr(custom_testing, "MAX_REQUESTS", 4)
    assert build_plan(main, stages)["errors"] == ["Plan needs 5 requests; the cap is 4."]


def test_the_downloadable_samples_are_valid_plans():
    main = parse_main_csv(SAMPLE_SINGLE_CSV.encode())
    stages = parse_stage_csv(SAMPLE_STAGES_CSV.encode())
    assert main["errors"] == [] and stages["errors"] == []
    assert len(main["cases"]) == 5 and len(stages["cases"]) == 2
    assert [len(item["stages"]) for item in stages["cases"]] == [2, 4]
    plan = build_plan(main, stages)
    assert plan["errors"] == [] and plan["requests"] == 11 and plan["multi_stage"] == 2
    assert "TESTONLY" in SAMPLE_SINGLE_CSV and "fixture-only-test-key" not in SAMPLE_STAGES_CSV


# ── Run engine ──

def test_run_sends_cases_sequentially_and_records_outcomes(monkeypatch):
    snap, calls = run_plan(monkeypatch, ["TESTONLY ok", "Request blocked by FortiAIGate"],
                           [case("c-2", "test-baseline", "TESTONLY one"), case("c-3", "test-roleplay", "TESTONLY two")])
    assert snap["status"] == "done" and snap["sent"] == 2 == snap["planned_requests"]
    assert [call["messages"][-1]["content"] for call in calls] == ["TESTONLY one", "TESTONLY two"]
    rows = custom_rows(snap)
    assert [row["outcome"] for row in rows] == ["Through", "Blocked"]
    metrics = assessment_metrics(rows, snap["planned_cases"])
    assert (metrics["tested"], metrics["blocks"], metrics["through"], metrics["errors"]) == (2, 1, 1, 0)
    assert metrics["block_rate"] == pytest.approx(0.5)


def test_verdict_uses_the_exact_block_phrase_not_the_legacy_heuristic(monkeypatch):
    snap, _ = run_plan(monkeypatch, ["FortiAIGate is a gateway product", "BLOCKED BY FORTIAIGATE", "clean reply"],
                       [case("c-2", "t", "mention only"), case("c-3", "t", "shouting block"), case("c-4", "t", "clean")])
    assert [row["outcome"] for row in custom_rows(snap)] == ["Through", "Blocked", "Through"]


def test_multi_stage_case_accumulates_history_and_stops_at_the_first_block(monkeypatch):
    snap, calls = run_plan(monkeypatch, ["TESTONLY stage one reply", "Request blocked by FortiAIGate"],
                           [case("ms-2", "test-roleplay", "s1", "s2", "s3", "s4")])
    assert [call["messages"] for call in calls] == [
        [{"role": "user", "content": "s1"}],
        [{"role": "user", "content": "s1"}, {"role": "assistant", "content": "TESTONLY stage one reply"},
         {"role": "user", "content": "s2"}],
    ]
    rows = custom_rows(snap)
    assert len(rows) == 1
    assert rows[0]["outcome"] == "Blocked" and rows[0]["finalized"] is True
    assert rows[0]["latency_ms"] == 24  # summed over the two executed stages
    outcomes = [(stage["stage"], stage["outcome"]) for stage in rows[0]["stages"]]
    assert outcomes == [(1, "Through"), (2, "Blocked"), (3, "Skipped"), (4, "Skipped")]
    assert rows[0]["stages"][2]["note"] == "Skipped — blocked at stage 2."
    assert snap["sent"] == 2 and snap["planned_requests"] == 4


def test_stage_error_halts_the_case_and_is_excluded_from_the_block_rate(monkeypatch):
    snap, calls = run_plan(monkeypatch, [failure("Timeout"), "TESTONLY ok"],
                           [case("ms-2", "t", "s1", "s2"), case("c-3", "t", "one")])
    rows = custom_rows(snap)
    assert [row["outcome"] for row in rows] == ["Error", "Through"]
    assert rows[0]["error"] == "Timeout" and rows[0]["stages"][1]["outcome"] == "Skipped"
    metrics = assessment_metrics(rows, snap["planned_cases"])
    assert (metrics["tested"], metrics["errors"], metrics["block_rate"]) == (2, 1, 0.0)
    assert len(calls) == 2  # the failed case sent no second stage


def test_stop_leaves_the_running_case_unfinished(monkeypatch):
    calls = []

    def slow_send(endpoint, api_key, messages, model=None, timeout=30):
        calls.append(messages)
        time.sleep(0.3)  # long enough for stop() to land mid-run, short enough to stay offline
        return reply("TESTONLY ok")

    monkeypatch.setattr(custom_testing, "send_messages", slow_send)
    run = CustomRun([case("c-2", "t", "one"), case("c-3", "t", "two"), case("c-4", "t", "three")], SETTINGS)
    run.start()
    while not calls:
        time.sleep(0.01)
    run.stop()
    snap = wait_terminal(run)
    assert snap["status"] == "stopped"
    assert snap["verdict"][0] == "warn" and "Stopped by operator" in snap["verdict"][1]
    assert snap["completed"] == 1 and len(calls) == 1
    assert [row["status"] for row in custom_rows(snap)] == ["Through"]


def test_request_cap_produces_a_partial_run_verdict(monkeypatch):
    with patch.object(custom_testing, "MAX_REQUESTS", 2):
        snap, calls = run_plan(monkeypatch, ["TESTONLY ok"],
                               [case("c-2", "t", "one"), case("c-3", "t", "two"), case("c-4", "t", "three")])
    assert snap["status"] == "halted" and len(calls) == 2
    assert "request cap" in snap["verdict"][1]
    assert [row["status"] for row in custom_rows(snap)] == ["Through", "Through"]


def test_run_freezes_settings_and_stores_truncated_evidence(monkeypatch):
    long_body = dict(reply("TESTONLY ok"), raw_body="x" * (custom_testing.RAW_BODY_LIMIT + 100))
    snap, calls = run_plan(monkeypatch, [long_body], [case("c-2", "t", "one")])
    assert snap["settings"]["api_key"] == SETTINGS["api_key"]
    assert calls[0]["endpoint"] == SETTINGS["endpoint"] and calls[0]["model"] == SETTINGS["model"]
    stored = custom_rows(snap)[0]["stages"][0]["raw_body"]
    assert stored.endswith("[truncated]") and len(stored) < len(long_body["raw_body"])
    assert _truncate(None) is None and _truncate("short") == "short"


def test_export_payload_is_redacted_and_csv_holds_outcomes_only(monkeypatch):
    snap, _ = run_plan(monkeypatch, ["TESTONLY ok", "Request blocked by FortiAIGate"],
                       [case("ms-2", "test-roleplay", "s1", "s2"), case("c-3", "test-baseline", "one")])
    rows = custom_rows(snap)
    payload = export_payload(snap, assessment_metrics(rows, snap["planned_cases"]))
    assert set(payload) == {"run", "summary", "results"}
    assert payload["run"]["plan_counts"] == {"cases": 2, "multi_stage": 1, "requests": 3}
    assert payload["run"]["endpoint_host"] == "test.invalid"
    assert "api_key" not in json.dumps(payload)
    dumped = json.dumps(payload, ensure_ascii=False)
    assert "fixture-only-test-key" not in dumped and "raw_body" not in dumped
    assert payload["results"][0]["stages"][1]["outcome"] == "Blocked"
    table = export_csv(snap).splitlines()
    assert table[0] == "case_id,technique,stages,outcome,blocked_at_stage,latency_ms,error,response_first_500"
    assert table[1].startswith("ms-2,test-roleplay,2,Blocked,2,")
    assert "fixture-only-test-key" not in export_csv(snap)


def test_pg_messages_replays_history_and_adds_the_prefix_only_when_set():
    history = [{"role": "user", "content": "a"}, {"role": "assistant", "content": "b", "meta": {}}]
    assert _pg_messages(history, "  ", "c") == [{"role": "user", "content": "a"}, {"role": "assistant", "content": "b"},
                                               {"role": "user", "content": "c"}]
    assert _pg_messages(history, "You are inert.", "c")[0] == {"role": "system", "content": "You are inert."}


# ── send_messages transport ──

def response(body, status=200):
    resp = Mock(status_code=status, text=json.dumps(body) if not isinstance(body, str) else body)
    resp.json.return_value = body
    return resp


def test_send_messages_matches_the_send_prompt_contract_and_redacts():
    messages = [{"role": "user", "content": "a"}, {"role": "assistant", "content": "b"},
                {"role": "user", "content": "c"}]
    body = {"choices": [{"message": {"content": "hi"}}]}
    with patch("common.fortiaigate_test.requests.post", return_value=response(body)) as post:
        sent = send_messages(SETTINGS["endpoint"], "fixture-only-test-key", messages, model="test-model", timeout=5)
        single = send_prompt(SETTINGS["endpoint"], "k", "hi", model="test-model")
    multi_turn, one_turn = (call.kwargs for call in post.call_args_list)
    assert multi_turn["json"]["messages"] == messages
    assert multi_turn["json"]["model"] == "test-model"
    assert "max_tokens" not in multi_turn["json"]
    assert multi_turn["allow_redirects"] is False
    assert one_turn["json"]["messages"] == [{"role": "user", "content": "hi"}]  # send_prompt unchanged
    assert sent["status"] == "OK" and sent["response_text"] == "hi" and sent["usage"] is None
    assert set(sent) == set(single)
    assert "fixture-only-test-key" not in json.dumps(sent)


def test_send_messages_reports_transport_failures_like_send_prompt():
    with patch("common.fortiaigate_test.requests.post", side_effect=requests.Timeout()):
        assert send_messages(SETTINGS["endpoint"], "k", [{"role": "user", "content": "a"}])["error"] == "Timeout"
    with patch("common.fortiaigate_test.requests.post", return_value=response("fixture-only-test-key", 401)):
        sent = send_messages(SETTINGS["endpoint"], "fixture-only-test-key", [{"role": "user", "content": "a"}])
    assert sent["status"] == "Error" and sent["error"] == "Unauthorized — check API key"
    assert "fixture-only-test-key" not in json.dumps(sent)


# ── Page rendering ──

def button(test, label):
    return next(item for item in test.button if label in item.label)


def test_page_gates_on_missing_configuration_but_keeps_the_samples():
    test = page()
    test.run()
    assert not test.exception
    assert any("Configuration" in warning.value for warning in test.warning)
    assert button(test, "Run tests").disabled
    assert test.chat_input[0].disabled
    values = {widget.label: widget.value for widget in test.text_input}
    assert values["Requests per run cap"] == str(custom_testing.MAX_REQUESTS)
    assert values["API key (masked)"] == ""


def test_configured_page_shows_the_masked_key_and_both_tabs():
    test = page(**CONFIGURED)
    test.run()
    assert not test.exception
    values = {widget.label: widget.value for widget in test.text_input}
    assert values["API key (masked)"] == "fixture-…••••"
    assert values["Model"] == "test-model" and values["Delay between requests (s)"] == "0"
    assert "fixture-only-test-key" not in elements(test)
    assert [tab.label for tab in test.tabs] == ["CSV testing", "Playground"]
    assert not test.chat_input[0].disabled
    assert button(test, "Run tests").disabled  # nothing uploaded yet
    assert button(test, "Stop").disabled


def test_terminal_run_renders_the_garak_style_summary_and_evidence(monkeypatch):
    snap, _ = run_plan(monkeypatch, ["Request blocked by FortiAIGate", "TESTONLY ok", failure("Timeout")],
                       [case("c-2", "test-baseline", "TESTONLY blocked"),
                        case("ms-3", "test-roleplay", "TESTONLY stage one"),
                        case("c-4", "test-baseline", "TESTONLY failing")])
    test = page(**CONFIGURED)
    test.session_state["_custom_run"] = _finished(snap)
    test.run()
    assert not test.exception
    labels = [metric.label for metric in test.metric]
    assert labels == ["Total tested", "Blocked", "Through", "Errors", "Block rate", "Avg response time"]
    values = {metric.label: metric.value for metric in test.metric}
    assert (values["Total tested"], values["Blocked"], values["Through"], values["Errors"]) == ("3", "1", "1", "1")
    assert values["Block rate"] == "50.0%"
    body = elements(test)
    assert ":green-badge[Blocked]" in body and ":red-badge[Through]" in body and ":orange-badge[Error]" in body
    assert "By technique" in body and "test-baseline" in body and "test-roleplay" in body
    assert "All finished does not mean all passed" in body
    assert "Completion not verified" not in body  # every recorded case finalized
    assert "fixture-only-test-key" not in body
    assert not button(test, "New test run").disabled and button(test, "Stop").disabled


def _finished(snap):
    """Rebuild a terminal CustomRun from a snapshot's records without sending anything."""
    run = CustomRun([], SETTINGS)
    run.id = snap["id"]
    run.plan = [case(record["case_id"], record["technique"],
                     *[stage["prompt"] for stage in record["stages"]]) for record in snap["records"]]
    run._records = [dict(record) for record in snap["records"]]
    run._sent = snap["sent"]
    run._status = snap["status"]
    run._verdict = snap["verdict"]
    run.finished_at = snap["finished_at"]
    return run


def test_active_run_disables_new_test_run_and_keeps_stop(monkeypatch):
    snap, _ = run_plan(monkeypatch, ["TESTONLY ok"], [case("c-2", "test-baseline", "TESTONLY one")])
    run = _finished(snap)
    run._status = "running"
    run._started = True
    run._current = {"case_id": "c-2", "stage": 1, "stages": 1}
    test = page(**CONFIGURED)
    test.session_state["_custom_run"] = run
    test.run()
    assert not test.exception
    assert button(test, "New test run").disabled  # offering it mid-run would orphan the worker thread
    assert not button(test, "Stop").disabled


def test_elapsed_freezes_once_the_run_reaches_a_terminal_status():
    run = CustomRun([], SETTINGS)
    assert run.start()
    wait_terminal(run)
    first = run.snapshot()["elapsed_seconds"]
    time.sleep(0.05)
    assert run.snapshot()["elapsed_seconds"] == first


def test_parse_reports_malformed_csv_fields_as_validation_errors():
    error = "File is not readable CSV: a field is malformed or oversized."
    assert parse_main_csv(b"technique,description,prompt_text\nt,a,\x00\n")["errors"] == [error]
    big = b"technique,stage_1\nt,\"" + b"x" * 200000 + b"\"\n"
    assert parse_stage_csv(big)["errors"] == [error]


def test_export_csv_neutralizes_spreadsheet_formula_prefixes(monkeypatch):
    snap, _ = run_plan(monkeypatch, ['=HYPERLINK("http://evil")', "@SUM(A1:A2)"],
                       [case("c-2", "=1+1", "TESTONLY one"), case("c-3", "t", "TESTONLY two")])
    rows = export_csv(snap).splitlines()
    c2 = [row for row in rows if row.startswith("c-2,")][0]
    c3 = [row for row in rows if row.startswith("c-3,")][0]
    assert c2.startswith("c-2,'=1+1,")
    assert c3.endswith(",'@SUM(A1:A2)")


def test_untrusted_csv_text_renders_as_inert_text(monkeypatch):
    snap, _ = run_plan(monkeypatch, ["<img src=x onerror=alert(1)>"],
                       [case("c-2", "<script>alert(1)</script>", "<script>alert(2)</script>")])
    test = page(**CONFIGURED)
    test.session_state["_custom_run"] = _finished(snap)
    test.run()
    assert not test.exception
    assert any("<script>alert(2)</script>" in item.value for item in test.text)
    assert "<script>" not in "\n".join(item.value for item in test.markdown)


def test_pager_moves_the_evidence_page(monkeypatch):
    cases = [case("c-{}".format(index), "test-baseline", "TESTONLY prompt {}".format(index)) for index in range(2, 27)]
    snap, _ = run_plan(monkeypatch, ["TESTONLY ok"], cases)
    test = page(**CONFIGURED)
    test.session_state["_custom_run"] = _finished(snap)
    test.run()
    assert not test.exception
    assert any("of 25 cases" in item.value for item in test.caption)
    button(test, "›").click().run()
    assert not test.exception
    assert test.session_state["_assessment_custom_page_" + snap["id"]] == 2
    assert any("21–25 of 25 cases" in item.value for item in test.caption)


def test_new_session_clears_the_playground_and_preserves_everything_else():
    test = page(**CONFIGURED)
    test.session_state["_pg_history"] = [{"role": "user", "content": "TESTONLY turn"},
                                         {"role": "assistant", "content": "TESTONLY reply",
                                          "meta": {"outcome": "Through", "latency_ms": 12, "status_code": 200,
                                                   "tokens": 7, "error": "", "note": ""}}]
    test.session_state["_pg_session_id"] = "aaaaaaaa11111111"
    test.session_state["_saved_pg_system"] = "You are inert."
    test.session_state["_runner_session_id"] = "runner-session-must-survive"
    test.run()
    assert not test.exception
    assert any("TESTONLY reply" in item.value for item in test.markdown)
    assert any("Session aaaaaaaa · 1 turns · 7 tokens" in item.value for item in test.caption)
    button(test, "New session").click().run()
    assert not test.exception
    assert test.session_state["_pg_history"] == []
    assert test.session_state["_pg_session_id"] != "aaaaaaaa11111111"
    assert test.session_state["_runner_session_id"] == "runner-session-must-survive"
    assert test.session_state["_saved_pg_system"] == "You are inert."
    assert not any("TESTONLY reply" in item.value for item in test.markdown)


def test_playground_send_appends_a_badged_turn_and_a_failure_appends_none(monkeypatch):
    calls = []
    monkeypatch.setattr(custom_testing, "send_messages", sender(["Request blocked by FortiAIGate"], calls))
    test = page(**CONFIGURED)
    test.session_state["pg_system"] = "You are inert."
    test.session_state["_saved_pg_system"] = "You are inert."
    test.run()
    assert not test.exception
    test.chat_input[0].set_value("TESTONLY playground prompt").run()
    assert not test.exception
    history = test.session_state["_pg_history"]
    assert [turn["role"] for turn in history] == ["user", "assistant"]
    assert history[1]["meta"]["outcome"] == "Blocked"
    assert calls[0]["messages"][0] == {"role": "system", "content": "You are inert."}
    assert ":green-badge[Blocked]" in elements(test)
    monkeypatch.setattr(custom_testing, "send_messages", sender([failure("Connection error")], calls))
    test.chat_input[0].set_value("TESTONLY second prompt").run()
    assert not test.exception
    history = test.session_state["_pg_history"]
    assert [turn["role"] for turn in history] == ["user", "assistant", "user"]  # no assistant turn on failure
    assert test.session_state["_pg_error"]["error"] == "Connection error"
    assert ":orange-badge[Error]" in elements(test)
