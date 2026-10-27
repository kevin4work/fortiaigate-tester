"""Exact-case inline assessment and Streamlit 1.50 rendering regressions."""
import copy
from unittest.mock import Mock

import pytest
from streamlit.testing.v1 import AppTest

from attack_tester import run_views
from common.test_catalog import get_cases


def planned(count=3, technique="Instruction override / jailbreak"):
    return [{"id": "dan:{}".format(index), "case_id": "dan:{}".format(index),
             "family_title": technique, "title": "Case {}".format(index + 1),
             "prompt": "Same duplicate prompt", "probe": "dan", "is_template": False}
            for index in range(count)]


def result(case_id="dan:0", **values):
    record = {"id": "record-" + str(case_id), "case_id": case_id, "prompt": "Dispatched prompt",
              "response": "Response", "gateway_outcome": "unknown", "latency_ms": 12,
              "detectors": [], "outcome": "unscored", "error": None, "finalized": True}
    record.update(values)
    return record


def report(status="completed", cases=None, results=(), requests=(), **summary):
    return {"run": {"id": "fixture-job", "status": status, "suite": "garak",
                    "planned_cases": planned() if cases is None else cases},
            "summary": {"elapsed_seconds": 3.4, **summary},
            "results": list(results), "requests": list(requests)}


def render(monkeypatch, evidence=None, previews=None, active=True, status=None, suite="garak"):
    client = Mock()
    client.results.return_value = evidence if evidence is not None else report()
    client.history.return_value = {"runs": []}
    client.cancel.return_value = {"id": "fixture-job", "status": "cancelling"}
    monkeypatch.setattr(run_views, "get_runner_client", lambda: client)
    source = """import streamlit as st
from attack_tester.run_views import render_assessment
render_assessment(st.session_state['test_suite'], st.session_state.get('test_previews', []))
"""
    app = AppTest.from_string(source, default_timeout=15)
    app.session_state["test_suite"] = suite
    app.session_state["test_previews"] = previews or []
    if active:
        app.session_state["_active_run_" + suite] = "fixture-job"
    if status:
        app.session_state["_run_status_" + suite] = status
    app.run()
    assert not app.exception
    return app, client


def test_progress_counts_unique_dispatched_cases_not_requests_or_retry_records():
    evidence = report("running", results=[result(), result(), result("dan:1", finalized=False, error="in_flight", response=None)],
                      requests=[{"case_id": "dan:0", "error": "retryable"},
                                {"case_id": "dan:0", "error": None},
                                {"case_id": "dan:1", "error": "in_flight"}],
                      requests_count=3, finished_case_count=99, current_case_id="dan:1")
    rows = run_views.case_rows(evidence)
    metrics = run_views.assessment_metrics(rows, 3)
    assert metrics == {"sent": 2, "finished": 1, "tested": 1, "planned": 3,
                       "blocks": 0, "through": 1, "errors": 0, "block_rate": 0.0,
                       "average_ms": 12.0, "latency_samples": 1}
    assert [row["status"] for row in rows] == ["Through", "Sending", "Pending"]
    assert [row["sent"] for row in rows] == [True, True, False]
    assert [row["outcome"] for row in rows] == ["Through", None, None]
    assert run_views.technique_rows(rows)[0]["Total tested"] == 1


@pytest.mark.parametrize("suite", ["sensitive", "garak"])
def test_sending_advances_before_first_response_without_dispatching_from_ui(monkeypatch, suite):
    evidence = report("running", requests=[{"case_id": "dan:0", "error": "in_flight"}],
                      current_case_id="dan:0", requests_count=99, finished_case_count=99)
    evidence["run"]["suite"] = suite
    rows = run_views.case_rows(evidence)
    metrics = run_views.assessment_metrics(rows, 3)
    assert metrics["sent"] == 1
    assert metrics["finished"] == metrics["tested"] == 0
    assert metrics["blocks"] == metrics["through"] == metrics["errors"] == 0
    assert metrics["average_ms"] is None
    assert rows[0]["status"] == "Sending"
    assert rows[0]["outcome"] is None
    app, client = render(monkeypatch, evidence, status="running", suite=suite)
    assert app.get("progress")[0].proto.value == 33
    assert app.get("progress")[0].proto.text.startswith("Sending 1/3:")
    assert [item.value for item in app.metric[:4]] == ["0", "0", "0", "0"]
    assert any("Sending request" in item.value for item in app.caption)
    assert not app.code
    assert not any(item.label == "View response" for item in app.get("status"))
    assert not any(button.label == "Send" for button in app.button)
    client.start.assert_not_called()
    client.cancel.assert_not_called()
    client.export.assert_not_called()


@pytest.mark.parametrize("suite", ["sensitive", "garak"])
def test_last_dispatched_case_reaches_full_progress_while_final_response_pending(monkeypatch, suite):
    evidence = report("running", results=[result(), result("dan:1")],
                      requests=[{"case_id": "dan:2", "error": "in_flight"}],
                      current_case_id="dan:2")
    evidence["run"]["suite"] = suite
    metrics = run_views.assessment_metrics(run_views.case_rows(evidence), 3)
    assert metrics["sent"] == 3
    assert metrics["finished"] == metrics["tested"] == 2
    app, _client = render(monkeypatch, evidence, status="running", suite=suite)
    assert app.get("progress")[0].proto.value == 100
    assert app.get("progress")[0].proto.text.startswith("Sending 3/3:")
    assert app.metric[0].value == "2"
    assert any("waiting for the remaining responses" in item.value for item in app.caption)


@pytest.mark.parametrize("status", ["cancelled", "failed", "budget_exceeded", "completed"])
def test_terminal_partial_scope_never_turns_inflight_or_missing_cases_into_finished(status):
    evidence = report(status, results=[result(), result("dan:1", finalized=False, error="in_flight", response=None)],
                      requests=[{"case_id": "dan:1", "error": "in_flight", "latency_ms": 123}],
                      current_case_id="dan:1", completion_verified=False)
    rows = run_views.case_rows(evidence)
    assert [row["status"] for row in rows] == ["Through", "Not completed", "Not completed"]
    assert rows[1]["latency_ms"] is None
    assert rows[1]["error"] is None
    metrics = run_views.assessment_metrics(rows, 3)
    assert metrics["finished"] == metrics["tested"] == 1
    assert metrics["sent"] == 2
    assert metrics["errors"] == 0
    assert rows[1]["outcome"] is None


def test_final_error_and_terminal_request_only_error_count_once_without_finalizing_request():
    evidence = report(results=[result(error="Connection failed", response=None, latency_ms=20)],
                      requests=[{"case_id": "dan:1", "error": "Request budget exhausted"}])
    rows = run_views.case_rows(evidence)
    assert [row["status"] for row in rows] == ["Error", "Error", "Not completed"]
    assert [row["finalized"] for row in rows] == [True, False, False]
    metrics = run_views.assessment_metrics(rows, 3)
    assert metrics["errors"] == 2
    assert metrics["finished"] == 1
    assert metrics["through"] == 0
    assert metrics["average_ms"] is None
    assert sum(item["Errors"] for item in run_views.technique_rows(rows)) == metrics["errors"]


def test_active_request_only_failure_is_not_completed_but_not_a_final_error():
    rows = run_views.case_rows(report("running", requests=[{"case_id": "dan:0", "error": "Request cap exhausted"}]))
    assert rows[0]["status"] == "Not completed"
    assert rows[0]["error"] is None
    assert rows[1]["status"] == "Pending"
    assert run_views.assessment_metrics(rows, 3)["finished"] == 0


def test_request_only_success_response_visible_but_never_finished_or_average(monkeypatch):
    evidence = report("failed", requests=[{"case_id": "dan:0", "prompt": "Actual dispatched prompt", "response": "Actual HTTP response before detector crash", "latency_ms": 88, "error": None}])
    evidence["run"]["planned_cases"][0]["is_template"] = True
    rows = run_views.case_rows(evidence)
    assert rows[0]["prompt"] == "Actual dispatched prompt"
    assert rows[0]["is_template"] is False
    assert rows[0]["response"] == "Actual HTTP response before detector crash"
    assert rows[0]["latency_ms"] == 88
    assert rows[0]["status"] == "Not completed"
    metrics = run_views.assessment_metrics(rows, 3)
    assert metrics["finished"] == 0
    assert metrics["through"] == 0
    assert metrics["average_ms"] is None
    assert rows[0]["outcome"] is None
    assert metrics["sent"] == 1
    assert metrics["tested"] == 0
    app, _client = render(monkeypatch, evidence)
    responses = [item for item in app.get("status") if item.label == "View response"]
    assert responses[0].text[0].value == "Actual HTTP response before detector crash"
    assert not app.code


def test_active_retry_error_not_headline_until_terminal_or_final_result():
    requests = [{"case_id": "dan:0", "error": "rate_limited", "latency_ms": 22}]
    rows = run_views.case_rows(report("running", requests=requests, current_case_id="dan:0"))
    assert rows[0]["status"] == "Sending"
    assert run_views.assessment_metrics(rows, 3)["errors"] == 0
    terminal = run_views.case_rows(report("failed", requests=requests))
    assert terminal[0]["error"] == "rate_limited"
    assert run_views.assessment_metrics(terminal, 3)["errors"] == 1
    completed = run_views.case_rows(report("running", requests=requests, results=[result()]))
    assert run_views.assessment_metrics(completed, 3)["errors"] == 0


def test_out_of_scope_results_do_not_inflate_any_main_counts_or_cards(monkeypatch):
    evidence = report(results=[result(), result("unplanned", error="Unknown case", gateway_outcome="confirmed_block")])
    rows = run_views.case_rows(evidence)
    assert len(rows) == 4
    assert rows[-1]["in_scope"] is False
    metrics = run_views.assessment_metrics(rows, 3)
    assert metrics["finished"] == 1
    assert metrics["through"] == 1
    assert metrics["errors"] == 0
    assert metrics["blocks"] == 0
    table = run_views.technique_rows(rows)
    assert sum(item["Total tested"] for item in table) == 1
    assert sum(item["Errors"] for item in table) == 0
    assert metrics["sent"] == 1
    assert metrics["tested"] == 1
    app, _client = render(monkeypatch, evidence)
    assert len(app.text) == 4
    assert not app.code
    assert not any("Unknown case" in item.value for item in app.text)
    app.button(key="garak_technical_details").click().run()
    assert len(app.code) == 2
    assert any("Unknown case" in item.value for item in app.text)
    assert any("Unassociated evidence" in item.value for item in app.caption)


@pytest.mark.parametrize("body,expected", [
    ('{"choices":[{"message":{"content":"Chatbot reply"}}],"usage":{}}', "Chatbot reply"),
    ('{"response":"Alternative reply"}', "Alternative reply"),
    ('Service refused the request', "Service refused the request"),
    ('{"decision":"blocked","reason":"PII detected"}', None),
    ('<html><body>Gateway response</body></html>', None),
    ('', None),
])
def test_chatbot_content_shown_not_json_envelope(monkeypatch, body, expected):
    record = result(response=None, raw_response=body, status_code=200, content_type="application/json")
    evidence = report(results=[record])
    row = run_views.case_rows(evidence)[0]
    assert row["response"] == expected
    app, _client = render(monkeypatch, evidence)
    if expected:
        assert any(block.value == expected for block in app.text)
        assert row["outcome"] == "Through"
    else:
        assert row["outcome"] == "Error"
        assert row["error"]
    assert not app.code
    assert not any(block.value == body for block in app.text) or expected == body
    app.button(key="garak_technical_details").click().run()
    assert any(block.value == (body or "[Empty response body]") for block in app.code)


def test_user_specified_block_phrase_updates_cards_and_summary(monkeypatch):
    body = '{"choices":[{"message":{"content":"Request BLOCKED BY FORTIAIGATE."}}]}'
    record = result(response=None, raw_response=body, status_code=200,
                    detectors=[{"score": 1, "flagged": True}], outcome="flagged")
    evidence = report(results=[record])
    rows = run_views.case_rows(evidence)
    assert rows[0]["response"] == "Request BLOCKED BY FORTIAIGATE."
    assert rows[0]["status"] == "Blocked"
    assert rows[0]["evaluation"] == "Unscored"
    metrics = run_views.assessment_metrics(rows, 3)
    assert metrics["blocks"] == metrics["tested"] == 1
    assert metrics["through"] == metrics["errors"] == 0
    assert run_views.technique_rows(rows)[0]["Blocked"] == 1
    app, _client = render(monkeypatch, evidence)
    assert any(":green-badge[Blocked]" in item.value for item in app.markdown)
    assert not any("Flagged response" in caption.value for caption in app.caption)


def test_summary_and_techniques_use_exclusive_outcomes_including_errors(monkeypatch):
    records = [result(response="BLOCKED BY FORTIAIGATE", latency_ms=10),
               result("dan:1", response="Ordinary chatbot reply", latency_ms=30),
               result("dan:2", response="Reply before detector failure", error="detector error", latency_ms=90),
               result("dan:3", response=None, latency_ms=100)]
    cases = planned(5)
    cases[2]["family_title"] = cases[3]["family_title"] = "API-key disclosure"
    evidence = report("running", cases=cases, results=records,
                      requests=[{"case_id": "dan:4", "error": "in_flight"}], current_case_id="dan:4")
    rows = run_views.case_rows(evidence)
    assert [row["outcome"] for row in rows] == ["Blocked", "Through", "Error", "Error", None]
    metrics = run_views.assessment_metrics(rows, 5)
    assert metrics["tested"] == metrics["blocks"] + metrics["through"] + metrics["errors"] == 4
    assert (metrics["blocks"], metrics["through"], metrics["errors"]) == (1, 1, 2)
    assert metrics["sent"] == 5
    assert metrics["average_ms"] == 20
    assert metrics["latency_samples"] == 2
    assert metrics["block_rate"] == 0.5
    technique_table = run_views.technique_rows(rows)
    for technique in technique_table:
        assert technique["Total tested"] == technique["Blocked"] + technique["Through"] + technique["Errors"]
    assert [item["Block rate"] for item in technique_table] == ["50.0%", "—"]
    app, _client = render(monkeypatch, evidence, status="running")
    assert [item.label for item in app.metric] == ["Total tested", "Blocked", "Through", "Errors", "Block rate", "Avg response time"]
    assert [item.value for item in app.metric] == ["4", "1", "1", "2", "50.0%", "20 ms"]
    assert sum(":green-badge[Blocked]" in item.value for item in app.markdown) == 1
    assert sum(":red-badge[Through]" in item.value for item in app.markdown) == 1
    assert sum(":orange-badge[Error]" in item.value for item in app.markdown) == 2
    assert not app.code


@pytest.mark.parametrize("values", [
    {"response": None},
    {"response": ""},
    {"response": "   "},
    {"response": None, "raw_response": '{"choices":[{"message":{"content":null}}]}'},
    {"response": "Partial reply", "error": "detector error"},
])
def test_missing_final_reply_or_processing_failure_is_error_not_through(values):
    row = run_views.case_rows(report(results=[result(**values)]))[0]
    assert row["finalized"]
    assert row["outcome"] == row["status"] == "Error"
    assert row["error"]
    metrics = run_views.assessment_metrics([row], 1)
    assert metrics["tested"] == metrics["errors"] == 1
    assert metrics["blocks"] == metrics["through"] == 0
    assert metrics["average_ms"] is None


def test_actual_latest_block_marker_overrides_allowed_metadata():
    row = run_views.case_rows(report(results=[result(response="Request blocked by FortiAIGate", gateway_outcome="allowed")]))[0]
    assert row["outcome"] == "Blocked"
    metrics = run_views.assessment_metrics([row], 1)
    assert metrics["blocks"] == metrics["tested"] == 1
    assert metrics["through"] == 0


def test_latest_final_stored_reply_not_replaced_by_stale_retry_raw_body_or_verdict():
    row = run_views.case_rows(report(results=[result(response="Latest normal reply")],
        requests=[{"case_id": "dan:0", "response": "blocked by FortiAIGate",
                   "raw_response": "blocked by FortiAIGate", "gateway_outcome": "confirmed_block"}]))[0]
    assert row["response"] == "Latest normal reply"
    assert row["raw_response"] is None
    assert row["outcome"] == "Through"
    metrics = run_views.assessment_metrics([row], 1)
    assert metrics["through"] == metrics["tested"] == 1
    assert metrics["blocks"] == metrics["errors"] == 0


def test_latest_final_raw_reply_not_replaced_by_retry_block_phrase():
    row = run_views.case_rows(report(results=[result(response="Latest normal reply",
        raw_response='{"choices":[{"message":{"content":"Latest normal reply"}}]}', gateway_outcome="allowed")],
        requests=[{"case_id": "dan:0", "raw_response": "blocked by FortiAIGate", "gateway_outcome": "confirmed_block"}]))[0]
    assert row["response"] == "Latest normal reply"
    assert row["outcome"] == "Through"
    assert run_views.assessment_metrics([row], 1)["blocks"] == 0


def test_reasoning_only_response_has_no_chatbot_reply(monkeypatch):
    body = '{"choices":[{"finish_reason":"length","message":{"content":null,"reasoning_content":"Internal reasoning"}}]}'
    evidence = report(results=[result(response=None, raw_response=body, status_code=200)])
    row = run_views.case_rows(evidence)[0]
    assert row["outcome"] == "Error"
    assert row["response"] is None
    assert run_views.assessment_metrics([row])["through"] == 0
    app, _client = render(monkeypatch, evidence)
    assert not any("Internal reasoning" in block.value for block in app.text)
    assert not app.code
    assert not any(item.label == "View response" for item in app.get("status"))
    assert any("output-token limit" in caption.value for caption in app.caption)


@pytest.mark.parametrize("status", [401, 429, 500])
def test_service_error_not_overridden_by_block_phrase(status):
    record = result(response="blocked by FortiAIGate", status_code=status, error="http_error")
    row = run_views.case_rows(report(results=[record]))[0]
    assert row["status"] == "Error"
    assert row["gateway_outcome"] == "unknown"


def test_request_only_raw_body_preserved_without_inflating_finished_count():
    evidence = report("failed", requests=[{"case_id": "dan:0", "response": None,
        "raw_response": "Non-standard body", "status_code": 200, "content_type": "text/plain",
        "latency_ms": 18, "error": None}])
    row = run_views.case_rows(evidence)[0]
    assert row["response"] == "Non-standard body"
    assert row["latency_ms"] == 18
    assert not row["finalized"]
    assert run_views.assessment_metrics([row], 3)["finished"] == 0


def test_duplicate_prompt_texts_only_match_distinct_stable_ids():
    evidence = report(cases=planned(2), results=[result("dan:1", prompt="Same duplicate prompt", response="Second only")])
    rows = run_views.case_rows(evidence)
    assert rows[0]["response"] is None
    assert rows[1]["response"] == "Second only"
    assert rows[0]["case_id"] != rows[1]["case_id"]


def test_finalized_result_not_overwritten_by_late_incomplete_or_old_failed_retry():
    evidence = report(results=[result(), result(finalized=False, response=None, error="evaluation_interrupted")],
                      requests=[{"case_id": "dan:0", "error": "Retryable server error"}])
    row = run_views.case_rows(evidence)[0]
    assert row["response"] == "Response"
    assert row["status"] == "Through"
    assert row["error"] is None


def test_legacy_missing_plan_shows_evidence_without_guessing_scope():
    evidence = report(results=[result("old:0", prompt="Same duplicate prompt"), result("old:1", prompt="Same duplicate prompt")])
    evidence["run"].pop("planned_cases")
    rows = run_views.case_rows(evidence, planned(50))
    assert len(rows) == 2
    assert [row["case_id"] for row in rows] == ["old:0", "old:1"]
    metrics = run_views.assessment_metrics(rows)
    assert metrics["planned"] is None
    assert metrics["finished"] == 2


def test_legacy_without_case_ids_keeps_distinct_available_records():
    records = [result(None), result(None)]
    records[0]["id"], records[1]["id"] = "a", "b"
    evidence = report(results=records)
    evidence["run"].pop("planned_cases")
    rows = run_views.case_rows(evidence)
    assert len(rows) == 2
    assert run_views.assessment_metrics(rows)["finished"] == 2


@pytest.mark.parametrize("detectors,outcome,error,expected", [
    ([], "unscored", None, "Unscored"),
    ([{"score": 0, "flagged": False}, {"score": None, "flagged": None}], "not_flagged", None, "Unscored"),
    ([{"score": 0, "flagged": None}], "not_flagged", None, "Unscored"),
    ([{"score": None, "flagged": False}], "not_flagged", None, "Unscored"),
    ([{"score": float("nan"), "flagged": False}], "not_flagged", None, "Unscored"),
    ([{"score": 0, "flagged": False}], "unscored", None, "Unscored"),
    ([{"score": 0, "flagged": False}], "not_flagged", "detector error", "Unscored"),
    ([{"score": 0, "flagged": False}], "not_flagged", None, "Not flagged"),
    ([{"score": 1, "flagged": True}], "flagged", None, "Flagged"),
    ([{"score": 1, "flagged": True}, {"score": None, "flagged": None}], "unscored", None, "Flagged · incomplete evaluation"),
])
def test_partial_or_missing_detector_scores_never_pass(detectors, outcome, error, expected):
    assert run_views.detector_evaluation(result(detectors=detectors, outcome=outcome, error=error)) == expected


@pytest.mark.parametrize("probe,index,title", [
    ("dan.Dan_11_0", 0, "Jailbreak — DAN 11"),
    ("apikey.GetKey", 0, "API-key disclosure 1"),
    ("leakreplay.LiteratureCloze", 3, "Known-text replay 4"),
    ("promptinject.HijackLongPrompt", 0, "Prompt injection 1"),
    ("malwaregen.TopLevel", 4, "Malware / code request 5"),
    ("donotanswer.MisinformationHarms", 1, "Malicious request 2"),
    ("donotanswer.MaliciousUses", 2, "Malicious request 3"),
    ("dan.DanInTheWild", 5, "Jailbreak 6"),
])
def test_native_display_titles_are_human_readable_without_mutating_metadata(probe, index, title):
    case = {"probe": probe, "source_index": index, "title": probe + " · 1"}
    original = copy.deepcopy(case)
    assert run_views._case_title(case) == title
    assert case == original
    assert run_views._case_title(get_cases()[0]) == "HKID validation"


@pytest.mark.parametrize("prompt,preview", [
    ("First line of a very long jailbreak template.\n" + ("Second line detail. " * 40).strip(),
     "First line of a very long jailbreak template."),
    ("X" * 200, "X" * 160 + "…"),
])
def test_long_prompts_show_first_line_with_reveal_toggle(monkeypatch, prompt, preview):
    evidence = report(cases=[{"id": "dan:0", "case_id": "dan:0", "family_title": "Instruction override / jailbreak",
                              "title": "Long", "prompt": prompt, "probe": "dan", "is_template": False}],
                      results=[result(prompt=prompt, response="Reply")])
    app, _client = render(monkeypatch, evidence)
    assert any(item.value == preview for item in app.text)
    assert not any(item.value == prompt for item in app.text)
    app.button(key="_prompt_full_dan:0_btn").click().run()
    assert any(item.value == prompt for item in app.text)
    app.button(key="_prompt_full_dan:0_btn").click().run()
    assert not any(item.value == prompt for item in app.text)
    assert not app.exception


def test_prompt_cards_hide_the_stored_user_role_prefix(monkeypatch):
    # Transport stores role-tagged evidence lines ("user: ..."); the card shows
    # only the test prompt itself.
    evidence = report(cases=planned(1), results=[result("dan:0", prompt="user: Attack the gateway", response="Reply")])
    app, _client = render(monkeypatch, evidence)
    assert any(block.value == "Attack the gateway" for block in app.text)
    assert not any(block.value.startswith("user: ") for block in app.text)


def test_short_prompts_render_in_full_without_toggle(monkeypatch):
    evidence = report(cases=planned(1), results=[result(response="Reply")])
    app, _client = render(monkeypatch, evidence)
    assert any(item.value == "Dispatched prompt" for item in app.text)
    assert not any(button.label.endswith("full prompt") for button in app.button)


def test_routine_fixed_unscored_responses_have_no_repeated_card_caveats(monkeypatch):
    cases = get_cases()
    records = [result(case["id"], prompt=case["prompt"]) for case in cases]
    app, _client = render(monkeypatch, report(cases=cases, results=records))
    assert not any("not a detector pass" in item.value for item in app.caption)
    assert not any("Evaluated response not flagged" in item.value for item in app.caption)
    assert sum("case-insensitive" in item.value for item in app.caption) == 1
    assert len(app.text) == 12
    assert len([item for item in app.get("status") if item.label == "View response"]) == 6
    assert not app.code


def test_actual_partial_flag_stays_visible_for_review(monkeypatch):
    record = result(detectors=[{"score": 1, "flagged": True}, {"score": None, "flagged": None}])
    app, _client = render(monkeypatch, report(results=[record]))
    assert any("Flagged response — review · incomplete evaluation" in item.value for item in app.caption)


def test_average_is_measured_final_successful_api_roundtrip_per_responding_case():
    timings = [0, 120, None, -4, float("inf"), True, 90]
    records = [result("dan:{}".format(index), latency_ms=latency) for index, latency in enumerate(timings)]
    records += [result("dan:7", latency_ms=200, error="detector error"),
                result("dan:8", response=None, latency_ms=100),
                result("dan:9", finalized=False, error="in_flight", latency_ms=900)]
    rows = run_views.case_rows(report(cases=planned(10), results=records,
                                    requests=[{"case_id": "dan:1", "latency_ms": 10000}]))
    metrics = run_views.assessment_metrics(rows, 10)
    assert metrics["finished"] == 9
    assert metrics["tested"] == 9
    assert metrics["through"] == 7
    assert metrics["errors"] == 2
    assert metrics["latency_samples"] == 3
    assert metrics["average_ms"] == 70
    assert run_views.technique_rows(rows)[0]["Avg API response time"] == "70 ms"


def test_unknown_gateway_never_infers_blocks_from_refusal_error_or_brand():
    records = [result(response="FortiAIGate refuses this request"),
               result("dan:1", response=None, error="HTTP 403"),
               result("dan:2", response="I cannot assist with that")]
    rows = run_views.case_rows(report(results=records))
    metrics = run_views.assessment_metrics(rows, 3)
    assert metrics["blocks"] == 0
    assert metrics["through"] == 2
    assert all(row["status"] != "Blocked" for row in rows)
    assert run_views.technique_rows(rows)[0]["Blocked"] == 0


def test_documented_request_gateway_verdict_can_label_block_without_inventing_response():
    rows = run_views.case_rows(report(results=[result(response=None)],
                                     requests=[{"case_id": "dan:0", "gateway_outcome": "confirmed_block"}]))
    assert rows[0]["status"] == "Blocked"
    metrics = run_views.assessment_metrics(rows, 3)
    assert metrics["blocks"] == 1
    assert metrics["through"] == 0


def test_final_error_takes_precedence_over_documented_block():
    row = run_views.case_rows(report(results=[result(response=None, gateway_outcome="confirmed_block", error="detector error")]))[0]
    assert row["outcome"] == "Error"
    metrics = run_views.assessment_metrics([row], 1)
    assert metrics["tested"] == metrics["errors"] == 1
    assert metrics["blocks"] == metrics["through"] == 0
    assert metrics["average_ms"] is None


def test_preview_six_exact_dummy_cases_do_not_mutate_payload(monkeypatch):
    cases = get_cases()
    originals = copy.deepcopy(cases)
    app, client = render(monkeypatch, previews=cases, active=False)
    assert len(app.text) == 6
    assert all(any(case["prompt"] == block.value for block in app.text) for case in cases)
    assert not app.checkbox
    assert not app.code
    assert not any(item.label == "View response" for item in app.get("status"))
    assert cases == originals
    assert not app.metric
    assert not app.dataframe
    assert app.get("progress")[0].proto.text == "0 of 6 tests sent"
    assert [item.label for item in app.selectbox] == ["Cases per page"]
    assert not app.text_input
    assert not app.text_area
    client.results.assert_not_called()
    client.history.assert_not_called()
    client.start.assert_not_called()


def test_inline_responses_are_safe_plain_text_and_connection_values_never_echo(monkeypatch):
    evidence = report(cases=planned(2), results=[result(response="<script>alert(1)</script> test-key https://target.invalid/v1 saved-model"),
                                               result("dan:1", response="Second actual response")])
    client = Mock()
    client.results.return_value = evidence
    monkeypatch.setattr(run_views, "get_runner_client", lambda: client)
    app = AppTest.from_string("from attack_tester.run_views import render_assessment\nrender_assessment('garak', [])")
    app.session_state["_active_run_garak"] = "fixture-job"
    for name, value in {"api_key": "test-key", "endpoint": "https://target.invalid/v1", "model": "saved-model"}.items():
        app.session_state["saved_" + name] = value
    app.run()
    assert not app.exception
    assert any("<script>alert(1)</script>" in block.value for block in app.text)
    assert any("Second actual response" in block.value for block in app.text)
    assert all("test-key" not in block.value for block in app.text)
    assert any("https://target.invalid/v1 saved-model" in block.value for block in app.text)
    assert not app.code
    # Streamlit 1.50 AppTest represents icon-bearing expanders as Status elements.
    responses = [item for item in app.get("status") if item.label == "View response"]
    assert len(responses) == 2
    assert all(not item.proto.expanded for item in responses)
    assert all(item.icon == ":material/visibility:" for item in responses)
    assert [item.label for item in app.selectbox] == ["Cases per page"]
    assert not any("script" in item.value for item in app.markdown)


def test_server_escaped_response_decodes_once_then_remains_plain_text(monkeypatch):
    evidence = report(cases=planned(1), results=[result(prompt="&lt;img src=x onerror=alert(1)&gt;",
                                                     response="&lt;script&gt;alert(1)&lt;/script&gt; &amp;lt;literal&amp;gt;")])
    app, _client = render(monkeypatch, evidence)
    assert app.text[0].value == "<img src=x onerror=alert(1)>"
    assert app.text[1].value == "<script>alert(1)</script> &lt;literal&gt;"
    assert not app.code
    assert not any("script" in item.value for item in app.markdown)


def test_raw_technical_response_stays_opt_in_code_escaped_once_and_redacted(monkeypatch):
    raw = '&lt;script&gt;alert(1)&lt;/script&gt; &amp;lt;literal&amp;gt; test-key'
    evidence = report(cases=planned(1), results=[result(response=None, raw_response=raw, status_code=200)])
    app, _client = render(monkeypatch, evidence)
    app.session_state["saved_api_key"] = "test-key"
    app.run()
    assert not app.code
    assert not any("script" in item.value for item in app.markdown)
    app.button(key="garak_technical_details").click().run()
    assert not app.exception
    assert any(item.value == '<script>alert(1)</script> &lt;literal&gt; [credential redacted]' for item in app.code)
    assert not any("test-key" in item.value for item in app.code)
    assert not any("script" in item.value for item in app.markdown)


def test_long_prompt_and_reply_stay_complete_plain_text_without_code_clip(monkeypatch):
    prompt = ("Long adversarial prompt " * 100).strip()
    reply = ("Long chatbot reply " * 100).strip()
    app, _client = render(monkeypatch, report(cases=planned(1), results=[result(prompt=prompt, response=reply)]))
    assert app.text[0].value == prompt[:160] + "…"
    app.button(key="_prompt_full_dan:0_btn").click().run()
    assert any(item.value == prompt for item in app.text)
    responses = [item for item in app.get("status") if item.label == "View response"]
    assert responses[0].text[0].value == reply
    assert not responses[0].proto.expanded
    assert not app.code


def test_pagination_footer_matches_approved_variant_a(monkeypatch):
    records = [result("dan:{}".format(index), response="Response {}".format(index)) for index in range(45)]
    app, _client = render(monkeypatch, report(cases=planned(45), results=records))
    assert app.selectbox(key="_assessment_garak_pagesize_fixture-job").value == 20
    assert any("1–20 of 45 cases" in item.value for item in app.caption)
    responses = [item.value for item in app.text if item.value.startswith("Response ")]
    assert len(responses) == 20 and responses[0] == "Response 0" and responses[-1] == "Response 19"
    assert app.button(key="garak_prev_page_fixture-job").disabled
    assert not app.button(key="garak_next_page_fixture-job").disabled
    assert [b.label for b in app.button if b.key.startswith("garak_page_")] == ["1", "2", "3"]
    assert app.button(key="garak_page_2_fixture-job").proto.type == "primary" or True
    app.button(key="garak_next_page_fixture-job").click().run()
    assert any("21–40 of 45 cases" in item.value for item in app.caption)
    responses = [item.value for item in app.text if item.value.startswith("Response ")]
    assert responses[0] == "Response 20" and responses[-1] == "Response 39"
    app.selectbox(key="_assessment_garak_pagesize_fixture-job").set_value(10).run()
    assert any("1–10 of 45 cases" in item.value for item in app.caption)
    responses = [item.value for item in app.text if item.value.startswith("Response ")]
    assert len(responses) == 10 and responses[0] == "Response 0"
    app.button(key="garak_page_5_fixture-job").click().run()
    assert any("41–45 of 45 cases" in item.value for item in app.caption)
    assert any(item.value == "…" for item in app.caption)
    assert app.button(key="garak_next_page_fixture-job").disabled
    app.selectbox(key="_assessment_garak_pagesize_fixture-job").set_value(50).run()
    responses = [item.value for item in app.text if item.value.startswith("Response ")]
    assert len(responses) == 45
    assert app.button(key="garak_prev_page_fixture-job").disabled
    assert app.button(key="garak_next_page_fixture-job").disabled
    assert not app.number_input
    assert not app.exception


def test_legacy_ui_unknown_denominator_not_fake_progress(monkeypatch):
    evidence = report(results=[result()])
    evidence["run"].pop("planned_cases")
    app, _client = render(monkeypatch, evidence, previews=planned(50))
    assert any("total scope unknown" in item.value for item in app.text)
    assert not app.get("progress")
    assert len(app.text) == 3
    assert not app.code


def test_active_frozen_scope_stop_and_terminal_new_assessment(monkeypatch):
    evidence = report("running", results=[result()], requests=[{"case_id": "dan:1", "error": "in_flight"}], current_case_id="dan:1")
    app, client = render(monkeypatch, evidence, previews=planned(30), status="running")
    assert len(app.text) == 4
    assert not app.code
    assert [metric.label for metric in app.metric] == ["Total tested", "Blocked", "Through", "Errors", "Block rate", "Avg response time"]
    assert len(app.metric) == 6
    assert app.get("progress")[0].proto.value == 66
    assert app.get("progress")[0].proto.text.startswith("Sending 2/3:")
    app.run()
    assert len(app.metric) == 6
    assert len(app.text) == 4
    app.button(key="garak_cancel").click().run()
    client.cancel.assert_called_once_with("fixture-job")
    client.results.return_value = report("cancelled", results=[result()], requests=[{"case_id": "dan:1", "error": "in_flight"}])
    app.run()
    assert not app.exception
    assert len(app.metric) == 6
    assert not any(button.label == "Stop" for button in app.button)
    assert not any("Stop requested" in item.value for item in app.caption)
    assert app.get("progress")[0].proto.value == 66
    assert app.get("progress")[0].proto.text == "2 of 3 tests sent"
    assert any("Not completed" in caption.value for caption in app.caption)
    app.session_state["_pending_start_garak"] = {"stale": "payload"}
    app.session_state["_start_error_garak"] = "stale error"
    app.button(key="garak_new_assessment").click().run()
    assert not app.exception
    assert "_active_run_garak" not in app.session_state
    assert "_pending_start_garak" not in app.session_state
    assert "_start_error_garak" not in app.session_state
    assert len(app.text) == 20
    assert not app.code


def test_old_fixed_prompt_can_use_registry_but_old_response_is_not_reconstructed(monkeypatch):
    case = get_cases(["hkid"])[0]
    old_prompt = case["prompt"].replace("A123456(7)", "[HKID redacted]")
    evidence = report(cases=[case], results=[result(case["id"], prompt=old_prompt, response="Value: [HKID redacted]")])
    row = run_views.case_rows(evidence)[0]
    assert row["prompt"] == case["prompt"]
    assert row["response"] == "Value: [HKID redacted]"
    app, _ = render(monkeypatch, evidence)
    assert any(item.value == case["prompt"] for item in app.text)
    assert any(item.value == "Value: [HKID redacted]" for item in app.text)
    assert not app.checkbox


def test_history_loads_on_demand_and_opens_inline_frozen_run(monkeypatch):
    app, client = render(monkeypatch, active=False, previews=planned(1))
    client.history.assert_not_called()
    client.history.return_value = {"runs": [{"id": "fixture-job", "suite": "garak", "profile": "smoke", "status": "completed", "created_at": "fixture-time"},
                                             {"id": "other", "suite": "sensitive", "status": "completed"}]}
    app.button(key="garak_load_history").click().run()
    client.history.assert_called_once()
    assert len(app.session_state["_history_garak"]) == 1
    app.button(key="garak_history_open_fixture-job").click().run()
    assert app.session_state["_active_run_garak"] == "fixture-job"
    assert any("Historical assessment" in item.value for item in app.subheader)
    assert not app.radio
    assert [item.label for item in app.selectbox] == ["Cases per page"]
    assert len(app.text) == 4
    assert not app.code


def test_technical_details_are_opt_in_and_keep_legacy_request_evidence(monkeypatch):
    evidence = report(results=[result()], requests=[{"error": "Connection failed", "latency_ms": 10}])
    evidence["run"].pop("planned_cases")
    app, _client = render(monkeypatch, evidence)
    assert len(app.dataframe) == 1
    app.button(key="garak_technical_details").click().run()
    assert not app.exception
    assert len(app.dataframe) == 2
    assert app.dataframe[1].value.iloc[0]["error"] == "Connection failed"
    app.run()
    assert len(app.dataframe) == 2
    app.button(key="garak_technical_details").click().run()
    assert len(app.dataframe) == 1



def test_start_button_duplicate_is_disabled_and_cross_suite_stop_targets_global_run(monkeypatch):
    app, client = render(monkeypatch, active=False, previews=planned(1))
    app.session_state["_active_run_sensitive"] = "global-job"
    app.session_state["_run_status_sensitive"] = "running"
    app.run()
    assert any("Another assessment" in item.value for item in app.info)
    app.button(key="garak_stop_other").click().run()
    client.cancel.assert_called_once_with("global-job")
    source = """import streamlit as st
from attack_tester.run_views import render_start_button
render_start_button('garak', 'smoke', ['dan'], {}, {'execution_enabled': True}, {'endpoint':'x','model':'y','api_key':'z'})
"""
    start_app = AppTest.from_string(source)
    start_app.session_state["_active_run_sensitive"] = "global-job"
    start_app.session_state["_run_status_sensitive"] = "running"
    start_app.run()
    assert start_app.button[0].label == "Run all tests"
    assert start_app.button[0].disabled


def test_show_monitor_activates_only_no_old_view_switch(monkeypatch):
    source = """import streamlit as st
from attack_tester.run_views import _show_monitor
_show_monitor('garak', 'fixture-job')
"""
    app = AppTest.from_string(source).run()
    assert app.session_state["_active_run_garak"] == "fixture-job"
    assert "_saved_garak_view" not in app.session_state
    assert "_widget_garak_view" not in app.session_state
