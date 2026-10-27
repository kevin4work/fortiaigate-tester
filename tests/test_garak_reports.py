import json

from runner.reports import NativeReport, redact, summary


def attempt(identifier="attempt-a", status=2, scores=None, outputs=None):
    return {"entry_type": "attempt", "uuid": identifier, "status": status, "probe_classname": "fixture.Probe",
            "prompt": {"turns": [{"role": "user", "content": {"text": "prompt"}}]},
            "outputs": outputs if outputs is not None else [{"text": "output"}],
            "detector_results": scores if scores is not None else {"a": [1], "b": [0]}}


def test_native_nested_records_dedup_and_partial_lines():
    parser = NativeReport()
    parser.feed(json.dumps({"entry_type": "init", "run": "run"}) + "\n")
    parser.feed(json.dumps(attempt(status=1, scores={})) + "\n")
    line = json.dumps(attempt()) + "\n"
    parser.feed(line[:30])
    assert parser.attempts["attempt-a"]["status"] == 1
    parser.feed(line[30:])
    parser.feed(json.dumps(attempt(status=1, scores={})) + "\n")
    rows = parser.rows({"fixture.Probe": ["a", "b"]})
    assert len(rows) == 1 and rows[0]["outcome"] == "flagged"
    assert rows[0]["prompt"] == "user: prompt"
    parser.feed(json.dumps({"entry_type": "completion", "run": "wrong"}) + "\n")
    assert not parser.verified(True, 1, 1)
    parser.feed(json.dumps({"entry_type": "completion", "run": "run"}) + "\n")
    assert parser.verified(True, 1, 1)
    assert not parser.verified(True, 1, 1, ["other.Probe"], 1)
    assert not parser.verified(True, 1, 1, ["fixture.Probe"], 2)
    assert not parser.verified(False, 1, 1)
    assert not parser.verified(True, 2, 1)


def test_absent_completion_hitlog_and_incomplete_attempt():
    parser = NativeReport()
    parser.feed(json.dumps({"entry_type": "init", "run": "run"}) + "\n")
    parser.feed(json.dumps(attempt(status=1)) + "\n")
    assert not parser.verified(True, 1, 1)
    assert parser.rows({"fixture.Probe": ["a", "b"]})[0]["outcome"] == "unscored"


def test_multi_detectors_correct_denominators_partial_unscored_errors():
    parser = NativeReport()
    records = [attempt("both", scores={"a": [1], "b": [1]}),
               attempt("pass", scores={"a": [0], "b": [0]}),
               attempt("partial", scores={"a": [0], "b": [None]}),
               attempt("error", scores={"a": [0], "b": [0]}, outputs=[None])]
    parser.feed("".join(json.dumps(r) + "\n" for r in records))
    rows = parser.rows({"fixture.Probe": ["a", "b"]})
    rows[-1]["error"] = "transport_error"
    metrics = summary(rows, [{"error": None, "gateway_outcome": "confirmed_block"},
                             {"error": None, "gateway_outcome": "allowed"},
                             {"error": "timeout", "gateway_outcome": "unknown"}])
    assert metrics["requests"] == 3 and metrics["request_errors"] == 1
    assert metrics["scored"] == 3 and metrics["flagged"] == 1 and metrics["not_flagged"] == 1
    assert metrics["unscored"] == 2
    assert metrics["confirmed_blocks"] == 1 and metrics["known_gateway_outcomes"] == 2
    assert metrics["per_detector"] == [{"name": "a", "scored": 3, "flagged": 1}, {"name": "b", "scored": 2, "flagged": 1}]


def test_summary_excludes_gateway_blocks_from_detector_denominators():
    parser = NativeReport()
    parser.feed(json.dumps(attempt("model", scores={"a": [0], "b": [1]})) + "\n")
    parser.feed(json.dumps(attempt("gateway", scores={"a": [1], "b": [1]})) + "\n")
    rows = parser.rows({"fixture.Probe": ["a", "b"]})
    rows[1].update(response="Request blocked by FortiAIGate", gateway_outcome="confirmed_block", outcome="unscored")
    metrics = summary(rows, [{"error": None, "gateway_outcome": "unknown"},
                             {"error": None, "gateway_outcome": "confirmed_block"}])
    assert metrics["outputs"] == 2 and metrics["scored"] == metrics["flagged"] == metrics["unscored"] == 1
    assert metrics["confirmed_blocks"] == metrics["known_gateway_outcomes"] == metrics["unknown_gateway_outcomes"] == 1
    assert metrics["per_detector"] == [{"name": "a", "scored": 1, "flagged": 0}, {"name": "b", "scored": 1, "flagged": 1}]


def test_nested_conversation_output_fallback_and_nan():
    record = attempt(scores={"a": [float("nan")], "b": [None]})
    record.pop("outputs")
    record["conversations"] = [{"turns": [{"role": "user", "content": {"text": "prompt"}},
                                           {"role": "assistant", "content": {"text": "reply"}}]}]
    parser = NativeReport()
    parser.feed(json.dumps(record) + "\n")
    row = parser.rows({"fixture.Probe": ["a", "b"]})[0]
    assert row["response"] == "reply" and row["outcome"] == "unscored"


def test_numeric_uuid_tail_survives_native_redaction_and_correlation(tmp_path):
    from runner.reports import RedactedWriter
    identifier = "425afa31-22f5-484b-8505-155250637228"
    path = tmp_path / "native.jsonl"
    with path.open("w") as stream:
        # Garak emits init before the redacted writer is installed.
        stream.write(json.dumps({"entry_type": "init", "run": identifier}) + "\n")
        writer = RedactedWriter(stream, "fake-test-credential")
        writer.write(json.dumps(attempt(identifier=identifier, status=1, scores={})) + "\n")
        writer.write(json.dumps(attempt(identifier=identifier)) + "\n")
        writer.write(json.dumps({"entry_type": "completion", "run": identifier}) + "\n")
    parser = NativeReport()
    parser.feed(path.read_text())
    assert parser.verified(True, 1, 1, ["fixture.Probe"], 1)
    assert parser.run_id == parser.completion_id == identifier
    assert list(parser.attempts) == [identifier]
    for key in ("run", "uuid", "attempt_id", "logical_id", "id"):
        for value in (identifier, identifier + ":0"):
            assert redact({key: value}, display=True) == {key: value}
        assert redact({key: identifier}, secret=identifier) == {key: "[credential redacted]"}
    assert redact("4111-1111-1111-1111") == "[card redacted]"
    assert redact(identifier, secret=identifier) == "[credential redacted]"


def test_uuid_shaped_content_cannot_bypass_card_redaction():
    counterexample = "a25afa31-22f5-484b-4111-111111111111"
    for key in ("prompt", "response", "request_id", "text"):
        content = redact({key: counterexample}, display=True)[key]
        assert "4111-111111111111" not in content
        assert "[card redacted]" in content
    assert "4111-111111111111" not in redact(counterexample)
    for value in ("prefix " + counterexample, counterexample + " suffix"):
        assert "4111-111111111111" not in redact({"id": value})["id"]


def test_export_redacts_secret_pii_controls_markup_urls():
    payload = {"api_key": "never", "token": "never", "endpoint": "never", "prompt": "A123456(7) 4111 1111 1111 1111", "response": "<img src=https://evil.example/a>\x1b[31m fake-secret Bearer credential"}
    sanitized = redact(payload, "fake-secret", display=True)
    text = json.dumps(sanitized)
    for forbidden in ("fake-secret", "https://evil.example", "<img", "never", "\x1b"):
        assert forbidden not in text


def test_supplied_dummy_values_remain_exact_but_credentials_still_win():
    from common.test_catalog import get_cases, DUMMY_HKIDS, DUMMY_CARD_NUMBERS
    for case in get_cases():
        assert redact(case["prompt"]) == case["prompt"]
        assert redact({"response": case["prompt"]})["response"] == case["prompt"]
    for value in DUMMY_HKIDS | DUMMY_CARD_NUMBERS:
        assert redact(value, secret=value) == "[credential redacted]"
    other = "Z987654(3) 5555 4444 3333 2222"
    assert redact(other) == "[HKID redacted] [card redacted]"


def test_case_progress_retries_final_errors_partial_cancel_and_legacy():
    from runner.reports import case_progress
    plan = [{"case_id": "probe:0"}, {"case_id": "probe:1"}, {"case_id": "probe:2"}, {"case_id": "probe:3"}]
    requests = [{"id": "retry0", "case_id": "probe:0", "error": "rate_limited"},
                {"id": "retry1", "case_id": "probe:0", "error": None},
                {"id": "error", "case_id": "probe:1", "error": "forbidden_unknown"},
                {"id": "flight", "case_id": "probe:2", "error": "in_flight"},
                {"id": "old", "case_id": None, "error": None},
                {"id": "outside", "case_id": "unplanned", "error": None}]
    results = [{"id": "output0", "case_id": "probe:0", "finalized": True, "response": "reply", "error": None},
               {"id": "output0duplicate", "case_id": "probe:0", "finalized": True, "response": "reply", "error": None},
               {"id": "output1", "case_id": "probe:1", "finalized": True, "response": None, "error": "forbidden_unknown"},
               {"id": "partial", "case_id": "probe:2", "finalized": False, "response": None, "error": "in_flight"}]
    active = case_progress(results, requests, plan, active=True)
    assert active == {"planned_case_count": 4, "started_case_count": 3, "finished_case_count": 2, "current_case_id": "probe:2"}
    assert case_progress(results, requests, plan)["current_case_id"] is None
    assert case_progress(results[:-1], requests, plan)["finished_case_count"] == 2
    assert case_progress([], requests, plan)["finished_case_count"] == 0  # Request-only errors are not finalized tests.
    assert case_progress(results, requests, None) == {"planned_case_count": None, "started_case_count": None,
                                                    "finished_case_count": None, "current_case_id": None}
    old = [{"id": "old", "case_id": "probe:0", "response": "reply"}]
    assert case_progress(old, [], plan)["finished_case_count"] == 1
    assert case_progress([{**old[0], "error": "evaluation_interrupted"}], [], plan)["finished_case_count"] == 0


def test_native_case_notes_preserve_duplicate_prompt_correlation_and_finalization():
    records = [attempt("first"), attempt("second"), attempt("partial", status=1)]
    for index, record in enumerate(records):
        record["notes"] = {"case_id": f"fixture.Probe:{index}"}
    parser = NativeReport()
    parser.feed("".join(json.dumps(r) + "\n" for r in records))
    rows = parser.rows({"fixture.Probe": ["a", "b"]})
    assert [r["case_id"] for r in rows] == ["fixture.Probe:0", "fixture.Probe:1", "fixture.Probe:2"]
    assert rows[0]["prompt"] == rows[1]["prompt"]
    assert [r["finalized"] for r in rows] == [True, True, False]
    assert summary(rows, [], planned_cases=[{"case_id": r["case_id"]} for r in rows])["finished_case_count"] == 2
