"""Native Streamlit start, monitor and evidence views shared by both suites."""
import html
import json
import math
import os
import uuid

from common.test_catalog import get_cases, DUMMY_HKIDS, DUMMY_CARD_NUMBERS
from common.gateway_response import response_details

import streamlit as st

from attack_tester.runner_client import (
    RunnerUnavailable,
    get_runner_client,
    missing_configuration,
    saved_configuration,
)


ACTIVE_STATUSES = {"queued", "starting", "running", "cancelling", "cancel_requested"}


STYLE = """<style>
[data-testid="stVerticalBlockBorderWrapper"] {border-color:#30363d; border-radius:8px;}
[data-testid="stRadio"] label {font-size:0.9rem;}
[role="radiogroup"][aria-label="Test profile"],
[role="radiogroup"][aria-label="Coverage profile"] {display:flex; gap:12px; width:100%;}
[data-testid="stElementContainer"]:has(> [data-testid="stRadio"] [role="radiogroup"][aria-label="Coverage profile"]) {width:100%;}
[role="radiogroup"][aria-label="Test profile"] > label,
[role="radiogroup"][aria-label="Coverage profile"] > label {
    flex:1; min-width:120px; padding:16px; margin:0; border:1px solid #30363d;
    border-radius:6px; background:#10151c; align-items:flex-start;
}
[role="radiogroup"][aria-label="Test profile"] > label:has(input:checked),
[role="radiogroup"][aria-label="Coverage profile"] > label:has(input:checked) {
    border-color:#c8453a; background:#261d21;
}
[role="radiogroup"][aria-label="Test profile"] > label:has(input[value="0"])::after {
    content:"HKID + credit cards · 6 fixed cases"; color:#a8b3c2; font-size:12px;
}
[role="radiogroup"][aria-label="Test profile"] > label:has(input[value="1"])::after {
    content:"Choose categories and available probes"; color:#a8b3c2; font-size:12px;
}
[role="radiogroup"][aria-label="Test profile"] > label,
[role="radiogroup"][aria-label="Coverage profile"] > label {flex-wrap:wrap; row-gap:8px;}
[role="radiogroup"][aria-label="Test profile"] > label::after,
[role="radiogroup"][aria-label="Coverage profile"] > label::after {flex-basis:100%; padding-left:26px;}
[role="radiogroup"] > label:has(input:focus-visible) {outline:2px solid #3987e5; outline-offset:3px;}
.st-key-sensitive_categories [data-testid="stVerticalBlock"] {gap:8px;}
.st-key-sensitive_categories [data-testid="stHorizontalBlock"] + [data-testid="stHorizontalBlock"] {border-top:1px solid #30363d; padding-top:12px;}
@media(max-width:640px) {
    [role="radiogroup"][aria-label="Coverage profile"] {flex-wrap:wrap;}
}
[data-testid="stCheckbox"]:has(input:disabled) {opacity:.5; filter:grayscale(1);}
[data-testid="stCheckbox"]:has(input:disabled) label {cursor:not-allowed;}
[data-testid="stMetricValue"] {font-size:1.8rem;}
[data-testid="stCode"] {border:1px solid #30363d; border-radius:6px;}
[class*="st-key-fag_pager"] [data-testid="stHorizontalBlock"] {justify-content:space-between;}
[class*="st-key-fag_pager"] [data-testid="stHorizontalBlock"] > div {flex:0 0 auto !important; width:auto !important;}
[class*="st-key-fag_pager"] [data-testid="stSelectbox"], [class*="st-key-fag_pager"] [data-testid="stSelectbox"] > div {width:88px; min-width:88px;}
[class*="st-key-fag_pager"] .stButton button {min-width:32px; height:32px; padding:0 9px; font-size:12px; border-radius:6px;}
[class*="st-key-fag_pager"] [data-testid="stBaseButton-primary"],
[class*="st-key-fag_pager"] [data-testid="stBaseButton-primary"]:hover {background:#2c1c20; border-color:#67302b; color:#f0f3f6; box-shadow:none;}
[class*="st-key-fag_pager"] p {margin:0;}
[class*="st-key-fag_pager"] [data-testid="stCaptionContainer"] p {white-space:nowrap;}
[class*="st-key-fag_pager"] [data-testid="stSelectbox"] {min-width:72px;}
@media(max-width:640px) {
    [class*="st-key-fag_pager"] [data-testid="stHorizontalBlock"] {flex-wrap:wrap; row-gap:8px;}
    [class*="st-key-fag_pager"] .stButton button {min-width:26px; height:28px; padding:0 6px; font-size:11px;}
    [class*="st-key-fag_pager"] [data-testid="stCaptionContainer"] {font-size:10px;}
}
.fag-eyebrow {color:#8b98a9; text-transform:uppercase; font-size:11px; letter-spacing:1.6px; margin-bottom:6px;}
.fag-description {color:#a8b3c2; font-size:14px; margin-bottom:24px;}
</style>"""


def apply_page_style():
    st.markdown(STYLE, unsafe_allow_html=True)


def safe_text(value):
    """Redact configured credentials before displaying any runner-supplied string."""
    text = str(value if value is not None else "Not reported")
    for secret in (st.session_state.get("saved_api_key", ""),
                   os.environ.get("FORTIAIGATE_RUNNER_TOKEN", "")):
        if secret:
            text = text.replace(str(secret), "[credential redacted]")
    return text


def safe_data(value):
    if isinstance(value, dict):
        return {
            safe_text(key): safe_data(item)
            for key, item in value.items()
            if str(key).lower() not in {"api_key", "authorization", "token", "service_token"}
        }
    if isinstance(value, list):
        return [safe_data(item) for item in value]
    return safe_text(value) if isinstance(value, str) else value


def persistent_radio(label, options, name, default, **kwargs):
    """Keep a separate value because Streamlit cleans widgets on page navigation."""
    saved_key, widget_key = "_saved_" + name, "_widget_" + name
    value = st.session_state.get(saved_key, default)
    if value not in options:
        value = default
    if widget_key not in st.session_state:
        st.session_state[widget_key] = value

    def changed():
        st.session_state[saved_key] = st.session_state[widget_key]

    return st.radio(label, options, key=widget_key, on_change=changed, **kwargs)


def runner_context():
    """Read-only readiness calls. These never dispatch target requests."""
    try:
        client = get_runner_client()
        health = client.health()
        catalog = client.catalog()
    except RunnerUnavailable as exc:
        return None, {}, {}, str(exc)
    return client, health, catalog, None


def catalog_records(catalog, section):
    return {item["id"]: item for item in catalog.get(section, []) if isinstance(item, dict) and "id" in item}


def available(record):
    return record.get("available") is True


def execution_gate(health, configuration, runner_error=None, scope_error=None):
    if runner_error:
        return runner_error
    if missing_configuration(configuration):
        return "Execution is not ready. Save the endpoint, model and API key in Configuration. Previews remain available."
    if health.get("execution_enabled") is not True:
        return "Runner execution is disabled. Ask the operator to enable the private service after reviewing its policy."
    return scope_error


def readiness_notice(health, configuration, runner_error=None, scope_error=None):
    reason = execution_gate(health, configuration, runner_error, scope_error)
    if reason:
        st.warning(safe_text(reason))
    else:
        st.caption("Ready. Click Run all tests to run the selected tests.")
    return reason


def _show_monitor(suite, run_id):
    st.session_state["_active_run_" + suite] = run_id
    st.session_state["_run_status_" + suite] = "queued"
    st.session_state.pop("_historical_run_" + suite, None)


def _running_suite():
    for suite in ("sensitive", "garak"):
        if _run_id(suite) and st.session_state.get("_run_status_" + suite) in ACTIVE_STATUSES:
            return suite
    return None


def start_assessment(suite, profile, selection, limits, scope_error=None):
    """Only an explicit button click dispatches; ambiguous retries reuse their key."""
    client, health, _catalog, error = runner_context()
    configuration = saved_configuration(st.session_state)
    reason = execution_gate(health, configuration, error, scope_error)
    error_key = "_start_error_" + suite
    if reason:
        st.session_state[error_key] = reason
        return
    payload = {
        "suite": suite,
        "profile": profile,
        "configuration": configuration,
        "selection": list(selection),
        "limits": dict(limits),
        "cases": [],
    }
    pending_key = "_pending_start_" + suite
    pending = st.session_state.get(pending_key)
    if not pending or pending["payload"] != payload:
        pending = {"payload": payload, "idempotency_key": str(uuid.uuid4())}
        st.session_state[pending_key] = pending
    try:
        for known_suite in (suite, "garak" if suite == "sensitive" else "sensitive"):
            active_id = _run_id(known_suite)
            if active_id:
                status = client.status(active_id).get("status")
                st.session_state["_run_status_" + known_suite] = status
                if status in ACTIVE_STATUSES:
                    st.session_state[error_key] = "An assessment is already running. Stop it or wait before starting another."
                    return
        run = client.start(dict(payload, idempotency_key=pending["idempotency_key"]))
        if not run.get("id") or not run.get("status"):
            raise RunnerUnavailable("The runner did not confirm a job. Retry with the same settings or check History.")
    except RunnerUnavailable as exc:
        st.session_state[error_key] = str(exc)
    else:
        st.session_state.pop(pending_key, None)
        st.session_state.pop(error_key, None)
        _show_monitor(suite, run["id"])


def render_start_button(suite, profile, selection, limits, health, configuration,
                        runner_error=None, scope_error=None):
    reason = execution_gate(health, configuration, runner_error, scope_error)
    st.button("Run all tests", key="_" + suite + "_start", type="primary",
              disabled=bool(reason) or bool(_running_suite()), on_click=start_assessment,
              args=(suite, profile, list(selection), dict(limits), scope_error),
              use_container_width=True)
    if st.session_state.get("_start_error_" + suite):
        st.error(safe_text(st.session_state["_start_error_" + suite]))
        st.caption("No successful start is assumed. Retry unchanged settings to reuse the same request; check History before changing scope.")


def _run_id(suite):
    return st.session_state.get("_active_run_" + suite)


def detector_evaluation(record):
    detectors = record.get("detectors") or []
    scores = [item for item in detectors if isinstance(item, dict)
              and isinstance(item.get("score"), (int, float))
              and not isinstance(item.get("score"), bool) and math.isfinite(item["score"])
              and isinstance(item.get("flagged"), bool)]
    complete = (bool(detectors) and len(scores) == len(detectors)
                and not record.get("error") and record.get("finalized") is not False
                and record.get("outcome") in {"flagged", "not_flagged"})
    if any(item["flagged"] for item in scores):
        return "Flagged" if complete else "Flagged · incomplete evaluation"
    return "Not flagged" if complete and record.get("outcome") == "not_flagged" else "Unscored"


def _finalized(record):
    return bool(record) and record.get("finalized") is not False and record.get("error") not in {
        "in_flight", "evaluation_interrupted",
    }


def _technique(case):
    return (case.get("family_title") or case.get("technique")
            or {"hkid": "HKID", "cards": "Credit cards", "dan": "Instruction override / jailbreak",
                "apikey": "API-key disclosure",
                "leakreplay": "Known-text replay", "promptinject": "Prompt injection",
                "malwaregen": "Malware / code policy",
                "donotanswer": "Malicious requests"}.get(case.get("family") or case.get("group"))
            or "Other evidence")


def _case_title(case):
    """Keep catalog metadata intact while giving native prompt cards readable titles."""
    probe = str(case.get("probe") or "")
    if not probe:
        return case.get("title") or "Prompt"
    family = case.get("family") or probe.split(".", 1)[0]
    index = case.get("source_index", case.get("manifest_index"))
    if index is None:
        suffix = str(case.get("case_id") or case.get("id") or "").rsplit(":", 1)[-1]
        index = int(suffix) if suffix.isdigit() else None
    number = " {}".format(index + 1) if isinstance(index, int) else ""
    if family == "dan":
        return "Jailbreak — DAN 11" if probe.endswith("Dan_11_0") else "Jailbreak" + number
    title = {"apikey": "API-key disclosure",
             "leakreplay": "Known-text replay", "promptinject": "Prompt injection",
             "malwaregen": "Malware / code request",
             "donotanswer": "Malicious request"}.get(family)
    return title + number if title else case.get("title") or "Prompt" + number


def case_rows(report, preview_cases=()):
    """Join only stable IDs; prompt text and request retry counts never identify cases."""
    run = report.get("run") or {}
    preview = not bool(run)
    plan = list(preview_cases) if preview else run.get("planned_cases")
    known_scope = isinstance(plan, list)
    records = {}
    for index, record in enumerate(report.get("results") or []):
        key = record.get("case_id") or "record:" + str(record.get("id") or index)
        if key not in records or _finalized(record) or not _finalized(records[key]):
            records[key] = record
    requests = {}
    for request in report.get("requests") or []:
        if request.get("case_id"):
            requests[request["case_id"]] = request
    cases = []
    seen = set()
    for case in plan or []:
        key = case.get("case_id") or case.get("id")
        if key and key not in seen:
            cases.append((key, case, True))
            seen.add(key)
    for key, record in records.items():
        if key not in seen:
            cases.append((key, record, not known_scope))
    active = run.get("status") in ACTIVE_STATUSES
    current = (report.get("summary") or run.get("summary") or {}).get("current_case_id")
    rows = []
    fixed_prompts = {case["id"]: case["prompt"] for case in get_cases()}
    for key, case, in_scope in cases:
        record, request = records.get(key, {}), requests.get(key, {})
        finished = _finalized(record)
        error = record.get("error") if finished else record.get("error") or request.get("error")
        if error == "in_flight" or (active and not finished):
            error = None
        response = record.get("response")
        authoritative_reply = finished and (record.get("response") is not None or record.get("raw_response") is not None)
        if response is None and not authoritative_reply and request.get("error") != "in_flight":
            response = request.get("response")
        raw_response = record.get("raw_response")
        if raw_response is None and not authoritative_reply:
            raw_response = request.get("raw_response")
        # API evidence is HTML-escaped for transport; decode before extracting only
        # chatbot-visible fields. Render as inert text below, never as HTML.
        details = response_details(html.unescape(raw_response) if isinstance(raw_response, str) else None,
                                   html.unescape(response) if isinstance(response, str) else response)
        displayed_response = details["text"]
        status_code = record.get("status_code", request.get("status_code"))
        truncated = record.get("response_truncated", request.get("response_truncated", False))
        signature_block = (details["blocked"] and not truncated
                           and status_code in (None, 200, 403)
                           and error in (None, "forbidden_unknown"))
        prompt = record.get("prompt")
        if prompt is None:
            prompt = request.get("prompt") if request.get("prompt") is not None else case.get("prompt", "")
        # Older reports masked fixture inputs before storage. Restore only an
        # exact trusted fixture representation, never guess a response value.
        if key in fixed_prompts and isinstance(prompt, str):
            original = fixed_prompts[key]
            masked = original
            for value in DUMMY_HKIDS:
                masked = masked.replace(value, "[HKID redacted]")
            for value in DUMMY_CARD_NUMBERS:
                masked = masked.replace(value, "[card redacted]")
            if html.unescape(prompt) in (masked, "user: " + masked):
                prompt = original
        latency = record.get("latency_ms")
        if not finished:
            latency = None
            if displayed_response is not None and request.get("error") != "in_flight":
                latency = record.get("latency_ms") if record.get("response") is not None or record.get("raw_response") is not None else request.get("latency_ms")
        gateway = record.get("gateway_outcome")
        if gateway not in {"allowed", "confirmed_block"} and not authoritative_reply:
            gateway = request.get("gateway_outcome") or gateway
        if signature_block:
            gateway = "confirmed_block"
            error = None
        outcome = None
        if finished:
            if error:
                outcome = "Error"
            elif gateway == "confirmed_block":
                outcome = "Blocked"
            elif displayed_response is not None:
                outcome = "Through"
            else:
                outcome = "Error"
                error = ("Output-token limit reached before a final reply" if details["finish_reason"] == "length"
                         else "No chatbot reply returned")
        elif not active and error:
            outcome = "Error"
        if outcome:
            status = outcome
        elif active and (key == current or request.get("error") == "in_flight"):
            status = "Sending"
        else:
            status = "Not tested" if preview else ("Pending" if active and not record and not request else "Not completed")
        rows.append({
            "case_id": key, "title": _case_title(case),
            "technique": _technique(case), "prompt": prompt,
            "is_template": bool(case.get("is_template")) and not bool(record) and not bool(request),
            "status": status, "outcome": outcome, "sent": bool(request) or bool(record),
            "finalized": finished, "in_scope": in_scope,
            "response": displayed_response, "raw_response": raw_response,
            "reply_source": details["source"], "finish_reason": details["finish_reason"],
            "block_checked": finished and displayed_response is not None and not error and not truncated
                             and status_code in (None, 200, 403),
            "status_code": status_code,
            "content_type": record.get("content_type", request.get("content_type")),
            "response_format": record.get("response_format", request.get("response_format")),
            "response_truncated": record.get("response_truncated", request.get("response_truncated", False)),
            "error": error, "gateway_outcome": gateway, "latency_ms": latency,
            "evaluation": "Unscored" if gateway == "confirmed_block" else detector_evaluation(record),
            "record": record, "request": request,
        })
    return rows


def assessment_metrics(rows, planned_count=None):
    rows = [row for row in rows if row["in_scope"]]
    finished = [row for row in rows if row["finalized"]]
    tested = [row for row in rows if row["outcome"] in {"Blocked", "Through", "Error"}]
    measured = [row["latency_ms"] for row in finished
                if row["outcome"] in {"Blocked", "Through"}
                and isinstance(row["latency_ms"], (int, float)) and not isinstance(row["latency_ms"], bool)
                and math.isfinite(row["latency_ms"]) and row["latency_ms"] >= 0]
    blocks = sum(row["outcome"] == "Blocked" for row in tested)
    through = sum(row["outcome"] == "Through" for row in tested)
    classifiable = blocks + through
    return {"sent": sum(bool(row["sent"]) for row in rows), "finished": len(finished),
            "tested": len(tested), "planned": planned_count,
            "blocks": blocks, "through": through,
            "errors": sum(row["outcome"] == "Error" for row in tested),
            "block_rate": blocks / classifiable if classifiable else None,
            "average_ms": sum(measured) / len(measured) if measured else None,
            "latency_samples": len(measured)}


def _duration(milliseconds):
    if milliseconds is None:
        return "—"
    return "{:.0f} ms".format(milliseconds) if milliseconds < 1000 else "{:.2f} s".format(milliseconds / 1000)


def _percentage(value):
    return "—" if value is None else "{:.1f}%".format(value * 100)


def technique_rows(rows):
    groups = {}
    for row in rows:
        if row["in_scope"]:
            groups.setdefault(row["technique"], []).append(row)
    table = []
    for technique, cases in groups.items():
        metrics = assessment_metrics(cases)
        table.append({"Technique": technique, "Total tested": metrics["tested"],
                      "Blocked": metrics["blocks"], "Through": metrics["through"], "Errors": metrics["errors"],
                      "Block rate": _percentage(metrics["block_rate"]),
                      "Avg API response time": _duration(metrics["average_ms"])})
    return table


def _new_assessment(suite):
    for prefix in ("_active_run_", "_run_status_", "_pending_start_", "_start_error_",
                   "_cancel_requested_", "_historical_run_"):
        st.session_state.pop(prefix + suite, None)
    for key in list(st.session_state):
        if key.startswith("_assessment_" + suite + "_"):
            st.session_state.pop(key, None)


def _stop(suite, run_id):
    try:
        get_runner_client().cancel(run_id)
    except RunnerUnavailable as exc:
        st.error(safe_text(exc))
    else:
        st.session_state["_cancel_requested_" + suite] = run_id
        st.session_state["_run_status_" + suite] = "cancelling"
        st.rerun()


def _case_card(row, server_evidence=False):
    with st.container(border=True):
        st.caption(safe_text(row["title"]))
        prompt = html.unescape(str(row["prompt"])) if server_evidence else row["prompt"]
        # Stored evidence joins role-tagged lines ("user: ..."). Show the test
        # prompt itself; other roles' lines (system/context) stay labelled.
        if isinstance(prompt, str) and prompt.startswith("user: "):
            prompt = prompt[len("user: "):]
        prompt = safe_text(prompt)
        st.caption("Prompt")
        # Native plain-text elements match Prompt Injection without rendering model HTML.
        first = prompt.split("\n", 1)[0]
        preview = first if len(first) <= 160 else first[:160] + "…"
        long_prompt = prompt != preview
        toggle_key = "_prompt_full_" + str(row["case_id"])
        st.text(prompt if long_prompt and st.session_state.get(toggle_key) else preview)
        if row["is_template"]:
            st.caption("Template preview; the dispatched prompt appears after sending.")
        if long_prompt:
            st.button("Hide full prompt" if st.session_state.get(toggle_key) else "Show full prompt",
                      key=toggle_key + "_btn", type="tertiary",
                      on_click=_toggle_prompt, args=(toggle_key,))
        colors = {"Blocked": "green", "Through": "red", "Error": "orange"}
        if row["outcome"] in colors:
            st.markdown(":{}-badge[{}] · {}".format(colors[row["outcome"]], row["outcome"], _duration(row["latency_ms"])))
        elif row["status"] == "Sending":
            st.caption("Sending request...")
        else:
            captions = {"Not tested": "Not yet tested — click Run all tests", "Pending": "Waiting to be sent"}
            st.caption(captions.get(row["status"], "Not completed"))
        if row["response"] is not None:
            with st.expander("View response", icon=":material/visibility:"):
                st.text(safe_text(row["response"]))
                if row["evaluation"].startswith("Flagged"):
                    st.caption("Flagged response — review" + (" · incomplete evaluation" if "incomplete" in row["evaluation"] else ""))
        if row["error"]:
            st.text("Error: " + safe_text(row["error"]))
        if row.get("reply_source") == "reasoning_only":
            st.caption("No final chatbot reply was returned; internal reasoning is not displayed.")
            if row.get("finish_reason") == "length":
                st.caption("The model reached its output-token limit before producing a final reply.")
        elif row["response"] is None and row.get("raw_response") is not None:
            st.caption("The full response is available in Technical details.")


def _assessment_body(suite, report, preview_cases=()):
    run = report.get("run") or {}
    active = run.get("status") in ACTIVE_STATUSES
    if run:
        st.session_state["_run_status_" + suite] = run.get("status")
        label = "Historical assessment" if st.session_state.get("_historical_run_" + suite) == run.get("id") else "Assessment"
        st.subheader(label + " · " + safe_text(run.get("status")))
        if active:
            if st.button("Stop", key=suite + "_cancel", disabled=run.get("status") in {"cancelling", "cancel_requested"}):
                _stop(suite, run.get("id", _run_id(suite)))
        else:
            st.button("New assessment", key=suite + "_new_assessment", on_click=_new_assessment, args=(suite,))
        if active and st.session_state.get("_cancel_requested_" + suite) == run.get("id"):
            st.caption("Stop requested. An already-issued request cannot be recalled; wait for terminal status.")
    else:
        other = _running_suite()
        if other and other != suite:
            st.info("Another assessment is running. Open " + ("Sensitive Data" if other == "sensitive" else "Garak") + " for its progress.")
            if st.button("Stop active assessment", key=suite + "_stop_other"):
                _stop(other, _run_id(other))
    rows = [row for row in case_rows(report, preview_cases) if row["in_scope"]]
    plan = run.get("planned_cases") if run else list(preview_cases)
    planned = len({case.get("case_id") or case.get("id") for case in plan}) if isinstance(plan, list) else None
    metrics = assessment_metrics(rows, planned)
    summary = report.get("summary") or run.get("summary") or {}
    current = next((row for row in rows if row["status"] == "Sending"), None)
    if active and current:
        progress = "Sending {}/{}: {}".format(metrics["sent"], planned if planned is not None else "?", current["technique"])
    else:
        progress = ("{} of {} tests sent".format(metrics["sent"], planned) if planned is not None
                    else "{} tests sent · total scope unknown".format(metrics["sent"]))
    if planned:
        st.progress(min(metrics["sent"] / planned, 1.0), text=progress)
    else:
        st.text(progress)
    if active and planned and metrics["sent"] == planned and metrics["tested"] < planned:
        st.caption("All tests sent — waiting for the remaining responses.")
    if run:
        elapsed = summary.get("elapsed_seconds")
        st.caption("Elapsed: " + ("{:.1f} s".format(elapsed) if isinstance(elapsed, (int, float)) else "—"))
        if planned is None:
            st.caption("This older run has no frozen case plan. Only available evidence is shown; total coverage is unknown.")
        if run.get("error"):
            st.error(safe_text(run["error"]))
        if not active and summary.get("completion_verified") is not True:
            st.caption("Completion not verified. Partial, stopped or unscored work is not a pass.")
        elif not active:
            st.caption("All finished does not mean all passed; review the individual evidence.")
    if run:
        with st.expander("Summary", expanded=True):
            tiles = st.columns(6)
            values = (str(metrics["tested"]), str(metrics["blocks"]), str(metrics["through"]),
                      str(metrics["errors"]), _percentage(metrics["block_rate"]),
                      _duration(metrics["average_ms"]))
            for tile, label, value in zip(tiles, ("Total tested", "Blocked", "Through", "Errors", "Block rate", "Avg response time"), values):
                tile.metric(label, value, border=True)
        st.caption('Block rate = Blocked ÷ (Blocked + Through); Errors are excluded because their gateway outcome is unknown. Blocked = “blocked by FortiAIGate” (case-insensitive). Through does not mean a successful attack.')
        st.caption("Average covers {} measured Blocked/Through replies, including gateway and upstream time; retry waits and errors are excluded.".format(metrics["latency_samples"]))
        st.caption("Average covers {} measured Blocked/Through replies, including gateway and upstream time; retry waits and errors are excluded.".format(metrics["latency_samples"]))
    if not rows:
        st.info("No cases or evidence available. No successful tests are assumed.")
        return
    if run:
        st.subheader("By technique")
        st.dataframe(safe_data(technique_rows(rows)), hide_index=True, use_container_width=True)
    st.subheader("Test cases")
    scope = str(run.get("id") or "preview_" + uuid.uuid5(uuid.NAMESPACE_URL, "|".join(str(row["case_id"]) for row in rows)).hex[:12])
    page_key = "_assessment_" + suite + "_page_" + scope
    size_key = "_assessment_" + suite + "_pagesize_" + scope
    if page_key not in st.session_state:
        st.session_state[page_key] = 1
    if size_key not in st.session_state:
        st.session_state[size_key] = 20
    page_size = int(st.session_state[size_key])
    pages = max(1, -(-len(rows) // page_size))
    page = min(max(1, st.session_state[page_key]), pages)
    st.session_state[page_key] = page
    start = (page - 1) * page_size
    visible = rows[start:start + page_size]
    # Pagination row above the list: natural-width controls, right-aligned, no column squeeze.
    window = _page_window(page, pages)
    with st.container(key="fag_pager_" + suite):
        row = st.container(horizontal=True, vertical_alignment="center")
        left = row.container(horizontal=True, vertical_alignment="center")
        right = row.container(horizontal=True, vertical_alignment="center")
        left.button("‹", key=suite + "_prev_page_" + scope, disabled=page <= 1,
                    on_click=_step_page, args=(page_key, -1))
        for item in window:
            if item == "gap":
                left.caption("…")
            else:
                left.button(str(item), key=suite + "_page_{}_{}".format(item, scope),
                            type="primary" if item == page else "secondary",
                            on_click=_goto_page, args=(page_key, item))
        left.button("›", key=suite + "_next_page_" + scope, disabled=page >= pages,
                    on_click=_step_page, args=(page_key, 1))
        right.caption("Cases per page")
        right.selectbox("Cases per page", [10, 20, 50], key=size_key, label_visibility="collapsed",
                        on_change=_reset_page, args=(page_key,))
        right.caption("{}–{} of {} cases".format(start + 1, min(len(rows), start + page_size), len(rows)))
    groups = {}
    for row in visible:
        groups.setdefault(row["technique"], []).append(row)
    for technique, cases in groups.items():
        with st.container(border=True):
            st.subheader(safe_text(technique))
            for row in cases:
                _case_card(row, server_evidence=bool(run))


def _step_page(page_key, delta):
    st.session_state[page_key] = st.session_state.get(page_key, 1) + delta


def _goto_page(page_key, page):
    st.session_state[page_key] = page


def _toggle_prompt(toggle_key):
    st.session_state[toggle_key] = not st.session_state.get(toggle_key, False)


def _reset_page(page_key):
    st.session_state[page_key] = 1


def _page_window(page, pages):
    """First, last and current ±1; skipped ranges collapse to one gap marker."""
    keep = {1, pages, page - 1, page, page + 1}
    out, last = [], 0
    for i in range(1, pages + 1):
        if i not in keep:
            continue
        if last and i - last > 1:
            out.append("gap")
        out.append(i)
        last = i
    return out


def _technical_details(report):
    st.code(json.dumps(safe_data(report.get("summary") or {}), ensure_ascii=False, indent=2), language="json")
    run = report.get("run") or {}
    snapshot = {key: run[key] for key in ("id", "suite", "profile", "selection", "limits", "created_at", "started_at", "finished_at") if key in run}
    st.code(json.dumps(safe_data(snapshot), ensure_ascii=False, indent=2), language="json")
    requests = [{key: request.get(key) for key in ("case_id", "probe", "error", "latency_ms", "gateway_outcome", "status_code", "content_type")}
                for request in report.get("requests") or []]
    if requests:
        st.caption("HTTP request evidence includes retries and unfinished work; these are not finished-test counts.")
        st.dataframe(safe_data(requests), hide_index=True, use_container_width=True)
    raw_records = report.get("requests") or report.get("results") or []
    for index, record in enumerate(raw_records):
        if record.get("raw_response") is not None:
            label = "Raw response {} · {}".format(index + 1, safe_text(record.get("case_id") or "request"))
            with st.expander(label):
                st.caption("HTTP {} · {}".format(record.get("status_code"), safe_text(record.get("content_type") or "unknown content type")))
                raw = html.unescape(record["raw_response"])
                st.code(safe_text(raw) if raw else "[Empty response body]", language=None, wrap_lines=True)
                if record.get("response_truncated"):
                    st.caption("Capture truncated at the response-size limit.")
    unassociated = [row for row in case_rows(report) if not row["in_scope"]]
    if unassociated:
        st.caption("Unassociated evidence is outside the frozen plan and excluded from test counts.")
        for row in unassociated:
            _case_card(row, server_evidence=True)
    scores = [{"Case": record.get("case_id") or record.get("id"), "Detector": detector.get("name"),
               "Score": detector.get("score"), "Threshold": detector.get("threshold"),
               "Flagged": detector.get("flagged"), "Evaluation": detector_evaluation(record)}
              for record in report.get("results") or [] for detector in record.get("detectors") or [] if isinstance(detector, dict)]
    if scores:
        st.dataframe(safe_data(scores), hide_index=True, use_container_width=True)


def render_history(suite):
    if st.button("Load run history", key=suite + "_load_history"):
        try:
            data = get_runner_client().history()
        except RunnerUnavailable as exc:
            st.warning(safe_text(exc))
        else:
            st.session_state["_history_" + suite] = [run for run in data.get("runs", []) if run.get("suite") == suite]
    runs = st.session_state.get("_history_" + suite)
    if runs is None:
        return
    if not runs:
        st.caption("No runs in this session. History is not shared with other operator sessions.")
        return
    for run in runs:
        st.text(safe_text(run.get("profile")) + " · " + safe_text(run.get("status")) + " · " + safe_text(run.get("created_at")))
        if st.button("Open assessment", key=suite + "_history_open_" + str(run["id"])):
            st.session_state["_active_run_" + suite] = run["id"]
            st.session_state["_run_status_" + suite] = run.get("status")
            st.session_state["_historical_run_" + suite] = run["id"]
            st.rerun()


def _secondary(suite, report):
    if report.get("run"):
        with st.expander("Technical details"):
            details_key = "_assessment_" + suite + "_details_" + str(_run_id(suite))
            if st.button("Hide technical details" if st.session_state.get(details_key) else "Show technical details", key=suite + "_technical_details"):
                st.session_state[details_key] = not st.session_state.get(details_key, False)
            if st.session_state.get(details_key):
                _technical_details(report)
    with st.expander("History"):
        render_history(suite)


def _load_assessment(suite):
    try:
        report = get_runner_client().results(_run_id(suite))
    except RunnerUnavailable as exc:
        st.warning(safe_text(exc))
        if st.button("Refresh assessment", key=suite + "_offline_refresh"):
            st.rerun()
        return None
    return report


@st.fragment(run_every="3s")
def _assessment_fragment(suite):
    # All polling output is owned by the fragment; no external containers accumulate.
    report = _load_assessment(suite)
    if report is None:
        return
    if (report.get("run") or {}).get("status") not in ACTIVE_STATUSES:
        st.session_state["_run_status_" + suite] = (report.get("run") or {}).get("status")
        st.rerun()
    _assessment_body(suite, report)
    _secondary(suite, report)


def render_assessment(suite, preview_cases):
    if not _run_id(suite):
        _assessment_body(suite, {}, preview_cases)
        _secondary(suite, {})
        return
    # A terminal run is rendered without a timed fragment, stopping further polling.
    if st.session_state.get("_run_status_" + suite) in ACTIVE_STATUSES:
        _assessment_fragment(suite)
    else:
        report = _load_assessment(suite)
        if report is None:
            return
        if (report.get("run") or {}).get("status") in ACTIVE_STATUSES:
            st.session_state["_run_status_" + suite] = report["run"]["status"]
            _assessment_fragment(suite)
        else:
            _assessment_body(suite, report)
            _secondary(suite, report)
