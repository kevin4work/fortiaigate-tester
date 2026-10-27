"""Native Streamlit 1.50 state and private runner contract regression tests."""

import uuid
from unittest.mock import Mock

import pytest
import requests
from streamlit.testing.v1 import AppTest

from common.test_catalog import get_cases
from attack_tester.garak_page import profile_limits
from attack_tester.runner_client import RunnerClient, RunnerUnavailable, saved_configuration
from attack_tester.run_views import execution_gate, detector_evaluation
from attack_tester.sensitive_data import current_selection, selected_preview_cases, CATEGORY_NAMES


CATALOG = {
    "profiles": [
        {"id": profile, "title": profile.title(), "available": True, "probe_ids": ["dan.Dan_11_0"], "planned_cases": [{"id": "dan.Dan_11_0:0", "case_id": "dan.Dan_11_0:0", "family": "dan", "family_title": "Instruction override", "title": "DAN test", "prompt": "Synthetic fixture prompt", "probe": "dan.Dan_11_0"}]}
        for profile in ("smoke", "core", "extended")
    ],
    "families": [
        {"id": "apikey", "available": True, "probe_ids": ["apikey.GetKey", "apikey.CompleteKey"],
         "previews": [{"id": "apikey.GetKey:0", "case_id": "apikey.GetKey:0", "family": "apikey",
                       "family_title": "API-key disclosure", "title": "GetKey 1", "prompt": "Sampled disclosure prompt"}]},
    ],
}
FAMILIES = {item["id"]: item for item in CATALOG["families"]}


def context_ready():
    return Mock(), {"status": "ok", "execution_enabled": True,
                    "capabilities": {"sensitive": True, "garak": True, "concurrency": 20}}, CATALOG, None


def app(page="sensitive", configuration=False):
    source = "from attack_tester.{} import {}\n{}()".format(
        "sensitive_data" if page == "sensitive" else "garak_page",
        "render_sensitive_data" if page == "sensitive" else "render_garak_page",
        "render_sensitive_data" if page == "sensitive" else "render_garak_page",
    )
    test = AppTest.from_string(source, default_timeout=15)
    if configuration:
        for key, value in {"endpoint": "https://test.invalid/v1/chat/completions", "model": "test-model", "api_key": "fixture-only-test-key", "timeout": 60, "max_tokens": 512}.items():
            test.session_state["saved_" + key] = value
    test.run()
    assert not test.exception
    return test


def test_selection_is_the_three_reviewed_types_only():
    assert current_selection({"apikey": {"available": True}}) == ["hkid", "cards", "apikey"]
    assert current_selection({}) == ["hkid", "cards"]
    assert current_selection({"apikey": {"available": False, "reason": "offline"}}) == ["hkid", "cards"]
    assert len(get_cases(current_selection({}))) == 6


def test_preview_cases_combine_fixtures_and_sampled_disclosure():
    families = {item["id"]: item for item in CATALOG["families"]}
    cases = selected_preview_cases(["hkid", "cards", "apikey"], families)
    assert [case["case_id"] for case in cases][:6] == [case["id"] for case in get_cases()]
    assert [case["family"] for case in cases[6:]] == ["apikey"]
    assert selected_preview_cases(["hkid", "cards"], {}) == selected_preview_cases(["hkid", "cards"], families)


def test_selected_cases_keep_exact_dummy_values():
    originals = get_cases()
    assert len(originals) == 6
    assert [item["group"] for item in get_cases(["hkid"])] == ["hkid", "hkid"]
    assert "A123456(7)" in originals[0]["prompt"]
    assert get_cases() == originals


@pytest.mark.parametrize("profile,cap,minutes,concurrency",
                         [("smoke", 60, 3, 1), ("core", 600, 5, 10), ("extended", 1800, 30, 20)])
def test_garak_guardrail_ceilings(profile, cap, minutes, concurrency):
    assert profile_limits(profile) == {"request_cap": cap, "rpm": 100, "minutes": minutes,
                                       "concurrency": concurrency}


def test_saved_state_only_and_configuration_gate():
    state = {"saved_endpoint": "https://test.invalid", "saved_model": "explicit-model", "saved_api_key": "fixture-key", "saved_timeout": 9, "saved_max_tokens": 88, "model": "wrong-widget"}
    configuration = saved_configuration(state)
    assert configuration["model"] == "explicit-model"
    assert "max_tokens" not in configuration
    assert not execution_gate({"execution_enabled": True}, configuration)
    assert execution_gate({}, configuration)
    assert execution_gate({"execution_enabled": True}, {})


def test_sensitive_page_has_no_profile_or_category_controls(monkeypatch):
    monkeypatch.delenv("FORTIAIGATE_RUNNER_TOKEN", raising=False)
    test = app()
    assert not test.checkbox
    assert not any(radio.label == "Test profile" for radio in test.radio)
    assert all(any(case["prompt"] in block.value for block in test.text) for case in get_cases())
    assert test.warning
    assert not test.text_input


def test_garak_profile_survives_navigation_while_sensitive_has_no_selection_state(monkeypatch):
    monkeypatch.setattr("attack_tester.sensitive_data.runner_context", context_ready)
    source = '''import streamlit as st
from attack_tester.sensitive_data import render_sensitive_data
from attack_tester.garak_page import render_garak_page
page = st.radio("Page", ["Sensitive", "Garak"], key="test_navigation")
if page == "Sensitive":
    render_sensitive_data()
else:
    render_garak_page()
'''
    test = AppTest.from_string(source).run()
    assert all(any(case["prompt"] in block.value for block in test.text) for case in get_cases())
    test.radio(key="test_navigation").set_value("Garak").run()
    test.radio(key="_widget_garak_profile").set_value("smoke").run()
    test.radio(key="test_navigation").set_value("Sensitive").run()
    test.radio(key="test_navigation").set_value("Garak").run()
    assert test.radio(key="_widget_garak_profile").value == "smoke"
    assert not test.exception


def test_fixed_cases_are_visible_inline_without_dialog_or_results_dropdown(monkeypatch):
    monkeypatch.delenv("FORTIAIGATE_RUNNER_TOKEN", raising=False)
    test = app()
    text = "\n".join(block.value for block in test.text)
    for case in get_cases():
        assert case["prompt"] in text
    assert "A123456(7)" in text
    assert not any(radio.label.endswith("view") for radio in test.radio)
    assert not any(select.label == "Evidence record" for select in test.selectbox)
    assert not test.exception


def test_garak_offline_native_guardrails(monkeypatch):
    monkeypatch.delenv("FORTIAIGATE_RUNNER_TOKEN", raising=False)
    test = app("garak")
    assert [item.disabled for item in test.number_input] == [False, False, False]
    assert [item.value for item in test.number_input] == [100, 5, 10]
    assert not test.text_input
    assert test.warning
    test.radio(key="_widget_garak_profile").set_value("smoke").run()
    assert [item.value for item in test.number_input] == [100, 3]
    test.radio(key="_widget_garak_profile").set_value("core").run()
    assert [item.value for item in test.number_input] == [100, 5, 10]
    assert test.number_input(key="_garak_minutes_core").proto.max == 5
    test.radio(key="_widget_garak_profile").set_value("extended").run()
    assert [item.value for item in test.number_input] == [100, 30, 20]
    assert test.number_input(key="_garak_minutes_extended").proto.max == 30
    assert not test.exception


def test_garak_editable_budgets_are_preserved_per_profile_and_flow_to_start(monkeypatch):
    client = Mock()
    client.start.return_value = {"id": "budget-job", "status": "queued"}
    context = lambda: (client, {"execution_enabled": True,
                                "capabilities": {"sensitive": True, "garak": True, "concurrency": 20}}, CATALOG, None)
    monkeypatch.setattr("attack_tester.garak_page.runner_context", context)
    monkeypatch.setattr("attack_tester.run_views.runner_context", context)
    monkeypatch.setattr("attack_tester.garak_page.render_assessment", lambda *args: None)
    test = app("garak", configuration=True)
    table = "\n".join(block.value for block in test.markdown)
    assert "DAN persona" in table and "What it tests" in table
    test.number_input(key="_garak_rpm_core").set_value(12).run()
    test.number_input(key="_garak_minutes_core").set_value(4).run()
    test.radio(key="_widget_garak_profile").set_value("smoke").run()
    assert [item.value for item in test.number_input] == [100, 3]
    assert test.number_input(key="_garak_rpm_smoke").proto.max == 100
    assert test.number_input(key="_garak_minutes_smoke").proto.max == 3
    test.radio(key="_widget_garak_profile").set_value("core").run()
    assert test.number_input(key="_garak_minutes_core").proto.max == 5
    assert [item.value for item in test.number_input] == [12, 4, 10]
    test.number_input(key="_garak_concurrency_core").set_value(5).run()
    test.run()
    assert [item.value for item in test.number_input] == [12, 4, 5]
    test.button(key="_garak_start").click().run()
    assert client.start.call_args.args[0]["limits"] == {"request_cap": 600, "rpm": 12, "minutes": 4, "concurrency": 5}
    assert not test.exception


def test_garak_profile_labels_and_techniques_use_current_frozen_plans(monkeypatch):
    from runner.catalog import PROFILE_PROBES, planned_cases
    from attack_tester.garak_page import PROBE_INFO
    catalog = {"profiles": [
        {"id": profile, "available": True, "probe_ids": probes,
         "planned_cases": planned_cases(profile)}
        for profile, probes in PROFILE_PROBES.items()
    ], "families": []}
    client = Mock()
    context = lambda: (client, {"execution_enabled": True, "capabilities": {"concurrency": 20}}, catalog, None)
    monkeypatch.setattr("attack_tester.garak_page.runner_context", context)
    monkeypatch.setattr("attack_tester.garak_page.render_assessment", lambda *args: None)
    test = app("garak")
    options = test.radio(key="_widget_garak_profile").options
    assert "10 test cases" in options[0] and "<=3 min" in options[0]
    assert "27 test cases" in options[1] and "<=5 min" in options[1]
    assert "1151 test cases" in options[2] and "<=30 min" in options[2]
    test.radio(key="_widget_garak_profile").set_value("extended").run()
    table = "\n".join(block.value for block in test.markdown)
    for probe_id in PROFILE_PROBES["extended"]:
        assert probe_id in PROBE_INFO
        assert PROBE_INFO[probe_id][0] in table
    client.start.assert_not_called()
    assert not test.exception


def test_garak_concurrency_clamped_to_runner_capability(monkeypatch):
    client = Mock()
    client.start.return_value = {"id": "clamp-job", "status": "queued"}
    context = lambda: (client, {"execution_enabled": True, "capabilities": {"concurrency": 1}}, CATALOG, None)
    monkeypatch.setattr("attack_tester.garak_page.runner_context", context)
    monkeypatch.setattr("attack_tester.run_views.runner_context", context)
    monkeypatch.setattr("attack_tester.garak_page.render_assessment", lambda *args: None)
    test = app("garak", configuration=True)
    assert test.number_input(key="_garak_concurrency_core").value == 10
    test.button(key="_garak_start").click().run()
    assert client.start.call_args.args[0]["limits"]["concurrency"] == 1
    assert not test.exception


def test_direct_start_has_no_review_and_retries_are_idempotent(monkeypatch):
    client = Mock()
    client.start.side_effect = [RunnerUnavailable("Offline"), {"id": "real-test-job", "status": "queued"}]
    context = lambda: (client, {"execution_enabled": True}, CATALOG, None)
    monkeypatch.setattr("attack_tester.sensitive_data.runner_context", context)
    monkeypatch.setattr("attack_tester.run_views.runner_context", context)
    monkeypatch.setattr("attack_tester.sensitive_data.render_assessment", lambda *args: None)
    test = app(configuration=True)
    client.start.assert_not_called()
    assert not test.button(key="_sensitive_start").disabled
    assert not any("review" in button.label.lower() for button in test.button)
    test.button(key="_sensitive_start").click().run()
    assert test.error
    key = test.session_state["_pending_start_sensitive"]["idempotency_key"]
    test.button(key="_sensitive_start").click().run()
    assert client.start.call_count == 2
    assert all(call.args[0]["idempotency_key"] == key for call in client.start.call_args_list)
    payload = client.start.call_args.args[0]
    assert payload["cases"] == []
    assert payload["selection"] == ["hkid", "cards", "apikey"]
    assert "max_tokens" not in payload["configuration"]
    assert test.session_state["_active_run_sensitive"] == "real-test-job"
    assert "_pending_start_sensitive" not in test.session_state
    test.run()
    assert client.start.call_count == 2
    assert not any(radio.label.endswith("view") for radio in test.radio)
    assert not test.exception


@pytest.mark.parametrize("page", ["sensitive", "garak"])
def test_direct_start_rechecks_readiness_after_click(monkeypatch, page):
    client = Mock()
    health = {"execution_enabled": True}
    context = lambda: (client, health, CATALOG, None)
    module = "sensitive_data" if page == "sensitive" else "garak_page"
    monkeypatch.setattr("attack_tester." + module + ".runner_context", context)
    monkeypatch.setattr("attack_tester.run_views.runner_context", context)
    test = app(page, configuration=True)
    assert not test.button(key="_" + page + "_start").disabled
    health["execution_enabled"] = False
    test.button(key="_" + page + "_start").click().run()
    client.start.assert_not_called()
    assert test.button(key="_" + page + "_start").disabled
    assert test.error



def test_changed_scope_uses_new_start_key_after_failure(monkeypatch):
    client = Mock()
    client.start.side_effect = RunnerUnavailable("Offline")
    context = lambda: (client, {"execution_enabled": True}, CATALOG, None)
    monkeypatch.setattr("attack_tester.garak_page.runner_context", context)
    monkeypatch.setattr("attack_tester.run_views.runner_context", context)
    test = app("garak", configuration=True)
    test.button(key="_garak_start").click().run()
    first_key = client.start.call_args.args[0]["idempotency_key"]
    test.number_input(key="_garak_rpm_core").set_value(12).run()
    test.button(key="_garak_start").click().run()
    assert client.start.call_args.args[0]["idempotency_key"] != first_key
    assert client.start.call_args.args[0]["limits"]["rpm"] == 12


def test_private_client_headers_redirects_and_safe_transport_error(monkeypatch):
    send = Mock(return_value=Mock(status_code=200, json=lambda: {"status": "ok"}))
    monkeypatch.setattr(requests.Session, "request", send)
    session = str(uuid.uuid4())
    client = RunnerClient(session, token="fixture-service-token")
    assert client.health()["status"] == "ok"
    kwargs = send.call_args.kwargs
    assert kwargs["headers"] == {"Authorization": "Bearer fixture-service-token", "X-Session-ID": session}
    assert kwargs["allow_redirects"] is False
    send.side_effect = requests.ConnectionError("fixture-target-key must not appear")
    with pytest.raises(RunnerUnavailable) as failure:
        client.start({"configuration": {"api_key": "fixture-target-key"}})
    assert "fixture-target-key" not in str(failure.value)


def test_private_client_ignores_proxy_environment_and_netrc(monkeypatch):
    for name in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"):
        monkeypatch.setenv(name, "http://proxy.invalid:3128")
    monkeypatch.setenv("NO_PROXY", "")
    monkeypatch.setenv("no_proxy", "")
    monkeypatch.setenv("NETRC", "/nonexistent/netrc")
    observed = []

    def capture_send(session, request, **kwargs):
        observed.append((session.trust_env, kwargs["proxies"], request))
        response = requests.Response()
        response.status_code = 200
        response._content = b'{"id":"fixture-job","status":"queued"}'
        return response

    monkeypatch.setattr(requests.Session, "send", capture_send)
    client = RunnerClient(str(uuid.uuid4()), token="fixture-service-token")
    client.start({"configuration": {"api_key": "fixture-target-key"}})
    assert len(observed) == 1
    trust_env, proxies, request = observed[0]
    assert trust_env is False
    assert not proxies
    assert request.url == "http://127.0.0.1:8765/runs"
    assert request.headers["Authorization"] == "Bearer fixture-service-token"
    assert b"fixture-target-key" in request.body


@pytest.mark.parametrize("page", ["sensitive", "garak"])
def test_missing_configuration_disables_direct_start(monkeypatch, page):
    module = "sensitive_data" if page == "sensitive" else "garak_page"
    monkeypatch.setattr("attack_tester." + module + ".runner_context", context_ready)
    monkeypatch.setattr("attack_tester.run_views.runner_context", context_ready)
    test = app(page)
    assert test.button(key="_" + page + "_start").disabled
    assert any("Configuration" in warning.value for warning in test.warning)
    assert not any("review" in button.label.lower() for button in test.button)
    if page == "sensitive":
        assert all(any(case["prompt"] in block.value for block in test.text) for case in get_cases())
    assert not test.exception



@pytest.mark.parametrize("outcome,detectors,error,expected", [
    ("unscored", [{"score": 0, "flagged": False}, {"score": None, "flagged": None}], None, "Unscored"),
    ("not_flagged", [{"score": 0, "flagged": False}, {"score": None, "flagged": None}], None, "Unscored"),
    ("not_flagged", [{"score": 0, "flagged": None}], None, "Unscored"),
    ("not_flagged", [{"score": None, "flagged": False}], None, "Unscored"),
    ("unscored", [{"score": 0, "flagged": False}], None, "Unscored"),
    ("not_flagged", [{"score": 0, "flagged": False}], "detector error", "Unscored"),
    ("not_flagged", [{"score": 0, "flagged": False}], None, "Not flagged"),
    ("unscored", [{"score": 1, "flagged": True}, {"score": None, "flagged": None}], None, "Flagged · incomplete evaluation"),
])
def test_partial_detector_evaluation_never_becomes_not_flagged(monkeypatch, outcome, detectors, error, expected):
    assert detector_evaluation({"outcome": outcome, "detectors": detectors, "error": error}) == expected


def test_server_session_identity_persists_across_page_navigation(monkeypatch):
    monkeypatch.setenv("FORTIAIGATE_RUNNER_TOKEN", "fixture-service-token")
    send = Mock(return_value=Mock(status_code=200, json=lambda: {"status": "ok", "profiles": [], "families": []}))
    monkeypatch.setattr(requests.Session, "request", send)
    test = app()
    session = test.session_state["_runner_session_id"]
    assert str(uuid.UUID(session)) == session
    test.run()
    assert test.session_state["_runner_session_id"] == session
    assert all(call.kwargs["headers"]["X-Session-ID"] == session for call in send.call_args_list)


@pytest.mark.parametrize("status", [302, 401, 403, 404, 409, 422, 500])
def test_runner_http_failures_do_not_echo_service_body_or_target_key(monkeypatch, status):
    response = Mock(status_code=status)
    response.json.return_value = {"detail": "fixture-target-key", "configuration": {"api_key": "fixture-target-key"}}
    monkeypatch.setattr(requests.Session, "request", Mock(return_value=response))
    client = RunnerClient("session", token="fixture-service-token")
    with pytest.raises(RunnerUnavailable) as failure:
        client.start({"configuration": {"api_key": "fixture-target-key"}})
    assert "fixture-target-key" not in str(failure.value)
    response.json.assert_not_called()


def test_unreadable_runner_response_never_becomes_success(monkeypatch):
    response = Mock(status_code=200)
    response.json.side_effect = ValueError("fixture-target-key")
    monkeypatch.setattr(requests.Session, "request", Mock(return_value=response))
    with pytest.raises(RunnerUnavailable) as failure:
        RunnerClient("session", token="fixture-service-token").health()
    assert "fixture-target-key" not in str(failure.value)


@pytest.mark.parametrize("url", ["http://private.example:8765", "https://user:password@example.com", "https://example.com?token=secret"])
def test_runner_url_rejects_cleartext_remote_and_embedded_credentials(url):
    with pytest.raises(RunnerUnavailable):
        RunnerClient("session", url=url, token="fixture")
