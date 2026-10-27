"""Configuration owns shared settings and never fills in a target credential."""

from streamlit.testing.v1 import AppTest


APP = """
from attack_tester.configuration import initialize_state, render_configuration
import streamlit as st
initialize_state()
page = st.radio('Page', ['Configuration', 'Other'], key='test_page')
if page == 'Configuration':
    render_configuration()
else:
    st.text('Other page')
"""


def test_configuration_is_blank_key_and_persists_off_page():
    app = AppTest.from_string(APP).run()
    assert not app.exception
    assert app.text_input(key="config_api_key").value == ""
    assert app.text_input(key="config_budget_api_key").value == ""
    assert app.text_input(key="config_rate_limit_api_key").value == ""
    assert not any(widget.label == "CSV file path" for widget in app.text_input)
    app.text_input(key="config_model").set_value("test-model").run()
    assert app.session_state.saved_model == "test-model"
    app.radio(key="test_page").set_value("Other").run()
    assert not app.text_input
    app.radio(key="test_page").set_value("Configuration").run()
    assert app.text_input(key="config_model").value == "test-model"
    assert app.text_input(key="config_api_key").value == ""


def test_configuration_has_no_output_token_budget():
    app = AppTest.from_string(APP)
    app.session_state["saved_max_tokens"] = 512
    app.session_state["config_max_tokens"] = 512
    app.run()
    assert app.number_input(key="config_timeout").max == 300
    assert app.number_input(key="config_timeout").value == 120
    assert all(widget.label != "Maximum output tokens" for widget in app.number_input)
    assert not app.exception


def test_clear_key_removes_widget_and_saved_value():
    app = AppTest.from_string(APP).run()
    app.text_input(key="config_api_key").set_value("test-only-value").run()
    app.text_input(key="config_budget_api_key").set_value("budget-only-value").run()
    app.text_input(key="config_rate_limit_api_key").set_value("rate-only-value").run()
    assert app.session_state.saved_api_key == "test-only-value"
    assert app.session_state.saved_budget_api_key == "budget-only-value"
    assert app.session_state.saved_rate_limit_api_key == "rate-only-value"
    app.session_state["_pending_start_sensitive"] = {"payload": {"configuration": {"api_key": "test-only-value"}}}
    app.session_state["_start_error_sensitive"] = "Prior failure"
    button = next(b for b in app.button if b.label == "Clear API keys")
    button.click().run()
    assert app.session_state.saved_api_key == ""
    assert app.session_state.saved_budget_api_key == ""
    assert app.session_state.saved_rate_limit_api_key == ""
    assert app.text_input(key="config_budget_api_key").value == ""
    assert app.text_input(key="config_rate_limit_api_key").value == ""
    assert "_pending_start_sensitive" not in app.session_state
    assert "_start_error_sensitive" not in app.session_state
    assert app.text_input(key="config_api_key").value == ""
    assert not app.exception
