"""Connection settings are edited here and consumed by every test page."""

import os
from urllib.parse import urlsplit

import streamlit as st


DEFAULT_ENDPOINT = "https://aigate.fortilaboratory.com/ai/openai/v1/chat/completions"
DEFAULT_MODEL = "qwen3.8-flash"


def initialize_state():
    defaults = {
        "saved_endpoint": os.getenv("FORTIAIGATE_ENDPOINT", DEFAULT_ENDPOINT),
        "saved_model": os.getenv("FORTIAIGATE_MODEL", DEFAULT_MODEL),
        "saved_api_key": "",
        "saved_budget_api_key": "",
        "saved_rate_limit_api_key": "",
        "saved_delay": 1.0,
        "saved_timeout": 120,
        "saved_csv_path": os.getenv("FORTIAIGATE_CSV", os.path.join(os.path.dirname(__file__), "fortiaigate_prompt_test_01.csv")),
        "configuration_version": 0,
        "page": "Overview",
        "results": {},
    }
    for key, value in defaults.items():
        if key not in st.session_state:
            st.session_state[key] = value
    if st.session_state.page is None:
        st.session_state.page = "Overview"
    elif st.session_state.page == "Sensitive Data Leakage":
        st.session_state.page = "Sensitive Data"


def connection_error(endpoint, model):
    try:
        url = urlsplit(endpoint)
        if url.scheme != "https" or not url.hostname or url.username or url.password:
            return "Use an HTTPS endpoint without embedded credentials."
        if url.query or url.fragment or not url.path.rstrip("/").endswith("/chat/completions"):
            return "Use the full /chat/completions URL without a query string or fragment."
        if url.port not in (None, 443):
            return "Use the standard HTTPS port."
    except ValueError:
        return "Enter a valid HTTPS endpoint."
    if not model.strip():
        return "Enter an explicit model ID."
    return ""


def _sync_setting(widget_key, saved_key):
    st.session_state[saved_key] = st.session_state[widget_key]
    for suite in ("sensitive", "garak"):
        st.session_state.pop("_pending_start_" + suite, None)
        st.session_state.pop("_start_error_" + suite, None)
    st.session_state.configuration_version += 1


def _clear_key():
    st.session_state.saved_api_key = ""
    st.session_state.config_api_key = ""
    st.session_state.saved_budget_api_key = ""
    st.session_state.config_budget_api_key = ""
    st.session_state.saved_rate_limit_api_key = ""
    st.session_state.config_rate_limit_api_key = ""
    for suite in ("sensitive", "garak"):
        st.session_state.pop("_pending_start_" + suite, None)
        st.session_state.pop("_start_error_" + suite, None)
    st.session_state.configuration_version += 1


def render_configuration():
    st.header("Configuration")
    st.caption("Set the connection once. Testing pages use these settings without repeating them.")
    with st.container(border=True):
        st.subheader("Model connection")
        for label, saved_key, widget_key, help_text in (
            ("Chat completions endpoint", "saved_endpoint", "config_endpoint", "Use the full HTTPS /chat/completions URL."),
            ("Model ID", "saved_model", "config_model", "Sent explicitly in every model request; never inferred from the URL."),
        ):
            if widget_key not in st.session_state:
                st.session_state[widget_key] = st.session_state[saved_key]
            st.text_input(label, key=widget_key, help=help_text, on_change=_sync_setting, args=(widget_key, saved_key))
        error = connection_error(st.session_state.saved_endpoint, st.session_state.saved_model)
        if error:
            st.warning(error)
        else:
            st.markdown("<span style='color:#f0f3f6;font-size:12px'>OpenAI-compatible base URL</span>",
                        unsafe_allow_html=True)
            st.code(st.session_state.saved_endpoint.rstrip("/")[:-len("chat/completions")], language=None)
        if "config_api_key" not in st.session_state:
            st.session_state.config_api_key = st.session_state.saved_api_key
        if "config_budget_api_key" not in st.session_state:
            st.session_state.config_budget_api_key = st.session_state.saved_budget_api_key
        if "config_rate_limit_api_key" not in st.session_state:
            st.session_state.config_rate_limit_api_key = st.session_state.saved_rate_limit_api_key
        st.text_input("API key (security test suites)", type="password", key="config_api_key", on_change=_sync_setting,
                      args=("config_api_key", "saved_api_key"),
                      help="Used by Prompt Injection, Sensitive Data and Garak Testing. Stored only in this server session.")
        st.text_input("API key (Budget Control)", type="password", key="config_budget_api_key", on_change=_sync_setting,
                      args=("config_budget_api_key", "saved_budget_api_key"),
                      help="Separate key for Budget Control tests against the same endpoint. Stored only in this server session.")
        st.text_input("API key (Rate Limit)", type="password", key="config_rate_limit_api_key", on_change=_sync_setting,
                      args=("config_rate_limit_api_key", "saved_rate_limit_api_key"),
                      help="Separate key for Rate Limit tests against the same endpoint. Stored only in this server session.")
        st.button("Clear API keys", on_click=_clear_key,
                  disabled=not (st.session_state.saved_api_key or st.session_state.saved_budget_api_key
                                or st.session_state.saved_rate_limit_api_key))
        st.caption("Saving settings does not contact the endpoint. Enter credentials only over a trusted local connection or authenticated HTTPS.")
    with st.container(border=True):
        st.subheader("Request settings")
        if "config_timeout" not in st.session_state:
            st.session_state.config_timeout = st.session_state.saved_timeout
        st.number_input("Request timeout (seconds)", min_value=1, max_value=300, key="config_timeout",
                        on_change=_sync_setting, args=("config_timeout", "saved_timeout"))
        st.caption("No output-token limit is sent by this app. Model/provider limits still apply.")
        if "config_delay" not in st.session_state:
            st.session_state.config_delay = st.session_state.saved_delay
        st.slider("Manual test delay (seconds)", 0.0, 5.0, step=0.5, key="config_delay",
                  on_change=_sync_setting, args=("config_delay", "saved_delay"))
        st.caption("Scanner request budgets, rate limits, and run duration are selected on the testing pages.")
    with st.container(border=True):
        st.subheader("Scanner service")
        st.caption("The private runner is configured by the server administrator. No service token is shown here.")
        if st.button("Check scanner readiness", icon=":material/health_and_safety:"):
            from attack_tester.runner_client import RunnerClient
            try:
                status = RunnerClient().health()
                if status.get("execution_enabled"):
                    st.success("Scanner service is available and execution is enabled.")
                else:
                    st.info("Scanner service is available; execution is disabled by the administrator.")
            except Exception:
                st.warning("Scanner service is unavailable or authentication is not configured. See the local setup instructions.")
        st.caption("This checks only the private scanner service, not the model endpoint.")
