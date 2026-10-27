"""Streamlit security testing workspace for FortiAIGate.

Run with:
  streamlit run app.py
"""

import os
import sys
import csv
import time
import base64

# Make package imports work from either the app folder or repository root.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pandas as pd
import streamlit as st
from common.fortiaigate_test import classify_response, send_prompt
from attack_tester.configuration import initialize_state, render_configuration
from attack_tester.ui import apply_theme, render_navigation, render_breadcrumb, render_placeholder

st.set_page_config(
    page_title="FortiAIGate attack tester",
    page_icon=":material/shield:",
    layout="wide",
)

# ── Helper: load SVG as base64 for HTML embedding ──

IMAGES_DIR = os.path.join(os.path.dirname(__file__), "..", "common", "images")


def svg_to_base64(filename: str) -> str:
    """Read an SVG file and return a base64-encoded data URI."""
    path = os.path.join(IMAGES_DIR, filename)
    with open(path, "rb") as f:
        encoded = base64.b64encode(f.read()).decode("utf-8")
    return f"data:image/svg+xml;base64,{encoded}"


def svg_to_html(filename: str, height: int = 64) -> str:
    """Read an SVG file and return it as an inline <img> tag."""
    uri = svg_to_base64(filename)
    return f'<img src="{uri}" height="{height}" alt="{filename}" style="display:block; margin:auto;">'


# ── Load prompts from CSV ──


def load_attack_prompts(csv_path: str) -> list[dict]:
    """Load attack prompts from the test CSV.

    Returns list of dicts: attack_type, description, prompt_text
    """
    prompts = []
    with open(csv_path, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            text = row.get("prompt_text", "").strip()
            if text:
                prompts.append({
                    "attack_type": row["attack_type"],
                    "description": row["description"],
                    "prompt_text": text,
                })
    return prompts


def group_by_attack_type(prompts: list[dict]) -> dict[str, list[dict]]:
    """Group prompts by attack_type, preserving order."""
    groups: dict[str, list[dict]] = {}
    for p in prompts:
        groups.setdefault(p["attack_type"], []).append(p)
    return groups


# ── Shared workspace shell ──

initialize_state()
apply_theme()
page = render_navigation()
render_breadcrumb(page)

# ── Page: Home (architecture diagram) ──

if page == "Overview":
    st.header("Overview")
    st.caption("FortiAIGate testing: attack blocking and policy enforcement")
    # Architecture diagram: User/AI Agents (FortiDLP) → FortiGate → FortiWeb → FortiAIGate → LLM
    user_icon = svg_to_base64("GenerativeAI.svg")
    dlp_icon = svg_to_base64("FortiDLP.svg")
    gate_icon = svg_to_base64("FortiGate.svg")
    web_icon = svg_to_base64("FortiWeb.svg")
    aigate_icon = svg_to_base64("FortiAIGate.svg")
    llm_icon = svg_to_base64("GenerativeAI.svg")

    diagram_html = f"""
    <div style="display:flex; align-items:center; justify-content:center; flex-wrap:wrap;
                gap:0; padding:40px 10px; max-width:960px; margin:auto;">

      <!-- User / AI Agents card -->
      <div style="flex:0 0 150px; text-align:center; padding:20px 14px;
                  background:#ffffff; border-radius:12px; border:2px solid #d0d0d0;
                  box-shadow:0 2px 8px rgba(0,0,0,0.06);">
        <img src="{user_icon}" height="56" style="display:block; margin:0 auto 8px;">
        <div style="font-size:15px; font-weight:700; color:#222;">User / AI Agent</div>
        <div style="margin-top:6px;">
          <img src="{dlp_icon}" height="28" style="display:inline-block; vertical-align:middle; margin-right:4px;">
          <span style="font-size:11px; color:#444; vertical-align:middle;">FortiDLP</span>
        </div>
      </div>

      <!-- Arrow -->
      <div style="flex:0 0 40px; text-align:center; color:#EE3325; font-size:28px;">→</div>

      <!-- FortiGate card -->
      <div style="flex:0 0 150px; text-align:center; padding:20px 14px;
                  background:#ffffff; border-radius:12px; border:2px solid #d0d0d0;
                  box-shadow:0 2px 8px rgba(0,0,0,0.06);">
        <img src="{gate_icon}" height="56" style="display:block; margin:0 auto 8px;">
        <div style="font-size:15px; font-weight:700; color:#222;">FortiGate</div>
        <div style="font-size:11px; color:#444; margin-top:6px;">Network firewall</div>
      </div>

      <!-- Arrow -->
      <div style="flex:0 0 40px; text-align:center; color:#EE3325; font-size:28px;">→</div>

      <!-- FortiWeb card -->
      <div style="flex:0 0 150px; text-align:center; padding:20px 14px;
                  background:#ffffff; border-radius:12px; border:2px solid #d0d0d0;
                  box-shadow:0 2px 8px rgba(0,0,0,0.06);">
        <img src="{web_icon}" height="56" style="display:block; margin:0 auto 8px;">
        <div style="font-size:15px; font-weight:700; color:#222;">FortiWeb</div>
        <div style="font-size:11px; color:#444; margin-top:6px;">Web app firewall</div>
      </div>

      <!-- Arrow -->
      <div style="flex:0 0 40px; text-align:center; color:#EE3325; font-size:28px;">→</div>

      <!-- FortiAIGate card (highlighted) -->
      <div style="flex:0 0 150px; text-align:center; padding:20px 14px;
                  background:#ffffff; border-radius:12px; border:3px solid #EE3325;
                  box-shadow:0 2px 12px rgba(238,51,37,0.25);">
        <img src="{aigate_icon}" height="56" style="display:block; margin:0 auto 8px;">
        <div style="font-size:15px; font-weight:700; color:#EE3325;">FortiAIGate</div>
        <div style="font-size:11px; color:#EE3325; opacity:0.85; margin-top:6px;">Inspection &amp; enforcement</div>
      </div>

      <!-- Arrow -->
      <div style="flex:0 0 40px; text-align:center; color:#EE3325; font-size:28px;">→</div>

      <!-- LLM card -->
      <div style="flex:0 0 150px; text-align:center; padding:20px 14px;
                  background:#ffffff; border-radius:12px; border:2px solid #d0d0d0;
                  box-shadow:0 2px 8px rgba(0,0,0,0.06);">
        <img src="{llm_icon}" height="56" style="display:block; margin:0 auto 8px;">
        <div style="font-size:15px; font-weight:700; color:#222;">LLM</div>
        <div style="font-size:11px; color:#444; margin-top:6px;">Large language model</div>
      </div>

    </div>

    <div style="text-align:center; max-width:720px; margin:24px auto 0; color:#ccc; font-size:13px;">
      FortiAIGate sits between your web firewall and the LLM, inspecting every prompt
      and enforcing the policies that govern traffic to the model. This lab will test:
      attack blocking through <b style="color:#EE3325;">Prompt Injection</b>,
      <b style="color:#EE3325;">Sensitive Data</b>, and more comprehensively with <b style="color:#EE3325;">Garak Testing</b>;
      on the other hand keep your cost and token usage in control through <b style="color:#EE3325;">Budget Control</b> and
      <b style="color:#EE3325;">Rate Limit</b>. Set your connection and API keys in
      <b style="color:#EE3325;">Configuration</b>, then open any of the suites above from the
      sidebar to start testing.
    </div>
    """
    st.markdown(diagram_html, unsafe_allow_html=True)

# ── Page: Configuration ──

if page == "Configuration":
    render_configuration()

# ── Page: Budget Control ──

if page == "Budget Control":
    from attack_tester.budget_control import render_budget_control
    render_budget_control()

# ── Page: Rate Limit ──

if page == "Rate Limit":
    from attack_tester.rate_limit import render_rate_limit
    render_rate_limit()

# ── Page: Prompt Injection ──

if page == "Prompt Injection":
    # Read config from session state (pre-initialized, persists across page switches)
    # Read from saved keys (persist across page switches and widget reruns)
    endpoint = st.session_state.saved_endpoint
    api_key = st.session_state.saved_api_key
    delay = st.session_state.saved_delay
    timeout = st.session_state.saved_timeout

    st.header(":material/shield: Prompt Injection")
    st.caption("Manual results use a response-text signature heuristic. Blocked is not verified gateway provenance; Through is not a confirmed vulnerability.")

    # ── Load prompts ──

    try:
        prompts = load_attack_prompts(st.session_state.saved_csv_path)
        groups = group_by_attack_type(prompts)
        total = len(prompts)
        st.info(f"Test that FortiAIGate blocks malicious prompts designed to override system instructions, extract data, and hijack agent behavior. Loaded **{total}** test prompts across **{len(groups)}** attack types.", icon=":material/info:")
    except FileNotFoundError:
        st.error(f"CSV file not found: `{st.session_state.saved_csv_path}`", icon=":material/error:")
        prompts = []
        groups = {}

    # ── Summary dashboard placeholder (filled after tests run) ──

    dashboard_ph = st.container()

    # ── Batch "Run all" ──

    run_all_clicked = False
    if not api_key or not endpoint:
        st.warning("Configure the Endpoint URL and API key on the **Configuration** page first.", icon=":material/warning:")
    else:
        run_all_clicked = st.button(":material/play_arrow: Run all tests", type="primary", width="stretch")

    if run_all_clicked and prompts and api_key and endpoint:
        # Progress inside dashboard_ph (above Run all button) so it doesn't
        # insert new elements between Run all and the card sections
        with dashboard_ph:
            progress_ph = st.empty()
            status_ph = st.empty()
            progress = progress_ph.progress(0, text="Running all tests...")

        for i, p in enumerate(prompts):
            status_ph.text(f"Sending {i + 1}/{total}: {p['attack_type']}")
            progress.progress(i / total, text=f"Testing {i + 1}/{total}...")

            sent = send_prompt(endpoint, api_key, p["prompt_text"], model=st.session_state.saved_model,
                               timeout=timeout)
            outcome = classify_response(sent["response_text"]) if sent["status"] == "OK" else "Error"

            st.session_state.results[i] = {
                "attack_type": p["attack_type"],
                "description": p["description"],
                "prompt_text": p["prompt_text"],
                "response_text": sent["response_text"],
                "outcome": outcome,
                "latency_ms": sent["latency_ms"],
                "error": sent["error"],
            }

            if delay > 0 and i < total - 1:
                time.sleep(delay)

        with dashboard_ph:
            progress_ph.empty()
            status_ph.empty()
        st.toast("All tests completed!", icon=":material/check_circle:")

    # ── Attack cards ──

    if prompts and api_key and endpoint:
        global_idx = 0

        for attack_type, attack_prompts in groups.items():
            description = attack_prompts[0]["description"]
            with st.container(border=True):
                st.subheader(f":material/warning: {attack_type}")
                st.caption(description)

                for p in attack_prompts:
                    idx = global_idx
                    global_idx += 1

                    # ── Everything inside the card ──
                    with st.container(border=True):
                        st.caption("Prompt")
                        st.text(p["prompt_text"])

                        col_send, col_result = st.columns([1, 3])
                        with col_send:
                            send_btn = st.button(
                                ":material/send: Send",
                                key=f"send_{idx}",
                                width="stretch",
                            )

                        result_ph = col_result.empty()

                        # ── Handle Send click: dim, send, resume ──
                        if send_btn:
                            # Clear old result so the card dims
                            st.session_state.results.pop(idx, None)
                            result_ph.caption("Sending request...")

                            with st.spinner("Sending test…"):
                                sent = send_prompt(endpoint, api_key, p["prompt_text"], model=st.session_state.saved_model,
                                                   timeout=timeout)
                                outcome = classify_response(sent["response_text"]) if sent["status"] == "OK" else "Error"
                                new_result = {
                                    "attack_type": p["attack_type"],
                                    "description": p["description"],
                                    "prompt_text": p["prompt_text"],
                                    "response_text": sent["response_text"],
                                    "outcome": outcome,
                                    "latency_ms": sent["latency_ms"],
                                    "error": sent["error"],
                                }
                                st.session_state.results[idx] = new_result

                                # Result appears inline after skeleton exits
                                result = new_result
                                if result["outcome"] == "Blocked":
                                    result_ph.markdown(
                                        f":green-badge[Blocked] :material/check_circle: · {result['latency_ms']}ms"
                                    )
                                elif result["outcome"] == "Through":
                                    result_ph.markdown(
                                        f":red-badge[Through] :material/error: · {result['latency_ms']}ms"
                                    )
                                else:
                                    result_ph.markdown(
                                        f":orange-badge[Error] :material/error: · {result['error']}"
                                    )

                            # Response expander inside the card — auto-expand on Send
                            if st.session_state.results[idx]["response_text"]:
                                with st.expander("View response", icon=":material/visibility:", expanded=True):
                                    st.text(st.session_state.results[idx]["response_text"][:2000])
                        else:
                            # ── Show current state (no click) ──
                            result = st.session_state.results.get(idx)
                            if result:
                                if result["outcome"] == "Blocked":
                                    result_ph.markdown(
                                        f":green-badge[Blocked] :material/check_circle: · {result['latency_ms']}ms"
                                    )
                                elif result["outcome"] == "Through":
                                    result_ph.markdown(
                                        f":red-badge[Through] :material/error: · {result['latency_ms']}ms"
                                    )
                                else:
                                    result_ph.markdown(
                                        f":orange-badge[Error] :material/error: · {result['error']}"
                                    )

                                # Response expander — collapsed (only the just-sent one auto-expands)
                                if result["response_text"]:
                                    with st.expander("View response", icon=":material/visibility:", expanded=False):
                                        st.text(result["response_text"][:2000])
                            else:
                                result_ph.caption("Not yet tested — click Send")

            st.markdown("")

    # ── Fill summary dashboard placeholder (after results are available) ──

    if st.session_state.results:
        df = pd.DataFrame(st.session_state.results.values())

        total_tests = len(df)
        blocked = len(df[df["outcome"] == "Blocked"])
        through = len(df[df["outcome"] == "Through"])
        errors = len(df[df["outcome"] == "Error"])

        with dashboard_ph:
            with st.expander(":material/query_stats: Summary dashboard", expanded=True):
                with st.container(horizontal=True):
                    st.metric("Total tested", str(total_tests), border=True)
                    st.metric("Blocked", str(blocked), border=True)
                    st.metric("Through", str(through), border=True)
                    st.metric("Errors", str(errors), border=True)

# ── Page: Shadow AI ──

if page == "Shadow AI":
    render_placeholder(page)

# ── Scanner-backed test pages ──

if page == "Sensitive Data":
    from attack_tester.sensitive_data import render_sensitive_data
    render_sensitive_data()

if page == "Garak Testing":
    from attack_tester.garak_page import render_garak_page
    render_garak_page()
