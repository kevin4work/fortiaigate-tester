"""Streamlit attack tester for FortiAIGate — vivid card-based UI.

Run with:
  streamlit run app.py
"""

import os
import sys
import csv
import time
import base64

# Add common module to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "common"))

import pandas as pd
import streamlit as st
from fortiaigate_test import classify_response, send_prompt

st.set_page_config(
    page_title="FortiAIGate attack tester",
    page_icon=":material/shield:",
    layout="wide",
)

# ── Custom CSS: sidebar layout + button styling ──

st.markdown("""
<style>
/* Sidebar: flex column so footer pins to bottom */
[data-testid="stSidebar"] {
    display: flex !important;
    flex-direction: column !important;
}
[data-testid="stSidebarContent"] {
    display: flex !important;
    flex-direction: column !important;
    flex: 1 1 auto !important;
}
[data-testid="stSidebarUserContent"] {
    display: flex !important;
    flex-direction: column !important;
    flex: 1 1 auto !important;
}
/* Make Streamlit's intermediate wrapper divs flex too */
[data-testid="stSidebarUserContent"] > div {
    display: flex !important;
    flex-direction: column !important;
    flex: 1 1 auto !important;
}
[data-testid="stSidebarUserContent"] > div > div[data-testid="stVerticalBlock"] {
    flex: 1 1 auto !important;
}

/* Sidebar buttons: bigger, left-aligned, red theme */
[data-testid="stSidebar"] .stButton button {
    font-size: 16px;
    font-weight: 600;
    text-align: left;
    padding: 12px 16px;
    min-height: 48px;
    line-height: 1.4;
    border-radius: 8px;
    transition: all 0.2s;
    background-color: #EE3325 !important;
    color: #fff !important;
    border-color: #EE3325 !important;
}
/* Hover: darken red */
[data-testid="stSidebar"] .stButton button:hover {
    background-color: #CC2920 !important;
    border-color: #CC2920 !important;
    color: #fff !important;
}
/* Active button: brighter red with subtle glow */
[data-testid="stSidebar"] .stButton button[kind="primary"] {
    box-shadow: 0 4px 12px rgba(238,51,37,0.4) !important;
}

/* Footer: push the last ElementContainer to bottom via flex margin */
[data-testid="stSidebarUserContent"] [data-testid="stVerticalBlock"] > [data-testid="stElementContainer"]:last-child {
    margin-top: auto !important;
}
.sidebar-footer {
    padding-top: 24px;
    padding-bottom: 32px;
    text-align: center;
    color: #888;
    font-size: 12px;
}
</style>
""", unsafe_allow_html=True)

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


# ── Initialize session state ──

if "results" not in st.session_state:
    st.session_state.results = {}  # keyed by global index

if "csv_path" not in st.session_state:
    default_csv = os.getenv(
        "FORTIAIGATE_CSV",
        os.path.join(os.path.dirname(__file__), "fortiaigate_prompt_test_01.csv"),
    )
    st.session_state.csv_path = default_csv

if "page" not in st.session_state:
    st.session_state.page = None  # No page auto-selected → show Home

# ── Sidebar: button-style page menu ──

with st.sidebar:
    # Configuration button
    cfg_active = st.session_state.page == "Configuration"
    if st.button(
        ":material/settings: Configuration",
        type="primary" if cfg_active else "secondary",
        use_container_width=True,
    ):
        st.session_state.page = "Configuration"

    # Prompt Injection button
    pi_active = st.session_state.page == "Prompt Injection"
    if st.button(
        ":material/shield: Prompt Injection",
        type="primary" if pi_active else "secondary",
        use_container_width=True,
    ):
        st.session_state.page = "Prompt Injection"

    # Footer at bottom of sidebar
    st.markdown('<div class="sidebar-footer">FortiAIGate attack tester v1.0</div>', unsafe_allow_html=True)

page = st.session_state.page

# ── Title banner with Fortinet logo ──

logo_uri = svg_to_base64("Fortinet-logomark-rgb-red.svg")

with st.container(horizontal_alignment="center"):
    st.markdown(
        f"<h1 style='text-align: center; margin: 0;'>"
        f'<img src="{logo_uri}" height="80" style="vertical-align:middle; margin-bottom:7px;" alt="Fortinet">'
        f"Fortinet Unified AI Solutions</h1>",
        unsafe_allow_html=True,
    )
st.caption("AI gateway security testing — verify that FortiAIGate blocks malicious prompts", text_alignment="center")
st.space("medium")

# ── Page: Home (architecture diagram) ──

if page is None:
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
        <div style="font-size:11px; color:#EE3325; opacity:0.85; margin-top:6px;">AI prompt inspection</div>
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

    <div style="text-align:center; max-width:700px; margin:24px auto 0; color:#ccc; font-size:13px;">
      FortiAIGate sits between your web firewall and the LLM, inspecting every prompt
      to block malicious inputs before they reach the model.
      Select <b style="color:#EE3325;">Prompt Injection</b> from the sidebar to test its effectiveness.
    </div>
    """
    st.markdown(diagram_html, unsafe_allow_html=True)

# ── Page: Configuration ──

if page == "Configuration":
    with st.container(border=True):
        st.header(":material/settings: Configuration")

        st.text_input(
            "Endpoint URL",
            value=os.getenv(
                "FORTIAIGATE_ENDPOINT",
                "http://k8s-fortiaigate-321fd6173c-711875050.us-west-2.elb.amazonaws.com/qwen/3_6_flash/chat/completions",
            ),
            key="endpoint",
        )

        st.text_input(
            "API key",
            value=os.getenv("FORTIAIGATE_API_KEY", ""),
            type="password",
            key="api_key",
        )

        st.slider("Delay between requests (seconds)", 0.0, 5.0, 1.0, 0.5, key="delay")
        st.slider("Request timeout (seconds)", 10, 120, 30, key="timeout")

        st.text_input(
            "CSV file path",
            value=st.session_state.csv_path,
            key="csv_path_input",
        )

    # Keep csv_path synced from the input widget
    if "csv_path_input" in st.session_state:
        st.session_state.csv_path = st.session_state.csv_path_input

# ── Page: Prompt Injection ──

if page == "Prompt Injection":
    # Read config from session state (set on Configuration page)
    endpoint = st.session_state.get("endpoint", os.getenv(
        "FORTIAIGATE_ENDPOINT",
        "http://k8s-fortiaigate-321fd6173c-711875050.us-west-2.elb.amazonaws.com/qwen/3_6_flash/chat/completions",
    ))
    api_key = st.session_state.get("api_key", os.getenv("FORTIAIGATE_API_KEY", ""))
    delay = st.session_state.get("delay", 1.0)
    timeout = st.session_state.get("timeout", 30)

    # ── Load prompts ──

    try:
        prompts = load_attack_prompts(st.session_state.csv_path)
        groups = group_by_attack_type(prompts)
        total = len(prompts)
        st.info(f"Loaded **{total}** test prompts across **{len(groups)}** attack types", icon=":material/info:")
    except FileNotFoundError:
        st.error(f"CSV file not found: `{st.session_state.csv_path}`", icon=":material/error:")
        prompts = []
        groups = {}

    # ── Batch "Run all" ──

    run_all_clicked = st.button(":material/play_arrow: Run all tests", type="primary", use_container_width=True)

    if run_all_clicked and prompts and api_key and endpoint:
        progress = st.progress(0, text="Running all tests...")
        status = st.empty()

        for i, p in enumerate(prompts):
            status.text(f"Sending {i + 1}/{total}: {p['attack_type']}")
            progress.progress(i / total, text=f"Testing {i + 1}/{total}...")

            sent = send_prompt(endpoint, api_key, p["prompt_text"], timeout=timeout)
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

        progress.progress(1.0, text="All tests completed")
        status.text("")
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
                        st.markdown(f"**Prompt:** {p['prompt_text']}")

                        col_send, col_result = st.columns([1, 3])
                        with col_send:
                            send_btn = st.button(
                                ":material/send: Send",
                                key=f"send_{idx}",
                                use_container_width=True,
                            )

                        result_ph = col_result.empty()

                        # ── Handle Send click: dim, send, resume ──
                        if send_btn:
                            # Clear old result so the card dims
                            st.session_state.results.pop(idx, None)
                            result_ph.caption(":shimmer[Sending request...]")

                            # Skeleton/dimmed state while request is in flight,
                            # then result appears when skeleton exits
                            with st.skeleton(height=40):
                                sent = send_prompt(endpoint, api_key, p["prompt_text"], timeout=timeout)
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

                            # Response expander inside the card
                            if st.session_state.results[idx]["response_text"]:
                                with st.expander("View response", icon=":material/visibility:"):
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

                                # Response expander inside the card
                                if result["response_text"]:
                                    with st.expander("View response", icon=":material/visibility:"):
                                        st.text(result["response_text"][:2000])
                            else:
                                result_ph.caption("Not yet tested — click Send")

            st.space("small")

    # ── Summary dashboard (shown after any results exist) ──

    if st.session_state.results:
        df = pd.DataFrame(st.session_state.results.values())

        total_tests = len(df)
        blocked = len(df[df["outcome"] == "Blocked"])
        through = len(df[df["outcome"] == "Through"])
        errors = len(df[df["outcome"] == "Error"])
        valid = total_tests - errors
        block_rate = blocked / valid * 100 if valid > 0 else 0

        with st.expander(":material/query_stats: Summary dashboard", expanded=False):
            # KPI row
            with st.container(horizontal=True):
                st.metric("Total tested", str(total_tests), border=True)
                st.metric("Blocked", str(blocked), f"{block_rate:.1f}%", border=True,
                          chart_data=[blocked], chart_type="bar")
                st.metric("Through", str(through), border=True)
                st.metric("Errors", str(errors), border=True)

            st.space("small")

            # Block rate per attack type
            valid_df = df[df["outcome"] != "Error"]
            if len(valid_df) > 0:
                attack_summary = (
                    valid_df.groupby("attack_type")
                    .apply(lambda g: pd.Series({
                        "Blocked": len(g[g["outcome"] == "Blocked"]),
                        "Through": len(g[g["outcome"] == "Through"]),
                        "Total": len(g),
                        "Block rate": len(g[g["outcome"] == "Blocked"]) / len(g) * 100,
                    }))
                    .reset_index()
                )

                with st.container(border=True):
                    st.subheader("Block rate per attack type")
                    st.bar_chart(attack_summary, x="attack_type", y="Block rate")
                    st.dataframe(attack_summary, hide_index=True)

            # Outcome distribution
            if len(valid_df) > 0:
                with st.container(border=True):
                    st.subheader("Outcome distribution")
                    outcome_counts = valid_df["outcome"].value_counts().reset_index()
                    outcome_counts.columns = ["Outcome", "Count"]
                    st.bar_chart(outcome_counts, x="Outcome", y="Count")

            # Export
            st.space("small")
            with st.container(horizontal_alignment="center"):
                csv_export = df.to_csv(index=False)
                st.download_button(
                    ":material/download: Download results as CSV",
                    csv_export,
                    "fortiaigate_attack_results.csv",
                    "text/csv",
                )
