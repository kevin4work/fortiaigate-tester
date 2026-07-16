"""Streamlit UI for FortiAIGate bulk security testing.

Run with:
  streamlit run app.py
"""

import os
import sys
import time

# Add common module to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "common"))

import pandas as pd
import streamlit as st
from fortiaigate_test import load_prompts, classify_response, send_prompt

st.set_page_config(page_title="FortiAIGate Security Tester", layout="wide")

# ── Sidebar ──
with st.sidebar:
    st.header("Configuration")

    endpoint = st.text_input(
        "Endpoint URL",
        value=os.getenv(
            "FORTIAIGATE_ENDPOINT",
            "http://k8s-fortiaigate-321fd6173c-711875050.us-west-2.elb.amazonaws.com/qwen/3_6_flash/chat/completions",
        ),
    )

    api_key = st.text_input(
        "API Key",
        value=os.getenv("FORTIAIGATE_API_KEY", ""),
        type="password",
    )

    delay = st.slider("Delay between requests (seconds)", 0.0, 5.0, 1.0, 0.5)
    timeout = st.slider("Request timeout (seconds)", 10, 120, 30)

    csv_path = st.text_input(
        "CSV file path",
        value=os.getenv(
            "FORTIAIGATE_CSV",
            os.path.join(os.path.dirname(__file__), "AI_Security_Testing_Guide.csv"),
        ),
    )

    st.divider()
    st.caption("FortiAIGate POC Security Tester")

# ── Main area ──
st.title("🛡️ FortiAIGate Security Tester")
st.markdown("Test how effectively FortiAIGate blocks malicious prompts across LLM, Agentic AI, and MCP risk categories.")

# Load prompts
try:
    prompts = load_prompts(csv_path)
    st.info(f"Loaded **{len(prompts)}** test prompts from `{csv_path}`")
except FileNotFoundError:
    st.error(f"CSV file not found: `{csv_path}`. Place it in the same directory or set the path in the sidebar.")
    prompts = []

if not api_key:
    st.warning("Enter an API Key in the sidebar to proceed.")

if prompts and api_key and endpoint:
    # Show prompt overview
    with st.expander("📋 View loaded prompts"):
        preview_df = pd.DataFrame(prompts)
        st.dataframe(preview_df, use_container_width=True)

    # Run button
    if st.button("🚀 Run All Tests", type="primary"):
        # Placeholder for progress
        progress_bar = st.progress(0, text="Starting tests...")
        status_text = st.empty()

        results = []
        total = len(prompts)

        for i, p in enumerate(prompts):
            status_text.text(f"Sending prompt {i + 1}/{total}: {p['risk_id']} — {p['prompt_column']}")
            progress_bar.progress(i / total, text=f"Testing {i + 1}/{total}...")

            sent = send_prompt(endpoint, api_key, p["prompt_text"], timeout=timeout)
            outcome = classify_response(sent["response_text"]) if sent["status"] == "OK" else "Error"

            results.append({
                **p,
                "response_text": sent["response_text"],
                "outcome": outcome,
                "latency_ms": sent["latency_ms"],
                "error": sent["error"],
            })

            if delay > 0 and i < total - 1:
                time.sleep(delay)

        progress_bar.progress(1.0, text="Done!")
        status_text.text("All tests completed.")

        # Store results in session state so they persist across interactions
        st.session_state["results"] = results

    # ── Results display ──
    if "results" in st.session_state:
        results = st.session_state["results"]
        df = pd.DataFrame(results)

        # ── Summary metrics ──
        st.subheader("📊 Summary")

        total_tests = len(df)
        blocked = len(df[df["outcome"] == "Blocked"])
        through = len(df[df["outcome"] == "Through"])
        errors = len(df[df["outcome"] == "Error"])
        valid = total_tests - errors
        block_rate = blocked / valid * 100 if valid > 0 else 0

        col1, col2, col3, col4 = st.columns(4)
        col1.metric("Total Tests", total_tests)
        col2.metric("Blocked ✅", blocked, f"{block_rate:.1f}%")
        col3.metric("Through ⚠️", through)
        col4.metric("Errors 🔴", errors)

        # ── Category breakdown ──
        st.subheader("📂 By Category")

        valid_df = df[df["outcome"] != "Error"]
        cat_summary = (
            valid_df.groupby("category")
            .apply(lambda g: pd.Series({
                "Blocked": len(g[g["outcome"] == "Blocked"]),
                "Through": len(g[g["outcome"] == "Through"]),
                "Block Rate": f"{len(g[g['outcome'] == 'Blocked']) / len(g) * 100:.1f}%",
            }))
            .reset_index()
        )
        st.dataframe(cat_summary, use_container_width=True)

        # ── Outcome distribution chart ──
        st.subheader("📈 Outcome Distribution")
        outcome_counts = valid_df["outcome"].value_counts()
        st.bar_chart(outcome_counts)

        # ── Block rate per Risk ID ──
        st.subheader("🛡️ Block Rate per Risk ID")
        risk_summary = (
            valid_df.groupby(["category", "risk_id", "title"])
            .apply(lambda g: pd.Series({
                "Blocked": len(g[g["outcome"] == "Blocked"]),
                "Through": len(g[g["outcome"] == "Through"]),
                "Block Rate": f"{len(g[g['outcome'] == 'Blocked']) / len(g) * 100:.1f}%",
            }))
            .reset_index()
        )
        st.dataframe(risk_summary, use_container_width=True)

        # ── Detailed results ──
        st.subheader("🔍 Detailed Results")

        # Filters
        filter_col1, filter_col2 = st.columns(2)
        categories = df["category"].unique().tolist()
        selected_cat = filter_col1.multiselect("Filter by Category", categories, categories)
        outcomes = ["Blocked", "Through", "Error"]
        selected_outcome = filter_col2.multiselect("Filter by Outcome", outcomes, outcomes)

        filtered = df[df["category"].isin(selected_cat) & df["outcome"].isin(selected_outcome)]

        # Show each result with expandable detail
        for _, row in filtered.iterrows():
            outcome_icon = {
                "Blocked": "✅",
                "Through": "⚠️",
                "Error": "🔴",
            }.get(row["outcome"], "")

            with st.expander(f"{outcome_icon} {row['risk_id']} — {row['title']} ({row['prompt_column']})"):
                st.markdown(f"**Prompt:** {row['prompt_text']}")
                st.markdown(f"**Outcome:** {row['outcome']} | **Latency:** {row['latency_ms']}ms")
                if row["error"]:
                    st.error(f"Error: {row['error']}")
                if row["response_text"]:
                    st.markdown("**Response:**")
                    st.text(row["response_text"][:2000])

        # ── Export ──
        st.subheader("💾 Export")
        csv_export = df.to_csv(index=False)
        st.download_button(
            "Download results as CSV",
            csv_export,
            "fortiaigate_test_results.csv",
            "text/csv",
        )
