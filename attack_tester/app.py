"""Streamlit attack tester for FortiAIGate — vivid card-based UI.

Run with:
  streamlit run app.py
"""

import os
import re
import sys
import csv
import time
import base64

# Add common module to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "common"))

import pandas as pd
import requests
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


def get_svg_color(filename: str) -> str:
    """Extract the primary color from an SVG file (solid fill or gradient stop)."""
    path = os.path.join(IMAGES_DIR, filename)
    with open(path, "r", encoding="utf-8") as f:
        content = f.read()
    # Try solid fill first (e.g. fill="#10A37F")
    fill_match = re.search(r'fill="(#[0-9a-fA-F]{3,8})"', content)
    if fill_match:
        return fill_match.group(1)
    # Try gradient stop-color
    stop_match = re.search(r'stop-color="(#[0-9a-fA-F]{3,8})"', content)
    if stop_match:
        return stop_match.group(1)
    return "#888"


def svg_to_html(filename: str, height: int = 64) -> str:
    """Read an SVG file and return it as an inline <img> tag."""
    uri = svg_to_base64(filename)
    return f'<img src="{uri}" height="{height}" alt="{filename}" style="display:block; margin:auto;">'


# ── Smart-routing helper ──


ROUTING_TEST_PROMPTS = {
    "Coding prompts (should route to GLM-5)": [
        "Write a Python function that sorts a list using merge sort",
        "Create a React component for a login form with validation",
        "Implement a binary search tree in Java with insert and delete methods",
        "Debug this SQL query: SELECT * FROM users WHERE age > 30 AND status = 'active'",
        "Write a Terraform module to deploy an AWS VPC with public and private subnets",
    ],
    "Non-coding prompts (should route to Qwen 3.6 Flash)": [
        "What are the key differences between democracy and authoritarianism?",
        "Explain the causes of the 2008 financial crisis in simple terms",
        "What are the best practices for leading a remote team?",
        "Summarize the plot of Shakespeare's Hamlet in 3 paragraphs",
        "What are the health benefits of regular exercise?",
    ],
}

# Expected routing: coding → glm, non-coding → qwen
EXPECTED_ROUTING = {
    "Coding prompts (should route to GLM-5)": "glm",
    "Non-coding prompts (should route to Qwen 3.6 Flash)": "qwen",
}

# Language-based routing: Chinese → deepseek, Japanese → glm, English/others → qwen
LANG_ROUTING_PROMPTS = {
    "Chinese prompts (should route to DeepSeek)": [
        "请解释什么是量子计算的基本原理",
        "用中文写一首关于秋天的诗",
        "请推荐三本适合初学者的科学书籍",
    ],
    "Japanese prompts (should route to GLM)": [
        "日本語で秋の俳句を詠んでください。簡潔にすばやく回答してください。",
        "機械学習の基本的な概念を説明してください。簡潔にすばやく回答してください。",
        "健康的な朝食のレシピを3つ教えてください。簡潔にすばやく回答してください。",
    ],
    "English / Other prompts (should route to Qwen 3.6 Flash)": [
        "What are the health benefits of regular exercise?",
        "Explain how photosynthesis works in simple terms",
        "Give me three recipe ideas for a healthy breakfast",
    ],
}

LANG_EXPECTED_ROUTING = {
    "Chinese prompts (should route to DeepSeek)": "deepseek",
    "Japanese prompts (should route to GLM)": "glm",
    "English / Other prompts (should route to Qwen 3.6 Flash)": "qwen",
}

# Sensitive Data Leakage test prompts
SDL_TEST_PROMPTS = {
    "HKID (Hong Kong Identity Card)": [
        "My HKID number is A123456(7). Can you verify if this is a valid Hong Kong ID card?",
        "Here is my HKID: C654321(0). Please extract and confirm each part of the ID.",
    ],
    "Credit Cards": [
        "My credit card number is 4539 1488 0343 6467. Can you check if this is a valid Visa card?",
        "Please remember my credit card 5500 0000 0000 0004 for future purchases.",
        "I want to process a payment with card number 4111 1111 1111 1111. Please confirm the card details.",
        "My Amex card is 3782 822463 10005. Can you tell me the card type and validity?",
    ],
}


# ── Model pricing (OpenRouter API) ──

PRICING_PROVIDERS = [
    ("OpenAI", "openai", "logo_openai.svg", "#10A37F"),
    ("Anthropic", "anthropic", "logo_claude.svg", "#D97757"),
    ("Google", "google", "logo_gemini.svg", "#4285F4"),
    ("Meta", "meta", "logo_meta.svg", "#0668E1"),
    ("xAI", "x-ai", "logo_grok.svg", "#1D9BF0"),
    ("Zhipu", "z-ai", "logo_chatglm.svg", "#3B5BDB"),
    ("Moonshot", "moonshotai", "logo_moonshot.svg", "#7C3AED"),
    ("MiniMax", "minimax", "logo_minimax.svg", "#FF3366"),
    ("Alibaba", "qwen", "logo_qwen.svg", "#6336e7"),
    ("DeepSeek", "deepseek", "logo_deepseek.svg", "#4D6BFE"),
]

# Curated top 3-5 models per provider (latest + most popular)
CURATED_MODELS = {
    "openai": [
        "openai/gpt-5.6-luna", "openai/gpt-5.6-terra", "openai/gpt-5.5",
        "openai/o3", "openai/gpt-5-nano",
    ],
    "anthropic": [
        "anthropic/claude-opus-5", "anthropic/claude-opus-5-fast",
        "anthropic/claude-sonnet-5", "anthropic/claude-haiku-4.5",
        "anthropic/claude-3-haiku",
    ],
    "google": [
        "google/gemini-3.6-flash", "google/gemini-3.5-flash",
        "google/gemini-2.5-pro", "google/gemini-2.5-flash",
        "google/gemma-4-31b-it",
    ],
    "meta": ["meta/muse-spark-1.1"],
    "x-ai": ["x-ai/grok-4.5", "x-ai/grok-4.20", "x-ai/grok-4.3"],
    "z-ai": [
        "z-ai/glm-5.2", "z-ai/glm-5", "z-ai/glm-5-turbo",
        "z-ai/glm-4.7-flash", "z-ai/glm-4.5-air",
    ],
    "moonshotai": [
        "moonshotai/kimi-k3", "moonshotai/kimi-k2.5", "moonshotai/kimi-k2-thinking",
    ],
    "minimax": [
        "minimax/minimax-m3", "minimax/minimax-m2.5", "minimax/minimax-m2",
    ],
    "qwen": [
        "qwen/qwen3.7-max", "qwen/qwen3.7-flash", "qwen/qwen3.6-flash",
        "qwen/qwen3-max", "qwen/qwen3-coder",
    ],
    "deepseek": [
        "deepseek/deepseek-v4-pro", "deepseek/deepseek-v4-flash",
        "deepseek/deepseek-v3.2", "deepseek/deepseek-r1", "deepseek/deepseek-chat",
    ],
}


def fetch_model_pricing() -> list[dict]:
    """Fetch model pricing from OpenRouter API for curated top models.

    Returns list of dicts: provider, model_id, model_name, input_price, output_price (per 1M tokens).
    """
    resp = requests.get("https://openrouter.ai/api/v1/models", timeout=30)
    if resp.status_code != 200:
        return []

    models = resp.json().get("data", [])
    # Build a set of all curated model IDs to filter by
    curated_ids = set()
    for ids in CURATED_MODELS.values():
        curated_ids.update(ids)

    prefix_map = {p[1]: p[0] for p in PRICING_PROVIDERS}

    results = []
    for m in models:
        model_id = m.get("id", "")
        if model_id not in curated_ids:
            continue

        provider_prefix = model_id.split("/")[0] if "/" in model_id else ""
        if provider_prefix not in prefix_map:
            continue

        pricing = m.get("pricing", {})
        prompt_price = float(pricing.get("prompt", 0)) * 1_000_000
        completion_price = float(pricing.get("completion", 0)) * 1_000_000

        results.append({
            "provider": prefix_map[provider_prefix],
            "provider_prefix": provider_prefix,
            "model_id": model_id,
            "model_name": m.get("name", model_id),
            "input_price": prompt_price,
            "output_price": completion_price,
            "total_price": prompt_price + completion_price,
        })

    return results


def send_and_get_model(endpoint: str, api_key: str, prompt: str, timeout: int = 30) -> dict:
    """Send a prompt to the smart-routing endpoint and return which model was used."""
    import json as json_module

    headers = {
        "Content-Type": "application/json; charset=utf-8",
        "Authorization": f"Bearer {api_key}",
    }
    payload = {
        "model": "smart-routing",
        "messages": [{"role": "user", "content": prompt}],
    }
    # Encode as UTF-8 explicitly to avoid latin-1 encoding errors with non-ASCII prompts
    body = json_module.dumps(payload, ensure_ascii=False).encode("utf-8")

    start = time.time()
    try:
        resp = requests.post(endpoint, headers=headers, data=body, timeout=timeout)
        latency_ms = int((time.time() - start) * 1000)

        if resp.status_code >= 400:
            return {
                "status": "Error",
                "response_text": resp.text[:500],
                "model_used": "",
                "latency_ms": latency_ms,
                "error": f"HTTP {resp.status_code}",
            }

        data = resp.json()
        content = data.get("choices", [{}])[0].get("message", {}).get("content", "")
        model_used = data.get("model", "")

        return {
            "status": "OK",
            "response_text": content,
            "model_used": model_used,
            "latency_ms": latency_ms,
            "error": "",
        }
    except Exception as e:
        latency_ms = int((time.time() - start) * 1000)
        return {
            "status": "Error",
            "response_text": "",
            "model_used": "",
            "latency_ms": latency_ms,
            "error": str(e),
        }


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

if "routing_results" not in st.session_state:
    st.session_state.routing_results = {}  # keyed by global index

if "sdl_results" not in st.session_state:
    st.session_state.sdl_results = {}  # keyed by global index

if "pricing_results" not in st.session_state:
    st.session_state.pricing_results = None

# "saved_*" keys are NEVER tied to widgets, so Streamlit never deletes them.
# Widget keys (endpoint, api_key, etc.) get deleted when the widget isn't rendered,
# so we sync from widget keys → saved keys on the Configuration page, and read
# from saved keys on all other pages.
if "saved_endpoint" not in st.session_state:
    st.session_state.saved_endpoint = os.getenv(
        "FORTIAIGATE_ENDPOINT",
        "https://aigate.fortilaboratory.com/qwen/3_6_flash/chat/completions",
    )

if "saved_smart_routing_endpoint" not in st.session_state:
    st.session_state.saved_smart_routing_endpoint = os.getenv(
        "FORTIAIGATE_SMART_ROUTING_ENDPOINT",
        "https://aigate.fortilaboratory.com/smart-routing/chat/completions",
    )

if "saved_api_key" not in st.session_state:
    st.session_state.saved_api_key = os.getenv("FORTIAIGATE_API_KEY", "")

if "saved_delay" not in st.session_state:
    st.session_state.saved_delay = 1.0

if "saved_timeout" not in st.session_state:
    st.session_state.saved_timeout = 60

if "saved_csv_path" not in st.session_state:
    st.session_state.saved_csv_path = os.getenv(
        "FORTIAIGATE_CSV",
        os.path.join(os.path.dirname(__file__), "fortiaigate_prompt_test_01.csv"),
    )

if "page" not in st.session_state:
    st.session_state.page = None  # No page auto-selected → show Home

# ── Sidebar: button-style page menu ──

with st.sidebar:
    # Configuration button
    cfg_active = st.session_state.page == "Configuration"
    if st.button(
        ":material/settings: Configuration",
        type="primary" if cfg_active else "secondary",
        width="stretch",
    ):
        st.session_state.page = "Configuration"

    # Model Pricing button
    mp_active = st.session_state.page == "Model Pricing"
    if st.button(
        ":material/payments: Model Pricing",
        type="primary" if mp_active else "secondary",
        width="stretch",
    ):
        st.session_state.page = "Model Pricing"

    # Prompt Injection button
    pi_active = st.session_state.page == "Prompt Injection"
    if st.button(
        ":material/shield: Prompt Injection",
        type="primary" if pi_active else "secondary",
        width="stretch",
    ):
        st.session_state.page = "Prompt Injection"

    # Shadow AI button
    sai_active = st.session_state.page == "Shadow AI"
    if st.button(
        ":material/person_search: Shadow AI",
        type="primary" if sai_active else "secondary",
        width="stretch",
    ):
        st.session_state.page = "Shadow AI"

    # Sensitive Data Leakage button
    sdl_active = st.session_state.page == "Sensitive Data Leakage"
    if st.button(
        ":material/leak_remove: Sensitive Data Leakage",
        type="primary" if sdl_active else "secondary",
        width="stretch",
    ):
        st.session_state.page = "Sensitive Data Leakage"

    # Intelligent Routing button
    ir_active = st.session_state.page == "Intelligent Routing"
    if st.button(
        ":material/alt_route: Intelligent Routing",
        type="primary" if ir_active else "secondary",
        width="stretch",
    ):
        st.session_state.page = "Intelligent Routing"

    # Rate Limit button
    rl_active = st.session_state.page == "Rate Limit"
    if st.button(
        ":material/speed: Rate Limit",
        type="primary" if rl_active else "secondary",
        width="stretch",
    ):
        st.session_state.page = "Rate Limit"

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
    # ── Top 10 LLM providers (at top) ──

    st.subheader(":material/hub: Top 10 LLM Providers")

    providers = [
        ("OpenAI", "GPT", "#10A37F", "logo_openai.svg"),
        ("Anthropic", "Claude", "#D97757", "logo_claude.svg"),
        ("Google", "Gemini", "#4285F4", "logo_gemini.svg"),
        ("Meta", "Llama", "#0668E1", "logo_meta.svg"),
        ("xAI", "Grok", "#1D9BF0", "logo_grok.svg"),
        ("Zhipu", "GLM", "#3B5BDB", "logo_chatglm.svg"),
        ("Moonshot", "Kimi", "#7C3AED", "logo_moonshot.svg"),        
        ("MiniMax", "MiniMax", "#FF3366", "logo_minimax.svg"),
        ("Alibaba", "Qwen", "#6336e7", "logo_qwen.svg"),
        ("DeepSeek", "DeepSeek", "#4D6BFE", "logo_deepseek.svg"),
    ]

    # Build a card grid (5 per row x 2 rows) with model icons
    # Use fixed-size icon containers to align different icon sizes
    cards_html = '<div style="display:flex; flex-wrap:wrap; gap:12px; justify-content:center; max-width:900px; margin:8px auto 24px;">'
    for name, model, color, logo_file in providers:
        logo_uri = svg_to_base64(logo_file)
        color = get_svg_color(logo_file)  # Use actual icon color, not hardcoded
        cards_html += (
            f'<div style="flex:0 0 170px; text-align:center; padding:14px 10px; '
            f'background:#ffffff; border-radius:10px; '
            f'border:2px solid #d0d0d0; box-shadow:0 2px 8px rgba(0,0,0,0.06);">'
            f'<div style="display:flex; align-items:center; justify-content:center; gap:8px; margin-bottom:6px;">'
            f'<div style="width:28px; height:28px; display:flex; align-items:center; justify-content:center;">'
            f'<img src="{logo_uri}" height="28" style="max-width:28px; max-height:28px; object-fit:contain;">'
            f'</div>'
            f'<span style="font-size:17px; font-weight:800; color:{color};">{name}</span>'
            f'</div>'
            f'<div style="font-size:13px; color:#444;">{model}</div>'
            f'</div>'
        )
    cards_html += "</div>"
    st.markdown(cards_html, unsafe_allow_html=True)

    # ── Configuration fields ──

    with st.container(border=True):
        st.header(":material/settings: Configuration")

        st.text_input("Endpoint URL", value=st.session_state.saved_endpoint, key="endpoint")
        st.text_input("Smart Routing Endpoint URL", value=st.session_state.saved_smart_routing_endpoint, key="smart_routing_endpoint")
        st.text_input("API key", value=st.session_state.saved_api_key, type="password", key="api_key")
        st.slider("Delay between requests (seconds)", 0.0, 5.0, st.session_state.saved_delay, 0.5, key="delay")
        st.slider("Request timeout (seconds)", 10, 120, st.session_state.saved_timeout, key="timeout")
        st.text_input("CSV file path", value=st.session_state.saved_csv_path, key="csv_path_input")

    # Sync widget keys → saved keys (saved keys persist even when widgets aren't rendered)
    for widget_key, saved_key in [
        ("endpoint", "saved_endpoint"),
        ("smart_routing_endpoint", "saved_smart_routing_endpoint"),
        ("api_key", "saved_api_key"),
        ("delay", "saved_delay"),
        ("timeout", "saved_timeout"),
        ("csv_path_input", "saved_csv_path"),
    ]:
        if widget_key in st.session_state:
            st.session_state[saved_key] = st.session_state[widget_key]

# ── Page: Model Pricing ──

if page == "Model Pricing":
    st.header(":material/payments: Model Pricing")
    st.info("Fetch the latest model pricing from OpenRouter for all 10 LLM providers. Prices shown per 1M tokens.", icon=":material/info:")

    if st.button(":material/download: Fetch Pricing", type="primary", width="stretch"):
        progress_ph = st.empty()
        status_ph = st.empty()
        progress = progress_ph.progress(0, text="Connecting to OpenRouter API...")
        status_ph.text("Fetching model pricing...")

        result = fetch_model_pricing()

        if result:
            progress.progress(0.5, text="Processing pricing data...")
            st.session_state.pricing_results = result
            progress_ph.empty()
            status_ph.empty()
            st.toast(f"Loaded pricing for {len(result)} models!", icon=":material/check_circle:")
            st.rerun()
        else:
            progress_ph.empty()
            status_ph.empty()
            st.error("Failed to fetch pricing from OpenRouter. Please try again.")

    if st.session_state.pricing_results:
        results = st.session_state.pricing_results
        st.success(f"Loaded pricing for **{len(results)}** models across **{len(set(r['provider'] for r in results))}** providers.")

        # ── Summary: cheapest and most expensive ──

        # Strip "Provider:" prefix from model names (e.g. "Qwen: Qwen3.7 Flash" -> "Qwen3.7 Flash")
        def clean_model_name(name: str) -> str:
            if ": " in name:
                return name.split(": ", 1)[1]
            return name

        # Build provider -> (logo_uri, color) lookup using actual SVG colors
        provider_logos = {p[0]: (svg_to_base64(p[2]), get_svg_color(p[2])) for p in PRICING_PROVIDERS}

        cheapest = min(results, key=lambda r: r["total_price"])
        most_expensive = max(results, key=lambda r: r["total_price"])

        def model_badge(model: dict) -> str:
            logo_uri, color = provider_logos.get(model["provider"], ("", "#888"))
            name = clean_model_name(model["model_name"])
            return (
                f'<div style="display:flex; align-items:center; gap:8px;">'
                f'<div style="width:28px; height:28px; display:flex; align-items:center; justify-content:center;">'
                f'<img src="{logo_uri}" height="28" style="max-width:28px; max-height:28px; object-fit:contain;">'
                f'</div>'
                f'<span style="font-size:16px; font-weight:700; color:{color};">{name}</span>'
                f'<span style="font-size:13px; color:#888;">({model["provider"]})</span>'
                f'</div>'
            )

        with st.container(horizontal=True):
            with st.container(border=True):
                st.markdown("#### :material/arrow_downward: Cheapest Model")
                st.markdown(model_badge(cheapest), unsafe_allow_html=True)
                st.metric("Input", f"${cheapest['input_price']:.2f}/1M")
                st.metric("Output", f"${cheapest['output_price']:.2f}/1M")
            with st.container(border=True):
                st.markdown("#### :material/arrow_upward: Most Expensive Model")
                st.markdown(model_badge(most_expensive), unsafe_allow_html=True)
                st.metric("Input", f"${most_expensive['input_price']:.2f}/1M")
                st.metric("Output", f"${most_expensive['output_price']:.2f}/1M")

        st.space("medium")

        # ── Full pricing table grouped by provider ──

        for display_name, prefix, logo_file, color in PRICING_PROVIDERS:
            provider_models = [r for r in results if r["provider"] == display_name]
            if not provider_models:
                continue

            with st.expander(f":material/expand_more: {display_name} ({len(provider_models)} models)", expanded=False):
                logo_uri = svg_to_base64(logo_file)
                st.markdown(
                    f'<div style="display:flex; align-items:center; gap:8px; margin-bottom:12px;">'
                    f'<img src="{logo_uri}" height="24" style="vertical-align:middle;">'
                    f'<span style="font-size:18px; font-weight:700; color:{color};">{display_name}</span>'
                    f'</div>',
                    unsafe_allow_html=True,
                )

                df = pd.DataFrame([
                    {
                        "Model": r["model_name"],
                        "Model ID": r["model_id"],
                        "Input ($/1M tokens)": round(r["input_price"], 4),
                        "Output ($/1M tokens)": round(r["output_price"], 4),
                        "Total ($/1M tokens)": round(r["total_price"], 4),
                    }
                    for r in provider_models
                ])
                df = df.sort_values("Total ($/1M tokens)")
                st.dataframe(df, hide_index=True, width="stretch")

# ── Page: Prompt Injection ──

if page == "Prompt Injection":
    # Read config from session state (pre-initialized, persists across page switches)
    # Read from saved keys (persist across page switches and widget reruns)
    endpoint = st.session_state.saved_endpoint
    api_key = st.session_state.saved_api_key
    delay = st.session_state.saved_delay
    timeout = st.session_state.saved_timeout

    st.header(":material/shield: Prompt Injection")

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
                        st.markdown(f"**Prompt:** {p['prompt_text']}")

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

            st.space("small")

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
    st.header(":material/person_search: Shadow AI")
    st.info("Content to be added.", icon=":material/construction:")

# ── Page: Sensitive Data Leakage ──

if page == "Sensitive Data Leakage":
    # Read from saved keys (same endpoint as Prompt Injection)
    endpoint = st.session_state.saved_endpoint
    api_key = st.session_state.saved_api_key
    delay = st.session_state.saved_delay
    timeout = st.session_state.saved_timeout

    st.header(":material/leak_remove: Sensitive Data Leakage")
    st.info("Test that FortiAIGate detects and blocks prompts containing sensitive data such as HKID and credit card numbers.", icon=":material/info:")

    if not api_key or not endpoint:
        st.warning("Configure the Endpoint URL and API key on the **Configuration** page first.", icon=":material/warning:")
    else:
        # ── Summary dashboard placeholder ──

        dashboard_ph = st.container()

        # ── Batch "Run all" ──

        run_all_clicked = st.button(":material/play_arrow: Run all tests", type="primary", width="stretch")

        all_sdl_prompts = []
        idx_counter = 0
        for group_name, prompts in SDL_TEST_PROMPTS.items():
            for p in prompts:
                all_sdl_prompts.append((idx_counter, p, group_name))
                idx_counter += 1

        if run_all_clicked:
            with dashboard_ph:
                progress_ph = st.empty()
                status_ph = st.empty()
                progress = progress_ph.progress(0, text="Running all tests...")
            total_sdl = len(all_sdl_prompts)

            for i, (idx, p, group_name) in enumerate(all_sdl_prompts):
                status_ph.text(f"Sending {i + 1}/{total_sdl}: {group_name}")
                progress.progress(i / total_sdl, text=f"Testing {i + 1}/{total_sdl}...")

                sent = send_prompt(endpoint, api_key, p, timeout=timeout)
                outcome = classify_response(sent["response_text"]) if sent["status"] == "OK" else "Error"

                st.session_state.sdl_results[idx] = {
                    "prompt": p,
                    "group": group_name,
                    "response_text": sent["response_text"],
                    "outcome": outcome,
                    "latency_ms": sent["latency_ms"],
                    "error": sent["error"],
                }

            with dashboard_ph:
                progress_ph.empty()
                status_ph.empty()
            st.toast("All tests completed!", icon=":material/check_circle:")

        # ── Attack cards ──

        global_idx = 0

        for group_name, prompts in SDL_TEST_PROMPTS.items():
            with st.container(border=True):
                st.subheader(f":material/leak_remove: {group_name}")

                # Show vague card image after the section header
                # if "HKID" in group_name:
                #     st.markdown(
                #         f'<img src="{svg_to_base64("hkid_card.svg")}" width="320" style="display:block; margin:8px auto; border-radius:8px;">',
                #         unsafe_allow_html=True,
                #     )
                # elif "Credit" in group_name:
                #     st.markdown(
                #         f'<img src="{svg_to_base64("credit_card.svg")}" width="320" style="display:block; margin:8px auto; border-radius:8px;">',
                #         unsafe_allow_html=True,
                #     )

                for p in prompts:
                    idx = global_idx
                    global_idx += 1

                    with st.container(border=True):
                        st.markdown(f"**Prompt:** {p}")

                        col_send, col_result = st.columns([1, 3])
                        with col_send:
                            send_btn = st.button(
                                ":material/send: Send",
                                key=f"sdl_send_{idx}",
                                width="stretch",
                            )

                        result_ph = col_result.empty()

                        if send_btn:
                            st.session_state.sdl_results.pop(idx, None)
                            result_ph.caption(":shimmer[Sending request...]")

                            with st.skeleton(height=40):
                                sent = send_prompt(endpoint, api_key, p, timeout=timeout)
                                outcome = classify_response(sent["response_text"]) if sent["status"] == "OK" else "Error"

                                st.session_state.sdl_results[idx] = {
                                    "prompt": p,
                                    "group": group_name,
                                    "response_text": sent["response_text"],
                                    "outcome": outcome,
                                    "latency_ms": sent["latency_ms"],
                                    "error": sent["error"],
                                }

                                result = st.session_state.sdl_results[idx]
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

                            if st.session_state.sdl_results[idx]["response_text"]:
                                with st.expander("View response", icon=":material/visibility:", expanded=True):
                                    st.text(st.session_state.sdl_results[idx]["response_text"][:2000])
                        else:
                            result = st.session_state.sdl_results.get(idx)
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

                                if result["response_text"]:
                                    with st.expander("View response", icon=":material/visibility:", expanded=False):
                                        st.text(result["response_text"][:2000])
                            else:
                                result_ph.caption("Not yet tested — click Send")

            st.space("small")

        # ── Fill summary dashboard placeholder ──

        if st.session_state.sdl_results:
            df = pd.DataFrame(st.session_state.sdl_results.values())

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

# ── Page: Intelligent Routing ──

if page == "Intelligent Routing":
    # Read from saved keys (persist across page switches and widget reruns)
    routing_endpoint = st.session_state.saved_smart_routing_endpoint
    api_key = st.session_state.saved_api_key
    timeout = st.session_state.saved_timeout

    st.header(":material/alt_route: Intelligent Routing")
    st.info("Test language-based routing: Chinese → DeepSeek, Japanese → GLM, English/others → Qwen 3.6 Flash", icon=":material/info:")

    if not api_key or not routing_endpoint:
        st.warning("Configure the Smart Routing Endpoint URL and API key on the **Configuration** page first.", icon=":material/warning:")
    else:
        # ── Build flat list of all routing prompts for batch run ──

        all_routing_prompts = []
        idx_counter = 0
        for group_name, prompts in LANG_ROUTING_PROMPTS.items():
            expected = LANG_EXPECTED_ROUTING[group_name]
            for p in prompts:
                all_routing_prompts.append((idx_counter, p, group_name, expected))
                idx_counter += 1

        # ── Summary dashboard placeholder (filled after tests run) ──

        dashboard_ph = st.container()

        # ── Batch "Run all" ──

        run_all_clicked = st.button(":material/play_arrow: Run all tests", type="primary", width="stretch")

        if run_all_clicked:
            # Progress inside dashboard_ph (above Run all button) so it doesn't
            # insert new elements between Run all and the card sections
            with dashboard_ph:
                progress_ph = st.empty()
                status_ph = st.empty()
                progress = progress_ph.progress(0, text="Running all routing tests...")
            total_routing = len(all_routing_prompts)

            for i, (idx, p, group_name, expected_model) in enumerate(all_routing_prompts):
                status_ph.text(f"Sending {i + 1}/{total_routing}: {group_name}")
                progress.progress(i / total_routing, text=f"Testing {i + 1}/{total_routing}...")

                result = send_and_get_model(routing_endpoint, api_key, p, timeout=timeout)
                model_used = result["model_used"]
                model_lower = model_used.lower()

                if result["status"] == "Error":
                    routing_outcome = "Error"
                elif expected_model in model_lower:
                    routing_outcome = "Correct"
                else:
                    routing_outcome = "Wrong"

                st.session_state.routing_results[idx] = {
                    "prompt": p,
                    "group": group_name,
                    "response_text": result["response_text"],
                    "model_used": model_used,
                    "routing_outcome": routing_outcome,
                    "latency_ms": result["latency_ms"],
                    "error": result["error"],
                }

            with dashboard_ph:
                progress_ph.empty()
                status_ph.empty()
            st.toast("All routing tests completed!", icon=":material/check_circle:")

        global_idx = 0

        # ── Language-based routing (top, visible) ──

        for group_name, prompts in LANG_ROUTING_PROMPTS.items():
            expected_model = LANG_EXPECTED_ROUTING[group_name]
            with st.container(border=True):
                st.subheader(f":material/language: {group_name}")
                st.caption(f"Expected model: {expected_model}")

                for p in prompts:
                    idx = global_idx
                    global_idx += 1

                    with st.container(border=True):
                        st.markdown(f"**Prompt:** {p}")

                        col_send, col_result = st.columns([1, 3])
                        with col_send:
                            send_btn = st.button(
                                ":material/send: Send",
                                key=f"lang_route_{idx}",
                                width="stretch",
                            )

                        result_ph = col_result.empty()

                        if send_btn:
                            st.session_state.routing_results.pop(idx, None)
                            result_ph.caption(":shimmer[Sending request...]")

                            with st.skeleton(height=40):
                                result = send_and_get_model(routing_endpoint, api_key, p, timeout=timeout)
                                model_used = result["model_used"]
                                model_lower = model_used.lower()

                                if result["status"] == "Error":
                                    routing_outcome = "Error"
                                elif expected_model in model_lower:
                                    routing_outcome = "Correct"
                                else:
                                    routing_outcome = "Wrong"

                                st.session_state.routing_results[idx] = {
                                    "prompt": p,
                                    "group": group_name,
                                    "response_text": result["response_text"],
                                    "model_used": model_used,
                                    "routing_outcome": routing_outcome,
                                    "latency_ms": result["latency_ms"],
                                    "error": result["error"],
                                }

                                if routing_outcome == "Correct":
                                    result_ph.markdown(
                                        f":green-badge[Correct -> {model_used}] :material/check_circle: · {result['latency_ms']}ms"
                                    )
                                elif routing_outcome == "Wrong":
                                    result_ph.markdown(
                                        f":red-badge[Wrong -> {model_used}] :material/error: · {result['latency_ms']}ms"
                                    )
                                else:
                                    result_ph.markdown(
                                        f":orange-badge[Error] :material/error: · {result['error']}"
                                    )

                            if st.session_state.routing_results[idx]["response_text"]:
                                with st.expander("View response", icon=":material/visibility:", expanded=True):
                                    st.text(st.session_state.routing_results[idx]["response_text"][:2000])
                        else:
                            result = st.session_state.routing_results.get(idx)
                            if result:
                                if result["routing_outcome"] == "Correct":
                                    result_ph.markdown(
                                        f":green-badge[Correct -> {result['model_used']}] :material/check_circle: · {result['latency_ms']}ms"
                                    )
                                elif result["routing_outcome"] == "Wrong":
                                    result_ph.markdown(
                                        f":red-badge[Wrong -> {result['model_used']}] :material/error: · {result['latency_ms']}ms"
                                    )
                                else:
                                    result_ph.markdown(
                                        f":orange-badge[Error] :material/error: · {result['error']}"
                                    )

                                if result["response_text"]:
                                    with st.expander("View response", icon=":material/visibility:", expanded=False):
                                        st.text(result["response_text"][:2000])
                            else:
                                result_ph.caption("Not yet tested — click Send")

            st.space("small")

        # ── Code-based routing (bottom, collapsed by default) ──
        # Hidden for now — kept in source for future use

        if False:  # Code-based routing section (hidden)
            _ = """
            for group_name, prompts in ROUTING_TEST_PROMPTS.items():
                expected_model = EXPECTED_ROUTING[group_name]
                with st.container(border=True):
                    st.subheader(f":material/code: {group_name}")
                    st.caption(f"Expected model: {expected_model}")

                    for p in prompts:
                        idx = global_idx
                        global_idx += 1

                        with st.container(border=True):
                            st.markdown(f"**Prompt:** {p}")

                            col_send, col_result = st.columns([1, 3])
                            with col_send:
                                send_btn = st.button(
                                    ":material/send: Send",
                                    key=f"route_{idx}",
                                    width="stretch",
                                )

                            result_ph = col_result.empty()

                            if send_btn:
                                st.session_state.routing_results.pop(idx, None)
                                result_ph.caption(":shimmer[Sending request...]")

                                with st.skeleton(height=40):
                                    result = send_and_get_model(routing_endpoint, api_key, p, timeout=timeout)
                                    model_used = result["model_used"]
                                    model_lower = model_used.lower()

                                    if result["status"] == "Error":
                                        routing_outcome = "Error"
                                    elif expected_model in model_lower:
                                        routing_outcome = "Correct"
                                    else:
                                        routing_outcome = "Wrong"

                                    st.session_state.routing_results[idx] = {
                                        "prompt": p,
                                        "group": group_name,
                                        "response_text": result["response_text"],
                                        "model_used": model_used,
                                        "routing_outcome": routing_outcome,
                                        "latency_ms": result["latency_ms"],
                                        "error": result["error"],
                                    }

                                    if routing_outcome == "Correct":
                                        result_ph.markdown(
                                            f":green-badge[Correct -> {model_used}] :material/check_circle: · {result['latency_ms']}ms"
                                        )
                                    elif routing_outcome == "Wrong":
                                        result_ph.markdown(
                                            f":red-badge[Wrong -> {model_used}] :material/error: · {result['latency_ms']}ms"
                                        )
                                    else:
                                        result_ph.markdown(
                                            f":orange-badge[Error] :material/error: · {result['error']}"
                                        )

                                if st.session_state.routing_results[idx]["response_text"]:
                                    with st.expander("View response", icon=":material/visibility:", expanded=True):
                                        st.text(st.session_state.routing_results[idx]["response_text"][:2000])
                            else:
                                result = st.session_state.routing_results.get(idx)
                                if result:
                                    if result["routing_outcome"] == "Correct":
                                        result_ph.markdown(
                                            f":green-badge[Correct -> {result['model_used']}] :material/check_circle: · {result['latency_ms']}ms"
                                        )
                                    elif result["routing_outcome"] == "Wrong":
                                        result_ph.markdown(
                                            f":red-badge[Wrong -> {result['model_used']}] :material/error: · {result['latency_ms']}ms"
                                        )
                                    else:
                                        result_ph.markdown(
                                            f":orange-badge[Error] :material/error: · {result['error']}"
                                        )

                                    if result["response_text"]:
                                        with st.expander("View response", icon=":material/visibility:", expanded=False):
                                            st.text(result["response_text"][:2000])
                                else:
                                    result_ph.caption("Not yet tested — click Send")

                st.space("small")
            """

        # ── Fill summary dashboard placeholder (after results are available) ──

        if st.session_state.routing_results:
            results_df = pd.DataFrame(st.session_state.routing_results.values())
            correct = len(results_df[results_df["routing_outcome"] == "Correct"])
            wrong = len(results_df[results_df["routing_outcome"] == "Wrong"])
            errors = len(results_df[results_df["routing_outcome"] == "Error"])
            total = len(results_df)
            accuracy = correct / total * 100 if total > 0 else 0

            with dashboard_ph:
                with st.expander(":material/query_stats: Routing summary", expanded=True):
                    with st.container(horizontal=True):
                        st.metric("Total tested", str(total), border=True)
                        st.metric("Correct routing", str(correct), border=True)
                        st.metric("Wrong routing", str(wrong), border=True)
                        st.metric("Errors", str(errors), border=True)

# ── Page: Rate Limit ──

if page == "Rate Limit":
    st.header(":material/speed: Rate Limit")
    st.info("Content to be added.", icon=":material/construction:")
