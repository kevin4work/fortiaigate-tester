"""Shared navigation and visual shell for the testing workspace."""

import html

import streamlit as st


NAVIGATION = (
    ("WORKSPACE", (("Overview", "home"), ("Configuration", "settings"), ("Budget Control", "account_balance_wallet"),
                   ("Rate Limit", "speed"))),
    ("TEST SUITES", (("Prompt Injection", "shield"),
                     ("Sensitive Data", "privacy_tip"), ("Garak Testing", "radar"))),
    ("PLANNED", (("Shadow AI", "person_search"),)),
)


def apply_theme():
    st.markdown("""
<style>
.stApp { background:#0d1117; color:#f0f3f6; }
label { color:#f0f3f6 !important; }
[data-testid="stMainBlockContainer"] { max-width:1500px; padding-top:4rem; }
[data-testid="stHeader"] { background:#0d1117; }
[data-testid="stSidebar"] { background:#10151b; border-right:1px solid #30363d; }
[data-testid="stSidebar"] .stButton button {
    width:100%; justify-content:flex-start; text-align:left; padding:10px 12px;
    background:transparent; color:#a8b3c2; border:1px solid transparent;
    border-radius:6px; min-height:42px; box-shadow:none;
}
[data-testid="stSidebar"] .stButton button:hover { background:#1b222c; color:#f0f3f6; }
[data-testid="stSidebar"] .stButton button[kind="primary"] {
    color:#f0f3f6; background:#2c1c20; border-color:#67302b;
    box-shadow:inset 3px 0 #EE3124;
}
[data-testid="stSidebar"] .stButton p { font-size:13px; font-weight:500; }
.brand { font-size:24px; font-weight:750; letter-spacing:-.8px; margin-bottom:4px; }
.brand-mark { color:#EE3124; margin-right:9px; }
.brand-caption,.nav-group { font-size:10px; letter-spacing:1.5px; color:#8b98a9; }
.brand-caption { margin-bottom:25px; }
.nav-group { margin:21px 0 6px 12px; font-weight:600; }
.sidebar-footer { color:#8b98a9; font-size:11px; border-top:1px solid #30363d; padding-top:18px; margin-top:35px; }
.breadcrumb { color:#a8b3c2; font-size:12px; padding-bottom:16px; margin-bottom:22px; border-bottom:1px solid #30363d; }
.breadcrumb span { padding:0 12px; color:#8b98a9; }
.breadcrumb strong { color:#f0f3f6; font-weight:500; }
h1 { font-size:29px !important; font-weight:650 !important; letter-spacing:-.7px; }
h2 { font-size:20px !important; }
h3 { font-size:16px !important; }
[data-testid="stVerticalBlockBorderWrapper"] > div { border-color:#30363d; }
[data-testid="stBaseButton-primary"] { background:#ce291e; border-color:#ce291e; color:white; }
[data-testid="stBaseButton-primary"]:hover { background:#b92219; border-color:#b92219; color:white; }
[data-testid="stCaptionContainer"] { color:#8b98a9; }
.planned { min-height:350px; display:flex; flex-direction:column; align-items:center; justify-content:center; text-align:center; }
.planned-icon { font-size:32px; margin-bottom:20px; }
.planned h2 { font-size:25px !important; }
.planned p { color:#a8b3c2; font-size:13px; }
@media (max-width:640px) { [data-testid="stMainBlockContainer"] { padding:1.5rem 1rem; } }
</style>
""", unsafe_allow_html=True)


def _select_page(page):
    st.session_state.page = page


def render_navigation():
    with st.sidebar:
        st.markdown('<div class="brand"><span class="brand-mark">▦</span>FortiAIGate</div>'
                    '<div class="brand-caption">SECURITY TESTING LAB</div>', unsafe_allow_html=True)
        for group, pages in NAVIGATION:
            st.markdown('<div class="nav-group">{}</div>'.format(group), unsafe_allow_html=True)
            for page, icon in pages:
                st.button(page, icon=":material/{}:".format(icon), key="nav_" + page,
                          type="primary" if st.session_state.page == page else "secondary",
                          on_click=_select_page, args=(page,), width="stretch")
        st.markdown('<div class="sidebar-footer">FortiAIGate testing lab<br>Security assessment workspace</div>',
                    unsafe_allow_html=True)
    return st.session_state.page


def render_breadcrumb(page):
    group = next((name.title() for name, pages in NAVIGATION if any(label == page for label, _ in pages)), "Workspace")
    st.markdown('<div class="breadcrumb">Security lab<span>/</span>{}<span>/</span><strong>{}</strong></div>'.format(
        html.escape(group), html.escape(page)), unsafe_allow_html=True)


def render_placeholder(title):
    st.header(title)
    st.caption("Reserved in the workspace. No testing controls are available.")
    with st.container(border=True):
        st.markdown('<div class="planned"><div class="planned-icon">⚒</div>'
                    '<h2>To be constructed</h2><p>Content to be added.</p></div>', unsafe_allow_html=True)
