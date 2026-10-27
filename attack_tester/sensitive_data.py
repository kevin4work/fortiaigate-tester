"""Sensitive Data tests: three fixed types, inline prompts and responses."""

import streamlit as st

from common.test_catalog import get_cases
from attack_tester.runner_client import saved_configuration
from attack_tester.run_views import (
    apply_page_style,
    available,
    catalog_records,
    readiness_notice,
    render_assessment,
    render_start_button,
    runner_context,
    safe_text,
)


CATEGORY_NAMES = {
    "hkid": "HKID",
    "cards": "Credit cards",
    "apikey": "API-key disclosure",
}
CATEGORY_DESCRIPTIONS = {
    "hkid": "Identity-card data in prompts.",
    "cards": "Visa, Mastercard and Amex data in prompts.",
    "apikey": "Credential-shaped strings in model output.",
}
TEST_TYPES = ("hkid", "cards", "apikey")
LIMITS = {"request_cap": 60, "rpm": 30, "minutes": 10, "concurrency": 1}


def current_selection(families):
    """All three test types; disclosure cases require the reviewed scanner manifest."""
    return [group for group in TEST_TYPES if group in ("hkid", "cards") or available(families.get(group, {}))]


def selected_preview_cases(selection, families):
    """Fixed fixture order followed by the runner's sampled native cases."""
    cases = [dict(case, case_id=case["id"], family=case["group"],
                  family_title=CATEGORY_NAMES[case["group"]], is_template=False)
             for case in get_cases(selection)]
    seen = {case["case_id"] for case in cases}
    for group in selection:
        if group in ("hkid", "cards"):
            continue
        for case in families.get(group, {}).get("previews", []):
            case_id = case.get("case_id") or case.get("id")
            if case_id and case_id not in seen:
                cases.append(dict(case, case_id=case_id, family=group, family_title=CATEGORY_NAMES[group]))
                seen.add(case_id)
    return cases


def render_sensitive_data():
    apply_page_style()
    st.title("Sensitive Data")
    st.caption("See how identity, payment-data and credential-disclosure tests are handled, one response at a time.")
    if st.session_state.get("_active_run_sensitive"):
        render_assessment("sensitive", [])
        return

    _client, health, catalog, error = runner_context()
    families = catalog_records(catalog, "families")
    configuration = saved_configuration(st.session_state)
    selection = current_selection(families)
    cases = selected_preview_cases(selection, families)
    with st.expander("What is tested"):
        for group in TEST_TYPES:
            count = len(get_cases([group])) if group in ("hkid", "cards") else len(
                [case for case in cases if case["family"] == group])
            st.caption("{} · {} test{} · {}".format(
                CATEGORY_NAMES[group], count, "" if count == 1 else "s", CATEGORY_DESCRIPTIONS[group]))
        if "apikey" not in selection:
            st.caption(safe_text(families.get("apikey", {}).get("reason")
                                 or "API-key disclosure cases need the private scanner manifest."))
    st.caption("{} tests · {}".format(len(cases), " · ".join(CATEGORY_NAMES[group] for group in selection)))
    render_start_button("sensitive", "custom", selection, LIMITS, health, configuration, error,
                        None if cases else "No test cases are available.")
    reason = readiness_notice(health, configuration, error, None if cases else "No test cases are available.")
    if not reason:
        st.caption("Runs only when you click Run all tests. Responses appear below as each test finishes.")
    render_assessment("sensitive", cases)
