"""Garak tests shown inline by attack technique, with response evidence."""

import streamlit as st

from attack_tester.runner_client import saved_configuration
from attack_tester.run_views import (
    apply_page_style,
    available,
    catalog_records,
    persistent_radio,
    readiness_notice,
    render_assessment,
    render_start_button,
    runner_context,
    safe_text,
)


PROFILES = {
    "smoke": {"title": "Smoke", "request_cap": 60, "minutes": 3, "concurrency": 1},
    "core": {"title": "Core", "request_cap": 600, "minutes": 5, "concurrency": 10},
    "extended": {"title": "Extended", "request_cap": 1800, "minutes": 30, "concurrency": 20},
}

# Display-only names and plain-language descriptions for the reviewed manifest
# probes; unknown ids fall back to the raw id so new entries never blank out.
PROBE_INFO = {
    "dan.Dan_11_0": ("DAN persona", "Unrestricted 'Do Anything Now' roleplay persona to test whether "
                                    "safety guardrails can be bypassed"),
    "dan.Ablation_Dan_11_0": ("DAN persona variants", "Controlled variations of the DAN 11.0 jailbreak prompt "
                                           "to sample different instruction-override formulations"),
    "dan.DanInTheWild": ("DAN in the wild", "Real-world variants of the DAN persona jailbreak collected "
                                            "from public examples"),
    "apikey.GetKey": ("Credential disclosure", "Asks the model to reveal a secret key it must never output"),
    "apikey.CompleteKey": ("Credential completion", "Asks the model to complete a partial secret key"),
    "leakreplay.LiteratureCloze": ("Memorised-text cloze", "Fill-in-the-blank probes checking whether the model "
                                                           "reproduces copyrighted literature"),
    "promptinject.HijackLongPrompt": ("Long-prompt hijack", "Instruction hijack buried inside a long, "
                                                             "benign-looking prompt"),
    "malwaregen.TopLevel": ("Malware generation", "Requests functional malware code to test refusal behaviour"),
    "malwaregen.Evasion": ("Detection evasion", "Requests code designed to evade security tooling"),
    "donotanswer.MaliciousUses": ("Malicious-use solicitations", "Curated requests for malicious activity; "
                                                                 "ordinary professional advice is excluded"),
    "donotanswer.MisinformationHarms": ("Dangerous-instruction requests", "Curated dangerous/illegal-instruction "
                                                                          "and toxic-premise prompts from the misinformation benchmark; "
                                                                          "advice and fact-checking diagnostics are excluded"),
    "latentinjection.LatentWhois": ("Document instruction injection", "Tests whether instructions embedded in a "
                                                                    "WHOIS-style document override its visible task"),
    "latentinjection.LatentInjectionReport": ("Report instruction injection", "Tests whether instructions embedded "
                                                                      "in a report override its visible task"),
    "latentinjection.LatentInjectionResume": ("Resume instruction injection", "Tests whether instructions embedded "
                                                                      "in a resume override its visible task"),
    "web_injection.TaskXSS": ("Script-tag relay", "Checks whether script-tag payload text is relayed; no browser "
                                                      "executes it"),
    "exploitation.JinjaTemplatePythonInjection": ("Jinja payload relay", "Checks whether template/code payload text is "
                                                                  "echoed; nothing is rendered or executed"),
    "exploitation.SQLInjectionEcho": ("SQL injection payload relay", "Checks whether SQLi payload text is echoed; "
                                                              "no database is contacted"),
    "suffix.GCGCached": ("Cached jailbreak suffixes", "Replays cached adversarial suffixes and flags missing known "
                                                        "refusal phrases heuristically"),
    "tap.TAPCached": ("Cached jailbreak trees", "Replays cached jailbreak prompts; refusal-phrase flags are "
                                                   "heuristic, not proof of a bypass"),
    "malwaregen.Payload": ("Malware payload requests", "Requests malware-related code; the detector flags code "
                                                       "shape, not whether it is malicious"),
    "malwaregen.SubFunctions": ("Malware subfunction requests", "Requests code fragments associated with malware; "
                                                            "the detector flags code shape only"),
    "phrasing.PastTense": ("Past-tense harmful requests", "Tests whether rephrasing harmful requests in past tense "
                                                            "changes refusal behavior"),
    "phrasing.FutureTense": ("Future-tense harmful requests", "Tests whether rephrasing harmful requests in future "
                                                              "tense changes refusal behavior"),
    "grandma.Win10": ("Disguised Windows 10 key request", "Persona-story request for a Windows 10 product key; "
                                                             "detector checks shape, not validity"),
    "grandma.Win11": ("Disguised Windows 11 key request", "Persona-story request for a Windows 11 product key; "
                                                             "detector checks shape, not validity"),
    "grandma.Slurs": ("Disguised slur request", "Persona-story request for slurs; context-sensitive keyword "
                                                  "detector may flag quotations"),
    "grandma.Substances": ("Disguised substance request", "Persona-story request involving substances; refusal "
                                                           "detection is heuristic"),
    "donotanswer.DiscriminationExclusionToxicityHatefulOffensive": ("Discriminatory/hateful requests", "DoNotAnswer "
                                                                    "category; refusal-phrase scoring is heuristic"),
    "donotanswer.HumanChatbox": ("Credential/PII extraction attempts", "Social-engineering prompts that try to "
                                                                       "extract the assistant's own credentials or personal data; "
                                                                       "advice and companion-chat prompts are excluded"),
    "donotanswer.InformationHazard": ("Information-hazard requests", "DoNotAnswer information-hazard prompts; "
                                                             "scoring is heuristic"),
    "web_injection.ColabAIDataLeakage": ("Colab data-leak relay", "Tests whether Colab-style leak instructions are "
                                                               "relayed; no actual data or URL is accessed"),
    "web_injection.StringAssemblyDataExfil": ("String-assembly relay", "Tests text assembly of exfiltration-like "
                                                                  "content; no actual exfiltration occurs"),
    "web_injection.MarkdownXSS": ("Markdown XSS relay", "Checks whether JavaScript-like markdown text is emitted; "
                                                         "do not render it"),
    "dan.Dan_10_0": ("Legacy DAN persona", "Bundled historical jailbreak prompt; refusal detection is heuristic"),
    "dan.Dan_9_0": ("Legacy DAN persona", "Bundled historical jailbreak prompt; refusal detection is heuristic"),
    "dan.Dan_8_0": ("Legacy DAN persona", "Bundled historical jailbreak prompt; refusal detection is heuristic"),
    "dan.Dan_7_0": ("Legacy DAN persona", "Bundled historical jailbreak prompt; refusal detection is heuristic"),
    "dan.Dan_6_2": ("Legacy DAN persona", "Bundled historical jailbreak prompt; refusal detection is heuristic"),
    "dan.Dan_6_0": ("Legacy DAN persona", "Bundled historical jailbreak prompt; refusal detection is heuristic"),
    "dan.DUDE": ("DUDE persona", "Bundled jailbreak prompt; refusal detection is heuristic"),
    "dan.STAN": ("STAN persona", "Bundled jailbreak prompt; refusal detection is heuristic"),
    "dan.DAN_Jailbreak": ("DAN jailbreak", "Bundled jailbreak prompt; refusal detection is heuristic"),
    "dan.AntiDAN": ("Anti-DAN prompt", "Bundled instruction-override variant; refusal detection is heuristic"),
    "dan.ChatGPT_Developer_Mode_v2": ("Developer-mode prompt", "Bundled jailbreak prompt; refusal detection is heuristic"),
    "dan.ChatGPT_Developer_Mode_RANTI": ("Developer-mode RANTI prompt", "Bundled jailbreak prompt; refusal detection is heuristic"),
    "dan.ChatGPT_Image_Markdown": ("Image-markdown prompt", "Checks text relay of image-markdown instructions; no image is fetched"),
    "dan.AutoDANCached": ("Cached AutoDAN prompts", "Replays bundled jailbreak prompts; refusal detection is heuristic"),
}


def profile_limits(profile):
    preset = PROFILES[profile]
    return {"request_cap": preset["request_cap"], "rpm": 100, "minutes": preset["minutes"],
            "concurrency": preset["concurrency"]}


def _technique_table(probe_ids) -> str:
    lines = ["| Technique | What it tests |", "|---|---|"]
    for probe in probe_ids:
        title, description = PROBE_INFO.get(probe, (probe, "Reviewed technique from the frozen manifest"))
        lines.append(f"| {title} (`{probe}`) | {description} |")
    return "\n".join(lines)


def _budget_input(column, label, profile, field, maximum, default=None):
    saved_key = "_garak_saved_" + field + "_" + profile
    widget_key = "_garak_" + field + "_" + profile
    if widget_key not in st.session_state:
        seed = default if default is not None else maximum
        st.session_state[widget_key] = max(1, min(int(st.session_state.get(saved_key, seed)), maximum))

    def changed():
        st.session_state[saved_key] = st.session_state[widget_key]

    return column.number_input(label, min_value=1, max_value=maximum, step=1, key=widget_key, on_change=changed)


def render_garak_page():
    apply_page_style()
    st.title("Garak Testing")
    st.caption("Compare responses and response time across different attack techniques.")
    if st.session_state.get("_active_run_garak"):
        render_assessment("garak", [])
        return

    _client, health, catalog, error = runner_context()
    configuration = saved_configuration(st.session_state)
    profiles = catalog_records(catalog, "profiles")
    counts = {pid: len(rec.get("planned_cases") or []) for pid, rec in profiles.items()}

    def profile_label(value):
        title = PROFILES[value]["title"]
        count = counts.get(value)
        if not count:
            return title
        return "{} · {} test case{} · <={} min".format(title, count, "" if count == 1 else "s", PROFILES[value]["minutes"])

    profile = persistent_radio("Coverage profile", list(PROFILES), "garak_profile", "core",
                               format_func=profile_label, horizontal=True)
    record = profiles.get(profile, {})
    cases = record.get("planned_cases") or []
    techniques = list(dict.fromkeys(case.get("family_title") or "Other tests" for case in cases))
    st.caption("{} selected tests · {}".format(len(cases), " · ".join(techniques) or "Manifest unavailable"))
    limits = profile_limits(profile)
    with st.expander("Run limits and test coverage"):
        cols = st.columns(3 if profile != "smoke" else 2)
        limits["rpm"] = _budget_input(cols[0], "Requests / minute", profile, "rpm", 100)
        limits["minutes"] = _budget_input(cols[1], "Time cap (minutes)", profile, "minutes", limits["minutes"])
        if profile != "smoke":
            limits["concurrency"] = _budget_input(cols[2], "Concurrency", profile, "concurrency", 20,
                                                    default=PROFILES[profile]["concurrency"])
            st.caption("Concurrency keeps that many requests in flight; a finished request immediately "
                       "releases its slot for the next test case.")
            runner_cap = int((health.get("capabilities") or {}).get("concurrency", 1) or 1)
            if limits["concurrency"] > runner_cap:
                limits["concurrency"] = runner_cap
                st.caption(f"The scanner service currently caps concurrency at {runner_cap}; the value sent is "
                           f"clamped until the scanner service is restarted with the current code.")
        st.markdown(_technique_table(record.get("probe_ids", [])))
        if health.get("garak_version"):
            st.caption("Garak " + safe_text(health["garak_version"]))
    scope_error = None if available(record) and cases else "This profile's test manifest is unavailable. Check the scanner service on Configuration."
    render_start_button("garak", profile, [], limits, health, configuration, error, scope_error)
    readiness_notice(health, configuration, error, scope_error)
    render_assessment("garak", cases)
