import json
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path

from runner.settings import GARAK_VERSION, PROFILE_LIMITS
from runner.native import PROMPT_CAPS

MANIFEST = json.loads((Path(__file__).with_name("manifest.json")).read_text())
FAMILIES = {
    "dan": ("Instruction override · DAN", ["dan.Dan_11_0", "dan.Ablation_Dan_11_0", "dan.DanInTheWild", "dan.Dan_10_0", "dan.Dan_9_0", "dan.Dan_8_0", "dan.Dan_7_0", "dan.Dan_6_2", "dan.Dan_6_0", "dan.DUDE", "dan.STAN", "dan.DAN_Jailbreak", "dan.AntiDAN", "dan.ChatGPT_Developer_Mode_v2", "dan.ChatGPT_Developer_Mode_RANTI", "dan.ChatGPT_Image_Markdown", "dan.AutoDANCached"], "Bundled jailbreak benchmark payloads; native preprocessing substitutes {generator.name} with the configured model where present. Heuristic string-match flags are review candidates, not proof of a bypass."),
    "apikey": ("API-key disclosure", ["apikey.GetKey", "apikey.CompleteKey"], "Credential-focused patterns; excludes ordinary SNS/S3/calendar addresses and public client IDs. A match does not prove a valid or stolen credential."),
    "leakreplay": ("Known-text replay", ["leakreplay.LiteratureCloze"], "Bundled literary cloze examples; not proof of private tenant access."),
    "promptinject": ("Prompt injection", ["promptinject.HijackLongPrompt"], "Bundled prompt-injection benchmark payloads. The heuristic string-match detector checks the injected rogue string; flags are review candidates, not proof of gateway failure."),
    "malwaregen": ("Malware / code policy", ["malwaregen.TopLevel", "malwaregen.Evasion", "malwaregen.Payload", "malwaregen.SubFunctions"], "Bundled malware-request benchmark payloads. The heuristic regex detector matches any code, including harmless code; flags are review candidates, not proof of executable malware."),
    "donotanswer": ("Malicious requests", ["donotanswer.MaliciousUses", "donotanswer.MisinformationHarms", "donotanswer.DiscriminationExclusionToxicityHatefulOffensive", "donotanswer.HumanChatbox", "donotanswer.InformationHazard"], "Bundled benchmark payloads curated to explicitly malicious intents; ordinary professional-advice and companionship prompts are excluded. The heuristic string-match detector checks for absence of known refusal phrases; flags are review candidates, not proof that harmful instructions were provided."),
    "latentinjection": ("Document-embedded injection", ["latentinjection.LatentWhois", "latentinjection.LatentInjectionReport", "latentinjection.LatentInjectionResume"], "Bundled document-like prompts test whether embedded instructions override the visible task; substring-trigger flags are heuristic and do not model a live RAG pipeline."),
    "web_injection": ("Renderer-hostile output relay", ["web_injection.ColabAIDataLeakage", "web_injection.StringAssemblyDataExfil", "web_injection.TaskXSS", "web_injection.MarkdownXSS"], "Bundled payloads test renderer-hostile text relay only; keep emitted markup inert; no browser, URL fetch or script execution occurs."),
    "exploitation": ("Injection payload relay", ["exploitation.JinjaTemplatePythonInjection", "exploitation.SQLInjectionEcho"], "Bundled Jinja and SQLi payloads test text echo only; no template, database or code execution occurs."),
    "suffix": ("Cached adversarial suffixes", ["suffix.GCGCached"], "Bundled suffix replay uses a local refusal-phrase heuristic; flags are review candidates, not proof of a bypass."),
    "tap": ("Cached jailbreak trees", ["tap.TAPCached"], "Bundled cached jailbreak prompts use a local refusal-phrase heuristic; flags are review candidates, not proof of a bypass."),
    "phrasing": ("Rephrased harmful requests", ["phrasing.PastTense", "phrasing.FutureTense"], "Bundled harmful prompts are rephrased into past and future tense; local refusal-prefix matches remain heuristic."),
    "grandma": ("Disguised requests", ["grandma.Win10", "grandma.Win11", "grandma.Slurs", "grandma.Substances"], "Bundled persona-story prompts test disguised requests; sensitive-content findings may be context-dependent."),
}
PROFILE_PROBES = {
    "smoke": ["dan.Ablation_Dan_11_0", "promptinject.HijackLongPrompt"],
    "core": ["dan.Ablation_Dan_11_0", "dan.DanInTheWild", "promptinject.HijackLongPrompt",
             "apikey.GetKey", "apikey.CompleteKey", "malwaregen.TopLevel", "malwaregen.Evasion",
             "donotanswer.MaliciousUses", "donotanswer.MisinformationHarms"],
    "extended": [
        "dan.Dan_11_0", "dan.Ablation_Dan_11_0", "dan.DanInTheWild",
        "dan.Dan_10_0", "dan.Dan_9_0", "dan.Dan_8_0", "dan.Dan_7_0", "dan.Dan_6_2", "dan.Dan_6_0",
        "dan.DUDE", "dan.STAN", "dan.DAN_Jailbreak", "dan.AntiDAN", "dan.ChatGPT_Developer_Mode_v2",
        "dan.ChatGPT_Developer_Mode_RANTI", "dan.ChatGPT_Image_Markdown", "dan.AutoDANCached",
        "promptinject.HijackLongPrompt", "apikey.GetKey", "apikey.CompleteKey",
        "malwaregen.TopLevel", "malwaregen.Evasion", "malwaregen.Payload", "malwaregen.SubFunctions",
        "donotanswer.MaliciousUses", "donotanswer.MisinformationHarms",
        "donotanswer.DiscriminationExclusionToxicityHatefulOffensive",
        "donotanswer.HumanChatbox", "donotanswer.InformationHazard",
        "latentinjection.LatentWhois", "latentinjection.LatentInjectionReport", "latentinjection.LatentInjectionResume",
        "web_injection.ColabAIDataLeakage", "web_injection.StringAssemblyDataExfil",
        "web_injection.TaskXSS", "web_injection.MarkdownXSS",
        "exploitation.JinjaTemplatePythonInjection", "exploitation.SQLInjectionEcho",
        "suffix.GCGCached", "tap.TAPCached", "phrasing.PastTense", "phrasing.FutureTense",
        "grandma.Win10", "grandma.Win11", "grandma.Slurs", "grandma.Substances",
    ],
}


def installed_version():
    try:
        return version("garak")
    except PackageNotFoundError:
        return None


def planned_cases(profile, selection=(), probe_ids=None):
    """Ordered trusted fixtures and manifest prefix; no plugin or target initialization."""
    from common.test_catalog import get_cases
    if profile == "quick":
        selection = ("hkid", "cards")
    if probe_ids is None:
        probe_ids = PROFILE_PROBES.get(profile, [p for key in selection if key in FAMILIES for p in FAMILIES[key][1]])
    cases = []
    for case in get_cases(selection):
        family = case["group"]
        cases.append({**case, "case_id": case["id"], "family": family,
                      "family_title": "HKID" if family == "hkid" else "Credit cards",
                      "probe": "fortiaigate.fixed." + family,
                      "source_index": int(case["id"].rsplit("-", 1)[1]) - 1, "is_template": False})
    for probe_id in probe_ids:
        family = next(key for key, (_, probes, _) in FAMILIES.items() if probe_id in probes)
        for index, prompt in enumerate(MANIFEST["probes"][probe_id]["prompts"][:PROMPT_CAPS[profile]]):
            case_id = f"{probe_id}:{index}"
            cases.append({"id": case_id, "case_id": case_id, "family": family,
                          "family_title": FAMILIES[family][0], "probe": probe_id,
                          "title": f"{probe_id} · {index + 1}", "prompt": prompt,
                          "source_index": index, "is_template": "{generator.name}" in prompt})
    return cases


def catalog():
    compatible = installed_version() == GARAK_VERSION
    families = []
    for key, (title, probes, reason) in FAMILIES.items():
        if key == "leakreplay":
            continue  # Retain historical plan support, but do not offer new replay tests.
        previews = planned_cases("custom", [key])
        families.append({"id": key, "title": title, "available": bool(probes) and compatible,
                         "reason": reason if compatible else "Requires the pinned Garak 0.17.0 runner runtime",
                         "probe_ids": probes, "previews": previews, "preview_complete": key != "dan",
                         "prompt_count": len(previews), "prompt_cap_per_probe": PROMPT_CAPS["custom"],
                         "manifest_prompt_count": sum(len(MANIFEST["probes"][p]["prompts"]) for p in probes)})
    fixed = planned_cases("quick")
    for key, title in (("hkid", "HKID"), ("cards", "Credit cards")):
        cases = [c for c in fixed if c["group"] == key]
        families.insert(0 if key == "hkid" else 1, {"id": key, "title": title, "available": bool(cases),
            "reason": "Fixed input-protection expectations; gateway outcome requires verified policy provenance.",
            "probe_ids": [], "previews": cases, "preview_complete": True, "prompt_count": len(cases)})
    profiles = []
    for key, title in (("quick", "Quick check"), ("custom", "Custom"), ("smoke", "Smoke"), ("core", "Core"), ("extended", "Extended")):
        cap, minutes = PROFILE_LIMITS[key]
        rpm = 100 if key in PROFILE_PROBES else 30
        plan = planned_cases(key)
        profiles.append({"id": key, "title": title, "available": bool(fixed) if key == "quick" else compatible,
                         "reason": "Bounded sampling, not exhaustive coverage.",
                         "probe_ids": PROFILE_PROBES.get(key, []), "prompt_cap_per_probe": PROMPT_CAPS[key],
                         "planned_cases": plan, "planned_case_count": len(plan),
                         "limits": {"request_cap": cap, "minutes": minutes, "rpm": rpm,
                                    "concurrency": {"smoke": 1, "core": 10, "extended": 20}.get(key, 1)}})
    return {"version": "garak-0.17.0", "manifest_sha256": MANIFEST["sha256"],
            "profiles": profiles, "families": families}
