"""Version-specific, reviewed native Garak classes. No remote assets or judges."""
import importlib
import random
import re
from datetime import datetime

from runner.apikey_filter import DETECTOR_ID, credential_detector
from runner.curation import donotanswer_kept_indices, filter_attack_only

PROBES = {
    "dan.Dan_11_0": ["dan.DAN", "mitigation.MitigationBypass"],
    "dan.Ablation_Dan_11_0": ["dan.DAN", "mitigation.MitigationBypass"],
    "dan.Dan_10_0": ["dan.DAN", "mitigation.MitigationBypass"],
    "dan.Dan_9_0": ["dan.DAN", "mitigation.MitigationBypass"],
    "dan.Dan_8_0": ["dan.DAN", "mitigation.MitigationBypass"],
    "dan.Dan_7_0": ["dan.DAN", "mitigation.MitigationBypass"],
    "dan.Dan_6_2": ["dan.DAN", "mitigation.MitigationBypass"],
    "dan.Dan_6_0": ["dan.DAN", "mitigation.MitigationBypass"],
    "dan.DUDE": ["dan.DUDE", "mitigation.MitigationBypass"],
    "dan.STAN": ["dan.STAN", "mitigation.MitigationBypass"],
    "dan.DAN_Jailbreak": ["dan.DANJailbreak", "mitigation.MitigationBypass"],
    "dan.AntiDAN": ["dan.AntiDAN", "mitigation.MitigationBypass"],
    "dan.ChatGPT_Developer_Mode_v2": ["dan.DevMode", "mitigation.MitigationBypass"],
    "dan.ChatGPT_Developer_Mode_RANTI": ["dan.DevMode", "mitigation.MitigationBypass"],
    "dan.ChatGPT_Image_Markdown": ["dan.MarkdownLink", "mitigation.MitigationBypass"],
    "dan.AutoDANCached": ["dan.DAN", "mitigation.MitigationBypass"],
    "latentinjection.LatentWhois": ["base.TriggerListDetector"],
    "latentinjection.LatentInjectionReport": ["base.TriggerListDetector"],
    "latentinjection.LatentInjectionResume": ["base.TriggerListDetector"],
    # Colab does not supply content-detector terms; score relay shape only.
    "web_injection.ColabAIDataLeakage": ["web_injection.MarkdownExfilBasic"],
    "web_injection.StringAssemblyDataExfil": ["web_injection.MarkdownExfilBasic"],
    "web_injection.TaskXSS": ["web_injection.XSS"],
    "web_injection.MarkdownXSS": ["web_injection.XSS"],
    "exploitation.JinjaTemplatePythonInjection": ["exploitation.JinjaTemplateInjectionDetector", "exploitation.PythonCodeExecution"],
    "exploitation.SQLInjectionEcho": ["exploitation.SQLiEcho"],
    "suffix.GCGCached": ["mitigation.MitigationBypass"],
    "tap.TAPCached": ["mitigation.MitigationBypass"],
    "malwaregen.Payload": ["malwaregen.AnyCode"],
    "malwaregen.SubFunctions": ["malwaregen.AnyCode"],
    "phrasing.PastTense": ["mitigation.Prefixes"],
    "phrasing.FutureTense": ["mitigation.Prefixes"],
    "grandma.Win10": ["productkey.Win5x5", "mitigation.MitigationBypass"],
    "grandma.Win11": ["productkey.Win5x5", "mitigation.MitigationBypass"],
    "grandma.Slurs": ["unsafe_content.SlursReclaimedSlurs", "mitigation.MitigationBypass"],
    "grandma.Substances": ["mitigation.MitigationBypass"],
    "donotanswer.DiscriminationExclusionToxicityHatefulOffensive": ["mitigation.MitigationBypass"],
    # Intent-filtered: only the assistant-directed credential/PII-elicitation
    # rows are attacks; advice/companion/self-harm-distress rows are excluded.
    "donotanswer.HumanChatbox": ["mitigation.MitigationBypass"],
    "donotanswer.InformationHazard": ["mitigation.MitigationBypass"],


    "apikey.GetKey": [DETECTOR_ID],
    "apikey.CompleteKey": [DETECTOR_ID],
    "leakreplay.LiteratureCloze": ["base.TriggerListDetector"],
    "dan.DanInTheWild": ["mitigation.MitigationBypass"],
    "promptinject.HijackLongPrompt": ["promptinject.AttackRogueString"],
    "malwaregen.TopLevel": ["malwaregen.AnyCode"],
    "malwaregen.Evasion": ["malwaregen.AnyCode"],
    "donotanswer.MaliciousUses": ["mitigation.MitigationBypass"],
    "donotanswer.MisinformationHarms": ["mitigation.MitigationBypass"],
}
PROMPT_CAPS = {"smoke": 5, "core": 3, "extended": 64, "custom": 16, "quick": 0}


def configure_native():
    from garak import _config
    _config.load_base_config()  # Never load site/user configuration.
    _config.system.parallel_requests = False
    _config.system.parallel_attempts = False
    _config.system.max_workers = 1
    _config.system.lite = False
    _config.run.generations = 1
    _config.run.soft_probe_prompt_cap = 64
    _config.run.seed = 17
    _config.run.target_lang = "en"
    _config.run.langproviders = []
    _config.reporting.confidence_interval_method = "none"
    _config.transient.starttime = datetime.now()
    _config.transient.starttime_iso = _config.transient.starttime.isoformat()
    _config.buffmanager.buffs = []
    return _config


def load_probe(probe_id):
    if probe_id not in PROBES:
        raise ValueError("Probe is not reviewed")
    random.seed(17)
    module, name = probe_id.rsplit(".", 1)
    probe = getattr(importlib.import_module("garak.probes." + module), name)()
    # Reviewed curation policy: only genuine attacks/malicious requests stay.
    # DoNotAnswer prompts are kept by bundled malicious-intent metadata (full
    # per-row intent lists, kept before the cap so advice-only prefixes cannot
    # crowd out attacks); operator-removed prompts, non-secret credential
    # patterns and benign dual-use/advice strings apply to every probe.
    if probe_id.startswith("donotanswer."):
        keep = donotanswer_kept_indices(probe.dna_category, probe.prompts)
        probe.prompts = [probe.prompts[index] for index in keep]
        probe._prompt_intents = [probe._prompt_intents[index] for index in keep]
    prompts, intents = filter_attack_only(
        probe.prompts, list(probe._prompt_intents) if hasattr(probe, "_prompt_intents") else None)
    probe.prompts = prompts
    if intents is not None:
        probe._prompt_intents = intents
    if probe_id in ("web_injection.TaskXSS", "web_injection.MarkdownXSS"):
        # Keep plain-text XSS relay, not encoded/obfuscated payload variants.
        probe.prompts = [prompt for prompt in probe.prompts if not re.search(
            r"base64|&#|&(?:lt|gt|amp|quot);|%[0-9a-f]{2}|\\x[0-9a-f]{2}|\\u[0-9a-f]{4}|[\x00-\x08\x0b\x0c\x0e-\x1f]",
            prompt, re.I)]
    probe.prompts = list(probe.prompts)[:64]
    if hasattr(probe, "_prompt_intents"):
        probe._prompt_intents = list(probe._prompt_intents)[:64]
    if hasattr(probe, "triggers"):
        probe.triggers = list(probe.triggers)[:64]
    return probe


def load_detectors(probe_id):
    if probe_id not in PROBES:
        raise ValueError("Probe is not reviewed")
    detectors = []
    for detector_id in PROBES[probe_id]:
        if detector_id == DETECTOR_ID:
            detectors.append((detector_id, credential_detector()))
        else:
            module, name = detector_id.rsplit(".", 1)
            detectors.append((detector_id, getattr(importlib.import_module("garak.detectors." + module), name)()))
    return detectors
