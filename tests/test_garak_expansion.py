"""Audited bundled native classes: offline construction and loopback-only scoring."""
import hashlib
import json
import os
import socket
import subprocess
import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from runner.api import RunRequest, create_app, resolve
from runner.catalog import FAMILIES, MANIFEST, PROFILE_PROBES, planned_cases
from runner.native import PROBES, PROMPT_CAPS, configure_native, load_detectors, load_probe
from runner.reports import NativeReport
from runner.settings import Settings
from test_garak_native import fake_target, start_body
from test_runner_api import request_body

ADDITIONS = {
    "dan.Ablation_Dan_11_0": (["dan.DAN", "mitigation.MitigationBypass"], 64),
    "dan.DanInTheWild": (["mitigation.MitigationBypass"], 61),
    "promptinject.HijackLongPrompt": (["promptinject.AttackRogueString"], 64),
    "malwaregen.TopLevel": (["malwaregen.AnyCode"], 16),
    "malwaregen.Evasion": (["malwaregen.AnyCode"], 48),
    "donotanswer.MaliciousUses": (["mitigation.MitigationBypass"], 64),
    "donotanswer.MisinformationHarms": (["mitigation.MitigationBypass"], 13),
    "latentinjection.LatentWhois": (["base.TriggerListDetector"], 64),
    "web_injection.TaskXSS": (["web_injection.XSS"], 28),
    "exploitation.JinjaTemplatePythonInjection": (["exploitation.JinjaTemplateInjectionDetector", "exploitation.PythonCodeExecution"], 9),
    "exploitation.SQLInjectionEcho": (["exploitation.SQLiEcho"], 10),
    "suffix.GCGCached": (["mitigation.MitigationBypass"], 26),
    "tap.TAPCached": (["mitigation.MitigationBypass"], 9),
    "phrasing.PastTense": (["mitigation.Prefixes"], 54),
    "grandma.Win10": (["productkey.Win5x5", "mitigation.MitigationBypass"], 6),
    "donotanswer.InformationHazard": (["mitigation.MitigationBypass"], 64),
    "donotanswer.HumanChatbox": (["mitigation.MitigationBypass"], 19),
}


@pytest.mark.parametrize("probe_id", PROBES)
def test_audited_new_native_classes_construct_offline(monkeypatch, probe_id):
    monkeypatch.setenv("HF_HUB_OFFLINE", "1")
    monkeypatch.setenv("HF_DATASETS_OFFLINE", "1")
    monkeypatch.setattr(socket.socket, "connect", lambda *_: pytest.fail("Bundled construction attempted network access"))
    config = configure_native()
    assert config.run.generations == 1 and config.run.seed == 17
    detector_ids, count = ADDITIONS.get(probe_id, (MANIFEST["probes"][probe_id]["detectors"],
                                                  len(MANIFEST["probes"][probe_id]["prompts"])))
    assert PROBES[probe_id] == detector_ids
    probe = load_probe(probe_id)
    assert len(probe.prompts) == count
    assert all(isinstance(prompt, str) for prompt in probe.prompts)
    assert list(probe.prompts) == MANIFEST["probes"][probe_id]["prompts"]
    assert [name for name, _ in load_detectors(probe_id)] == detector_ids
    assert all(not detector.skip for _, detector in load_detectors(probe_id))
    if hasattr(probe, "triggers"):
        assert list(probe.triggers) == MANIFEST["probes"][probe_id]["triggers"]


def test_removed_encoding_family_is_not_offered_or_executable():
    from runner.catalog import catalog
    assert "encoding" not in FAMILIES
    assert "encoding" not in {family["id"] for family in catalog()["families"]}
    assert not any(probe.startswith("encoding.") for probe in MANIFEST["probes"])
    for profile in PROFILE_PROBES:
        assert not any(case["family"] == "encoding" for case in planned_cases(profile))
    for probe_id in ("encoding.InjectBase64", "encoding.InjectHex", "encoding.InjectMorse"):
        assert probe_id not in PROBES
        with pytest.raises(ValueError, match="not reviewed"):
            load_probe(probe_id)
        with pytest.raises(ValueError, match="not reviewed"):
            load_detectors(probe_id)


def test_expanded_profiles_exact_scope_caps_and_counts():
    assert PROFILE_PROBES["smoke"] == ["dan.Ablation_Dan_11_0", "promptinject.HijackLongPrompt"]
    assert PROFILE_PROBES["core"] == [
        "dan.Ablation_Dan_11_0", "dan.DanInTheWild", "promptinject.HijackLongPrompt",
        "apikey.GetKey", "apikey.CompleteKey", "malwaregen.TopLevel", "malwaregen.Evasion",
        "donotanswer.MaliciousUses", "donotanswer.MisinformationHarms"]
    assert len(PROFILE_PROBES["extended"]) == 46
    assert set(PROFILE_PROBES["extended"]) <= set(PROBES) == set(MANIFEST["probes"])
    for profile, count, cap in (("smoke", 10, 5), ("core", 27, 3), ("extended", 1151, 64)):
        plan = planned_cases(profile)
        assert PROMPT_CAPS[profile] == cap
        assert len(plan) == count == sum(min(cap, len(MANIFEST["probes"][probe]["prompts"]))
                                         for probe in PROFILE_PROBES[profile])
        assert len({case["case_id"] for case in plan}) == count
        assert not any(case["probe"].startswith("leakreplay.") for case in plan)
    assert len(planned_cases("smoke")) >= 10
    core_counts = {probe: sum(case["probe"] == probe for case in planned_cases("core"))
                   for probe in PROFILE_PROBES["core"]}
    assert all(count >= 3 for count in core_counts.values())
    assert "leakreplay.LiteratureCloze" in PROBES and "leakreplay" in FAMILIES
    for family in ("promptinject", "malwaregen", "donotanswer"):
        assert "heuristic" in FAMILIES[family][2].lower() and "review candidates" in FAMILIES[family][2]
    assert len(planned_cases("extended")) <= 1800
    assert "web_injection.MarkdownImageExfil" not in PROFILE_PROBES["extended"]
    assert "web_injection.PlaygroundMarkdownExfil" not in PROBES
    for probe_id in ("web_injection.TaskXSS", "web_injection.MarkdownXSS"):
        assert all(not any(marker in prompt.lower() for marker in ("base64", "&#", "\\x", "\\u", "&lt;", "&gt;"))
                   for prompt in MANIFEST["probes"][probe_id]["prompts"])
    assert not any(probe.startswith(("encoding.", "snowball.")) for probe in PROFILE_PROBES["extended"])
    assert not any("hallucination" in probe.lower() for probe in PROFILE_PROBES["extended"])


def test_new_candidate_probes_match_family_mapping_and_frozen_manifest():
    assert all(probe in MANIFEST["probes"] and probe in PROBES
               for probes in PROFILE_PROBES.values() for probe in probes)
    for probe_id in PROFILE_PROBES["extended"]:
        assert sum(probe_id in values[1] for values in FAMILIES.values()) == 1
    assert "exploitation.PythonCodeExecution" in PROBES["exploitation.JinjaTemplatePythonInjection"]
    assert "latentinjection.LatentWhois" in MANIFEST["probes"]
    assert MANIFEST["probes"]["latentinjection.LatentWhois"]["triggers"]
    assert "web_injection.TaskXSS" in PROFILE_PROBES["extended"]


@pytest.mark.parametrize("family", ["dan", "promptinject", "malwaregen", "donotanswer"])
def test_expansion_does_not_change_sensitive_selection(tmp_path, family):
    body = request_body(profile="custom", selection=[family])
    with pytest.raises(ValueError, match="supported categories"):
        resolve(RunRequest.model_validate(body), Settings("service-only", tmp_path))


def test_manifest_reconstructs_identically_in_fresh_offline_process(tmp_path):
    # Exercise the actual regeneration builder in a fresh process, so the
    # frozen metadata (apikey_filter, attack_curation) cannot drift from a
    # duplicated reconstruction.
    code = """
import importlib.util, sys
from pathlib import Path
spec = importlib.util.spec_from_file_location(
    "regen_manifest", Path(sys.argv[1]) / "tools" / "regen_manifest.py")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
print('MANIFEST_HASH=' + module.build()["sha256"])
"""
    body = {key: value for key, value in MANIFEST.items() if key != "sha256"}
    assert MANIFEST["sha256"] == hashlib.sha256(json.dumps(body, sort_keys=True).encode()).hexdigest()
    assert MANIFEST["attack_curation"]["version"] == "attack-only-v1"
    for index in range(2):
        env = {**os.environ, "HF_HUB_OFFLINE": "1", "HF_DATASETS_OFFLINE": "1",
               "HF_HOME": str(tmp_path / str(index))}
        result = subprocess.run([sys.executable, "-I", "-c", code, str(Path(__file__).resolve().parent.parent)],
                                env=env, capture_output=True, text=True, check=True, timeout=180)
        digest = next(line.split("=", 1)[1] for line in result.stdout.splitlines() if line.startswith("MANIFEST_HASH="))
        assert digest == MANIFEST["sha256"]


@pytest.mark.parametrize("probe_id,reply,flagged", [
    ("promptinject.HijackLongPrompt", None, True),
    ("promptinject.HijackLongPrompt", "Clean unrelated fixture reply", False),
    ("malwaregen.TopLevel", "int main() { return 0; }", True),
    ("malwaregen.TopLevel", "I cannot provide that", False),
    ("latentinjection.LatentWhois", None, True),
    ("latentinjection.LatentWhois", "Clean unrelated fixture reply", False),
    ("web_injection.TaskXSS", None, True),
    ("web_injection.TaskXSS", "Clean unrelated fixture reply", False),
])
def test_actual_native_injection_and_code_detectors(tmp_path, probe_id, reply, flagged):
    if reply is None:
        configure_native()
        probe = load_probe(probe_id)
        if probe_id.startswith("promptinject."):
            reply = probe.pi_prompts[0]["settings"]["attack_rogue_string"]
            assert reply and reply in probe.prompts[0]
        elif probe_id.startswith("latentinjection."):
            reply = " ".join(probe.triggers[:PROMPT_CAPS["smoke"]])
        else:
            import garak.payloads
            reply = garak.payloads.load("web_html_js").payloads[0]
        assert reply
    with fake_target(response=reply) as (endpoint, sent):
        app = create_app(Settings("service-only", tmp_path, True, (endpoint,), test_loopback=True))
        with TestClient(app) as client:
            # Internal fixture selects an audited native class; browser class/path
            # overrides remain forbidden and Garak admission owns fixed profiles.
            body = start_body(endpoint)
            body["configuration"].pop("api_key")
            body.update({"probe_ids": [probe_id], "cases": [], "manifest_sha256": MANIFEST["sha256"],
                         "planned_cases": planned_cases("smoke", [], [probe_id])})
            run, _ = app.state.store.create("internal-test", "audited-native", "fp", body)
            app.state.supervisor.launch(run["id"], "fake-test-credential")
            import time
            from runner.store import TERMINAL
            deadline = time.monotonic() + 15
            while app.state.store.get(run["id"])["status"] not in TERMINAL and time.monotonic() < deadline:
                time.sleep(0.05)
            run = app.state.store.get(run["id"])
            assert run["status"] == "completed" and run["summary"]["completion_verified"], run
            count = len(body["planned_cases"])
            assert len(sent) == run["summary"]["finished_case_count"] == count
            rows = app.state.store.records("results", run["id"])
            assert len(rows) == count and all(row["finalized"] for row in rows)
            assert all(row["detectors"][0]["name"] == PROBES[probe_id][0] for row in rows)
            assert all(row["detectors"][0]["flagged"] is flagged for row in rows)
            assert all(row["outcome"] == ("flagged" if flagged else "not_flagged") for row in rows)
            parser = NativeReport()
            parser.feed((tmp_path / run["id"] / "native.report.jsonl").read_text())
            assert parser.verified(True, 1, 1, [probe_id], count)
            if probe_id.startswith(("promptinject.", "latentinjection.")):
                assert all(attempt["notes"].get("triggers") for attempt in parser.attempts.values())
            assert not any(b"fake-test-credential" in p.read_bytes() for p in tmp_path.rglob("*") if p.is_file())
