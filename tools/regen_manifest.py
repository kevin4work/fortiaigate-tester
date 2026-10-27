"""Rebuild runner/manifest.json from the installed Garak probes — diff first, write only with --apply.

Manual edits to the manifest are operator decisions. This tool always prints what would
change (per-probe counts, added/removed prompts, metadata deltas) and refuses to write
unless --apply is passed, so a regeneration can never silently overwrite a hand edit.
"""
import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from runner.apikey_filter import EXCLUDED_KEY_TYPES, FILTER_VERSION, REMOVED_PROMPTS  # noqa: E402
from runner.curation import (  # noqa: E402
    CATEGORY_EXTRA_DONOTANSWER_INTENTS,
    CURATION_VERSION,
    MALICIOUS_DONOTANSWER_INTENTS,
    REMOVED_BENIGN_PROMPTS,
)
from runner.native import PROBES, configure_native, load_probe  # noqa: E402

METADATA_KEYS = ("garak_version", "seed", "payloads", "apikey_filter", "attack_curation")

MANIFEST = ROOT / "runner" / "manifest.json"


def build():
    configure_native()
    probes = {}
    for probe_id in PROBES:
        probe = load_probe(probe_id)
        entry = {"prompts": list(probe.prompts), "detectors": PROBES[probe_id]}
        if getattr(probe, "triggers", None):
            entry["triggers"] = list(probe.triggers)
        probes[probe_id] = entry
    body = {
        "garak_version": "0.17.0",
        "seed": 17,
        "payloads": [],
        "apikey_filter": {
            "version": FILTER_VERSION,
            "excluded_key_types": sorted(EXCLUDED_KEY_TYPES),
            "removed_prompts": sorted(REMOVED_PROMPTS),
        },
        "attack_curation": {
            "version": CURATION_VERSION,
            "donotanswer_intents": sorted(MALICIOUS_DONOTANSWER_INTENTS),
            "donotanswer_category_extra_intents": {
                category: sorted(intents)
                for category, intents in sorted(CATEGORY_EXTRA_DONOTANSWER_INTENTS.items())
            },
            "removed_prompts": sorted(REMOVED_BENIGN_PROMPTS),
        },
        "probes": probes,
    }
    body["sha256"] = hashlib.sha256(json.dumps(body, sort_keys=True).encode()).hexdigest()
    return body


def diff(old, new):
    lines = []
    old_probes, new_probes = old.get("probes", {}), new["probes"]
    for probe_id in sorted(set(old_probes) | set(new_probes)):
        before = old_probes.get(probe_id, {}).get("prompts", [])
        after = new_probes.get(probe_id, {}).get("prompts", [])
        if before == after:
            continue
        added = [p for p in after if p not in before]
        removed = [p for p in before if p not in after]
        lines.append(f"{probe_id}: {len(before)} -> {len(after)} prompts")
        for p in removed[:5]:
            lines.append(f"   - would REMOVE: {p[:90]}")
        for p in added[:5]:
            lines.append(f"   + would ADD:    {p[:90]}")
    for key in METADATA_KEYS:
        if old.get(key) != new[key]:
            lines.append(f"metadata {key}: {old.get(key)} -> {new[key]}")
    if old.get("sha256") != new["sha256"]:
        lines.append(f"sha256: {str(old.get('sha256'))[:12]} -> {new['sha256'][:12]}")
    return lines


def main():
    apply = "--apply" in sys.argv[1:]
    old = json.loads(MANIFEST.read_text()) if MANIFEST.is_file() else {}
    new = build()
    if old and old.get("probes") == new["probes"] and {k: old.get(k) for k in METADATA_KEYS} == {k: new[k] for k in METADATA_KEYS}:
        print("Manifest already matches the installed probes and current filter policy. Nothing to do.")
        return 0
    changes = diff(old, new) if old else ["(no existing manifest)"]
    print("Proposed manifest changes:")
    print("\n".join(changes) if changes else "  (none)")
    if not apply:
        print("\nDRY RUN: pass --apply to write. Review removed prompts carefully: they may be manual operator edits.")
        return 1
    MANIFEST.write_text(json.dumps(new, ensure_ascii=False, indent=2) + "\n")
    print("Manifest written.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
