# Reviewed local test-case data

All inputs for the ProPILE and system-prompt disclosure suites live here so every test case can be reviewed offline and no run depends on a remote location.

Retrieved: **13 October 2026**, using the pinned runner environment (Garak 0.17.0, `datasets` 3.6.0).

## Layout

| Path | Content | Provenance |
|---|---|---|
| `propile/pii_data.jsonl` | 26 reference records (`name`, `email`, `source_dataset`, `source_id`) | Copied from the pinned package `garak/data/propile/pii_data.jsonl`; sha256 `5d75b709…38ada` verified equal |
| `propile/prompt_templates.tsv` | 25 elicitation templates | Copied from `garak/data/propile/prompt_templates.tsv`; sha256 `a57e6dcf…341` verified equal |
| `sysprompt/dataset/system_prompts.jsonl` | 990 unique system prompts (`source`, `prompt`) | Downloaded once from HuggingFace `garak-llm/drh-System-Prompt-processed` (944 rows, 921 kept) and `garak-llm/tm-system_prompt` (69 rows, 69 kept); filtered and deduplicated with the same rules the probe applies (text columns `systemprompt`/`prompt`, length > 20) |
| `sysprompt/attacks.json` | 28 extraction attack templates in 9 groups | Copied from `garak/data/sysprompt_extraction/attacks.json`; sha256 `9de1d55a…2bee` verified equal |

The runtime probe still reads `prompt_templates.tsv` and `attacks.json` from the pinned package because Garak does not expose those paths as settings; tests assert the package copies are byte-identical to the review copies above, so reviewing these files is reviewing exactly what executes. `pii_data.jsonl` and the system-prompt dataset are configured to load from this directory at runtime.

## Privacy and redistribution

- `propile/pii_data.jsonl` is documented by Garak as PII extracted from NVIDIA Nemotron-CC web-crawl data. The values are real-person-shaped. Treat this file as review-only: do not redistribute it, and prefer synthetic records for customer-facing demonstrations. A match during testing can be coincidence and does not prove training-data memorization.
- The system-prompt files are third-party prompt collections republished on HuggingFace (credits: danielrosehill/System-Prompt-Library-030825 and teilomillet/system_prompt). Verify their dataset cards before any redistribution.
- These files contain test inputs only. No credentials, gateway settings, or run evidence belong here.

## Reviewing the actual test cases

Expanded per-case prompts (probe id, case id, prompt or system/user conversation, expected trigger where applicable) are generated from these inputs into the frozen runner manifest and the catalog previews; the UI shows them before any run. Regenerate with the runner environment after editing inputs:

```sh
.venv-runner/bin/python -m pytest tests/test_garak_native.py -q   # validates manifest equality
```

## Execution status

These two suites are **review-only**: the app no longer offers ProPILE or system-prompt disclosure as executable test types, and the runner has no probe entries for them. Nothing in this directory is loaded by the worker or sent to any endpoint. The files exist so the full test-case inputs can be inspected offline, and so a future, separately approved enablement can start from reviewed local data instead of remote downloads.

- Editing a file here changes only the review artifact; no manifest or run depends on it today.
- If these suites are ever re-enabled, the worker must resolve them from this directory with HuggingFace offline mode forced, and must freeze the resulting prompts in the run manifest.
