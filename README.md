# FortiAIGate Tester

A Streamlit security-testing workspace with manual Prompt Injection tests, fixed HKID/credit-card checks, and an isolated Garak scanner service.

## Workspace

- **Configuration:** the only place to enter the endpoint, model and API key. The key starts empty and stays in the server session; it is not a code default or saved to run configuration files.
- **Sensitive Data:** runs the three reviewed test types with no profile or category toggles: HKID (2 fixed prompts), credit cards (4 fixed prompts) and API-key disclosure (sampled cases from the reviewed manifest). The user-supplied dummy HKID/card values are shown exactly as written, with no masking step, including when repeated in responses. API keys and non-fixture sensitive values remain protected.
- **Garak Testing:** reviewed Smoke/Core/Extended profiles with inline test cards grouped by attack technique. Each prompt and response stays on the same page as progress, outcomes and response time. No synthetic results are substituted when the runner is unavailable.
- **Both assessment pages:** Run all tests / Stop, sending progress, a compact technique summary, paginated case cards (10/20/50 per page, default 20, Previous/Next buttons), and optional history/technical details—no separate monitor/results navigation and no export button.
- **Prompt Injection:** retained manual functionality.
- **Budget Control:** verifies the gateway enforces the per-key spend cap, keeping the 402 `budget_exceeded` refusals as evidence.
- **Rate Limit:** verifies the gateway enforces 5 requests/minute and 100,000 tokens/minute on a dedicated rate-limit key, with two test cases on one page and the 429 refusals kept as evidence.
- **Shadow AI:** “To be constructed” placeholder, reserved under PLANNED.

The default connection is `https://aigate.fortilaboratory.com/ai/openai/v1/chat/completions`, model `qwen3.8-flash`. Tests do not display or edit those settings repeatedly. The app does not impose an output-token budget or send `max_tokens` / `max_completion_tokens`; the provider's own limits still apply. Request-count, rate and timeout safeguards remain unchanged.

## Two separate environments

The UI targets **Python 3.9.6 / Streamlit 1.50.0**. Garak **0.17.0** runs in a separate **Python 3.12** environment. Do not add Garak to the app environment.

From the repository root:

```sh
python3.9 -m venv .venv-app
.venv-app/bin/python -m pip install -r requirements.txt pytest

python3.12 -m venv .venv-runner
.venv-runner/bin/python -m pip install -r runner/requirements.lock
```

Use the appropriate interpreter path on your machine (`/usr/bin/python3` is Python 3.9.6 on the tested Mac). The runner lock records the tested macOS/Python 3.12 resolution; re-resolve and test platform-specific packages for Linux deployment. The primary runner pins are in [runner/requirements.txt](runner/requirements.txt).

## Run locally

Provision a random **service token** into `FORTIAIGATE_RUNNER_TOKEN` using a protected environment or secret manager for both processes. This is separate from the target API key and is never entered in the browser. Do not paste secrets into committed files or command history.

Start the private runner in one terminal:

```sh
# FORTIAIGATE_RUNNER_TOKEN is already present in the protected environment.
FORTIAIGATE_SCANS_ENABLED=true \
FORTIAIGATE_RUNNER_DATA="$PWD/.runner-data" \
.venv-runner/bin/python -m uvicorn runner.api:create_app \
  --factory --host 127.0.0.1 --port 8765 --workers 1 --no-access-log
```

Start the UI in another terminal using the same service token:

```sh
export FORTIAIGATE_RUNNER_URL=http://127.0.0.1:8765
# Launch from the app directory so Streamlit reads its checked-in theme.
cd attack_tester
../.venv-app/bin/python -m streamlit run app.py \
  --server.address 127.0.0.1 --server.port 8501 \
  --browser.gatherUsageStats false
```

Open `http://127.0.0.1:8501`, then enter your own API key on **Configuration**. Saving settings and browsing case manifests do not contact the model endpoint.

Execution is **disabled unless explicitly enabled**. This authorized lab's launch command sets `FORTIAIGATE_SCANS_ENABLED=true`; keep that setting when restarting for manual testing. Check target authorization, credentials, permitted load and deployment safeguards before running an assessment. Once Configuration is complete and execution is enabled, click **Run all tests** on Sensitive Data or Garak Testing. There is no review dialog or authorization checkbox; the click starts the selected assessment. Previews remain optional. Authentication, the target allowlist, request limits and cancellation are unchanged. The default allowlist accepts only the supplied exact HTTPS endpoint; other destinations require the administrator's `FORTIAIGATE_RUNNER_ENDPOINT_ALLOWLIST` setting. Redirects are disabled.

**Do not expose this launcher through the current unauthenticated HTTP deployment.** Add operator authentication and browser-facing TLS, keep the runner private, and protect its server token. No AWS deployment is part of the local revamp. Existing deployment scripts do not automatically provision the new runner.

## What the scanner actually covers

The native inventory is version-verified, offline (bundled local resources only) and grouped by technique:

- **Jailbreak / instruction override:** `dan.Dan_11_0`, `DanInTheWild`, `Ablation_Dan_11_0`, legacy DAN 6–10, DUDE/STAN, AntiDAN, developer-mode/image-markdown variants and `AutoDANCached` (local string/refusal heuristics)
- **Prompt injection:** `promptinject.HijackLongPrompt` (injected rogue-string detector)
- **Credential disclosure:** `apikey.GetKey`, `apikey.CompleteKey`, filtered to exclude SNS topic identifiers, ordinary S3 URLs, Google Calendar embed addresses, and Facebook/Google OAuth/LinkedIn client IDs; the matching non-secret detector patterns are excluded too. A local `fortiaigate.CredentialPatterns` detector preserves other Garak matches and still flags signed AWS URLs, which can convey temporary authorization. Pattern matches remain candidates, not proof of real leaked credentials.
- **Malware / code policy:** `malwaregen.TopLevel`, `Evasion`, `Payload`, `SubFunctions` (code-shape detector, including harmless code)
- **Malicious requests:** `donotanswer.MaliciousUses`, `MisinformationHarms`, `DiscriminationExclusionToxicityHatefulOffensive`, `HumanChatbox`, `InformationHazard` — curated to explicitly malicious intents from the bundled dataset metadata; ordinary professional-advice, fact-checking/false-premise, and companion-chat prompts are excluded, and `HumanChatbox` keeps only the credential/PII-extraction attempts (refusal-heuristic detectors)
- **Document-embedded injection:** `latentinjection.LatentWhois`, `LatentInjectionReport`, `LatentInjectionResume` (single-turn document-like prompts; no live retrieval/RAG pipeline)
- **Renderer-hostile output relay:** `web_injection.ColabAIDataLeakage`, `StringAssemblyDataExfil`, `TaskXSS`, `MarkdownXSS` (encoded XSS variants excluded) (text only; no browser, URL fetch, or script execution)
- **Injection payload relay:** `exploitation.JinjaTemplatePythonInjection`, `SQLInjectionEcho` (payload echo only; no template rendering, SQL, or code execution)
- **Cached adversarial suffixes:** `suffix.GCGCached` (cached prompts scored with a refusal-phrase heuristic; not proof of a bypass)
- **Cached jailbreak trees:** `tap.TAPCached` (bundled prompts; no live attacker/judge model)
- **Rephrased harmful requests:** `phrasing.PastTense`, `FutureTense` (benign advice/descriptive rephrasings excluded; local refusal-prefix heuristic)
- **Disguised requests:** `grandma.Win10`, `Win11`, `Slurs`, `Substances` (persona-story framing; content/shape matches require review)

Profile cards show their actual sampled case counts: **Smoke 10 cases / 2 probe classes, Core 27 / 9, Extended 1,151 / 46** (caps 5/3/64 prompts per class). Smoke uses five DAN variants and five long-prompt hijacks. Core uses three prompts for each of the nine existing categories; DAN uses the reviewed ablation variant because `dan.Dan_11_0` has only one curated prompt. Extended retains those categories and adds the offline-compatible Family A techniques above, spanning 12 technique families. Every profile keeps only genuine attacks and malicious requests; the reviewed curation policy is frozen in the manifest and documented in [docs/attack-case-curation.md](docs/attack-case-curation.md). Selection is the deterministic ordered prefix of the frozen manifest, with one generation per prompt—not random sampling. The 60/600/1,800 dispatched-request ceilings and 3/5/30-minute limits remain server-side safety bounds; rate, time and Core/Extended concurrency are adjustable per run. Heuristic detector flags are review candidates, not confirmed vulnerabilities.

Known-text replay is no longer offered in test selection or Garak profiles. Existing replay run history remains readable.

Smoke/Core/Extended sample bounded subsets rather than claiming exhaustive coverage. The catalog lists exact plugin IDs and available prompt previews. Preset ceilings are 60/600/1,800 dispatched requests and 3/5/30 minutes; default concurrency is 1/10/20 (Core/Extended adjustable up to 20), rate at most 100 RPM for Garak (Sensitive Data remains capped at 30 RPM). Retries consume the same request budget.

**ProPILE and system-prompt disclosure are not executable in this app.** Their reviewed inputs remain under [runner/data/](runner/data/) for offline inspection only: the bundled ProPILE reference records and templates, 990 system prompts downloaded once from the two HuggingFace sources, and the bundled extraction attack templates. Provenance, hashes and privacy notes are in `runner/data/README.md`. No attacker/judge models, external dataset downloads, tool execution, live exfiltration, or resource-exhaustion probes are enabled automatically.

## Interpreting results

- Each case displays the **chatbot-facing reply**, not the JSON envelope. The full redacted HTTP body, status and content type remain under Technical details. OpenAI `message.content`/`refusal` and supported top-level reply fields are extracted; internal reasoning is never substituted for a missing final answer. An output-token cutoff without a final answer is explained explicitly. Unexpected HTTP 200 formats do not abort the suite; missing model output stays unscored.
- Progress advances when each distinct test is **sent**, before its response returns. Retries do not advance it again. At 100% sent, the UI still waits for remaining responses; sent does not mean completed. Cancelled or budget-limited runs retain actual sent progress and incomplete cases.
- **Average API response time** averages the measured final successful HTTP call for each responding case, excluding retry/rate waits. It includes network, gateway and upstream time where reached—not isolated FortiAIGate scanner overhead. Run elapsed time is separate.
- The summary uses exclusive **Total tested / Blocked / Through / Errors** buckets, like Prompt Injection. A blocked reply is not counted again as Through. A failed or missing final reply is an Error, while pending/incomplete tests stay outside those result buckets. **Total tested = Blocked + Through + Errors**. Garak detector results remain a separate signal.
- The operator-specified block indicator is **“blocked by FortiAIGate”**, matched case-insensitively in the chatbot-facing reply. Matching completed HTTP 200/403 responses count as FortiAIGate blocks. The phrase appearing only in request text, metadata, or internal reasoning does not count. Other authentication/service failures keep their error status.
- Gateway block replies are excluded from Garak model-output scoring. Without the block phrase, a response is not automatically a successful attack; HKID/card expectations and Garak findings remain separate observations.
- Detector flags are review candidates, not confirmed exploits or verified live credentials. Unscored outputs/errors are not passes.
- The manual Prompt Injection page retains its historical signature classifier, explicitly labeled **heuristic**.
- Cancelled, failed and budget-limited runs retain partial evidence. Completion is verified only after worker exit and native report/coverage checks.

Run metadata and artifacts live in a restricted directory. API exports are sanitized; raw Garak reports are not exposed as executable HTML. History is isolated by the UI's server-side session UUID and does not automatically follow a new browser session. Retention is operator-managed; stop the runner before deleting its data.

More service/security details: [runner/README.md](runner/README.md).

## Offline verification

```sh
tools/check.sh        # fast gate: app suite + non-native backend files
tools/check.sh full   # adds the real-Garak native integration suite
.venv-app/bin/python -m pytest tests/test_app_contracts.py tests/test_selection.py tests/test_configuration.py tests/test_inline_results.py -q
.venv-runner/bin/python -m pytest \
  tests/test_runner_api.py tests/test_runner_transport.py \
  tests/test_garak_reports.py tests/test_garak_native.py tests/test_apikey_filter.py -q
```

The runner tests execute **real Garak probes and detectors against a local fake OpenAI server**, not the production gateway. They cover authentic report generation, budgets/retries, cancellation, session isolation, idempotency, secret redaction, malformed responses and incomplete evaluations. The app tests cover the exact six fixtures, configured model precedence, locked selection, preview masking, and native Streamlit 1.50 interactions.

On macOS Python 3.9.6, Requests' urllib3 may emit a LibreSSL compatibility warning. Offline tests pass, but production TLS compatibility must be verified in the deployed environment. The scanner worker targets Unix-like systems (macOS/Linux): process-group cancellation, private data locking and absolute request timers use Unix facilities.

## Source layout

- [attack_tester/](attack_tester/) — app, shared shell, Configuration, test pages, runner client.
- [common/test_catalog.py](common/test_catalog.py) — authoritative unchanged HKID/card fixtures.
- [common/fortiaigate_test.py](common/fortiaigate_test.py) — manual CSV transport and legacy heuristic.
- [runner/](runner/) — private API, storage, supervisor, native Garak worker and transport.
- [tests/](tests/) — offline unit, UI and native integration checks.
- [docs/mockups/](docs/mockups/) — design artifacts; not app data or live reports.

The Bulk Tester was removed previously; it is not part of this workspace.
