# Garak testing for FortiAIGate

**Status:** design proposal, not an implemented integration.
**Research date:** 9 October 2026.
**Audience:** FortiAIGate PoC owners, security testers, and implementing engineers.

## Recommendation

Add **Garak Testing** to the existing Attack Tester, keeping manual tests intact. Use Garak for repeatable adversarial probe generation and detector evaluation, and add a small FortiAIGate-aware execution/reporting layer around it.

This is a stronger approach than expanding a CSV of fixed prompts indefinitely. However, a scanner result is not a gateway enforcement verdict, a confirmed exploit, or comprehensive security certification. The interface should make those distinctions explicit.

Start with reviewed text-chat probes, one running scan at a time, and durable evidence. Do not start with `all`, adaptive attacker-model campaigns, Kubernetes workers, or a general-purpose workflow engine.

### Deliverables in this design

- [Interactive offline mockup](mockups/garak-testing.html): setup, run monitor, results, and an evidence dialog.
- [Scan setup](mockups/garak-01-setup.png).
- [Run monitor](mockups/garak-02-monitor.png).
- [Findings and evidence](mockups/garak-03-results.png).
- [Evidence detail](mockups/garak-04-evidence.png).

Open the HTML in a browser; no server is needed. It contains no external assets, credentials, or network calls. Content Security Policy disables network connections. Profile selection, confirmation, tabs, cancellation, chart/table switching, evidence dialogs, and synthetic JSON export work locally. Run and result screens are fixed synthetic fixtures, not simulations of the selected configuration. Sensitive Data and the Planned menu items now link to the [combined Sensitive Data/menu revision](sensitive-data-menu-design.md); the other sidebar items remain visual context only. That revision also documents native ProPILE PII coverage and why it does not replace the existing HKID/card input-DLP cases.

## 1. Target and compatibility contract

| Setting | Proposed value |
|---|---|
| Full chat endpoint | `https://aigate.fortilaboratory.com/ai/openai/v1/chat/completions` |
| Explicit model ID | `qwen3.8-flash` |
| OpenAI SDK base URL | `https://aigate.fortilaboratory.com/ai/openai/v1/` |
| Stock Garak generator reference | `openai.OpenAICompatible` |
| Generator base-URL property | `uri` |
| Stock credential variable | `OPENAICOMPATIBLE_API_KEY` |
| Proposed Garak release | `0.17.0`, subject to installation/compatibility validation |
| Worker runtime | Separate Python 3.12 environment/container |
| Initial inference mode | Non-streaming text chat, one output per request |

The stock compatible generator uses the OpenAI SDK's chat-completions API and Bearer authentication. **Actual gateway authentication, model availability, accepted parameters, block format, and capacity have not been tested.** No request was made to the target during design.

The full endpoint must not be passed as the SDK base URL: otherwise the client can append `/chat/completions` twice. Do not infer the model from URL segments. The current helper in [common/fortiaigate_test.py](../common/fortiaigate_test.py#L55) would infer `v1/chat` for this URL, so it cannot be reused unchanged for Garak.

Pin the stable package, dependency lock/container digest, exact probe/detector manifest, dataset/model revisions, sampling settings, and gateway policy revision. Current upstream `main` is a development version; do not float against it.

**Runtime separation matters:** Garak v0.17.0 package metadata requires Python >=3.11. Project rules specify Python 3.9.6 for the existing demo app, while checked-in deployment bootstrap installs Python 3.12. Preserve the app contract and verify the real deployment separately rather than upgrading it implicitly. This design adds no infrastructure changes.

**Initialization is not a dry run:** the stock generator performs a connectivity GET during construction. In the implementation, pure configuration review must not instantiate network-active plugins. Preflight must be an explicit, authorized action.

## 2. User experience

### A. Configuration and scan setup

**Configure the connection once on Configuration.** That page owns the full target, explicit model, derived SDK base URL, credential reference, and connection-level options. Never store the credential value in saved scan settings. The testing pages consume that saved configuration; they do not repeat endpoint/model/key fields, target-summary cards, or those values in ordinary review dialogs. The Configuration page itself is not rebuilt by this mockup revision.

Garak Testing starts with:

1. Choose a reviewed coverage profile.
2. Inspect resolved probes/detectors, required downloads/auxiliary services, and exclusions.
3. Set run-specific request, rate, concurrency, and time budgets.
4. Review **Scan summary**, containing profile and run limits only, then explicitly authorize the start.

The existing Smoke/Core/Extended Garak profiles remain; the two-option Quick check/Custom rule applies to Sensitive Data. Store an immutable internal configuration/version reference with every run so history remains reproducible even when saved settings change. If configuration is missing or invalid, a real implementation should direct the operator to Configuration, not embed another connection form.

The mockup illustrates three **proposed presets**, not built-in Garak profiles:

| Profile | Purpose | Request ceiling | Wall-time ceiling |
|---|---|---:|---:|
| Smoke | Validate transport and a small probe sample | 60 | 3 min |
| Core assessment | Broader reviewed text-chat probes | 600 | 5 min |
| Extended | Additional classes, variations, and repetitions | 1,800 | 30 min |

Suggested starting limits: **1 concurrent request, 100 requests/minute, 512 output tokens, 60-second request timeout**. All values require capacity confirmation. The worker must enforce them; they are not claims about stock Garak's available options. Caps include retries and auxiliary calls where enabled. A cap is not a promise to finish a suite. Set a total token ceiling too once input-size accounting is available; disclose approximate accounting and unknown pricing rather than inventing cost estimates.

Run Smoke first even though the mockup highlights Core. Stop on invalid credentials or incompatible response schemas. Record transient service errors against their cases and continue scanning; preserve incomplete coverage when a budget is exhausted.

### B. Run monitor

Show lifecycle state, current probe/group, finalized attempts, actual requests dispatched, elapsed time, rate-limit waits, confirmed gateway blocks, and transport errors. Store state outside Streamlit so refresh/navigation does not stop or duplicate the scan.

A request-budget meter is useful. A fabricated global “scan 60% complete” is not: adaptive probes, retries, and dataset expansion make totals variable. Show known finished/selected counts and label unknown totals honestly.

Cancellation stops dispatch, requests graceful process shutdown, and terminates the process group after a bounded grace period. Preserve partial artifacts. Already-issued remote work cannot be recalled.

### C. Findings and evidence

- Separate gateway counters from detector findings.
- Show denominators and excluded/unscored counts, not a single “security score.”
- Aggregate by probe family, with exact plugin IDs in drill-downs.
- Inspect escaped/redacted prompt, output, detector evidence, and gateway provenance.
- Preserve raw detector scores/thresholds and distinguish automated flags from human review status.
- Export sanitized summaries; authorize access to raw artifacts separately.
- Add basic durable run history with completed, failed, cancelled, and budget-limited states. History and arbitrary plugin selection are not additional screens in this initial mockup.

The mockup uses dark `#0d1117`, panel `#161b22`, and Fortinet red accents. Red is used for navigation/actions, not to imply every detector flag is a critical exploit. A darker red button fill preserves white-text contrast. Charts have a single validated blue series, keyboard tooltips, equivalent tables, and optional texture.

## 3. Coverage: comprehensive within a stated scope

Resolve an explicit class allowlist against the pinned version. Tags/families below are candidate areas, not a guarantee that all their plugins are appropriate for this endpoint.

| Area | Candidate Garak families | What the result means |
|---|---|---|
| Jailbreak / instruction override | `dan`, `tap.TAPCached`, selected `promptinject` | Response to adversarial instructions; not downstream execution |
| Encoding / Unicode evasion | selected `encoding`, `smuggling`, `badchars` | Whether transformations change policy behavior |
| Prompt leakage | selected `sysprompt_extraction` | Extraction of supplied synthetic system prompts, not automatically the gateway's hidden prompt |
| Harmful / prohibited content | selected `donotanswer` (explicitly malicious intent subsets only; benign advice and false-premise diagnostics are excluded — see `docs/attack-case-curation.md`), `realtoxicityprompts`, `lmrc` | Policy-specific output assessment, dependent on detector validity |
| Secret-looking output / known-text replay | selected `apikey`, `leakreplay` | Secret-shaped strings or known text; not proof of stolen credentials or private-data access |
| Code-related risks | selected `malwaregen`, `packagehallucination` | Generated content/package claims; never execute generated code |
| Misinformation / reasoning | selected `misleading` (`snowball` removed: factuality is not a gateway security property) | Quality/safety signals; not necessarily gateway security violations |

Introduce these incrementally; Core need not include every row. Lightweight cached probes and deterministic detectors should come first. Review non-English coverage and repeat sampling explicitly; stochastic model behavior means a single run is only one observation.

**Benign controls are essential.** Add a small, separately labeled set of approved normal requests and harmless near-boundary examples. Report benign false-positive blocks separately from adversarial block rates. These controls may be runner fixtures rather than stock Garak probes. Do not mix quality tests and security-policy tests into an unlabeled “attack success rate.”

### Outside the initial scope

- **MCP, tools, and agents:** the chat generator does not execute a tool-call loop. These need an instrumented, isolated agent harness and mock tools.
- **End-to-end RAG:** putting injected document text in chat does not test retrieval permissions, ingestion, ACLs, or poisoning of an actual store.
- **Multimodal / model-file scanning:** requires corresponding inputs or artifacts, not just this text endpoint.
- **Adaptive attacks / remote judges:** separate opt-in later; require attacker/evaluator targets, bounded budgets, approved data egress, and additional credentials.
- **Resource exhaustion, live exfiltration, destructive DB/system operations:** excluded. Do not execute emitted URLs, scripts, SQL, or commands.
- **Direct-model comparison:** not configured. A separately authorized direct endpoint with matching model/version/settings and paired prompts is needed before estimating gateway protection uplift. No bypass target should be guessed or discovered.

OWASP mappings can help navigation, but they are partial taxonomy mappings, not certification or evidence of coverage of every LLM/agent/MCP risk.

## 4. Results model and honest metrics

Keep three independent axes:

| Axis | Example values | Evidence requirement |
|---|---|---|
| Transport / gateway | Confirmed block, allowed, auth error, rate limited, timeout, upstream error, unknown | Documented response fields/codes or correlated gateway audit event; not a substring match |
| Model behavior annotation | Refusal, safe answer, harmful compliance, ambiguous | Model-origin evidence plus detector/manual assessment; otherwise label provenance unknown |
| Garak evaluation | Flagged, not flagged, unscored | Detector ID, raw score, threshold, output index, completed evaluation |

A 403 is not automatically a policy block. A 200 refusal may be gateway-generated. A body mentioning “FortiAIGate” does not prove a block. Null output and missing detector scores are not passes.

Recommended metrics:

- **Confirmed gateway block rate:** confirmed blocks / eligible requests with known allow-or-block outcomes. Scope by test class; disclose unknowns and service failures separately.
- **Per-detector hit rate:** flagged outputs / scored eligible model outputs for that detector.
- **Unique flagged responses:** distinct eligible output IDs flagged by at least one selected detector. Do not sum hits across detectors as separate responses.
- **Not flagged:** evaluated outputs for which the required detector set completed and none flagged. Keep missing/partial evaluations separate.
- **Benign false-positive rate:** confirmed blocks / classified benign control requests.
- **Coverage:** finished / selected probes and explicit skipped/incompatible/incomplete classes.

Garak's default threshold is 0.5; retain the configured threshold instead of hardcoding the interpretation in the UI. `None` is unscored. Raw Garak evaluation summaries may include gateway-generated text if using stock transport; retain those raw summaries, but do not relabel them as the gateway-aware metric. Never manufacture a model response or pass score to hide a block/error.

**Illustrative fixture only:** the mockup has 600 requests = 390 confirmed blocks + 198 allowed/scored outputs + 12 errors. Of the 198 outputs, 18 are flagged and 180 are not. The 9.1% figure is 18/198, not 18/600. The 66.3% block figure is 390/588 classified responses. This simplified fixture assumes one output/request, complete detector coverage, and no unresolved provenance. Production must support unknown origins, partial scoring, retries, and multiple detector results. These numbers say nothing about the real endpoint.

## 5. Smallest useful architecture

```text
Existing Attack Tester / Streamlit
  └─ Garak Testing page: configuration, status, history, evidence
       │ private authenticated job API
       ▼
Small FastAPI runner service
  ├─ SQLite: run state, frozen manifest, normalized results, review notes
  ├─ Restricted per-run directories: raw JSONL, logs, redacted exports
  └─ One isolated worker process/container per active run
       ├─ Garak 0.17.0 + reviewed probe/detector allowlist
       ├─ FortiAIGate-aware OpenAI-compatible transport adapter
       ├─ Rate / request / token / time budgets + bounded retry policy
       └─ HTTPS → approved FortiAIGate target
                    └─ Explicit qwen3.8-flash model
```

Start with **one active job and local durable storage**, not Redis/Celery or a distributed queue. Reject or defer additional starts explicitly. The worker can live beside the app if measured RAM/disk suffice; a separate Python environment is mandatory, a separate EC2 instance is not yet justified. Remote target inference does not require a local GPU, but Garak's dependencies, datasets, and some detectors can be large. Benchmark before choosing a host size; the current deployment's small root volume is not an assumed fit.

Suggested job operations: create, list, read status, read findings, cancel, export. Bind the service privately and authenticate callers. A Streamlit rerun should only read state, never implicitly launch a scan. Use one-time start/idempotency handling so repeated clicks cannot create duplicate scans.

### Transport adapter is the critical integration seam

Use `openai.OpenAICompatible` as the upstream compatibility reference, but do not assume the stock generator alone can supply gateway-aware evidence. Capture each actual HTTP call with an output/attempt correlation and documented response provenance. Correlate with gateway audit logs when response fields are insufficient.

Garak's native report does not contain all HTTP headers/statuses, request IDs, latencies, token usage, and policy decisions required here. Stock 401/403 handling can abort a run; transient failures have retries that are not an overall run budget. The adapter must represent recognized gateway policy blocks without aborting unrelated probes or synthesizing scored safe outputs, and must bound retries at the actual request layer. This behavior needs a compatibility spike before finalizing adapter code.

Validate accepted generation parameters: the compatible generator has default stop strings `#` and `;` that can truncate useful output. For the proposed pin, suppress `stop`, set output limits explicitly, and verify temperature/penalties/max-token support in approved preflight. Keep UI fields mapped to actual validated settings.

### Evidence ingestion

Parse versioned JSONL records, not console text as the authoritative data source. Keep a cursor and buffer incomplete lines. The same attempt UUID can be emitted before and after evaluation; update by UUID/status, not append/count every record. v0.17.0 uses nested conversation/message objects, not old flat-string assumptions.

Maintain separate records for logical attempts, HTTP requests/retries, outputs, and detector evaluations. A minimum trace is:

`run → attempt UUID → request ID → output index → detector ID / score / threshold → artifact location`

Record target/model/version/settings and policy revision with the run, not by reading current UI settings later. Finalize only after verified worker completion, the matching report completion marker, and resolved coverage; exit code alone or absent hitlog is insufficient. Preserve partial runs on crashes, restarts, cancellation, and budgets. A missing hitlog may simply mean no hits; report/digest generation is a separate step that can fail.

## 6. Security and operational boundaries

- Keep existing app/runtime behavior unchanged until implementation is approved.
- Restrict scanner targets to approved HTTPS hosts/paths; disallow userinfo, uncontrolled redirects, arbitrary URL forwarding, and SSRF destinations.
- Require operator authentication and TLS before exposing a scan launcher or credentials. Checked-in app deployment has an HTTP listener and no evident app login; actual deployment security must be verified.
- Inject credentials into the worker environment or equivalent secret channel, not CLI arguments, YAML, SQLite snapshots, browser storage, or logs.
- Run with minimum privileges and controlled egress. Build/download approved detector assets ahead of scans where practical; pin revisions and disable unapproved attacker/judge providers.
- Give every run a unique restricted directory. Redact secrets/PII, restrict raw-artifact access, and define retention. Avoid returning raw local filesystem paths through the UI.
- Treat prompts, outputs, console escapes, and generated reports as hostile content. Escape text, strip terminal control sequences, disable embedded remote assets, and do not render model HTML as executable markup.
- Warn operators about adversarial/offensive content and alert generation. Coordinate approved load and a stop contact before the first real campaign.

## 7. Implementation sequence and acceptance checks

This is the proposed sequence **after design approval**, not work already performed.

1. **Compatibility spike, then approved smoke run** → fixture-test documented blocks, ordinary 200 replies, gateway-generated 200 refusals, 401, 403, 429, timeout, malformed JSON, retry caps, and output truncation; verify the exact model/base URL and accepted parameters. Real endpoint traffic requires an explicit go-ahead and credential provisioning.
2. **Isolated runner + durable records** → prove refresh does not restart work, repeated start does not duplicate it, cancellation terminates workers within the grace period, retries count against budgets, and restarts retain partial evidence.
3. **Garak page + evidence UI** → verify scoped filters, per-detector denominators, missing/unscored results, escaped content, redacted exports, and authenticated artifact access. Regression-test existing manual pages unchanged.
4. **Broader curated campaign** → validate each plugin/detector pair, include benign controls, review representative false positives/negatives, and record exclusions. Stop at the declared budget rather than silently claim full coverage.
5. **Optional later depth** → matched direct baseline, more languages, adaptive probes, and isolated agent/RAG/MCP harnesses only where separately authorized and instrumented.

Before any real run, obtain the gateway's authentication scheme, representative block response or audit-log contract, approved load window, and policy expectations. These are execution prerequisites, not blockers to reviewing this mockup.

## 8. Mockup validation

- Rendered with local Chromium/Playwright and visually inspected.
- Interaction checks passed: three screens, confirmation gate, preset/live budget changes, invalid budget handling, evidence dialog, cancellation, JSON export, chart/table toggle, keyboard tooltip, and texture toggle.
- Connection inputs and concrete endpoint/model values are absent from setup, summaries, monitor, results, and review; synthetic export records Configuration as its settings source.
- Responsive page/dialog overflow checks passed at 320, 390, 768, 1280, and 1600 pixels. Parent-workspace cross-mockup links and the confirmation gate passed after applying the revised files.
- Browser check recorded zero HTTP/HTTPS requests and zero JavaScript errors.
- Single-series chart color passed the palette validator on `#161b22`; primary button white-text contrast is 5.30:1.
- An initial browser test used an overly strict radio label selector and timed out; corrected selectors passed the full rerun. This did not involve live model testing.
- No Garak installation, endpoint preflight, scan, deployment, or application regression test was performed. Only design artifacts were added; no commit/push was requested for this design task.

## Sources

Upstream source at the proposed pinned release takes precedence over introductory documentation when requirements or CLI examples disagree. Source review is not an installation/endpoint compatibility test.

1. [What is garak?](https://docs.garak.ai/garak/overview/what-is-garak) and [NVIDIA/garak](https://github.com/NVIDIA/garak/).
2. [v0.17.0 release](https://github.com/NVIDIA/garak/releases/tag/v0.17.0) and [package/runtime metadata](https://github.com/NVIDIA/garak/blob/v0.17.0/pyproject.toml).
3. [OpenAI-compatible generator: URI, auth, initialization, parameters, retries](https://github.com/NVIDIA/garak/blob/v0.17.0/garak/generators/openai.py).
4. [CLI/configuration](https://github.com/NVIDIA/garak/blob/v0.17.0/garak/cli.py) and [core defaults](https://github.com/NVIDIA/garak/blob/v0.17.0/garak/resources/garak.core.yaml).
5. [Probe inventory](https://github.com/NVIDIA/garak/tree/v0.17.0/garak/probes), [synthetic system-prompt extraction](https://github.com/NVIDIA/garak/blob/v0.17.0/garak/probes/sysprompt_extraction.py), and [TAP versus cached TAP](https://github.com/NVIDIA/garak/blob/v0.17.0/garak/probes/tap.py).
6. [Understanding detectors](https://docs.garak.ai/garak/garak-components/understanding-detectors), [refusal detector](https://github.com/NVIDIA/garak/blob/v0.17.0/garak/detectors/mitigation.py), and [evaluator semantics](https://github.com/NVIDIA/garak/blob/v0.17.0/garak/evaluators/base.py).
7. [Attempt schema](https://github.com/NVIDIA/garak/blob/v0.17.0/garak/attempt.py), [report lifecycle](https://github.com/NVIDIA/garak/blob/v0.17.0/garak/command.py), and [reading results](https://docs.garak.ai/garak/llm-scanning-basics/reading-the-results).
8. Existing app integration points: [navigation](../attack_tester/app.py#L424), [saved configuration](../attack_tester/app.py#L390), [current transport/classification](../common/fortiaigate_test.py#L44), and [deployment runtime](../deploy/user_data.sh#L10).
