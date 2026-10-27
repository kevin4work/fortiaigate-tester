# Private assessment runner

This service requires Python 3.12 and the separate Garak 0.17.0 environment. Do not install its dependencies into the Python 3.9 Streamlit environment.

From the repository root:

```sh
python3.12 -m venv .venv-runner
.venv-runner/bin/python -m pip install -r runner/requirements.lock
```

`requirements.lock` records the tested macOS/Python 3.12 resolution. Re-resolve and test platform-specific dependencies when packaging for another operating system; the primary pins are in `runner/requirements.txt`.

## Start privately for the authorized lab

Provision `FORTIAIGATE_RUNNER_TOKEN` using a server secret manager or protected environment injection. This is a separate service token, never the target API key. Do not put either credential in a command, checked-in file, or saved scan configuration.

```sh
# FORTIAIGATE_RUNNER_TOKEN must already be present in the protected environment.
FORTIAIGATE_SCANS_ENABLED=true \
FORTIAIGATE_RUNNER_DATA="$PWD/.runner-data" \
.venv-runner/bin/python -m uvicorn runner.api:create_app \
  --factory --host 127.0.0.1 --port 8765 --workers 1 --no-access-log
```

Every API call requires `Authorization: Bearer <service token>`. Run operations additionally require `X-Session-ID`, a random session UUID generated and retained by the trusted server-side UI. A caller cannot read, list, cancel, or export another session's runs. A single shared service token is not an end-user login: keep it server-side, and add operator authentication and TLS before any public UI deployment.

Execution defaults to disabled in code. The authorized lab launch above explicitly sets `FORTIAIGATE_SCANS_ENABLED=true`; preserve that setting for local manual testing. Enabling the service alone does not start an assessment. Health checks and catalog previews make no target requests. The default production target is exactly:

`https://aigate.fortilaboratory.com/ai/openai/v1/chat/completions`

`FORTIAIGATE_RUNNER_ENDPOINT_ALLOWLIST` may specify a comma-separated list of operator-approved exact HTTPS chat-completions URLs. Credentials in URLs, query strings, fragments, unapproved targets, and redirects are rejected. Proxy environment settings are not used. There is no environment switch permitting HTTP or loopback scan targets; tests instantiate `Settings(test_loopback=True)` with a separate exact `127.0.0.1` allowlist only.

## Execution and evidence

- One service process and one active worker; SQLite admission and idempotency are atomic. A data-directory lock prevents competing service instances.
- Target credentials reach the worker only through its stdin pipe, never argv, persisted configuration, or the service token. Per-run files are private, mode 0600 under mode 0700 directories.
- Paced dispatch at most 30 RPM for Sensitive Data and 100 RPM for Garak, with per-profile in-flight concurrency (default 1 for Sensitive, Quick, Custom and Smoke; 10 for Core and 20 for Extended, operator-adjustable to 20): a finished request immediately releases its slot for the next case. Absolute per-request timeout and output-size limits plus profile request/walltime ceilings still apply; slow-drip reads are cut by the per-request chunk-loop deadline, independent of SIGTERM cancellation. Two bounded retries only for transient failures; retries consume the dispatch cap. Repeated errors stop execution.
- Cancellation stops new dispatch, signals the process group, and kills it after a bounded grace period. Already-issued requests cannot be recalled. Parent-service death closes a watchdog pipe so the worker does not remain dispatching as an orphan. Restart marks unfinished metadata interrupted and retains evidence.
- Native probes are reviewed fixed classes, not browser-supplied Python paths. Smoke/Core/Extended sample at most 5/3/64 prompts per class with one generation. The frozen plans contain Smoke 10 cases / 2 probe classes, Core 27 / 9 (three per class), and Extended 1,151 / 46 across 12 technique families. Smoke/Core use the DAN ablation variant to provide enough prompts. Extended includes additional DAN/malware/malicious-request variants, document-embedded injection, renderer-hostile text relay, Jinja/SQL payload echo, cached suffix/tree jailbreaks, past/future-tense rephrasing, disguised requests. Attack-only curation (`runner/curation.py`, frozen in the manifest as `attack_curation`) keeps only genuine attacks/malicious requests: DoNotAnswer prompts are kept by explicitly malicious bundled intent metadata (ordinary professional-advice, fact-checking/false-premise, companion-chat and self-harm-distress prompts are excluded — `HumanChatbox` keeps only its credential/PII-extraction rows — as are token-instability diagnostics, benign in-the-wild dataset entries and dual-use screen-scraping/advice rephrasings). Their detectors are heuristic: no RAG/document retrieval, browser, URL fetch, template rendering, SQL execution, or harmful-payload execution occurs. Encoded-payload probes are not offered or executable. Native API-key, latent-injection, and renderer-relay probes use bundled local resources/deterministic detectors. System-prompt extraction is unavailable because its datasets are not reviewed; ProPILE remains disabled. No automatic model/dataset downloads or remote judges.
- Native success requires zero worker exit, matching native completion UUID, expected probe coverage and attempt counts. Missing hitlogs are not treated as failure or proof of success. Partial/cancelled/error runs are not passes.
- The operator-defined block marker is the exact case-insensitive phrase `blocked by FortiAIGate` in extracted chatbot reply text, accepted for complete HTTP 200/403 replies. Brand mentions alone, reasoning, request text and metadata do not count. Block replies remain visible but are excluded from native model scoring. Native scoring accepts only OpenAI chat/refusal content; other readable replies remain unscored. Metrics deduplicate cases and outputs. Internal reasoning is never displayed as a final chatbot reply.
- API results and JSON exports redact credentials/key-shaped text, fixture identifiers, controls, URLs, and HTML. Raw native artifacts are not served and must not be rendered as trusted HTML. Retention is operator-managed: stop the service before removing a private data directory.

## Local verification only

```sh
.venv-runner/bin/python -m pytest \
  tests/test_runner_api.py tests/test_runner_transport.py \
  tests/test_garak_reports.py tests/test_garak_native.py -q
```

These tests execute real Garak probes/detectors against a local fake OpenAI HTTP server using the constructor-only test allowlist. They do not call the production target or use a real credential. Production gateway authentication, model availability, response policy contract, and load capacity remain unverified.
