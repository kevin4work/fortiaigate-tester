# App revamp implementation notes

The working app now follows the latest Sensitive Data and Garak designs. The HTML files under `docs/mockups` remain design references; their synthetic data is not used by the app.

## Implemented

- Grouped dark navigation and centralized Configuration.
- Configuration starts with an empty API-key field; model is explicit and not inferred from URL segments. The app no longer enforces or transmits an output-token budget. Provider limits and request/rate/time safeguards still apply.
- Sensitive Data Quick check/Custom selection and Garak profiles on a single-screen flow: Run all tests / Stop, exact case progress, a small outcome/latency summary, and prompt/response cards grouped by technique. Budgets, history and technical details are secondary expanders; case cards paginate 10/20/50 per page with Previous/Next buttons, and the UI no longer offers an evidence export button. Exact six fixed prompts and Configuration-only credentials remain unchanged.
- Exact six HKID/card payloads moved to `common/test_catalog.py`, unchanged in value/order/grouping.
- Garak Smoke/Core/Extended profiles backed by actual Garak 0.17.0 probes/detectors, with frozen reviewed manifests and no automatic dataset/model downloads.
- Private authenticated FastAPI runner, session-scoped history, one active worker, idempotency, bounded dispatch/retries, cancellation, native report verification and sanitized exports.
- Budget Control page verifying the per-key spend cap (402 budget_exceeded). Rate Limit page verifying the 5 RPM / 100,000 TPM limits on a dedicated rate-limit key. Shadow AI reserved under PLANNED. Manual Prompt Injection retained.

## Validation

The simplified inline UI passed **110 app tests and 80 runner tests**. Real browser tests used the actual native Garak worker against a loopback fake API: Smoke produced three individual results with 3/3 progress; Quick check produced six with 6/6 progress; stopping a new run preserved partial progress and unfinished cards. Both environment dependency checks passed. No production model requests were sent by these tests.

- Python 3.9.6 / Streamlit 1.50.0 app environment created and exercised.
- Separate Python 3.12.13 / Garak 0.17.0 runner environment created from the resolved lock.
- App tests cover fixtures, configuration persistence/key clearing, transport/model behavior, native UI state, dialogs, direct-start configuration gating, idempotent retries and client interactions.
- Runner tests exercise real Garak probes and detectors against a loopback fake OpenAI server, plus authentication, ownership, budgets, retries, cancellation, recovery, report parsing and export redaction.
- Real Chromium checks cover grouped navigation, blank-key Configuration, native disabled Quick selectors, editable Custom, case/manifest dialogs, close/Escape/reveal-reset, and desktop/mobile layout.
- App-to-private-runner catalog/readiness checks were exercised without sending a production model request.

An actual browser found a dialog-fragment close defect missed by the initial AppTest checks; the dialog now requests an app-level rerun when its open state is cleared. Browser checks verify the overlay disappears. Independent review also led to targeted regression work for terminal job transitions/cancellation races, native probe preprocessing, absolute request deadlines, private-client proxy isolation, and partially scored output labels. Repeated native tests exposed a separate card-redaction collision with numeric UUID tails; correlation identifiers require structural handling rather than an exemption for arbitrary response content. Some preliminary browser scripts also needed Streamlit-specific selectors for icon-prefixed buttons and hidden native checkbox inputs; those were test-driver issues, not application failures.

## Remaining operational boundaries

- No production endpoint scan, AWS deployment, commit or push was performed.
- The supplied chat credential was not used, stored, displayed as a default, or included in source/test files.
- Scanner execution defaults to disabled in server settings. At the user's request, the current loopback development runner was restarted with execution enabled; it sends no model requests until the user clicks Run all tests. There is no review dialog or authorization checkbox. Configuration, catalog availability, authentication, allowlist, budgets and cancellation remain enforced.
- Production gateway block provenance is unverified. Unknown outcomes are not mislabeled as confirmed blocks or passes.
- ProPILE stays disabled pending dataset review. Native system-prompt extraction is unavailable until its external dataset is approved.
- Profiles are bounded reviewed samples, not complete Garak/OWASP coverage. Garak Core/Extended run with operator-adjustable in-flight concurrency (defaults 10/20, ceiling 20); Sensitive and Smoke stay serial.
- Public deployment needs operator authentication and TLS; existing deployment scripts do not provision the runner.
- macOS Python 3.9.6 emits urllib3's LibreSSL compatibility warning. Runner tests emit an upstream Starlette/AnyIO deprecation warning. These do not fail the offline tests; production TLS compatibility remains a deployment check.

See the root README and `runner/README.md` for launch instructions, environment boundaries, exact coverage, and security prerequisites.
