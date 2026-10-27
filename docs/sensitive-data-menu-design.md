# Sensitive Data assessment: unified selection design

**Status:** mockup only; application changes await confirmation of the combined design.
**UI audience:** customers evaluating FortiAIGate data protection.
**Document audience:** PoC owners and implementing engineers.
**Date:** 9 October 2026.

## Current mockup

Open [Sensitive Data](mockups/sensitive-data.html) in a browser. The menu links to [Garak Testing](mockups/garak-testing.html) and the matching Intelligent Routing / Rate Limit placeholders.

- [Quick check — locked category selection](mockups/sensitive-01-selection.png)
- [Custom — editable category selection](mockups/sensitive-05-custom.png)
- [Selected test-case preview](mockups/sensitive-02-test-cases.png)
- [Results and evidence examples](mockups/sensitive-03-evidence.png)
- [Intelligent Routing placeholder](mockups/menu-01-routing.png)
- [Rate Limit placeholder](mockups/menu-02-rate-limit.png)
- [Mobile layout](mockups/sensitive-04-mobile.png)

This revision supersedes the earlier separate DLP/Garak tab design. The old case-list and Garak-tab screenshots are not the current design.

## Customer-facing presentation

Use **Test selection** and **Results & evidence** as the two tabs. Do not expose redesign history, migration language, or labels such as “Existing DLP cases,” “original cases,” and “preserved suite” in the customer interface.

HKID and Credit cards are the first two rows of one checkbox-based test catalog. Additional Garak disclosure categories follow in the same list. Technical provenance remains available in **Test source & interpretation**, without presenting the customer with two disconnected selection workflows or falsely labeling the HKID/card fixtures as native Garak probes.

### Simple profiles

| Profile | Selected categories | Fixed test cases | Additional Garak probes |
|---|---|---:|---|
| **Quick check** — default, smoke-test equivalent | HKID + Credit cards | 6 | None |
| **Custom** | User-selected categories | Derived from selection | Optional |

There are only two profiles. **Quick check** selects exactly HKID + Credit cards and clears all additional probes. All category checkboxes are natively disabled and their labels/counts greyed out; an explicit lock message instructs the user to switch to Custom. Case-preview buttons remain active because reading cases does not change selection. **Custom** retains the current choices and unlocks available categories; ProPILE stays disabled pending dataset review. To run HKID only or cards only, use Custom and select that category. An empty selection disables review and selected-case preview. Counts, review text, and preview contents all follow the same selection state.

The six/two/four counts are prompt counts, not unlimited retry budgets or guarantees of a successful response. Quick check proposes one generation per fixed prompt. A real runner must separately enforce request/retry/time limits.

### One category list

1. **HKID** — two fixed prompts, with **View 2 cases**.
2. **Credit cards** — four fixed prompts, with **View 4 cases**.
3. **API-key disclosure** — optional Garak probes.
4. **Personal information · ProPILE** — disabled until dataset review; details remain readable.
5. **Known-text replay** — optional Garak probes.
6. **System-prompt disclosure** — optional Garak probes.

Each additional category offers **View details**. These families have unresolved prompt counts in the offline mockup. Never display “6 tests” as the complete scope after adding a Garak family: show fixed-case count and additional-family count separately.

## How customers see the actual test cases

**View test cases** opens a read-only dialog containing the currently selected fixed prompts, case labels, and expected outcomes. Per-category preview buttons show that category even if unchecked, without changing the run selection.

- Identifiers are masked by default for presentation.
- **Reveal test values** shows the exact full HKID/card prompt strings, including the current fixture values.
- Closing or reopening the dialog returns it to masked mode.
- Display masking never changes outbound payloads.
- The review dialog names only the selected categories and offers another route to their prompt preview.

The local HTML contains the fixed test values to support this reveal interaction. Masking is a display feature, **not a security boundary**: anyone with the file can inspect its source. Do not distribute the HTML as if it contained no identifiers. Screenshots linked above remain masked. The values are carried from the application's test fixtures; no claim is made about real-world ownership or validity.

### Garak-generated cases

The offline preview does not invent “actual Garak prompts.” Its detail cards explicitly say the exact prompts are not loaded. In the implementation, resolve the selected plugin classes and approved datasets into a read-only manifest before execution for static/dataset-driven probes. Allow browsing that manifest from the same test-preview experience.

Network-active plugin initialization must not occur merely because the operator opens a preview. The runner needs a controlled manifest-resolution step that does not contact the target. Record manifest version/hash with the reviewed configuration. Adaptive follow-up prompts cannot all be known in advance; disclose this and record them in per-request evidence if such probes are later enabled. No adaptive probes are included in Quick check.

## Fixture and evidence contract

The application registry [SDL_TEST_PROMPTS](../attack_tester/app.py#L183) remains the source of truth. Keep all six full prompt strings, values, category names, and order unchanged. Do not regenerate values, normalize formatting, or correct identifier checksums as part of the UI work.

| Display ID | Purpose | Documented expected result |
|---|---|---|
| HKID-01 | HKID validation | Blocked — PII detected |
| HKID-02 | HKID extraction | Blocked — PII detected |
| CARD-01 | Visa validation | Blocked — Financial PII detected |
| CARD-02 | Mastercard storage for future purchases | Blocked — Financial PII detected |
| CARD-03 | Visa payment confirmation | Blocked — Financial PII detected |
| CARD-04 | Amex type and validity | Blocked — Financial PII detected |

IDs/titles are display metadata, not changes to the payloads. Expectations come from [the PoC guide](FortiAIGate_PoC_Document.md#L296), not observed results. The revised batch flow uses **Review N tests**, not the earlier unconditional Run all 6 action: HKID only must review only its two cases; Credit cards only must review only its four.

**Configuration owns all connection settings:** full endpoint, explicit model, SDK base URL, API credential reference, and connection-level options. Sensitive Data and Garak Testing must consume this saved configuration without repeating its fields or values in ordinary page summaries or review dialogs. The Sensitive Data sidebar is now **Selected tests**, containing scope and counts only; Garak uses **Scan summary** for profile and run budgets. Run-specific budgets belong with the scan; connection details belong in Configuration. The Configuration page itself is not rebuilt in this mockup revision. Saved app configuration has not changed. Before actual execution, use the explicit configured model instead of the incompatible URL-segment inference. Store a configuration-version reference and immutable target metadata with the run internally for reproducibility, without displaying credentials or duplicating settings UI.

Gateway input protection and model disclosure are different evidence types despite sharing one selection interface:

- HKID/card cases assess the gateway's handling of sensitive values supplied in a request.
- Native Garak probes assess output patterns, withheld fields, replay, or supplied test instructions.
- Keep expected policy, confirmed gateway outcome, and detector score/threshold separate.
- Require a documented gateway policy signal or correlated audit event; a substring match, refusal, or 403 alone is insufficient.
- Errors/unscored outputs stay unknown, not passes. A regex match is not proof of an active credential or actual data theft.

Use the shared runner/evidence architecture in [the main Garak design](garak-testing-design.md), not another scanner service. A future custom Garak wrapper may reuse the fixture registry, but must not duplicate/alter payloads or pretend an output detector proves input rejection.

## Garak coverage reference

| Native family | Coverage | Limitation |
|---|---|---|
| `apikey.GetKey` / `apikey.CompleteKey` | Credential-shaped model output | Pattern match, not proof of a valid key; never test returned strings against services. |
| `propile.PIILeak*` | Withheld-field/relationship elicitation from reference records | Inactive by default; approved dataset required; trigger overlap can be coincidental. |
| `leakreplay` | Benchmark literary/news text reproduction | Not proof of private tenant access or definitive training membership. |
| `sysprompt_extraction.SystemPromptExtraction` | Extraction of supplied synthetic system prompts | Not automatically leakage of the gateway's real hidden instructions. |

No dedicated native HKID/card input-DLP suite was found in the reviewed v0.17.0 probe/detector source scope. Keep those fixed tests as FortiAIGate input-protection cases within the unified catalog. Do not use real personal datasets for ProPILE by default, and do not interpret synthetic canaries as proof of training-data memorization.

## Menu and planned pages

Keep the proposed **Workspace / Test Suites / Planned** grouping and dark theme with red active indicator. Retain Shadow AI and the other existing navigation entries. The Sensitive Data label remains short and customer-facing.

Intelligent Routing and Rate Limit use the same placeholder: individual title, **To be constructed**, and **Content to be added.** No testing controls appear. The app's current Routing implementation remains untouched pending confirmation.

## Verification and approval boundary

Completed mockup checks:

- AST comparison confirms application fixtures are unchanged from Git HEAD.
- Revealed prompt text matches all six application fixture strings exactly and in order.
- Only Quick check / Custom remain; Quick check selects exactly six HKID/card prompts and clears additional probes.
- Quick check disables and greys all category selectors while retaining readable case previews; Custom unlocks available categories and keeps ProPILE gated.
- Custom HKID-only/card-only choices produce two/four-case scopes; counts, previews, and review remain aligned.
- Sensitive Data's selection, evidence, and review dialog contain no repeated endpoint/model/credential values.
- Category previews do not change selection. Reveal resets on close/reopen.
- Empty selection disables actions; additional-only selection shows no misleading fixed-case count.
- Garak details disclose unresolved manifests; ProPILE selection is gated.
- Evidence, cross-mockup links, matching placeholders, and keyboard/mobile navigation work.
- Page/dialog overflow checks passed at 1600, 1280, 1024, 768, and 390 pixels.
- Local browser run recorded zero JavaScript errors and zero HTTP/HTTPS requests.
- Masked screenshots were rendered and visually inspected.
- An extra label-click test initially timed out because Playwright correctly treated the associated checkbox as disabled. A real pointer-click test then confirmed the label cannot change Quick check selections; no UI fix was required.

No app source, deployment, dependency, saved configuration, or credential changed. No live test, commit, or push was performed. Implementation still awaits the user's combined-design confirmation.

## Sources

- [API-key probes](https://github.com/NVIDIA/garak/blob/v0.17.0/garak/probes/apikey.py).
- [ProPILE probes](https://github.com/NVIDIA/garak/blob/v0.17.0/garak/probes/propile.py) and [ethical guidance](https://github.com/NVIDIA/garak/blob/v0.17.0/docs/source/probes/propile.rst).
- [Known-text replay](https://github.com/NVIDIA/garak/blob/v0.17.0/garak/probes/leakreplay.py).
- [Synthetic system-prompt extraction](https://github.com/NVIDIA/garak/blob/v0.17.0/garak/probes/sysprompt_extraction.py).
