# Verification playbook (approved 15 October 2026)

Standing process for UI updates and page-feature requests in this project. Approved by the project owner to keep small tasks small.

## Rules

1. **Diff before regenerating any generated/frozen file** (`runner/manifest.json` and similar). Use `tools/regen_manifest.py`, which prints per-probe added/removed prompts and metadata deltas and writes only with `--apply`. If the diff shows removals that are not explained by a code change, treat them as manual operator edits: stop and ask before applying.
2. **Targeted tests first; full suites only at the end, and only when runner/worker/manifest code changed.** Pure UI, text, or test-only changes run `tools/check.sh` (fast mode). Add `full` only for runner/transport/worker/manifest changes: `tools/check.sh full`.
3. **Batch UI tweaks into one restart + one browser pass.** Streamlit caches imported modules, so each restart cycle costs ~1–2 min; collect related tweaks before restarting.
4. **Use the locator recipes below for browser checks.** Browser verification is reserved for layout/geometry questions AppTest cannot answer; behavior and control-state assertions belong in AppTest (`tests/test_inline_results.py`, `tests/test_selection.py`).
5. **One command gate:** `tools/check.sh [full]` runs the app suite (Python 3.9.6 / Streamlit 1.50) plus the fast backend files (Python 3.12 / Garak 0.17).

Browser checks always run against the loopback harness pattern (`fake OpenAI server + Settings(test_loopback=True)` runner on port 8766 + app on 8518 with `FORTIAIGATE_ENDPOINT` pointed at the fake). Never verify UI by clicking through a session whose Configuration still holds the production endpoint.

## Streamlit locator recipes (verified on 1.50)

- Sidebar navigation: `page.locator('[data-testid="stSidebar"] .stButton button').filter(has=page.get_by_text(LABEL, exact=True)).click()` — button accessible names include the material icon text, so role/name matching fails.
- Profile radios with custom labels: click via `page.locator('[data-testid="stRadio"] label').filter(has_text=SUBSTRING)`; `exact=True` breaks as soon as labels carry counts/suffixes.
- Selectbox (baseweb combobox, not a native select): value via `page.locator('[data-testid="stSelectbox"] [data-baseweb="select"]').inner_text()`; change via click then `page.get_by_role('option', name=VALUE, exact=True).click()`, or click + `page.keyboard.type(VALUE)` + Enter when option clicks are flaky.
- Disabled native checkboxes: inputs are visually hidden; assert state via `page.get_by_role('checkbox', name=X).is_disabled()` with `wait_for(state='attached')`, never `visible`.
- Caption/text duplication: `text=Foo` matches both the caption container and its inner `<p>`; count via `page.locator('[data-testid="stCaptionContainer"]')` or use `get_by_text(..., exact=True)` for assertions.
- Icon-bearing expanders (e.g. “View response”) surface as `status` elements in AppTest (`app.get("status")`), not `expander`.
- Geometry checks: compare `bounding_box()` of the pager container vs first/last control; assert single-row layout via the set of `y` values of the buttons; assert right-flush via container right edge minus last element right edge.
- `st.text` strips trailing whitespace — fixtures compared through rendered text must be `.strip()`-safe.
- After any `attack_tester/` module change, restart the app process; hot reload does not re-import modules.

## Restart recipe

Stop the previous harness/service task with TaskStop (never `lsof | xargs kill` on ports — it was denied and is unsafe), then relaunch: runner `uvicorn runner.api:create_app --factory --host 127.0.0.1 --port 8765` with `FORTIAIGATE_RUNNER_TOKEN` (random per launch), `FORTIAIGATE_SCANS_ENABLED=true`, `FORTIAIGATE_RUNNER_DATA="$PWD/.runner-data"`; app `streamlit run app.py` from `attack_tester/` on 8517 (or 8518 for the harness). Browser sessions lose Configuration after restart; re-enter the API key.
