"""Budget Control: verify FortiAIGate enforces the hourly spend limit on the budget key.

Sends parallel paid requests in waves until the gateway refuses with HTTP 402
(error.code "budget_exceeded"), then keeps the refusal body as evidence.
Design reference: docs/mockups/budget-control.html.
"""

import html
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests
import streamlit as st

# Mirrors of the FortiAIGate gateway configuration for the budget key:
# per-1M-token rates ($ in, $ out) and the hourly spend limit in dollars.
RATES_PER_1M = {"qwen3.8-flash": (5.0, 50.0)}
HOURLY_BUDGET = 1.00

WAVE = 2            # parallel requests per batch
SAFETY_CAP = 10     # five batches of two requests
# Each request must bill ~$0.12 so that nine paid requests cross the $1.00
# hourly budget and the tenth is refused with 402. Output tokens cost 10x more
# but generation is slow (~20-40 tok/s observed) and the whole non-streaming
# request must finish inside the ~60 s edge/ALB idle timeout that cut earlier
# probes with a 504. So the probe is input-heavy and trivially easy on both
# sides: ~20k padded input tokens ($0.10) plus a ~400-token counting list
# ($0.02), which prefills and generates at full speed in ~30 s.
_PROBE_FILLER = (
    "Stateful inspection firewalls track each connection across packets and compare later packets to an "
    "established session table before admitting them at the perimeter. "
)
_PROBE_INSTRUCTION = (
    "Using the context above as background, list the integers from 1 to 300, one per line, and nothing else."
)
PROBE_PROMPT = _PROBE_FILLER * 750 + _PROBE_INSTRUCTION

CONTRACT_NOTE = (
    '402 with OpenAI-style body error.code = "budget_exceeded", type "payment_required_error", '
    'message "budget exhausted for this API key". Refused at admission: ≈0.2 s, zero tokens billed. '
    "Enforcement lags one request boundary — the request that crosses the limit still succeeds; the next is refused. "
    "A 402 with a different code, or any other status, is reported as-is and never relabelled as budget enforcement."
)


def mask_key(key: str) -> str:
    """Mask a credential for display: first 8 characters only, never the whole value."""
    if not key:
        return ""
    if len(key) < 8:
        return "••••"
    return key[:8] + "…••••"


def _money(value) -> str:
    return f"${value:.2f}"


def _md(text: str) -> str:
    """Escape dollars so Streamlit markdown does not typeset them as a math span."""
    return text.replace("$", r"\$")


USAGE_TOKEN_KEYS = ("prompt_tokens", "completion_tokens", "total_tokens")


def _usage_tokens(data) -> dict:
    """Validated OpenAI-style usage tokens from a parsed body, or {}."""
    if not isinstance(data, dict):
        return {}
    usage = data.get("usage")
    if not isinstance(usage, dict):
        return {}
    return {k: v for k, v in usage.items()
            if k in USAGE_TOKEN_KEYS and isinstance(v, int) and v >= 0}


def _send_probe_request(settings: dict) -> dict:
    """Send one probe and always capture status, usage and the raw body.

    Deliberately self-contained (not send_prompt): the budget page needs the
    numeric status, token usage and refusal body on every response, and must
    keep working even if a long-lived server process holds an older
    common.fortiaigate_test module in memory.
    """
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {settings['api_key']}",
    }
    payload = {
        "model": settings["model"],
        "messages": [{"role": "user", "content": PROBE_PROMPT}],
    }
    out = {"status": "Error", "status_code": None, "raw_body": None,
           "usage": {}, "latency_ms": 0, "error": "Send failed"}
    start = time.time()
    try:
        resp = requests.post(settings["endpoint"], headers=headers, json=payload,
                             timeout=settings["timeout"], allow_redirects=False)
        out["latency_ms"] = int((time.time() - start) * 1000)
        out["status_code"] = resp.status_code
        try:
            body = resp.text
        except Exception:
            body = ""
        key = settings["api_key"]
        out["raw_body"] = body.replace(key, "[REDACTED]") if key else body
        if resp.status_code >= 300:
            out["error"] = f"HTTP {resp.status_code}"
        else:
            out["status"] = "OK"
            out["error"] = ""
            try:
                out["usage"] = _usage_tokens(resp.json())
            except ValueError:
                out["usage"] = {}
    except requests.Timeout:
        out["latency_ms"] = int((time.time() - start) * 1000)
        out["error"] = "Timeout"
    except requests.ConnectionError:
        out["latency_ms"] = int((time.time() - start) * 1000)
        out["error"] = "Connection error"
    except Exception:
        out["latency_ms"] = int((time.time() - start) * 1000)
        out["error"] = "Invalid response or request failure"
    return out


class BudgetRun:
    """One bounded budget-enforcement run. Worker threads never touch Streamlit."""

    def __init__(self, settings: dict):
        self.settings = dict(settings)
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._started = False
        self._records = []
        self._wave = 0
        self._sent = 0
        self._completed = 0
        self._tokens_in = 0
        self._tokens_out = 0
        self._added = 0.0
        self._refusals = 0
        self._status = "running"
        self._verdict = ("warn", "Running · sending parallel requests against the hourly budget…")

    def start(self) -> bool:
        with self._lock:
            if self._started:
                return False
            self._started = True
        threading.Thread(target=self._coordinate, daemon=True).start()
        return True

    def stop(self):
        self._stop.set()

    def snapshot(self) -> dict:
        with self._lock:
            return {
                "status": self._status,
                "verdict": self._verdict,
                "wave": self._wave,
                "sent": self._sent,
                "completed": self._completed,
                "tokens_in": self._tokens_in,
                "tokens_out": self._tokens_out,
                "added": self._added,
                "refusals": self._refusals,
                "records": [dict(r) for r in self._records],
                "settings": dict(self.settings),
            }

    def _send_one(self, wave: int, index: int) -> dict:
        sent = _send_probe_request(self.settings)
        code = sent["status_code"]
        usage = sent.get("usage") or {}
        rec = {
            "index": index,
            "wave": wave,
            "status_code": code,
            "latency_ms": sent["latency_ms"],
            "tokens_in": None,
            "tokens_out": None,
            "cost": None,
            "running_total": None,
            "evidence": None,
            "result": "Error",
            "note": sent["error"] or "Send failed",
        }
        if code == 402:
            # the budget key's only refusal mode: the hourly limit was reached
            rec["result"] = "402 Budget Exceeded"
            rec["evidence"] = sent.get("raw_body") or ""
            rec["tokens_in"], rec["tokens_out"] = 0, 0
            rec["cost"] = 0.0
            rec["note"] = "Hourly budget reached — request refused, zero tokens billed"
        elif sent["status"] == "OK":
            tin = usage.get("prompt_tokens")
            tout = usage.get("completion_tokens")
            rec["tokens_in"], rec["tokens_out"] = tin, tout
            if tin is not None and tout is not None:
                rate_in, rate_out = self.settings["rates"]
                rec["cost"] = tin / 1e6 * rate_in + tout / 1e6 * rate_out
                rec["note"] = "Completed; spend recorded by gateway"
            else:
                rec["note"] = "Completed; token usage unavailable"
            rec["result"] = "200 OK"
        else:
            rec["result"] = f"HTTP {code}" if code else "Error"
            if code == 504:
                rec["note"] = "Gateway time-out — generation exceeded the ~60 s edge idle limit"
        return rec

    def _coordinate(self):
        hit_index = None
        # A 402 refusal costs nothing at admission, so the remaining batches
        # still run and document the enforcement.
        while self._sent < SAFETY_CAP and not self._stop.is_set():
            with self._lock:
                self._wave += 1
                wave = self._wave
                count = min(WAVE, SAFETY_CAP - self._sent)
                first = self._sent + 1
                self._sent += count
            with ThreadPoolExecutor(max_workers=count) as pool:
                futures = [pool.submit(self._send_one, wave, first + j) for j in range(count)]
                for future in as_completed(futures):
                    rec = future.result()
                    with self._lock:
                        self._records.append(rec)
                        self._completed += 1
                        if rec["status_code"] == 402:
                            self._refusals += 1
                            if hit_index is None:
                                hit_index = rec["index"]
                        if rec["cost"] is not None:
                            self._tokens_in += rec["tokens_in"]
                            self._tokens_out += rec["tokens_out"]
                            self._added += rec["cost"]
                        rec["running_total"] = self._added
        with self._lock:
            if hit_index is not None:
                self._status = "done"
                self._verdict = ("ok", f"Budget limit enforced. The gateway refused request #{hit_index} and "
                                        f"{self._refusals - 1} more with 402 budget_exceeded after "
                                        f"{_money(self._added)} added spend this run "
                                        f"({_money(HOURLY_BUDGET)}/hour budget). Actual response and code explanation below.")
            elif self._stop.is_set():
                self._status = "stopped"
                self._verdict = ("warn", f"Stopped by operator after {self._completed} requests. "
                                         f"No conclusion about enforcement.")
            else:
                self._status = "done"
                self._verdict = ("warn", f"Reached the safety cap of {SAFETY_CAP} requests at "
                                         f"{_money(self._added)} added spend without a refusal. "
                                         f"Inconclusive: check the gateway budget window.")


def _settings_from_state() -> dict:
    model = st.session_state.saved_model
    return {
        "endpoint": st.session_state.saved_endpoint,
        "model": model,
        "api_key": st.session_state.saved_budget_api_key,
        "key_mask": mask_key(st.session_state.saved_budget_api_key),
        "rates": RATES_PER_1M.get(model),
        "timeout": st.session_state.saved_timeout,
    }


def _render_settings(settings: dict):
    with st.container(border=True):
        st.subheader("Test settings")
        st.caption("CONNECTION · READ-ONLY FROM CONFIGURATION")
        col_a, col_b = st.columns(2)
        col_a.text_input("Endpoint", value=settings["endpoint"], disabled=True)
        col_b.text_input("Budget key (masked)", value=settings["key_mask"], disabled=True)
        st.caption("MODEL & RATES · CONFIGURED / EXTRACTED BY FORTIAIGATE")
        col_m, col_in, col_out, col_bud = st.columns(4)
        col_m.text_input("Model", value=settings["model"], disabled=True)
        rates = settings["rates"]
        col_in.text_input("Rate $/1M in", value=f"{rates[0]:g}" if rates else "—", disabled=True)
        col_out.text_input("Rate $/1M out", value=f"{rates[1]:g}" if rates else "—", disabled=True)
        col_bud.text_input("Hourly budget", value=f"{_money(HOURLY_BUDGET)} / hour", disabled=True)
        st.caption("Settings cannot be edited here. Rates are configured or extracted by FortiAIGate; the gateway's "
                   "own accounting is authoritative. The budget key is managed on the Configuration page and never "
                   "shown in full. The security suites never use this key.")


_LOG_STYLE = """
<style>
table.bc-log { width:100%; border-collapse:collapse; font-size:12.5px; }
table.bc-log th { text-align:left; color:#8b98a9; font-weight:500; border-bottom:1px solid #30363d; padding:7px 8px; }
table.bc-log td { border-bottom:1px solid #30363d; padding:7px 8px; color:#a8b3c2; }
table.bc-log td.num, table.bc-log th.num { text-align:right; }
.bc-pill { border-radius:10px; padding:2px 9px; font-size:11px; font-weight:600; white-space:nowrap; }
.bc-pill.ok { background:#12261a; color:#7ee2a0; border:1px solid #274b31; }
.bc-pill.stop { background:#2c1c20; color:#f0a9a2; border:1px solid #67302b; }
.bc-pill.warn { background:#2b2317; color:#e3c56d; border:1px solid #5c4a1e; }
</style>
"""


def _log_html(records: list) -> str:
    """Request log as a mockup-styled table: result pills, right-aligned numbers.

    Rows are in completion order (the order records were appended), so the
    running total increases monotonically down the table even when responses
    within a batch return out of order. "#" stays the send-time request number.
    """
    rows = []
    for rec in records:
        if rec["status_code"] == 200:
            pill = "ok"
        elif rec["status_code"] == 402:
            pill = "stop"
        else:
            pill = "warn"
        cells = [
            str(rec["index"]),
            f'<span class="bc-pill {pill}">{html.escape(rec["result"])}</span>',
            f"{rec['latency_ms'] / 1000:.1f} s",
            "—" if rec["tokens_in"] is None else f"{rec['tokens_in']:,}",
            "—" if rec["tokens_out"] is None else f"{rec['tokens_out']:,}",
            _money(rec["cost"]) if rec["cost"] is not None else "—",
            _money(rec["running_total"]) if rec["running_total"] is not None else "—",
            html.escape(rec["note"]),
        ]
        rows.append("<tr><td>{}</td><td>{}</td><td class='num'>{}</td><td class='num'>{}</td>"
                    "<td class='num'>{}</td><td class='num'>{}</td><td class='num'>{}</td><td>{}</td></tr>"
                    .format(*cells))
    return ("<table class='bc-log'><thead><tr><th>#</th><th>Result</th><th class='num'>Latency</th>"
            "<th class='num'>In</th><th class='num'>Out</th><th class='num'>Cost</th>"
            "<th class='num'>Running total</th><th>Note</th></tr></thead><tbody>"
            + "".join(rows) + "</tbody></table>")


def _render_results(snap: dict):
    col_r, col_t, col_s, col_f = st.columns(4)
    col_r.metric("Requests completed", snap["completed"])
    col_t.metric("Tokens in / out", f"{snap['tokens_in']} / {snap['tokens_out']}")
    col_s.metric("Added spend", _money(snap["added"]))
    col_f.metric("402 refusals", snap["refusals"])
    kind, text = snap["verdict"]
    ({"ok": st.success, "err": st.error}.get(kind, st.warning))(_md(text))

    with st.container(border=True):
        st.subheader("Request log")
        if snap["records"]:
            st.markdown(_LOG_STYLE + _log_html(snap["records"]), unsafe_allow_html=True)
        else:
            st.caption("No requests yet.")

    hit = next((r for r in snap["records"] if r["status_code"] == 402), None)
    if hit:
        with st.container(border=True):
            st.subheader(f"Budget-hit response (request #{hit['index']})")
            st.code(f"HTTP/1.1 402 Payment Required\nContent-Type: application/json\n\n{hit['evidence']}")
            st.markdown(_md(
                "**402 — Payment Required.** FortiAIGate tracks per-key spend against the configured hourly "
                f"budget ({_money(HOURLY_BUDGET)}/hour). When the hourly total reaches the limit, the gateway "
                "refuses further requests **at admission** — ≈0.2 s latency, zero tokens billed — with "
                '`error.code = "budget_exceeded"`. Enforcement lags one request boundary: the request that '
                "crosses the limit still succeeds; the next one is refused."))


def _render_run_area(snap, active: bool):
    with st.container(border=True):
        col_run, col_stop, _ = st.columns([1, 1, 4])
        started = col_run.button("Run budget test", type="primary", key="budget_start", disabled=active)
        if col_stop.button("Stop", key="budget_stop", disabled=not active):
            st.session_state["_budget_run"].stop()
        st.caption("Navigating away does not cancel an active run; it ends at the first 402, the safety cap, or Stop.")
        if snap:
            batches = -(-SAFETY_CAP // WAVE)
            if snap["status"] == "running":
                # the bar moves when requests go out, like the Prompt Injection page
                head = f"Sending {snap['sent']} of {SAFETY_CAP} requests · batch {snap['wave']}/{batches}..."
            else:
                head = f"Finished · {snap['completed']} of {SAFETY_CAP} requests"
            st.progress(min(snap["sent"] / SAFETY_CAP, 1.0), text=_md(head))
            st.progress(min(snap["added"] / HOURLY_BUDGET, 1.0),
                        text=_md(f"added this run: {_money(snap['added'])} of {_money(HOURLY_BUDGET)} / hour"))
        else:
            st.progress(0.0, text="Idle · no requests sent")
            st.progress(0.0, text=_md(f"added this run: {_money(0.0)} of {_money(HOURLY_BUDGET)} / hour"))
    if started:
        run = BudgetRun(_settings_from_state())
        st.session_state["_budget_run"] = run
        run.start()
        st.rerun()
    return started


def _render_contract():
    with st.container(border=True):
        st.subheader("Verified enforcement contract")
        st.caption(CONTRACT_NOTE)


@st.fragment(run_every=1.0)
def _live_fragment():
    run = st.session_state.get("_budget_run")
    snap = run.snapshot() if run else None
    if not snap or snap["status"] == "running":
        _render_settings(snap["settings"] if snap else _settings_from_state())
        _render_run_area(snap, active=True)
        if snap:
            _render_results(snap)
        _render_contract()
        return
    st.rerun()


def render_budget_control():
    st.header(":material/account_balance_wallet: Budget Control")
    st.caption("Verify that FortiAIGate enforces the spend limit on the budget key: send parallel requests "
               "until the gateway refuses, and keep the refusal as evidence.")

    # An active run keeps rendering from its frozen settings, even if the live
    # configuration changes underneath it.
    run = st.session_state.get("_budget_run")
    snap = run.snapshot() if run else None
    if snap and snap["status"] == "running":
        _live_fragment()
        return

    live = _settings_from_state()
    if not live["endpoint"] or not live["model"] or not live["api_key"]:
        st.warning("Configure the Endpoint URL, Model and the **API key (Budget Control)** on the "
                   "**Configuration** page first.", icon=":material/warning:")
        return
    if not live["rates"]:
        st.warning(f"No rate configured for model **{live['model']}**; Budget Control cannot price this run.",
                   icon=":material/warning:")
        return

    _render_settings(snap["settings"] if snap else live)
    _render_run_area(snap, active=False)
    if snap:
        _render_results(snap)
    _render_contract()
