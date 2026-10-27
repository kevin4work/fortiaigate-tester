"""Rate Limit: verify FortiAIGate enforces the request-rate and token-rate limits on the rate-limit key.

Two bounded tests share the page: small requests sent one at a time for the
5 requests/minute limit, and token-heavy requests plus a small confirm for the
100,000 tokens/minute limit. The gateway uses fixed clock-minute buckets shared
by both limits; runs start immediately and a run that crosses a minute boundary
is reported as such. Refusals (HTTP 429, error.code "rate_limit_exceeded") are
kept as evidence. Design mirrors Budget Control.
"""

import html
import math
import threading
import time

import requests
import streamlit as st

# Limits enforced by the gateway on the rate-limit key in fixed clock-minute
# buckets shared by both limits (verified against the production gateway).
RPM_LIMIT = 5
TPM_LIMIT = 100000

RPM_BURST = 8             # small requests sent one at a time: first 5 admitted, 3 refused
TPM_XL_COUNT = 3          # large requests that carry the token budget over the limit
TPM_XL_FILLER_REPEATS = 1500
REQUEST_INTERVAL = 3.0    # seconds between sequential requests
COOLDOWN_SECONDS = 65     # the bucket is shared: wait it out between tests

SMALL_PROMPT = "Reply with the single word OK and nothing else."
# Calibration (measured): filler x1500 plus the counting instruction is exactly
# 39,088 prompt tokens; three of them total ~118k tokens, above the 100,000 TPM
# limit, while staying at 4 requests — below the 5 RPM cap. Sent one at a time,
# each large request takes ~11-15 s end to end; the page gate still requires a
# >= 90 s timeout for safety.
_XL_FILLER = (
    "Stateful inspection firewalls track each connection across packets and compare later packets to an "
    "established session table before admitting them at the perimeter. "
)
_XL_INSTRUCTION = (
    "Using the context above as background, list the integers from 1 to 100, one per line, and nothing else."
)
XL_PROMPT = _XL_FILLER * TPM_XL_FILLER_REPEATS + _XL_INSTRUCTION

CONTRACT_NOTE = (
    '429 with OpenAI-style body error.code = "rate_limit_exceeded", type "rate_limit_exceeded", '
    'message "rate limit exceeded for this API key". Refused at admission: ≈0.2-1 s, zero tokens. '
    "Token usage is counted when a request completes, so enforcement lags one request boundary — the "
    "request that crosses the limit still succeeds; the next is refused. Both limits share fixed "
    "clock-minute buckets: 5 admissions and 100,000 counted tokens per clock minute. The body does not "
    "name the limit that was hit — each test sends only a few requests, so attribution is by design, "
    "and a run that crosses a minute boundary is reported as such. A 429 during the other test, or any "
    "other status, is reported as-is and never relabelled."
)


def mask_key(key: str) -> str:
    """Mask a credential for display: first 8 characters only, never the whole value."""
    if not key:
        return ""
    if len(key) < 8:
        return "••••"
    return key[:8] + "…••••"


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


def _send_request(settings: dict, prompt: str) -> dict:
    """Send one request and always capture status, usage and the raw body.

    Deliberately self-contained (a copy of the Budget Control sender, not an
    import): the page needs the numeric status, token usage and refusal body
    on every response, and must keep working even if a long-lived server
    process holds an older attack_tester.budget_control module in memory.
    """
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {settings['api_key']}",
    }
    payload = {
        "model": settings["model"],
        "messages": [{"role": "user", "content": prompt}],
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


class RateLimitRun:
    """One bounded rate-limit enforcement run. Worker threads never touch Streamlit."""

    def __init__(self, settings: dict, kind: str):
        self.kind = kind
        self.settings = dict(settings)
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._started = False
        self._records = []
        self._sent = 0
        self._completed = 0
        self._tokens_in = 0
        self._tokens_out = 0
        self._tokens_counted = 0
        self._refusals = 0
        self._last_request_at = None
        self._status = "running"
        if kind == "rpm":
            self._planned = RPM_BURST
            self._verdict = ("warn", "Running · sending small requests one at a time against the "
                                     "request-rate limit…")
        else:
            self._planned = TPM_XL_COUNT + 1
            self._verdict = ("warn", "Running · sending token-heavy requests one at a time against the "
                                     "token-rate limit…")

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
                "kind": self.kind,
                "status": self._status,
                "verdict": self._verdict,
                "sent": self._sent,
                "completed": self._completed,
                "planned": self._planned,
                "tokens_in": self._tokens_in,
                "tokens_out": self._tokens_out,
                "refusals": self._refusals,
                "records": [dict(r) for r in self._records],
                "settings": dict(self.settings),
                "last_request_at": self._last_request_at,
            }

    def _steps(self) -> list:
        """Ordered prompt list: every request goes out one at a time, in order."""
        if self.kind == "rpm":
            return [SMALL_PROMPT] * RPM_BURST
        return [XL_PROMPT] * TPM_XL_COUNT + [SMALL_PROMPT]

    def _send_one(self, index: int, prompt: str) -> dict:
        sent = _send_request(self.settings, prompt)
        code = sent["status_code"]
        usage = sent.get("usage") or {}
        rec = {
            "index": index,
            "status_code": code,
            "latency_ms": sent["latency_ms"],
            "tokens_in": None,
            "tokens_out": None,
            "running_tokens": None,
            "evidence": None,
            "result": "Error",
            "note": sent["error"] or "Send failed",
        }
        if code == 429:
            # the rate-limit key's refusal mode for both limits; the body does
            # not name the limit, attribution comes from the test design
            rec["result"] = "429 Rate Limited"
            rec["evidence"] = sent.get("raw_body") or ""
            rec["tokens_in"], rec["tokens_out"] = 0, 0
            if self.kind == "rpm":
                rec["note"] = "Requests-per-minute limit reached — refused at admission, zero tokens"
            elif index <= TPM_XL_COUNT:
                rec["note"] = ("Refused at admission — the clock minute was already full "
                               "before this test")
            else:
                rec["note"] = (f"Token budget spent — refused at admission with only {index - 1} "
                               f"requests sent, below the {RPM_LIMIT} RPM cap")
        elif sent["status"] == "OK":
            tin = usage.get("prompt_tokens")
            tout = usage.get("completion_tokens")
            rec["tokens_in"], rec["tokens_out"] = tin, tout
            if tin is not None and tout is not None:
                rec["note"] = "Completed; tokens counted by gateway"
                total = usage.get("total_tokens")
                rec["usage_total"] = total if total is not None else tin + tout
            else:
                rec["note"] = "Completed; token usage unavailable"
            rec["result"] = "200 OK"
        else:
            rec["result"] = f"HTTP {code}" if code else "Error"
            if code == 504:
                rec["note"] = "Gateway time-out — generation exceeded the ~60 s edge idle limit"
        return rec

    def _coordinate(self):
        # Requests go out the moment the run starts; the 65 s cooldown between
        # runs already keeps the previous test's traffic in an earlier bucket.
        for index, prompt in enumerate(self._steps(), 1):
            if index > 1 and self._stop.wait(REQUEST_INTERVAL):
                break
            if self._stop.is_set():
                break
            # A 429 refusal costs nothing at admission, so the remaining
            # requests still run and document the enforcement.
            with self._lock:
                self._sent += 1
                self._last_request_at = time.time()
            rec = self._send_one(index, prompt)
            counted = rec.pop("usage_total", None)
            with self._lock:
                self._records.append(rec)
                self._completed += 1
                if rec["status_code"] == 429:
                    self._refusals += 1
                elif (rec["status_code"] == 200 and rec["tokens_in"] is not None
                      and rec["tokens_out"] is not None):
                    self._tokens_in += rec["tokens_in"]
                    self._tokens_out += rec["tokens_out"]
                if counted is not None:
                    self._tokens_counted += counted
                rec["running_tokens"] = self._tokens_counted
        with self._lock:
            sent, completed, refusals = self._sent, self._completed, self._refusals
            tokens = self._tokens_counted
            admitted = sum(1 for r in self._records if r["status_code"] == 200)
            # An operator-truncated run gets no enforcement verdict, even if it
            # already saw 429s: every verdict below assumes the full sample.
            # Stop pressed after the last request drained keeps them.
            if self._stop.is_set() and (completed < self._planned or not refusals):
                self._status = "stopped"
                self._verdict = ("warn", f"Stopped by operator after {completed} requests. "
                                         f"No conclusion about enforcement.")
            elif refusals and self.kind == "rpm":
                self._status = "done"
                if admitted:
                    first_ref = min(r["index"] for r in self._records if r["status_code"] == 429)
                    resumed = next((r["index"] for r in self._records
                                    if r["status_code"] == 200 and r["index"] > first_ref), None)
                    if resumed:
                        tail = (f" Admissions resumed at request #{resumed} because the run crossed a "
                                f"clock-minute boundary; the refusals document one bucket filling to "
                                f"{RPM_LIMIT}.")
                    elif admitted > RPM_LIMIT:
                        # refusals only come at the run's end here: the boundary fell early,
                        # the first bucket took <5 admissions and the second filled to 5
                        tail = (f" The run crossed a clock-minute boundary, so the {admitted} admissions "
                                f"span two buckets of at most {RPM_LIMIT} each; the refusals document the "
                                f"second bucket filling to {RPM_LIMIT}.")
                    else:
                        tail = ""
                    self._verdict = ("ok", f"Request-rate limit enforced. The gateway admitted the first "
                                           f"{admitted} of {sent} requests sent one at a time and refused "
                                           f"{refusals} with 429 rate_limit_exceeded at admission ({RPM_LIMIT} "
                                           f"requests per clock-minute limit).{tail} Actual response and code "
                                           f"explanation below.")
                else:
                    self._verdict = ("warn", f"All {sent} requests were refused with 429, but a clean run "
                                             f"should admit the first {RPM_LIMIT} of {RPM_BURST} — the clock "
                                             f"minute was already full from earlier traffic, so the limit that "
                                             f"refused them is ambiguous. Wait a minute and run again.")
            elif refusals and self.kind == "tpm":
                self._status = "done"
                if any(r["status_code"] == 429 and r["index"] <= TPM_XL_COUNT for r in self._records):
                    self._verdict = ("warn", "Attribution ambiguous: a large request was itself refused, so the "
                                             "clock minute was already busy before this test. Only "
                                             f"{sent} requests were sent, below the {RPM_LIMIT} RPM cap, so the "
                                             "refusal cannot be from this test's own request rate. Wait a minute "
                                             "and run again.")
                else:
                    xl_ok = sum(1 for r in self._records
                                if r["index"] <= TPM_XL_COUNT and r["status_code"] == 200)
                    if xl_ok == TPM_XL_COUNT and tokens >= TPM_LIMIT:
                        self._verdict = ("ok", f"Token limit enforced. {TPM_XL_COUNT} large requests sent one "
                                               f"at a time carried {tokens:,} tokens into the clock minute — "
                                               f"above the {TPM_LIMIT:,} TPM limit — and the confirm request "
                                               f"(the {sent}th request, below the {RPM_LIMIT} RPM cap) was "
                                               f"refused with 429 rate_limit_exceeded. Actual response and code "
                                               f"explanation below.")
                    else:
                        self._verdict = ("warn", f"The confirm request was refused, but the large requests "
                                                 f"carried only {tokens:,} counted tokens ({xl_ok} of "
                                                 f"{TPM_XL_COUNT} completed) — not above the {TPM_LIMIT:,} TPM "
                                                 f"limit — so the refusal cannot be attributed to this test's "
                                                 f"own token usage. Inconclusive: check the gateway "
                                                 f"configuration and rerun.")
            else:
                self._status = "done"
                if self.kind == "rpm":
                    self._verdict = ("warn", f"Reached the end of the test with {admitted} of {sent} requests "
                                             f"admitted, {sent - admitted} failed and no 429 refusal. The run "
                                             f"may have split across two clock-minute buckets (each admits "
                                             f"{RPM_LIMIT}), or the gateway did not enforce. Inconclusive: run "
                                             f"again right at a minute boundary, or check the gateway "
                                             f"rate-limit configuration and key policy.")
                else:
                    self._verdict = ("warn", f"Reached the end of the test at {tokens:,} counted tokens without "
                                             f"a refusal. Inconclusive: check the gateway rate-limit "
                                             f"configuration and key policy — completions may have crossed a "
                                             f"minute boundary, splitting the tokens across two clock-minute "
                                             f"buckets.")


def cooldown_remaining(snaps, now=None) -> float:
    """Seconds until the shared one-minute window has cooled down, or 0.

    Pure function of the newest last_request_at among the snapshots (dicts or
    None values), so it is unit-testable without a live run.
    """
    if now is None:
        now = time.time()
    newest = None
    for snap in snaps:
        if not snap:
            continue
        stamp = snap.get("last_request_at")
        if stamp is not None and (newest is None or stamp > newest):
            newest = stamp
    if newest is None:
        return 0.0
    return max(COOLDOWN_SECONDS - (now - newest), 0.0)


def _settings_from_state() -> dict:
    return {
        "endpoint": st.session_state.saved_endpoint,
        "model": st.session_state.saved_model,
        "api_key": st.session_state.saved_rate_limit_api_key,
        "key_mask": mask_key(st.session_state.saved_rate_limit_api_key),
        "timeout": st.session_state.saved_timeout,
    }


def _render_settings(settings: dict):
    with st.container(border=True):
        st.subheader("Test settings")
        st.caption("CONNECTION · READ-ONLY FROM CONFIGURATION")
        col_a, col_b = st.columns(2)
        col_a.text_input("Endpoint", value=settings["endpoint"], disabled=True)
        col_b.text_input("Rate-limit key (masked)", value=settings["key_mask"], disabled=True)
        st.caption("LIMITS · CONFIGURED OR EXTRACTED BY FORTIAIGATE")
        col_m, col_rpm, col_tpm, col_win = st.columns(4)
        col_m.text_input("Model", value=settings["model"], disabled=True)
        col_rpm.text_input("Requests / min", value=f"{RPM_LIMIT} / minute", disabled=True)
        col_tpm.text_input("Tokens / min", value=f"{TPM_LIMIT:,} / minute", disabled=True)
        col_win.text_input("Window", value="clock-minute bucket", disabled=True)
        st.caption("Settings cannot be edited here. Limits are configured or extracted by FortiAIGate; the "
                   "gateway's own accounting is authoritative. The rate-limit key is managed on the Configuration "
                   "page and never shown in full. The security suites never use this key.")


_LOG_STYLE = """
<style>
table.rl-log { width:100%; border-collapse:collapse; font-size:12.5px; }
table.rl-log th { text-align:left; color:#8b98a9; font-weight:500; border-bottom:1px solid #30363d; padding:7px 8px; }
table.rl-log td { border-bottom:1px solid #30363d; padding:7px 8px; color:#a8b3c2; }
table.rl-log td.num, table.rl-log th.num { text-align:right; }
.rl-pill { border-radius:10px; padding:2px 9px; font-size:11px; font-weight:600; white-space:nowrap; }
.rl-pill.ok { background:#12261a; color:#7ee2a0; border:1px solid #274b31; }
.rl-pill.stop { background:#2c1c20; color:#f0a9a2; border:1px solid #67302b; }
.rl-pill.warn { background:#2b2317; color:#e3c56d; border:1px solid #5c4a1e; }
</style>
"""


def _log_html(records: list) -> str:
    """Request log as a mockup-styled table: result pills, right-aligned numbers.

    Rows are in completion order, which for one-at-a-time dispatch equals
    send order, so the running token count increases monotonically down the
    table. "#" is the send-time request number.
    """
    rows = []
    for rec in records:
        if rec["status_code"] == 200:
            pill = "ok"
        elif rec["status_code"] == 429:
            pill = "stop"
        else:
            pill = "warn"
        cells = [
            str(rec["index"]),
            f'<span class="rl-pill {pill}">{html.escape(rec["result"])}</span>',
            f"{rec['latency_ms'] / 1000:.1f} s",
            "—" if rec["tokens_in"] is None else f"{rec['tokens_in']:,}",
            "—" if rec["tokens_out"] is None else f"{rec['tokens_out']:,}",
            "—" if rec["running_tokens"] is None else f"{rec['running_tokens']:,}",
            html.escape(rec["note"]),
        ]
        rows.append("<tr><td>{}</td><td>{}</td><td class='num'>{}</td><td class='num'>{}</td>"
                    "<td class='num'>{}</td><td class='num'>{}</td><td>{}</td></tr>"
                    .format(*cells))
    return ("<table class='rl-log'><thead><tr><th>#</th><th>Result</th><th class='num'>Latency</th>"
            "<th class='num'>In</th><th class='num'>Out</th><th class='num'>Running tokens</th>"
            "<th>Note</th></tr></thead><tbody>"
            + "".join(rows) + "</tbody></table>")


def _render_results(snap: dict):
    col_r, col_t, col_s, col_l = st.columns(4)
    col_r.metric("Requests completed", snap["completed"])
    col_t.metric("Tokens counted (in / out)", f"{snap['tokens_in']:,} / {snap['tokens_out']:,}")
    col_s.metric("429 refusals", snap["refusals"])
    col_l.metric("Limit tested", f"{RPM_LIMIT} RPM" if snap["kind"] == "rpm" else f"{TPM_LIMIT:,} TPM")
    vkind, text = snap["verdict"]
    ({"ok": st.success, "err": st.error}.get(vkind, st.warning))(_md(text))

    with st.container(border=True):
        st.subheader("Request log")
        if snap["records"]:
            st.markdown(_LOG_STYLE + _log_html(snap["records"]), unsafe_allow_html=True)
        else:
            st.caption("No requests yet.")

    hit = next((r for r in snap["records"] if r["status_code"] == 429), None)
    if hit:
        with st.container(border=True):
            st.subheader(f"Rate-limit refusal (request #{hit['index']})")
            st.code(f"HTTP/1.1 429 Too Many Requests\nContent-Type: application/json\n\n{hit['evidence']}")
            st.markdown(_md(
                "**429 — Too Many Requests.** FortiAIGate tracks per-key request count (5/min) and token usage "
                "(100,000/min) in fixed clock-minute buckets shared by both limits. When either limit is spent, "
                "the gateway refuses further requests **at admission** — ~0.2-1 s latency, zero tokens — with "
                '`error.code = "rate_limit_exceeded"`. Token usage is counted when a request completes, so '
                "enforcement lags one request boundary: the request that crosses the limit still succeeds; the "
                "next one is refused. The body does not name the limit that was hit — each test sends only "
                "a few requests, so attribution is by design, and a run that crosses a minute boundary is "
                "reported as such."))


def _render_test_card(kind: str, snap, active_any: bool, cooling: float, live_timeout: int):
    # the gate must read the LIVE configuration timeout, not the frozen
    # settings of a previous run, or a stale low timeout blocks the button
    timeout_ok = kind == "rpm" or live_timeout >= 90
    with st.container(border=True):
        if kind == "rpm":
            st.subheader("Test 1 · Requests per minute (5 RPM)")
            st.caption("Eight small chat requests (~100 tokens each) sent one at a time, 3 s apart, starting "
                       "the moment you press Run; the gateway admits the first 5 of each clock minute and "
                       "refuses the rest at admission with 429. About 40 s total.")
        else:
            st.subheader("Test 2 · Tokens per minute (100,000 TPM)")
            st.caption("Three large requests (~39,000 input tokens each, ~118,000 total) sent one at a time, "
                       "3 s apart, then one small confirm request; only 4 requests — below the 5 RPM cap — so "
                       "any refusal is attributable to the token budget. The run starts immediately and takes "
                       "~50 s; large requests ~10-15 s each.")
            if not timeout_ok:
                st.warning(f"Request timeout is {live_timeout}s — the large requests need at "
                           "least 90 s. Raise it on the Configuration page.")
        active = bool(snap) and snap["status"] == "running"
        col_run, col_stop, _ = st.columns([1, 1, 4])
        started = col_run.button("Run RPM test" if kind == "rpm" else "Run TPM test", type="primary",
                                 key="rate_limit_" + kind + "_start",
                                 disabled=active_any or cooling > 0 or not timeout_ok)
        if col_stop.button("Stop", key="rate_limit_" + kind + "_stop", disabled=not active):
            st.session_state["_rate_limit_run_" + kind].stop()
        st.caption("Navigating away does not cancel an active run; it ends after its last request, or at Stop. "
                   f"The shared clock-minute bucket then cools down for up to {COOLDOWN_SECONDS} s before "
                   "either test can run again.")
        if cooling > 0 and not active:
            st.caption(f"Shared clock-minute bucket cooling down — ready in {math.ceil(cooling)} s.")
        if snap:
            if snap["status"] == "running":
                # the bar moves when requests go out, like the Budget Control page
                head = (f"Sending {snap['sent']} of {snap['planned']} requests · one at a time, "
                        "3 s apart...")
            else:
                head = f"Finished · {snap['completed']} of {snap['planned']} requests"
            st.progress(min(snap["sent"] / snap["planned"], 1.0), text=_md(head))
            admitted = sum(1 for r in snap["records"] if r["status_code"] == 200)
            tokens = 0
            for rec in snap["records"]:
                if rec["running_tokens"] is not None:
                    tokens = rec["running_tokens"]
            st.progress(min(admitted / RPM_LIMIT, 1.0),
                        text=f"requests admitted this run: {admitted} of {RPM_LIMIT} / min")
            st.progress(min(tokens / TPM_LIMIT, 1.0),
                        text=f"tokens counted this run: {tokens:,} of {TPM_LIMIT:,} / min")
            _render_results(snap)
    if started:
        run = RateLimitRun(_settings_from_state(), kind)
        st.session_state["_rate_limit_run_" + kind] = run
        run.start()
        st.rerun()


def _render_contract():
    with st.container(border=True):
        st.subheader("Verified enforcement contract")
        st.caption(CONTRACT_NOTE)


def _runs_and_state():
    snaps = {}
    for kind in ("rpm", "tpm"):
        run = st.session_state.get("_rate_limit_run_" + kind)
        snaps[kind] = run.snapshot() if run else None
    active_any = any(s and s["status"] == "running" for s in snaps.values())
    cooling = cooldown_remaining(list(snaps.values()))
    return snaps, active_any, cooling


def _display_settings(snaps, live):
    # An active run keeps rendering from its frozen settings, even if the live
    # configuration changes underneath it; a terminal run keeps its last view.
    for kind in ("rpm", "tpm"):
        snap = snaps[kind]
        if snap and snap["status"] == "running":
            return snap["settings"]
    for kind in ("rpm", "tpm"):
        if snaps[kind]:
            return snaps[kind]["settings"]
    return live


@st.fragment(run_every=1.0)
def _live_fragment():
    snaps, active_any, cooling = _runs_and_state()
    if not active_any and cooling <= 0:
        st.rerun()
        return
    live = _settings_from_state()
    display = _display_settings(snaps, live)
    _render_settings(display)
    for kind in ("rpm", "tpm"):
        _render_test_card(kind, snaps[kind], active_any, cooling, live["timeout"])
    _render_contract()


def render_rate_limit():
    st.header(":material/speed: Rate Limit")
    st.caption("Verify that FortiAIGate enforces the request-rate and token-rate limits on the rate-limit key: "
               "small requests one at a time for the 5 RPM limit, token-heavy requests one at a time for the "
               "100,000 TPM limit, refusals kept as evidence. Both limits count per clock minute, so a run "
               "that crosses a minute boundary is reported as such.")

    snaps, active_any, cooling = _runs_and_state()
    if active_any or cooling > 0:
        _live_fragment()
        return

    live = _settings_from_state()
    if not live["endpoint"] or not live["model"] or not live["api_key"]:
        st.warning("Configure the Endpoint URL, Model and the **API key (Rate Limit)** on the "
                   "**Configuration** page first.", icon=":material/warning:")
        return

    display = _display_settings(snaps, live)
    _render_settings(display)
    for kind in ("rpm", "tpm"):
        _render_test_card(kind, snaps[kind], False, 0.0, live["timeout"])
    _render_contract()
