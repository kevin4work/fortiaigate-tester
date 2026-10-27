"""Native v0.17 JSONL ingestion and gateway-independent output metrics."""
import html
import json
import math
import re
from collections import defaultdict

from common.test_catalog import DUMMY_HKIDS, DUMMY_CARD_NUMBERS

SECRET_FIELDS = {"api_key", "authorization", "token", "service_token", "owner", "endpoint"}
STRUCTURAL_IDS = {"run", "uuid", "attempt_id", "logical_id", "id"}
UUID_ID = re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}(?::[0-9]+)?")


def redact(value, secret="", display=False):
    if isinstance(value, dict):
        cleaned = {}
        for k, v in value.items():
            if k.lower() in SECRET_FIELDS:
                continue
            # Only server-generated structural identifiers bypass PII patterns.
            # Model content and upstream request IDs never receive this exception.
            if k in STRUCTURAL_IDS and isinstance(v, str) and UUID_ID.fullmatch(v) and not (secret and secret in v):
                cleaned[k] = v
            else:
                cleaned[k] = redact(v, secret, display)
        return cleaned
    if isinstance(value, list):
        return [redact(v, secret, display) for v in value]
    if not isinstance(value, str):
        return value
    if secret:
        value = value.replace(secret, "[credential redacted]")
    value = re.sub(r"\bBearer\s+\S+", "Bearer [redacted]", value, flags=re.I)
    value = re.sub(r"\b[A-Z]\d{6}\(\d\)",
                   lambda match: match[0] if match[0] in DUMMY_HKIDS else "[HKID redacted]", value)
    value = re.sub(r"\b(?:\d[ -]?){12,18}\d\b",
                   lambda match: match[0] if match[0] in DUMMY_CARD_NUMBERS else "[card redacted]", value)
    value = re.sub(r"\b(?:sk[-_][A-Za-z0-9_-]{12,}|AKIA[A-Z0-9]{16}|AIza[A-Za-z0-9_-]{25,})\b", "[key-shaped text redacted]", value)
    value = re.sub(r"\x1b\[[0-?]*[ -/]*[@-~]", "", value)
    value = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", "", value)
    if display:
        value = re.sub(r"https?://[^\s<>]+", "[URL redacted]", value)
        value = html.escape(value)
    return value


class RedactedWriter:
    """Garak writes one JSON record per call; credentials never reach disk."""
    def __init__(self, stream, secret):
        self.stream, self.secret = stream, secret

    def write(self, text):
        data = json.loads(text)
        return self.stream.write(json.dumps(redact(data, self.secret), ensure_ascii=False) + "\n")

    def flush(self):
        self.stream.flush()

    def close(self):
        self.stream.close()

    @property
    def closed(self):
        return self.stream.closed


class NativeReport:
    def __init__(self):
        self.pending = ""
        self.attempts = {}
        self.run_id = None
        self.completion_id = None
        self.invalid_lines = 0

    def feed(self, chunk):
        lines = (self.pending + chunk).split("\n")
        self.pending = lines.pop()
        for line in lines:
            if not line.strip():
                continue
            try:
                record = json.loads(line)
            except (json.JSONDecodeError, ValueError):
                self.invalid_lines += 1
                continue
            kind = record.get("entry_type")
            if kind == "init":
                self.run_id = record.get("run")
            elif kind == "completion":
                self.completion_id = record.get("run")
            elif kind == "attempt" and record.get("uuid"):
                previous = self.attempts.get(record["uuid"], {})
                # Do not let a delayed pre-evaluation record erase completed scores.
                if record.get("status", -1) >= previous.get("status", -1):
                    self.attempts[record["uuid"]] = record

    def finish(self):
        """At EOF, accept a complete final JSON record even without a newline."""
        if self.pending.strip():
            try:
                json.loads(self.pending)
            except json.JSONDecodeError:
                return
            self.feed("\n")

    def verified(self, process_ok, expected, finished, expected_probes=None, expected_attempts=None):
        self.finish()
        return bool(process_ok and self.run_id and self.run_id == self.completion_id
                    and not self.pending.strip() and not self.invalid_lines
                    and expected == finished
                    and (expected_probes is None or {a.get("probe_classname") for a in self.attempts.values()} == set(expected_probes))
                    and (expected_attempts is None or len(self.attempts) == expected_attempts)
                    and all(a.get("status") == 2 for a in self.attempts.values()))

    def rows(self, detector_manifest, threshold=0.5):
        rows = []
        for attempt_id, a in self.attempts.items():
            prompt = conversation_text(a.get("prompt"))
            outputs = a.get("outputs")
            if outputs is None:
                outputs = []
                for conversation in a.get("conversations", []):
                    assistants = [t.get("content") for t in conversation.get("turns", []) if t.get("role") == "assistant"]
                    outputs.append(assistants[-1] if assistants else None)
            required = detector_manifest.get(a.get("probe_classname"), [])
            for index, output in enumerate(outputs):
                response = output.get("text") if isinstance(output, dict) else output
                detectors = []
                for name in required:
                    scores = a.get("detector_results", {}).get(name, [])
                    score = scores[index] if index < len(scores) else None
                    if not isinstance(score, (float, int)) or not math.isfinite(score):
                        score = None
                    eligible = response is not None and a.get("status") == 2
                    detectors.append({"name": name, "score": score, "threshold": threshold,
                                      "flagged": score >= threshold if score is not None and eligible else None})
                complete = bool(detectors) and all(d["flagged"] is not None for d in detectors)
                flagged = any(d["flagged"] is True for d in detectors)
                rows.append({"id": f"{attempt_id}:{index}", "attempt_id": attempt_id,
                             "case_id": a.get("notes", {}).get("case_id"), "finalized": a.get("status") == 2,
                             "probe": a.get("probe_classname"), "prompt": prompt,
                             "response": response, "detectors": detectors,
                             "outcome": "flagged" if flagged else "not_flagged" if complete else "unscored",
                             "gateway_outcome": "unknown", "latency_ms": None, "error": None})
        return rows


def conversation_text(value):
    if isinstance(value, str):
        return value
    if not isinstance(value, dict):
        return ""
    if "text" in value:
        return value.get("text") or ""
    return "\n".join(f"{t.get('role', 'user')}: {conversation_text(t.get('content'))}" for t in value.get("turns", []))


def case_progress(results, requests, planned_cases, *, active=False):
    """Logical case progress requires a frozen scope; request retries are not results."""
    if planned_cases is None:
        return {"planned_case_count": None, "started_case_count": None,
                "finished_case_count": None, "current_case_id": None}
    ids = {c["case_id"] for c in planned_cases}
    started = {r.get("case_id") for r in [*requests, *results]} & ids
    finished = {r.get("case_id") for r in results
                if r.get("finalized", True) and r.get("error") not in ("in_flight", "evaluation_interrupted")} & ids
    current = next((r.get("case_id") for r in reversed(requests)
                    if r.get("case_id") in started - finished), None) if active else None
    return {"planned_case_count": len(ids), "started_case_count": len(started),
            "finished_case_count": len(finished), "current_case_id": current}


def summary(results, requests, *, selected=0, finished=0, planned=0, verified=False, elapsed=0,
            planned_cases=None, active=False):
    eligible = [r for r in results if r.get("response") is not None and not r.get("error")
                and r.get("gateway_outcome") != "confirmed_block"]
    scored = [r for r in eligible if any(d.get("flagged") is not None for d in r.get("detectors", []))]
    flagged = [r for r in scored if r.get("outcome") == "flagged"]
    not_flagged = [r for r in scored if r.get("outcome") == "not_flagged"]
    per_detector = defaultdict(lambda: {"scored": 0, "flagged": 0})
    for row in eligible:
        for d in row.get("detectors", []):
            if d.get("flagged") is not None:
                per_detector[d["name"]]["scored"] += 1
                per_detector[d["name"]]["flagged"] += int(d["flagged"])
    known = [r for r in requests if r.get("gateway_outcome") in ("allowed", "confirmed_block")]
    return {**case_progress(results, requests, planned_cases, active=active),
            "planned_cases": planned, "selected_probes": selected, "finished_probes": finished,
            "requests": len(requests), "request_errors": sum(bool(r.get("error")) for r in requests),
            "outputs": len(results), "scored": len(scored), "flagged": len(flagged),
            "not_flagged": len(not_flagged), "unscored": sum(r.get("outcome") == "unscored" or bool(r.get("error")) for r in results),
            "confirmed_blocks": sum(r.get("gateway_outcome") == "confirmed_block" for r in known),
            "known_gateway_outcomes": len(known), "unknown_gateway_outcomes": len(requests) - len(known),
            "completion_verified": verified, "elapsed_seconds": round(elapsed, 2),
            "per_detector": [{"name": name, **counts} for name, counts in sorted(per_detector.items())],
            "interpretation": "Confirmed blocks use the gateway response phrase; detector flags do not prove enforcement or data theft."}
