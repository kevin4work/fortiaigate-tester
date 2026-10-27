"""Paced outbound HTTP calls; retries consume the dispatch budget.

Dispatch pacing and budget counters are lock-protected so several worker
threads may keep requests in flight concurrently.
"""
import json
import threading
import time
import uuid

import httpx

from common.gateway_response import response_details
from runner.reports import redact
from runner.settings import validate_endpoint


RESPONSE_BODY_LIMIT = 1_048_576
RESPONSE_TRUNCATION_MARKER = "\n[response truncated]"


class StopRun(Exception):
    def __init__(self, reason):
        self.reason = reason


class Transport:
    def __init__(self, configuration, limits, allowlist, test_loopback, store, run_id, *, clock=time.monotonic, sleep=time.sleep, client=None):
        self.configuration, self.limits = configuration, limits
        validate_endpoint(configuration["endpoint"], allowlist, test_loopback)
        self.store, self.run_id = store, run_id
        self.clock, self.sleep = clock, sleep
        self.started = clock()
        self.next_dispatch = self.started
        self.dispatched = 0
        self._lock = threading.Lock()
        if client is not None:
            self.client = client
        else:
            pool = max(4, int(limits.get("concurrency", 1)) + 4)
            self.client = httpx.Client(follow_redirects=False, trust_env=False,
                                       limits=httpx.Limits(max_connections=pool))

    def check(self):
        run = self.store.get(self.run_id)
        if not run or run["cancel_requested"] or run["status"] == "interrupted":
            raise StopRun("cancelled")
        if self.clock() - self.started >= self.limits["minutes"] * 60:
            raise StopRun("walltime")
        if self.dispatched >= self.limits["request_cap"]:
            raise StopRun("requests")

    def wait(self, seconds):
        until = self.clock() + seconds
        while self.clock() < until:
            self.check()
            self.sleep(max(0, min(0.1, until - self.clock())))

    def request(self, messages, *, attempt_id=None, probe=None, case_id=None):
        logical_id = attempt_id or str(uuid.uuid4())
        last = None
        for retry in range(3):  # Two retries, only transient transport/429/5xx.
            self.check()
            # Reserve the rpm pacing slot atomically; the cap is checked and
            # counted atomically at dispatch so concurrent callers cannot
            # overshoot either limit.
            with self._lock:
                slot = max(self.next_dispatch, self.clock())
                slot_wait = slot - self.clock()
                self.next_dispatch = slot + 60 / self.limits["rpm"]
            self.wait(slot_wait)
            with self._lock:
                if self.dispatched >= self.limits["request_cap"]:
                    raise StopRun("requests")
                self.dispatched += 1
            record = {"id": str(uuid.uuid4()), "logical_id": logical_id, "attempt_id": attempt_id,
                      "probe": probe, "case_id": case_id, "retry": retry,
                      "prompt": "\n".join(m["role"] + ": " + m["content"] for m in messages),
                      "response": None, "raw_response": None, "content_type": None,
                      "status_code": None, "response_truncated": False, "response_format": None,
                      "finish_reason": None, "block_source": None, "gateway_outcome": "unknown",
                      "latency_ms": None, "error": "in_flight", "request_id": None}
            self.store.put("requests", self.run_id, redact(record, self.configuration["api_key"]))
            started = self.clock()
            transient = False
            fatal = False
            raw = bytearray()
            encoding = "utf-8"
            try:
                remaining = self.limits["minutes"] * 60 - (self.clock() - self.started)
                timeout = min(self.configuration["timeout"], max(0.01, remaining))
                deadline = started + timeout
                # httpx timeout covers stalled I/O; the chunk loop below cuts
                # slow-drip reads at the same deadline, from any thread.
                with self.client.stream("POST", self.configuration["endpoint"],
                        headers={"Authorization": "Bearer " + self.configuration["api_key"]},
                        json={"model": self.configuration["model"], "messages": messages, "stream": False},
                        timeout=timeout) as response:
                    record["status_code"] = response.status_code
                    record["content_type"] = response.headers.get("content-type", "")[:200] or None
                    record["request_id"] = response.headers.get("x-request-id", "")[:200] or None
                    encoding = response.encoding or "utf-8"
                    record["response_truncated"] = True
                    try:
                        for chunk in response.iter_bytes():
                            available = RESPONSE_BODY_LIMIT - len(raw)
                            raw.extend(chunk[:available])
                            if len(chunk) > available:
                                raise ValueError("response_too_large")
                            if self.clock() >= deadline:
                                raise httpx.TimeoutException("request deadline")
                        record["response_truncated"] = False
                    finally:
                        try:
                            record["raw_response"] = raw.decode(encoding, errors="replace")
                        except LookupError:
                            record["raw_response"] = raw.decode("utf-8", errors="replace")
                        if record["response_truncated"]:
                            record["raw_response"] += RESPONSE_TRUNCATION_MARKER
                    code = response.status_code
                    details = response_details(record["raw_response"]) if code in (200, 403) else None
                    blocked = details is not None and details["blocked"]
                    if code != 200 and not blocked:
                        record["error"] = ("auth_error" if code == 401 else "forbidden_unknown" if code == 403 else
                                           "rate_limited" if code == 429 else "redirect_rejected" if 300 <= code < 400 else "http_error")
                        transient = code == 429 or 500 <= code < 600
                        fatal = code in (401, 403) or 300 <= code < 400
                    else:
                        record["error"] = None
                        record["response"] = details["text"]
                        record["response_format"] = details["source"]
                        record["finish_reason"] = details["finish_reason"]
                        if blocked:
                            record["gateway_outcome"] = "confirmed_block"
                            record["block_source"] = "response_phrase"
                        if details["source"] == "openai_chat":
                            data = json.loads(record["raw_response"])
                            usage = data.get("usage")
                            if isinstance(usage, dict):
                                record["usage"] = {k: v for k, v in usage.items() if k in ("prompt_tokens", "completion_tokens", "total_tokens") and isinstance(v, int) and v >= 0}
            except httpx.TimeoutException:
                record["error"] = "timeout"
                transient = True
            except httpx.HTTPError:
                record["error"] = "transport_error"
                transient = True
            except ValueError as exc:
                record["error"] = "response_too_large" if str(exc) == "response_too_large" else "invalid_or_empty_response"
                fatal = True
            except (TypeError, AttributeError, KeyError):
                record["error"] = "invalid_or_empty_response"
                fatal = True
            except StopRun:
                self.store.put("requests", self.run_id, redact(record, self.configuration["api_key"]))
                raise
            record["latency_ms"] = round((self.clock() - started) * 1000, 2)
            record["fatal"] = fatal
            self.store.put("requests", self.run_id, redact(record, self.configuration["api_key"]))
            last = record
            if not record["error"]:
                return record
            if not transient or retry == 2:
                return record
            self.wait(0.5 * (retry + 1))
        return last

    def close(self):
        self.client.close()


class StructuredPolicyMapping:
    """Testable seam only; production has no verified mapping and never constructs it."""
    def __init__(self, field, allow_value, block_value, contract_reference):
        if not contract_reference:
            raise ValueError("A verified policy contract reference is required")
        self.field, self.allow_value, self.block_value = field, allow_value, block_value

    def classify(self, payload):
        if payload.get(self.field) == self.block_value:
            return "confirmed_block"
        if payload.get(self.field) == self.allow_value:
            return "allowed"
        return "unknown"
