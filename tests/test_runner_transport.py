import json

import httpx
import pytest

from runner.settings import DEFAULT_ENDPOINT, validate_endpoint
from runner.store import Store
from runner.transport import RESPONSE_BODY_LIMIT, RESPONSE_TRUNCATION_MARKER, StopRun, StructuredPolicyMapping, Transport


class Clock:
    def __init__(self):
        self.now = 0
    def __call__(self):
        return self.now
    def sleep(self, seconds):
        self.now += seconds


def make_transport(tmp_path, handler, *, request_cap=6, rpm=30, minutes=1):
    store = Store(tmp_path)
    run, _ = store.create("owner", "idem", "fp", {})
    clock = Clock()
    transport = Transport({"endpoint": DEFAULT_ENDPOINT, "model": "explicit-model", "api_key": "fake-test-credential", "timeout": 1},
        {"request_cap": request_cap, "rpm": rpm, "minutes": minutes}, (DEFAULT_ENDPOINT,), False, store, run["id"],
        clock=clock, sleep=clock.sleep, client=httpx.Client(transport=httpx.MockTransport(handler), follow_redirects=False))
    return transport, store, run["id"], clock


@pytest.mark.parametrize("endpoint", [
    "http://aigate.fortilaboratory.com/ai/openai/v1/chat/completions", DEFAULT_ENDPOINT + "/", DEFAULT_ENDPOINT + "?a=1",
    DEFAULT_ENDPOINT + "#fragment", "https://user:pass@aigate.fortilaboratory.com/ai/openai/v1/chat/completions",
    "https://evil.example/chat/completions", "http://127.0.0.1:1234/chat/completions", "file:///tmp/model",
])
def test_endpoint_restrictions(endpoint):
    with pytest.raises(ValueError):
        validate_endpoint(endpoint, (DEFAULT_ENDPOINT,))


def test_rate_wait_never_sleeps_negative_on_clock_boundary(tmp_path):
    transport, _, _, _ = make_transport(tmp_path, lambda _: httpx.Response(200))
    class MovingClock:
        def __init__(self):
            self.value = 0
        def __call__(self):
            self.value += 0.04
            return self.value
    transport.clock = MovingClock()
    sleeps = []
    transport.sleep = sleeps.append
    transport.check = lambda: None
    transport.wait(0.1)
    assert sleeps and all(s >= 0 for s in sleeps)


def test_exact_endpoint_and_test_only_loopback():
    assert validate_endpoint(DEFAULT_ENDPOINT, (DEFAULT_ENDPOINT,)) == DEFAULT_ENDPOINT
    local = "http://127.0.0.1:1234/chat/completions"
    assert validate_endpoint(local, (local,), test_loopback=True) == local
    with pytest.raises(ValueError):
        validate_endpoint(local, (local,))


def test_retries_rate_caps_and_explicit_model(tmp_path):
    sent = []
    def handler(request):
        sent.append(json.loads(request.content))
        return httpx.Response(429) if len(sent) < 3 else httpx.Response(200, json={"choices": [{"message": {"content": "safe reply"}}]})
    transport, store, run_id, clock = make_transport(tmp_path, handler)
    record = transport.request([{"role": "user", "content": "prompt"}])
    assert record["response"] == "safe reply"
    assert transport.dispatched == 3
    assert clock.now >= 4
    assert all(s["model"] == "explicit-model" and "stop" not in s and not s["stream"] for s in sent)
    assert all("max_tokens" not in s and "max_completion_tokens" not in s for s in sent)
    assert len(store.records("requests", run_id)) == 3
    assert record["gateway_outcome"] == "unknown"


def test_legacy_stored_output_budget_is_not_sent(tmp_path):
    sent = []
    def handler(request):
        sent.append(json.loads(request.content))
        return httpx.Response(200, json={"choices": [{"message": {"content": "reply"}}]})
    transport, _, _, _ = make_transport(tmp_path, handler)
    transport.configuration["max_tokens"] = 512
    transport.request([{"role": "user", "content": "prompt"}])
    assert "max_tokens" not in sent[0]
    assert "max_completion_tokens" not in sent[0]


def test_retry_cap_counts_dispatch(tmp_path):
    transport, store, run_id, _ = make_transport(tmp_path, lambda _: httpx.Response(500), request_cap=2)
    with pytest.raises(StopRun) as exc:
        transport.request([{"role": "user", "content": "prompt"}])
    assert exc.value.reason == "requests"
    assert len(store.records("requests", run_id)) == 2


@pytest.mark.parametrize("code,body,error", [
    (200, {"choices": [{"message": {"content": "FortiAIGate refusal"}}]}, None),
    (401, {}, "auth_error"), (403, {}, "forbidden_unknown"), (302, {}, "redirect_rejected"),
    (200, {"choices": []}, None),
    (200, {"choices": [{"message": {"content": None}}]}, None),
    (200, {"choices": [{"message": {"content": ""}}]}, None),
])
def test_gateway_provenance_and_no_false_pass(tmp_path, code, body, error):
    transport, _, _, _ = make_transport(tmp_path, lambda _: httpx.Response(code, json=body, headers={"location": "https://evil.example"}))
    record = transport.request([{"role": "user", "content": "prompt"}])
    assert record["error"] == error
    assert record["gateway_outcome"] == "unknown"
    assert transport.dispatched == 1


def test_timeout_retries_do_not_stop_the_scan(tmp_path):
    def handler(_):
        raise httpx.ReadTimeout("secret exception not persisted")
    transport, store, run_id, clock = make_transport(tmp_path, handler, request_cap=12)
    result = transport.request([{"role": "user", "content": "prompt"}])
    assert result["error"] == "timeout" and transport.dispatched == 3
    second = transport.request([{"role": "user", "content": "another"}])
    assert second["error"] == "timeout" and transport.dispatched == 6
    assert "secret exception" not in json.dumps(store.records("requests", run_id))
    store.update(run_id, cancel=1)
    with pytest.raises(StopRun) as exc:
        transport.check()
    assert exc.value.reason == "cancelled"
    store.update(run_id, cancel=0)
    clock.now = 61
    with pytest.raises(StopRun) as exc:
        transport.check()
    assert exc.value.reason == "walltime"


def test_persistent_gateway_errors_do_not_stop_the_scan(tmp_path):
    # Even repeated 504s remain per-case errors; safety ceilings still apply.
    transport, store, run_id, _ = make_transport(tmp_path, lambda _: httpx.Response(504), request_cap=12)
    records = [transport.request([{"role": "user", "content": str(index)}],
                                 case_id="malwaregen.Evasion:{}".format(index))
               for index in range(3)]
    assert all(row["error"] == "http_error" and row["status_code"] == 504 for row in records)
    transport.check()
    assert len(store.records("requests", run_id)) == 9
    assert transport.dispatched == 9
    with pytest.raises(StopRun) as exc:
        for index in range(3, 5):
            transport.request([{"role": "user", "content": str(index)}], case_id="case:{}".format(index))
    assert exc.value.reason == "requests"  # only the configured budget stops dispatch
    assert transport.dispatched == 12
    assert len(store.records("requests", run_id)) == 12
    assert all(row["error"] == "http_error" for row in store.records("requests", run_id))


@pytest.mark.parametrize("body,content_type,expected_format", [
    (b'["JSON array reply"]', "application/json", "unrecognized"),
    pytest.param(b'[' * 2000 + b'0' + b']' * 2000, "application/json", "unrecognized", id="deep-json"),
    (b'{"choices":[null]}', "application/json", "unrecognized"),
    (b'{"choices":[{"message":"unexpected"}]}', "application/json", "unrecognized"),
    (b'{"choices":[{"message":{"content":["not text"]}}]}', "application/json", "unrecognized"),
    (b'{"choices":[{"message":{"content":"  "}}]}', "application/json", "unrecognized"),
    (b'<html>Blocked by gateway</html>', "text/html", "unrecognized"),
    (b'', "text/plain", "empty"),
])
def test_http200_unrecognized_is_success_not_model_output(tmp_path, body, content_type, expected_format):
    transport, store, run_id, _ = make_transport(tmp_path, lambda _: httpx.Response(200, content=body, headers={"content-type": content_type}))
    for _ in range(6):
        record = transport.request([{"role": "user", "content": "fixture"}])
        assert record["response"] is None and record["error"] is None and not record["fatal"]
        assert record["raw_response"] == body.decode()
        assert record["response_format"] == expected_format
        assert record["content_type"] == content_type and record["status_code"] == 200
        assert not record["response_truncated"] and record["gateway_outcome"] == "unknown"
    assert transport.dispatched == len(store.records("requests", run_id)) == 6


@pytest.mark.parametrize("body,source,text", [
    ({"choices": [{"message": {"content": "safe reply"}}]}, "openai_chat", "safe reply"),
    ({"choices": [{"message": {"content": "FortiAIGate"}}]}, "openai_chat", "FortiAIGate"),
    ({"choices": [{"message": {"content": None, "refusal": "I cannot comply"}}]}, "refusal", "I cannot comply"),
    ({"response": "alternate reply"}, "response", "alternate reply"),
    ({"output": "alternate reply"}, "output", "alternate reply"),
    ({"message": "FortiAIGate blocked"}, "message", "FortiAIGate blocked"),
    ({"error": {"message": "safe reply"}}, "error_message", "safe reply"),
    ("JSON string reply", "json_string", "JSON string reply"),
])
def test_readable_http200_reply_is_separate_from_raw_evidence(tmp_path, body, source, text):
    raw = json.dumps(body)
    transport, store, run_id, _ = make_transport(tmp_path, lambda _: httpx.Response(200, content=raw))
    record = transport.request([{"role": "user", "content": "blocked by FortiAIGate"}])
    assert record["response"] == text and record["response_format"] == source
    assert record["gateway_outcome"] == "unknown" and record["block_source"] is None
    assert record["error"] is None and not record["fatal"]
    assert record["raw_response"] == store.records("requests", run_id)[0]["raw_response"] == raw


def test_plaintext_http200_reply_is_readable_not_json(tmp_path):
    transport, _, _, _ = make_transport(tmp_path, lambda _: httpx.Response(200, content="not JSON"))
    record = transport.request([{"role": "user", "content": "fixture"}])
    assert record["response"] == "not JSON" and record["response_format"] == "plain_text"
    assert record["gateway_outcome"] == "unknown" and record["error"] is None


@pytest.mark.parametrize("code", [200, 403])
@pytest.mark.parametrize("body,source", [
    ({"choices": [{"message": {"content": "Request BLOCKED BY FoRtIaIGaTe.", "reasoning_content": "ignored"}, "finish_reason": "stop"}]}, "openai_chat"),
    ({"choices": [{"message": {"content": None, "refusal": "Request BLOCKED BY FoRtIaIGaTe."}}]}, "refusal"),
    ({"response": "Request BLOCKED BY FoRtIaIGaTe."}, "response"),
    ({"message": "Request BLOCKED BY FoRtIaIGaTe."}, "message"),
    ({"error": {"message": "Request BLOCKED BY FoRtIaIGaTe."}}, "error_message"),
    ("Request BLOCKED BY FoRtIaIGaTe.", "json_string"),
])
def test_exact_response_phrase_confirms_completed_gateway_block(tmp_path, code, body, source):
    raw = json.dumps(body)
    transport, store, run_id, _ = make_transport(tmp_path, lambda _: httpx.Response(code, content=raw))
    for _ in range(4):
        record = transport.request([{"role": "user", "content": "fixture"}])
        assert record["response"] == "Request BLOCKED BY FoRtIaIGaTe."
        assert record["gateway_outcome"] == "confirmed_block" and record["block_source"] == "response_phrase"
        assert record["response_format"] == source and record["raw_response"] == raw
        assert record["error"] is None and not record["fatal"] and not record["response_truncated"]
        assert record["finish_reason"] == ("stop" if source == "openai_chat" else None)
    assert transport.dispatched == len(store.records("requests", run_id)) == 4


@pytest.mark.parametrize("code", [200, 403])
def test_plaintext_response_phrase_confirms_gateway_block(tmp_path, code):
    raw = "Request blocked by FortiAIGate."
    transport, _, _, _ = make_transport(tmp_path, lambda _: httpx.Response(code, content=raw))
    record = transport.request([{"role": "user", "content": "fixture"}])
    assert record["response"] == record["raw_response"] == raw
    assert record["gateway_outcome"] == "confirmed_block" and record["block_source"] == "response_phrase"
    assert record["response_format"] == "plain_text" and record["error"] is None and not record["fatal"]


@pytest.mark.parametrize("body,expected_response,source", [
    ({"choices": [{"message": {"content": "FortiAIGate refused", "reasoning_content": "blocked by FortiAIGate"}, "finish_reason": "stop"}],
      "metadata": {"message": "blocked by FortiAIGate"}, "prompt": "blocked by FortiAIGate"}, "FortiAIGate refused", "openai_chat"),
    ({"choices": [{"message": {"content": None, "reasoning_content": "blocked by FortiAIGate"}, "finish_reason": "length"}]}, None, "reasoning_only"),
    ({"metadata": {"message": "blocked by FortiAIGate"}, "prompt": "blocked by FortiAIGate"}, None, "unrecognized"),
])
def test_prompt_reasoning_and_metadata_do_not_confirm_blocks(tmp_path, body, expected_response, source):
    raw = json.dumps(body)
    transport, _, _, _ = make_transport(tmp_path, lambda _: httpx.Response(200, content=raw))
    record = transport.request([{"role": "user", "content": "blocked by FortiAIGate"}])
    assert record["gateway_outcome"] == "unknown" and record["block_source"] is None
    assert record["response"] == expected_response and record["response_format"] == source
    assert record["raw_response"] == raw and record["error"] is None
    assert record["finish_reason"] == ("length" if source == "reasoning_only" else "stop" if source == "openai_chat" else None)


@pytest.mark.parametrize("code,error,dispatches", [(401, "auth_error", 1), (429, "rate_limited", 3), (503, "http_error", 3)])
def test_response_phrase_does_not_override_auth_or_http_errors(tmp_path, code, error, dispatches):
    transport, _, _, _ = make_transport(tmp_path, lambda _: httpx.Response(code, content="blocked by FortiAIGate"))
    record = transport.request([{"role": "user", "content": "fixture"}])
    assert record["gateway_outcome"] == "unknown" and record["block_source"] is None
    assert record["error"] == error and record["response"] is None
    assert transport.dispatched == dispatches


def test_model_response_is_separate_from_decoded_raw_evidence(tmp_path):
    body = '{"choices":[{"message":{"content":"model reply"}}],"extra":"café"}'.encode("latin-1")
    transport, store, run_id, _ = make_transport(tmp_path, lambda _: httpx.Response(200, content=body, headers={"content-type": "application/json; charset=iso-8859-1"}))
    record = transport.request([{"role": "user", "content": "fixture"}])
    assert record["raw_response"] == body.decode("latin-1")
    assert record["response"] == "model reply" and record["error"] is None
    assert store.records("requests", run_id)[0]["raw_response"] == record["raw_response"]
    transport.close()
    body = b'{"choices":[{"message":{"content":"model reply"}}],"usage":{"total_tokens":2}}'
    transport, _, _, _ = make_transport(tmp_path / "utf8", lambda _: httpx.Response(200, content=body))
    record = transport.request([{"role": "user", "content": "fixture"}])
    assert record["response"] == "model reply" and record["raw_response"] == body.decode()
    assert record["response_format"] == "openai_chat" and record["usage"] == {"total_tokens": 2}


@pytest.mark.parametrize("code,error,dispatches", [(401, "auth_error", 1), (403, "forbidden_unknown", 1),
    (302, "redirect_rejected", 1), (400, "http_error", 1), (429, "rate_limited", 3), (503, "http_error", 3)])
def test_error_bodies_preserved_redacted_and_policy_unchanged(tmp_path, code, error, dispatches):
    body = b'<html>fake-test-credential A123456(7) 4539 1488 0343 6467</html>'
    transport, store, run_id, _ = make_transport(tmp_path, lambda _: httpx.Response(code, content=body, headers={"content-type": "text/html"}))
    record = transport.request([{"role": "user", "content": "fixture"}])
    assert record["raw_response"] == body.decode() and record["response"] is None
    assert record["content_type"] == "text/html" and record["status_code"] == code
    assert record["error"] == error and record["fatal"] == (code in (401, 403, 302))
    assert not record["response_truncated"] and transport.dispatched == dispatches
    persisted = json.dumps(store.records("requests", run_id))
    assert "fake-test-credential" not in persisted
    assert "A123456(7)" in persisted and "4539 1488 0343 6467" in persisted
    assert "[credential redacted]" in persisted


@pytest.mark.parametrize("code", [200, 401, 403, 503])
def test_response_cap_preserves_bounded_partial_redacted_body(tmp_path, code):
    prefix = b'blocked by FortiAIGate fake-test-credential A123456(7) 4539 1488 0343 6467 '
    class LargeBody(httpx.SyncByteStream):
        def __iter__(self):
            yield prefix
            yield b'x' * RESPONSE_BODY_LIMIT
            pytest.fail("Oversize response must not be read beyond the cap")
    transport, store, run_id, _ = make_transport(tmp_path, lambda _: httpx.Response(code, stream=LargeBody(), headers={"content-type": "text/plain"}))
    record = transport.request([{"role": "user", "content": "fixture"}])
    assert record["error"] == "response_too_large" and record["fatal"]
    assert record["status_code"] == code and record["content_type"] == "text/plain"
    assert record["response"] is None and record["response_truncated"]
    assert record["gateway_outcome"] == "unknown" and record["block_source"] is None
    assert record["raw_response"] == (prefix + b'x' * (RESPONSE_BODY_LIMIT - len(prefix))).decode() + RESPONSE_TRUNCATION_MARKER
    assert transport.dispatched == 1
    persisted = json.dumps(store.records("requests", run_id))
    assert "fake-test-credential" not in persisted
    assert "A123456(7)" in persisted and "4539 1488 0343 6467" in persisted


def test_response_exact_cap_and_partial_timeout_and_interruption(tmp_path):
    transport, _, _, _ = make_transport(tmp_path / "exact", lambda _: httpx.Response(200, content=b'x' * RESPONSE_BODY_LIMIT))
    record = transport.request([{"role": "user", "content": "fixture"}])
    assert record["error"] is None and not record["response_truncated"]
    assert len(record["raw_response"]) == RESPONSE_BODY_LIMIT
    for reason in ("timeout", "cancelled"):
        class PartialBody(httpx.SyncByteStream):
            def __iter__(self):
                yield b'blocked by FortiAIGate partial fake-test-credential'
                if reason == "timeout":
                    raise httpx.ReadTimeout("fixture")
                raise StopRun("cancelled")
        transport, store, run_id, _ = make_transport(tmp_path / reason, lambda _: httpx.Response(200, stream=PartialBody()))
        if reason == "cancelled":
            with pytest.raises(StopRun):
                transport.request([{"role": "user", "content": "fixture"}])
        else:
            assert transport.request([{"role": "user", "content": "fixture"}])["error"] == "timeout"
        rows = store.records("requests", run_id)
        assert all(row["raw_response"] == "blocked by FortiAIGate partial [credential redacted]" + RESPONSE_TRUNCATION_MARKER for row in rows)
        assert all(row["response_truncated"] and row["status_code"] == 200 for row in rows)
        assert all(row["gateway_outcome"] == "unknown" and row["response"] is None for row in rows)


def test_verified_structured_mapping_test_fixture_only():
    mapping = StructuredPolicyMapping("fixture_decision", "allow", "deny", "test-only-contract-v1")
    assert mapping.classify({"fixture_decision": "deny"}) == "confirmed_block"
    assert mapping.classify({"fixture_decision": "allow"}) == "allowed"
    assert mapping.classify({"text": "blocked by FortiAIGate"}) == "unknown"
    with pytest.raises(ValueError):
        StructuredPolicyMapping("field", "allow", "deny", "")
