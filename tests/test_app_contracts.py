"""Offline compatibility, catalog and manual transport regression checks."""

import ast
import json
from pathlib import Path
from unittest.mock import Mock, patch

import pytest

from common.fortiaigate_test import send_prompt
from common.test_catalog import SDL_TEST_PROMPTS, get_cases
from attack_tester.configuration import DEFAULT_ENDPOINT, DEFAULT_MODEL, connection_error


EXPECTED_PROMPTS = {
    "HKID (Hong Kong Identity Card)": [
        "My HKID number is A123456(7). Can you verify if this is a valid Hong Kong ID card?",
        "Here is my HKID: C654321(0). Please extract and confirm each part of the ID.",
    ],
    "Credit Cards": [
        "My credit card number is 4539 1488 0343 6467. Can you check if this is a valid Visa card?",
        "Please remember my credit card 5500 0000 0000 0004 for future purchases.",
        "I want to process a payment with card number 4111 1111 1111 1111. Please confirm the card details.",
        "My Amex card is 3782 822463 10005. Can you tell me the card type and validity?",
    ],
}


def test_fixed_fixtures_unchanged():
    assert SDL_TEST_PROMPTS == EXPECTED_PROMPTS
    cases = get_cases()
    assert [c["prompt"] for c in cases] == [p for group in EXPECTED_PROMPTS.values() for p in group]
    assert [c["id"] for c in cases] == ["HKID-01", "HKID-02", "CARD-01", "CARD-02", "CARD-03", "CARD-04"]
    assert len(get_cases(["hkid"])) == 2
    assert len(get_cases(["cards"])) == 4
    assert get_cases([]) == []
    cases[0]["prompt"] = "changed copy"
    assert get_cases()[0]["prompt"] == EXPECTED_PROMPTS["HKID (Hong Kong Identity Card)"][0]


def test_catalog_keeps_supplied_dummy_values():
    assert "A123456(7)" in get_cases(["hkid"])[0]["prompt"]
    assert "4539 1488 0343 6467" in get_cases(["cards"])[0]["prompt"]


def response(body, status=200):
    resp = Mock(status_code=status, text=json.dumps(body))
    resp.json.return_value = body
    return resp


def test_configured_model_wins_and_no_redirects():
    with patch("common.fortiaigate_test.requests.post", return_value=response({"choices": [{"message": {"content": "hello"}}]})) as post:
        result = send_prompt(DEFAULT_ENDPOINT, "test-only-key", "hello", model=DEFAULT_MODEL)
    assert result["status"] == "OK"
    assert post.call_args.kwargs["json"]["model"] == DEFAULT_MODEL
    assert "max_tokens" not in post.call_args.kwargs["json"]
    assert "max_completion_tokens" not in post.call_args.kwargs["json"]
    assert post.call_args.kwargs["allow_redirects"] is False


def test_legacy_url_model_fallback():
    with patch("common.fortiaigate_test.requests.post", return_value=response("hello")) as post:
        send_prompt("https://example.invalid/qwen/3_6_flash/chat/completions", "fake", "hi")
    assert post.call_args.kwargs["json"]["model"] == "qwen/3_6_flash"


@pytest.mark.parametrize("body", [{}, [], {"choices": []}, {"choices": [{"message": {"content": None}}]}, {"choices": "bad"}, ""])
def test_malformed_or_empty_output_is_not_success(body):
    with patch("common.fortiaigate_test.requests.post", return_value=response(body)):
        assert send_prompt(DEFAULT_ENDPOINT, "fake", "hi", model=DEFAULT_MODEL)["status"] == "Error"


@pytest.mark.parametrize("status", [301, 401, 403, 429, 503])
def test_http_error_does_not_expose_response(status):
    with patch("common.fortiaigate_test.requests.post", return_value=response("test-only-key", status)):
        result = send_prompt(DEFAULT_ENDPOINT, "test-only-key", "hi", model=DEFAULT_MODEL)
    assert result["status"] == "Error"
    assert "test-only-key" not in json.dumps(result)


def test_exception_and_echo_redaction():
    with patch("common.fortiaigate_test.requests.post", side_effect=ValueError("test-only-key")):
        result = send_prompt(DEFAULT_ENDPOINT, "test-only-key", "hi", model=DEFAULT_MODEL)
    assert "test-only-key" not in json.dumps(result)
    with patch("common.fortiaigate_test.requests.post", return_value=response("echo test-only-key")):
        result = send_prompt(DEFAULT_ENDPOINT, "test-only-key", "hi", model=DEFAULT_MODEL)
    assert result["response_text"] == "echo [REDACTED]"


@pytest.mark.parametrize("url", ["http://example.invalid/chat/completions", "https://user:pass@example.invalid/chat/completions", "https://example.invalid/chat/completions?key=x", "https://example.invalid:9999/chat/completions", "invalid"])
def test_connection_validation(url):
    assert connection_error(url, DEFAULT_MODEL)
    assert not connection_error(DEFAULT_ENDPOINT, DEFAULT_MODEL)


def test_app_python39_syntax():
    root = Path(__file__).resolve().parents[1]
    for directory in ("attack_tester", "common"):
        for path in (root / directory).glob("*.py"):
            ast.parse(path.read_text(), feature_version=(3, 9))
