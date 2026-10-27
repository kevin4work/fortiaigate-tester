"""Chatbot reply extraction and the operator-specified FortiAIGate signature."""
import json

import pytest

from common.gateway_response import response_details


def test_chat_reply_not_json_or_internal_reasoning():
    raw = json.dumps({"choices": [{"finish_reason": "stop", "message": {
        "content": "The visible reply", "reasoning_content": "Internal text"}}], "id": "metadata"})
    assert response_details(raw) == {"text": "The visible reply", "source": "openai_chat", "finish_reason": "stop", "blocked": False}


@pytest.mark.parametrize("reply", ["Request blocked by FortiAIGate.", "BLOCKED BY FORTIAIGATE", "Your prompt was Blocked By FortiAIGate."])
def test_exact_phrase_case_insensitive(reply):
    details = response_details(json.dumps({"choices": [{"message": {"content": reply}}]}))
    assert details["blocked"] is True
    assert details["text"] == reply


@pytest.mark.parametrize("field", ["reasoning", "reasoning_content", "reasoning_details", "metadata"])
def test_phrase_in_non_reply_fields_does_not_block(field):
    data = {"choices": [{"message": {"content": "Normal answer", field: "blocked by FortiAIGate"}}]}
    assert not response_details(json.dumps(data))["blocked"]


def test_reasoning_only_does_not_become_reply():
    raw = json.dumps({"choices": [{"finish_reason": "length", "message": {"content": None, "reasoning_content": "Private model reasoning"}}]})
    assert response_details(raw) == {"text": None, "source": "reasoning_only", "finish_reason": "length", "blocked": False}


@pytest.mark.parametrize("body,expected", [
    ({"response": "Visible reply"}, "Visible reply"),
    ({"output": "Visible reply"}, "Visible reply"),
    ({"message": "blocked by FortiAIGate"}, "blocked by FortiAIGate"),
    ({"error": {"message": "blocked by FortiAIGate"}}, "blocked by FortiAIGate"),
    ("Visible reply", "Visible reply"),
    ({"choices": [{"message": {"content": None, "refusal": "I cannot help"}}]}, "I cannot help"),
    ({"choices": [{"message": {"content": [{"type": "text", "text": "One"}, {"type": "reasoning", "text": "Hidden"}, {"type": "output_text", "text": "Two"}]}}]}, "One\nTwo"),
])
def test_supported_visible_reply_fields(body, expected):
    assert response_details(json.dumps(body))["text"] == expected


@pytest.mark.parametrize("raw", ['{"bad json"', '<html>error</html>', '{"decision":"block","reason":"policy"}', 'null', '[]'])
def test_no_json_envelope_or_html_fallback(raw):
    assert response_details(raw)["text"] is None
    assert response_details(raw)["source"] == "unrecognized"


def test_legacy_text_and_plain_text():
    assert response_details(None, "Previously stored reply")["text"] == "Previously stored reply"
    assert response_details("Plain chatbot reply")["text"] == "Plain chatbot reply"
    assert response_details("")["text"] is None
    assert response_details("")["source"] == "empty"
    assert not response_details("FortiAIGate is an AI gateway")["blocked"]
