"""User-facing gateway reply extraction, separate from raw technical evidence."""

import json


BLOCK_PHRASE = "blocked by fortiaigate"


def _text(value):
    if isinstance(value, str):
        return value if value.strip() else None
    if isinstance(value, list):
        # OpenAI text-content blocks only; never reasoning/tool/metadata fields.
        parts = [part["text"] for part in value if isinstance(part, dict)
                 and part.get("type") in ("text", "output_text")
                 and isinstance(part.get("text"), str)]
        return "\n".join(parts) if any(part.strip() for part in parts) else None
    return None


def response_details(raw_response, parsed_response=None):
    """Extract only reply fields; the exact configured phrase identifies a block."""
    text, source, finish_reason = None, "unrecognized", None
    if raw_response is not None:
        try:
            data = json.loads(raw_response)
        except (ValueError, TypeError, RecursionError):
            # HTML and malformed JSON are technical evidence, not chatbot content.
            stripped = raw_response.lstrip() if isinstance(raw_response, str) else ""
            data = raw_response if stripped and not stripped.startswith(("{", "[", "<")) else None
            source = "plain_text"
        if isinstance(data, str):
            text = _text(data)
            source = "plain_text" if source == "plain_text" else "json_string"
        elif isinstance(data, dict):
            choices = data.get("choices")
            first = choices[0] if isinstance(choices, list) and choices and isinstance(choices[0], dict) else {}
            finish_reason = first.get("finish_reason") if isinstance(first.get("finish_reason"), str) else None
            message = first.get("message")
            if isinstance(message, dict):
                text = _text(message.get("content"))
                source = "openai_chat"
                if text is None:
                    text = _text(message.get("refusal"))
                    source = "refusal"
                if text is None and any(message.get(key) for key in ("reasoning", "reasoning_content", "reasoning_details")):
                    source = "reasoning_only"
            if text is None:
                for key in ("response", "output", "message"):
                    candidate = _text(data.get(key))
                    if candidate is not None:
                        text, source = candidate, key
                        break
            if text is None and isinstance(data.get("error"), dict):
                text = _text(data["error"].get("message"))
                if text is not None:
                    source = "error_message"
        if text is None and not str(raw_response).strip():
            source = "empty"
    else:
        text = _text(parsed_response)
        source = "stored_text" if text is not None else "empty"
    if text is None and source not in ("reasoning_only", "empty"):
        source = "unrecognized"
    return {
        "text": text,
        "source": source,
        "finish_reason": finish_reason,
        "blocked": text is not None and BLOCK_PHRASE in text.casefold(),
    }
