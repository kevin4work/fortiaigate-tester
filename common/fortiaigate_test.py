"""Core logic for FortiAIGate security testing.

Reads prompts from CSV, sends them to the gateway endpoint,
and classifies responses as Blocked, Through, or Error.

Classification rule:
  - Blocked: response contains "FortiAIGate" (the gate intervened)
  - Through: response is a normal response (gate did not intervene)
  - Error: network/auth/timeout failure
"""

import csv
import time
from typing import Optional
from urllib.parse import urlsplit

import requests

GATE_SIGNATURE = "fortiaigate"


def load_prompts(csv_path: str) -> list[dict]:
    """Load test prompts from the CSV file.

    Returns a list of dicts with keys:
      category, risk_id, title, description,
      prompt_column, prompt_text
    """
    prompts = []
    with open(csv_path, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            for col in ["Test Prompt 1", "Test Prompt 2", "Test Prompt 3"]:
                text = row.get(col, "").strip()
                if text:
                    prompts.append({
                        "category": row["Category"],
                        "risk_id": row["Risk ID"],
                        "title": row["Title"],
                        "description": row["Description"],
                        "prompt_column": col,
                        "prompt_text": text,
                    })
    return prompts


def classify_response(response_text: str) -> str:
    """Classify a response as Blocked, Through, or Error.

    Simple rule: if "FortiAIGate" appears in the response, the gate
    intervened → Blocked. Otherwise it's a normal response → Through.
    """
    if GATE_SIGNATURE in response_text.lower():
        return "Blocked"
    return "Through"


USAGE_TOKEN_KEYS = ("prompt_tokens", "completion_tokens", "total_tokens")


def _extract_usage(data) -> Optional[dict]:
    """Return validated OpenAI-style usage tokens from a parsed body, or None."""
    if not isinstance(data, dict):
        return None
    usage = data.get("usage")
    if not isinstance(usage, dict):
        return None
    tokens = {k: v for k, v in usage.items()
              if k in USAGE_TOKEN_KEYS and isinstance(v, int) and v >= 0}
    return tokens or None


def send_prompt(
    endpoint: str,
    api_key: str,
    prompt: str,
    model: Optional[str] = None,
    timeout: int = 30,
) -> dict:
    """Send a single prompt to the FortiAIGate endpoint.

    Returns a dict with keys: status, response_text, latency_ms, error,
    status_code, raw_body, usage. The last three are None when no HTTP
    response or usage was available; raw_body never echoes the api_key.
    """
    # Explicit Configuration settings always take precedence. Retain the old
    # /provider/model/chat/completions format only for callers without a model.
    parts = urlsplit(endpoint).path.strip("/").split("/")
    if model is not None:
        inferred_model = model
    elif len(parts) == 4 and parts[-2:] == ["chat", "completions"]:
        inferred_model = "/".join(parts[:2])
    else:
        inferred_model = "qwen/3_6_flash"

    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {api_key}",
    }

    payload = {
        "model": inferred_model,
        "messages": [{"role": "user", "content": prompt}],
    }

    start = time.time()
    status_code = None
    raw_body = None
    usage = None
    try:
        resp = requests.post(endpoint, headers=headers, json=payload, timeout=timeout, allow_redirects=False)
        latency_ms = int((time.time() - start) * 1000)
        status_code = resp.status_code
        try:
            body = resp.text
        except Exception:
            body = ""
        raw_body = body.replace(api_key, "[REDACTED]") if api_key else body

        if resp.status_code == 401:
            return {
                "status": "Error",
                "response_text": "",
                "latency_ms": latency_ms,
                "error": "Unauthorized — check API key",
                "status_code": status_code,
                "raw_body": raw_body,
                "usage": usage,
            }
        if resp.status_code == 429:
            return {
                "status": "Error",
                "response_text": "",
                "latency_ms": latency_ms,
                "error": "Rate limited",
                "status_code": status_code,
                "raw_body": raw_body,
                "usage": usage,
            }
        if resp.status_code >= 300:
            return {
                "status": "Error",
                "response_text": "",
                "latency_ms": latency_ms,
                "error": f"HTTP {resp.status_code}",
                "status_code": status_code,
                "raw_body": raw_body,
                "usage": usage,
            }

        data = resp.json()
        usage = _extract_usage(data)
        content = data if isinstance(data, str) else ""
        if isinstance(data, dict):
            choices = data.get("choices")
            if isinstance(choices, list) and choices and isinstance(choices[0], dict):
                message = choices[0].get("message")
                if isinstance(message, dict):
                    content = message.get("content", "")
            if not content:
                content = data.get("response", data.get("output", ""))
        if not isinstance(content, str) or not content.strip():
            return {
                "status": "Error",
                "response_text": "",
                "latency_ms": latency_ms,
                "error": "Missing or invalid text response",
                "status_code": status_code,
                "raw_body": raw_body,
                "usage": usage,
            }
        if api_key:
            content = content.replace(api_key, "[REDACTED]")

        return {
            "status": "OK",
            "response_text": content,
            "latency_ms": latency_ms,
            "error": "",
            "status_code": status_code,
            "raw_body": raw_body,
            "usage": usage,
        }
    except requests.Timeout:
        latency_ms = int((time.time() - start) * 1000)
        return {
            "status": "Error",
            "response_text": "",
            "latency_ms": latency_ms,
            "error": "Timeout",
            "status_code": status_code,
            "raw_body": raw_body,
            "usage": usage,
        }
    except requests.ConnectionError:
        latency_ms = int((time.time() - start) * 1000)
        return {
            "status": "Error",
            "response_text": "",
            "latency_ms": latency_ms,
            "error": "Connection error",
            "status_code": status_code,
            "raw_body": raw_body,
            "usage": usage,
        }
    except Exception:
        latency_ms = int((time.time() - start) * 1000)
        return {
            "status": "Error",
            "response_text": "",
            "latency_ms": latency_ms,
            "error": "Invalid response or request failure",
            "status_code": status_code,
            "raw_body": raw_body,
            "usage": usage,
        }


def run_all_tests(
    endpoint: str,
    api_key: str,
    prompts: list[dict],
    delay: float = 1.0,
    timeout: int = 30,
) -> list[dict]:
    """Run all prompts against the endpoint, returning full results.

    Each result dict has the original prompt fields plus:
      response_text, outcome, latency_ms, error
    """
    results = []
    total = len(prompts)
    for i, p in enumerate(prompts):
        # Expose progress info for the UI via a callback-like mechanism
        # The Streamlit app reads this list as it grows
        sent = send_prompt(endpoint, api_key, p["prompt_text"], timeout=timeout)

        outcome = classify_response(sent["response_text"]) if sent["status"] == "OK" else "Error"

        result = {
            **p,
            "response_text": sent["response_text"],
            "outcome": outcome,
            "latency_ms": sent["latency_ms"],
            "error": sent["error"],
        }
        results.append(result)

        if delay > 0 and i < total - 1:
            time.sleep(delay)

    return results
