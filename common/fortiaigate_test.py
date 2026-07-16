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


def send_prompt(
    endpoint: str,
    api_key: str,
    prompt: str,
    model: str = "qwen/3_6_flash",
    timeout: int = 30,
) -> dict:
    """Send a single prompt to the FortiAIGate endpoint.

    Returns a dict with keys: status, response_text, latency_ms, error
    """
    # Derive model from endpoint path if possible
    # e.g. /qwen/3_6_flash/chat/completions -> qwen/3_6_flash
    parts = endpoint.rstrip("/").split("/")
    if len(parts) >= 3 and parts[-1] == "completions" and parts[-2] == "chat":
        inferred_model = "/".join(parts[-3:-1])
    else:
        inferred_model = model

    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {api_key}",
    }

    payload = {
        "model": inferred_model,
        "messages": [{"role": "user", "content": prompt}],
    }

    start = time.time()
    try:
        resp = requests.post(endpoint, headers=headers, json=payload, timeout=timeout)
        latency_ms = int((time.time() - start) * 1000)

        if resp.status_code == 401:
            return {
                "status": "Error",
                "response_text": "",
                "latency_ms": latency_ms,
                "error": "Unauthorized — check API key",
            }
        if resp.status_code == 429:
            return {
                "status": "Error",
                "response_text": "",
                "latency_ms": latency_ms,
                "error": "Rate limited",
            }
        if resp.status_code >= 400:
            return {
                "status": "Error",
                "response_text": resp.text[:500],
                "latency_ms": latency_ms,
                "error": f"HTTP {resp.status_code}",
            }

        data = resp.json()
        # OpenAI-compatible response format
        content = data.get("choices", [{}])[0].get("message", {}).get("content", "")
        if not content:
            # Some gateways return the response in a different field
            content = data.get("response", data.get("output", ""))
        if not content and isinstance(data, str):
            content = data

        return {
            "status": "OK",
            "response_text": content,
            "latency_ms": latency_ms,
            "error": "",
        }
    except requests.Timeout:
        latency_ms = int((time.time() - start) * 1000)
        return {
            "status": "Error",
            "response_text": "",
            "latency_ms": latency_ms,
            "error": "Timeout",
        }
    except requests.ConnectionError as e:
        latency_ms = int((time.time() - start) * 1000)
        return {
            "status": "Error",
            "response_text": "",
            "latency_ms": latency_ms,
            "error": f"Connection error: {e}",
        }
    except Exception as e:
        latency_ms = int((time.time() - start) * 1000)
        return {
            "status": "Error",
            "response_text": "",
            "latency_ms": latency_ms,
            "error": str(e),
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
