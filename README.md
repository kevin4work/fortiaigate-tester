# FortiAIGate Tester

Security testing toolkit for **FortiAIGate** — Fortinet's AI gateway that protects LLM, Agentic AI, and MCP workloads from malicious prompts.

This project provides two Streamlit web apps that send adversarial prompts through the gateway and classify each response as **Blocked** (gate intervened), **Through** (gate missed it), or **Error** (network/auth failure).

## Apps

| App | Path | Description |
|---|---|---|
| **Attack Tester** | `attack_tester/app.py` | Card-based UI — send prompts one-by-one or batch-run, grouped by attack type. Includes a summary dashboard with block-rate charts. |
| **Bulk Tester** | `bulk_tester/app.py` | Table-based UI — run all prompts from a comprehensive CSV, view results by category and risk ID, filter and export. |

Both apps share the same core logic in `common/fortiaigate_test.py`.

## How It Works

1. **Load prompts** from a CSV file (attack types, risk IDs, prompt text).
2. **Send each prompt** to the FortiAIGate endpoint via an OpenAI-compatible HTTP request.
3. **Classify the response**: if the response contains the FortiAIGate signature → **Blocked**; otherwise → **Through**.
4. **Display results** with metrics, charts, and CSV export.

## Setup

```bash
python3 -m venv .venv
source .venv/bin/activate

# Install dependencies
python3 -m pip install streamlit pandas requests
```

## Running

Set the gateway endpoint and API key via environment variables, or enter them in the sidebar at runtime.

```bash
export FORTIAIGATE_ENDPOINT="http://your-gateway-endpoint/chat/completions"
export FORTIAIGATE_API_KEY="your-api-key"

# Attack Tester
streamlit run attack_tester/app.py

# Bulk Tester
streamlit run bulk_tester/app.py
```

## Project Structure

```
fortiaigate-tester/
├── attack_tester/
│   ├── app.py                       # Streamlit attack tester UI
│   ├── fortiaigate_prompt_test_01.csv  # Attack prompt data
│   └── .streamlit/config.toml       # Dark theme config
├── bulk_tester/
│   ├── app.py                       # Streamlit bulk tester UI
│   ├── AI_Security_Testing_Guide.csv   # Full risk-category prompt data
│   └── .streamlit/config.toml       # Light theme config
├── common/
│   └── fortiaigate_test.py          # Shared logic: load, send, classify
├── .gitignore
└── README.md
```

## Test Prompt CSVs

- `attack_tester/fortiaigate_prompt_test_01.csv` — columns: `attack_type`, `description`, `prompt_text`
- `bulk_tester/AI_Security_Testing_Guide.csv` — columns: `Category`, `Risk ID`, `Title`, `Description`, `Test Prompt 1`, `Test Prompt 2`, `Test Prompt 3`

Categories cover LLM Applications (Prompt Injection, Sensitive Information Disclosure, Supply Chain Vulnerabilities, Data and Model Poisoning, etc.), Agentic AI, and MCP risk domains.

## Environment Variables

| Variable | Default | Description |
|---|---|---|
| `FORTIAIGATE_ENDPOINT` | AWS ELB endpoint | Gateway chat/completions URL |
| `FORTIAIGATE_API_KEY` | *(empty)* | Bearer token for the gateway |
| `FORTIAIGATE_CSV` | Per-app default CSV | Override the prompt CSV path |
