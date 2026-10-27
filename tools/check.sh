#!/bin/sh
# Fast verification gate. Usage: tools/check.sh [full]
# default: app suite + fast backend files (no loopback native runs)
# full:    adds the real-Garak native integration suite (~5 min)
set -e
cd "$(dirname "$0")/.."
APP=.venv-app/bin/python
RUN=.venv-runner/bin/python
"$APP" -m pytest tests/test_app_contracts.py tests/test_budget_control.py tests/test_configuration.py \
    tests/test_gateway_response.py tests/test_inline_results.py tests/test_rate_limit.py tests/test_selection.py -q
if [ "$1" = "full" ]; then
    "$RUN" -m pytest tests/test_runner_api.py tests/test_runner_transport.py \
        tests/test_garak_reports.py tests/test_apikey_filter.py tests/test_attack_curation.py tests/test_garak_expansion.py \
        tests/test_garak_native.py -q
    echo "check.sh: OK (full)"
else
    "$RUN" -m pytest tests/test_runner_api.py tests/test_runner_transport.py \
        tests/test_garak_reports.py tests/test_apikey_filter.py tests/test_attack_curation.py tests/test_garak_expansion.py -q
    echo "check.sh: OK (fast)"
fi
