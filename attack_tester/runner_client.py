"""Server-side client for the private, session-authorized scan runner."""

import os
import uuid
from urllib.parse import quote, urlsplit

import requests


class RunnerUnavailable(Exception):
    """A safe operator-facing failure, never a raw transport exception."""


class RunnerClient:
    def __init__(self, session_id=None, url=None, token=None):
        if session_id is None:
            import streamlit as st

            if "_runner_session_id" not in st.session_state:
                st.session_state["_runner_session_id"] = str(uuid.uuid4())
            session_id = st.session_state["_runner_session_id"]
        self.url = (url or os.environ.get("FORTIAIGATE_RUNNER_URL", "http://127.0.0.1:8765")).rstrip("/")
        self.token = token if token is not None else os.environ.get("FORTIAIGATE_RUNNER_TOKEN", "")
        self.session_id = session_id
        parsed = urlsplit(self.url)
        local = parsed.hostname in ("127.0.0.1", "localhost", "::1")
        if parsed.username or parsed.password or parsed.query or parsed.fragment:
            raise RunnerUnavailable("The private runner URL is invalid. Ask the operator to configure it.")
        if not parsed.hostname or not (parsed.scheme == "https" or (parsed.scheme == "http" and local)):
            raise RunnerUnavailable("The private runner requires HTTPS or a loopback HTTP address.")
        if not self.token:
            raise RunnerUnavailable("Runner unavailable: the server-side service token is not configured.")

    def _request(self, method, path, payload=None):
        # Never surface requests exceptions or response bodies: either may contain secrets.
        try:
            with requests.Session() as session:
                # Private service auth and target credentials must never use environment proxies/netrc.
                session.trust_env = False
                response = session.request(
                    method,
                    self.url + path,
                    headers={"Authorization": "Bearer " + self.token, "X-Session-ID": self.session_id},
                    json=payload,
                    timeout=(3, 15),
                    allow_redirects=False,
                )
        except requests.RequestException:
            raise RunnerUnavailable("Runner unavailable: the private service could not be reached. No success is assumed.") from None
        if not 200 <= response.status_code < 300:
            if response.status_code in (401, 403):
                message = "Runner access denied. Ask the operator to check service authentication and execution policy."
            elif response.status_code == 404:
                message = "The requested run or runner resource is unavailable for this session."
            elif response.status_code == 409:
                message = "The runner did not accept this action. Refresh status; a run may already be active."
            elif response.status_code in (400, 422):
                message = ("The runner rejected the saved configuration or selected scope. Review Configuration "
                           "and the catalog. After an app update this usually means the scanner service is still "
                           "running older code — restart the scanner service.")
            else:
                message = "The private runner returned an unsuccessful response (HTTP {}).".format(response.status_code)
            raise RunnerUnavailable(message)
        try:
            data = response.json()
        except (ValueError, requests.RequestException):
            raise RunnerUnavailable("The runner returned an unreadable response. No success is assumed.") from None
        if not isinstance(data, dict):
            raise RunnerUnavailable("The runner returned an invalid response. No success is assumed.")
        return data

    def health(self):
        return self._request("GET", "/health")

    def catalog(self):
        return self._request("GET", "/catalog")

    def start(self, payload):
        return self._request("POST", "/runs", payload)

    def history(self):
        return self._request("GET", "/runs")

    def status(self, run_id):
        return self._request("GET", "/runs/" + quote(str(run_id), safe=""))

    def results(self, run_id):
        return self._request("GET", "/runs/" + quote(str(run_id), safe="") + "/results")

    def cancel(self, run_id):
        return self._request("POST", "/runs/" + quote(str(run_id), safe="") + "/cancel")

    def export(self, run_id):
        return self._request("GET", "/runs/" + quote(str(run_id), safe="") + "/export")


def get_runner_client():
    import streamlit as st

    # This identifier is server-created, not editable operator/browser configuration.
    if "_runner_session_id" not in st.session_state:
        st.session_state["_runner_session_id"] = str(uuid.uuid4())
    return RunnerClient(st.session_state["_runner_session_id"])


def saved_configuration(state):
    """Read widget-independent connection values without mutating or displaying them."""
    return {
        "endpoint": state.get("saved_endpoint", ""),
        "model": state.get("saved_model", ""),
        "api_key": state.get("saved_api_key", ""),
        "timeout": state.get("saved_timeout", 120),
    }


def missing_configuration(configuration):
    return [name for name in ("endpoint", "model", "api_key") if not str(configuration.get(name) or "").strip()]
