import os
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

DEFAULT_ENDPOINT = "https://aigate.fortilaboratory.com/ai/openai/v1/chat/completions"
GARAK_VERSION = "0.17.0"
PROFILE_LIMITS = {
    "quick": (60, 10), "custom": (600, 45),
    "smoke": (60, 3), "core": (600, 5), "extended": (1800, 30),
}


def validate_endpoint(endpoint, allowlist, test_loopback=False):
    parsed = urlsplit(endpoint)
    if parsed.username or parsed.password or parsed.fragment or parsed.query:
        raise ValueError("Endpoint must not contain credentials, query, or fragment")
    if endpoint not in allowlist:
        raise ValueError("Endpoint is not in the server allowlist")
    if parsed.scheme == "https" and parsed.hostname and parsed.path.endswith("/chat/completions"):
        return endpoint
    if test_loopback and parsed.scheme == "http" and parsed.hostname == "127.0.0.1" and parsed.port:
        return endpoint
    raise ValueError("Production endpoints require an exact approved HTTPS chat-completions URL")


@dataclass(frozen=True)
class Settings:
    token: str
    data_dir: Path
    execution_enabled: bool = False
    allowlist: tuple = (DEFAULT_ENDPOINT,)
    test_loopback: bool = False  # Constructor-only; never enabled by an environment variable.
    cancel_grace: float = 3.0

    @classmethod
    def from_env(cls):
        token = os.environ.get("FORTIAIGATE_RUNNER_TOKEN", "")
        if not token:
            raise RuntimeError("FORTIAIGATE_RUNNER_TOKEN is required")
        allowlist = tuple(x.strip() for x in os.environ.get(
            "FORTIAIGATE_RUNNER_ENDPOINT_ALLOWLIST", DEFAULT_ENDPOINT
        ).split(",") if x.strip())
        for endpoint in allowlist:
            validate_endpoint(endpoint, allowlist)
        return cls(token=token,
                   data_dir=Path(os.environ.get("FORTIAIGATE_RUNNER_DATA", ".runner-data")).resolve(),
                   execution_enabled=os.environ.get("FORTIAIGATE_SCANS_ENABLED", "false").lower() == "true",
                   allowlist=allowlist)
