"""Authenticated loopback-only launcher. Run with one Uvicorn worker."""
import hashlib
import hmac
import json
import os
import uuid
from contextlib import asynccontextmanager
from typing import Literal

from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field, SecretStr, ValidationError

from runner.catalog import FAMILIES, MANIFEST, PROFILE_PROBES, catalog, installed_version, planned_cases
from runner.reports import case_progress, redact
from runner.native import PROMPT_CAPS
from runner.settings import GARAK_VERSION, PROFILE_LIMITS, Settings, validate_endpoint
from runner.store import AdmissionError, Store
from runner.supervisor import Supervisor


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Configuration(StrictModel):
    endpoint: str = Field(min_length=1, max_length=2048)
    model: str = Field(min_length=1, max_length=200)
    api_key: SecretStr
    timeout: float = Field(default=60, gt=0, le=300)


class Limits(StrictModel):
    request_cap: int = Field(ge=1, le=1800)
    rpm: int = Field(default=30, ge=1, le=100)
    minutes: float = Field(gt=0, le=120)
    concurrency: int = Field(default=1, ge=1, le=20)


class Case(StrictModel):
    id: str
    group: Literal["hkid", "cards"]
    title: str
    prompt: str
    expected: str


class RunRequest(StrictModel):
    idempotency_key: str = Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9_-]+$")
    suite: Literal["sensitive", "garak"]
    profile: Literal["quick", "custom", "smoke", "core", "extended"]
    configuration: Configuration
    selection: list[str] = Field(default_factory=list, max_length=8)
    limits: Limits
    cases: list[Case] = Field(default_factory=list, max_length=6)


def resolve(body, settings):
    validate_endpoint(body.configuration.endpoint, settings.allowlist, settings.test_loopback)
    key = body.configuration.api_key.get_secret_value()
    if not key.strip() or len(key) > 8192 or any(ord(c) < 32 for c in key):
        raise ValueError("A valid target API key must be provided")
    if key in body.configuration.model or key in body.configuration.endpoint or key in body.idempotency_key:
        raise ValueError("Target credentials must not appear in persisted settings or identifiers")
    if any(ord(c) < 32 for c in body.configuration.model):
        raise ValueError("Model must be explicit text without control characters")
    cap, minutes = PROFILE_LIMITS[body.profile]
    rpm_ceiling = 30 if body.suite == "sensitive" else 100
    if body.limits.request_cap > cap or body.limits.minutes > minutes or body.limits.rpm > rpm_ceiling:
        raise ValueError("Run limits exceed the selected profile ceiling")
    concurrency_ceiling = 1 if body.suite == "sensitive" or body.profile == "smoke" else 20
    if body.limits.concurrency > concurrency_ceiling:
        raise ValueError("Run limits exceed the selected profile ceiling")
    selection = list(dict.fromkeys(body.selection))
    probes, fixed = [], []
    if body.suite == "garak":
        if body.profile not in PROFILE_PROBES or selection or body.cases:
            raise ValueError("Garak uses only its fixed reviewed profile and no browser cases")
        probes = PROFILE_PROBES[body.profile]
    else:
        if body.profile not in ("quick", "custom"):
            raise ValueError("Sensitive Data supports Quick check or Custom only")
        if body.profile == "quick":
            if set(selection) != {"hkid", "cards"}:
                raise ValueError("Quick check is locked to HKID and Credit cards")
            selection = ["hkid", "cards"]
        if not selection or not set(selection) <= {"hkid", "cards", "apikey"}:
            raise ValueError("Select supported categories only")
        from common.test_catalog import get_cases
        fixed = get_cases(selection)
        if body.cases and [c.model_dump() for c in body.cases] != fixed:
            raise ValueError("Fixed cases must match the trusted server registry exactly")
        for family in selection:
            if family in ("hkid", "cards"):
                continue
            _, ids, reason = FAMILIES[family]
            if not ids:
                raise ValueError(reason)
            probes.extend(ids)
    if probes and installed_version() != GARAK_VERSION:
        raise ValueError("Native scanner execution requires Garak 0.17.0")
    data = body.model_dump(exclude={"idempotency_key"})
    data["configuration"].pop("api_key")
    data["selection"], data["cases"], data["probe_ids"] = selection, fixed, probes
    data["manifest_sha256"] = MANIFEST["sha256"]
    data["garak_version"] = installed_version()
    data["prompt_cap_per_probe"] = PROMPT_CAPS[body.profile]
    data["planned_cases"] = planned_cases(body.profile, selection, probes)
    if any(key in value for case in data["planned_cases"] for value in case.values() if isinstance(value, str)):
        raise ValueError("Target credentials must not appear in persisted case metadata")
    return data, key


def create_app(settings=None):
    settings = settings or Settings.from_env()
    if not settings.token:
        raise RuntimeError("FORTIAIGATE_RUNNER_TOKEN is required")
    os.umask(0o077)
    store = Store(settings.data_dir)
    supervisor = Supervisor(store, settings)

    @asynccontextmanager
    async def lifespan(app):
        supervisor.start()
        yield
        supervisor.close()

    app = FastAPI(title="Private FortiAIGate runner", lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)
    app.state.store, app.state.supervisor, app.state.settings = store, supervisor, settings

    def authenticate(request: Request, authorization: str = Header(default="")):
        # Network binding alone is not a sufficient guard against accidental public launch.
        if request.client and request.client.host not in ("127.0.0.1", "::1", "testclient"):
            raise HTTPException(403, "Runner accepts loopback callers only")
        expected = "Bearer " + settings.token
        if not hmac.compare_digest(authorization.encode(), expected.encode()):
            raise HTTPException(401, "Service authentication required")

    def owner(x_session_id: str = Header(default="", alias="X-Session-ID"), _=Depends(authenticate)):
        try:
            session = str(uuid.UUID(x_session_id))
        except (ValueError, AttributeError):
            raise HTTPException(400, "A server-generated session UUID is required")
        return hmac.new(settings.token.encode(), session.encode(), hashlib.sha256).hexdigest()

    def get_owned(run_id, session):
        run = store.get(run_id, session)
        if run is None:
            raise HTTPException(404, "Run not found")
        return run

    def public(run, result_rows=None, request_rows=None):
        # Keep frozen connection metadata internally, never duplicate credentials/target UI.
        data = {k: v for k, v in run.items() if k not in ("configuration", "cases")}
        result_rows = store.records("results", run["id"]) if result_rows is None else result_rows
        request_rows = store.records("requests", run["id"]) if request_rows is None else request_rows
        data["summary"] = {**run["summary"], **case_progress(
            result_rows, request_rows, run.get("planned_cases"),
            active=run["status"] in ("running", "cancelling") and not run["summary"].get("worker_status"))}
        return redact(data, display=True)

    @app.get("/health", dependencies=[Depends(authenticate)])
    def health():
        compatible = installed_version() == GARAK_VERSION
        return {"status": "ok", "execution_enabled": settings.execution_enabled,
                "garak_version": installed_version(), "capabilities": {"sensitive": True, "garak": compatible, "concurrency": 20},
                "reason": "Execution is disabled server-side" if not settings.execution_enabled else
                          "Gateway block provenance is unverified; serial execution only"}

    @app.get("/catalog", dependencies=[Depends(authenticate)])
    def get_catalog():
        return catalog()  # Read-only static manifest, never initializes target-active plugins.

    @app.post("/runs")
    async def start_run(request: Request, session=Depends(owner)):
        if not settings.execution_enabled:
            raise HTTPException(403, "Execution is disabled server-side")
        raw = await request.body()
        if len(raw) > 131072:
            raise HTTPException(413, "Run request is too large")
        try:
            body = RunRequest.model_validate_json(raw)
            data, key = resolve(body, settings)
        except ValidationError as exc:
            # FastAPI's default validation response echoes input, including credentials.
            raise HTTPException(422, [{"loc": list(e["loc"]), "msg": e["msg"], "type": e["type"]} for e in exc.errors()])
        except (ValueError, ImportError) as exc:
            raise HTTPException(422, str(exc))
        fingerprint = hashlib.sha256(json.dumps(data, sort_keys=True).encode()).hexdigest()
        try:
            run, created = store.create(session, body.idempotency_key, fingerprint, data)
        except AdmissionError as exc:
            raise HTTPException(409, str(exc))
        if created:
            try:
                supervisor.launch(run["id"], key)
            except Exception:
                raise HTTPException(503, "Private worker could not start")
        return public(store.get(run["id"], session))

    @app.get("/runs")
    def list_runs(session=Depends(owner)):
        return {"runs": [public(r) for r in store.list(session)]}

    @app.get("/runs/{run_id}")
    def status(run_id: str, session=Depends(owner)):
        return public(get_owned(run_id, session))

    @app.get("/runs/{run_id}/results")
    def results(run_id: str, session=Depends(owner)):
        run = get_owned(run_id, session)
        result_rows, request_rows = store.records("results", run_id), store.records("requests", run_id)
        public_run = public(run, result_rows, request_rows)
        return {"run": public_run, "summary": public_run["summary"],
                "results": redact(result_rows, display=True),
                "requests": redact(request_rows, display=True)}

    @app.post("/runs/{run_id}/cancel")
    def cancel(run_id: str, session=Depends(owner)):
        get_owned(run_id, session)
        return public(supervisor.cancel(run_id))

    @app.get("/runs/{run_id}/export")
    def export(run_id: str, session=Depends(owner)):
        run = get_owned(run_id, session)
        result_rows, request_rows = store.records("results", run_id), store.records("requests", run_id)
        public_run = public(run, result_rows, request_rows)
        return JSONResponse({"run": public_run, "summary": public_run["summary"],
                    "results": redact(result_rows, display=True),
                    "requests": redact(request_rows, display=True)},
                    headers={"Content-Disposition": f'attachment; filename="assessment-{uuid.UUID(run_id)}.json"',
                             "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff"})

    return app
