import json
import os
import time
import uuid
from concurrent.futures import ThreadPoolExecutor

import pytest
from fastapi.testclient import TestClient

from runner.api import RunRequest, create_app, resolve
from runner.settings import DEFAULT_ENDPOINT, Settings
from runner.store import AdmissionError, Store


def headers(session=None):
    return {"Authorization": "Bearer service-only", "X-Session-ID": session or str(uuid.uuid4())}


def request_body(**changes):
    body = {"idempotency_key": str(uuid.uuid4()), "suite": "sensitive", "profile": "quick",
            "configuration": {"endpoint": DEFAULT_ENDPOINT, "model": "qwen3.8-flash", "api_key": "fake-test-credential", "timeout": 1},
            "selection": ["hkid", "cards"], "limits": {"request_cap": 6, "rpm": 30, "minutes": 1, "concurrency": 1}, "cases": []}
    body.update(changes)
    return body


@pytest.fixture
def app(tmp_path):
    return create_app(Settings(token="service-only", data_dir=tmp_path, execution_enabled=True))


def test_auth_disabled_default_and_session(tmp_path):
    app = create_app(Settings(token="service-only", data_dir=tmp_path))
    with TestClient(app) as client:
        assert client.get("/health").status_code == 401
        assert client.get("/health", headers=headers()).json()["execution_enabled"] is False
        assert client.get("/runs", headers={"Authorization": "Bearer service-only"}).status_code == 400
        assert client.post("/runs", headers=headers(), json=request_body()).status_code == 403
        assert DEFAULT_ENDPOINT not in client.get("/health", headers=headers()).text


def test_missing_service_token(monkeypatch):
    monkeypatch.delenv("FORTIAIGATE_RUNNER_TOKEN", raising=False)
    with pytest.raises(RuntimeError):
        Settings.from_env()


def test_session_scoping_idempotency_and_no_secret(app, monkeypatch):
    monkeypatch.setattr(app.state.supervisor, "launch", lambda *_: None)
    a, b = headers(), headers()
    body = request_body()
    with TestClient(app) as client:
        first = client.post("/runs", json=body, headers=a)
        assert first.status_code == 200
        run_id = first.json()["id"]
        assert client.post("/runs", json=body, headers=a).json()["id"] == run_id
        for path in (f"/runs/{run_id}", f"/runs/{run_id}/results", f"/runs/{run_id}/export"):
            assert client.get(path, headers=b).status_code == 404
        assert client.post(f"/runs/{run_id}/cancel", headers=b).status_code == 404
        assert client.get("/runs", headers=b).json() == {"runs": []}
        assert client.post("/runs", json=request_body(), headers=b).status_code == 409
        changed = {**body, "limits": {**body["limits"], "request_cap": 5}}
        assert client.post("/runs", json=changed, headers=a).status_code == 409
        assert "fake-test-credential" not in first.text
        assert b"fake-test-credential" not in app.state.store.path.read_bytes()
        assert os.stat(app.state.store.path).st_mode & 0o777 == 0o600
        assert os.stat(app.state.store.directory / run_id).st_mode & 0o777 == 0o700
        assert client.post(f"/runs/{run_id}/cancel", headers=a).json()["status"] == "cancelling"


@pytest.mark.parametrize("changes", [
    {"profile": "core"}, {"selection": ["hkid"]}, {"selection": ["hkid", "cards", "apikey"]},
    {"profile": "custom", "selection": ["sysprompt"]}, {"profile": "custom", "selection": ["propile"]},
    {"suite": "garak", "profile": "smoke", "selection": ["apikey"]},
    {"limits": {"request_cap": 61, "rpm": 30, "minutes": 10, "concurrency": 1}},
    {"limits": {"request_cap": 6, "rpm": 101, "minutes": 10, "concurrency": 1}},
    {"limits": {"request_cap": 6, "rpm": 30, "minutes": 31, "concurrency": 1}},
    {"limits": {"request_cap": 6, "rpm": 101, "minutes": 1, "concurrency": 2}},
    {"suite": "garak", "profile": "smoke", "selection": [], "limits": {"request_cap": 6, "rpm": 30, "minutes": 1, "concurrency": 2}},
    {"suite": "garak", "profile": "core", "selection": [], "limits": {"request_cap": 6, "rpm": 30, "minutes": 1, "concurrency": 21}},
    {"plugin_path": "os.system"},
])
def test_reject_invalid_browser_options(app, changes):
    with TestClient(app) as client:
        response = client.post("/runs", headers=headers(), json=request_body(**changes))
        assert response.status_code == 422
        assert "fake-test-credential" not in response.text


def test_garak_concurrency_within_profile_ceiling(app, monkeypatch):
    monkeypatch.setattr(app.state.supervisor, "launch", lambda *_: None)
    with TestClient(app) as client:
        body = request_body(suite="garak", profile="core", selection=[],
                            limits={"request_cap": 6, "rpm": 100, "minutes": 5, "concurrency": 10})
        assert client.post("/runs", json=body, headers=headers()).status_code == 200


def test_sensitive_rpm_stays_capped_at_30(app, monkeypatch):
    monkeypatch.setattr(app.state.supervisor, "launch", lambda *_: None)
    with TestClient(app) as client:
        body = request_body(limits={"request_cap": 6, "rpm": 31, "minutes": 1, "concurrency": 1})
        assert client.post("/runs", json=body, headers=headers()).status_code == 422


def test_sensitive_registry_only_and_garak_profiles(tmp_path):
    from common.test_catalog import get_cases
    settings = Settings("service-only", tmp_path)
    body = RunRequest.model_validate(request_body(cases=get_cases()))
    data, _ = resolve(body, settings)
    assert data["cases"] == get_cases()
    tampered = request_body(cases=get_cases())
    tampered["cases"][0]["prompt"] = "arbitrary browser prompt"
    with pytest.raises(ValueError, match="registry"):
        resolve(RunRequest.model_validate(tampered), settings)
    custom, _ = resolve(RunRequest.model_validate(request_body(profile="custom", selection=["hkid"])), settings)
    assert len(custom["cases"]) == 2
    garak, _ = resolve(RunRequest.model_validate(request_body(suite="garak", profile="smoke", selection=[])), settings)
    assert garak["probe_ids"] == ["dan.Ablation_Dan_11_0", "promptinject.HijackLongPrompt"]


def test_configuration_has_no_output_token_budget(tmp_path):
    body = request_body()
    data, _ = resolve(RunRequest.model_validate(body), Settings("service-only", tmp_path))
    assert "max_tokens" not in data["configuration"]
    assert "max_completion_tokens" not in data["configuration"]
    body["configuration"]["max_tokens"] = 512
    with pytest.raises(ValueError):
        RunRequest.model_validate(body)


def test_atomic_admission(tmp_path):
    store = Store(tmp_path)
    def create(i):
        try:
            return store.create("owner", str(i), "fp", {})[1]
        except AdmissionError:
            return False
    with ThreadPoolExecutor(max_workers=8) as pool:
        assert sum(pool.map(create, range(20))) == 1


def test_restart_recovery_and_service_lock(tmp_path):
    from runner.supervisor import Supervisor
    store = Store(tmp_path)
    run, _ = store.create("owner", "idem", "fp", {})
    store.put("results", run["id"], {"id": "partial", "response": "partial"})
    a = Supervisor(store, Settings("service-only", tmp_path))
    b = Supervisor(store, Settings("service-only", tmp_path))
    a.start()
    assert store.get(run["id"])["status"] == "interrupted"
    assert len(store.records("results", run["id"])) == 1
    with pytest.raises(RuntimeError, match="Only one"):
        b.start()
    a.close()


def test_cancel_terminal_race_does_not_reoccupy_admission(tmp_path, monkeypatch):
    from runner.supervisor import Supervisor
    store = Store(tmp_path)
    run, _ = store.create("owner", "idem", "fp", {})
    supervisor = Supervisor(store, Settings("service-only", tmp_path))
    original = store.update
    def finish_before_cancel(run_id, **values):
        # Deterministic interleaving: monitor commits while cancel is pending.
        store.finalize(run_id, "completed", None, {"completion_verified": True})
        return original(run_id, **values)
    monkeypatch.setattr(store, "update", finish_before_cancel)
    cancelled = supervisor.cancel(run["id"])
    assert cancelled["status"] == "completed" and not cancelled["cancel_requested"]
    assert store.create("owner", "next", "fp", {})[1]


def test_cancel_during_terminal_finalization_wins_atomically(tmp_path, monkeypatch):
    from runner.supervisor import Supervisor
    store = Store(tmp_path)
    body = {"limits": {"minutes": 1}, "cases": [], "probe_ids": [], "profile": "quick"}
    run, _ = store.create("owner", "idem", "fp", body)
    store.update(run["id"], summary={"worker_status": "completed", "worker_verified": True})
    original = store.finalize
    def cancel_before_finalize(run_id, *args):
        store.request_cancel(run_id)
        return original(run_id, *args)
    monkeypatch.setattr(store, "finalize", cancel_before_finalize)
    class Process:
        returncode = 0
        def poll(self):
            return 0
        def wait(self):
            return 0
    Supervisor(store, Settings("service-only", tmp_path)).monitor(run["id"], Process())
    result = store.get(run["id"])
    assert result["status"] == "cancelled" and not result["summary"]["completion_verified"]
    assert store.create("owner", "next", "fp", {})[1]


@pytest.mark.parametrize("worker_status,final_error,recovered,expected", [
    ("failed", "http_error", False, "failed"),
    ("failed", None, False, "failed"),
    ("completed", "http_error", False, "completed"),
    ("completed", None, True, "completed"),
])
def test_native_coverage_keeps_transport_errors_as_case_evidence(tmp_path, worker_status, final_error, recovered, expected):
    from runner.catalog import MANIFEST
    from runner.supervisor import Supervisor
    store = Store(tmp_path)
    body = {"limits": {"minutes": 1}, "cases": [], "probe_ids": ["dan.Dan_11_0"], "profile": "smoke"}
    run, _ = store.create("owner", "idem", "fp", body)
    report = [
        {"entry_type": "init", "run": "native-run"},
        {"entry_type": "attempt", "uuid": "attempt", "status": 2, "probe_classname": "dan.Dan_11_0"},
        {"entry_type": "completion", "run": "native-run"},
    ]
    (tmp_path / run["id"] / "native.report.jsonl").write_text("".join(json.dumps(r) + "\n" for r in report))
    store.update(run["id"], summary={"worker_status": worker_status, "worker_verified": True, "finished_probes": 1})
    if recovered:
        store.put("requests", run["id"], {"id": "retry0", "logical_id": "attempt", "error": "rate_limited"})
    store.put("requests", run["id"], {"id": "final", "logical_id": "attempt", "error": final_error})
    store.put("results", run["id"], {"id": "output", "response": "reply" if not final_error else None, "outcome": "unscored", "error": final_error})
    class Process:
        returncode = 0
        def poll(self):
            return 0
        def wait(self):
            return 0
    Supervisor(store, Settings("service-only", tmp_path)).monitor(run["id"], Process())
    result = store.get(run["id"])
    assert result["status"] == expected
    assert result["summary"]["completion_verified"] == (expected == "completed")
    if recovered:
        assert result["summary"]["request_errors"] == 1


def test_catalog_does_not_initialize_plugins(app, monkeypatch):
    import runner.native
    monkeypatch.setattr(runner.native, "load_probe", lambda *_: pytest.fail("preview initialized probe"))
    monkeypatch.setattr("httpx.Client.stream", lambda *_args, **_kwargs: pytest.fail("catalog made a target request"))
    with TestClient(app) as client:
        data = client.get("/catalog", headers=headers()).json()
    families = {f["id"]: f for f in data["families"]}
    profiles = {p["id"]: p for p in data["profiles"]}
    assert profiles["smoke"]["limits"]["minutes"] == 3
    assert profiles["core"]["limits"]["minutes"] == 5
    assert profiles["extended"]["limits"]["minutes"] == 30
    assert profiles["smoke"]["limits"]["rpm"] == 100
    assert profiles["core"]["limits"]["rpm"] == 100
    assert profiles["extended"]["limits"]["rpm"] == 100
    assert profiles["quick"]["limits"]["rpm"] == 30
    assert profiles["custom"]["limits"]["rpm"] == 30
    assert "sysprompt" not in families
    assert "propile" not in families
    assert "leakreplay" not in families
    assert families["apikey"]["previews"]
    assert len(families["hkid"]["previews"]) == 2


@pytest.mark.parametrize("profile,count", [("quick", 6), ("smoke", 10), ("core", 27), ("extended", 1151)])
def test_catalog_and_admission_share_exact_sampled_plan(tmp_path, profile, count):
    from common.test_catalog import get_cases
    from runner.catalog import MANIFEST, catalog, planned_cases
    from runner.native import PROMPT_CAPS
    body = request_body() if profile == "quick" else request_body(suite="garak", profile=profile, selection=[])
    data, _ = resolve(RunRequest.model_validate(body), Settings("service-only", tmp_path))
    preview = next(p for p in catalog()["profiles"] if p["id"] == profile)
    plan = data["planned_cases"]
    assert plan == preview["planned_cases"] == planned_cases(profile)
    assert len(plan) == preview["planned_case_count"] == count
    assert len({c["case_id"] for c in plan}) == count
    assert all(c["id"] == c["case_id"] and c["family"] and c["family_title"] for c in plan)
    assert data["manifest_sha256"] == MANIFEST["sha256"]
    if profile == "quick":
        assert [{k: c[k] for k in get_cases()[0]} for c in plan] == get_cases()
    else:
        expected = [(p, i, prompt) for p in data["probe_ids"]
                    for i, prompt in enumerate(MANIFEST["probes"][p]["prompts"][:PROMPT_CAPS[profile]])]
        assert [(c["probe"], c["source_index"], c["prompt"]) for c in plan] == expected
        assert all(c["case_id"] == f"{p}:{i}" for c, (p, i, _) in zip(plan, expected))
        assert plan[0]["is_template"] and "{generator.name}" in plan[0]["prompt"]


def test_known_text_replay_is_not_selectable(app):
    from runner.catalog import catalog, PROFILE_PROBES
    assert "leakreplay" not in {family["id"] for family in catalog()["families"]}
    assert all(not probe.startswith("leakreplay.") for probes in PROFILE_PROBES.values() for probe in probes)
    assert all(case["family"] != "leakreplay" for profile in catalog()["profiles"] for case in profile["planned_cases"])
    with TestClient(app) as client:
        response = client.post("/runs", headers=headers(), json=request_body(profile="custom", selection=["leakreplay"]))
        assert response.status_code == 422


def test_custom_family_previews_exact_sampling_and_fixture_order(tmp_path):
    from runner.catalog import catalog
    data, _ = resolve(RunRequest.model_validate(request_body(profile="custom", selection=["cards", "apikey", "hkid"])),
                      Settings("service-only", tmp_path))
    families = {f["id"]: f for f in catalog()["families"]}
    expected = [c for key in ("hkid", "cards", "apikey") for c in families[key]["previews"]]
    assert data["planned_cases"] == expected
    assert len(families["apikey"]["previews"]) == 32
    assert "leakreplay" not in families
    assert families["apikey"]["prompt_cap_per_probe"] == 16
    assert families["apikey"]["manifest_prompt_count"] > len(families["apikey"]["previews"])


def test_frozen_plan_public_redaction_and_legacy_unknown_scope(app, monkeypatch):
    from common.test_catalog import get_cases
    monkeypatch.setattr(app.state.supervisor, "launch", lambda *_: None)
    auth = headers()
    with TestClient(app) as client:
        admitted = client.post("/runs", headers=auth, json=request_body()).json()
        run_id = admitted["id"]
        original = app.state.store.get(run_id)["planned_cases"]
        assert original[0]["prompt"] == get_cases()[0]["prompt"]
        monkeypatch.setattr("common.test_catalog.get_cases", lambda *_: [])
        for path in (f"/runs/{run_id}", f"/runs/{run_id}/results", f"/runs/{run_id}/export"):
            response = client.get(path, headers=auth)
            data = response.json()
            public_run = data.get("run", data)
            assert public_run["planned_cases"] == admitted["planned_cases"]
            assert public_run["summary"]["planned_case_count"] == 6
            assert public_run["summary"]["started_case_count"] == public_run["summary"]["finished_case_count"] == 0
            for forbidden in ("fake-test-credential", DEFAULT_ENDPOINT):
                assert forbidden not in response.text
        assert app.state.store.get(run_id)["planned_cases"] == original
        app.state.store.finalize(run_id, "cancelled", "test", {})
        # Store body predates plans; use existing authenticated run's owner in SQLite only.
        with app.state.store.connect() as db:
            owner = db.execute("SELECT owner FROM runs WHERE id=?", (run_id,)).fetchone()[0]
        legacy, _ = app.state.store.create(owner, "legacy", "fp", {"profile": "quick", "probe_ids": [], "cases": []})
        app.state.store.put("results", legacy["id"], {"id": "old-id", "case_id": None, "response": "old reply"})
        app.state.store.finalize(legacy["id"], "completed", None, {"outputs": 1, "planned_cases": 6, "completion_verified": True})
        evidence = client.get(f"/runs/{legacy['id']}/results", headers=auth).json()
        assert "planned_cases" not in evidence["run"]
        assert evidence["summary"]["planned_case_count"] is None
        assert evidence["summary"]["finished_case_count"] is None
        assert evidence["summary"]["planned_cases"] == 6 and evidence["summary"]["outputs"] == 1
        assert evidence["results"][0]["response"] == "old reply"


def test_reject_browser_plan_or_case_override(app):
    with TestClient(app) as client:
        for extra in ({"planned_cases": [{"case_id": "evil", "prompt": "arbitrary"}]}, {"case_id": "HKID-01"}, {"probe_ids": ["unreviewed.Plugin"]}):
            assert client.post("/runs", headers=headers(), json=request_body(**extra)).status_code == 422
        assert client.post("/runs/HKID-01/send", headers=headers(), json={"prompt": "arbitrary"}).status_code == 404


def test_credentials_cannot_enter_trusted_plan(tmp_path):
    body = request_body()
    body["configuration"]["api_key"] = "A123456(7)"
    with pytest.raises(ValueError, match="case metadata"):
        resolve(RunRequest.model_validate(body), Settings("service-only", tmp_path))


@pytest.mark.parametrize("change", ["plan", "fixed_dispatch", "manifest"])
def test_worker_rejects_changed_frozen_scope_without_dispatch(tmp_path, monkeypatch, change):
    from runner.worker import execute
    monkeypatch.setattr("httpx.Client.stream", lambda *_args, **_kwargs: pytest.fail("invalid scope dispatched"))
    data, key = resolve(RunRequest.model_validate(request_body()), Settings("service-only", tmp_path))
    if change == "plan":
        data["planned_cases"][0]["source_index"] = 9
    elif change == "fixed_dispatch":
        data["cases"][0]["prompt"] = "different dispatch"
    else:
        data["manifest_sha256"] = "wrong-manifest"
    store = Store(tmp_path)
    run, _ = store.create("owner", "idem", "fp", data)
    execute({"data_dir": str(tmp_path), "run_id": run["id"], "api_key": key, "allowlist": (DEFAULT_ENDPOINT,), "test_loopback": False})
    evidence = store.get(run["id"])
    assert evidence["summary"]["worker_status"] == "failed"
    assert evidence["summary"]["started_case_count"] == evidence["summary"]["finished_case_count"] == 0
    assert store.records("requests", run["id"]) == store.records("results", run["id"]) == []


def test_terminal_request_only_failure_is_not_finished_case(tmp_path):
    from runner.supervisor import Supervisor
    data, _ = resolve(RunRequest.model_validate(request_body()), Settings("service-only", tmp_path))
    store = Store(tmp_path)
    run, _ = store.create("owner", "idem", "fp", data)
    store.put("requests", run["id"], {"id": "request", "case_id": "HKID-01", "error": "timeout"})
    class Process:
        returncode = 1
        def poll(self):
            return 1
        def wait(self):
            return 1
    Supervisor(store, Settings("service-only", tmp_path)).monitor(run["id"], Process())
    result = store.get(run["id"])
    assert result["status"] == "failed"
    assert result["summary"]["started_case_count"] == 1 and result["summary"]["finished_case_count"] == 0
    assert result["summary"]["planned_case_count"] == 6 and result["summary"]["current_case_id"] is None
    assert result["summary"]["request_errors"] == 1
    assert store.records("results", run["id"]) == []


def test_configuration_accepts_the_app_timeout_range():
    from pydantic import ValidationError
    from runner.api import Configuration
    base = {"endpoint": "https://test.invalid/v1/chat/completions", "model": "m", "api_key": "k"}
    assert Configuration(timeout=120, **base).timeout == 120
    with pytest.raises(ValidationError):
        Configuration(timeout=301, **base)
