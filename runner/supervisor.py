import fcntl
import json
import os
import signal
import subprocess
import sys
import threading
import time
from pathlib import Path

from runner.reports import summary
from runner.store import ACTIVE


class Supervisor:
    def __init__(self, store, settings):
        self.store, self.settings = store, settings
        self.processes = {}
        self.lock = threading.RLock()
        self.service_lock = None

    def start(self):
        self.service_lock = open(self.store.directory / "service.lock", "a")
        os.chmod(self.store.directory / "service.lock", 0o600)
        try:
            fcntl.flock(self.service_lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            self.service_lock.close()
            raise RuntimeError("Only one runner service may use this data directory")
        self.store.recover()

    def launch(self, run_id, api_key):
        with self.lock:
            watch_read, watch_write = os.pipe()
            process = None
            try:
                env = {"PATH": os.environ.get("PATH", ""), "HOME": str(self.store.directory / run_id),
                       "HF_HUB_OFFLINE": "1", "HF_DATASETS_OFFLINE": "1", "TRANSFORMERS_OFFLINE": "1",
                       "HF_HUB_DISABLE_TELEMETRY": "1", "DO_NOT_TRACK": "1",
                       "XDG_CONFIG_HOME": str(self.store.directory / run_id / "config"),
                       "XDG_CACHE_HOME": str(self.store.directory / run_id / "cache"),
                       "XDG_DATA_HOME": str(self.store.directory / run_id / "data"),
                       "RUNNER_PARENT_FD": str(watch_read)}
                process = subprocess.Popen([sys.executable, "-m", "runner.worker"],
                    stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                    cwd=Path(__file__).resolve().parent.parent, env=env,
                    pass_fds=(watch_read,), start_new_session=True)
                os.close(watch_read)
                self.processes[run_id] = (process, watch_write)
                payload = {"data_dir": str(self.store.directory), "run_id": run_id, "api_key": api_key,
                           "allowlist": self.settings.allowlist, "test_loopback": self.settings.test_loopback}
                process.stdin.write(json.dumps(payload).encode())
                process.stdin.close()
            except Exception:
                if process is not None:
                    self.signal_group(process, signal.SIGKILL)
                    process.wait(timeout=2)
                    self.processes.pop(run_id, None)
                else:
                    os.close(watch_read)
                self.store.finalize(run_id, "failed", "Could not start private worker", {})
                os.close(watch_write)
                raise
            threading.Thread(target=self.monitor, args=(run_id, process), daemon=True).start()

    @staticmethod
    def signal_group(process, sig):
        if process.poll() is None:
            try:
                os.killpg(process.pid, sig)
            except ProcessLookupError:
                pass

    def monitor(self, run_id, process):
        run = self.store.get(run_id)
        deadline = time.monotonic() + run["limits"]["minutes"] * 60
        stop_at = None
        stop_status = None
        while process.poll() is None:
            current = self.store.get(run_id)
            if current["cancel_requested"] or time.monotonic() >= deadline:
                if stop_at is None:
                    stop_status = "cancelled" if current["cancel_requested"] else "budget_limited"
                    stop_at = time.monotonic()
                    self.signal_group(process, signal.SIGTERM)
                elif time.monotonic() - stop_at >= self.settings.cancel_grace:
                    self.signal_group(process, signal.SIGKILL)
            time.sleep(0.05)
        process.wait()
        current = self.store.get(run_id)
        if current and current["status"] in ACTIVE:
            rows = self.store.records("results", run_id)
            requests = self.store.records("requests", run_id)
            metrics = summary(rows, requests, selected=len(current["probe_ids"]),
                              finished=current["summary"].get("finished_probes", 0),
                              planned=len(current["cases"]), elapsed=(time.time() - (current["started_at"] or current["created_at"])),
                              planned_cases=current.get("planned_cases"))
            verified = False
            worker_status = current["summary"].get("worker_status", "failed")
            if process.returncode == 0 and not stop_status and not current["cancel_requested"] and worker_status == "completed" and current["summary"].get("worker_verified"):
                if current["probe_ids"]:
                    from runner.reports import NativeReport
                    report = self.store.directory / run_id / "native.report.jsonl"
                    if report.exists():
                        parser = NativeReport()
                        parser.feed(report.read_text())
                        from runner.catalog import MANIFEST
                        from runner.native import PROMPT_CAPS
                        expected_attempts = sum(min(len(MANIFEST["probes"][p]["prompts"]), PROMPT_CAPS[current["profile"]]) for p in current["probe_ids"])
                        verified = parser.verified(True, len(current["probe_ids"]), current["summary"].get("finished_probes", 0), current["probe_ids"], expected_attempts)
                else:
                    verified = len(rows) == len(current["cases"])
            if "planned_cases" in current:
                verified = verified and metrics["finished_case_count"] == metrics["planned_case_count"]
            metrics["completion_verified"] = verified
            final_status = "completed" if verified else stop_status or (worker_status if worker_status != "completed" else "failed")
            self.store.finalize(run_id, final_status,
                None if verified else current["summary"].get("worker_error") or "Worker ended without verified completion; partial evidence preserved", metrics)
        with self.lock:
            entry = self.processes.pop(run_id, None)
            if entry:
                os.close(entry[1])

    def cancel(self, run_id):
        self.store.request_cancel(run_id)
        return self.store.get(run_id)

    def close(self):
        with self.lock:
            processes = list(self.processes.items())
        for run_id, (process, _) in processes:
            self.cancel(run_id)
            self.signal_group(process, signal.SIGTERM)
        for _, (process, _) in processes:
            try:
                process.wait(timeout=self.settings.cancel_grace)
            except subprocess.TimeoutExpired:
                self.signal_group(process, signal.SIGKILL)
                process.wait(timeout=2)
        deadline = time.monotonic() + 2
        while self.processes and time.monotonic() < deadline:
            time.sleep(0.02)
        if self.service_lock:
            self.service_lock.close()
