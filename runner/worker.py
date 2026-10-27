"""Private process entrypoint. Configuration and target key arrive via stdin pipe."""
import copy
import json
import os
import signal
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from runner.reports import NativeReport, RedactedWriter, case_progress, redact, summary
from runner.store import Store
from runner.transport import StopRun, Transport


def execute(payload):
    os.umask(0o077)
    store = Store(payload["data_dir"])
    run_id = payload["run_id"]
    run = store.get(run_id)
    if not run or run["cancel_requested"] or run["status"] != "queued":
        return
    if not store.update(run_id, expected_status=("queued",), status="running", started_at=time.time()):
        return
    configuration = {**run["configuration"], "api_key": payload["api_key"]}
    transport = Transport(configuration, run["limits"], payload["allowlist"], payload["test_loopback"], store, run_id)
    started = time.monotonic()
    finished = 0
    status, error, verified = "completed", None, False
    native_report = None
    native_config = None
    try:
        from runner.catalog import MANIFEST, planned_cases
        if "planned_cases" in run and (
                run.get("manifest_sha256") != MANIFEST["sha256"] or
                run["planned_cases"] != planned_cases(run["profile"], run.get("selection", []), run["probe_ids"])):
            raise RuntimeError("Frozen case plan does not match the reviewed execution scope")
        if "planned_cases" in run:
            fixed_plan = [{key: case[key] for key in ("id", "group", "title", "prompt", "expected")}
                          for case in run["planned_cases"] if case.get("group") in ("hkid", "cards")]
            if run["cases"] != fixed_plan:
                raise RuntimeError("Fixed dispatch cases do not match the frozen case plan")
        for case in run["cases"]:
            attempt_id = "fixed:" + case["id"]
            record = transport.request([{"role": "user", "content": case["prompt"]}],
                                       attempt_id=attempt_id, case_id=case["id"])
            row = {"id": attempt_id, "case_id": case["id"], "probe": "fortiaigate.fixed." + case["group"],
                   "prompt": case["prompt"], "response": record["response"], "expected": case["expected"],
                   **{key: record[key] for key in ("raw_response", "content_type", "status_code", "response_truncated", "response_format", "finish_reason", "block_source")},
                   "outcome": "unscored", "gateway_outcome": record["gateway_outcome"],
                   "latency_ms": record["latency_ms"], "detectors": [], "error": record["error"], "finalized": True}
            store.put("results", run_id, redact(row, payload["api_key"]))
            update_progress(store, run_id, run, finished, started)
            if record["fatal"]:
                raise StopRun(record["error"])
        if run["probe_ids"]:
            from runner.native import configure_native, load_probe, load_detectors, PROBES, PROMPT_CAPS
            from runner.garak_adapter import GatewayGenerator
            from garak import command
            from garak.attempt import ATTEMPT_COMPLETE
            from garak.evaluators.base import ThresholdEvaluator
            native_config = configure_native()
            native_config.reporting.report_dir = str(store.directory / run_id)
            native_config.reporting.report_prefix = "native"
            native_config.plugins.target_type = "runner.garak_adapter.GatewayGenerator"
            native_config.plugins.target_name = run["configuration"]["model"]
            command.start_run()
            native_config.transient.reportfile = RedactedWriter(native_config.transient.reportfile, payload["api_key"])
            native_report = Path(native_config.transient.report_filename)
            generator = GatewayGenerator(run["configuration"]["model"], transport)
            evaluator = ThresholdEvaluator(0.5)
            report_lock = threading.Lock()
            progress_lock = threading.Lock()
            progress_last = [0.0]
            for probe_id in run["probe_ids"]:
                transport.check()
                probe = load_probe(probe_id)
                # The reviewed manifest is the exact execution source, not browser text.
                from runner.catalog import MANIFEST
                if list(probe.prompts) != MANIFEST["probes"][probe_id]["prompts"]:
                    raise RuntimeError("Installed native prompt manifest does not match reviewed version")
                cap = PROMPT_CAPS[run["profile"]]
                probe.prompts = list(probe.prompts)[:cap]
                if hasattr(probe, "triggers"):
                    probe.triggers = list(probe.triggers)[:cap]
                detectors = load_detectors(probe_id)
                # Retain native probe preprocessing (including DAN model formatting).
                # Only its serial execution loop is instrumented to persist each
                # scored attempt before the next dispatch or cancellation.
                def run_attempt(attempt, halt):
                    if halt.is_set():
                        raise StopRun("cancelled")
                    transport.check()
                    if type(attempt.seq) is not int or not 0 <= attempt.seq < len(probe.prompts):
                        raise RuntimeError("Native attempt sequence is outside the reviewed case scope")
                    # Every in-flight attempt owns its generator: the adapter carries
                    # per-attempt correlation state and is not parallel-capable.
                    gen = GatewayGenerator(run["configuration"]["model"], transport)
                    gen.attempt_id, gen.probe_id = str(attempt.uuid), probe_id
                    gen.case_id = f"{probe_id}:{attempt.seq}"
                    gen.last_request = None
                    attempt.notes["case_id"] = gen.case_id
                    with report_lock:
                        native_config.transient.reportfile.write(json.dumps(attempt.as_dict()) + "\n")
                    try:
                        # Mirror garak's _execute_attempt against the per-attempt
                        # generator instead of the shared probe.generator.
                        probe._generator_precall_hook(gen, attempt)
                        attempt.outputs = gen.generate(attempt.prompt, generations_this_call=probe.generations)
                        if probe.post_buff_hook:
                            attempt = probe._postprocess_buff(attempt)
                        attempt = probe._postprocess_hook(attempt)
                        attempt = copy.deepcopy(attempt)
                    except StopRun:
                        request_rows = [r for r in store.records("requests", run_id) if r.get("attempt_id") == str(attempt.uuid)]
                        if request_rows:
                            last = request_rows[-1]
                            store.put("results", run_id, {"id": str(attempt.uuid) + ":0", "case_id": gen.case_id,
                                "attempt_id": str(attempt.uuid), "finalized": False,
                                "probe": probe_id, "prompt": last["prompt"], "response": last["response"],
                                **{key: last[key] for key in ("raw_response", "content_type", "status_code", "response_truncated", "response_format", "finish_reason", "block_source")},
                                "outcome": "unscored", "gateway_outcome": last["gateway_outcome"], "latency_ms": last["latency_ms"],
                                "detectors": [], "error": last["error"] or "evaluation_interrupted"})
                        raise
                    attempt = probe._postprocess_attempt(attempt)
                    for detector_id, detector in detectors:
                        if (gen.last_request["gateway_outcome"] == "confirmed_block" or
                                gen.last_request["response_format"] not in ("openai_chat", "refusal") or
                                gen.last_request["response"] is None or gen.last_request["error"] or detector.skip):
                            attempt.detector_results[detector_id] = [None] * len(attempt.outputs)
                        else:
                            attempt.detector_results[detector_id] = list(detector.detect(attempt))
                    attempt.status = ATTEMPT_COMPLETE
                    attempt.notes.update({key: gen.last_request[key] for key in
                                          ("response", "gateway_outcome", "raw_response", "content_type", "status_code", "response_truncated", "response_format", "finish_reason", "block_source")})
                    with report_lock:
                        native_config.transient.reportfile.write(json.dumps(attempt.as_dict()) + "\n")
                    parser = NativeReport()
                    parser.feed(json.dumps(attempt.as_dict()) + "\n")
                    for row in parser.rows(PROBES):
                        row.update({key: gen.last_request[key] for key in
                                    ("response", "gateway_outcome", "raw_response", "content_type", "status_code", "response_truncated", "response_format", "finish_reason", "block_source")})
                        row["latency_ms"] = gen.last_request["latency_ms"]
                        row["error"] = gen.last_request["error"]
                        if row["error"] or row["gateway_outcome"] == "confirmed_block":
                            row["outcome"] = "unscored"
                        store.put("results", run_id, redact(row, payload["api_key"]))
                    # Scores use genuine output; only disk copies are redacted.
                    for output in attempt.outputs:
                        if output is not None and output.text is not None:
                            output.text = redact(output.text, payload["api_key"])
                    with progress_lock:
                        now = time.monotonic()
                        if now - progress_last[0] >= 1.0:
                            progress_last[0] = now
                            update_progress(store, run_id, run, finished, started)
                    if gen.last_request["fatal"]:
                        raise StopRun(gen.last_request["error"])
                    return attempt

                def execute_all(attempts_todo):
                    # Keep `concurrency` requests in flight; a finished attempt
                    # releases its slot as the pool drains the reviewed plan.
                    concurrency = max(1, int(run["limits"].get("concurrency", 1)))
                    if concurrency <= 1:
                        return [run_attempt(attempt, threading.Event()) for attempt in attempts_todo]
                    halt = threading.Event()
                    attempts = []
                    with ThreadPoolExecutor(max_workers=concurrency) as pool:
                        futures = [pool.submit(run_attempt, attempt, halt) for attempt in attempts_todo]
                        for future in futures:
                            try:
                                attempts.append(future.result())
                            except StopRun:
                                halt.set()
                                for pending in futures:
                                    pending.cancel()
                                raise
                    return attempts
                probe._execute_all = execute_all
                attempts = probe.probe(generator)
                evaluator.evaluate(attempts)
                finished += 1
                update_progress(store, run_id, run, finished, started)
            # Native end_run emits completion first, then an optional local HTML digest.
            command.end_run()
            parser = NativeReport()
            parser.feed(native_report.read_text())
            expected_attempts = sum(min(len(MANIFEST["probes"][p]["prompts"]), PROMPT_CAPS[run["profile"]]) for p in run["probe_ids"])
            verified = parser.verified(True, len(run["probe_ids"]), finished, run["probe_ids"], expected_attempts)
            if not verified:
                status, error = "failed", "Native completion or coverage verification failed"
        else:
            verified = len(store.records("results", run_id)) == len(run["cases"])
        if "planned_cases" in run:
            progress = case_progress(store.records("results", run_id), store.records("requests", run_id), run["planned_cases"])
            verified = verified and progress["finished_case_count"] == progress["planned_case_count"]
            if not verified:
                status, error = "failed", "Frozen case coverage verification failed; partial evidence preserved"
    except StopRun as exc:
        if exc.reason == "cancelled":
            status, error = "cancelled", "Dispatch stopped; already-issued requests cannot be recalled"
        elif exc.reason in ("requests", "walltime"):
            status, error = "budget_limited", "Execution stopped at the " + exc.reason + " ceiling; coverage incomplete"
        else:
            messages = {"auth_error": "HTTP 401 authentication failed", "forbidden_unknown": "HTTP 403 forbidden; gateway provenance unknown",
                        "redirect_rejected": "HTTP redirect rejected", "response_too_large": "Response exceeded the 1 MiB body limit",
                        "invalid_or_empty_response": "Invalid response processing"}
            status, error = "failed", messages.get(exc.reason, "Execution stopped") + "; evidence preserved"
    except Exception as exc:
        import traceback
        trace = traceback.extract_tb(exc.__traceback__)
        location = Path(trace[-1].filename).name + ":" + str(trace[-1].lineno) if trace else "worker"
        status, error = "failed", "Worker failed during execution (" + type(exc).__name__ + " at " + location + ")"
    finally:
        transport.close()
        if native_config is not None:
            for stream in (native_config.transient.reportfile, native_config.transient.hitlogfile):
                if stream and not stream.closed:
                    stream.close()
        current = store.get(run_id)
        if current and current["status"] not in ("interrupted", "cancelled"):
            if current["cancel_requested"]:
                status, error, verified = "cancelled", "Cancelled by operator", False
            update_progress(store, run_id, run, finished, started, False, active=False)
            metrics = store.get(run_id)["summary"]
            metrics.update({"worker_status": status, "worker_error": error, "worker_verified": verified and status == "completed"})
            store.update(run_id, expected_status=("running", "cancelling"), summary=metrics)
            # Only the supervisor releases atomic admission after the process exits.


def update_progress(store, run_id, run, finished, started, verified=False, active=True):
    store.update(run_id, expected_status=("running", "cancelling"), summary=summary(store.records("results", run_id), store.records("requests", run_id),
        selected=len(run["probe_ids"]), finished=finished, planned=len(run["cases"]),
        verified=verified, elapsed=time.monotonic() - started, planned_cases=run.get("planned_cases"), active=active))


def main():
    os.umask(0o077)
    payload = json.load(sys.stdin)
    def terminate(*_):
        run = Store(payload["data_dir"]).get(payload["run_id"])
        reason = "cancelled" if not run or run["cancel_requested"] else "walltime"
        raise StopRun(reason)
    signal.signal(signal.SIGTERM, terminate)
    if "RUNNER_PARENT_FD" in os.environ:
        import threading
        fd = int(os.environ["RUNNER_PARENT_FD"])
        def parent_watch():
            try:
                os.read(fd, 1)  # EOF means the service died; no orphan target dispatch.
            finally:
                os.close(fd)
                os.kill(os.getpid(), signal.SIGTERM)
        threading.Thread(target=parent_watch, daemon=True).start()
    execute(payload)


if __name__ == "__main__":
    main()
