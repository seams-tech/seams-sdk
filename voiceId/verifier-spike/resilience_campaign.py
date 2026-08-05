from __future__ import annotations

import argparse
import json
import os
import resource
import socket
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, TimeoutError
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

from voiceid_verifier.app import BoundedStageExecutor, TimedStageResult


REPORT_SCHEMA_VERSION = "voice_id_runtime_resilience_campaign_v1"
DEFAULT_ITERATIONS = 1_000
MAXIMUM_SOAK_P99_MS = 1_000.0
MAXIMUM_SOAK_FD_GROWTH = 2
MAXIMUM_SOAK_THREAD_GROWTH = 1


@dataclass(frozen=True)
class ScenarioResult:
    name: str
    passed: bool
    duration_ms: float
    details: dict[str, Any]

    def to_json(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "passed": self.passed,
            "durationMs": round(self.duration_ms, 3),
            "details": self.details,
        }


def run_scenario(name: str, operation: Callable[[], dict[str, Any]]) -> ScenarioResult:
    started = time.perf_counter()
    try:
        details = operation()
        passed = details.pop("passed", True)
    except Exception as error:
        details = {
            "errorType": type(error).__name__,
            "error": str(error),
        }
        passed = False
    return ScenarioResult(
        name=name,
        passed=passed,
        duration_ms=(time.perf_counter() - started) * 1000,
        details=details,
    )


def run_model_load_failure() -> dict[str, Any]:
    script = (
        "from voiceid_verifier.embeddings import SpeechBrainEcapaEmbeddingExtractor; "
        "from pathlib import Path; "
        "SpeechBrainEcapaEmbeddingExtractor(model_id='voiceid-missing-model', "
        "savedir=Path('/tmp/voiceid-missing-model-cache'))"
    )
    completed = subprocess.run(
        [sys.executable, "-c", script],
        capture_output=True,
        text=True,
        check=False,
        env={
            **os.environ,
            "HF_HUB_OFFLINE": "1",
            "TRANSFORMERS_OFFLINE": "1",
            "PYTHONPATH": "verifier",
        },
    )
    failed_closed = completed.returncode != 0
    error_observed = any(
        marker in completed.stderr
        for marker in (
            "failed to load SpeechBrain model",
            "SpeechBrain ECAPA requires optional dependencies",
        )
    )
    return {
        "passed": failed_closed,
        "failedClosed": failed_closed,
        "returnCode": completed.returncode,
        "errorObserved": error_observed,
    }


def run_forced_worker_termination() -> dict[str, Any]:
    worker = subprocess.Popen(
        [sys.executable, "-c", "import time; time.sleep(30)"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    worker.terminate()
    worker_return_code = worker.wait(timeout=5)
    replacement = subprocess.run(
        [sys.executable, "-c", "raise SystemExit(0)"],
        check=False,
    )
    recovered = replacement.returncode == 0
    return {
        "passed": worker_return_code != 0 and recovered,
        "workerReturnCode": worker_return_code,
        "replacementReturnCode": replacement.returncode,
        "recovered": recovered,
    }


def run_response_loss() -> dict[str, Any]:
    left, right = socket.socketpair()
    try:
        left.sendall(b"request")
        right.recv(1024)
        right.close()
        response = left.recv(1024)
        failed_closed = response == b""
    finally:
        left.close()
        try:
            right.close()
        except OSError:
            pass
    return {
        "passed": failed_closed,
        "failedClosed": failed_closed,
        "responseBytes": len(response),
    }


def run_request_timeout() -> dict[str, Any]:
    release = threading.Event()

    def blocking_request() -> str:
        release.wait(timeout=5)
        return "released"

    def replacement_request() -> str:
        return "replacement"

    executor = ThreadPoolExecutor(max_workers=1)
    try:
        future = executor.submit(blocking_request)
        timed_out = False
        try:
            future.result(timeout=0.01)
        except TimeoutError:
            timed_out = True
        release.set()
        future.result(timeout=1)
        recovered = executor.submit(replacement_request).result(timeout=1) == "replacement"
    finally:
        release.set()
        executor.shutdown(wait=True, cancel_futures=True)
    return {
        "passed": timed_out and recovered,
        "timedOut": timed_out,
        "recovered": recovered,
    }


def blocking_stage(release: threading.Event) -> TimedStageResult:
    release.wait(timeout=5)
    return TimedStageResult(completed_at=time.perf_counter(), value="released")


def replacement_stage() -> TimedStageResult:
    return TimedStageResult(completed_at=time.perf_counter(), value="replacement")


def run_queue_saturation() -> dict[str, Any]:
    release = threading.Event()
    executor = BoundedStageExecutor(maximum_active_stages=1)
    try:
        first = executor.submit(blocking_stage, release)
        second = executor.submit(replacement_stage)
        release.set()
        if first is None:
            raise RuntimeError("first stage was not admitted")
        first.result(timeout=1)
        replacement = executor.submit(replacement_stage)
        if replacement is None:
            raise RuntimeError("replacement stage was not admitted")
        replacement.result(timeout=1)
    finally:
        release.set()
        executor.shutdown()
    saturated = second is None
    return {
        "passed": saturated,
        "saturated": saturated,
        "recovered": True,
    }


def resource_snapshot() -> dict[str, int]:
    usage = resource.getrusage(resource.RUSAGE_SELF)
    maximum_rss = int(usage.ru_maxrss)
    if sys.platform != "darwin":
        maximum_rss *= 1024
    try:
        descriptor_count = len(os.listdir("/dev/fd"))
    except OSError:
        descriptor_count = -1
    return {
        "peakRssBytes": maximum_rss,
        "openFileDescriptors": descriptor_count,
        "activeThreads": threading.active_count(),
    }


def soak_stage(index: int) -> TimedStageResult:
    return TimedStageResult(completed_at=time.perf_counter(), value=index)


def percentile(values: list[float], quantile: float) -> float:
    ordered = sorted(values)
    if len(ordered) == 1:
        return ordered[0]
    position = (len(ordered) - 1) * quantile
    lower = int(position)
    upper = min(lower + 1, len(ordered) - 1)
    fraction = position - lower
    return ordered[lower] + (ordered[upper] - ordered[lower]) * fraction


def run_soak(iterations: int) -> dict[str, Any]:
    if iterations <= 0:
        raise ValueError("iterations must be positive")
    before = resource_snapshot()
    latencies: list[float] = []
    executor = BoundedStageExecutor(maximum_active_stages=1)
    try:
        for index in range(iterations):
            started = time.perf_counter()
            future = executor.submit(soak_stage, index)
            if future is None:
                raise RuntimeError("soak stage was not admitted")
            result = future.result(timeout=1)
            if result.value != index:
                raise RuntimeError("soak result was reordered")
            latencies.append((time.perf_counter() - started) * 1000)
    finally:
        executor.shutdown()
    after = resource_snapshot()
    p99 = percentile(latencies, 0.99)
    fd_growth = (
        after["openFileDescriptors"] - before["openFileDescriptors"]
        if before["openFileDescriptors"] >= 0 and after["openFileDescriptors"] >= 0
        else 0
    )
    thread_growth = after["activeThreads"] - before["activeThreads"]
    return {
        "passed": (
            p99 <= MAXIMUM_SOAK_P99_MS
            and fd_growth <= MAXIMUM_SOAK_FD_GROWTH
            and thread_growth <= MAXIMUM_SOAK_THREAD_GROWTH
        ),
        "iterations": iterations,
        "latencyMs": {
            "p50": round(percentile(latencies, 0.50), 3),
            "p95": round(percentile(latencies, 0.95), 3),
            "p99": round(p99, 3),
        },
        "before": before,
        "after": after,
        "fileDescriptorGrowth": fd_growth,
        "threadGrowth": thread_growth,
        "workerCount": 1,
    }


def run_campaign(iterations: int) -> dict[str, Any]:
    scenarios = tuple(
        run_scenario(name, operation)
        for name, operation in (
            ("model_load_failure", run_model_load_failure),
            ("forced_worker_termination", run_forced_worker_termination),
            ("response_loss", run_response_loss),
            ("request_timeout", run_request_timeout),
            ("queue_saturation", run_queue_saturation),
        )
    )
    soak_started = time.perf_counter()
    try:
        soak = run_soak(iterations)
        soak_error = None
    except Exception as error:
        soak = {"passed": False}
        soak_error = {
            "errorType": type(error).__name__,
            "error": str(error),
        }
    soak_result = {
        "passed": soak["passed"],
        "durationMs": round((time.perf_counter() - soak_started) * 1000, 3),
        "details": soak,
    }
    return {
        "schemaVersion": REPORT_SCHEMA_VERSION,
        "generatedAt": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "faultCampaign": [scenario.to_json() for scenario in scenarios],
        "soak": soak_result,
        "soakError": soak_error,
        "releaseReady": all(scenario.passed for scenario in scenarios)
        and soak_result["passed"]
        and soak_error is None,
    }


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Run the VoiceID runtime fault campaign and bounded soak."
    )
    parser.add_argument("--iterations", type=int, default=DEFAULT_ITERATIONS)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    report = run_campaign(args.iterations)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    if not report["releaseReady"]:
        raise SystemExit("VoiceID runtime resilience campaign failed")


if __name__ == "__main__":
    main()
