from __future__ import annotations

import argparse
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any


BUDGET_SCHEMA_VERSION = "voice_id_benchmark_budgets_v1"
REPORT_SCHEMA_VERSION = "voice_id_benchmark_budget_check_v1"


class BenchmarkBudgetError(ValueError):
    pass


@dataclass(frozen=True)
class StageBudget:
    maximum_p95_latency_ms: float
    maximum_p99_latency_ms: float
    maximum_error_rate: float
    maximum_retry_or_uncertainty_rate: float
    minimum_accuracy: float
    maximum_peak_rss_bytes: int


@dataclass(frozen=True)
class BenchmarkBudgets:
    dataset_version: str
    model_manifest_sha256: str
    moonshine: StageBudget
    ecapa: StageBudget
    aasist: StageBudget


def load_budgets(path: Path) -> BenchmarkBudgets:
    value = json.loads(path.read_text(encoding="utf-8"))
    data = require_exact_object(
        value,
        "benchmark budgets",
        {
            "schemaVersion",
            "datasetVersion",
            "modelManifestSha256",
            "moonshine",
            "ecapa",
            "aasist",
        },
    )
    if data["schemaVersion"] != BUDGET_SCHEMA_VERSION:
        raise BenchmarkBudgetError(
            f"schemaVersion must be {BUDGET_SCHEMA_VERSION}"
        )
    return BenchmarkBudgets(
        dataset_version=require_string(data, "datasetVersion"),
        model_manifest_sha256=require_sha256(data, "modelManifestSha256"),
        moonshine=parse_stage_budget(data["moonshine"], "moonshine"),
        ecapa=parse_stage_budget(data["ecapa"], "ecapa"),
        aasist=parse_stage_budget(data["aasist"], "aasist"),
    )


def parse_stage_budget(value: object, field_name: str) -> StageBudget:
    data = require_exact_object(
        value,
        field_name,
        {
            "maximumP95LatencyMs",
            "maximumP99LatencyMs",
            "maximumErrorRate",
            "maximumRetryOrUncertaintyRate",
            "minimumAccuracy",
            "maximumPeakRssBytes",
        },
    )
    maximum_p95 = require_positive_number(data, "maximumP95LatencyMs")
    maximum_p99 = require_positive_number(data, "maximumP99LatencyMs")
    if maximum_p95 > maximum_p99:
        raise BenchmarkBudgetError(
            f"{field_name} p95 latency budget must not exceed p99"
        )
    return StageBudget(
        maximum_p95_latency_ms=maximum_p95,
        maximum_p99_latency_ms=maximum_p99,
        maximum_error_rate=require_probability(data, "maximumErrorRate"),
        maximum_retry_or_uncertainty_rate=require_probability(
            data,
            "maximumRetryOrUncertaintyRate",
        ),
        minimum_accuracy=require_probability(data, "minimumAccuracy"),
        maximum_peak_rss_bytes=require_positive_int(data, "maximumPeakRssBytes"),
    )


def check_benchmark_budgets(
    suite: dict[str, Any],
    budgets: BenchmarkBudgets,
) -> dict[str, Any]:
    if suite.get("schemaVersion") != "voice_id_benchmark_suite_v1":
        raise BenchmarkBudgetError("benchmark suite schemaVersion is invalid")
    violations = []
    compare_equal(
        violations,
        "datasetVersion",
        suite.get("datasetVersion"),
        budgets.dataset_version,
    )
    compare_equal(
        violations,
        "modelManifestSha256",
        suite.get("modelManifestSha256"),
        budgets.model_manifest_sha256,
    )
    inventory = require_report_object(suite, "inventory")
    if inventory.get("measurementReady") is not True:
        violations.append("inventory.measurementReady must be true")

    moonshine = require_report_object(suite, "moonshine")
    check_stage(
        violations=violations,
        name="moonshine",
        budget=budgets.moonshine,
        latency=require_report_object(
            require_report_object(moonshine, "stageLatencyMs"),
            "complete",
        ),
        error_rate=require_report_number(moonshine, "failureRate"),
        retry_or_uncertainty_rate=require_report_number(moonshine, "retryRate"),
        accuracy=require_report_number(moonshine, "hybridPhraseAccuracy"),
        peak_rss_bytes=require_report_number(
            require_report_object(moonshine, "resources"),
            "peakRssBytes",
        ),
    )

    ecapa = require_report_object(suite, "ecapa")
    ecapa_evaluation = require_report_object(ecapa, "evaluation")
    check_stage(
        violations=violations,
        name="ecapa",
        budget=budgets.ecapa,
        latency=require_report_object(ecapa, "latencyMs"),
        error_rate=require_report_number(
            require_report_object(ecapa_evaluation, "far"),
            "rate",
        ),
        retry_or_uncertainty_rate=require_report_number(
            require_report_object(ecapa_evaluation, "frr"),
            "rate",
        ),
        accuracy=1.0 - require_report_number(ecapa_evaluation, "eer"),
        peak_rss_bytes=require_report_number(ecapa, "peakRssBytes"),
    )

    aasist = require_report_object(
        require_report_object(suite, "aasist"),
        "evaluation",
    )
    if aasist.get("releaseReady") is not True:
        violations.append("aasist.releaseReady must be true")
    check_stage(
        violations=violations,
        name="aasist",
        budget=budgets.aasist,
        latency=require_report_object(aasist, "latencyMs"),
        error_rate=require_report_number(
            require_report_object(aasist, "apcer"),
            "rate",
        ),
        retry_or_uncertainty_rate=require_report_number(
            require_report_object(aasist, "uncertainty"),
            "rate",
        ),
        accuracy=1.0
        - require_report_number(require_report_object(aasist, "bpcer"), "rate"),
        peak_rss_bytes=require_report_number(aasist, "peakRssBytes"),
    )
    return {
        "schemaVersion": REPORT_SCHEMA_VERSION,
        "datasetVersion": budgets.dataset_version,
        "modelManifestSha256": budgets.model_manifest_sha256,
        "passed": len(violations) == 0,
        "violations": violations,
    }


def check_stage(
    *,
    violations: list[str],
    name: str,
    budget: StageBudget,
    latency: dict[str, Any],
    error_rate: float,
    retry_or_uncertainty_rate: float,
    accuracy: float,
    peak_rss_bytes: float,
) -> None:
    compare_maximum(
        violations,
        f"{name}.latencyMs.p95",
        require_report_number(latency, "p95"),
        budget.maximum_p95_latency_ms,
    )
    compare_maximum(
        violations,
        f"{name}.latencyMs.p99",
        require_report_number(latency, "p99"),
        budget.maximum_p99_latency_ms,
    )
    compare_maximum(
        violations,
        f"{name}.errorRate",
        error_rate,
        budget.maximum_error_rate,
    )
    compare_maximum(
        violations,
        f"{name}.retryOrUncertaintyRate",
        retry_or_uncertainty_rate,
        budget.maximum_retry_or_uncertainty_rate,
    )
    if accuracy < budget.minimum_accuracy:
        violations.append(
            f"{name}.accuracy {accuracy} is below {budget.minimum_accuracy}"
        )
    compare_maximum(
        violations,
        f"{name}.peakRssBytes",
        peak_rss_bytes,
        budget.maximum_peak_rss_bytes,
    )


def compare_equal(
    violations: list[str],
    field_name: str,
    actual: object,
    expected: object,
) -> None:
    if actual != expected:
        violations.append(f"{field_name} does not match the frozen budget")


def compare_maximum(
    violations: list[str],
    field_name: str,
    actual: float,
    maximum: float,
) -> None:
    if actual > maximum:
        violations.append(f"{field_name} {actual} exceeds {maximum}")


def require_exact_object(
    value: object,
    field_name: str,
    expected_keys: set[str],
) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value.keys()) != expected_keys:
        raise BenchmarkBudgetError(
            f"{field_name} contains unexpected or missing fields"
        )
    return value


def require_report_object(data: dict[str, Any], field_name: str) -> dict[str, Any]:
    value = data.get(field_name)
    if not isinstance(value, dict):
        raise BenchmarkBudgetError(f"benchmark report {field_name} must be an object")
    return value


def require_report_number(data: dict[str, Any], field_name: str) -> float:
    value = data.get(field_name)
    if not is_number(value):
        raise BenchmarkBudgetError(f"benchmark report {field_name} must be numeric")
    return float(value)


def require_string(data: dict[str, Any], field_name: str) -> str:
    value = data[field_name]
    if not isinstance(value, str) or value.strip() == "":
        raise BenchmarkBudgetError(f"{field_name} must be a non-empty string")
    return value.strip()


def require_sha256(data: dict[str, Any], field_name: str) -> str:
    value = require_string(data, field_name).lower()
    if len(value) != 64 or any(character not in "0123456789abcdef" for character in value):
        raise BenchmarkBudgetError(f"{field_name} must be a SHA-256 digest")
    return value


def require_positive_number(data: dict[str, Any], field_name: str) -> float:
    value = data[field_name]
    if not is_number(value) or value <= 0:
        raise BenchmarkBudgetError(f"{field_name} must be positive")
    return float(value)


def require_probability(data: dict[str, Any], field_name: str) -> float:
    value = data[field_name]
    if not is_number(value) or value < 0 or value > 1:
        raise BenchmarkBudgetError(f"{field_name} must be a probability")
    return float(value)


def require_positive_int(data: dict[str, Any], field_name: str) -> int:
    value = data[field_name]
    if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
        raise BenchmarkBudgetError(f"{field_name} must be a positive integer")
    return value


def is_number(value: object) -> bool:
    return isinstance(value, int | float) and not isinstance(value, bool)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Fail a VoiceID benchmark suite that exceeds frozen release budgets."
    )
    parser.add_argument("--suite", type=Path, required=True)
    parser.add_argument("--budgets", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    suite = json.loads(args.suite.read_text(encoding="utf-8"))
    if not isinstance(suite, dict):
        raise BenchmarkBudgetError("benchmark suite must be an object")
    report = check_benchmark_budgets(suite, load_budgets(args.budgets))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    if not report["passed"]:
        raise SystemExit("benchmark release budgets failed")


if __name__ == "__main__":
    main()
