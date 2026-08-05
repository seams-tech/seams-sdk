from __future__ import annotations

import argparse
import hashlib
import json
from datetime import datetime
from pathlib import Path
from typing import Any

from benchmark import load_benchmark_manifest


SCHEMA_VERSION = "voice_id_calibration_record_v1"
SUITE_SCHEMA_VERSION = "voice_id_benchmark_suite_v1"
BUDGET_CHECK_SCHEMA_VERSION = "voice_id_benchmark_budget_check_v1"


class CalibrationFreezeError(ValueError):
    pass


def freeze_calibration(
    *,
    corpus_manifest_path: Path,
    suite_path: Path,
    budgets_path: Path,
    budget_check_path: Path,
    model_manifest_path: Path,
    output_path: Path,
    created_at: str,
) -> dict[str, Any]:
    require_iso_date_time(created_at)
    corpus_path = corpus_manifest_path.expanduser().resolve()
    suite_file = suite_path.expanduser().resolve()
    budgets_file = budgets_path.expanduser().resolve()
    budget_check_file = budget_check_path.expanduser().resolve()
    model_file = model_manifest_path.expanduser().resolve()
    corpus = load_benchmark_manifest(corpus_path)
    suite = read_object(suite_file, "benchmark suite")
    model_hash = sha256_file(model_file)
    require_suite(suite, corpus, corpus_path, model_hash)
    budgets = read_object(budgets_file, "benchmark budgets")
    budget_check = read_object(budget_check_file, "budget check")
    model_manifest = read_object(model_file, "model manifest")
    require_budget_inputs(budgets, corpus.dataset_version, model_hash)
    require_budget_check(budget_check, corpus.dataset_version, model_hash)
    calibration = {
        "schemaVersion": SCHEMA_VERSION,
        "createdAt": created_at,
        "datasetVersion": corpus.dataset_version,
        "corpusManifestSha256": sha256_file(corpus_path),
        "modelManifestSha256": model_hash,
        "benchmarkSuiteSha256": sha256_file(suite_file),
        "budgetManifestSha256": sha256_file(budgets_file),
        "budgetCheckSha256": sha256_file(budget_check_file),
        "modelArtifacts": model_artifact_ids(model_manifest),
        "intent": {
            "modelArch": require_string(suite["moonshine"], "modelArch"),
            "threshold": require_probability(suite["moonshine"], "intentThreshold"),
            "margin": require_probability(suite["moonshine"], "intentMargin"),
            "challengePolicy": "all_unpredictable_tokens_any_order_v1",
        },
        "speaker": {
            "modelVersion": require_string(suite["ecapa"], "modelVersion"),
            "threshold": require_probability(suite["ecapa"], "threshold"),
        },
        "pad": pad_calibration(suite),
        "captureProfiles": capture_profiles(corpus),
        "retryPolicy": {
            "maximumQualityRetries": 1,
            "afterRetry": "alternate_authentication_method",
            "outsideCalibration": "uncertain",
        },
        "releaseBudget": {
            "schemaVersion": BUDGET_CHECK_SCHEMA_VERSION,
            "passed": True,
            "datasetVersion": corpus.dataset_version,
            "modelManifestSha256": model_hash,
        },
    }
    write_json(output_path.expanduser().resolve(), calibration)
    return calibration


def require_suite(
    suite: dict[str, Any], corpus: Any, corpus_path: Path, model_hash: str
) -> None:
    if suite.get("schemaVersion") != SUITE_SCHEMA_VERSION:
        raise CalibrationFreezeError("benchmark suite schemaVersion is invalid")
    if suite.get("datasetVersion") != corpus.dataset_version:
        raise CalibrationFreezeError("benchmark suite dataset does not match corpus")
    if suite.get("corpusManifestSha256") != sha256_file(corpus_path):
        raise CalibrationFreezeError("benchmark suite corpus binding does not match corpus")
    if suite.get("modelManifestSha256") != model_hash:
        raise CalibrationFreezeError("benchmark suite model binding does not match model manifest")
    inventory = suite.get("inventory")
    if not isinstance(inventory, dict) or inventory.get("measurementReady") is not True:
        raise CalibrationFreezeError("benchmark suite inventory is not measurement-ready")
    for field_name in ("moonshine", "ecapa", "aasist"):
        if not isinstance(suite.get(field_name), dict):
            raise CalibrationFreezeError(f"benchmark suite {field_name} report is missing")


def require_budget_inputs(
    budgets: dict[str, Any], dataset_version: str, model_hash: str
) -> None:
    if budgets.get("schemaVersion") != "voice_id_benchmark_budgets_v1":
        raise CalibrationFreezeError("benchmark budget schemaVersion is invalid")
    if budgets.get("datasetVersion") != dataset_version:
        raise CalibrationFreezeError("benchmark budgets dataset does not match corpus")
    if budgets.get("modelManifestSha256") != model_hash:
        raise CalibrationFreezeError("benchmark budgets model binding does not match model manifest")
    for name in ("moonshine", "ecapa", "aasist"):
        if not isinstance(budgets.get(name), dict):
            raise CalibrationFreezeError(f"benchmark budget {name} is missing")


def require_budget_check(
    report: dict[str, Any], dataset_version: str, model_hash: str
) -> None:
    if report.get("schemaVersion") != BUDGET_CHECK_SCHEMA_VERSION:
        raise CalibrationFreezeError("budget check schemaVersion is invalid")
    if report.get("datasetVersion") != dataset_version:
        raise CalibrationFreezeError("budget check dataset does not match corpus")
    if report.get("modelManifestSha256") != model_hash:
        raise CalibrationFreezeError("budget check model binding does not match model manifest")
    if report.get("passed") is not True or report.get("violations") != []:
        raise CalibrationFreezeError("release budget check has not passed")


def pad_calibration(suite: dict[str, Any]) -> dict[str, Any]:
    aasist = suite["aasist"]
    raw = aasist.get("raw")
    evaluation = aasist.get("evaluation")
    if not isinstance(raw, dict) or not isinstance(evaluation, dict):
        raise CalibrationFreezeError("AASIST raw and evaluation reports are required")
    return {
        "modelVersion": require_string(raw, "modelVersion"),
        "calibrationVersion": require_string(evaluation, "padCalibrationVersion"),
        "rejectThreshold": require_probability(raw, "rejectThreshold"),
        "acceptThreshold": require_probability(raw, "acceptThreshold"),
        "targetApcer": require_probability(raw, "targetApcer"),
        "targetBpcer": require_probability(raw, "targetBpcer"),
    }


def capture_profiles(corpus: Any) -> list[str]:
    return sorted(
        {
            "|".join(
                (
                    entry.capture.platform,
                    entry.capture.microphone,
                    entry.capture.room,
                    str(entry.capture.distance_cm),
                    entry.capture.codec,
                    str(entry.capture.sample_rate_hz),
                    str(entry.capture.channel_count),
                    entry.capture.language,
                    entry.capture.accent,
                    entry.capture.noise_profile,
                )
            )
            for entry in corpus.entries
        }
    )


def model_artifact_ids(model_manifest: dict[str, Any]) -> list[str]:
    artifacts = model_manifest.get("artifacts")
    if not isinstance(artifacts, list) or len(artifacts) == 0:
        raise CalibrationFreezeError("model manifest artifacts are missing")
    identifiers = []
    for artifact in artifacts:
        if not isinstance(artifact, dict) or not isinstance(artifact.get("id"), str):
            raise CalibrationFreezeError("model manifest artifact id is invalid")
        identifiers.append(artifact["id"])
    return sorted(identifiers)


def read_object(path: Path, label: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise CalibrationFreezeError(f"failed to read {label}: {error}") from error
    if not isinstance(value, dict):
        raise CalibrationFreezeError(f"{label} must be an object")
    return value


def require_string(data: dict[str, Any], field_name: str) -> str:
    value = data.get(field_name)
    if not isinstance(value, str) or value.strip() == "":
        raise CalibrationFreezeError(f"{field_name} must be a non-empty string")
    return value


def require_probability(data: dict[str, Any], field_name: str) -> float:
    value = data.get(field_name)
    if not isinstance(value, int | float) or isinstance(value, bool) or not 0 <= value <= 1:
        raise CalibrationFreezeError(f"{field_name} must be a probability")
    return float(value)


def require_iso_date_time(value: str) -> None:
    normalized = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError as error:
        raise CalibrationFreezeError("created_at must be an ISO date-time") from error
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise CalibrationFreezeError("created_at must include a UTC offset")


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write_json(path: Path, value: object) -> None:
    encoded = (json.dumps(value, indent=2) + "\n").encode("utf-8")
    if path.exists():
        if path.is_file() and path.read_bytes() == encoded:
            return
        raise CalibrationFreezeError(f"immutable calibration output collision: {path.name}")
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("xb") as output:
        output.write(encoded)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Freeze one VoiceID calibration record from a passing benchmark suite."
    )
    parser.add_argument("--corpus-manifest", type=Path, required=True)
    parser.add_argument("--suite", type=Path, required=True)
    parser.add_argument("--budgets", type=Path, required=True)
    parser.add_argument("--budget-check", type=Path, required=True)
    parser.add_argument("--model-manifest", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--created-at", required=True)
    args = parser.parse_args()
    freeze_calibration(
        corpus_manifest_path=args.corpus_manifest,
        suite_path=args.suite,
        budgets_path=args.budgets,
        budget_check_path=args.budget_check,
        model_manifest_path=args.model_manifest,
        output_path=args.output,
        created_at=args.created_at,
    )


if __name__ == "__main__":
    main()
