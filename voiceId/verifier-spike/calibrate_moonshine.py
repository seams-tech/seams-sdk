from __future__ import annotations

import argparse
import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal


REPORT_SCHEMA_VERSION = "voice_id_moonshine_benchmark_v2"
CALIBRATION_SCHEMA_VERSION = "voice_id_moonshine_calibration_v1"
MODEL_ARTIFACT_BY_ARCH = {
    "tiny_streaming": "moonshine-streaming-tiny-native-quantized",
    "small_streaming": "moonshine-streaming-small-native-quantized",
}


class MoonshineCalibrationError(ValueError):
    pass


@dataclass(frozen=True)
class IntentObservation:
    fixture_id: str
    partition: str
    expected_kind: Literal["accepted", "uncertain"]
    expected_intent: str
    matched_intent: str | None
    confidence: float
    runner_up_confidence: float


@dataclass(frozen=True)
class Candidate:
    path: Path
    model_arch: str
    complete_p95_ms: float
    peak_rss_bytes: int
    observations: tuple[IntentObservation, ...]


@dataclass(frozen=True)
class CalibrationPoint:
    threshold: float
    margin: float
    accuracy: float
    unauthorized_acceptance_rate: float
    retry_rate: float


def calibrate_candidates(
    candidates: tuple[Candidate, ...],
    *,
    maximum_complete_p95_ms: float,
    maximum_peak_rss_bytes: int,
) -> tuple[Candidate, CalibrationPoint, CalibrationPoint]:
    eligible = tuple(
        candidate
        for candidate in candidates
        if candidate.complete_p95_ms <= maximum_complete_p95_ms
        and candidate.peak_rss_bytes <= maximum_peak_rss_bytes
    )
    if len(eligible) == 0:
        raise MoonshineCalibrationError("no candidate meets the runtime budgets")
    evaluated = []
    for candidate in eligible:
        calibration = select_calibration_point(candidate.observations)
        evaluation = evaluate_point(
            tuple(
                observation
                for observation in candidate.observations
                if observation.partition == "evaluation"
            ),
            threshold=calibration.threshold,
            margin=calibration.margin,
        )
        evaluated.append((candidate, calibration, evaluation))
    return min(
        evaluated,
        key=lambda item: (
            -item[2].accuracy,
            item[2].unauthorized_acceptance_rate,
            item[2].retry_rate,
            item[0].complete_p95_ms,
            item[0].peak_rss_bytes,
        ),
    )


def select_calibration_point(
    observations: tuple[IntentObservation, ...],
) -> CalibrationPoint:
    calibration = tuple(
        observation
        for observation in observations
        if observation.partition == "calibration"
    )
    if len(calibration) == 0:
        raise MoonshineCalibrationError("candidate requires calibration observations")
    points = tuple(
        evaluate_point(calibration, threshold=threshold, margin=margin)
        for threshold in threshold_grid()
        for margin in margin_grid()
    )
    return min(
        points,
        key=lambda point: (
            -point.accuracy,
            point.unauthorized_acceptance_rate,
            point.retry_rate,
            point.threshold,
            point.margin,
        ),
    )


def evaluate_point(
    observations: tuple[IntentObservation, ...],
    *,
    threshold: float,
    margin: float,
) -> CalibrationPoint:
    if len(observations) == 0:
        raise MoonshineCalibrationError("evaluation requires observations")
    decisions = tuple(
        classify_observation(
            observation,
            threshold=threshold,
            margin=margin,
        )
        for observation in observations
    )
    correct = sum(
        decision == observation.expected_kind
        for decision, observation in zip(decisions, observations, strict=True)
    )
    negative_count = sum(
        observation.expected_kind != "accepted" for observation in observations
    )
    unauthorized_acceptances = sum(
        decision == "accepted" and observation.expected_kind != "accepted"
        for decision, observation in zip(decisions, observations, strict=True)
    )
    retries = sum(decision == "uncertain" for decision in decisions)
    return CalibrationPoint(
        threshold=threshold,
        margin=margin,
        accuracy=round(correct / len(observations), 6),
        unauthorized_acceptance_rate=round(
            unauthorized_acceptances / negative_count if negative_count > 0 else 0.0,
            6,
        ),
        retry_rate=round(retries / len(observations), 6),
    )


def classify_observation(
    observation: IntentObservation,
    *,
    threshold: float,
    margin: float,
) -> Literal["accepted", "uncertain", "rejected"]:
    if (
        observation.confidence < threshold
        or observation.confidence - observation.runner_up_confidence < margin
    ):
        return "uncertain"
    if observation.matched_intent == observation.expected_intent:
        return "accepted"
    return "rejected"


def load_candidate(path: Path) -> Candidate:
    resolved = path.expanduser().resolve()
    value = read_object(resolved)
    if value.get("schemaVersion") != REPORT_SCHEMA_VERSION:
        raise MoonshineCalibrationError(f"{path} is not a Moonshine v2 benchmark report")
    model_arch = require_string(value, "modelArch")
    if model_arch not in MODEL_ARTIFACT_BY_ARCH:
        raise MoonshineCalibrationError("benchmark modelArch is invalid")
    stage_latency = require_object(value.get("stageLatencyMs"), "stageLatencyMs")
    complete = require_object(stage_latency.get("complete"), "stageLatencyMs.complete")
    resources = require_object(value.get("resources"), "resources")
    raw_results = value.get("results")
    if not isinstance(raw_results, list) or len(raw_results) == 0:
        raise MoonshineCalibrationError("benchmark results must be non-empty")
    observations = tuple(parse_observation(result) for result in raw_results)
    partitions = {observation.partition for observation in observations}
    if not {"calibration", "evaluation"}.issubset(partitions):
        raise MoonshineCalibrationError(
            "benchmark requires calibration and evaluation observations"
        )
    return Candidate(
        path=resolved,
        model_arch=model_arch,
        complete_p95_ms=require_non_negative_number(complete, "p95"),
        peak_rss_bytes=require_non_negative_int(resources, "peakRssBytes"),
        observations=observations,
    )


def parse_observation(value: object) -> IntentObservation:
    data = require_object(value, "benchmark result")
    partition = require_string(data, "partition")
    if partition not in {"development", "calibration", "evaluation"}:
        raise MoonshineCalibrationError("benchmark result partition is invalid")
    challenge_error_kind = data.get("challengeErrorKind")
    expected_kind: Literal["accepted", "uncertain"] = (
        "uncertain" if challenge_error_kind == "ambiguous" else "accepted"
    )
    matched_intent = data.get("matchedIntent")
    if matched_intent is not None and not isinstance(matched_intent, str):
        raise MoonshineCalibrationError("matchedIntent must be a string or null")
    return IntentObservation(
        fixture_id=require_string(data, "fixtureId"),
        partition=partition,
        expected_kind=expected_kind,
        expected_intent=require_string(data, "expectedIntent"),
        matched_intent=matched_intent,
        confidence=require_probability(data, "intentConfidence"),
        runner_up_confidence=require_probability(data, "runnerUpConfidence"),
    )


def build_calibration_manifest(
    *,
    selected: Candidate,
    calibration: CalibrationPoint,
    evaluation: CalibrationPoint,
    model_manifest_path: Path,
    maximum_complete_p95_ms: float,
    maximum_peak_rss_bytes: int,
) -> dict[str, Any]:
    model_manifest = read_object(model_manifest_path.expanduser().resolve())
    artifact_id = MODEL_ARTIFACT_BY_ARCH[selected.model_arch]
    artifact = find_artifact(model_manifest, artifact_id)
    return {
        "schemaVersion": CALIBRATION_SCHEMA_VERSION,
        "modelArch": selected.model_arch,
        "modelArtifact": artifact,
        "modelManifestSha256": sha256_file(model_manifest_path),
        "benchmarkReportSha256": sha256_file(selected.path),
        "intentThreshold": calibration.threshold,
        "intentMargin": calibration.margin,
        "normalization": "lowercase_ascii_alphanumeric_tokens_v1",
        "challengePolicy": "all_unpredictable_tokens_any_order_v1",
        "calibration": point_to_json(calibration),
        "evaluation": point_to_json(evaluation),
        "runtimeBudgets": {
            "maximumCompleteP95Ms": maximum_complete_p95_ms,
            "maximumPeakRssBytes": maximum_peak_rss_bytes,
            "observedCompleteP95Ms": selected.complete_p95_ms,
            "observedPeakRssBytes": selected.peak_rss_bytes,
        },
    }


def find_artifact(model_manifest: dict[str, Any], artifact_id: str) -> dict[str, Any]:
    artifacts = model_manifest.get("artifacts")
    if not isinstance(artifacts, list):
        raise MoonshineCalibrationError("model manifest artifacts must be an array")
    for artifact in artifacts:
        if isinstance(artifact, dict) and artifact.get("id") == artifact_id:
            return {
                "id": artifact_id,
                "revision": require_string(artifact, "revision"),
                "treeSha256": require_string(artifact, "treeSha256"),
                "downloadedBytes": require_non_negative_int(artifact, "downloadedBytes"),
                "license": require_string(artifact, "license"),
            }
    raise MoonshineCalibrationError(f"model artifact is missing: {artifact_id}")


def threshold_grid() -> tuple[float, ...]:
    return tuple(round(value / 100, 2) for value in range(50, 96, 5))


def margin_grid() -> tuple[float, ...]:
    return tuple(round(value / 100, 2) for value in range(0, 31, 5))


def point_to_json(point: CalibrationPoint) -> dict[str, Any]:
    return {
        "threshold": point.threshold,
        "margin": point.margin,
        "accuracy": point.accuracy,
        "unauthorizedAcceptanceRate": point.unauthorized_acceptance_rate,
        "retryRate": point.retry_rate,
    }


def read_object(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise MoonshineCalibrationError(f"failed to read {path}: {exc}") from exc
    return require_object(value, str(path))


def require_object(value: object, field_name: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise MoonshineCalibrationError(f"{field_name} must be an object")
    return value


def require_string(data: dict[str, Any], field_name: str) -> str:
    value = data.get(field_name)
    if not isinstance(value, str) or value.strip() == "":
        raise MoonshineCalibrationError(f"{field_name} must be a non-empty string")
    return value.strip()


def require_non_negative_number(data: dict[str, Any], field_name: str) -> float:
    value = data.get(field_name)
    if not isinstance(value, int | float) or isinstance(value, bool) or value < 0:
        raise MoonshineCalibrationError(f"{field_name} must be non-negative")
    return float(value)


def require_non_negative_int(data: dict[str, Any], field_name: str) -> int:
    value = data.get(field_name)
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise MoonshineCalibrationError(f"{field_name} must be a non-negative integer")
    return value


def require_probability(data: dict[str, Any], field_name: str) -> float:
    value = require_non_negative_number(data, field_name)
    if value > 1:
        raise MoonshineCalibrationError(f"{field_name} must be a probability")
    return value


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.expanduser().resolve().read_bytes()).hexdigest()


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Calibrate Moonshine intent threshold/margin and select a runtime candidate."
    )
    parser.add_argument("--candidate-report", type=Path, action="append", required=True)
    parser.add_argument("--model-manifest", type=Path, required=True)
    parser.add_argument("--maximum-complete-p95-ms", type=float, default=1_000)
    parser.add_argument("--maximum-peak-rss-bytes", type=int, default=1_073_741_824)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    selected, calibration, evaluation = calibrate_candidates(
        tuple(load_candidate(path) for path in args.candidate_report),
        maximum_complete_p95_ms=args.maximum_complete_p95_ms,
        maximum_peak_rss_bytes=args.maximum_peak_rss_bytes,
    )
    manifest = build_calibration_manifest(
        selected=selected,
        calibration=calibration,
        evaluation=evaluation,
        model_manifest_path=args.model_manifest,
        maximum_complete_p95_ms=args.maximum_complete_p95_ms,
        maximum_peak_rss_bytes=args.maximum_peak_rss_bytes,
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
