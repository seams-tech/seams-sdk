from __future__ import annotations

import argparse
import json
from dataclasses import asdict, dataclass
from math import sqrt
from pathlib import Path
from typing import Any, Literal


SCHEMA_VERSION = "voice_id_pad_evaluation_v2"
ATTACK_CLASSES = frozenset(
    {"replay", "synthesis", "voice_conversion", "splice", "relay", "digital_injection"}
)


class PadEvaluationError(ValueError):
    pass


@dataclass(frozen=True)
class PadEvaluationEntry:
    fixture_id: str
    subject_id: str
    session_id: str
    partition: Literal["calibration", "evaluation"]
    presentation: Literal["bona_fide", "attack"]
    attack_class: str | None
    capture_profile: str
    pad_score: float
    latency_ms: float


@dataclass(frozen=True)
class PadEvaluationManifest:
    dataset_manifest_version: str
    model_version: str
    pad_calibration_version: str
    reject_threshold: float
    accept_threshold: float
    entries: tuple[PadEvaluationEntry, ...]


@dataclass(frozen=True)
class RateEstimate:
    errors: int
    trials: int
    rate: float
    confidence_low: float
    confidence_high: float


@dataclass(frozen=True)
class LatencySummary:
    p50: float
    p95: float
    p99: float


@dataclass(frozen=True)
class PadEvaluationReport:
    schema_version: str
    dataset_manifest_version: str
    model_version: str
    pad_calibration_version: str
    reject_threshold: float
    accept_threshold: float
    calibration_fixture_count: int
    evaluation_fixture_count: int
    latency_ms: LatencySummary
    bpcer: RateEstimate
    apcer: RateEstimate
    uncertainty: RateEstimate
    apcer_by_attack_class: dict[str, RateEstimate]
    apcer_by_capture_profile: dict[str, RateEstimate]
    missing_attack_classes: tuple[str, ...]
    release_ready: bool


def load_pad_manifest(path: Path) -> PadEvaluationManifest:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise PadEvaluationError(f"failed to read PAD manifest: {exc}") from exc
    return parse_pad_manifest(value)


def parse_pad_manifest(value: object) -> PadEvaluationManifest:
    data = require_exact_object(
        value,
        "PAD manifest",
        {
            "schemaVersion",
            "datasetManifestVersion",
            "modelVersion",
            "padCalibrationVersion",
            "rejectThreshold",
            "acceptThreshold",
            "entries",
        },
    )
    if require_string(data, "schemaVersion") != SCHEMA_VERSION:
        raise PadEvaluationError(f"schemaVersion must be {SCHEMA_VERSION}")
    reject_threshold = require_probability(data, "rejectThreshold")
    accept_threshold = require_probability(data, "acceptThreshold")
    if reject_threshold > accept_threshold:
        raise PadEvaluationError("rejectThreshold must be less than or equal to acceptThreshold")
    raw_entries = data["entries"]
    if not isinstance(raw_entries, list) or len(raw_entries) == 0:
        raise PadEvaluationError("entries must be a non-empty array")
    entries = tuple(parse_pad_entry(item, index) for index, item in enumerate(raw_entries))
    assert_subject_disjoint_partitions(entries)
    return PadEvaluationManifest(
        dataset_manifest_version=require_string(data, "datasetManifestVersion"),
        model_version=require_string(data, "modelVersion"),
        pad_calibration_version=require_string(data, "padCalibrationVersion"),
        reject_threshold=reject_threshold,
        accept_threshold=accept_threshold,
        entries=entries,
    )


def parse_pad_entry(value: object, index: int) -> PadEvaluationEntry:
    field_name = f"entries[{index}]"
    data = require_exact_object(
        value,
        field_name,
        {
            "fixtureId",
            "subjectId",
            "sessionId",
            "partition",
            "presentation",
            "attackClass",
            "captureProfile",
            "padScore",
            "latencyMs",
        },
    )
    partition = require_one_of(data, "partition", {"calibration", "evaluation"})
    presentation = require_one_of(data, "presentation", {"bona_fide", "attack"})
    attack_class = parse_attack_class(data["attackClass"], presentation, field_name)
    return PadEvaluationEntry(
        fixture_id=require_string(data, "fixtureId"),
        subject_id=require_string(data, "subjectId"),
        session_id=require_string(data, "sessionId"),
        partition=partition,
        presentation=presentation,
        attack_class=attack_class,
        capture_profile=require_string(data, "captureProfile"),
        pad_score=require_probability(data, "padScore"),
        latency_ms=require_non_negative_number(data, "latencyMs"),
    )


def parse_attack_class(
    value: object,
    presentation: str,
    field_name: str,
) -> str | None:
    if presentation == "bona_fide":
        if value is not None:
            raise PadEvaluationError(f"{field_name}.attackClass must be null for bona_fide audio")
        return None
    if not isinstance(value, str) or value not in ATTACK_CLASSES:
        raise PadEvaluationError(f"{field_name}.attackClass is invalid")
    return value


def assert_subject_disjoint_partitions(entries: tuple[PadEvaluationEntry, ...]) -> None:
    calibration_subjects = {entry.subject_id for entry in entries if entry.partition == "calibration"}
    evaluation_subjects = {entry.subject_id for entry in entries if entry.partition == "evaluation"}
    overlap = calibration_subjects & evaluation_subjects
    if len(overlap) > 0:
        raise PadEvaluationError("calibration and evaluation subjects must be disjoint")


def evaluate_pad(manifest: PadEvaluationManifest) -> PadEvaluationReport:
    entries = tuple(entry for entry in manifest.entries if entry.partition == "evaluation")
    bona_fide = tuple(entry for entry in entries if entry.presentation == "bona_fide")
    attacks = tuple(entry for entry in entries if entry.presentation == "attack")
    if len(bona_fide) == 0 or len(attacks) == 0:
        raise PadEvaluationError("evaluation partition requires bona_fide and attack entries")

    bpcer = rate_estimate(
        sum(classify(entry, manifest) != "accepted" for entry in bona_fide),
        len(bona_fide),
    )
    apcer = rate_estimate(
        sum(classify(entry, manifest) == "accepted" for entry in attacks),
        len(attacks),
    )
    uncertainty = rate_estimate(
        sum(classify(entry, manifest) == "uncertain" for entry in entries),
        len(entries),
    )
    apcer_by_attack_class = grouped_apcer(attacks, group_by="attack_class", manifest=manifest)
    apcer_by_capture_profile = grouped_apcer(attacks, group_by="capture_profile", manifest=manifest)
    missing_attack_classes = tuple(sorted(ATTACK_CLASSES - set(apcer_by_attack_class)))
    return PadEvaluationReport(
        schema_version="voice_id_pad_report_v1",
        dataset_manifest_version=manifest.dataset_manifest_version,
        model_version=manifest.model_version,
        pad_calibration_version=manifest.pad_calibration_version,
        reject_threshold=manifest.reject_threshold,
        accept_threshold=manifest.accept_threshold,
        calibration_fixture_count=sum(
            entry.partition == "calibration" for entry in manifest.entries
        ),
        evaluation_fixture_count=len(entries),
        latency_ms=latency_summary([entry.latency_ms for entry in entries]),
        bpcer=bpcer,
        apcer=apcer,
        uncertainty=uncertainty,
        apcer_by_attack_class=apcer_by_attack_class,
        apcer_by_capture_profile=apcer_by_capture_profile,
        missing_attack_classes=missing_attack_classes,
        release_ready=len(missing_attack_classes) == 0,
    )


def calibrate_pad_thresholds(
    entries: tuple[PadEvaluationEntry, ...],
    *,
    target_apcer: float,
    target_bpcer: float,
) -> tuple[float, float]:
    if not 0 <= target_apcer <= 1 or not 0 <= target_bpcer <= 1:
        raise PadEvaluationError("calibration targets must be probabilities")
    calibration = tuple(entry for entry in entries if entry.partition == "calibration")
    bona_fide = tuple(
        entry for entry in calibration if entry.presentation == "bona_fide"
    )
    attacks = tuple(entry for entry in calibration if entry.presentation == "attack")
    if len(bona_fide) == 0 or len(attacks) == 0:
        raise PadEvaluationError(
            "calibration partition requires bona_fide and attack entries"
        )
    candidates = []
    for reject_percent in range(0, 100):
        reject_threshold = reject_percent / 100
        for accept_percent in range(reject_percent + 1, 101):
            accept_threshold = accept_percent / 100
            attack_acceptance = sum(
                classify_score(
                    entry.pad_score,
                    reject_threshold=reject_threshold,
                    accept_threshold=accept_threshold,
                )
                == "accepted"
                for entry in attacks
            ) / len(attacks)
            bona_fide_error = sum(
                classify_score(
                    entry.pad_score,
                    reject_threshold=reject_threshold,
                    accept_threshold=accept_threshold,
                )
                != "accepted"
                for entry in bona_fide
            ) / len(bona_fide)
            uncertainty = sum(
                classify_score(
                    entry.pad_score,
                    reject_threshold=reject_threshold,
                    accept_threshold=accept_threshold,
                )
                == "uncertain"
                for entry in calibration
            ) / len(calibration)
            feasible = (
                attack_acceptance <= target_apcer
                and bona_fide_error <= target_bpcer
            )
            candidates.append(
                (
                    (
                        0 if feasible else 1,
                        max(
                            attack_acceptance - target_apcer,
                            bona_fide_error - target_bpcer,
                            0,
                        ),
                        attack_acceptance + bona_fide_error,
                        uncertainty,
                        accept_threshold - reject_threshold,
                    ),
                    reject_threshold,
                    accept_threshold,
                )
            )
    _, reject_threshold, accept_threshold = min(candidates)
    return reject_threshold, accept_threshold


def classify(
    entry: PadEvaluationEntry,
    manifest: PadEvaluationManifest,
) -> Literal["accepted", "uncertain", "rejected"]:
    return classify_score(
        entry.pad_score,
        reject_threshold=manifest.reject_threshold,
        accept_threshold=manifest.accept_threshold,
    )


def classify_score(
    score: float,
    *,
    reject_threshold: float,
    accept_threshold: float,
) -> Literal["accepted", "uncertain", "rejected"]:
    if score >= accept_threshold:
        return "accepted"
    if score <= reject_threshold:
        return "rejected"
    return "uncertain"


def grouped_apcer(
    entries: tuple[PadEvaluationEntry, ...],
    *,
    group_by: Literal["attack_class", "capture_profile"],
    manifest: PadEvaluationManifest,
) -> dict[str, RateEstimate]:
    groups: dict[str, list[PadEvaluationEntry]] = {}
    for entry in entries:
        key = entry.attack_class if group_by == "attack_class" else entry.capture_profile
        if key is None:
            raise PadEvaluationError("attack entries require an attack class")
        groups.setdefault(key, []).append(entry)
    return {
        key: rate_estimate(
            sum(classify(entry, manifest) == "accepted" for entry in group_entries),
            len(group_entries),
        )
        for key, group_entries in sorted(groups.items())
    }


def rate_estimate(errors: int, trials: int) -> RateEstimate:
    if trials <= 0 or errors < 0 or errors > trials:
        raise PadEvaluationError("rate estimate counts are invalid")
    rate = errors / trials
    low, high = wilson_interval(errors, trials)
    return RateEstimate(
        errors=errors,
        trials=trials,
        rate=rate,
        confidence_low=low,
        confidence_high=high,
    )


def latency_summary(values: list[float]) -> LatencySummary:
    if len(values) == 0:
        raise PadEvaluationError("latency summary requires observations")
    ordered = sorted(values)
    return LatencySummary(
        p50=round(percentile(ordered, 0.50), 3),
        p95=round(percentile(ordered, 0.95), 3),
        p99=round(percentile(ordered, 0.99), 3),
    )


def percentile(values: list[float], quantile: float) -> float:
    if len(values) == 1:
        return values[0]
    position = (len(values) - 1) * quantile
    lower = int(position)
    upper = min(lower + 1, len(values) - 1)
    fraction = position - lower
    return values[lower] + (values[upper] - values[lower]) * fraction


def wilson_interval(errors: int, trials: int, z_score: float = 1.959963984540054) -> tuple[float, float]:
    rate = errors / trials
    denominator = 1 + z_score * z_score / trials
    center = (rate + z_score * z_score / (2 * trials)) / denominator
    margin = z_score * sqrt(rate * (1 - rate) / trials + z_score * z_score / (4 * trials * trials)) / denominator
    return max(0.0, center - margin), min(1.0, center + margin)


def report_to_json(report: PadEvaluationReport) -> dict[str, Any]:
    return {
        "schemaVersion": report.schema_version,
        "datasetManifestVersion": report.dataset_manifest_version,
        "modelVersion": report.model_version,
        "padCalibrationVersion": report.pad_calibration_version,
        "rejectThreshold": report.reject_threshold,
        "acceptThreshold": report.accept_threshold,
        "calibrationFixtureCount": report.calibration_fixture_count,
        "evaluationFixtureCount": report.evaluation_fixture_count,
        "latencyMs": asdict(report.latency_ms),
        "bpcer": asdict(report.bpcer),
        "apcer": asdict(report.apcer),
        "uncertainty": asdict(report.uncertainty),
        "apcerByAttackClass": {
            key: asdict(value)
            for key, value in report.apcer_by_attack_class.items()
        },
        "apcerByCaptureProfile": {
            key: asdict(value)
            for key, value in report.apcer_by_capture_profile.items()
        },
        "missingAttackClasses": list(report.missing_attack_classes),
        "releaseReady": report.release_ready,
    }


def require_exact_object(value: object, field_name: str, expected_keys: set[str]) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value.keys()) != expected_keys:
        raise PadEvaluationError(f"{field_name} contains unexpected or missing fields")
    return value


def require_string(data: dict[str, Any], field_name: str) -> str:
    value = data[field_name]
    if not isinstance(value, str) or len(value.strip()) == 0:
        raise PadEvaluationError(f"{field_name} must be a non-empty string")
    return value.strip()


def require_probability(data: dict[str, Any], field_name: str) -> float:
    value = data[field_name]
    if not is_number(value) or value < 0 or value > 1:
        raise PadEvaluationError(f"{field_name} must be between zero and one")
    return float(value)


def require_non_negative_number(data: dict[str, Any], field_name: str) -> float:
    value = data[field_name]
    if not is_number(value) or value < 0:
        raise PadEvaluationError(f"{field_name} must be non-negative")
    return float(value)


def require_one_of(data: dict[str, Any], field_name: str, allowed: set[str]) -> Any:
    value = data[field_name]
    if not isinstance(value, str) or value not in allowed:
        raise PadEvaluationError(f"{field_name} is invalid")
    return value


def is_number(value: object) -> bool:
    return isinstance(value, int | float) and not isinstance(value, bool)


def main() -> None:
    parser = argparse.ArgumentParser(description="Evaluate frozen VoiceID PAD scores by attack class.")
    parser.add_argument("--manifest", type=Path, required=True)
    args = parser.parse_args()
    report = evaluate_pad(load_pad_manifest(args.manifest))
    print(json.dumps(report_to_json(report), indent=2))


if __name__ == "__main__":
    main()
