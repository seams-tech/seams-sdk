from __future__ import annotations

import argparse
import json
from dataclasses import asdict, dataclass
from math import sqrt
from pathlib import Path
from typing import Any, Literal


SCHEMA_VERSION = "voice_id_pad_evaluation_v1"
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
    partition: Literal["development", "evaluation"]
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
class PadEvaluationReport:
    schema_version: str
    dataset_manifest_version: str
    model_version: str
    pad_calibration_version: str
    reject_threshold: float
    accept_threshold: float
    evaluation_fixture_count: int
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
    partition = require_one_of(data, "partition", {"development", "evaluation"})
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
    development_subjects = {entry.subject_id for entry in entries if entry.partition == "development"}
    evaluation_subjects = {entry.subject_id for entry in entries if entry.partition == "evaluation"}
    overlap = development_subjects & evaluation_subjects
    if len(overlap) > 0:
        raise PadEvaluationError("development and evaluation subjects must be disjoint")


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
        evaluation_fixture_count=len(entries),
        bpcer=bpcer,
        apcer=apcer,
        uncertainty=uncertainty,
        apcer_by_attack_class=apcer_by_attack_class,
        apcer_by_capture_profile=apcer_by_capture_profile,
        missing_attack_classes=missing_attack_classes,
        release_ready=len(missing_attack_classes) == 0,
    )


def classify(
    entry: PadEvaluationEntry,
    manifest: PadEvaluationManifest,
) -> Literal["accepted", "uncertain", "rejected"]:
    if entry.pad_score >= manifest.accept_threshold:
        return "accepted"
    if entry.pad_score <= manifest.reject_threshold:
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


def wilson_interval(errors: int, trials: int, z_score: float = 1.959963984540054) -> tuple[float, float]:
    rate = errors / trials
    denominator = 1 + z_score * z_score / trials
    center = (rate + z_score * z_score / (2 * trials)) / denominator
    margin = z_score * sqrt(rate * (1 - rate) / trials + z_score * z_score / (4 * trials * trials)) / denominator
    return max(0.0, center - margin), min(1.0, center + margin)


def report_to_json(report: PadEvaluationReport) -> dict[str, Any]:
    return asdict(report)


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
