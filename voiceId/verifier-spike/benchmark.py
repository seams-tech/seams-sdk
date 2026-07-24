from __future__ import annotations

import argparse
import hashlib
import json
from collections import Counter, defaultdict
from collections.abc import Iterable
from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Literal


SCHEMA_VERSION = "voice_id_benchmark_manifest_v2"
REPORT_SCHEMA_VERSION = "voice_id_benchmark_inventory_report_v2"
MINIMUM_AUDIO_BYTE_LENGTH = 1024
MAXIMUM_AUDIO_BYTE_LENGTH = 32 * 1024 * 1024
PARTITIONS = frozenset({"development", "calibration", "evaluation"})
CASE_KINDS = frozenset(
    {
        "enrollment",
        "genuine_verification",
        "zero_effort_impostor",
        "challenge_error",
        "presentation_attack",
    }
)
CHALLENGE_ERROR_KINDS = frozenset(
    {"substitution", "omission", "insertion", "reordering", "ambiguous"}
)
ATTACK_CLASSES = frozenset(
    {"replay", "synthesis", "voice_conversion", "splice", "relay", "digital_injection"}
)
INTENTS = frozenset({"approve", "reject", "cancel", "repeat", "unrelated"})
PLATFORMS = frozenset({"server", "browser", "embedded_nvidia", "embedded_cpu", "ios"})
PROVENANCE_KINDS = frozenset({"synthetic_generation", "consented_human_capture"})
SYNTHETIC_GENERATORS = frozenset({"dia2", "elevenlabs", "other"})
MINIMUM_HUMAN_METRIC_SUBJECTS = 2


class BenchmarkManifestError(ValueError):
    pass


@dataclass(frozen=True)
class CaptureProfile:
    platform: str
    microphone: str
    room: str
    distance_cm: float
    codec: str
    sample_rate_hz: int
    channel_count: int
    language: str
    accent: str
    noise_profile: str


@dataclass(frozen=True)
class ConsentedHumanCapture:
    kind: Literal["consented_human_capture"]
    consent_reference: str
    retention_class: str


@dataclass(frozen=True)
class SyntheticConditioning:
    source_subject_id: str
    consent_reference: str
    retention_class: str


@dataclass(frozen=True)
class SyntheticGeneration:
    kind: Literal["synthetic_generation"]
    generator: str
    model: str
    voice: str
    seed: int | None
    license: str
    request_hash: str
    conditioning: SyntheticConditioning | None


BenchmarkProvenance = ConsentedHumanCapture | SyntheticGeneration


@dataclass(frozen=True)
class BenchmarkCase:
    kind: str
    target_subject_id: str | None
    challenge_error_kind: str | None
    attack_class: str | None
    attack_tool: str | None


@dataclass(frozen=True)
class BenchmarkEntry:
    fixture_id: str
    audio_file_name: str
    audio_path: Path
    audio_sha256: str
    subject_id: str
    session_id: str
    partition: str
    case: BenchmarkCase
    expected_intent: str | None
    challenge_tokens: tuple[str, ...]
    capture: CaptureProfile
    captured_at: str
    duration_ms: int
    byte_length: int
    mime_type: str
    provenance: BenchmarkProvenance


@dataclass(frozen=True)
class BenchmarkManifest:
    manifest_path: Path
    dataset_version: str
    created_at: str
    entries: tuple[BenchmarkEntry, ...]


@dataclass(frozen=True)
class BenchmarkInventoryReport:
    schema_version: Literal["voice_id_benchmark_inventory_report_v2"]
    dataset_version: str
    fixture_count: int
    subject_count: int
    session_count: int
    partition_counts: dict[str, int]
    case_counts: dict[str, int]
    intent_counts: dict[str, int]
    attack_class_counts: dict[str, int]
    platform_counts: dict[str, int]
    provenance_kind_counts: dict[str, int]
    cohort_counts: dict[str, int]
    synthetic_impostor_count: int
    synthetic_attack_class_counts: dict[str, int]
    human_metrics_eligible: bool
    human_metrics_suppression_reason: str | None
    missing_partitions: tuple[str, ...]
    missing_case_kinds: tuple[str, ...]
    missing_attack_classes: tuple[str, ...]
    measurement_ready: bool


def load_benchmark_manifest(path: Path) -> BenchmarkManifest:
    manifest_path = path.expanduser().resolve()
    value = read_json_object(manifest_path)
    require_exact_keys(
        value,
        "benchmark manifest",
        {"schemaVersion", "datasetVersion", "createdAt", "entries"},
    )
    if require_string(value, "schemaVersion") != SCHEMA_VERSION:
        raise BenchmarkManifestError(f"schemaVersion must be {SCHEMA_VERSION}")
    raw_entries = value["entries"]
    if not isinstance(raw_entries, list) or len(raw_entries) == 0:
        raise BenchmarkManifestError("entries must be a non-empty array")
    entries = parse_entries(raw_entries, manifest_path.parent)
    enforce_subject_disjoint_partitions(entries)
    enforce_evaluable_subjects(entries)
    return BenchmarkManifest(
        manifest_path=manifest_path,
        dataset_version=require_string(value, "datasetVersion"),
        created_at=require_iso_date_time(value, "createdAt"),
        entries=entries,
    )


def build_inventory_report(manifest: BenchmarkManifest) -> BenchmarkInventoryReport:
    partition_counts = count(entry.partition for entry in manifest.entries)
    case_counts = count(entry.case.kind for entry in manifest.entries)
    intent_counts = count(
        entry.expected_intent for entry in manifest.entries if entry.expected_intent is not None
    )
    attack_class_counts = count(
        entry.case.attack_class for entry in manifest.entries if entry.case.attack_class is not None
    )
    platform_counts = count(entry.capture.platform for entry in manifest.entries)
    provenance_kind_counts = count(entry.provenance.kind for entry in manifest.entries)
    cohort_counts = count(entry_cohort(entry) for entry in manifest.entries)
    synthetic_impostor_count = sum(
        1
        for entry in manifest.entries
        if entry.case.kind == "zero_effort_impostor"
        and entry.provenance.kind == "synthetic_generation"
    )
    synthetic_attack_class_counts = count(
        entry.case.attack_class
        for entry in manifest.entries
        if entry.case.kind == "presentation_attack"
        and entry.provenance.kind == "synthetic_generation"
        and entry.case.attack_class is not None
    )
    human_metrics_eligible = has_qualifying_human_cohort(manifest.entries)
    missing_partitions = tuple(sorted(PARTITIONS - partition_counts.keys()))
    missing_case_kinds = tuple(sorted(CASE_KINDS - case_counts.keys()))
    missing_attack_classes = tuple(sorted(ATTACK_CLASSES - attack_class_counts.keys()))
    return BenchmarkInventoryReport(
        schema_version=REPORT_SCHEMA_VERSION,
        dataset_version=manifest.dataset_version,
        fixture_count=len(manifest.entries),
        subject_count=len(benchmark_subject_ids(manifest.entries)),
        session_count=len({entry.session_id for entry in manifest.entries}),
        partition_counts=partition_counts,
        case_counts=case_counts,
        intent_counts=intent_counts,
        attack_class_counts=attack_class_counts,
        platform_counts=platform_counts,
        provenance_kind_counts=provenance_kind_counts,
        cohort_counts=cohort_counts,
        synthetic_impostor_count=synthetic_impostor_count,
        synthetic_attack_class_counts=synthetic_attack_class_counts,
        human_metrics_eligible=human_metrics_eligible,
        human_metrics_suppression_reason=(
            None if human_metrics_eligible else "no_qualifying_human_cohort"
        ),
        missing_partitions=missing_partitions,
        missing_case_kinds=missing_case_kinds,
        missing_attack_classes=missing_attack_classes,
        measurement_ready=(
            len(missing_partitions) == 0
            and len(missing_case_kinds) == 0
            and len(missing_attack_classes) == 0
        ),
    )


def render_inventory_report(report: BenchmarkInventoryReport) -> str:
    return "\n".join(
        [
            "# VoiceID Reproducible Benchmark Inventory",
            "",
            f"- Dataset version: `{report.dataset_version}`",
            f"- Fixtures: {report.fixture_count}",
            f"- Subjects: {report.subject_count}",
            f"- Sessions: {report.session_count}",
            f"- Inventory complete: `{str(report.measurement_ready).lower()}`",
            f"- Human FAR/FRR/EER eligible: `{str(report.human_metrics_eligible).lower()}`",
            (
                f"- Human FAR/FRR/EER: suppressed (`{report.human_metrics_suppression_reason}`)"
                if report.human_metrics_suppression_reason is not None
                else "- Human FAR/FRR/EER: enabled"
            ),
            (
                f"- Human metric suppression: `{report.human_metrics_suppression_reason}`"
                if report.human_metrics_suppression_reason is not None
                else "- Human metric suppression: `none`"
            ),
            "",
            "## Coverage",
            "",
            f"- Partitions: {format_counts(report.partition_counts)}",
            f"- Cases: {format_counts(report.case_counts)}",
            f"- Intents: {format_counts(report.intent_counts)}",
            f"- Attack classes: {format_counts(report.attack_class_counts)}",
            f"- Platforms: {format_counts(report.platform_counts)}",
            f"- Provenance: {format_counts(report.provenance_kind_counts)}",
            f"- Cohorts: {format_counts(report.cohort_counts)}",
            f"- Synthetic impostors: {report.synthetic_impostor_count}",
            f"- Synthetic attack classes: {format_counts(report.synthetic_attack_class_counts)}",
            "",
            "## Missing Required Coverage",
            "",
            f"- Partitions: {format_missing(report.missing_partitions)}",
            f"- Cases: {format_missing(report.missing_case_kinds)}",
            f"- Attack classes: {format_missing(report.missing_attack_classes)}",
            "",
            "This inventory report validates corpus structure and coverage. Synthetic results are",
            "reported as pipeline and attack evidence. Human FAR, FRR, and EER remain suppressed",
            "until a qualifying real-human cohort is present in the evaluation partition.",
        ]
    )


def report_to_json(report: BenchmarkInventoryReport) -> dict[str, Any]:
    return camelize_report(asdict(report))


def write_reports(
    *,
    report: BenchmarkInventoryReport,
    json_path: Path,
    markdown_path: Path,
) -> None:
    json_path.parent.mkdir(parents=True, exist_ok=True)
    markdown_path.parent.mkdir(parents=True, exist_ok=True)
    json_path.write_text(json.dumps(report_to_json(report), indent=2) + "\n", encoding="utf-8")
    markdown_path.write_text(render_inventory_report(report) + "\n", encoding="utf-8")


def parse_entries(raw_entries: list[Any], manifest_dir: Path) -> tuple[BenchmarkEntry, ...]:
    entries: list[BenchmarkEntry] = []
    fixture_ids: set[str] = set()
    audio_file_names: set[str] = set()
    for index, value in enumerate(raw_entries):
        entry = parse_entry(value, manifest_dir, index)
        if entry.fixture_id in fixture_ids:
            raise BenchmarkManifestError(f"fixtureId {entry.fixture_id} is duplicated")
        if entry.audio_file_name in audio_file_names:
            raise BenchmarkManifestError(f"audioFileName {entry.audio_file_name} is duplicated")
        fixture_ids.add(entry.fixture_id)
        audio_file_names.add(entry.audio_file_name)
        entries.append(entry)
    return tuple(entries)


def parse_entry(value: object, manifest_dir: Path, index: int) -> BenchmarkEntry:
    data = require_object(value, f"entries[{index}]")
    require_exact_keys(
        data,
        f"entries[{index}]",
        {
            "fixtureId", "audioFileName", "audioSha256", "subjectId", "sessionId",
            "partition", "case", "expectedIntent", "challengeTokens", "capture",
            "capturedAt", "durationMs", "byteLength", "mimeType", "provenance",
        },
    )
    fixture_id = require_identifier(data, "fixtureId")
    audio_file_name = require_file_name(data, "audioFileName")
    audio_path = (manifest_dir / audio_file_name).resolve()
    if audio_path.parent != manifest_dir.resolve():
        raise BenchmarkManifestError(f"audio file escapes the manifest directory: {audio_file_name}")
    byte_length = require_positive_int(data, "byteLength")
    audio_sha256 = require_sha256(data, "audioSha256")
    validate_audio_file(audio_path, audio_file_name, byte_length, audio_sha256)
    case = parse_case(data["case"], index)
    subject_id = require_identifier(data, "subjectId")
    expected_intent = parse_expected_intent(data["expectedIntent"], case.kind)
    challenge_tokens = parse_challenge_tokens(data["challengeTokens"], case.kind)
    if case.kind == "zero_effort_impostor" and case.target_subject_id == subject_id:
        raise BenchmarkManifestError(
            f"entries[{index}] zero-effort impostor must differ from targetSubjectId"
        )
    return BenchmarkEntry(
        fixture_id=fixture_id,
        audio_file_name=audio_file_name,
        audio_path=audio_path,
        audio_sha256=audio_sha256,
        subject_id=subject_id,
        session_id=require_identifier(data, "sessionId"),
        partition=require_one_of(data, "partition", PARTITIONS),
        case=case,
        expected_intent=expected_intent,
        challenge_tokens=challenge_tokens,
        capture=parse_capture(data["capture"], index),
        captured_at=require_iso_date_time(data, "capturedAt"),
        duration_ms=require_positive_int(data, "durationMs"),
        byte_length=byte_length,
        mime_type=require_string(data, "mimeType"),
        provenance=parse_provenance(data["provenance"], index),
    )


def parse_case(value: object, index: int) -> BenchmarkCase:
    data = require_object(value, f"entries[{index}].case")
    kind = require_one_of(data, "kind", CASE_KINDS)
    if kind in {"enrollment", "genuine_verification"}:
        require_exact_keys(data, f"entries[{index}].case", {"kind"})
        return BenchmarkCase(kind, None, None, None, None)
    if kind == "zero_effort_impostor":
        require_exact_keys(data, f"entries[{index}].case", {"kind", "targetSubjectId"})
        return BenchmarkCase(kind, require_identifier(data, "targetSubjectId"), None, None, None)
    if kind == "challenge_error":
        require_exact_keys(data, f"entries[{index}].case", {"kind", "errorKind"})
        return BenchmarkCase(kind, None, require_one_of(data, "errorKind", CHALLENGE_ERROR_KINDS), None, None)
    require_exact_keys(
        data,
        f"entries[{index}].case",
        {"kind", "targetSubjectId", "attackClass", "attackTool"},
    )
    return BenchmarkCase(
        kind,
        require_identifier(data, "targetSubjectId"),
        None,
        require_one_of(data, "attackClass", ATTACK_CLASSES),
        require_string(data, "attackTool"),
    )


def parse_capture(value: object, index: int) -> CaptureProfile:
    data = require_object(value, f"entries[{index}].capture")
    require_exact_keys(
        data,
        f"entries[{index}].capture",
        {"platform", "microphone", "room", "distanceCm", "codec", "sampleRateHz", "channelCount", "language", "accent", "noiseProfile"},
    )
    return CaptureProfile(
        platform=require_one_of(data, "platform", PLATFORMS),
        microphone=require_string(data, "microphone"),
        room=require_string(data, "room"),
        distance_cm=require_non_negative_number(data, "distanceCm"),
        codec=require_string(data, "codec"),
        sample_rate_hz=require_positive_int(data, "sampleRateHz"),
        channel_count=require_positive_int(data, "channelCount"),
        language=require_string(data, "language"),
        accent=require_string(data, "accent"),
        noise_profile=require_string(data, "noiseProfile"),
    )


def parse_provenance(value: object, index: int) -> BenchmarkProvenance:
    data = require_object(value, f"entries[{index}].provenance")
    kind = require_one_of(data, "kind", PROVENANCE_KINDS)
    if kind == "consented_human_capture":
        require_exact_keys(
            data,
            f"entries[{index}].provenance",
            {"kind", "consentReference", "retentionClass"},
        )
        return ConsentedHumanCapture(
            kind="consented_human_capture",
            consent_reference=require_string(data, "consentReference"),
            retention_class=require_string(data, "retentionClass"),
        )
    require_exact_keys(
        data,
        f"entries[{index}].provenance",
        {"kind", "generator", "model", "voice", "seed", "license", "requestHash", "conditioning"},
    )
    seed = data["seed"]
    if seed is not None and (not isinstance(seed, int) or isinstance(seed, bool) or seed < 0):
        raise BenchmarkManifestError("synthetic_generation seed must be a non-negative integer or null")
    return SyntheticGeneration(
        kind="synthetic_generation",
        generator=require_one_of(data, "generator", SYNTHETIC_GENERATORS),
        model=require_string(data, "model"),
        voice=require_string(data, "voice"),
        seed=seed,
        license=require_string(data, "license"),
        request_hash=require_sha256(data, "requestHash"),
        conditioning=parse_synthetic_conditioning(data["conditioning"], index),
    )


def parse_synthetic_conditioning(value: object, index: int) -> SyntheticConditioning | None:
    if value is None:
        return None
    data = require_object(value, f"entries[{index}].provenance.conditioning")
    require_exact_keys(
        data,
        f"entries[{index}].provenance.conditioning",
        {"sourceSubjectId", "consentReference", "retentionClass"},
    )
    return SyntheticConditioning(
        source_subject_id=require_identifier(data, "sourceSubjectId"),
        consent_reference=require_string(data, "consentReference"),
        retention_class=require_string(data, "retentionClass"),
    )


def parse_expected_intent(value: object, case_kind: str) -> str | None:
    if case_kind == "enrollment":
        if value is not None:
            raise BenchmarkManifestError("enrollment expectedIntent must be null")
        return None
    if not isinstance(value, str) or value not in INTENTS:
        raise BenchmarkManifestError("verification expectedIntent is invalid")
    return value


def parse_challenge_tokens(value: object, case_kind: str) -> tuple[str, ...]:
    if not isinstance(value, list) or not all(isinstance(token, str) for token in value):
        raise BenchmarkManifestError("challengeTokens must be an array of strings")
    tokens = tuple(token.strip() for token in value)
    if any(len(token) == 0 for token in tokens) or len(tokens) != len(set(tokens)):
        raise BenchmarkManifestError("challengeTokens must be unique non-empty strings")
    if case_kind == "enrollment" and len(tokens) != 0:
        raise BenchmarkManifestError("enrollment challengeTokens must be empty")
    if case_kind != "enrollment" and len(tokens) == 0:
        raise BenchmarkManifestError("verification challengeTokens must not be empty")
    return tokens


def enforce_subject_disjoint_partitions(entries: tuple[BenchmarkEntry, ...]) -> None:
    subject_partitions: dict[str, set[str]] = defaultdict(set)
    for entry in entries:
        subject_partitions[entry.subject_id].add(entry.partition)
        if entry.case.target_subject_id is not None:
            subject_partitions[entry.case.target_subject_id].add(entry.partition)
    overlaps = {subject: partitions for subject, partitions in subject_partitions.items() if len(partitions) > 1}
    if overlaps:
        subject_id = sorted(overlaps)[0]
        partitions = ", ".join(sorted(overlaps[subject_id]))
        raise BenchmarkManifestError(
            f"subject {subject_id} crosses subject-disjoint partitions: {partitions}"
        )


def enforce_evaluable_subjects(entries: tuple[BenchmarkEntry, ...]) -> None:
    enrolled_subjects = {
        (entry.subject_id, entry.partition)
        for entry in entries
        if entry.case.kind == "enrollment"
    }
    required_subjects: set[tuple[str, str]] = set()
    for entry in entries:
        if entry.case.kind in {"genuine_verification", "challenge_error"}:
            required_subjects.add((entry.subject_id, entry.partition))
        if entry.case.target_subject_id is not None:
            required_subjects.add((entry.case.target_subject_id, entry.partition))
    missing_subjects = sorted(required_subjects - enrolled_subjects)
    if missing_subjects:
        subject_id, partition = missing_subjects[0]
        raise BenchmarkManifestError(
            f"subject {subject_id} requires an enrollment entry in {partition}"
        )


def validate_audio_file(path: Path, name: str, byte_length: int, expected_sha256: str) -> None:
    if not path.is_file():
        raise BenchmarkManifestError(f"audio file does not exist: {name}")
    if byte_length < MINIMUM_AUDIO_BYTE_LENGTH:
        raise BenchmarkManifestError(f"audio file {name} must contain at least 1024 bytes")
    if byte_length > MAXIMUM_AUDIO_BYTE_LENGTH:
        raise BenchmarkManifestError(f"audio file {name} exceeds the 32 MiB limit")
    actual_bytes = path.read_bytes()
    if len(actual_bytes) != byte_length:
        raise BenchmarkManifestError(
            f"audio file {name} has {len(actual_bytes)} bytes, manifest says {byte_length}"
        )
    if hashlib.sha256(actual_bytes).hexdigest() != expected_sha256:
        raise BenchmarkManifestError(f"audio file {name} SHA-256 does not match the manifest")


def read_json_object(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise BenchmarkManifestError(f"manifest file does not exist: {path}") from exc
    except json.JSONDecodeError as exc:
        raise BenchmarkManifestError(f"manifest JSON is malformed: {exc.msg}") from exc
    return require_object(value, "benchmark manifest")


def require_object(value: object, field_name: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise BenchmarkManifestError(f"{field_name} must be an object")
    return value


def require_exact_keys(data: dict[str, Any], field_name: str, keys: set[str]) -> None:
    if set(data.keys()) != keys:
        raise BenchmarkManifestError(f"{field_name} contains unexpected or missing fields")


def require_string(data: dict[str, Any], field_name: str) -> str:
    value = data[field_name]
    if not isinstance(value, str) or len(value.strip()) == 0:
        raise BenchmarkManifestError(f"{field_name} must be a non-empty string")
    return value.strip()


def require_identifier(data: dict[str, Any], field_name: str) -> str:
    value = require_string(data, field_name)
    if not all(character.isalnum() or character in {"_", "-"} for character in value):
        raise BenchmarkManifestError(f"{field_name} may only contain letters, numbers, underscore, or hyphen")
    return value


def require_file_name(data: dict[str, Any], field_name: str) -> str:
    value = require_string(data, field_name)
    if "/" in value or "\\" in value or value in {".", ".."}:
        raise BenchmarkManifestError(f"{field_name} must be a file name")
    return value


def require_sha256(data: dict[str, Any], field_name: str) -> str:
    value = require_string(data, field_name).lower()
    if len(value) != 64 or any(character not in "0123456789abcdef" for character in value):
        raise BenchmarkManifestError(f"{field_name} must be a lowercase SHA-256 hex digest")
    return value


def require_one_of(data: dict[str, Any], field_name: str, allowed: frozenset[str]) -> str:
    value = require_string(data, field_name)
    if value not in allowed:
        raise BenchmarkManifestError(f"{field_name} is invalid")
    return value


def require_positive_int(data: dict[str, Any], field_name: str) -> int:
    value = data[field_name]
    if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
        raise BenchmarkManifestError(f"{field_name} must be a positive integer")
    return value


def require_non_negative_number(data: dict[str, Any], field_name: str) -> float:
    value = data[field_name]
    if not isinstance(value, int | float) or isinstance(value, bool) or value < 0:
        raise BenchmarkManifestError(f"{field_name} must be non-negative")
    return float(value)


def require_iso_date_time(data: dict[str, Any], field_name: str) -> str:
    value = require_string(data, field_name)
    normalized = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError as exc:
        raise BenchmarkManifestError(f"{field_name} must be an ISO date-time") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise BenchmarkManifestError(f"{field_name} must include a UTC offset")
    return value


def benchmark_subject_ids(entries: tuple[BenchmarkEntry, ...]) -> set[str]:
    subject_ids = {entry.subject_id for entry in entries}
    subject_ids.update(
        entry.case.target_subject_id
        for entry in entries
        if entry.case.target_subject_id is not None
    )
    return subject_ids


def entry_cohort(entry: BenchmarkEntry) -> str:
    if entry.provenance.kind == "consented_human_capture":
        return "real_human"
    if entry.provenance.conditioning is not None:
        return "owner_conditioned_clone"
    return "fictional_synthetic"


def has_qualifying_human_cohort(entries: tuple[BenchmarkEntry, ...]) -> bool:
    evaluation_human_entries = [
        entry
        for entry in entries
        if entry.partition == "evaluation"
        and entry.provenance.kind == "consented_human_capture"
    ]
    evaluation_subjects = {entry.subject_id for entry in evaluation_human_entries}
    enrolled_subjects = {
        entry.subject_id
        for entry in evaluation_human_entries
        if entry.case.kind == "enrollment"
    }
    evaluated_subjects = {
        entry.subject_id
        for entry in evaluation_human_entries
        if entry.case.kind in {"genuine_verification", "challenge_error"}
    }
    return (
        len(evaluation_subjects) >= MINIMUM_HUMAN_METRIC_SUBJECTS
        and enrolled_subjects == evaluation_subjects
        and evaluated_subjects == evaluation_subjects
    )


def count(values: Iterable[str]) -> dict[str, int]:
    return dict(sorted(Counter(values).items()))


def format_counts(values: dict[str, int]) -> str:
    if len(values) == 0:
        return "none"
    return ", ".join(f"`{name}`={count_value}" for name, count_value in values.items())


def format_missing(values: tuple[str, ...]) -> str:
    if len(values) == 0:
        return "none"
    return ", ".join(f"`{value}`" for value in values)


def camelize_report(value: dict[str, Any]) -> dict[str, Any]:
    return {
        "schemaVersion": value["schema_version"],
        "datasetVersion": value["dataset_version"],
        "fixtureCount": value["fixture_count"],
        "subjectCount": value["subject_count"],
        "sessionCount": value["session_count"],
        "partitionCounts": value["partition_counts"],
        "caseCounts": value["case_counts"],
        "intentCounts": value["intent_counts"],
        "attackClassCounts": value["attack_class_counts"],
        "platformCounts": value["platform_counts"],
        "provenanceKindCounts": value["provenance_kind_counts"],
        "cohortCounts": value["cohort_counts"],
        "syntheticImpostorCount": value["synthetic_impostor_count"],
        "syntheticAttackClassCounts": value["synthetic_attack_class_counts"],
        "humanMetricsEligible": value["human_metrics_eligible"],
        "humanMetricsSuppressionReason": value["human_metrics_suppression_reason"],
        "missingPartitions": value["missing_partitions"],
        "missingCaseKinds": value["missing_case_kinds"],
        "missingAttackClasses": value["missing_attack_classes"],
        "measurementReady": value["measurement_ready"],
    }


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Validate the frozen VoiceID benchmark corpus and emit paired reports."
    )
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--json-out", type=Path, required=True)
    parser.add_argument("--report-out", type=Path, required=True)
    args = parser.parse_args()
    report = build_inventory_report(load_benchmark_manifest(args.manifest))
    write_reports(report=report, json_path=args.json_out, markdown_path=args.report_out)


if __name__ == "__main__":
    main()
