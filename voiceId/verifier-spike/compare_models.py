from __future__ import annotations

import argparse
import json
import shutil
import subprocess
from collections import Counter
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Callable


SCHEMA_VERSION = "voice_id_fixture_manifest_v1"
MIN_AUDIO_BYTE_LENGTH = 1024
EXPECTED_RELATIONS = frozenset(
    {
        "owner_enrollment",
        "owner_verification",
        "different_speaker",
        "wrong_phrase",
        "noisy",
        "too_short",
    }
)


class FixtureManifestError(ValueError):
    pass


@dataclass(frozen=True)
class FixtureManifestEntry:
    fixture_id: str
    audio_file_name: str
    speaker_label: str
    phrase_label: str
    expected_relation: str
    capture_device: str
    duration_ms: int
    environment_notes: str
    captured_at: str
    byte_length: int
    mime_type: str
    audio_path: Path


@dataclass(frozen=True)
class FixtureInventory:
    manifest_path: Path
    created_at: str
    entries: tuple[FixtureManifestEntry, ...]
    relation_counts: dict[str, int]
    speaker_counts: dict[str, int]
    phrase_counts: dict[str, int]


@dataclass(frozen=True)
class AudioStreamProbe:
    codec_name: str
    codec_type: str


@dataclass(frozen=True)
class ModelCandidate:
    model_id: str
    adapter_name: str
    preprocessing: str
    embedding_dimensions: str
    threshold_policy: str
    latency_notes: str
    implementation_notes: str


MODEL_CANDIDATES = (
    ModelCandidate(
        model_id="speechbrain/spkrec-ecapa-voxceleb",
        adapter_name="SpeechBrainEcapaAdapter",
        preprocessing="model-owned waveform normalization/resampling; confirm target sample rate in spike",
        embedding_dimensions="read from model metadata during adapter spike",
        threshold_policy="calibrate cosine threshold from owner vs different-speaker fixture scores",
        latency_notes="measure cold and warm embedding extraction latency on target CPU",
        implementation_notes="good first ECAPA-style baseline; likely Python-only for the spike",
    ),
    ModelCandidate(
        model_id="torchaudio-xvector-voxceleb",
        adapter_name="TorchaudioXVectorAdapter",
        preprocessing="model-owned feature extraction; confirm MFCC/log-mel requirements in adapter",
        embedding_dimensions="read from model metadata during adapter spike",
        threshold_policy="calibrate cosine or PLDA-style threshold from fixture scores",
        latency_notes="measure against ECAPA baseline on the same fixture clips",
        implementation_notes="useful x-vector baseline with simpler deployment story if available locally",
    ),
    ModelCandidate(
        model_id="pyannote/embedding",
        adapter_name="PyannoteEmbeddingAdapter",
        preprocessing="model-owned waveform normalization/resampling; check access and license before use",
        embedding_dimensions="read from model metadata during adapter spike",
        threshold_policy="calibrate cosine threshold from fixture scores",
        latency_notes="measure only if model access is available for the target environment",
        implementation_notes="useful comparison candidate; access constraints may make it unsuitable for MVP",
    ),
)


AudioStreamProbeFn = Callable[[Path], AudioStreamProbe]


def load_fixture_manifest(
    path: Path,
    *,
    check_media: bool = False,
    media_probe: AudioStreamProbeFn | None = None,
) -> list[FixtureManifestEntry]:
    return list(load_fixture_inventory(path, check_media=check_media, media_probe=media_probe).entries)


def load_fixture_inventory(
    path: Path,
    *,
    check_media: bool = False,
    media_probe: AudioStreamProbeFn | None = None,
) -> FixtureInventory:
    manifest_path = path.expanduser().resolve()
    manifest = _read_manifest_json(manifest_path)
    schema_version = _require_string(manifest, "schemaVersion")
    if schema_version != SCHEMA_VERSION:
        raise FixtureManifestError(f"schemaVersion must be {SCHEMA_VERSION}")

    created_at = _require_iso_date_time(manifest, "createdAt")
    raw_entries = manifest.get("entries")
    if not isinstance(raw_entries, list):
        raise FixtureManifestError("entries must be an array")

    entries = _parse_entries(raw_entries, manifest_path.parent)
    if check_media:
        validate_audio_streams(entries, media_probe=media_probe)
    return FixtureInventory(
        manifest_path=manifest_path,
        created_at=created_at,
        entries=entries,
        relation_counts=dict(Counter(entry.expected_relation for entry in entries)),
        speaker_counts=dict(Counter(entry.speaker_label for entry in entries)),
        phrase_counts=dict(Counter(entry.phrase_label for entry in entries)),
    )


def validate_audio_streams(
    entries: tuple[FixtureManifestEntry, ...],
    *,
    media_probe: AudioStreamProbeFn | None = None,
) -> None:
    probe = media_probe or probe_audio_stream
    for entry in entries:
        stream = probe(entry.audio_path)
        if stream.codec_type != "audio":
            raise FixtureManifestError(f"fixture {entry.audio_file_name} does not contain an audio stream")
        if len(stream.codec_name.strip()) == 0:
            raise FixtureManifestError(f"fixture {entry.audio_file_name} audio codec is missing")


def probe_audio_stream(path: Path) -> AudioStreamProbe:
    ffprobe = shutil.which("ffprobe")
    if ffprobe is None:
        raise FixtureManifestError("ffprobe is required for media validation")
    completed = subprocess.run(
        [
            ffprobe,
            "-v",
            "error",
            "-select_streams",
            "a:0",
            "-show_entries",
            "stream=codec_name,codec_type",
            "-of",
            "json",
            str(path),
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    if completed.returncode != 0:
        message = completed.stderr.strip() or "unknown ffprobe error"
        raise FixtureManifestError(f"ffprobe rejected {path.name}: {message}")
    try:
        payload = json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise FixtureManifestError(f"ffprobe output is malformed for {path.name}") from exc
    streams = payload.get("streams")
    if not isinstance(streams, list) or len(streams) == 0:
        raise FixtureManifestError(f"fixture {path.name} does not contain an audio stream")
    stream = streams[0]
    if not isinstance(stream, dict):
        raise FixtureManifestError(f"ffprobe stream output is malformed for {path.name}")
    codec_name = stream.get("codec_name")
    codec_type = stream.get("codec_type")
    if not isinstance(codec_name, str) or not isinstance(codec_type, str):
        raise FixtureManifestError(f"ffprobe stream output is malformed for {path.name}")
    return AudioStreamProbe(codec_name=codec_name, codec_type=codec_type)


def inventory_summary(inventory: FixtureInventory) -> dict[str, Any]:
    return {
        "manifestPath": str(inventory.manifest_path),
        "createdAt": inventory.created_at,
        "fixtureCount": len(inventory.entries),
        "relationCounts": inventory.relation_counts,
        "speakerCounts": inventory.speaker_counts,
        "phraseCounts": inventory.phrase_counts,
        "fixtures": [
            {
                "fixtureId": entry.fixture_id,
                "audioFileName": entry.audio_file_name,
                "speakerLabel": entry.speaker_label,
                "phraseLabel": entry.phrase_label,
                "expectedRelation": entry.expected_relation,
                "durationMs": entry.duration_ms,
                "byteLength": entry.byte_length,
                "mimeType": entry.mime_type,
            }
            for entry in inventory.entries
        ],
    }


def render_inventory_summary(inventory: FixtureInventory) -> str:
    lines = [
        "VoiceID fixture inventory",
        f"manifest: {inventory.manifest_path}",
        f"createdAt: {inventory.created_at}",
        f"fixtures: {len(inventory.entries)}",
        f"relations: {_format_counts(inventory.relation_counts)}",
        f"speakers: {_format_counts(inventory.speaker_counts)}",
        f"phrases: {_format_counts(inventory.phrase_counts)}",
        "",
        "Model adapters are still pending. Use this validated fixture set for the next comparison run.",
    ]
    return "\n".join(lines)


def render_model_selection_report_template(inventory: FixtureInventory) -> str:
    lines = [
        "# VoiceID Model Selection Report",
        "",
        "## Fixture Inventory",
        "",
        f"- Manifest: `{inventory.manifest_path}`",
        f"- Created at: `{inventory.created_at}`",
        f"- Fixture count: {len(inventory.entries)}",
        f"- Relations: {_format_counts(inventory.relation_counts)}",
        f"- Speakers: {_format_counts(inventory.speaker_counts)}",
        f"- Phrases: {_format_counts(inventory.phrase_counts)}",
        "",
        "## Candidate Models",
        "",
    ]
    for candidate in MODEL_CANDIDATES:
        lines.extend(
            [
                f"### `{candidate.model_id}`",
                "",
                f"- Adapter: `{candidate.adapter_name}`",
                f"- Preprocessing: {candidate.preprocessing}",
                f"- Embedding dimensions: {candidate.embedding_dimensions}",
                f"- Threshold policy: {candidate.threshold_policy}",
                f"- Latency notes: {candidate.latency_notes}",
                f"- Implementation notes: {candidate.implementation_notes}",
                "",
            ]
        )

    lines.extend(
        [
            "## Required Measurements",
            "",
            "- Embedding extraction latency, cold start and warm path.",
            "- Same-speaker score distribution across owner enrollment and owner verification clips.",
            "- Different-speaker score distribution.",
            "- Wrong-phrase behavior; phrase checks should fail independently of speaker score.",
            "- Noisy and too-short behavior; low-quality clips should return uncertain or rejected.",
            "- False accepts and false rejects at the chosen threshold.",
            "",
            "## Selection Decision",
            "",
            "- Selected model id: TBD",
            "- Selected adapter: TBD",
            "- Threshold version: TBD",
            "- Template version: TBD",
            "- Known gaps: TBD",
        ]
    )
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Validate browser-recorded VoiceID fixtures before model comparison."
    )
    parser.add_argument(
        "--manifest",
        type=Path,
        required=True,
        help="Path to voiceid-fixture-manifest.json exported by the browser demo.",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Print the validated fixture inventory as JSON.",
    )
    parser.add_argument(
        "--report-template",
        action="store_true",
        help="Print a Markdown model-selection report template for the validated fixtures.",
    )
    parser.add_argument(
        "--check-media",
        action="store_true",
        help="Use ffprobe to confirm every fixture file contains an audio stream.",
    )
    args = parser.parse_args()

    inventory = load_fixture_inventory(args.manifest, check_media=args.check_media)
    if args.report_template:
        print(render_model_selection_report_template(inventory))
    elif args.json:
        print(json.dumps(inventory_summary(inventory), indent=2))
    else:
        print(render_inventory_summary(inventory))


def _read_manifest_json(path: Path) -> dict[str, Any]:
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise FixtureManifestError(f"manifest file does not exist: {path}") from exc
    except json.JSONDecodeError as exc:
        raise FixtureManifestError(f"manifest JSON is malformed: {exc.msg}") from exc

    if not isinstance(raw, dict):
        raise FixtureManifestError("fixture manifest must be an object")
    return raw


def _parse_entries(raw_entries: list[Any], manifest_dir: Path) -> tuple[FixtureManifestEntry, ...]:
    entries: list[FixtureManifestEntry] = []
    fixture_ids: set[str] = set()
    audio_file_names: set[str] = set()
    for index, raw_entry in enumerate(raw_entries):
        entry = _parse_entry(raw_entry, manifest_dir, index)
        if entry.fixture_id in fixture_ids:
            raise FixtureManifestError(f"fixtureId {entry.fixture_id} is duplicated")
        fixture_ids.add(entry.fixture_id)
        if entry.audio_file_name in audio_file_names:
            raise FixtureManifestError(f"audioFileName {entry.audio_file_name} is duplicated")
        audio_file_names.add(entry.audio_file_name)
        entries.append(entry)
    return tuple(entries)


def _parse_entry(raw_entry: Any, manifest_dir: Path, index: int) -> FixtureManifestEntry:
    if not isinstance(raw_entry, dict):
        raise FixtureManifestError(f"entries[{index}] must be an object")

    fixture_id = _require_fixture_id(raw_entry, "fixtureId")
    audio_file_name = _require_audio_file_name(raw_entry, "audioFileName")
    audio_path = (manifest_dir / audio_file_name).resolve()
    speaker_label = _require_string(raw_entry, "speakerLabel")
    phrase_label = _require_string(raw_entry, "phraseLabel")
    expected_relation = _require_relation(raw_entry, "expectedRelation")
    capture_device = _require_string(raw_entry, "captureDevice")
    duration_ms = _require_positive_int(raw_entry, "durationMs")
    environment_notes = _require_string(raw_entry, "environmentNotes")
    captured_at = _require_iso_date_time(raw_entry, "capturedAt")
    byte_length = _require_positive_int(raw_entry, "byteLength")
    mime_type = _require_string(raw_entry, "mimeType")

    if not audio_path.is_file():
        raise FixtureManifestError(f"audio file does not exist: {audio_file_name}")
    actual_byte_length = audio_path.stat().st_size
    if byte_length < MIN_AUDIO_BYTE_LENGTH:
        raise FixtureManifestError(
            f"audio file {audio_file_name} has {byte_length} bytes, expected at least {MIN_AUDIO_BYTE_LENGTH}"
        )
    if actual_byte_length != byte_length:
        raise FixtureManifestError(
            f"audio file {audio_file_name} has {actual_byte_length} bytes, manifest says {byte_length}"
        )

    return FixtureManifestEntry(
        fixture_id=fixture_id,
        audio_file_name=audio_file_name,
        speaker_label=speaker_label,
        phrase_label=phrase_label,
        expected_relation=expected_relation,
        capture_device=capture_device,
        duration_ms=duration_ms,
        environment_notes=environment_notes,
        captured_at=captured_at,
        byte_length=byte_length,
        mime_type=mime_type,
        audio_path=audio_path,
    )


def _require_fixture_id(data: dict[str, Any], field_name: str) -> str:
    value = _require_string(data, field_name)
    if not all(character.isalnum() or character in {"_", "-"} for character in value):
        raise FixtureManifestError(f"{field_name} may only contain letters, numbers, underscore, or hyphen")
    return value


def _require_audio_file_name(data: dict[str, Any], field_name: str) -> str:
    value = _require_string(data, field_name)
    if "/" in value or "\\" in value or value in {".", ".."}:
        raise FixtureManifestError(f"{field_name} must be a file name, not a path")
    return value


def _require_relation(data: dict[str, Any], field_name: str) -> str:
    value = _require_string(data, field_name)
    if value not in EXPECTED_RELATIONS:
        raise FixtureManifestError(f"{field_name} is invalid")
    return value


def _require_iso_date_time(data: dict[str, Any], field_name: str) -> str:
    value = _require_string(data, field_name)
    normalized = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        datetime.fromisoformat(normalized)
    except ValueError as exc:
        raise FixtureManifestError(f"{field_name} must be an ISO date-time string") from exc
    return value


def _require_positive_int(data: dict[str, Any], field_name: str) -> int:
    value = data.get(field_name)
    if not isinstance(value, int) or value <= 0:
        raise FixtureManifestError(f"{field_name} must be a positive integer")
    return value


def _require_string(data: dict[str, Any], field_name: str) -> str:
    value = data.get(field_name)
    if not isinstance(value, str) or len(value.strip()) == 0:
        raise FixtureManifestError(f"{field_name} must be a non-empty string")
    return value.strip()


def _format_counts(counts: dict[str, int]) -> str:
    if len(counts) == 0:
        return "none"
    return ", ".join(f"{key}={value}" for key, value in sorted(counts.items()))


if __name__ == "__main__":
    main()
