from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
import tempfile
import wave
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

from benchmark import PARTITIONS, PLATFORMS, load_benchmark_manifest_fragment
from dia2_batch import inspect_wav, sha256_file


SCHEMA_VERSION = "voice_id_benchmark_manifest_v2"


class ConsentedCaptureImportError(ValueError):
    pass


@dataclass(frozen=True)
class ConsentedEnrollmentImport:
    dataset_version: str
    created_at: str
    captured_at: str
    fixture_id: str
    audio_file_name: str
    subject_id: str
    session_id: str
    partition: str
    consent_reference: str
    retention_class: str
    platform: str
    microphone: str
    room: str
    distance_cm: float
    language: str
    accent: str
    noise_profile: str


def import_consented_enrollment(
    spec: ConsentedEnrollmentImport,
    *,
    source_audio_path: Path,
    output_dir: Path,
) -> dict[str, Any]:
    validate_spec(spec)
    source = source_audio_path.expanduser().resolve()
    if not source.is_file():
        raise ConsentedCaptureImportError("source audio does not exist")
    source_snapshot = source.read_bytes()
    destination = output_dir.expanduser().resolve() / spec.audio_file_name
    audio = copy_immutable_audio(source_snapshot, destination)
    return {
        "schemaVersion": SCHEMA_VERSION,
        "datasetVersion": spec.dataset_version,
        "createdAt": spec.created_at,
        "entries": [
            {
                "fixtureId": spec.fixture_id,
                "audioFileName": spec.audio_file_name,
                "audioSha256": audio["sha256"],
                "subjectId": spec.subject_id,
                "sessionId": spec.session_id,
                "partition": spec.partition,
                "case": {"kind": "enrollment"},
                "expectedIntent": None,
                "challengeTokens": [],
                "capture": {
                    "platform": spec.platform,
                    "microphone": spec.microphone,
                    "room": spec.room,
                    "distanceCm": spec.distance_cm,
                    "codec": "pcm_s16le",
                    "sampleRateHz": audio["sampleRateHz"],
                    "channelCount": 1,
                    "language": spec.language,
                    "accent": spec.accent,
                    "noiseProfile": spec.noise_profile,
                },
                "capturedAt": spec.captured_at,
                "durationMs": audio["durationMs"],
                "byteLength": audio["byteLength"],
                "mimeType": "audio/wav",
                "provenance": {
                    "kind": "consented_human_capture",
                    "consentReference": spec.consent_reference,
                    "retentionClass": spec.retention_class,
                },
            }
        ],
    }


def validate_spec(spec: ConsentedEnrollmentImport) -> None:
    for field_name, value in (
        ("dataset_version", spec.dataset_version),
        ("consent_reference", spec.consent_reference),
        ("retention_class", spec.retention_class),
        ("microphone", spec.microphone),
        ("room", spec.room),
        ("language", spec.language),
        ("accent", spec.accent),
        ("noise_profile", spec.noise_profile),
    ):
        if value.strip() == "":
            raise ConsentedCaptureImportError(f"{field_name} must be non-empty")
    for field_name, value in (
        ("fixture_id", spec.fixture_id),
        ("subject_id", spec.subject_id),
        ("session_id", spec.session_id),
    ):
        if not is_identifier(value):
            raise ConsentedCaptureImportError(f"{field_name} must be an identifier")
    if Path(spec.audio_file_name).name != spec.audio_file_name:
        raise ConsentedCaptureImportError("audio_file_name must be a file name")
    if Path(spec.audio_file_name).suffix.lower() != ".wav":
        raise ConsentedCaptureImportError("audio_file_name must end in .wav")
    if spec.partition not in PARTITIONS:
        raise ConsentedCaptureImportError("partition is invalid")
    if spec.platform not in PLATFORMS:
        raise ConsentedCaptureImportError("platform is invalid")
    if spec.distance_cm < 0:
        raise ConsentedCaptureImportError("distance_cm must be non-negative")
    require_iso_date_time(spec.created_at, "created_at")
    require_iso_date_time(spec.captured_at, "captured_at")


def copy_immutable_audio(
    source_snapshot: bytes,
    destination: Path,
) -> dict[str, Any]:
    if len(source_snapshot) == 0:
        raise ConsentedCaptureImportError("source audio is empty")
    destination.parent.mkdir(parents=True, exist_ok=True)
    source_sha256 = hashlib.sha256(source_snapshot).hexdigest()
    temporary_path = create_temporary_path(destination)
    try:
        temporary_path.write_bytes(source_snapshot)
        fsync_file(temporary_path)
        audio = inspect_wav(temporary_path)
        if audio["sampleRateHz"] != 16000:
            raise ConsentedCaptureImportError(
                "source audio must be canonical mono PCM16 at 16 kHz"
            )
        if sha256_file(temporary_path) != source_sha256:
            raise ConsentedCaptureImportError(
                f"output audio integrity check failed: {destination.name}"
            )
        destination_exists = require_regular_file_or_absent(
            destination,
            "output audio",
        )
        if destination_exists:
            if sha256_file(destination) != source_sha256:
                raise ConsentedCaptureImportError(
                    f"output audio collision: {destination.name}"
                )
        else:
            try:
                os.link(temporary_path, destination, follow_symlinks=False)
            except FileExistsError:
                require_regular_file_or_absent(destination, "output audio")
                if sha256_file(destination) != source_sha256:
                    raise ConsentedCaptureImportError(
                        f"output audio collision: {destination.name}"
                    )
        fsync_directory(destination.parent)
        return audio
    except (OSError, ValueError, wave.Error) as error:
        if isinstance(error, ConsentedCaptureImportError):
            raise
        raise ConsentedCaptureImportError(
            f"source audio is not a valid canonical WAV: {error}"
        ) from error
    finally:
        temporary_path.unlink(missing_ok=True)


def require_iso_date_time(value: str, field_name: str) -> None:
    normalized = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError as error:
        raise ConsentedCaptureImportError(
            f"{field_name} must be an ISO date-time"
        ) from error
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ConsentedCaptureImportError(
            f"{field_name} must include a UTC offset"
        )


def is_identifier(value: str) -> bool:
    return value != "" and all(
        character.isalnum() or character in {"_", "-"}
        for character in value
    )


def write_json(path: Path, value: object) -> None:
    encoded = (json.dumps(value, indent=2) + "\n").encode("utf-8")
    path.parent.mkdir(parents=True, exist_ok=True)
    if require_regular_file_or_absent(path, "output manifest"):
        if path.read_bytes() != encoded:
            raise ConsentedCaptureImportError(
                f"output manifest collision: {path.name}"
            )
        return
    temporary_path = create_temporary_path(path)
    try:
        temporary_path.write_bytes(encoded)
        fsync_file(temporary_path)
        try:
            os.link(temporary_path, path, follow_symlinks=False)
        except FileExistsError:
            require_regular_file_or_absent(path, "output manifest")
            if path.read_bytes() != encoded:
                raise ConsentedCaptureImportError(
                    f"output manifest collision: {path.name}"
                )
        fsync_directory(path.parent)
    finally:
        temporary_path.unlink(missing_ok=True)


def create_temporary_path(destination: Path) -> Path:
    descriptor, temporary_name = tempfile.mkstemp(
        dir=destination.parent,
        prefix=f".{destination.name}.",
        suffix=".tmp",
    )
    os.close(descriptor)
    return Path(temporary_name)


def require_regular_file_or_absent(path: Path, label: str) -> bool:
    try:
        mode = path.lstat().st_mode
    except FileNotFoundError:
        return False
    except OSError as error:
        raise ConsentedCaptureImportError(
            f"cannot inspect {label}: {path.name}"
        ) from error
    if not stat.S_ISREG(mode):
        raise ConsentedCaptureImportError(
            f"{label} must be a regular file: {path.name}"
        )
    return True


def fsync_file(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Import one consented owner enrollment into a benchmark fragment."
    )
    parser.add_argument("--source-audio", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--manifest-out", type=Path, required=True)
    parser.add_argument("--dataset-version", required=True)
    parser.add_argument("--created-at", required=True)
    parser.add_argument("--captured-at", required=True)
    parser.add_argument("--fixture-id", required=True)
    parser.add_argument("--audio-file-name", required=True)
    parser.add_argument("--subject-id", required=True)
    parser.add_argument("--session-id", required=True)
    parser.add_argument("--partition", choices=sorted(PARTITIONS), required=True)
    parser.add_argument("--consent-reference", required=True)
    parser.add_argument("--retention-class", required=True)
    parser.add_argument("--platform", choices=sorted(PLATFORMS), required=True)
    parser.add_argument("--microphone", required=True)
    parser.add_argument("--room", required=True)
    parser.add_argument("--distance-cm", type=float, required=True)
    parser.add_argument("--language", required=True)
    parser.add_argument("--accent", required=True)
    parser.add_argument("--noise-profile", required=True)
    args = parser.parse_args()
    output_dir = args.output_dir.expanduser().resolve()
    manifest_path = args.manifest_out.expanduser().resolve()
    if manifest_path.parent != output_dir:
        raise SystemExit("--manifest-out must be inside --output-dir")
    spec = ConsentedEnrollmentImport(
        dataset_version=args.dataset_version,
        created_at=args.created_at,
        captured_at=args.captured_at,
        fixture_id=args.fixture_id,
        audio_file_name=args.audio_file_name,
        subject_id=args.subject_id,
        session_id=args.session_id,
        partition=args.partition,
        consent_reference=args.consent_reference,
        retention_class=args.retention_class,
        platform=args.platform,
        microphone=args.microphone,
        room=args.room,
        distance_cm=args.distance_cm,
        language=args.language,
        accent=args.accent,
        noise_profile=args.noise_profile,
    )
    manifest = import_consented_enrollment(
        spec,
        source_audio_path=args.source_audio,
        output_dir=output_dir,
    )
    write_json(manifest_path, manifest)
    load_benchmark_manifest_fragment(manifest_path)


if __name__ == "__main__":
    main()
