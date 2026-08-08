from __future__ import annotations

import argparse
import hashlib
import json
import math
import random
import struct
import wave
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

from benchmark import load_benchmark_manifest_fragment


REPORT_SCHEMA_VERSION = "voice_id_corpus_transform_report_v1"
TRANSFORMS = ("replay", "codec", "noise", "room")
TARGET_SAMPLE_RATE_HZ = 16_000
TARGET_SNR_DB = 18.0
ROOM_DELAY_SAMPLES = 1_200


class CorpusAugmentationError(ValueError):
    pass


@dataclass(frozen=True)
class SourceAudio:
    fixture_id: str
    audio_path: Path
    audio_sha256: str
    entry: dict[str, Any]


def augment_manifest(
    manifest_path: Path,
    *,
    output_dir: Path,
    manifest_out: Path,
    report_out: Path,
    created_at: str,
    seed: int,
) -> dict[str, Any]:
    require_iso_date_time(created_at)
    source_manifest = load_benchmark_manifest_fragment(manifest_path)
    raw_manifest = json.loads(source_manifest.manifest_path.read_text(encoding="utf-8"))
    raw_entries = raw_manifest["entries"]
    output_root = output_dir.expanduser().resolve()
    output_root.mkdir(parents=True, exist_ok=True)
    sources = tuple(
        SourceAudio(
            fixture_id=parsed.fixture_id,
            audio_path=parsed.audio_path,
            audio_sha256=parsed.audio_sha256,
            entry=raw_entry,
        )
        for raw_entry, parsed in zip(raw_entries, source_manifest.entries, strict=True)
        if parsed.case.kind in {"genuine_verification", "challenge_error", "presentation_attack"}
    )
    if len(sources) == 0:
        raise CorpusAugmentationError(
            "source manifest must contain verification or presentation-attack entries"
        )

    entries: list[dict[str, Any]] = []
    bindings: list[dict[str, Any]] = []
    used_fixture_ids: set[str] = set()
    used_audio_names: set[str] = set()
    for source in sources:
        pcm, sample_rate_hz = read_pcm(source.audio_path)
        if sample_rate_hz != TARGET_SAMPLE_RATE_HZ:
            raise CorpusAugmentationError(
                f"{source.audio_path.name} must be canonical PCM16 at 16 kHz"
            )
        for transform_index, transform in enumerate(TRANSFORMS):
            transform_seed = seed + transform_index
            transformed = apply_transform(pcm, transform, transform_seed)
            fixture_id = f"{source.fixture_id}__{transform}"
            audio_name = f"{fixture_id}.wav"
            if fixture_id in used_fixture_ids or audio_name in used_audio_names:
                raise CorpusAugmentationError(f"derived fixture collision: {fixture_id}")
            used_fixture_ids.add(fixture_id)
            used_audio_names.add(audio_name)
            output_path = output_root / audio_name
            write_immutable_wav(output_path, transformed)
            audio_sha256 = sha256_file(output_path)
            entry = derived_entry(
                source.entry,
                fixture_id=fixture_id,
                audio_name=audio_name,
                audio_sha256=audio_sha256,
                byte_length=output_path.stat().st_size,
                transform=transform,
                source_sha256=source.audio_sha256,
            )
            entries.append(entry)
            bindings.append(
                {
                    "sourceFixtureId": source.fixture_id,
                    "sourceAudioSha256": source.audio_sha256,
                    "derivedFixtureId": fixture_id,
                    "derivedAudioSha256": audio_sha256,
                    "transform": transform,
                    "seed": transform_seed,
                }
            )

    manifest = {
        "schemaVersion": "voice_id_benchmark_manifest_v2",
        "datasetVersion": f"{source_manifest.dataset_version}-transforms-v1",
        "createdAt": created_at,
        "entries": entries,
    }
    manifest_out_path = manifest_out.expanduser().resolve()
    if manifest_out_path.parent != output_root:
        raise CorpusAugmentationError("manifest_out must be inside output_dir")
    write_immutable_json(manifest_out_path, manifest)
    load_benchmark_manifest_fragment(manifest_out_path)
    report = {
        "schemaVersion": REPORT_SCHEMA_VERSION,
        "sourceManifest": {
            "path": str(source_manifest.manifest_path),
            "sha256": sha256_file(source_manifest.manifest_path),
        },
        "datasetVersion": manifest["datasetVersion"],
        "transformCount": len(entries),
        "transforms": list(TRANSFORMS),
        "bindings": bindings,
    }
    write_immutable_json(report_out.expanduser().resolve(), report)
    return report


def derived_entry(
    source: dict[str, Any],
    *,
    fixture_id: str,
    audio_name: str,
    audio_sha256: str,
    byte_length: int,
    transform: str,
    source_sha256: str,
) -> dict[str, Any]:
    capture = dict(source["capture"])
    capture["microphone"] = f"{capture['microphone']}__{transform}"
    if transform == "codec":
        capture["codec"] = "pcm_s16le_quantized_codec_simulation"
    elif transform == "noise":
        capture["noiseProfile"] = "deterministic_white_noise_snr18db"
    elif transform == "room":
        capture["room"] = "deterministic_short_room_response"
    elif transform == "replay":
        capture["microphone"] = "acoustic_replay_simulation"
        capture["room"] = "deterministic_replay_room"
    return {
        "fixtureId": fixture_id,
        "audioFileName": audio_name,
        "audioSha256": audio_sha256,
        "subjectId": source["subjectId"],
        "sessionId": f"{source['sessionId']}__{transform}",
        "partition": source["partition"],
        "case": {
            "kind": "presentation_attack",
            "targetSubjectId": source["subjectId"],
            "attackClass": "replay",
            "attackTool": f"deterministic_{transform}_transform_v1",
        },
        "expectedIntent": source["expectedIntent"],
        "challengeTokens": list(source["challengeTokens"]),
        "capture": capture,
        "capturedAt": source["capturedAt"],
        "durationMs": source["durationMs"],
        "byteLength": byte_length,
        "mimeType": "audio/wav",
        "provenance": transformed_provenance(source["provenance"], source_sha256, transform),
    }


def transformed_provenance(
    provenance: dict[str, Any], source_sha256: str, transform: str
) -> dict[str, Any]:
    result = dict(provenance)
    request_hash = hashlib.sha256(
        json.dumps(
            {"source": source_sha256, "provenance": provenance, "transform": transform},
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()
    if result["kind"] == "synthetic_generation":
        result["requestHash"] = request_hash
    return result


def apply_transform(pcm: tuple[int, ...], transform: str, seed: int) -> bytes:
    if transform == "replay":
        return encode_samples(quantize_codec(room_response(pcm)))
    if transform == "codec":
        return encode_samples(quantize_codec(pcm))
    if transform == "noise":
        return encode_samples(add_noise(pcm, seed))
    if transform == "room":
        return encode_samples(room_response(pcm))
    raise CorpusAugmentationError(f"unknown transform: {transform}")


def read_pcm(path: Path) -> tuple[tuple[int, ...], int]:
    try:
        with wave.open(str(path), "rb") as source:
            channels = source.getnchannels()
            sample_width = source.getsampwidth()
            sample_rate_hz = source.getframerate()
            frame_count = source.getnframes()
            if channels != 1 or sample_width != 2:
                raise CorpusAugmentationError(f"{path.name} must be mono PCM16")
            return tuple(struct.unpack(f"<{frame_count}h", source.readframes(frame_count))), sample_rate_hz
    except (OSError, wave.Error, struct.error) as error:
        if isinstance(error, CorpusAugmentationError):
            raise
        raise CorpusAugmentationError(f"invalid source WAV: {path.name}") from error


def quantize_codec(pcm: tuple[int, ...]) -> tuple[int, ...]:
    return tuple(max(-32768, min(32767, round(sample / 256) * 256)) for sample in pcm)


def add_noise(pcm: tuple[int, ...], seed: int) -> tuple[int, ...]:
    rms = math.sqrt(sum(sample * sample for sample in pcm) / max(1, len(pcm)))
    noise_rms = rms / (10 ** (TARGET_SNR_DB / 20))
    generator = random.Random(seed)
    return tuple(
        max(-32768, min(32767, round(sample + generator.gauss(0.0, noise_rms))))
        for sample in pcm
    )


def room_response(pcm: tuple[int, ...]) -> tuple[int, ...]:
    result: list[int] = []
    for index, sample in enumerate(pcm):
        delayed = pcm[index - ROOM_DELAY_SAMPLES] if index >= ROOM_DELAY_SAMPLES else 0
        second_delayed = pcm[index - (ROOM_DELAY_SAMPLES * 2)] if index >= ROOM_DELAY_SAMPLES * 2 else 0
        result.append(max(-32768, min(32767, round(sample * 0.78 + delayed * 0.16 + second_delayed * 0.06))))
    return tuple(result)


def encode_samples(samples: tuple[int, ...]) -> bytes:
    if len(samples) == 0:
        raise CorpusAugmentationError("source audio is empty")
    return struct.pack(f"<{len(samples)}h", *samples)


def write_immutable_wav(path: Path, pcm: bytes) -> None:
    encoded = encode_wav(pcm)
    write_immutable_bytes(path, encoded)


def encode_wav(pcm: bytes) -> bytes:
    from io import BytesIO

    raw_output = BytesIO()
    with wave.open(raw_output, "wb") as output:
        output.setnchannels(1)
        output.setsampwidth(2)
        output.setframerate(TARGET_SAMPLE_RATE_HZ)
        output.writeframes(pcm)
    return raw_output.getvalue()


def write_immutable_json(path: Path, value: object) -> None:
    write_immutable_bytes(path, (json.dumps(value, indent=2) + "\n").encode("utf-8"))


def write_immutable_bytes(path: Path, encoded: bytes) -> None:
    if path.exists():
        if path.is_file() and path.read_bytes() == encoded:
            return
        raise CorpusAugmentationError(f"immutable output collision: {path.name}")
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("xb") as raw_output:
        raw_output.write(encoded)


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def require_iso_date_time(value: str) -> None:
    normalized = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError as error:
        raise CorpusAugmentationError("created_at must be an ISO date-time") from error
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise CorpusAugmentationError("created_at must include a UTC offset")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Create deterministic replay/codec/noise/room attack fixtures from a validated manifest."
    )
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--manifest-out", type=Path, required=True)
    parser.add_argument("--report-out", type=Path, required=True)
    parser.add_argument("--created-at", required=True)
    parser.add_argument("--seed", type=int, default=1)
    args = parser.parse_args()
    augment_manifest(
        args.manifest,
        output_dir=args.output_dir,
        manifest_out=args.manifest_out,
        report_out=args.report_out,
        created_at=args.created_at,
        seed=args.seed,
    )


if __name__ == "__main__":
    main()
