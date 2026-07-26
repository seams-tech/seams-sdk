from __future__ import annotations

import argparse
import hashlib
import json
import shutil
from collections import Counter
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

from benchmark import (
    SCHEMA_VERSION,
    load_benchmark_manifest,
    load_benchmark_manifest_fragment,
)


FREEZE_REPORT_SCHEMA_VERSION = "voice_id_corpus_freeze_report_v1"


class CorpusFreezeError(ValueError):
    pass


@dataclass(frozen=True)
class SourceEntry:
    value: dict[str, Any]
    audio_path: Path


def freeze_corpus(
    manifest_paths: tuple[Path, ...],
    *,
    dataset_version: str,
    created_at: str,
    output_dir: Path,
) -> tuple[dict[str, Any], dict[str, Any]]:
    if len(manifest_paths) == 0:
        raise CorpusFreezeError("at least one source manifest is required")
    require_iso_date_time(created_at)
    if dataset_version.strip() == "":
        raise CorpusFreezeError("dataset_version must be non-empty")
    entries = load_source_entries(manifest_paths)
    output_dir.mkdir(parents=True, exist_ok=True)
    frozen_entries = []
    for entry in sorted(entries, key=entry_sort_key):
        destination = output_dir / require_file_name(entry.value["audioFileName"])
        copy_immutable_audio(entry.audio_path, destination)
        frozen_entries.append(entry.value)
    manifest = {
        "schemaVersion": SCHEMA_VERSION,
        "datasetVersion": dataset_version,
        "createdAt": created_at,
        "entries": frozen_entries,
    }
    report = build_freeze_report(manifest_paths, manifest)
    return manifest, report


def load_source_entries(manifest_paths: tuple[Path, ...]) -> tuple[SourceEntry, ...]:
    source_entries: list[SourceEntry] = []
    fixture_ids: set[str] = set()
    audio_file_names: set[str] = set()
    for path in manifest_paths:
        manifest = load_benchmark_manifest_fragment(path)
        raw = json.loads(manifest.manifest_path.read_text(encoding="utf-8"))
        raw_entries = raw["entries"]
        if not isinstance(raw_entries, list):
            raise CorpusFreezeError("validated manifest entries must be an array")
        for value, parsed in zip(raw_entries, manifest.entries, strict=True):
            if not isinstance(value, dict):
                raise CorpusFreezeError("validated manifest entry must be an object")
            if parsed.fixture_id in fixture_ids:
                raise CorpusFreezeError(f"fixtureId {parsed.fixture_id} is duplicated")
            if parsed.audio_file_name in audio_file_names:
                raise CorpusFreezeError(
                    f"audioFileName {parsed.audio_file_name} is duplicated"
                )
            fixture_ids.add(parsed.fixture_id)
            audio_file_names.add(parsed.audio_file_name)
            source_entries.append(SourceEntry(value=value, audio_path=parsed.audio_path))
    return tuple(source_entries)


def copy_immutable_audio(source: Path, destination: Path) -> None:
    source_digest = sha256_file(source)
    if destination.exists():
        if sha256_file(destination) != source_digest:
            raise CorpusFreezeError(f"frozen audio collision: {destination.name}")
        return
    shutil.copy2(source, destination)
    if sha256_file(destination) != source_digest:
        raise CorpusFreezeError(f"frozen audio copy failed integrity check: {destination.name}")


def build_freeze_report(
    manifest_paths: tuple[Path, ...],
    manifest: dict[str, Any],
) -> dict[str, Any]:
    entries = manifest["entries"]
    if not isinstance(entries, list):
        raise CorpusFreezeError("frozen entries must be an array")
    partition_counts = Counter(str(entry["partition"]) for entry in entries)
    cohort_counts = Counter(cohort_for_entry(entry) for entry in entries)
    canonical_lines = tuple(
        f"{entry['fixtureId']}\t{entry['audioSha256']}\t{entry['partition']}\n"
        for entry in entries
    )
    return {
        "schemaVersion": FREEZE_REPORT_SCHEMA_VERSION,
        "datasetVersion": manifest["datasetVersion"],
        "createdAt": manifest["createdAt"],
        "sourceManifests": [
            {
                "path": str(path.expanduser().resolve()),
                "sha256": sha256_file(path.expanduser().resolve()),
            }
            for path in manifest_paths
        ],
        "fixtureCount": len(entries),
        "partitionCounts": dict(sorted(partition_counts.items())),
        "cohortCounts": dict(sorted(cohort_counts.items())),
        "corpusTreeSha256": hashlib.sha256(
            "".join(canonical_lines).encode("utf-8")
        ).hexdigest(),
    }


def cohort_for_entry(entry: dict[str, Any]) -> str:
    provenance = entry.get("provenance")
    if not isinstance(provenance, dict):
        raise CorpusFreezeError("entry provenance must be an object")
    if provenance.get("kind") == "consented_human_capture":
        return "real_human"
    if provenance.get("conditioning") is not None:
        return "owner_conditioned_clone"
    return "fictional_synthetic"


def entry_sort_key(entry: SourceEntry) -> tuple[int, str]:
    partition_order = {"development": 0, "calibration": 1, "evaluation": 2}
    partition = str(entry.value["partition"])
    if partition not in partition_order:
        raise CorpusFreezeError("entry partition is invalid")
    return partition_order[partition], str(entry.value["fixtureId"])


def require_file_name(value: object) -> str:
    if not isinstance(value, str) or value == "" or Path(value).name != value:
        raise CorpusFreezeError("audioFileName must be a file name")
    return value


def require_iso_date_time(value: str) -> None:
    normalized = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError as exc:
        raise CorpusFreezeError("created_at must be an ISO date-time") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise CorpusFreezeError("created_at must include a UTC offset")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Merge validated VoiceID corpus sources into one immutable frozen split."
    )
    parser.add_argument("--source-manifest", type=Path, action="append", required=True)
    parser.add_argument("--dataset-version", required=True)
    parser.add_argument("--created-at", required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--manifest-out", type=Path, required=True)
    parser.add_argument("--report-out", type=Path, required=True)
    args = parser.parse_args()
    if args.manifest_out.expanduser().resolve().parent != args.output_dir.expanduser().resolve():
        raise SystemExit("--manifest-out must be inside --output-dir")
    manifest, report = freeze_corpus(
        tuple(args.source_manifest),
        dataset_version=args.dataset_version,
        created_at=args.created_at,
        output_dir=args.output_dir,
    )
    write_json(args.manifest_out, manifest)
    write_json(args.report_out, report)
    load_benchmark_manifest(args.manifest_out)


if __name__ == "__main__":
    main()
