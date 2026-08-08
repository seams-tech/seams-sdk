from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from benchmark import load_benchmark_manifest
from freeze_corpus import CorpusFreezeError, freeze_corpus, write_immutable_json


class FreezeCorpusTest(unittest.TestCase):
    def test_freezes_multiple_subject_disjoint_sources_deterministically(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            first = write_source_manifest(root / "first", "development", "dev_subject")
            second = write_source_manifest(root / "second", "evaluation", "eval_subject")
            output_dir = root / "frozen"

            manifest, report = freeze_corpus(
                (second, first),
                dataset_version="voiceid-frozen-v1",
                created_at="2026-07-26T00:00:00Z",
                output_dir=output_dir,
            )
            manifest_path = output_dir / "voiceid-benchmark-manifest.json"
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

            validated = load_benchmark_manifest(manifest_path)
            self.assertEqual(
                [entry.partition for entry in validated.entries],
                ["development", "evaluation"],
            )
            self.assertEqual(report["fixtureCount"], 2)
            self.assertEqual(
                report["partitionCounts"],
                {"development": 1, "evaluation": 1},
            )
            self.assertEqual(len(report["corpusTreeSha256"]), 64)

    def test_rejects_duplicate_fixture_ids_across_sources(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            first = write_source_manifest(root / "first", "development", "subject_one")
            second = write_source_manifest(root / "second", "evaluation", "subject_two")
            second_value = json.loads(second.read_text(encoding="utf-8"))
            second_value["entries"][0]["fixtureId"] = "development_subject_one"
            second.write_text(json.dumps(second_value), encoding="utf-8")

            with self.assertRaisesRegex(CorpusFreezeError, "duplicated"):
                freeze_corpus(
                    (first, second),
                    dataset_version="voiceid-frozen-v1",
                    created_at="2026-07-26T00:00:00Z",
                    output_dir=root / "frozen",
                )

    def test_manifest_writer_is_idempotent_and_rejects_mutation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            path = Path(temporary_directory) / "manifest.json"
            write_immutable_json(path, {"value": 1})
            write_immutable_json(path, {"value": 1})
            with self.assertRaisesRegex(CorpusFreezeError, "immutable output collision"):
                write_immutable_json(path, {"value": 2})


def write_source_manifest(root: Path, partition: str, subject_id: str) -> Path:
    root.mkdir(parents=True)
    audio_name = f"{partition}_{subject_id}.wav"
    audio_path = root / audio_name
    audio = b"RIFF" + bytes(range(256)) * 8
    audio_path.write_bytes(audio)
    entry = {
        "fixtureId": f"{partition}_{subject_id}",
        "audioFileName": audio_name,
        "audioSha256": hashlib.sha256(audio).hexdigest(),
        "subjectId": subject_id,
        "sessionId": f"{partition}_{subject_id}_session",
        "partition": partition,
        "case": {"kind": "enrollment"},
        "expectedIntent": None,
        "challengeTokens": [],
        "capture": {
            "platform": "server",
            "microphone": "digital_generation",
            "room": "none",
            "distanceCm": 0,
            "codec": "pcm_s16le",
            "sampleRateHz": 16000,
            "channelCount": 1,
            "language": "en",
            "accent": "synthetic",
            "noiseProfile": "none",
        },
        "capturedAt": "2026-07-26T00:00:00Z",
        "durationMs": 1000,
        "byteLength": len(audio),
        "mimeType": "audio/wav",
        "provenance": {
            "kind": "synthetic_generation",
            "generator": "other",
            "model": "test",
            "voice": subject_id,
            "seed": 1,
            "license": "test",
            "requestHash": hashlib.sha256(subject_id.encode()).hexdigest(),
            "conditioning": None,
        },
    }
    manifest_path = root / "manifest.json"
    manifest_path.write_text(
        json.dumps(
            {
                "schemaVersion": "voice_id_benchmark_manifest_v2",
                "datasetVersion": f"{partition}-source",
                "createdAt": "2026-07-26T00:00:00Z",
                "entries": [entry],
            }
        ),
        encoding="utf-8",
    )
    return manifest_path


if __name__ == "__main__":
    unittest.main()
