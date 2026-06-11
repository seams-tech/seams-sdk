from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

import numpy as np

from compare_models import FixtureManifestEntry, load_fixture_inventory
from evaluate_speechbrain_ecapa import (
    ADAPTER_ID,
    ExtractedEmbedding,
    evaluate_speechbrain_ecapa,
    render_speechbrain_report,
)


class SpeechBrainEcapaEvaluationTest(unittest.TestCase):
    def test_evaluates_fixture_inventory_with_injected_extractor(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            manifest_path = write_manifest(
                root,
                [
                    fixture_entry("enroll_1", "enroll-1.webm", "owner", "owner_enrollment"),
                    fixture_entry("enroll_2", "enroll-2.webm", "owner", "owner_enrollment"),
                    fixture_entry("verify_1", "verify-1.webm", "owner", "owner_verification"),
                    fixture_entry("other_1", "other-1.webm", "speaker_2", "different_speaker"),
                    fixture_entry("wrong_1", "wrong-1.webm", "owner", "wrong_phrase"),
                ],
            )
            inventory = load_fixture_inventory(manifest_path)
            vectors = {
                "enroll_1": vector(1.0, 0.0, 0.0),
                "enroll_2": vector(0.98, 0.02, 0.0),
                "verify_1": vector(0.99, 0.01, 0.0),
                "other_1": vector(0.05, 0.95, 0.0),
                "wrong_1": vector(0.98, 0.02, 0.0),
            }

            report = evaluate_speechbrain_ecapa(
                inventory,
                extractor=lambda entry: fake_extract(entry, vectors),
            )
            rendered = render_speechbrain_report(report)

            self.assertEqual(report.adapter_id, ADAPTER_ID)
            self.assertEqual(report.threshold.false_accepts, 0)
            self.assertEqual(report.threshold.false_rejects, 0)
            self.assertIn("SpeechBrain ECAPA", rendered)
            self.assertIn("speechbrain/spkrec-ecapa-voxceleb", rendered)


def fake_extract(
    entry: FixtureManifestEntry,
    vectors: dict[str, np.ndarray],
) -> ExtractedEmbedding:
    return ExtractedEmbedding(embedding=vectors[entry.fixture_id], latency_ms=5.0)


def write_manifest(root: Path, entries: list[dict[str, object]]) -> Path:
    for entry in entries:
        (root / str(entry["audioFileName"])).write_bytes(b"voice" * 300)
    manifest_path = root / "voiceid-fixture-manifest.json"
    manifest_path.write_text(
        json.dumps(
            {
                "schemaVersion": "voice_id_fixture_manifest_v1",
                "createdAt": "2026-06-09T00:01:00.000Z",
                "entries": entries,
            }
        ),
        encoding="utf-8",
    )
    return manifest_path


def fixture_entry(
    fixture_id: str,
    audio_file_name: str,
    speaker_label: str,
    expected_relation: str,
) -> dict[str, object]:
    return {
        "fixtureId": fixture_id,
        "audioFileName": audio_file_name,
        "speakerLabel": speaker_label,
        "phraseLabel": "Walking on clouds",
        "expectedRelation": expected_relation,
        "captureDevice": "browser microphone",
        "durationMs": 1800,
        "environmentNotes": "test fixture",
        "capturedAt": "2026-06-09T00:00:00.000Z",
        "byteLength": len(b"voice" * 300),
        "mimeType": "audio/webm",
    }


def vector(*values: float) -> np.ndarray:
    return np.asarray(values, dtype=np.float64)


if __name__ == "__main__":
    unittest.main()
