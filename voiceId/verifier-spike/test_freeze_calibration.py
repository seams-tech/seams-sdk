from __future__ import annotations

import hashlib
import json
import struct
import tempfile
import unittest
import wave
from pathlib import Path

from freeze_calibration import CalibrationFreezeError, freeze_calibration


class FreezeCalibrationTest(unittest.TestCase):
    def test_freezes_all_decisions_with_report_bindings(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            corpus = write_corpus(root)
            model = root / "model.json"
            model.write_text(json.dumps({"artifacts": [{"id": "moonshine-tiny"}]}), encoding="utf-8")
            model_hash = hashlib.sha256(model.read_bytes()).hexdigest()
            corpus_hash = hashlib.sha256(corpus.read_bytes()).hexdigest()
            suite = root / "suite.json"
            suite.write_text(json.dumps(suite_value(corpus_hash, model_hash)), encoding="utf-8")
            budgets = root / "budgets.json"
            budgets.write_text(json.dumps(budgets_value(model_hash)), encoding="utf-8")
            budget_check = root / "budget-check.json"
            budget_check.write_text(json.dumps(budget_check_value(model_hash)), encoding="utf-8")
            result = freeze_calibration(
                corpus_manifest_path=corpus,
                suite_path=suite,
                budgets_path=budgets,
                budget_check_path=budget_check,
                model_manifest_path=model,
                output_path=root / "calibration.json",
                created_at="2026-07-31T00:00:00Z",
            )
            self.assertEqual(result["intent"]["threshold"], 0.75)
            self.assertEqual(result["speaker"]["threshold"], 0.63)
            self.assertEqual(result["pad"]["calibrationVersion"], "pad-v1")
            self.assertEqual(result["retryPolicy"]["maximumQualityRetries"], 1)
            self.assertTrue(result["releaseBudget"]["passed"])
            resumed = freeze_calibration(
                corpus_manifest_path=corpus,
                suite_path=suite,
                budgets_path=budgets,
                budget_check_path=budget_check,
                model_manifest_path=model,
                output_path=root / "calibration.json",
                created_at="2026-07-31T00:00:00Z",
            )
            self.assertEqual(resumed, result)

    def test_rejects_suite_without_frozen_inventory(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            corpus = write_corpus(root)
            model = root / "model.json"
            model.write_text(json.dumps({"artifacts": [{"id": "model"}]}), encoding="utf-8")
            model_hash = hashlib.sha256(model.read_bytes()).hexdigest()
            suite = root / "suite.json"
            suite.write_text(
                json.dumps(
                    {
                        "schemaVersion": "voice_id_benchmark_suite_v1",
                        "datasetVersion": "fixture-v1",
                        "corpusManifestSha256": hashlib.sha256(corpus.read_bytes()).hexdigest(),
                        "modelManifestSha256": model_hash,
                        "inventory": {"measurementReady": False},
                    }
                ),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(CalibrationFreezeError, "measurement-ready"):
                freeze_calibration(
                    corpus_manifest_path=corpus,
                    suite_path=suite,
                    budgets_path=root / "budgets.json",
                    budget_check_path=root / "budget-check.json",
                    model_manifest_path=model,
                    output_path=root / "calibration.json",
                    created_at="2026-07-31T00:00:00Z",
                )


def suite_value(corpus_hash: str, model_hash: str) -> dict[str, object]:
    return {
        "schemaVersion": "voice_id_benchmark_suite_v1",
        "datasetVersion": "fixture-v1",
        "corpusManifestSha256": corpus_hash,
        "modelManifestSha256": model_hash,
        "inventory": {"measurementReady": True},
        "moonshine": {"modelArch": "tiny_streaming", "intentThreshold": 0.75, "intentMargin": 0.1},
        "ecapa": {"modelVersion": "ecapa-v1", "threshold": 0.63},
        "aasist": {
            "raw": {
                "modelVersion": "aasist-v1",
                "rejectThreshold": 0.2,
                "acceptThreshold": 0.7,
                "targetApcer": 0.01,
                "targetBpcer": 0.1,
            },
            "evaluation": {"padCalibrationVersion": "pad-v1"},
        },
    }


def budgets_value(model_hash: str) -> dict[str, object]:
    return {
        "schemaVersion": "voice_id_benchmark_budgets_v1",
        "datasetVersion": "fixture-v1",
        "modelManifestSha256": model_hash,
        "moonshine": {},
        "ecapa": {},
        "aasist": {},
    }


def budget_check_value(model_hash: str) -> dict[str, object]:
    return {
        "schemaVersion": "voice_id_benchmark_budget_check_v1",
        "datasetVersion": "fixture-v1",
        "modelManifestSha256": model_hash,
        "passed": True,
        "violations": [],
    }


def write_corpus(root: Path) -> Path:
    audio_path = root / "fixture.wav"
    pcm = struct.pack("<16000h", *([1000] * 16000))
    with audio_path.open("wb") as raw_output:
        with wave.open(raw_output, "wb") as output:
            output.setnchannels(1)
            output.setsampwidth(2)
            output.setframerate(16000)
            output.writeframes(pcm)
    audio = audio_path.read_bytes()
    entry = {
        "fixtureId": "development_subject_enrollment",
        "audioFileName": audio_path.name,
        "audioSha256": hashlib.sha256(audio).hexdigest(),
        "subjectId": "development_subject",
        "sessionId": "development_session",
        "partition": "development",
        "case": {"kind": "enrollment"},
        "expectedIntent": None,
        "challengeTokens": [],
        "capture": {
            "platform": "server", "microphone": "fixture", "room": "none",
            "distanceCm": 0, "codec": "pcm_s16le", "sampleRateHz": 16000,
            "channelCount": 1, "language": "en", "accent": "synthetic",
            "noiseProfile": "none",
        },
        "capturedAt": "2026-07-31T00:00:00Z",
        "durationMs": 1000,
        "byteLength": len(audio),
        "mimeType": "audio/wav",
        "provenance": {
            "kind": "synthetic_generation", "generator": "other", "model": "fixture",
            "voice": "development_subject", "seed": 1, "license": "test",
            "requestHash": hashlib.sha256(b"fixture").hexdigest(), "conditioning": None,
        },
    }
    manifest = root / "corpus.json"
    manifest.write_text(
        json.dumps({
            "schemaVersion": "voice_id_benchmark_manifest_v2",
            "datasetVersion": "fixture-v1", "createdAt": "2026-07-31T00:00:00Z",
            "entries": [entry],
        }),
        encoding="utf-8",
    )
    return manifest


if __name__ == "__main__":
    unittest.main()
