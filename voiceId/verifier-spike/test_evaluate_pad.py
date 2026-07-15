from __future__ import annotations

import unittest

from evaluate_pad import PadEvaluationError, evaluate_pad, parse_pad_manifest


class PadEvaluationTest(unittest.TestCase):
    def test_reports_fail_closed_pad_rates_by_attack_class_and_capture_profile(self) -> None:
        report = evaluate_pad(parse_pad_manifest(manifest_entries([
            entry("bona_1", "evaluation_owner", "bona_fide", None, 0.90, "browser"),
            entry("bona_2", "evaluation_owner", "bona_fide", None, 0.70, "browser"),
            entry("replay_1", "attacker_1", "attack", "replay", 0.85, "browser"),
            entry("replay_2", "attacker_2", "attack", "replay", 0.50, "robot"),
            entry("synth_1", "attacker_3", "attack", "synthesis", 0.70, "browser"),
        ])))

        self.assertEqual(report.bpcer.errors, 1)
        self.assertEqual(report.apcer.errors, 1)
        self.assertEqual(report.apcer.trials, 3)
        self.assertEqual(report.uncertainty.errors, 2)
        self.assertEqual(report.apcer_by_attack_class["replay"].errors, 1)
        self.assertFalse(report.release_ready)
        self.assertIn("digital_injection", report.missing_attack_classes)

    def test_rejects_subject_overlap_between_development_and_evaluation(self) -> None:
        value = manifest_entries([
            entry("development_1", "subject_1", "bona_fide", None, 0.9, "browser", "development"),
            entry("evaluation_1", "subject_1", "bona_fide", None, 0.9, "browser"),
        ])

        with self.assertRaisesRegex(PadEvaluationError, "subjects must be disjoint"):
            parse_pad_manifest(value)

    def test_rejects_attack_without_an_exact_attack_class(self) -> None:
        value = manifest_entries([
            entry("attack_1", "attacker_1", "attack", "unknown_attack", 0.1, "browser"),
        ])

        with self.assertRaisesRegex(PadEvaluationError, "attackClass is invalid"):
            parse_pad_manifest(value)


def manifest_entries(entries: list[dict[str, object]]) -> dict[str, object]:
    return {
        "schemaVersion": "voice_id_pad_evaluation_v1",
        "datasetManifestVersion": "pad-dataset-2026-07",
        "modelVersion": "pad-model-1",
        "padCalibrationVersion": "pad-calibration-1",
        "rejectThreshold": 0.60,
        "acceptThreshold": 0.80,
        "entries": entries,
    }


def entry(
    fixture_id: str,
    subject_id: str,
    presentation: str,
    attack_class: str | None,
    pad_score: float,
    capture_profile: str,
    partition: str = "evaluation",
) -> dict[str, object]:
    return {
        "fixtureId": fixture_id,
        "subjectId": subject_id,
        "sessionId": f"session_{fixture_id}",
        "partition": partition,
        "presentation": presentation,
        "attackClass": attack_class,
        "captureProfile": capture_profile,
        "padScore": pad_score,
        "latencyMs": 12.0,
    }


if __name__ == "__main__":
    unittest.main()
