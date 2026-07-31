from __future__ import annotations

import unittest

from evaluate_pad import (
    PadEvaluationError,
    calibrate_pad_thresholds,
    classify_score,
    evaluate_pad,
    parse_pad_manifest,
    report_to_json,
)


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
        self.assertEqual(report.latency_ms.p95, 12.0)
        self.assertEqual(report_to_json(report)["latencyMs"]["p99"], 12.0)

    def test_rejects_subject_overlap_between_calibration_and_evaluation(self) -> None:
        value = manifest_entries([
            entry("calibration_1", "subject_1", "bona_fide", None, 0.9, "browser", "calibration"),
            entry("evaluation_1", "subject_1", "bona_fide", None, 0.9, "browser"),
        ])

        with self.assertRaisesRegex(PadEvaluationError, "subjects must be disjoint"):
            parse_pad_manifest(value)

    def test_calibrates_disjoint_accept_and_reject_regions(self) -> None:
        manifest = parse_pad_manifest(manifest_entries([
            entry("cal_bona_1", "cal_owner", "bona_fide", None, 0.92, "browser", "calibration"),
            entry("cal_bona_2", "cal_owner", "bona_fide", None, 0.86, "browser", "calibration"),
            entry("cal_attack_1", "cal_attack", "attack", "synthesis", 0.12, "browser", "calibration"),
            entry("cal_attack_2", "cal_attack", "attack", "replay", 0.20, "browser", "calibration"),
            entry("eval_bona", "eval_owner", "bona_fide", None, 0.90, "browser"),
            entry("eval_attack", "eval_attack", "attack", "synthesis", 0.10, "browser"),
        ]))

        reject_threshold, accept_threshold = calibrate_pad_thresholds(
            manifest.entries,
            target_apcer=0.0,
            target_bpcer=0.0,
        )

        self.assertEqual(
            classify_score(
                0.20,
                reject_threshold=reject_threshold,
                accept_threshold=accept_threshold,
            ),
            "rejected",
        )
        self.assertEqual(
            classify_score(
                0.86,
                reject_threshold=reject_threshold,
                accept_threshold=accept_threshold,
            ),
            "accepted",
        )

    def test_rejects_attack_without_an_exact_attack_class(self) -> None:
        value = manifest_entries([
            entry("attack_1", "attacker_1", "attack", "unknown_attack", 0.1, "browser"),
        ])

        with self.assertRaisesRegex(PadEvaluationError, "attackClass is invalid"):
            parse_pad_manifest(value)


def manifest_entries(entries: list[dict[str, object]]) -> dict[str, object]:
    return {
        "schemaVersion": "voice_id_pad_evaluation_v2",
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
