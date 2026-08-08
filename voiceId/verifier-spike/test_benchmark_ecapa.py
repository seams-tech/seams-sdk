from __future__ import annotations

import unittest

from benchmark_ecapa import (
    SpeakerObservation,
    calibrate_threshold,
    evaluate_threshold,
)


class EcapaBenchmarkTest(unittest.TestCase):
    def test_calibrates_on_calibration_and_reports_held_out_far_frr(self) -> None:
        calibration = (
            observation("cal_genuine_1", "calibration", "accepted", 0.91),
            observation("cal_genuine_2", "calibration", "accepted", 0.86),
            observation("cal_impostor_1", "calibration", "rejected", 0.35),
            observation("cal_impostor_2", "calibration", "rejected", 0.42),
        )
        threshold = calibrate_threshold(calibration)
        evaluation = (
            observation("eval_genuine_1", "evaluation", "accepted", 0.90),
            observation("eval_genuine_2", "evaluation", "accepted", 0.80),
            observation("eval_impostor_1", "evaluation", "rejected", 0.40),
            observation("eval_impostor_2", "evaluation", "rejected", 0.30),
        )

        metrics = evaluate_threshold(evaluation, threshold)

        self.assertEqual(metrics.false_acceptance.errors, 0)
        self.assertEqual(metrics.false_rejection.errors, 0)
        self.assertEqual(metrics.equal_error_rate, 0.0)


def observation(
    fixture_id: str,
    partition: str,
    expected_kind: str,
    score: float,
) -> SpeakerObservation:
    return SpeakerObservation(
        fixture_id=fixture_id,
        partition=partition,
        case_kind="genuine_verification",
        attack_class=None,
        expected_kind=expected_kind,
        score=score,
        latency_ms=10.0,
    )


if __name__ == "__main__":
    unittest.main()
