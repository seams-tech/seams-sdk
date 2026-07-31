from __future__ import annotations

import unittest
from pathlib import Path

from calibrate_moonshine import (
    Candidate,
    IntentObservation,
    MoonshineCalibrationError,
    calibrate_candidates,
    classify_observation,
)


class MoonshineCalibrationTest(unittest.TestCase):
    def test_margin_returns_ambiguous_intent_as_uncertain(self) -> None:
        observation = intent_observation(
            fixture_id="ambiguous",
            partition="calibration",
            expected_kind="uncertain",
            confidence=0.88,
            runner_up_confidence=0.84,
        )

        self.assertEqual(
            classify_observation(observation, threshold=0.8, margin=0.1),
            "uncertain",
        )

    def test_selects_candidate_with_best_held_out_accuracy_inside_budgets(self) -> None:
        tiny = candidate(
            "tiny_streaming",
            (
                intent_observation("cal_good", "calibration", "accepted", 0.9, 0.2),
                intent_observation("cal_amb", "calibration", "uncertain", 0.85, 0.82),
                intent_observation("eval_good", "evaluation", "accepted", 0.9, 0.2),
                intent_observation("eval_amb", "evaluation", "uncertain", 0.86, 0.84),
            ),
            complete_p95_ms=700,
        )
        small = candidate(
            "small_streaming",
            (
                intent_observation("cal_good", "calibration", "accepted", 0.9, 0.2),
                intent_observation("cal_amb", "calibration", "uncertain", 0.9, 0.1),
                intent_observation("eval_good", "evaluation", "accepted", 0.9, 0.2),
                intent_observation("eval_amb", "evaluation", "uncertain", 0.9, 0.1),
            ),
            complete_p95_ms=750,
        )

        selected, calibration, evaluation = calibrate_candidates(
            (small, tiny),
            maximum_complete_p95_ms=1_000,
            maximum_peak_rss_bytes=1_000_000_000,
        )

        self.assertEqual(selected.model_arch, "tiny_streaming")
        self.assertEqual(calibration.accuracy, 1.0)
        self.assertEqual(evaluation.accuracy, 1.0)
        self.assertEqual(evaluation.unauthorized_acceptance_rate, 0.0)

    def test_fails_when_all_candidates_exceed_runtime_budget(self) -> None:
        slow = candidate(
            "small_streaming",
            (
                intent_observation("cal", "calibration", "accepted", 0.9, 0.1),
                intent_observation("eval", "evaluation", "accepted", 0.9, 0.1),
            ),
            complete_p95_ms=1_500,
        )

        with self.assertRaisesRegex(MoonshineCalibrationError, "runtime budgets"):
            calibrate_candidates(
                (slow,),
                maximum_complete_p95_ms=1_000,
                maximum_peak_rss_bytes=1_000_000_000,
            )


def intent_observation(
    fixture_id: str,
    partition: str,
    expected_kind: str,
    confidence: float,
    runner_up_confidence: float,
) -> IntentObservation:
    return IntentObservation(
        fixture_id=fixture_id,
        partition=partition,
        expected_kind=expected_kind,
        expected_intent="approve",
        matched_intent="approve",
        confidence=confidence,
        runner_up_confidence=runner_up_confidence,
    )


def candidate(
    model_arch: str,
    observations: tuple[IntentObservation, ...],
    *,
    complete_p95_ms: float,
) -> Candidate:
    return Candidate(
        path=Path(f"{model_arch}.json"),
        model_arch=model_arch,
        complete_p95_ms=complete_p95_ms,
        peak_rss_bytes=800_000_000,
        observations=observations,
    )


if __name__ == "__main__":
    unittest.main()
