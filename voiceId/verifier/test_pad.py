from __future__ import annotations

import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from voiceid_verifier.pad import (
    AASIST_SAMPLE_COUNT,
    classify_pad_score,
    load_aasist_model_class,
    prepare_aasist_samples,
    validate_thresholds,
)


class AasistPadTest(unittest.TestCase):
    def test_prepares_exact_deterministic_aasist_input(self) -> None:
        prepared = prepare_aasist_samples([0.25, -0.25, 0.5])

        self.assertEqual(len(prepared), AASIST_SAMPLE_COUNT)
        self.assertEqual(list(prepared[:6]), [0.25, -0.25, 0.5, 0.25, -0.25, 0.5])

    def test_classifies_rejected_uncertain_and_accepted_regions(self) -> None:
        rejected = decision(0.20)
        uncertain = decision(0.50)
        accepted = decision(0.80)

        self.assertEqual(rejected.kind, "rejected")
        self.assertEqual(rejected.reason, "presentation_attack")
        self.assertEqual(uncertain.kind, "uncertain")
        self.assertEqual(uncertain.reason, "model_low_confidence")
        self.assertEqual(accepted.kind, "accepted")
        self.assertIsNone(accepted.reason)

    def test_rejects_overlapping_threshold_regions(self) -> None:
        with self.assertRaisesRegex(ValueError, "less than"):
            validate_thresholds(0.6, 0.6)

    def test_loads_verified_source_without_mutating_its_directory(self) -> None:
        with TemporaryDirectory() as directory:
            source_path = Path(directory) / "AASIST.py"
            source_path.write_text("class Model:\n    pass\n", encoding="utf-8")

            model_class = load_aasist_model_class(source_path)

            self.assertEqual(model_class.__name__, "Model")
            self.assertEqual(
                sorted(path.name for path in Path(directory).iterdir()),
                ["AASIST.py"],
            )


def decision(score: float):
    return classify_pad_score(
        score=score,
        reject_threshold=0.35,
        accept_threshold=0.65,
        model_version="test-pad",
        calibration_version="test-calibration",
        latency_ms=10.0,
    )


if __name__ == "__main__":
    unittest.main()
