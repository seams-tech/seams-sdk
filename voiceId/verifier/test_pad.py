from __future__ import annotations

import threading
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from voiceid_verifier.pad import (
    AASIST_SAMPLE_COUNT,
    AasistPadDetector,
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

    def test_zeroes_adapter_owned_pcm_and_model_tensors(self) -> None:
        torch = FakeTorch()
        model = FakeModel()
        detector = object.__new__(AasistPadDetector)
        detector._torch = torch
        detector._device = "cpu"
        detector._model = model
        detector._lock = threading.Lock()
        detector.reject_threshold = 0.35
        detector.accept_threshold = 0.65
        detector.calibration_version = "test-calibration"

        result = detector.analyze([0.25, -0.25, 0.5])

        self.assertEqual(result.kind, "accepted")
        retained_tensors = (*torch.tensor_references, *torch.softmax_references, *model.outputs)
        self.assertEqual(len(retained_tensors), 4)
        self.assertTrue(
            all(all(value == 0.0 for value in tensor.values) for tensor in retained_tensors)
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


class FakeInferenceMode:
    def __enter__(self) -> None:
        return None

    def __exit__(self, *args: object) -> None:
        return None


class FakeTensor:
    def __init__(self, values: list[float]) -> None:
        self.values = values

    def unsqueeze(self, dimension: int) -> FakeTensor:
        return self

    def __getitem__(self, index: object) -> FakeTensor:
        return self

    def item(self) -> float:
        return self.values[0]

    def zero_(self) -> None:
        for index in range(len(self.values)):
            self.values[index] = 0.0


class FakeTorch:
    float32 = "float32"

    def __init__(self) -> None:
        self.tensor_references: list[FakeTensor] = []
        self.softmax_references: list[FakeTensor] = []

    def tensor(
        self,
        values: object,
        *,
        dtype: object,
        device: object,
    ) -> FakeTensor:
        tensor = FakeTensor(list(values))
        self.tensor_references.append(tensor)
        return tensor

    def inference_mode(self) -> FakeInferenceMode:
        return FakeInferenceMode()

    def softmax(self, logits: FakeTensor, *, dim: int) -> FakeTensor:
        tensor = FakeTensor([0.9])
        self.softmax_references.append(tensor)
        return tensor


class FakeModel:
    def __init__(self) -> None:
        self.outputs: list[FakeTensor] = []

    def __call__(self, input_tensor: FakeTensor) -> tuple[FakeTensor, FakeTensor]:
        features = FakeTensor([0.1, 0.2])
        logits = FakeTensor([0.1, 0.9])
        self.outputs.extend((features, logits))
        return features, logits


if __name__ == "__main__":
    unittest.main()
