from __future__ import annotations

import sys
import unittest
from unittest.mock import patch

from voiceid_verifier.embeddings import SpeechBrainEcapaEmbeddingExtractor


class FakeNoGrad:
    def __enter__(self) -> None:
        return None

    def __exit__(self, *args: object) -> None:
        return None


class FakeTensor:
    def __init__(self, values: list[float]) -> None:
        self.values = values

    def unsqueeze(self, dimension: int) -> FakeTensor:
        return self

    def detach(self) -> FakeTensor:
        return self

    def cpu(self) -> FakeTensor:
        return self

    def reshape(self, dimension: int) -> FakeTensor:
        return self

    def tolist(self) -> list[float]:
        return list(self.values)

    def zero_(self) -> None:
        for index in range(len(self.values)):
            self.values[index] = 0.0


class FakeTorch:
    float32 = "float32"

    def __init__(self) -> None:
        self.waveforms: list[FakeTensor] = []

    def tensor(self, samples: object, *, dtype: object) -> FakeTensor:
        tensor = FakeTensor(list(samples))
        self.waveforms.append(tensor)
        return tensor

    def no_grad(self) -> FakeNoGrad:
        return FakeNoGrad()


class FakeClassifier:
    def __init__(self) -> None:
        self.embeddings: list[FakeTensor] = []

    def encode_batch(self, waveform: FakeTensor) -> FakeTensor:
        tensor = FakeTensor([0.25, -0.5, 0.75])
        self.embeddings.append(tensor)
        return tensor


class SpeechBrainEcapaEmbeddingExtractorTest(unittest.TestCase):
    def test_zeroes_adapter_owned_waveform_and_embedding_tensors(self) -> None:
        torch = FakeTorch()
        classifier = FakeClassifier()
        extractor = SpeechBrainEcapaEmbeddingExtractor(classifier=classifier)

        with patch.dict(sys.modules, {"torch": torch}):
            result = extractor.extract_decoded([0.1, -0.2, 0.3])

        self.assertEqual(result.vector, [0.25, -0.5, 0.75])
        self.assertTrue(all(value == 0.0 for value in torch.waveforms[0].values))
        self.assertTrue(all(value == 0.0 for value in classifier.embeddings[0].values))


if __name__ == "__main__":
    unittest.main()
