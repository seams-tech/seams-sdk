from __future__ import annotations

import unittest
from dataclasses import dataclass

from voiceid_verifier.moonshine import MoonshineRecognizer, normalize_transcript


@dataclass(frozen=True)
class FakeLine:
    text: str


@dataclass(frozen=True)
class FakeTranscript:
    lines: tuple[FakeLine, ...]


@dataclass(frozen=True)
class FakeMatch:
    canonical_phrase: str
    similarity: float


class FakeTranscriber:
    last_sample_rate: int | None = None

    def __init__(self, *args: object, **kwargs: object) -> None:
        return

    def transcribe_without_streaming(self, samples: list[float], sample_rate: int) -> FakeTranscript:
        self.last_sample_rate = sample_rate
        if len(samples) == 0:
            return FakeTranscript(lines=())
        return FakeTranscript(lines=(FakeLine("Please approve this transfer"),))


class EmptyTranscriber(FakeTranscriber):
    def transcribe_without_streaming(self, samples: list[float], sample_rate: int) -> FakeTranscript:
        return FakeTranscript(lines=())


class FakeIntentRecognizer:
    def __init__(self, *args: object, **kwargs: object) -> None:
        self.registered: list[str] = []

    def clear_intents(self) -> None:
        self.registered = []

    def register_intent(self, canonical_phrase: str) -> None:
        self.registered.append(canonical_phrase)

    def get_closest_intents(self, utterance: str, tolerance_threshold: float) -> list[FakeMatch]:
        if not self.registered:
            return []
        canonical_phrase = 'approve' if 'approve' in self.registered else self.registered[0]
        return [FakeMatch(canonical_phrase=canonical_phrase, similarity=0.91)]


class MoonshineRecognizerTest(unittest.TestCase):
    def test_uses_canonical_pcm_and_separates_semantic_intent_from_exact_phrase(self) -> None:
        recognizer = MoonshineRecognizer(
            model_path="tiny",
            model_arch="tiny_streaming",
            intent_model_path="intent",
            transcriber_factory=FakeTranscriber,
            intent_factory=FakeIntentRecognizer,
        )
        result = recognizer.analyze(
            [0.1, -0.1],
            expected_phrase="approve transfer",
            intent_name="approve",
        )

        self.assertEqual(result.sample_rate_hz, 16000)
        self.assertEqual(result.intent.kind, "accepted")
        self.assertEqual(result.intent.intent, "approve")
        self.assertEqual(result.phrase.kind, "accepted")
        self.assertNotEqual(result.phrase.expected_normalized, result.phrase.spoken_normalized)
        self.assertEqual(normalize_transcript("Approve, transfer!"), "approve transfer")

    def test_empty_transcript_is_uncertain_and_not_an_intent_rejection(self) -> None:
        recognizer = MoonshineRecognizer(
            model_path="tiny",
            model_arch="tiny_streaming",
            intent_model_path="intent",
            transcriber_factory=EmptyTranscriber,
            intent_factory=FakeIntentRecognizer,
        )
        result = recognizer.analyze(
            [0.1],
            expected_phrase="approve transfer",
            intent_name="approve",
        )

        self.assertEqual(result.phrase.kind, "uncertain")
        self.assertEqual(result.intent.kind, "uncertain")


if __name__ == "__main__":
    unittest.main()
