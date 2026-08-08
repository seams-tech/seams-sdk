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
        self.closed = False

    def transcribe_without_streaming(
        self,
        samples: list[float],
        sample_rate: int,
    ) -> FakeTranscript:
        self.last_sample_rate = sample_rate
        if len(samples) == 0:
            return FakeTranscript(lines=())
        return FakeTranscript(lines=(FakeLine("Please approve this transfer"),))

    def close(self) -> None:
        self.closed = True


class EmptyTranscriber(FakeTranscriber):
    def transcribe_without_streaming(
        self,
        samples: list[float],
        sample_rate: int,
    ) -> FakeTranscript:
        return FakeTranscript(lines=())


class InspectingTranscriber(FakeTranscriber):
    instances: list[InspectingTranscriber] = []
    sample_references: list[list[float]] = []

    def __init__(self, *args: object, **kwargs: object) -> None:
        super().__init__(*args, **kwargs)
        self.instances.append(self)

    def transcribe_without_streaming(
        self,
        samples: list[float],
        sample_rate: int,
    ) -> FakeTranscript:
        self.sample_references.append(samples)
        return super().transcribe_without_streaming(samples, sample_rate)


class StatefulTranscriber(FakeTranscriber):
    instances: list[StatefulTranscriber] = []

    def __init__(self, *args: object, **kwargs: object) -> None:
        super().__init__(*args, **kwargs)
        self.instances.append(self)
        self.previous_signature: float | None = None

    def transcribe_without_streaming(
        self,
        samples: list[float],
        sample_rate: int,
    ) -> FakeTranscript:
        signature = samples[0]
        contaminated = (
            self.previous_signature is not None
            and self.previous_signature != signature
        )
        self.previous_signature = signature
        suffix = " contaminated" if contaminated else ""
        return FakeTranscript(
            lines=(FakeLine(f"Please approve this transfer{suffix}"),)
        )


class FailingTranscriber(FakeTranscriber):
    instances: list[FailingTranscriber] = []
    sample_references: list[list[float]] = []

    def __init__(self, *args: object, **kwargs: object) -> None:
        super().__init__(*args, **kwargs)
        self.instances.append(self)

    def transcribe_without_streaming(
        self,
        samples: list[float],
        sample_rate: int,
    ) -> FakeTranscript:
        self.sample_references.append(samples)
        raise RuntimeError("injected transcription failure")


class FakeIntentRecognizer:
    def __init__(self, *args: object, **kwargs: object) -> None:
        self.registered: list[str] = []

    def register_intent(self, canonical_phrase: str) -> None:
        self.registered.append(canonical_phrase)

    def get_closest_intents(self, utterance: str, tolerance_threshold: float) -> list[FakeMatch]:
        if not self.registered:
            return []
        canonical_phrase = next(
            (phrase for phrase in self.registered if phrase.startswith("approve")),
            self.registered[0],
        )
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
            challenge_tokens=("approve", "transfer"),
        )

        self.assertEqual(result.sample_rate_hz, 16000)
        self.assertEqual(result.intent.kind, "accepted")
        self.assertEqual(result.intent.intent, "approve")
        self.assertEqual(result.phrase.kind, "accepted")
        self.assertEqual(result.transcript, "please approve this transfer")
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
            challenge_tokens=("approve", "transfer"),
        )

        self.assertEqual(result.phrase.kind, "uncertain")
        self.assertEqual(result.intent.kind, "uncertain")

    def test_accepts_fresh_challenge_tokens_in_any_order(self) -> None:
        recognizer = MoonshineRecognizer(
            model_path="tiny",
            model_arch="tiny_streaming",
            intent_model_path="intent",
            transcriber_factory=ReorderedTokenTranscriber,
            intent_factory=FakeIntentRecognizer,
        )

        result = recognizer.analyze(
            [0.1],
            expected_phrase="approve this request maple eight star",
            intent_name="approve",
            challenge_tokens=("maple", "eight", "star"),
        )

        self.assertEqual(result.phrase.kind, "accepted")
        self.assertEqual(result.intent.kind, "accepted")

    def test_rejects_semantically_correct_utterance_missing_a_fresh_token(self) -> None:
        recognizer = MoonshineRecognizer(
            model_path="tiny",
            model_arch="tiny_streaming",
            intent_model_path="intent",
            transcriber_factory=MissingTokenTranscriber,
            intent_factory=FakeIntentRecognizer,
        )

        result = recognizer.analyze(
            [0.1],
            expected_phrase="approve this request maple eight star",
            intent_name="approve",
            challenge_tokens=("maple", "eight", "star"),
        )

        self.assertEqual(result.phrase.kind, "rejected")
        self.assertEqual(result.intent.kind, "accepted")

    def test_zeroes_the_transcriber_pcm_copy_after_every_terminal_result(self) -> None:
        InspectingTranscriber.instances.clear()
        InspectingTranscriber.sample_references.clear()
        recognizer = MoonshineRecognizer(
            model_path="tiny",
            model_arch="tiny_streaming",
            intent_model_path="intent",
            transcriber_factory=InspectingTranscriber,
            intent_factory=FakeIntentRecognizer,
        )

        result = recognizer.analyze(
            [0.1, -0.2, 0.3],
            expected_phrase="approve transfer",
            intent_name="approve",
            challenge_tokens=("approve", "transfer"),
        )

        self.assertEqual(result.phrase.kind, "accepted")
        self.assertEqual(len(InspectingTranscriber.sample_references), 1)
        self.assertTrue(
            all(value == 0.0 for value in InspectingTranscriber.sample_references[0])
        )
        self.assertEqual(len(InspectingTranscriber.instances), 2)
        self.assertTrue(
            all(transcriber.closed for transcriber in InspectingTranscriber.instances)
        )

    def test_uses_a_fresh_native_transcriber_handle_for_every_request(self) -> None:
        StatefulTranscriber.instances.clear()
        recognizer = MoonshineRecognizer(
            model_path="tiny",
            model_arch="tiny_streaming",
            intent_model_path="intent",
            transcriber_factory=StatefulTranscriber,
            intent_factory=FakeIntentRecognizer,
        )

        first_a = recognizer.analyze(
            [0.1],
            expected_phrase="approve transfer",
            intent_name="approve",
            challenge_tokens=("approve", "transfer"),
        )
        recognizer.analyze(
            [-0.1],
            expected_phrase="approve transfer",
            intent_name="approve",
            challenge_tokens=("approve", "transfer"),
        )
        second_a = recognizer.analyze(
            [0.1],
            expected_phrase="approve transfer",
            intent_name="approve",
            challenge_tokens=("approve", "transfer"),
        )

        self.assertEqual(first_a, second_a)
        self.assertEqual(len(StatefulTranscriber.instances), 4)
        self.assertTrue(
            all(transcriber.closed for transcriber in StatefulTranscriber.instances)
        )

    def test_closes_the_handle_and_zeroes_pcm_after_transcription_failure(self) -> None:
        FailingTranscriber.instances.clear()
        FailingTranscriber.sample_references.clear()
        recognizer = MoonshineRecognizer(
            model_path="tiny",
            model_arch="tiny_streaming",
            intent_model_path="intent",
            transcriber_factory=FailingTranscriber,
            intent_factory=FakeIntentRecognizer,
        )

        with self.assertRaisesRegex(RuntimeError, "injected transcription failure"):
            recognizer.analyze(
                [0.1, -0.2],
                expected_phrase="approve transfer",
                intent_name="approve",
                challenge_tokens=("approve", "transfer"),
            )

        self.assertEqual(len(FailingTranscriber.instances), 2)
        self.assertTrue(
            all(transcriber.closed for transcriber in FailingTranscriber.instances)
        )
        self.assertTrue(
            all(value == 0.0 for value in FailingTranscriber.sample_references[0])
        )

    def test_registers_the_closed_intent_set_once_and_reuses_it(self) -> None:
        recognizer = MoonshineRecognizer(
            model_path="tiny",
            model_arch="tiny_streaming",
            intent_model_path="intent",
            transcriber_factory=FakeTranscriber,
            intent_factory=FakeIntentRecognizer,
        )
        intent_recognizer = recognizer._intent_recognizer
        initially_registered = tuple(intent_recognizer.registered)

        first = recognizer.analyze(
            [0.1],
            expected_phrase="approve transfer",
            intent_name="approve",
            challenge_tokens=("approve", "transfer"),
        )
        second = recognizer.analyze(
            [0.1],
            expected_phrase="approve transfer",
            intent_name="approve",
            challenge_tokens=("approve", "transfer"),
        )

        self.assertEqual(first, second)
        self.assertEqual(tuple(intent_recognizer.registered), initially_registered)
        self.assertEqual(len(initially_registered), 5)

    def test_rejects_intents_outside_the_closed_set(self) -> None:
        recognizer = MoonshineRecognizer(
            model_path="tiny",
            model_arch="tiny_streaming",
            intent_model_path="intent",
            transcriber_factory=FakeTranscriber,
            intent_factory=FakeIntentRecognizer,
        )

        with self.assertRaisesRegex(ValueError, "closed intent set"):
            recognizer.analyze(
                [0.1],
                expected_phrase="transfer funds",
                intent_name="transfer_funds",
                challenge_tokens=("transfer", "funds"),
            )


class ReorderedTokenTranscriber(FakeTranscriber):
    def transcribe_without_streaming(
        self,
        samples: list[float],
        sample_rate: int,
    ) -> FakeTranscript:
        return FakeTranscript(
            lines=(FakeLine("Please approve this request. Star maple eight."),)
        )


class MissingTokenTranscriber(FakeTranscriber):
    def transcribe_without_streaming(
        self,
        samples: list[float],
        sample_rate: int,
    ) -> FakeTranscript:
        return FakeTranscript(
            lines=(FakeLine("Please approve this request. Maple star."),)
        )


if __name__ == "__main__":
    unittest.main()
