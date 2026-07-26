from __future__ import annotations

import re
import threading
from collections import Counter
from dataclasses import dataclass
from typing import Any, Callable, Literal, Mapping, Sequence

from voiceid_verifier.audio_decode import zero_float_sequence


CANONICAL_SAMPLE_RATE_HZ = 16000
MODEL_ARCHES = {
    "tiny_streaming": 2,
    "small_streaming": 4,
}
DEFAULT_INTENT_PHRASES = {
    "approve": "approve this request",
    "reject": "reject this request",
    "cancel": "cancel this request",
    "repeat": "repeat the challenge",
    "unrelated": "unrelated statement",
}


MoonshinePhraseKind = Literal["accepted", "uncertain", "rejected"]
MoonshineIntentKind = Literal["accepted", "uncertain", "rejected"]


@dataclass(frozen=True)
class MoonshinePhraseDecision:
    kind: MoonshinePhraseKind
    expected_normalized: str
    spoken_normalized: str
    confidence: float
    reason: str | None

    def to_json(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "expectedNormalized": self.expected_normalized,
            "spokenNormalized": self.spoken_normalized,
            "confidence": self.confidence,
            "reason": self.reason,
        }


@dataclass(frozen=True)
class MoonshineIntentDecision:
    kind: MoonshineIntentKind
    intent: str | None
    canonical_phrase: str | None
    confidence: float
    runner_up_intent: str | None
    runner_up_confidence: float
    reason: str | None

    def to_json(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "intent": self.intent,
            "canonicalPhrase": self.canonical_phrase,
            "confidence": self.confidence,
            "reason": self.reason,
        }


@dataclass(frozen=True)
class MoonshineSpeechAnalysis:
    transcript: str
    phrase: MoonshinePhraseDecision
    intent: MoonshineIntentDecision
    sample_rate_hz: int

    def to_json(self) -> dict[str, Any]:
        return {
            "kind": "speech_analysis",
            "requestId": "embedded",
            "transcript": self.transcript,
            "phrase": self.phrase.to_json(),
            "intent": self.intent.to_json(),
            "sampleRateHz": self.sample_rate_hz,
        }


class MoonshineRecognizer:
    """Run transcript and semantic intent recognition over one canonical PCM buffer."""

    def __init__(
        self,
        *,
        model_path: str,
        model_arch: str,
        intent_model_path: str,
        intent_threshold: float = 0.8,
        intent_margin: float = 0.1,
        intent_phrases: Mapping[str, str] | None = None,
        transcriber_factory: Callable[..., Any] | None = None,
        intent_factory: Callable[..., Any] | None = None,
    ) -> None:
        if model_arch not in MODEL_ARCHES:
            raise ValueError("model_arch must be tiny_streaming or small_streaming")
        if not 0 <= intent_threshold <= 1:
            raise ValueError("intent_threshold must be between 0 and 1")
        if not 0 <= intent_margin <= 1:
            raise ValueError("intent_margin must be between 0 and 1")
        factories = load_moonshine_factories(transcriber_factory, intent_factory)
        self._transcriber_factory = factories.transcriber
        self._model_path = model_path
        self._model_arch_value = model_arch_for_constructor(
            model_arch,
            transcriber_factory,
        )
        readiness_transcriber = self._new_transcriber()
        readiness_transcriber.close()
        self._intent_recognizer = factories.intent(
            intent_model_path,
            threshold=intent_threshold,
            model_variant="q4",
        )
        self._intent_threshold = intent_threshold
        self._intent_margin = intent_margin
        self._intent_phrases = dict(intent_phrases or DEFAULT_INTENT_PHRASES)
        validate_intent_phrases(self._intent_phrases)
        for canonical_phrase in self._intent_phrases.values():
            self._intent_recognizer.register_intent(canonical_phrase)
        self._lock = threading.Lock()

    def analyze(
        self,
        samples: Sequence[float],
        *,
        expected_phrase: str,
        intent_name: str,
        challenge_tokens: Sequence[str],
    ) -> MoonshineSpeechAnalysis:
        with self._lock:
            return self._analyze_locked(
                samples,
                expected_phrase=expected_phrase,
                intent_name=intent_name,
                challenge_tokens=challenge_tokens,
            )

    def _analyze_locked(
        self,
        samples: Sequence[float],
        *,
        expected_phrase: str,
        intent_name: str,
        challenge_tokens: Sequence[str],
    ) -> MoonshineSpeechAnalysis:
        if len(samples) == 0:
            raise ValueError("canonical PCM samples must not be empty")
        if expected_phrase.strip() == "" or intent_name.strip() == "":
            raise ValueError("expected_phrase and intent_name must be non-empty")
        if intent_name not in self._intent_phrases:
            raise ValueError("intent_name must belong to the closed intent set")
        normalized_challenge_tokens = tuple(
            normalize_transcript(token)
            for token in challenge_tokens
        )
        if len(normalized_challenge_tokens) == 0 or any(
            token == "" or " " in token
            for token in normalized_challenge_tokens
        ):
            raise ValueError("challenge_tokens must contain normalized non-empty tokens")
        raw_transcript = self._transcribe(samples)
        transcript = normalize_transcript(raw_transcript)
        spoken_normalized = transcript
        expected_normalized = normalize_transcript(expected_phrase)
        matches = self._intent_matches(transcript)
        phrase = build_phrase_decision(
            expected_normalized=expected_normalized,
            spoken_normalized=spoken_normalized,
            challenge_tokens=normalized_challenge_tokens,
        )
        intent = build_intent_decision(
            intent_name,
            matches,
            self._intent_threshold,
            self._intent_margin,
            self._intent_phrases,
        )
        return MoonshineSpeechAnalysis(
            transcript=transcript,
            phrase=phrase,
            intent=intent,
            sample_rate_hz=CANONICAL_SAMPLE_RATE_HZ,
        )

    def _transcribe(self, samples: Sequence[float]) -> str:
        transcriber_samples = list(samples)
        transcriber = None
        try:
            transcriber = self._new_transcriber()
            result = transcriber.transcribe_without_streaming(
                transcriber_samples,
                sample_rate=CANONICAL_SAMPLE_RATE_HZ,
            )
            lines = getattr(result, "lines", ())
            return " ".join(
                str(getattr(line, "text", "")).strip()
                for line in lines
                if str(getattr(line, "text", "")).strip()
            ).strip()
        finally:
            try:
                if transcriber is not None:
                    transcriber.close()
            finally:
                zero_float_sequence(transcriber_samples)

    def _new_transcriber(self) -> Any:
        return self._transcriber_factory(
            self._model_path,
            model_arch=self._model_arch_value,
            update_interval=0.5,
        )

    def _intent_matches(self, transcript: str) -> Sequence[Any]:
        if transcript == "":
            return ()
        return self._intent_recognizer.get_closest_intents(
            transcript,
            tolerance_threshold=self._intent_threshold,
        )


@dataclass(frozen=True)
class MoonshineFactories:
    transcriber: Callable[..., Any]
    intent: Callable[..., Any]


def load_moonshine_factories(
    transcriber_factory: Callable[..., Any] | None,
    intent_factory: Callable[..., Any] | None,
) -> MoonshineFactories:
    if transcriber_factory is not None and intent_factory is not None:
        return MoonshineFactories(transcriber_factory, intent_factory)
    if transcriber_factory is not None or intent_factory is not None:
        raise ValueError("transcriber_factory and intent_factory must be provided together")
    try:
        from moonshine_voice import IntentRecognizer, Transcriber
    except ImportError as exc:
        raise RuntimeError("moonshine-voice is required for Moonshine recognition") from exc
    return MoonshineFactories(Transcriber, IntentRecognizer)


def model_arch_for_constructor(model_arch: str, transcriber_factory: Callable[..., Any] | None) -> Any:
    if transcriber_factory is not None:
        return MODEL_ARCHES[model_arch]
    from moonshine_voice import ModelArch

    return ModelArch(MODEL_ARCHES[model_arch])


def normalize_transcript(value: str) -> str:
    return " ".join(re.findall(r"[a-z0-9]+", value.lower()))


def validate_intent_phrases(intent_phrases: Mapping[str, str]) -> None:
    if len(intent_phrases) == 0:
        raise ValueError("intent_phrases must not be empty")
    normalized_phrases = tuple(
        normalize_transcript(phrase)
        for phrase in intent_phrases.values()
    )
    if any(name.strip() == "" for name in intent_phrases):
        raise ValueError("intent names must be non-empty")
    if any(phrase == "" for phrase in normalized_phrases):
        raise ValueError("canonical intent phrases must be non-empty")
    if len(set(normalized_phrases)) != len(normalized_phrases):
        raise ValueError("canonical intent phrases must be unique")


def build_phrase_decision(
    *,
    expected_normalized: str,
    spoken_normalized: str,
    challenge_tokens: Sequence[str],
) -> MoonshinePhraseDecision:
    if spoken_normalized == "":
        return MoonshinePhraseDecision(
            kind="uncertain",
            expected_normalized=expected_normalized,
            spoken_normalized=spoken_normalized,
            confidence=0.0,
            reason="transcript_unavailable",
        )
    expected_counts = Counter(challenge_tokens)
    spoken_counts = Counter(spoken_normalized.split())
    matched_count = sum(
        min(expected_count, spoken_counts[token])
        for token, expected_count in expected_counts.items()
    )
    expected_count = sum(expected_counts.values())
    coverage = matched_count / expected_count
    if coverage == 1:
        return MoonshinePhraseDecision(
            kind="accepted",
            expected_normalized=expected_normalized,
            spoken_normalized=spoken_normalized,
            confidence=coverage,
            reason=None,
        )
    return MoonshinePhraseDecision(
        kind="rejected",
        expected_normalized=expected_normalized,
        spoken_normalized=spoken_normalized,
        confidence=coverage,
        reason="phrase_mismatch",
    )


def build_intent_decision(
    expected_intent: str,
    matches: Sequence[Any],
    threshold: float,
    margin: float,
    intent_phrases: Mapping[str, str],
) -> MoonshineIntentDecision:
    if not matches:
        return MoonshineIntentDecision(
            kind="uncertain",
            intent=None,
            canonical_phrase=None,
            confidence=0.0,
            runner_up_intent=None,
            runner_up_confidence=0.0,
            reason="intent_unavailable",
        )
    match = matches[0]
    canonical_phrase = str(getattr(match, "canonical_phrase", ""))
    confidence = float(getattr(match, "similarity", 0.0))
    runner_up_confidence = (
        float(getattr(matches[1], "similarity", 0.0))
        if len(matches) > 1
        else 0.0
    )
    matched_intent = intent_name_for_canonical_phrase(canonical_phrase, intent_phrases)
    runner_up_intent = (
        intent_name_for_canonical_phrase(
            str(getattr(matches[1], "canonical_phrase", "")),
            intent_phrases,
        )
        if len(matches) > 1
        else None
    )
    if confidence < threshold or confidence - runner_up_confidence < margin:
        return MoonshineIntentDecision(
            kind="uncertain",
            intent=matched_intent,
            canonical_phrase=canonical_phrase or None,
            confidence=confidence,
            runner_up_intent=runner_up_intent,
            runner_up_confidence=runner_up_confidence,
            reason="intent_low_confidence",
        )
    if matched_intent == expected_intent:
        return MoonshineIntentDecision(
            kind="accepted",
            intent=expected_intent,
            canonical_phrase=canonical_phrase,
            confidence=confidence,
            runner_up_intent=runner_up_intent,
            runner_up_confidence=runner_up_confidence,
            reason=None,
        )
    return MoonshineIntentDecision(
        kind="rejected",
        intent=matched_intent,
        canonical_phrase=canonical_phrase or None,
        confidence=confidence,
        runner_up_intent=runner_up_intent,
        runner_up_confidence=runner_up_confidence,
        reason="intent_mismatch",
    )


def intent_name_for_canonical_phrase(
    canonical_phrase: str,
    intent_phrases: Mapping[str, str],
) -> str | None:
    for intent_name, phrase in intent_phrases.items():
        if phrase == canonical_phrase:
            return intent_name
    return None
