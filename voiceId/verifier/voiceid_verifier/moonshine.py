from __future__ import annotations

import re
import threading
from dataclasses import dataclass
from typing import Any, Callable, Literal, Mapping, Sequence


CANONICAL_SAMPLE_RATE_HZ = 16000
MODEL_ARCHES = {
    "tiny_streaming": 2,
    "small_streaming": 4,
}
DEFAULT_INTENT_PHRASES = {
    "approve": "approve",
    "reject": "reject",
    "cancel": "cancel",
    "repeat": "repeat",
    "unrelated": "unrelated",
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
        intent_phrases: Mapping[str, str] | None = None,
        transcriber_factory: Callable[..., Any] | None = None,
        intent_factory: Callable[..., Any] | None = None,
    ) -> None:
        if model_arch not in MODEL_ARCHES:
            raise ValueError("model_arch must be tiny_streaming or small_streaming")
        if not 0 <= intent_threshold <= 1:
            raise ValueError("intent_threshold must be between 0 and 1")
        factories = load_moonshine_factories(transcriber_factory, intent_factory)
        model_arch_value = model_arch_for_constructor(model_arch, transcriber_factory)
        self._transcriber = factories.transcriber(
            model_path,
            model_arch=model_arch_value,
            update_interval=0.5,
        )
        self._intent_recognizer = factories.intent(
            intent_model_path,
            threshold=intent_threshold,
            model_variant="q4",
        )
        self._intent_threshold = intent_threshold
        self._intent_phrases = dict(intent_phrases or DEFAULT_INTENT_PHRASES)
        self._lock = threading.Lock()

    def analyze(
        self,
        samples: Sequence[float],
        *,
        expected_phrase: str,
        intent_name: str,
    ) -> MoonshineSpeechAnalysis:
        with self._lock:
            return self._analyze_locked(
                samples,
                expected_phrase=expected_phrase,
                intent_name=intent_name,
            )

    def _analyze_locked(
        self,
        samples: Sequence[float],
        *,
        expected_phrase: str,
        intent_name: str,
    ) -> MoonshineSpeechAnalysis:
        if len(samples) == 0:
            raise ValueError("canonical PCM samples must not be empty")
        if expected_phrase.strip() == "" or intent_name.strip() == "":
            raise ValueError("expected_phrase and intent_name must be non-empty")
        transcript = self._transcribe(samples)
        spoken_normalized = normalize_transcript(transcript)
        expected_normalized = normalize_transcript(expected_phrase)
        matches = self._intent_matches(transcript, intent_name)
        phrase = build_phrase_decision(
            expected_normalized=expected_normalized,
            spoken_normalized=spoken_normalized,
            expected_intent=intent_name,
            matches=matches,
        )
        intent = build_intent_decision(
            intent_name,
            matches,
            self._intent_threshold,
            self._intent_phrases,
        )
        return MoonshineSpeechAnalysis(
            transcript=transcript,
            phrase=phrase,
            intent=intent,
            sample_rate_hz=CANONICAL_SAMPLE_RATE_HZ,
        )

    def _transcribe(self, samples: Sequence[float]) -> str:
        result = self._transcriber.transcribe_without_streaming(
            list(samples),
            sample_rate=CANONICAL_SAMPLE_RATE_HZ,
        )
        lines = getattr(result, "lines", ())
        return " ".join(
            str(getattr(line, "text", "")).strip()
            for line in lines
            if str(getattr(line, "text", "")).strip()
        ).strip()

    def _intent_matches(self, transcript: str, intent_name: str) -> Sequence[Any]:
        self._intent_recognizer.clear_intents()
        intent_phrases = dict(self._intent_phrases)
        intent_phrases.setdefault(intent_name, intent_name)
        for canonical_phrase in intent_phrases.values():
            self._intent_recognizer.register_intent(canonical_phrase)
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


def build_phrase_decision(
    *,
    expected_normalized: str,
    spoken_normalized: str,
    expected_intent: str,
    matches: Sequence[Any],
) -> MoonshinePhraseDecision:
    if spoken_normalized == "":
        return MoonshinePhraseDecision(
            kind="uncertain",
            expected_normalized=expected_normalized,
            spoken_normalized=spoken_normalized,
            confidence=0.0,
            reason="transcript_unavailable",
        )
    if spoken_normalized == expected_normalized:
        return MoonshinePhraseDecision(
            kind="accepted",
            expected_normalized=expected_normalized,
            spoken_normalized=spoken_normalized,
            confidence=1.0,
            reason=None,
        )
    if matches and getattr(matches[0], "canonical_phrase", "") == expected_intent:
        return MoonshinePhraseDecision(
            kind="accepted",
            expected_normalized=expected_normalized,
            spoken_normalized=spoken_normalized,
            confidence=float(getattr(matches[0], "similarity", 0.0)),
            reason=None,
        )
    return MoonshinePhraseDecision(
        kind="rejected",
        expected_normalized=expected_normalized,
        spoken_normalized=spoken_normalized,
        confidence=float(getattr(matches[0], "similarity", 0.0)) if matches else 0.0,
        reason="phrase_mismatch",
    )


def build_intent_decision(
    expected_intent: str,
    matches: Sequence[Any],
    threshold: float,
    intent_phrases: Mapping[str, str],
) -> MoonshineIntentDecision:
    if not matches:
        return MoonshineIntentDecision(
            kind="uncertain",
            intent=None,
            canonical_phrase=None,
            confidence=0.0,
            reason="intent_unavailable",
        )
    match = matches[0]
    canonical_phrase = str(getattr(match, "canonical_phrase", ""))
    confidence = float(getattr(match, "similarity", 0.0))
    matched_intent = intent_name_for_canonical_phrase(canonical_phrase, intent_phrases)
    if matched_intent == expected_intent and confidence >= threshold:
        return MoonshineIntentDecision(
            kind="accepted",
            intent=expected_intent,
            canonical_phrase=canonical_phrase,
            confidence=confidence,
            reason=None,
        )
    return MoonshineIntentDecision(
        kind="rejected",
        intent=matched_intent,
        canonical_phrase=canonical_phrase or None,
        confidence=confidence,
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
