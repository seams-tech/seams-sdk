from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Literal

from voiceid_verifier.audio_decode import AudioDecodeError, DecodedAudio, decode_audio_bytes
from voiceid_verifier.audio_quality import AudioQuality, evaluate_audio_quality, evaluate_decoded_audio_quality
from voiceid_verifier.embeddings import (
    ECAPA_ADAPTER_ID,
    ECAPA_MODEL_ID,
    ECAPA_MODEL_VERSION,
    ECAPA_TEMPLATE_VERSION,
    ECAPA_THRESHOLD_VERSION,
    PLACEHOLDER_MODEL_VERSION,
    PLACEHOLDER_TEMPLATE_VERSION,
    PLACEHOLDER_THRESHOLD_VERSION,
    ExtractedSpeakerEmbedding,
    PlaceholderEmbeddingExtractor,
    SpeechBrainEcapaEmbeddingExtractor,
)


VerifierBackend = Literal["placeholder", "ecapa"]


@dataclass(frozen=True)
class VerifierRuntimeMetadata:
    backend: VerifierBackend
    adapter_id: str
    model_id: str
    model_version: str
    threshold_version: str
    template_version: str
    embedding_dimensions: int


@dataclass(frozen=True)
class EvaluatedAudio:
    quality: AudioQuality
    decoded_audio: DecodedAudio | None


class PlaceholderVerifierRuntime:
    metadata = VerifierRuntimeMetadata(
        backend="placeholder",
        adapter_id="python-placeholder",
        model_id="python-placeholder",
        model_version=PLACEHOLDER_MODEL_VERSION,
        threshold_version=PLACEHOLDER_THRESHOLD_VERSION,
        template_version=PLACEHOLDER_TEMPLATE_VERSION,
        embedding_dimensions=PlaceholderEmbeddingExtractor.embedding_dimensions,
    )

    def __init__(self) -> None:
        self.extractor = PlaceholderEmbeddingExtractor()

    def evaluate_audio(self, audio_bytes: bytes, duration_ms: int) -> EvaluatedAudio:
        return EvaluatedAudio(
            quality=evaluate_audio_quality(audio_bytes, duration_ms),
            decoded_audio=None,
        )

    def extract_embedding(self, audio_bytes: bytes, decoded_audio: DecodedAudio | None) -> ExtractedSpeakerEmbedding:
        return self.extractor.extract(audio_bytes)

    def zero_embedding(self) -> ExtractedSpeakerEmbedding:
        return self.extractor.zero_embedding()


class SpeechBrainEcapaVerifierRuntime:
    def __init__(
        self,
        *,
        extractor: SpeechBrainEcapaEmbeddingExtractor | None = None,
    ) -> None:
        self.extractor = extractor or SpeechBrainEcapaEmbeddingExtractor()
        self.metadata = VerifierRuntimeMetadata(
            backend="ecapa",
            adapter_id=ECAPA_ADAPTER_ID,
            model_id=ECAPA_MODEL_ID,
            model_version=ECAPA_MODEL_VERSION,
            threshold_version=ECAPA_THRESHOLD_VERSION,
            template_version=ECAPA_TEMPLATE_VERSION,
            embedding_dimensions=self.extractor.embedding_dimensions,
        )

    def evaluate_audio(self, audio_bytes: bytes, duration_ms: int) -> EvaluatedAudio:
        if len(audio_bytes) == 0:
            return EvaluatedAudio(
                quality=evaluate_audio_quality(audio_bytes, duration_ms),
                decoded_audio=None,
            )
        try:
            decoded_audio = decode_audio_bytes(audio_bytes)
        except AudioDecodeError:
            return EvaluatedAudio(
                quality=AudioQuality(kind="uncertain", duration_ms=duration_ms, reason="undecodable_audio"),
                decoded_audio=None,
            )
        return EvaluatedAudio(
            quality=evaluate_decoded_audio_quality(
                audio_bytes,
                duration_ms,
                samples=decoded_audio.samples,
                sample_rate_hz=decoded_audio.sample_rate_hz,
            ),
            decoded_audio=decoded_audio,
        )

    def extract_embedding(self, audio_bytes: bytes, decoded_audio: DecodedAudio | None) -> ExtractedSpeakerEmbedding:
        if decoded_audio is None:
            decoded_audio = decode_audio_bytes(audio_bytes)
        return self.extractor.extract_decoded(decoded_audio.samples)

    def zero_embedding(self) -> ExtractedSpeakerEmbedding:
        return self.extractor.zero_embedding()


VerifierRuntime = PlaceholderVerifierRuntime | SpeechBrainEcapaVerifierRuntime


def create_verifier_runtime_from_env() -> VerifierRuntime:
    backend = os.environ.get("VOICEID_VERIFIER_BACKEND", "placeholder").strip().lower()
    if backend == "placeholder":
        return PlaceholderVerifierRuntime()
    if backend == "ecapa":
        return SpeechBrainEcapaVerifierRuntime()
    raise RuntimeError("VOICEID_VERIFIER_BACKEND must be 'placeholder' or 'ecapa'")
