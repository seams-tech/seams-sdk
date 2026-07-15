from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Literal, Sequence

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
class AudioClaims:
    mime_type: str
    duration_ms: int
    sample_rate_hz: int | None
    channel_count: int | None


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

    def evaluate_audio(self, audio_bytes: bytes, claims: AudioClaims) -> EvaluatedAudio:
        return evaluate_decoded_input(audio_bytes=audio_bytes, claims=claims)

    def extract_verification_embedding(self, decoded_audio: DecodedAudio) -> ExtractedSpeakerEmbedding:
        return self.extractor.extract_decoded(decoded_audio.samples)

    def extract_window_embedding(self, samples: Sequence[float]) -> ExtractedSpeakerEmbedding:
        return self.extractor.extract_decoded(samples)

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

    def evaluate_audio(self, audio_bytes: bytes, claims: AudioClaims) -> EvaluatedAudio:
        return evaluate_decoded_input(audio_bytes=audio_bytes, claims=claims)

    def extract_verification_embedding(self, decoded_audio: DecodedAudio) -> ExtractedSpeakerEmbedding:
        return self.extractor.extract_decoded(decoded_audio.samples)

    def extract_window_embedding(self, samples: Sequence[float]) -> ExtractedSpeakerEmbedding:
        return self.extractor.extract_decoded(samples)

VerifierRuntime = PlaceholderVerifierRuntime | SpeechBrainEcapaVerifierRuntime


def evaluate_decoded_input(*, audio_bytes: bytes, claims: AudioClaims) -> EvaluatedAudio:
    if len(audio_bytes) == 0:
        return EvaluatedAudio(
            quality=evaluate_audio_quality(audio_bytes, claims.duration_ms),
            decoded_audio=None,
        )
    try:
        decoded_audio = decode_audio_bytes(audio_bytes)
    except AudioDecodeError:
        return EvaluatedAudio(
            quality=AudioQuality(
                kind="uncertain",
                duration_ms=claims.duration_ms,
                reason="undecodable_audio",
            ),
            decoded_audio=None,
        )
    if audio_claims_mismatch(claims=claims, decoded_audio=decoded_audio):
        return EvaluatedAudio(
            quality=AudioQuality(
                kind="uncertain",
                duration_ms=decoded_audio.decoded_duration_ms,
                reason="metadata_mismatch",
            ),
            decoded_audio=decoded_audio,
        )
    return EvaluatedAudio(
        quality=evaluate_decoded_audio_quality(
            audio_bytes,
            decoded_audio.decoded_duration_ms,
            samples=decoded_audio.samples,
            sample_rate_hz=decoded_audio.sample_rate_hz,
        ),
        decoded_audio=decoded_audio,
    )


def audio_claims_mismatch(*, claims: AudioClaims, decoded_audio: DecodedAudio) -> bool:
    duration_tolerance_ms = max(750, round(decoded_audio.source_duration_ms * 0.1))
    if abs(claims.duration_ms - decoded_audio.source_duration_ms) > duration_tolerance_ms:
        return True
    if claims.sample_rate_hz is not None and claims.sample_rate_hz != decoded_audio.source_sample_rate_hz:
        return True
    if claims.channel_count is not None and claims.channel_count != decoded_audio.source_channel_count:
        return True
    return decoded_audio.source_codec not in allowed_codecs_for_mime_type(claims.mime_type)


def allowed_codecs_for_mime_type(mime_type: str) -> frozenset[str]:
    normalized = mime_type.split(";", maxsplit=1)[0].strip().lower()
    codecs_by_mime_type = {
        "audio/webm": frozenset({"opus", "vorbis"}),
        "audio/ogg": frozenset({"opus", "vorbis", "flac"}),
        "audio/wav": frozenset({"pcm_s16le", "pcm_s24le", "pcm_s32le", "pcm_f32le"}),
        "audio/wave": frozenset({"pcm_s16le", "pcm_s24le", "pcm_s32le", "pcm_f32le"}),
        "audio/x-wav": frozenset({"pcm_s16le", "pcm_s24le", "pcm_s32le", "pcm_f32le"}),
        "audio/mp4": frozenset({"aac", "alac", "opus"}),
        "audio/mpeg": frozenset({"mp3"}),
    }
    return codecs_by_mime_type.get(normalized, frozenset())


def create_verifier_runtime_from_env() -> VerifierRuntime:
    backend = os.environ.get("VOICEID_VERIFIER_BACKEND", "placeholder").strip().lower()
    if backend == "placeholder":
        return PlaceholderVerifierRuntime()
    if backend == "ecapa":
        return SpeechBrainEcapaVerifierRuntime()
    raise RuntimeError("VOICEID_VERIFIER_BACKEND must be 'placeholder' or 'ecapa'")
