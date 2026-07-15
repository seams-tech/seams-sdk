from __future__ import annotations

import base64
import hashlib
import json
import struct
from dataclasses import dataclass
from typing import Literal

from voiceid_verifier.audio_decode import DecodedAudio, zero_float_sequence
from voiceid_verifier.audio_quality import AudioQuality, SpeechWindow, extract_speech_windows
from voiceid_verifier.embeddings import EmbeddingExtractionError, ExtractedSpeakerEmbedding
from voiceid_verifier.runtime import AudioClaims, VerifierRuntime
from voiceid_verifier.scoring import cosine_score


ANALYSIS_VERSION = "continuous-enrollment-v1"
MINIMUM_PROMPT_DURATION_MS = 3000
MINIMUM_SPEECH_PER_PROMPT_MS = 2000
MINIMUM_WINDOW_COHERENCE = 0.45
MULTI_SPEAKER_COHERENCE = 0.15

EnrollmentFailureReason = Literal[
    "decoder_failure",
    "metadata_mismatch",
    "interrupted_capture",
    "insufficient_speech",
    "insufficient_windows",
    "duplicate_windows",
    "multi_speaker",
    "clipped_audio",
    "low_snr",
    "incoherent_windows",
    "template_build_failed",
]


@dataclass(frozen=True)
class EnrollmentWindowSummary:
    index: int
    start_ms: int
    end_ms: int
    speech_ms: int
    signal_score: float
    template_weight: float


@dataclass(frozen=True)
class EnrollmentAnalysis:
    source_codec: str
    source_sample_rate_hz: int
    source_channel_count: int
    decoded_duration_ms: int
    usable_speech_ms: int
    windows: tuple[EnrollmentWindowSummary, ...]


@dataclass(frozen=True)
class BuiltEnrollment:
    kind: Literal["built"]
    encrypted_template: str
    quality: AudioQuality
    analysis: EnrollmentAnalysis


@dataclass(frozen=True)
class RejectedEnrollment:
    kind: Literal["rejected"]
    reason: EnrollmentFailureReason


EnrollmentResult = BuiltEnrollment | RejectedEnrollment


def build_continuous_enrollment(
    *,
    runtime: VerifierRuntime,
    audio_bytes: bytes,
    claims: AudioClaims,
    expected_prompt_count: int,
) -> EnrollmentResult:
    evaluated = runtime.evaluate_audio(audio_bytes, claims)
    decoded_audio = evaluated.decoded_audio
    windows: tuple[SpeechWindow, ...] = ()
    embeddings: list[ExtractedSpeakerEmbedding] = []
    try:
        quality_failure = failure_for_quality(evaluated.quality)
        if quality_failure is not None:
            return RejectedEnrollment(kind="rejected", reason=quality_failure)
        if decoded_audio is None:
            return RejectedEnrollment(kind="rejected", reason="decoder_failure")
        if decoded_audio.decoded_duration_ms < expected_prompt_count * MINIMUM_PROMPT_DURATION_MS:
            return RejectedEnrollment(kind="rejected", reason="interrupted_capture")

        windows = extract_speech_windows(
            samples=decoded_audio.samples,
            sample_rate_hz=decoded_audio.sample_rate_hz,
        )
        usable_speech_ms = sum(window.speech_ms for window in windows)
        if len(windows) < expected_prompt_count:
            return RejectedEnrollment(kind="rejected", reason="insufficient_windows")
        if usable_speech_ms < expected_prompt_count * MINIMUM_SPEECH_PER_PROMPT_MS:
            return RejectedEnrollment(kind="rejected", reason="insufficient_speech")
        if contains_duplicate_windows(windows):
            return RejectedEnrollment(kind="rejected", reason="duplicate_windows")

        try:
            embeddings = [runtime.extract_window_embedding(window.samples) for window in windows]
        except EmbeddingExtractionError:
            return RejectedEnrollment(kind="rejected", reason="template_build_failed")

        try:
            coherence_failure = failure_for_embedding_coherence(embeddings)
            if coherence_failure is not None:
                return RejectedEnrollment(kind="rejected", reason=coherence_failure)
            weights = normalized_window_weights(windows)
            template_embedding = weighted_average_embedding(embeddings, weights)
            try:
                encrypted_template = encode_template(
                    runtime=runtime,
                    template_embedding=template_embedding,
                    sample_count=len(embeddings),
                )
            finally:
                zero_float_sequence(template_embedding)
        except (EmbeddingExtractionError, ValueError):
            return RejectedEnrollment(kind="rejected", reason="template_build_failed")

        summaries = tuple(
            EnrollmentWindowSummary(
                index=index,
                start_ms=window.start_ms,
                end_ms=window.end_ms,
                speech_ms=window.speech_ms,
                signal_score=window.signal_score,
                template_weight=weights[index],
            )
            for index, window in enumerate(windows)
        )
        return BuiltEnrollment(
            kind="built",
            encrypted_template=encrypted_template,
            quality=evaluated.quality,
            analysis=EnrollmentAnalysis(
                source_codec=decoded_audio.source_codec,
                source_sample_rate_hz=decoded_audio.source_sample_rate_hz,
                source_channel_count=decoded_audio.source_channel_count,
                decoded_duration_ms=decoded_audio.decoded_duration_ms,
                usable_speech_ms=usable_speech_ms,
                windows=summaries,
            ),
        )
    finally:
        zero_enrollment_material(decoded_audio=decoded_audio, windows=windows, embeddings=embeddings)


def failure_for_quality(quality: AudioQuality) -> EnrollmentFailureReason | None:
    if quality.kind == "accepted":
        return None
    failures: dict[str, EnrollmentFailureReason] = {
        "empty_audio": "decoder_failure",
        "undecodable_audio": "decoder_failure",
        "metadata_mismatch": "metadata_mismatch",
        "too_short": "interrupted_capture",
        "low_speech": "insufficient_speech",
        "clipped_audio": "clipped_audio",
        "low_snr": "low_snr",
        "noisy_audio": "low_snr",
        "model_low_confidence": "template_build_failed",
    }
    return failures.get(quality.reason or "", "template_build_failed")


def contains_duplicate_windows(windows: tuple[SpeechWindow, ...]) -> bool:
    fingerprints = [window_fingerprint(window) for window in windows]
    return len(fingerprints) != len(set(fingerprints))


def window_fingerprint(window: SpeechWindow) -> bytes:
    digest = hashlib.sha256()
    digest.update(len(window.samples).to_bytes(8, byteorder="little", signed=False))
    for index in range(0, len(window.samples), 64):
        digest.update(struct.pack("<f", round(float(window.samples[index]), 5)))
    return digest.digest()


def failure_for_embedding_coherence(
    embeddings: list[ExtractedSpeakerEmbedding],
) -> EnrollmentFailureReason | None:
    labels = {embedding.speaker_label for embedding in embeddings if embedding.speaker_label != "unknown_speaker"}
    if len(labels) > 1:
        return "multi_speaker"
    scores = pairwise_scores(embeddings)
    if len(scores) == 0:
        return None
    lowest_score = min(scores)
    if lowest_score < MULTI_SPEAKER_COHERENCE:
        return "multi_speaker"
    if lowest_score < MINIMUM_WINDOW_COHERENCE:
        return "incoherent_windows"
    return None


def pairwise_scores(embeddings: list[ExtractedSpeakerEmbedding]) -> list[float]:
    scores: list[float] = []
    for left_index, left in enumerate(embeddings):
        for right in embeddings[left_index + 1 :]:
            scores.append(cosine_score(left.vector, right.vector))
    return scores


def normalized_window_weights(windows: tuple[SpeechWindow, ...]) -> tuple[float, ...]:
    raw_weights = tuple(max(0.01, window.signal_score) * window.speech_ms for window in windows)
    total = sum(raw_weights)
    return tuple(weight / total for weight in raw_weights)


def weighted_average_embedding(
    embeddings: list[ExtractedSpeakerEmbedding],
    weights: tuple[float, ...],
) -> list[float]:
    dimension = len(embeddings[0].vector)
    if dimension == 0 or any(len(embedding.vector) != dimension for embedding in embeddings):
        raise EmbeddingExtractionError("enrollment embeddings have inconsistent dimensions")
    totals = [0.0] * dimension
    for embedding, weight in zip(embeddings, weights, strict=True):
        for index, value in enumerate(embedding.vector):
            totals[index] += value * weight
    return totals


def encode_template(
    *,
    runtime: VerifierRuntime,
    template_embedding: list[float],
    sample_count: int,
) -> str:
    payload = {
        "adapterId": runtime.metadata.adapter_id,
        "modelId": runtime.metadata.model_id,
        "modelVersion": runtime.metadata.model_version,
        "thresholdVersion": runtime.metadata.threshold_version,
        "templateVersion": runtime.metadata.template_version,
        "sampleCount": sample_count,
        "embeddingDimensions": len(template_embedding),
        "embedding": template_embedding,
    }
    encoded = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    return base64.b64encode(encoded).decode("ascii")


def zero_enrollment_material(
    *,
    decoded_audio: DecodedAudio | None,
    windows: tuple[SpeechWindow, ...],
    embeddings: list[ExtractedSpeakerEmbedding],
) -> None:
    if decoded_audio is not None:
        zero_float_sequence(decoded_audio.samples)
    for window in windows:
        zero_float_sequence(window.samples)
    for embedding in embeddings:
        zero_float_sequence(embedding.vector)
