from __future__ import annotations

import base64
import hashlib
import json
import math
import struct
from dataclasses import dataclass
from typing import Literal

from voiceid_verifier.audio_decode import DecodedAudio, zero_float_sequence
from voiceid_verifier.audio_quality import AudioQuality, SpeechWindow
from voiceid_verifier.embeddings import EmbeddingExtractionError, ExtractedSpeakerEmbedding
from voiceid_verifier.runtime import AudioClaims, VerifierRuntime
from voiceid_verifier.scoring import cosine_score


ANALYSIS_VERSION = "continuous-enrollment-v1"
MINIMUM_PROMPT_DURATION_MS = 3000
MINIMUM_SPEECH_PER_PROMPT_MS = 2000
MINIMUM_WINDOW_COHERENCE = 0.45
MULTI_SPEAKER_COHERENCE = 0.15
MINIMUM_LEAVE_ONE_OUT_STABILITY = 0.98

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


@dataclass(frozen=True)
class TemplateAggregation:
    embedding: list[float]
    weights: tuple[float, ...]
    minimum_leave_one_out_similarity: float


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

        windows = evaluated.speech_windows
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
            aggregation = aggregate_template(windows, embeddings)
            template_embedding = aggregation.embedding
            weights = aggregation.weights
            if (
                aggregation.minimum_leave_one_out_similarity
                < MINIMUM_LEAVE_ONE_OUT_STABILITY
            ):
                zero_float_sequence(template_embedding)
                return RejectedEnrollment(kind="rejected", reason="incoherent_windows")
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


def aggregate_template(
    windows: tuple[SpeechWindow, ...],
    embeddings: list[ExtractedSpeakerEmbedding],
) -> TemplateAggregation:
    if len(windows) != len(embeddings) or len(embeddings) < 3:
        raise EmbeddingExtractionError(
            "robust enrollment aggregation requires at least three aligned windows"
        )
    weights = robust_window_weights(windows, embeddings)
    embedding = normalized_embedding(weighted_average_embedding(embeddings, weights))
    try:
        stability = minimum_leave_one_out_similarity(
            full_template=embedding,
            windows=windows,
            embeddings=embeddings,
        )
    except Exception:
        zero_float_sequence(embedding)
        raise
    return TemplateAggregation(
        embedding=embedding,
        weights=weights,
        minimum_leave_one_out_similarity=stability,
    )


def robust_window_weights(
    windows: tuple[SpeechWindow, ...],
    embeddings: list[ExtractedSpeakerEmbedding],
) -> tuple[float, ...]:
    quality_weights = normalized_window_weights(windows)
    medoid = embeddings[embedding_medoid_index(embeddings)].vector
    raw_weights = tuple(
        quality_weight * max(0.01, cosine_score(medoid, embedding.vector)) ** 2
        for quality_weight, embedding in zip(quality_weights, embeddings, strict=True)
    )
    total = sum(raw_weights)
    if not math.isfinite(total) or total <= 0:
        raise EmbeddingExtractionError("robust enrollment weights are invalid")
    return tuple(weight / total for weight in raw_weights)


def embedding_medoid_index(embeddings: list[ExtractedSpeakerEmbedding]) -> int:
    if len(embeddings) == 0:
        raise EmbeddingExtractionError("embedding medoid requires enrollment embeddings")
    selected_index = 0
    selected_centrality = float("-inf")
    for index, candidate in enumerate(embeddings):
        centrality = sum(
            cosine_score(candidate.vector, other.vector)
            for other_index, other in enumerate(embeddings)
            if other_index != index
        )
        if not math.isfinite(centrality):
            raise EmbeddingExtractionError("enrollment embedding centrality is invalid")
        if centrality > selected_centrality:
            selected_index = index
            selected_centrality = centrality
    return selected_index


def minimum_leave_one_out_similarity(
    *,
    full_template: list[float],
    windows: tuple[SpeechWindow, ...],
    embeddings: list[ExtractedSpeakerEmbedding],
) -> float:
    similarities: list[float] = []
    for omitted_index in range(len(embeddings)):
        retained_windows = tuple(
            window for index, window in enumerate(windows) if index != omitted_index
        )
        retained_embeddings = [
            embedding for index, embedding in enumerate(embeddings) if index != omitted_index
        ]
        weights = robust_window_weights(retained_windows, retained_embeddings)
        retained_template = normalized_embedding(
            weighted_average_embedding(retained_embeddings, weights)
        )
        try:
            similarities.append(cosine_score(full_template, retained_template))
        finally:
            zero_float_sequence(retained_template)
    minimum = min(similarities)
    if not math.isfinite(minimum):
        raise EmbeddingExtractionError("leave-one-out template stability is invalid")
    return minimum


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


def normalized_embedding(vector: list[float]) -> list[float]:
    magnitude = math.sqrt(sum(value * value for value in vector))
    if not math.isfinite(magnitude) or magnitude == 0:
        zero_float_sequence(vector)
        raise EmbeddingExtractionError("enrollment template magnitude is invalid")
    normalized = [value / magnitude for value in vector]
    zero_float_sequence(vector)
    return normalized


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
