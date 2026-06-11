from __future__ import annotations

import base64
import json
from typing import Any

from voiceid_verifier.audio_quality import evaluate_audio_quality
from voiceid_verifier.embeddings import extract_embedding
from voiceid_verifier.schemas import (
    AudioQualityAccepted,
    AudioQualityRejected,
    AudioQualityResponse,
    AudioQualityUncertain,
    BuiltTemplateResponse,
    EnrollmentEmbeddingResponse,
    RejectedTemplateResponse,
    SpeakerAccepted,
    SpeakerRejected,
    SpeakerUncertain,
    SpeakerVerificationResponse,
    TemplateEmbeddingInput,
    parse_build_template_request,
    parse_extract_enrollment_embedding_request,
    parse_verify_speaker_request,
)
from voiceid_verifier.scoring import cosine_score


MODEL_VERSION = "python-placeholder-model-v1"
THRESHOLD_VERSION = "python-placeholder-threshold-v1"
TEMPLATE_VERSION = "python-placeholder-template-v1"
SPEAKER_LABEL = "unknown_speaker"


def extract_enrollment_embedding(audio_bytes: bytes, duration_ms: int) -> dict:
    quality = evaluate_audio_quality(audio_bytes, duration_ms)
    response = EnrollmentEmbeddingResponse(
        kind="embedding",
        request_id="legacy-direct-call",
        model_version=MODEL_VERSION,
        threshold_version=THRESHOLD_VERSION,
        speaker_label=SPEAKER_LABEL,
        embedding=tuple(extract_embedding(audio_bytes)),
        quality=_audio_quality_response(quality),
    )
    return response.to_json()


def extract_enrollment_embedding_from_json(value: dict[str, Any]) -> dict[str, Any]:
    request = parse_extract_enrollment_embedding_request(value)
    quality = evaluate_audio_quality(request.audio.audio_bytes, request.audio.metadata.duration_ms)
    response = EnrollmentEmbeddingResponse(
        kind="embedding",
        request_id=request.request_id,
        model_version=MODEL_VERSION,
        threshold_version=THRESHOLD_VERSION,
        speaker_label=SPEAKER_LABEL,
        embedding=tuple(extract_embedding(request.audio.audio_bytes)),
        quality=_audio_quality_response(quality),
    )
    return response.to_json()


def build_template_from_json(value: dict[str, Any]) -> dict[str, Any]:
    request = parse_build_template_request(value)
    accepted_embeddings = [
        embedding for embedding in request.embeddings if embedding.quality.get("kind") == "accepted"
    ]
    if len(accepted_embeddings) == 0:
        return RejectedTemplateResponse(
            kind="rejected",
            request_id=request.request_id,
            reason="insufficient_quality",
        ).to_json()
    speaker_labels = {embedding.speaker_label for embedding in accepted_embeddings}
    if len(speaker_labels) != 1:
        return RejectedTemplateResponse(
            kind="rejected",
            request_id=request.request_id,
            reason="inconsistent_speaker",
        ).to_json()

    template_payload = {
        "modelVersion": MODEL_VERSION,
        "thresholdVersion": THRESHOLD_VERSION,
        "speakerLabel": accepted_embeddings[0].speaker_label,
        "embedding": _average_embedding(accepted_embeddings),
    }
    return BuiltTemplateResponse(
        kind="built",
        request_id=request.request_id,
        encrypted_template=_encode_template_payload(template_payload),
        template_version=TEMPLATE_VERSION,
        model_version=MODEL_VERSION,
        threshold_version=THRESHOLD_VERSION,
        speaker_label=accepted_embeddings[0].speaker_label,
    ).to_json()


def verify_speaker_from_json(value: dict[str, Any]) -> dict[str, Any]:
    request = parse_verify_speaker_request(value)
    quality = _audio_quality_response(
        evaluate_audio_quality(request.audio.audio_bytes, request.audio.metadata.duration_ms)
    )
    template_payload = _decode_template_payload(request.template.encrypted_template)
    template_embedding = template_payload["embedding"]
    runtime_embedding = extract_embedding(request.audio.audio_bytes)
    score = cosine_score(template_embedding, runtime_embedding)
    if quality.kind != "accepted":
        speaker = SpeakerUncertain(
            kind="uncertain",
            reason="model_low_confidence",
            score=score,
            threshold=request.threshold,
            model_version=MODEL_VERSION,
            threshold_version=THRESHOLD_VERSION,
        )
    elif score >= request.threshold:
        speaker = SpeakerAccepted(
            kind="accepted",
            score=score,
            threshold=request.threshold,
            model_version=MODEL_VERSION,
            threshold_version=THRESHOLD_VERSION,
        )
    else:
        speaker = SpeakerRejected(
            kind="rejected",
            reason="speaker_mismatch",
            score=score,
            threshold=request.threshold,
            model_version=MODEL_VERSION,
            threshold_version=THRESHOLD_VERSION,
        )
    return SpeakerVerificationResponse(
        kind="speaker_verification",
        request_id=request.request_id,
        quality=quality,
        speaker=speaker,
    ).to_json()


def _audio_quality_response(quality: object) -> AudioQualityResponse:
    kind = getattr(quality, "kind")
    duration_ms = getattr(quality, "duration_ms")
    reason = getattr(quality, "reason")
    signal_score = getattr(quality, "signal_score")
    if kind == "accepted":
        return AudioQualityAccepted(
            kind="accepted",
            duration_ms=duration_ms,
            signal_score=signal_score,
        )
    if kind == "rejected":
        return AudioQualityRejected(
            kind="rejected",
            reason=reason,
            duration_ms=duration_ms,
        )
    return AudioQualityUncertain(
        kind="uncertain",
        reason=reason,
        duration_ms=duration_ms,
    )


def _average_embedding(embeddings: list[TemplateEmbeddingInput]) -> list[float]:
    dimension = len(embeddings[0].vector)
    totals = [0.0] * dimension
    for embedding in embeddings:
        if len(embedding.vector) != dimension:
            raise ValueError("all enrollment embeddings must have the same dimension")
        for index, value in enumerate(embedding.vector):
            totals[index] += value
    return [value / len(embeddings) for value in totals]


def _encode_template_payload(payload: dict[str, Any]) -> str:
    return base64.b64encode(json.dumps(payload, separators=(",", ":")).encode("utf-8")).decode("ascii")


def _decode_template_payload(encrypted_template: str) -> dict[str, Any]:
    decoded = json.loads(base64.b64decode(encrypted_template, validate=True).decode("utf-8"))
    if not isinstance(decoded, dict):
        raise ValueError("template payload must be an object")
    embedding = decoded.get("embedding")
    if not isinstance(embedding, list) or len(embedding) == 0:
        raise ValueError("template payload embedding must be a non-empty array")
    if not all(_is_number(value) for value in embedding):
        raise ValueError("template payload embedding values must be numbers")
    decoded["embedding"] = [float(value) for value in embedding]
    return decoded


def _is_number(value: object) -> bool:
    return isinstance(value, int | float) and not isinstance(value, bool)


def main() -> None:
    print("VoiceID verifier service scaffold. Wire HTTP or subprocess transport next.")


if __name__ == "__main__":
    main()
