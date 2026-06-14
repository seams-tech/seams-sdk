from __future__ import annotations

import base64
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Literal


SCHEMA_VERSION = "voice_id_verifier_v1"


class VerifierSchemaError(ValueError):
    pass


@dataclass(frozen=True)
class KnownSampleRate:
    kind: Literal["known"]
    hertz: int

    def to_json(self) -> dict[str, Any]:
        return {"kind": self.kind, "hertz": self.hertz}


@dataclass(frozen=True)
class UnknownSampleRate:
    kind: Literal["unknown"]

    def to_json(self) -> dict[str, Any]:
        return {"kind": self.kind}


AudioSampleRate = KnownSampleRate | UnknownSampleRate


@dataclass(frozen=True)
class KnownChannelCount:
    kind: Literal["known"]
    count: int

    def to_json(self) -> dict[str, Any]:
        return {"kind": self.kind, "count": self.count}


@dataclass(frozen=True)
class UnknownChannelCount:
    kind: Literal["unknown"]

    def to_json(self) -> dict[str, Any]:
        return {"kind": self.kind}


AudioChannelCount = KnownChannelCount | UnknownChannelCount


@dataclass(frozen=True)
class AudioMetadata:
    mime_type: str
    duration_ms: int
    sample_rate: AudioSampleRate
    channel_count: AudioChannelCount
    byte_length: int
    captured_at: str
    recorder: str

    def to_json(self) -> dict[str, Any]:
        return {
            "mimeType": self.mime_type,
            "durationMs": self.duration_ms,
            "sampleRate": self.sample_rate.to_json(),
            "channelCount": self.channel_count.to_json(),
            "byteLength": self.byte_length,
            "capturedAt": self.captured_at,
            "recorder": self.recorder,
        }


@dataclass(frozen=True)
class AudioInput:
    audio_bytes: bytes
    metadata: AudioMetadata


@dataclass(frozen=True)
class ExtractEnrollmentEmbeddingRequest:
    schema_version: Literal["voice_id_verifier_v1"]
    request_id: str
    audio: AudioInput


@dataclass(frozen=True)
class TemplateEmbeddingInput:
    vector: tuple[float, ...]
    speaker_label: str
    quality: dict[str, Any]


@dataclass(frozen=True)
class BuildTemplateRequest:
    schema_version: Literal["voice_id_verifier_v1"]
    request_id: str
    embeddings: tuple[TemplateEmbeddingInput, ...]


@dataclass(frozen=True)
class TemplateReference:
    encrypted_template: str
    template_version: str
    model_version: str
    threshold_version: str


@dataclass(frozen=True)
class VerifySpeakerRequest:
    schema_version: Literal["voice_id_verifier_v1"]
    request_id: str
    audio: AudioInput
    template: TemplateReference
    threshold: float


@dataclass(frozen=True)
class AudioQualityAccepted:
    kind: Literal["accepted"]
    duration_ms: int
    signal_score: float

    def to_json(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "durationMs": self.duration_ms,
            "signalScore": self.signal_score,
        }


@dataclass(frozen=True)
class AudioQualityRejected:
    kind: Literal["rejected"]
    reason: Literal["too_short", "empty_audio"]
    duration_ms: int

    def to_json(self) -> dict[str, Any]:
        return {"kind": self.kind, "reason": self.reason, "durationMs": self.duration_ms}


@dataclass(frozen=True)
class AudioQualityUncertain:
    kind: Literal["uncertain"]
    reason: Literal[
        "noisy_audio",
        "too_short",
        "model_low_confidence",
        "undecodable_audio",
        "clipped_audio",
        "low_speech",
        "low_snr",
    ]
    duration_ms: int

    def to_json(self) -> dict[str, Any]:
        return {"kind": self.kind, "reason": self.reason, "durationMs": self.duration_ms}


AudioQualityResponse = AudioQualityAccepted | AudioQualityRejected | AudioQualityUncertain


@dataclass(frozen=True)
class EnrollmentEmbeddingResponse:
    kind: Literal["embedding"]
    request_id: str
    model_version: str
    threshold_version: str
    speaker_label: str
    embedding: tuple[float, ...]
    quality: AudioQualityResponse

    def to_json(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "requestId": self.request_id,
            "modelVersion": self.model_version,
            "thresholdVersion": self.threshold_version,
            "speakerLabel": self.speaker_label,
            "embedding": list(self.embedding),
            "quality": self.quality.to_json(),
        }


@dataclass(frozen=True)
class BuiltTemplateResponse:
    kind: Literal["built"]
    request_id: str
    encrypted_template: str
    template_version: str
    model_version: str
    threshold_version: str
    speaker_label: str

    def to_json(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "requestId": self.request_id,
            "encryptedTemplate": self.encrypted_template,
            "templateVersion": self.template_version,
            "modelVersion": self.model_version,
            "thresholdVersion": self.threshold_version,
            "speakerLabel": self.speaker_label,
        }


@dataclass(frozen=True)
class RejectedTemplateResponse:
    kind: Literal["rejected"]
    request_id: str
    reason: Literal["insufficient_quality", "inconsistent_speaker"]

    def to_json(self) -> dict[str, Any]:
        return {"kind": self.kind, "requestId": self.request_id, "reason": self.reason}


TemplateBuildResponse = BuiltTemplateResponse | RejectedTemplateResponse


@dataclass(frozen=True)
class SpeakerAccepted:
    kind: Literal["accepted"]
    score: float
    threshold: float
    model_version: str
    threshold_version: str

    def to_json(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "score": self.score,
            "threshold": self.threshold,
            "modelVersion": self.model_version,
            "thresholdVersion": self.threshold_version,
        }


@dataclass(frozen=True)
class SpeakerRejected:
    kind: Literal["rejected"]
    reason: Literal["speaker_mismatch"]
    score: float
    threshold: float
    model_version: str
    threshold_version: str

    def to_json(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "reason": self.reason,
            "score": self.score,
            "threshold": self.threshold,
            "modelVersion": self.model_version,
            "thresholdVersion": self.threshold_version,
        }


@dataclass(frozen=True)
class SpeakerUncertain:
    kind: Literal["uncertain"]
    reason: Literal["model_low_confidence", "verifier_unavailable", "low_audio_quality"]
    score: float
    threshold: float
    model_version: str
    threshold_version: str

    def to_json(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "reason": self.reason,
            "score": self.score,
            "threshold": self.threshold,
            "modelVersion": self.model_version,
            "thresholdVersion": self.threshold_version,
        }


SpeakerResponse = SpeakerAccepted | SpeakerRejected | SpeakerUncertain


@dataclass(frozen=True)
class SpeakerVerificationResponse:
    kind: Literal["speaker_verification"]
    request_id: str
    quality: AudioQualityResponse
    speaker: SpeakerResponse

    def to_json(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "requestId": self.request_id,
            "quality": self.quality.to_json(),
            "speaker": self.speaker.to_json(),
        }


def parse_extract_enrollment_embedding_request(
    value: dict[str, Any],
) -> ExtractEnrollmentEmbeddingRequest:
    data = _require_object(value, "extract enrollment embedding request")
    return ExtractEnrollmentEmbeddingRequest(
        schema_version=_require_schema_version(data),
        request_id=_require_string(data, "requestId"),
        audio=_parse_audio_input(data.get("audio")),
    )


def parse_build_template_request(value: dict[str, Any]) -> BuildTemplateRequest:
    data = _require_object(value, "build template request")
    return BuildTemplateRequest(
        schema_version=_require_schema_version(data),
        request_id=_require_string(data, "requestId"),
        embeddings=_parse_template_embeddings(data.get("embeddings")),
    )


def parse_verify_speaker_request(value: dict[str, Any]) -> VerifySpeakerRequest:
    data = _require_object(value, "verify speaker request")
    return VerifySpeakerRequest(
        schema_version=_require_schema_version(data),
        request_id=_require_string(data, "requestId"),
        audio=_parse_audio_input(data.get("audio")),
        template=_parse_template_reference(data.get("template")),
        threshold=_require_probability(data, "threshold"),
    )


def encode_audio_bytes(audio_bytes: bytes) -> str:
    return base64.b64encode(audio_bytes).decode("ascii")


def decode_audio_base64(value: object, field_name: str) -> bytes:
    if not isinstance(value, str) or len(value.strip()) == 0:
        raise VerifierSchemaError(f"{field_name} must be a non-empty base64 string")
    try:
        return base64.b64decode(value, validate=True)
    except ValueError as exc:
        raise VerifierSchemaError(f"{field_name} must be valid base64") from exc


def _parse_audio_input(value: object) -> AudioInput:
    data = _require_object(value, "audio")
    audio_bytes = decode_audio_base64(data.get("audioBase64"), "audioBase64")
    metadata = _parse_audio_metadata(data.get("metadata"))
    if len(audio_bytes) != metadata.byte_length:
        raise VerifierSchemaError("audio byte length does not match metadata.byteLength")
    return AudioInput(audio_bytes=audio_bytes, metadata=metadata)


def _parse_audio_metadata(value: object) -> AudioMetadata:
    data = _require_object(value, "metadata")
    return AudioMetadata(
        mime_type=_require_string(data, "mimeType"),
        duration_ms=_require_positive_int(data, "durationMs"),
        sample_rate=_parse_sample_rate(data.get("sampleRate")),
        channel_count=_parse_channel_count(data.get("channelCount")),
        byte_length=_require_positive_int(data, "byteLength"),
        captured_at=_require_iso_date_time(data, "capturedAt"),
        recorder=_require_string(data, "recorder"),
    )


def _parse_sample_rate(value: object) -> AudioSampleRate:
    data = _require_object(value, "sampleRate")
    kind = _require_string(data, "kind")
    if kind == "known":
        return KnownSampleRate(kind="known", hertz=_require_positive_int(data, "hertz"))
    if kind == "unknown":
        return UnknownSampleRate(kind="unknown")
    raise VerifierSchemaError("sampleRate.kind is invalid")


def _parse_channel_count(value: object) -> AudioChannelCount:
    data = _require_object(value, "channelCount")
    kind = _require_string(data, "kind")
    if kind == "known":
        return KnownChannelCount(kind="known", count=_require_positive_int(data, "count"))
    if kind == "unknown":
        return UnknownChannelCount(kind="unknown")
    raise VerifierSchemaError("channelCount.kind is invalid")


def _parse_template_embeddings(value: object) -> tuple[TemplateEmbeddingInput, ...]:
    if not isinstance(value, list):
        raise VerifierSchemaError("embeddings must be an array")
    return tuple(_parse_template_embedding(entry, index) for index, entry in enumerate(value))


def _parse_template_embedding(value: object, index: int) -> TemplateEmbeddingInput:
    data = _require_object(value, f"embeddings[{index}]")
    return TemplateEmbeddingInput(
        vector=_require_float_tuple(data.get("vector"), f"embeddings[{index}].vector"),
        speaker_label=_require_string(data, "speakerLabel"),
        quality=_require_object(data.get("quality"), f"embeddings[{index}].quality"),
    )


def _parse_template_reference(value: object) -> TemplateReference:
    data = _require_object(value, "template")
    return TemplateReference(
        encrypted_template=_require_string(data, "encryptedTemplate"),
        template_version=_require_string(data, "templateVersion"),
        model_version=_require_string(data, "modelVersion"),
        threshold_version=_require_string(data, "thresholdVersion"),
    )


def _require_schema_version(data: dict[str, Any]) -> Literal["voice_id_verifier_v1"]:
    schema_version = _require_string(data, "schemaVersion")
    if schema_version != SCHEMA_VERSION:
        raise VerifierSchemaError(f"schemaVersion must be {SCHEMA_VERSION}")
    return "voice_id_verifier_v1"


def _require_object(value: object, field_name: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise VerifierSchemaError(f"{field_name} must be an object")
    return value


def _require_string(data: dict[str, Any], field_name: str) -> str:
    value = data.get(field_name)
    if not isinstance(value, str) or len(value.strip()) == 0:
        raise VerifierSchemaError(f"{field_name} must be a non-empty string")
    return value.strip()


def _require_positive_int(data: dict[str, Any], field_name: str) -> int:
    value = data.get(field_name)
    if not isinstance(value, int) or value <= 0:
        raise VerifierSchemaError(f"{field_name} must be a positive integer")
    return value


def _require_probability(data: dict[str, Any], field_name: str) -> float:
    value = data.get(field_name)
    if not _is_number(value) or value < 0 or value > 1:
        raise VerifierSchemaError(f"{field_name} must be a number between 0 and 1")
    return float(value)


def _require_float_tuple(value: object, field_name: str) -> tuple[float, ...]:
    if not isinstance(value, list) or len(value) == 0:
        raise VerifierSchemaError(f"{field_name} must be a non-empty number array")
    vector: list[float] = []
    for index, item in enumerate(value):
        if not _is_number(item):
            raise VerifierSchemaError(f"{field_name}[{index}] must be a number")
        vector.append(float(item))
    return tuple(vector)


def _require_iso_date_time(data: dict[str, Any], field_name: str) -> str:
    value = _require_string(data, field_name)
    normalized = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        datetime.fromisoformat(normalized)
    except ValueError as exc:
        raise VerifierSchemaError(f"{field_name} must be an ISO date-time string") from exc
    return value


def _is_number(value: object) -> bool:
    return isinstance(value, int | float) and not isinstance(value, bool)
