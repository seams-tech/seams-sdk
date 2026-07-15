from __future__ import annotations

import base64
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Literal


SCHEMA_VERSION = "voice_id_verifier_v2"
MAXIMUM_AUDIO_BYTE_LENGTH = 32 * 1024 * 1024
MAXIMUM_AUDIO_BASE64_LENGTH = ((MAXIMUM_AUDIO_BYTE_LENGTH + 2) // 3) * 4


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
class BuildEnrollmentTemplateRequest:
    schema_version: Literal["voice_id_verifier_v2"]
    request_id: str
    audio: AudioInput
    expected_prompt_count: int


@dataclass(frozen=True)
class TemplateReference:
    encrypted_template: str
    template_version: str
    model_version: str
    threshold_version: str


@dataclass(frozen=True)
class VerifySpeakerRequest:
    schema_version: Literal["voice_id_verifier_v2"]
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
        "metadata_mismatch",
    ]
    duration_ms: int

    def to_json(self) -> dict[str, Any]:
        return {"kind": self.kind, "reason": self.reason, "durationMs": self.duration_ms}


AudioQualityResponse = AudioQualityAccepted | AudioQualityRejected | AudioQualityUncertain


@dataclass(frozen=True)
class EnrollmentSpeechWindowResponse:
    index: int
    start_ms: int
    end_ms: int
    speech_ms: int
    signal_score: float
    template_weight: float

    def to_json(self) -> dict[str, Any]:
        return {
            "index": self.index,
            "startMs": self.start_ms,
            "endMs": self.end_ms,
            "speechMs": self.speech_ms,
            "signalScore": self.signal_score,
            "templateWeight": self.template_weight,
        }


@dataclass(frozen=True)
class EnrollmentAnalysisResponse:
    analysis_version: str
    source_codec: str
    source_sample_rate_hz: int
    source_channel_count: int
    decoded_duration_ms: int
    usable_speech_ms: int
    windows: tuple[EnrollmentSpeechWindowResponse, ...]

    def to_json(self) -> dict[str, Any]:
        return {
            "analysisVersion": self.analysis_version,
            "sourceCodec": self.source_codec,
            "sourceSampleRateHz": self.source_sample_rate_hz,
            "sourceChannelCount": self.source_channel_count,
            "decodedDurationMs": self.decoded_duration_ms,
            "usableSpeechMs": self.usable_speech_ms,
            "windows": [window.to_json() for window in self.windows],
        }


@dataclass(frozen=True)
class BuiltEnrollmentTemplateResponse:
    kind: Literal["built"]
    request_id: str
    encrypted_template: str
    template_version: str
    model_version: str
    threshold_version: str
    quality: AudioQualityAccepted
    analysis: EnrollmentAnalysisResponse

    def to_json(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "requestId": self.request_id,
            "encryptedTemplate": self.encrypted_template,
            "templateVersion": self.template_version,
            "modelVersion": self.model_version,
            "thresholdVersion": self.threshold_version,
            "quality": self.quality.to_json(),
            "analysis": self.analysis.to_json(),
        }


@dataclass(frozen=True)
class RejectedEnrollmentTemplateResponse:
    kind: Literal["rejected"]
    request_id: str
    reason: Literal[
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

    def to_json(self) -> dict[str, Any]:
        return {"kind": self.kind, "requestId": self.request_id, "reason": self.reason}


EnrollmentTemplateResponse = BuiltEnrollmentTemplateResponse | RejectedEnrollmentTemplateResponse


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


def parse_build_enrollment_template_request(
    value: dict[str, Any],
) -> BuildEnrollmentTemplateRequest:
    data = _require_exact_object(
        value,
        "build enrollment template request",
        {"schemaVersion", "requestId", "audio", "expectedPromptCount"},
    )
    return BuildEnrollmentTemplateRequest(
        schema_version=_require_schema_version(data),
        request_id=_require_string(data, "requestId"),
        audio=_parse_audio_input(data.get("audio")),
        expected_prompt_count=_require_positive_int(data, "expectedPromptCount"),
    )


def parse_verify_speaker_request(value: dict[str, Any]) -> VerifySpeakerRequest:
    data = _require_exact_object(
        value,
        "verify speaker request",
        {"schemaVersion", "requestId", "audio", "template", "threshold"},
    )
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
    if len(value) > MAXIMUM_AUDIO_BASE64_LENGTH:
        raise VerifierSchemaError(f"{field_name} exceeds the maximum audio byte length")
    try:
        decoded = base64.b64decode(value, validate=True)
    except ValueError as exc:
        raise VerifierSchemaError(f"{field_name} must be valid base64") from exc
    if len(decoded) > MAXIMUM_AUDIO_BYTE_LENGTH:
        raise VerifierSchemaError(f"{field_name} exceeds the maximum audio byte length")
    return decoded


def _parse_audio_input(value: object) -> AudioInput:
    data = _require_exact_object(value, "audio", {"audioBase64", "metadata"})
    audio_bytes = decode_audio_base64(data.get("audioBase64"), "audioBase64")
    metadata = _parse_audio_metadata(data.get("metadata"))
    if len(audio_bytes) != metadata.byte_length:
        raise VerifierSchemaError("audio byte length does not match metadata.byteLength")
    return AudioInput(audio_bytes=audio_bytes, metadata=metadata)


def _parse_audio_metadata(value: object) -> AudioMetadata:
    data = _require_exact_object(
        value,
        "metadata",
        {
            "mimeType",
            "durationMs",
            "sampleRate",
            "channelCount",
            "byteLength",
            "capturedAt",
            "recorder",
        },
    )
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
        _require_exact_keys(data, "sampleRate", {"kind", "hertz"})
        return KnownSampleRate(kind="known", hertz=_require_positive_int(data, "hertz"))
    if kind == "unknown":
        _require_exact_keys(data, "sampleRate", {"kind"})
        return UnknownSampleRate(kind="unknown")
    raise VerifierSchemaError("sampleRate.kind is invalid")


def _parse_channel_count(value: object) -> AudioChannelCount:
    data = _require_object(value, "channelCount")
    kind = _require_string(data, "kind")
    if kind == "known":
        _require_exact_keys(data, "channelCount", {"kind", "count"})
        return KnownChannelCount(kind="known", count=_require_positive_int(data, "count"))
    if kind == "unknown":
        _require_exact_keys(data, "channelCount", {"kind"})
        return UnknownChannelCount(kind="unknown")
    raise VerifierSchemaError("channelCount.kind is invalid")


def _parse_template_reference(value: object) -> TemplateReference:
    data = _require_exact_object(
        value,
        "template",
        {"encryptedTemplate", "templateVersion", "modelVersion", "thresholdVersion"},
    )
    return TemplateReference(
        encrypted_template=_require_string(data, "encryptedTemplate"),
        template_version=_require_string(data, "templateVersion"),
        model_version=_require_string(data, "modelVersion"),
        threshold_version=_require_string(data, "thresholdVersion"),
    )


def _require_schema_version(data: dict[str, Any]) -> Literal["voice_id_verifier_v2"]:
    schema_version = _require_string(data, "schemaVersion")
    if schema_version != SCHEMA_VERSION:
        raise VerifierSchemaError(f"schemaVersion must be {SCHEMA_VERSION}")
    return "voice_id_verifier_v2"


def _require_exact_object(
    value: object,
    field_name: str,
    expected_keys: set[str],
) -> dict[str, Any]:
    data = _require_object(value, field_name)
    _require_exact_keys(data, field_name, expected_keys)
    return data


def _require_exact_keys(data: dict[str, Any], field_name: str, expected_keys: set[str]) -> None:
    if set(data.keys()) != expected_keys:
        raise VerifierSchemaError(f"{field_name} contains unexpected or missing fields")


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
