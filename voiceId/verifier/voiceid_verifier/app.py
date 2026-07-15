from __future__ import annotations

import base64
import json
import os
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import urlparse

from voiceid_verifier.audio_decode import zero_float_sequence
from voiceid_verifier.audio_quality import AudioQuality
from voiceid_verifier.embeddings import EmbeddingExtractionError
from voiceid_verifier.enrollment import BuiltEnrollment, build_continuous_enrollment
from voiceid_verifier.runtime import AudioClaims, VerifierRuntime, create_verifier_runtime_from_env
from voiceid_verifier.schemas import (
    AudioMetadata,
    AudioQualityAccepted,
    AudioQualityRejected,
    AudioQualityResponse,
    AudioQualityUncertain,
    BuiltEnrollmentTemplateResponse,
    EnrollmentAnalysisResponse,
    EnrollmentSpeechWindowResponse,
    KnownChannelCount,
    KnownSampleRate,
    RejectedEnrollmentTemplateResponse,
    SpeakerAccepted,
    SpeakerRejected,
    SpeakerResponse,
    SpeakerUncertain,
    SpeakerVerificationResponse,
    VerifierSchemaError,
    parse_build_enrollment_template_request,
    parse_verify_speaker_request,
)
from voiceid_verifier.scoring import cosine_score


DEFAULT_RUNTIME: VerifierRuntime | None = None

JSON_HEADERS = {
    "Content-Type": "application/json",
}


def build_enrollment_template_from_json(
    value: dict[str, Any],
    *,
    runtime: VerifierRuntime | None = None,
) -> dict[str, Any]:
    active_runtime = runtime or get_default_runtime()
    request = parse_build_enrollment_template_request(value)
    result = build_continuous_enrollment(
        runtime=active_runtime,
        audio_bytes=request.audio.audio_bytes,
        claims=_audio_claims(request.audio.metadata),
        expected_prompt_count=request.expected_prompt_count,
    )
    if result.kind == "rejected":
        return RejectedEnrollmentTemplateResponse(
            kind="rejected",
            request_id=request.request_id,
            reason=result.reason,
        ).to_json()

    return BuiltEnrollmentTemplateResponse(
        kind="built",
        request_id=request.request_id,
        encrypted_template=result.encrypted_template,
        template_version=active_runtime.metadata.template_version,
        model_version=active_runtime.metadata.model_version,
        threshold_version=active_runtime.metadata.threshold_version,
        quality=_accepted_audio_quality(result),
        analysis=_enrollment_analysis_response(result),
    ).to_json()


def verify_speaker_from_json(
    value: dict[str, Any],
    *,
    runtime: VerifierRuntime | None = None,
) -> dict[str, Any]:
    active_runtime = runtime or get_default_runtime()
    request = parse_verify_speaker_request(value)
    evaluated = active_runtime.evaluate_audio(
        request.audio.audio_bytes,
        _audio_claims(request.audio.metadata),
    )
    runtime_embedding: list[float] = []
    template_embedding: list[float] = []
    try:
        quality = _audio_quality_response(evaluated.quality)
        if quality.kind != "accepted":
            speaker: SpeakerResponse = SpeakerUncertain(
                kind="uncertain",
                reason="low_audio_quality",
                score=0.0,
                threshold=request.threshold,
                model_version=active_runtime.metadata.model_version,
                threshold_version=active_runtime.metadata.threshold_version,
            )
        else:
            try:
                template_embedding = _decode_template_embedding(
                    encrypted_template=request.template.encrypted_template,
                    runtime=active_runtime,
                )
                if evaluated.decoded_audio is None:
                    raise ValueError("accepted verification audio requires decoded samples")
                runtime_embedding = active_runtime.extract_verification_embedding(
                    evaluated.decoded_audio
                ).vector
                score = cosine_score(template_embedding, runtime_embedding)
            except (EmbeddingExtractionError, ValueError):
                speaker = SpeakerUncertain(
                    kind="uncertain",
                    reason="verifier_unavailable",
                    score=0.0,
                    threshold=request.threshold,
                    model_version=active_runtime.metadata.model_version,
                    threshold_version=active_runtime.metadata.threshold_version,
                )
            else:
                speaker = _speaker_result(
                    score=score,
                    threshold=request.threshold,
                    runtime=active_runtime,
                )
        return SpeakerVerificationResponse(
            kind="speaker_verification",
            request_id=request.request_id,
            quality=quality,
            speaker=speaker,
        ).to_json()
    finally:
        if evaluated.decoded_audio is not None:
            zero_float_sequence(evaluated.decoded_audio.samples)
        zero_float_sequence(runtime_embedding)
        zero_float_sequence(template_embedding)


def get_default_runtime() -> VerifierRuntime:
    global DEFAULT_RUNTIME
    if DEFAULT_RUNTIME is None:
        DEFAULT_RUNTIME = create_verifier_runtime_from_env()
    return DEFAULT_RUNTIME


def _audio_claims(metadata: AudioMetadata) -> AudioClaims:
    sample_rate_hz = metadata.sample_rate.hertz if isinstance(metadata.sample_rate, KnownSampleRate) else None
    channel_count = metadata.channel_count.count if isinstance(metadata.channel_count, KnownChannelCount) else None
    return AudioClaims(
        mime_type=metadata.mime_type,
        duration_ms=metadata.duration_ms,
        sample_rate_hz=sample_rate_hz,
        channel_count=channel_count,
    )


def _accepted_audio_quality(result: BuiltEnrollment) -> AudioQualityAccepted:
    quality = result.quality
    if quality.kind != "accepted" or quality.signal_score is None:
        raise RuntimeError("built enrollment requires accepted audio quality")
    return AudioQualityAccepted(
        kind="accepted",
        duration_ms=quality.duration_ms,
        signal_score=quality.signal_score,
    )


def _enrollment_analysis_response(result: BuiltEnrollment) -> EnrollmentAnalysisResponse:
    return EnrollmentAnalysisResponse(
        analysis_version="continuous-enrollment-v1",
        source_codec=result.analysis.source_codec,
        source_sample_rate_hz=result.analysis.source_sample_rate_hz,
        source_channel_count=result.analysis.source_channel_count,
        decoded_duration_ms=result.analysis.decoded_duration_ms,
        usable_speech_ms=result.analysis.usable_speech_ms,
        windows=tuple(
            EnrollmentSpeechWindowResponse(
                index=window.index,
                start_ms=window.start_ms,
                end_ms=window.end_ms,
                speech_ms=window.speech_ms,
                signal_score=window.signal_score,
                template_weight=window.template_weight,
            )
            for window in result.analysis.windows
        ),
    )


def _audio_quality_response(quality: AudioQuality) -> AudioQualityResponse:
    if quality.kind == "accepted":
        if quality.signal_score is None:
            raise ValueError("accepted audio quality requires signal score")
        return AudioQualityAccepted(
            kind="accepted",
            duration_ms=quality.duration_ms,
            signal_score=quality.signal_score,
        )
    if quality.kind == "rejected":
        return AudioQualityRejected(
            kind="rejected",
            reason=quality.reason,
            duration_ms=quality.duration_ms,
        )
    return AudioQualityUncertain(
        kind="uncertain",
        reason=quality.reason,
        duration_ms=quality.duration_ms,
    )


def _speaker_result(*, score: float, threshold: float, runtime: VerifierRuntime) -> SpeakerResponse:
    if score >= threshold:
        return SpeakerAccepted(
            kind="accepted",
            score=score,
            threshold=threshold,
            model_version=runtime.metadata.model_version,
            threshold_version=runtime.metadata.threshold_version,
        )
    if score >= threshold - 0.05:
        return SpeakerUncertain(
            kind="uncertain",
            reason="model_low_confidence",
            score=score,
            threshold=threshold,
            model_version=runtime.metadata.model_version,
            threshold_version=runtime.metadata.threshold_version,
        )
    return SpeakerRejected(
        kind="rejected",
        reason="speaker_mismatch",
        score=score,
        threshold=threshold,
        model_version=runtime.metadata.model_version,
        threshold_version=runtime.metadata.threshold_version,
    )


def _decode_template_embedding(
    *,
    encrypted_template: str,
    runtime: VerifierRuntime,
) -> list[float]:
    decoded = json.loads(base64.b64decode(encrypted_template, validate=True).decode("utf-8"))
    if not isinstance(decoded, dict):
        raise ValueError("template payload must be an object")
    expected_keys = {
        "adapterId",
        "modelId",
        "modelVersion",
        "thresholdVersion",
        "templateVersion",
        "sampleCount",
        "embeddingDimensions",
        "embedding",
    }
    if set(decoded.keys()) != expected_keys:
        raise ValueError("template payload contains unexpected or missing fields")
    expected_values = {
        "adapterId": runtime.metadata.adapter_id,
        "modelId": runtime.metadata.model_id,
        "modelVersion": runtime.metadata.model_version,
        "thresholdVersion": runtime.metadata.threshold_version,
        "templateVersion": runtime.metadata.template_version,
    }
    for field_name, expected_value in expected_values.items():
        if decoded[field_name] != expected_value:
            raise ValueError(f"template payload {field_name} does not match verifier runtime")
    embedding = decoded["embedding"]
    dimensions = decoded["embeddingDimensions"]
    sample_count = decoded["sampleCount"]
    if not _is_positive_int(dimensions):
        raise ValueError("template payload embeddingDimensions must be positive")
    if dimensions != runtime.metadata.embedding_dimensions:
        raise ValueError("template payload embeddingDimensions does not match verifier runtime")
    if not _is_positive_int(sample_count):
        raise ValueError("template payload sampleCount must be positive")
    if not isinstance(embedding, list) or len(embedding) != dimensions:
        raise ValueError("template payload embedding dimensions are invalid")
    if not all(_is_number(value) for value in embedding):
        raise ValueError("template payload embedding values must be numbers")
    return [float(value) for value in embedding]


def _is_number(value: object) -> bool:
    return isinstance(value, int | float) and not isinstance(value, bool)


def _is_positive_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value > 0


def main() -> None:
    if len(sys.argv) == 2:
        if sys.argv[1] == "serve_http":
            run_http_server_from_env()
            return
        request = json.load(sys.stdin)
        print(json.dumps(handle_cli_operation(sys.argv[1], request), separators=(",", ":")))
        return
    print("VoiceID verifier service. Use an operation name for CLI mode or serve_http for HTTP mode.")


def handle_cli_operation(operation: str, request: dict[str, Any]) -> dict[str, Any]:
    if operation == "build_enrollment_template":
        return build_enrollment_template_from_json(request)
    if operation == "verify_speaker":
        return verify_speaker_from_json(request)
    raise ValueError("unknown verifier operation")


def handle_http_operation(
    path: str,
    request: dict[str, Any],
    *,
    runtime: VerifierRuntime | None = None,
) -> dict[str, Any]:
    operation = _operation_for_path(path)
    if operation == "build_enrollment_template":
        return build_enrollment_template_from_json(request, runtime=runtime)
    if operation == "verify_speaker":
        return verify_speaker_from_json(request, runtime=runtime)
    raise ValueError("unknown verifier operation")


class VoiceIdVerifierHttpServer(ThreadingHTTPServer):
    def __init__(
        self,
        server_address: tuple[str, int],
        runtime: VerifierRuntime | None = None,
    ) -> None:
        self.verifier_runtime = runtime
        super().__init__(server_address, VoiceIdVerifierHttpHandler)


class VoiceIdVerifierHttpHandler(BaseHTTPRequestHandler):
    server_version = "VoiceIdVerifierHTTP/0.2"

    def do_GET(self) -> None:
        path = urlparse(self.path).path.rstrip("/")
        if path in ("", "/health"):
            self._write_json(
                200,
                {
                    "kind": "ok",
                    "service": "voice-id-verifier",
                    "routes": [
                        "POST /voice-id/verifier/build-enrollment-template",
                        "POST /voice-id/verifier/verify-speaker",
                    ],
                },
            )
            return
        self._write_json(404, {"kind": "error", "error": {"kind": "not_found"}})

    def do_POST(self) -> None:
        try:
            request = self._read_json_request()
            response = handle_http_operation(
                self.path,
                request,
                runtime=self._verifier_server().verifier_runtime,
            )
        except VerifierSchemaError as error:
            self._write_json(400, malformed_request(error))
            return
        except (json.JSONDecodeError, ValueError) as error:
            self._write_json(400, malformed_request(error))
            return
        except Exception as error:
            self._write_json(500, verifier_error(error))
            return
        self._write_json(200, response)

    def log_message(self, format: str, *args: Any) -> None:
        return

    def _verifier_server(self) -> VoiceIdVerifierHttpServer:
        if not isinstance(self.server, VoiceIdVerifierHttpServer):
            raise RuntimeError("VoiceID verifier handler requires VoiceIdVerifierHttpServer")
        return self.server

    def _read_json_request(self) -> dict[str, Any]:
        content_length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(content_length)
        value = json.loads(body.decode("utf-8"))
        if not isinstance(value, dict):
            raise ValueError("request body must be a JSON object")
        return value

    def _write_json(self, status: int, value: dict[str, Any]) -> None:
        body = json.dumps(value, separators=(",", ":")).encode("utf-8")
        self.send_response(status)
        for name, header_value in JSON_HEADERS.items():
            self.send_header(name, header_value)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def run_http_server_from_env() -> None:
    host = os.environ.get("VOICEID_VERIFIER_HOST", "127.0.0.1")
    port = int(os.environ.get("VOICEID_VERIFIER_PORT", "5051"))
    run_http_server(host=host, port=port)


def run_http_server(*, host: str, port: int) -> None:
    server = VoiceIdVerifierHttpServer((host, port))
    print(f"VoiceID verifier sidecar listening on http://{host}:{port}", flush=True)
    server.serve_forever()


def malformed_request(error: Exception) -> dict[str, Any]:
    return {
        "kind": "error",
        "error": {"kind": "malformed_request", "message": str(error)},
    }


def verifier_error(error: Exception) -> dict[str, Any]:
    return {
        "kind": "error",
        "error": {"kind": "verifier_unavailable", "message": str(error)},
    }


def _operation_for_path(path: str) -> str:
    normalized_path = urlparse(path).path.rstrip("/")
    if normalized_path.endswith("/build-enrollment-template"):
        return "build_enrollment_template"
    if normalized_path.endswith("/verify-speaker"):
        return "verify_speaker"
    raise ValueError("unknown verifier operation")


if __name__ == "__main__":
    main()
