from __future__ import annotations

import base64
import json
import os
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import urlparse

from voiceid_verifier.audio_quality import AudioQuality
from voiceid_verifier.embeddings import EmbeddingExtractionError
from voiceid_verifier.runtime import EvaluatedAudio, VerifierRuntime, create_verifier_runtime_from_env
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
    VerifierSchemaError,
    parse_build_template_request,
    parse_extract_enrollment_embedding_request,
    parse_verify_speaker_request,
)
from voiceid_verifier.scoring import cosine_score


DEFAULT_RUNTIME: VerifierRuntime | None = None

JSON_HEADERS = {
    "Content-Type": "application/json",
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type",
}


def extract_enrollment_embedding(audio_bytes: bytes, duration_ms: int) -> dict:
    runtime = get_default_runtime()
    evaluated = runtime.evaluate_audio(audio_bytes, duration_ms)
    embedding = (
        runtime.extract_embedding(audio_bytes, evaluated.decoded_audio)
        if evaluated.quality.kind == "accepted"
        else runtime.zero_embedding()
    )
    response = EnrollmentEmbeddingResponse(
        kind="embedding",
        request_id="legacy-direct-call",
        model_version=runtime.metadata.model_version,
        threshold_version=runtime.metadata.threshold_version,
        speaker_label=embedding.speaker_label,
        embedding=tuple(embedding.vector),
        quality=_audio_quality_response(evaluated.quality),
    )
    return response.to_json()


def extract_enrollment_embedding_from_json(
    value: dict[str, Any],
    *,
    runtime: VerifierRuntime | None = None,
) -> dict[str, Any]:
    active_runtime = runtime or get_default_runtime()
    request = parse_extract_enrollment_embedding_request(value)
    evaluated = active_runtime.evaluate_audio(request.audio.audio_bytes, request.audio.metadata.duration_ms)
    try:
        embedding = (
            active_runtime.extract_embedding(request.audio.audio_bytes, evaluated.decoded_audio)
            if evaluated.quality.kind == "accepted"
            else active_runtime.zero_embedding()
        )
    except EmbeddingExtractionError:
        evaluated = EvaluatedAudio(
            quality=AudioQuality(
                kind="uncertain",
                reason="model_low_confidence",
                duration_ms=request.audio.metadata.duration_ms,
            ),
            decoded_audio=evaluated.decoded_audio,
        )
        embedding = active_runtime.zero_embedding()
    response = EnrollmentEmbeddingResponse(
        kind="embedding",
        request_id=request.request_id,
        model_version=active_runtime.metadata.model_version,
        threshold_version=active_runtime.metadata.threshold_version,
        speaker_label=embedding.speaker_label,
        embedding=tuple(embedding.vector),
        quality=_audio_quality_response(evaluated.quality),
    )
    return response.to_json()


def build_template_from_json(
    value: dict[str, Any],
    *,
    runtime: VerifierRuntime | None = None,
) -> dict[str, Any]:
    active_runtime = runtime or get_default_runtime()
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
        "adapterId": active_runtime.metadata.adapter_id,
        "modelId": active_runtime.metadata.model_id,
        "modelVersion": active_runtime.metadata.model_version,
        "thresholdVersion": active_runtime.metadata.threshold_version,
        "templateVersion": active_runtime.metadata.template_version,
        "speakerLabel": accepted_embeddings[0].speaker_label,
        "sampleCount": len(accepted_embeddings),
        "embeddingDimensions": len(accepted_embeddings[0].vector),
        "embedding": _average_embedding(accepted_embeddings),
    }
    return BuiltTemplateResponse(
        kind="built",
        request_id=request.request_id,
        encrypted_template=_encode_template_payload(template_payload),
        template_version=active_runtime.metadata.template_version,
        model_version=active_runtime.metadata.model_version,
        threshold_version=active_runtime.metadata.threshold_version,
        speaker_label=accepted_embeddings[0].speaker_label,
    ).to_json()


def verify_speaker_from_json(
    value: dict[str, Any],
    *,
    runtime: VerifierRuntime | None = None,
) -> dict[str, Any]:
    active_runtime = runtime or get_default_runtime()
    request = parse_verify_speaker_request(value)
    evaluated = active_runtime.evaluate_audio(request.audio.audio_bytes, request.audio.metadata.duration_ms)
    quality = _audio_quality_response(evaluated.quality)
    if quality.kind != "accepted":
        speaker = SpeakerUncertain(
            kind="uncertain",
            reason="low_audio_quality",
            score=0.0,
            threshold=request.threshold,
            model_version=active_runtime.metadata.model_version,
            threshold_version=active_runtime.metadata.threshold_version,
        )
    else:
        try:
            template_payload = _decode_template_payload(request.template.encrypted_template)
            template_embedding = template_payload["embedding"]
            runtime_embedding = active_runtime.extract_embedding(
                request.audio.audio_bytes,
                evaluated.decoded_audio,
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
            if score >= request.threshold:
                speaker = SpeakerAccepted(
                    kind="accepted",
                    score=score,
                    threshold=request.threshold,
                    model_version=active_runtime.metadata.model_version,
                    threshold_version=active_runtime.metadata.threshold_version,
                )
            elif score >= request.threshold - 0.05:
                speaker = SpeakerUncertain(
                    kind="uncertain",
                    reason="model_low_confidence",
                    score=score,
                    threshold=request.threshold,
                    model_version=active_runtime.metadata.model_version,
                    threshold_version=active_runtime.metadata.threshold_version,
                )
            else:
                speaker = SpeakerRejected(
                    kind="rejected",
                    reason="speaker_mismatch",
                    score=score,
                    threshold=request.threshold,
                    model_version=active_runtime.metadata.model_version,
                    threshold_version=active_runtime.metadata.threshold_version,
                )
    return SpeakerVerificationResponse(
        kind="speaker_verification",
        request_id=request.request_id,
        quality=quality,
        speaker=speaker,
    ).to_json()


def get_default_runtime() -> VerifierRuntime:
    global DEFAULT_RUNTIME
    if DEFAULT_RUNTIME is None:
        DEFAULT_RUNTIME = create_verifier_runtime_from_env()
    return DEFAULT_RUNTIME


def _audio_quality_response(quality: object) -> AudioQualityResponse:
    kind = getattr(quality, "kind")
    duration_ms = getattr(quality, "duration_ms")
    reason = getattr(quality, "reason", None)
    signal_score = getattr(quality, "signal_score", None)
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
    if len(sys.argv) == 2:
        if sys.argv[1] == "serve_http":
            run_http_server_from_env()
            return
        request = json.load(sys.stdin)
        print(json.dumps(handle_cli_operation(sys.argv[1], request), separators=(",", ":")))
        return
    print("VoiceID verifier service. Use an operation name for CLI mode or serve_http for HTTP mode.")


def handle_cli_operation(operation: str, request: dict[str, Any]) -> dict[str, Any]:
    if operation == "extract_enrollment_embedding":
        return extract_enrollment_embedding_from_json(request)
    if operation == "build_template":
        return build_template_from_json(request)
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
    if operation == "extract_enrollment_embedding":
        return extract_enrollment_embedding_from_json(request, runtime=runtime)
    if operation == "build_template":
        return build_template_from_json(request, runtime=runtime)
    if operation == "verify_speaker":
        return verify_speaker_from_json(request, runtime=runtime)
    raise ValueError("unknown verifier operation")


def make_verifier_http_handler(
    *,
    runtime: VerifierRuntime | None = None,
) -> type[BaseHTTPRequestHandler]:
    class VerifierHttpHandler(BaseHTTPRequestHandler):
        server_version = "VoiceIdVerifierHTTP/0.1"

        def do_OPTIONS(self) -> None:
            self._write_json(200, {"kind": "ok"})

        def do_GET(self) -> None:
            path = urlparse(self.path).path.rstrip("/")
            if path in ("", "/health"):
                self._write_json(
                    200,
                    {
                        "kind": "ok",
                        "service": "voice-id-verifier",
                        "routes": [
                            "POST /voice-id/verifier/extract-enrollment-embedding",
                            "POST /voice-id/verifier/build-template",
                            "POST /voice-id/verifier/verify-speaker",
                        ],
                    },
                )
                return
            self._write_json(404, {"kind": "error", "error": {"kind": "not_found"}})

        def do_POST(self) -> None:
            try:
                request = self._read_json_request()
                response = handle_http_operation(self.path, request, runtime=runtime)
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

    return VerifierHttpHandler


def run_http_server_from_env() -> None:
    host = os.environ.get("VOICEID_VERIFIER_HOST", "127.0.0.1")
    port = int(os.environ.get("VOICEID_VERIFIER_PORT", "5051"))
    run_http_server(host=host, port=port)


def run_http_server(*, host: str, port: int) -> None:
    server = ThreadingHTTPServer((host, port), make_verifier_http_handler())
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
    if normalized_path.endswith("/extract-enrollment-embedding"):
        return "extract_enrollment_embedding"
    if normalized_path.endswith("/build-template"):
        return "build_template"
    if normalized_path.endswith("/verify-speaker"):
        return "verify_speaker"
    raise ValueError("unknown verifier operation")


if __name__ == "__main__":
    main()
