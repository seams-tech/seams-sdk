from __future__ import annotations

import io
import json
import math
import struct
import threading
import unittest
import wave
from http.server import ThreadingHTTPServer
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from voiceid_verifier.app import (
    build_template_from_json,
    extract_enrollment_embedding_from_json,
    make_verifier_http_handler,
    verify_speaker_from_json,
)
from voiceid_verifier.embeddings import ExtractedSpeakerEmbedding
from voiceid_verifier.runtime import SpeechBrainEcapaVerifierRuntime
from voiceid_verifier.schemas import (
    VerifierSchemaError,
    encode_audio_bytes,
    parse_extract_enrollment_embedding_request,
)


class VerifierSchemaTest(unittest.TestCase):
    def test_parses_extract_embedding_request(self) -> None:
        request = parse_extract_enrollment_embedding_request(
            extract_embedding_request(audio_bytes=b"voice")
        )

        self.assertEqual(request.schema_version, "voice_id_verifier_v1")
        self.assertEqual(request.request_id, "request_1")
        self.assertEqual(request.audio.audio_bytes, b"voice")
        self.assertEqual(request.audio.metadata.duration_ms, 1800)
        self.assertEqual(request.audio.metadata.sample_rate.kind, "known")
        self.assertEqual(request.audio.metadata.channel_count.kind, "known")

    def test_rejects_audio_byte_length_mismatch(self) -> None:
        payload = extract_embedding_request(audio_bytes=b"voice")
        payload["audio"]["metadata"]["byteLength"] = 4

        with self.assertRaisesRegex(VerifierSchemaError, "byte length"):
            parse_extract_enrollment_embedding_request(payload)

    def test_rejects_boolean_embedding_values(self) -> None:
        with self.assertRaisesRegex(VerifierSchemaError, "must be a number"):
            build_template_from_json(
                {
                    "schemaVersion": "voice_id_verifier_v1",
                    "requestId": "template_request_1",
                    "embeddings": [
                        {
                            "vector": [True],
                            "speakerLabel": "owner",
                            "quality": {"kind": "accepted", "durationMs": 1800, "signalScore": 0.9},
                        }
                    ],
                }
            )

    def test_extracts_embedding_response_with_camel_case_schema(self) -> None:
        response = extract_enrollment_embedding_from_json(
            extract_embedding_request(audio_bytes=b"voice")
        )

        self.assertEqual(response["kind"], "embedding")
        self.assertEqual(response["requestId"], "request_1")
        self.assertEqual(response["modelVersion"], "python-placeholder-model-v1")
        self.assertEqual(response["thresholdVersion"], "python-placeholder-threshold-v1")
        self.assertEqual(response["quality"]["kind"], "accepted")
        self.assertGreater(len(response["embedding"]), 0)

    def test_builds_template_and_verifies_speaker(self) -> None:
        embedding_response = extract_enrollment_embedding_from_json(
            extract_embedding_request(audio_bytes=b"voice")
        )
        template_response = build_template_from_json(
            {
                "schemaVersion": "voice_id_verifier_v1",
                "requestId": "template_request_1",
                "embeddings": [
                    {
                        "vector": embedding_response["embedding"],
                        "speakerLabel": "owner",
                        "quality": embedding_response["quality"],
                    }
                ],
            }
        )
        verification_response = verify_speaker_from_json(
            {
                "schemaVersion": "voice_id_verifier_v1",
                "requestId": "verify_request_1",
                "audio": audio_payload(audio_bytes=b"voice"),
                "template": {
                    "encryptedTemplate": template_response["encryptedTemplate"],
                    "templateVersion": template_response["templateVersion"],
                    "modelVersion": template_response["modelVersion"],
                    "thresholdVersion": template_response["thresholdVersion"],
                },
                "threshold": 0.5,
            }
        )

        self.assertEqual(template_response["kind"], "built")
        self.assertEqual(verification_response["kind"], "speaker_verification")
        self.assertEqual(verification_response["quality"]["kind"], "accepted")
        self.assertEqual(verification_response["speaker"]["kind"], "accepted")

    def test_verifies_speaker_rejected_branch(self) -> None:
        template_response = build_template_from_json(
            {
                "schemaVersion": "voice_id_verifier_v1",
                "requestId": "template_request_1",
                "embeddings": [accepted_embedding("owner", vector=[0.0, 0.0, 1.0, 0.0])],
            }
        )
        verification_response = verify_speaker_from_json(
            {
                "schemaVersion": "voice_id_verifier_v1",
                "requestId": "verify_request_1",
                "audio": audio_payload(audio_bytes=b"voice"),
                "template": template_reference(template_response),
                "threshold": 0.99,
            }
        )

        self.assertEqual(verification_response["quality"]["kind"], "accepted")
        self.assertEqual(verification_response["speaker"]["kind"], "rejected")
        self.assertEqual(verification_response["speaker"]["reason"], "speaker_mismatch")

    def test_verifies_speaker_uncertain_branch_for_low_quality_audio(self) -> None:
        template_response = build_template_from_json(
            {
                "schemaVersion": "voice_id_verifier_v1",
                "requestId": "template_request_1",
                "embeddings": [accepted_embedding("owner")],
            }
        )
        verification_response = verify_speaker_from_json(
            {
                "schemaVersion": "voice_id_verifier_v1",
                "requestId": "verify_request_1",
                "audio": audio_payload(audio_bytes=b"voice", duration_ms=500),
                "template": template_reference(template_response),
                "threshold": 0.5,
            }
        )

        self.assertEqual(verification_response["quality"]["kind"], "uncertain")
        self.assertEqual(verification_response["speaker"]["kind"], "uncertain")
        self.assertEqual(verification_response["speaker"]["reason"], "low_audio_quality")

    def test_template_build_rejects_inconsistent_speaker_labels(self) -> None:
        response = build_template_from_json(
            {
                "schemaVersion": "voice_id_verifier_v1",
                "requestId": "template_request_1",
                "embeddings": [
                    accepted_embedding("owner"),
                    accepted_embedding("other"),
                ],
            }
        )

        self.assertEqual(response["kind"], "rejected")
        self.assertEqual(response["reason"], "inconsistent_speaker")

    def test_ecapa_runtime_extracts_injected_model_embedding(self) -> None:
        runtime = SpeechBrainEcapaVerifierRuntime(extractor=FakeEcapaExtractor())
        response = extract_enrollment_embedding_from_json(
            extract_embedding_request(audio_bytes=wav_audio_bytes()),
            runtime=runtime,
        )

        self.assertEqual(response["modelVersion"], "speechbrain-ecapa-voxceleb@2026-06-11")
        self.assertEqual(response["thresholdVersion"], "ecapa-local-dev-v1")
        self.assertEqual(response["quality"]["kind"], "accepted")
        self.assertEqual(len(response["embedding"]), 192)

    def test_ecapa_runtime_skips_speaker_scoring_for_low_quality_audio(self) -> None:
        runtime = SpeechBrainEcapaVerifierRuntime(extractor=FailingEcapaExtractor())
        template_response = build_template_from_json(
            {
                "schemaVersion": "voice_id_verifier_v1",
                "requestId": "template_request_1",
                "embeddings": [accepted_embedding("owner", vector=[0.1] * 192)],
            },
            runtime=runtime,
        )

        verification_response = verify_speaker_from_json(
            {
                "schemaVersion": "voice_id_verifier_v1",
                "requestId": "verify_request_1",
                "audio": audio_payload(audio_bytes=wav_audio_bytes(duration_ms=500), duration_ms=500),
                "template": template_reference(template_response),
                "threshold": 0.6352,
            },
            runtime=runtime,
        )

        self.assertEqual(verification_response["quality"]["kind"], "uncertain")
        self.assertEqual(verification_response["quality"]["reason"], "too_short")
        self.assertEqual(verification_response["speaker"]["kind"], "uncertain")
        self.assertEqual(verification_response["speaker"]["reason"], "low_audio_quality")

    def test_ecapa_runtime_skips_speaker_scoring_when_vad_detects_too_little_speech(self) -> None:
        runtime = SpeechBrainEcapaVerifierRuntime(extractor=FailingEcapaExtractor())
        template_response = build_template_from_json(
            {
                "schemaVersion": "voice_id_verifier_v1",
                "requestId": "template_request_1",
                "embeddings": [accepted_embedding("owner", vector=[0.1] * 192)],
            },
            runtime=runtime,
        )

        verification_response = verify_speaker_from_json(
            {
                "schemaVersion": "voice_id_verifier_v1",
                "requestId": "verify_request_1",
                "audio": audio_payload(
                    audio_bytes=wav_audio_bytes(duration_ms=1400, speech_duration_ms=120),
                    duration_ms=1400,
                ),
                "template": template_reference(template_response),
                "threshold": 0.6352,
            },
            runtime=runtime,
        )

        self.assertEqual(verification_response["quality"]["kind"], "uncertain")
        self.assertEqual(verification_response["quality"]["reason"], "low_speech")
        self.assertEqual(verification_response["speaker"]["kind"], "uncertain")
        self.assertEqual(verification_response["speaker"]["reason"], "low_audio_quality")

    def test_http_sidecar_exposes_typed_verifier_operations(self) -> None:
        server, thread = start_http_server()
        try:
            base_url = f"http://127.0.0.1:{server.server_port}/voice-id/verifier"
            embedding_response = post_json(
                f"{base_url}/extract-enrollment-embedding",
                extract_embedding_request(audio_bytes=b"voice"),
            )
            template_response = post_json(
                f"{base_url}/build-template",
                {
                    "schemaVersion": "voice_id_verifier_v1",
                    "requestId": "template_request_1",
                    "embeddings": [
                        {
                            "vector": embedding_response["embedding"],
                            "speakerLabel": "owner",
                            "quality": embedding_response["quality"],
                        }
                    ],
                },
            )
            verification_response = post_json(
                f"{base_url}/verify-speaker",
                {
                    "schemaVersion": "voice_id_verifier_v1",
                    "requestId": "verify_request_1",
                    "audio": audio_payload(audio_bytes=b"voice"),
                    "template": template_reference(template_response),
                    "threshold": 0.5,
                },
            )

            self.assertEqual(embedding_response["kind"], "embedding")
            self.assertEqual(template_response["kind"], "built")
            self.assertEqual(verification_response["kind"], "speaker_verification")
            self.assertEqual(verification_response["speaker"]["kind"], "accepted")
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

    def test_http_sidecar_rejects_malformed_requests(self) -> None:
        server, thread = start_http_server()
        try:
            with self.assertRaises(HTTPError) as caught:
                post_json(
                    f"http://127.0.0.1:{server.server_port}/voice-id/verifier/extract-enrollment-embedding",
                    {"bad": True},
                )
            self.assertEqual(caught.exception.code, 400)
            body = json.loads(caught.exception.read().decode("utf-8"))
            self.assertEqual(body["kind"], "error")
            self.assertEqual(body["error"]["kind"], "malformed_request")
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)


def extract_embedding_request(*, audio_bytes: bytes) -> dict[str, object]:
    return {
        "schemaVersion": "voice_id_verifier_v1",
        "requestId": "request_1",
        "audio": audio_payload(audio_bytes=audio_bytes),
    }


def audio_payload(*, audio_bytes: bytes, duration_ms: int = 1800) -> dict[str, object]:
    return {
        "audioBase64": encode_audio_bytes(audio_bytes),
        "metadata": {
            "mimeType": "audio/webm",
            "durationMs": duration_ms,
            "sampleRate": {"kind": "known", "hertz": 48000},
            "channelCount": {"kind": "known", "count": 1},
            "byteLength": len(audio_bytes),
            "capturedAt": "2026-06-09T00:00:00.000Z",
            "recorder": "MediaRecorder",
        },
    }


def accepted_embedding(
    speaker_label: str,
    *,
    vector: list[float] | None = None,
) -> dict[str, object]:
    return {
        "vector": vector if vector is not None else [0.1, 0.2, 0.3, 0.4],
        "speakerLabel": speaker_label,
        "quality": {"kind": "accepted", "durationMs": 1800, "signalScore": 0.9},
    }


def template_reference(template_response: dict[str, object]) -> dict[str, object]:
    return {
        "encryptedTemplate": template_response["encryptedTemplate"],
        "templateVersion": template_response["templateVersion"],
        "modelVersion": template_response["modelVersion"],
        "thresholdVersion": template_response["thresholdVersion"],
    }


def start_http_server() -> tuple[ThreadingHTTPServer, threading.Thread]:
    server = ThreadingHTTPServer(("127.0.0.1", 0), make_verifier_http_handler())
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread


def post_json(url: str, payload: dict[str, object]) -> dict[str, object]:
    body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    request = Request(url, data=body, headers={"Content-Type": "application/json"}, method="POST")
    with urlopen(request, timeout=5) as response:
        value = json.loads(response.read().decode("utf-8"))
    if not isinstance(value, dict):
        raise AssertionError("HTTP sidecar response must be a JSON object")
    return value


def wav_audio_bytes(
    *,
    duration_ms: int = 1200,
    sample_rate_hz: int = 16000,
    speech_duration_ms: int | None = None,
) -> bytes:
    sample_count = int(sample_rate_hz * duration_ms / 1000)
    speech_sample_count = (
        sample_count
        if speech_duration_ms is None
        else int(sample_rate_hz * speech_duration_ms / 1000)
    )
    buffer = io.BytesIO()
    with wave.open(buffer, "wb") as wav_file:
        wav_file.setnchannels(1)
        wav_file.setsampwidth(2)
        wav_file.setframerate(sample_rate_hz)
        frames = bytearray()
        for index in range(sample_count):
            value = (
                int(0.2 * 32767 * math.sin(2 * math.pi * 440 * index / sample_rate_hz))
                if index < speech_sample_count
                else 0
            )
            frames.extend(struct.pack("<h", value))
        wav_file.writeframes(bytes(frames))
    return buffer.getvalue()


class FakeEcapaExtractor:
    embedding_dimensions = 192

    def extract_decoded(self, samples: object) -> ExtractedSpeakerEmbedding:
        return ExtractedSpeakerEmbedding(vector=[0.1] * self.embedding_dimensions, speaker_label="unknown_speaker")

    def zero_embedding(self) -> ExtractedSpeakerEmbedding:
        return ExtractedSpeakerEmbedding(vector=[0.0] * self.embedding_dimensions, speaker_label="unknown_speaker")


class FailingEcapaExtractor(FakeEcapaExtractor):
    def extract_decoded(self, samples: object) -> ExtractedSpeakerEmbedding:
        raise AssertionError("speaker extraction should not run for low-quality audio")


if __name__ == "__main__":
    unittest.main()
