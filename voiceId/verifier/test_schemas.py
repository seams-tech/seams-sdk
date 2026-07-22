from __future__ import annotations

import io
import json
import math
import struct
import threading
import unittest
import wave
from collections.abc import Sequence
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from voiceid_verifier.app import (
    VoiceIdVerifierHttpServer,
    build_enrollment_template_from_json,
    verify_speaker_from_json,
)
from voiceid_verifier.embeddings import ExtractedSpeakerEmbedding
from voiceid_verifier.runtime import SpeechBrainEcapaVerifierRuntime
from voiceid_verifier.schemas import (
    VerifierSchemaError,
    encode_audio_bytes,
    parse_build_enrollment_template_request,
)


class VerifierSchemaTest(unittest.TestCase):
    def test_parses_atomic_enrollment_request(self) -> None:
        audio_bytes = enrollment_audio_bytes()
        request = parse_build_enrollment_template_request(
            enrollment_request(audio_bytes=audio_bytes)
        )

        self.assertEqual(request.schema_version, "voice_id_verifier_v2")
        self.assertEqual(request.request_id, "enrollment_request_1")
        self.assertEqual(request.audio.audio_bytes, audio_bytes)
        self.assertEqual(request.expected_prompt_count, 4)

    def test_rejects_extra_boundary_fields(self) -> None:
        payload = enrollment_request(audio_bytes=enrollment_audio_bytes())
        payload["unexpectedField"] = [0.1]

        with self.assertRaisesRegex(VerifierSchemaError, "unexpected or missing fields"):
            parse_build_enrollment_template_request(payload)

    def test_rejects_audio_byte_length_mismatch(self) -> None:
        payload = enrollment_request(audio_bytes=enrollment_audio_bytes())
        payload["audio"]["metadata"]["byteLength"] = 4

        with self.assertRaisesRegex(VerifierSchemaError, "byte length"):
            parse_build_enrollment_template_request(payload)

    def test_builds_template_from_one_continuous_recording(self) -> None:
        response = build_enrollment_template_from_json(
            enrollment_request(audio_bytes=enrollment_audio_bytes())
        )

        self.assertEqual(response["kind"], "built")
        self.assertEqual(response["quality"]["kind"], "accepted")
        self.assertEqual(response["analysis"]["analysisVersion"], "continuous-enrollment-v1")
        self.assertGreaterEqual(len(response["analysis"]["windows"]), 4)
        self.assertNotIn("embedding", response)
        self.assertNotIn("speakerLabel", response)

    def test_enrollment_zeroes_decoded_windows_and_embeddings(self) -> None:
        extractor = InspectingEcapaExtractor()
        runtime = SpeechBrainEcapaVerifierRuntime(extractor=extractor)

        response = build_enrollment_template_from_json(
            enrollment_request(audio_bytes=enrollment_audio_bytes()),
            runtime=runtime,
        )

        self.assertEqual(response["kind"], "built")
        self.assertTrue(all(all(value == 0.0 for value in samples) for samples in extractor.sample_references))
        self.assertTrue(all(all(value == 0.0 for value in vector) for vector in extractor.vector_references))

    def test_builds_template_and_verifies_speaker(self) -> None:
        enrollment_bytes = enrollment_audio_bytes()
        template_response = build_enrollment_template_from_json(
            enrollment_request(audio_bytes=enrollment_bytes)
        )
        verification_bytes = wav_audio_bytes([(240, 1800)])
        verification_response = verify_speaker_from_json(
            verification_request(
                audio_bytes=verification_bytes,
                duration_ms=1800,
                template_response=template_response,
            )
        )

        self.assertEqual(template_response["kind"], "built")
        self.assertEqual(verification_response["kind"], "speaker_verification")
        self.assertEqual(verification_response["quality"]["kind"], "accepted")
        self.assertEqual(verification_response["speaker"]["kind"], "accepted")

    def test_canonical_pipeline_is_stable_across_repeated_runs(self) -> None:
        enrollment_payload = enrollment_request(audio_bytes=enrollment_audio_bytes())
        first_template = build_enrollment_template_from_json(enrollment_payload)
        second_template = build_enrollment_template_from_json(enrollment_payload)
        self.assertEqual(first_template, second_template)

        verification_bytes = wav_audio_bytes([(240, 1800)])
        verification_payload = verification_request(
            audio_bytes=verification_bytes,
            duration_ms=1800,
            template_response=first_template,
        )
        first_verification = verify_speaker_from_json(verification_payload)
        second_verification = verify_speaker_from_json(verification_payload)
        self.assertEqual(first_verification, second_verification)

    def test_returns_decoder_failure_for_undecodable_capture(self) -> None:
        response = build_enrollment_template_from_json(
            enrollment_request(audio_bytes=b"invalid audio", duration_ms=12000)
        )

        self.assertEqual(response, {
            "kind": "rejected",
            "requestId": "enrollment_request_1",
            "reason": "decoder_failure",
        })

    def test_returns_metadata_mismatch_for_false_capture_claims(self) -> None:
        response = build_enrollment_template_from_json(
            enrollment_request(
                audio_bytes=enrollment_audio_bytes(),
                mime_type="audio/webm",
                sample_rate_hz=48000,
            )
        )

        self.assertEqual(response["kind"], "rejected")
        self.assertEqual(response["reason"], "metadata_mismatch")

    def test_returns_insufficient_windows_for_interrupted_guidance(self) -> None:
        audio_bytes = wav_audio_bytes([(210, 2500), (None, 7000), (320, 2500)])
        response = build_enrollment_template_from_json(
            enrollment_request(audio_bytes=audio_bytes)
        )

        self.assertEqual(response["kind"], "rejected")
        self.assertEqual(response["reason"], "insufficient_windows")

    def test_returns_duplicate_windows_for_replayed_segments(self) -> None:
        audio_bytes = wav_audio_bytes(
            [(220, 2500), (None, 500)] * 4
        )
        response = build_enrollment_template_from_json(
            enrollment_request(audio_bytes=audio_bytes)
        )

        self.assertEqual(response["kind"], "rejected")
        self.assertEqual(response["reason"], "duplicate_windows")

    def test_returns_multi_speaker_for_inconsistent_window_labels(self) -> None:
        runtime = SpeechBrainEcapaVerifierRuntime(extractor=AlternatingSpeakerExtractor())
        response = build_enrollment_template_from_json(
            enrollment_request(audio_bytes=enrollment_audio_bytes()),
            runtime=runtime,
        )

        self.assertEqual(response["kind"], "rejected")
        self.assertEqual(response["reason"], "multi_speaker")

    def test_skips_speaker_scoring_for_low_quality_audio(self) -> None:
        runtime = SpeechBrainEcapaVerifierRuntime(extractor=InspectingEcapaExtractor())
        template_response = build_enrollment_template_from_json(
            enrollment_request(audio_bytes=enrollment_audio_bytes()),
            runtime=runtime,
        )
        failing_runtime = SpeechBrainEcapaVerifierRuntime(extractor=FailingEcapaExtractor())
        short_audio = wav_audio_bytes([(240, 500)])

        verification_response = verify_speaker_from_json(
            verification_request(
                audio_bytes=short_audio,
                duration_ms=500,
                template_response=template_response,
            ),
            runtime=failing_runtime,
        )

        self.assertEqual(verification_response["quality"]["kind"], "uncertain")
        self.assertEqual(verification_response["quality"]["reason"], "too_short")
        self.assertEqual(verification_response["speaker"]["kind"], "uncertain")
        self.assertEqual(verification_response["speaker"]["reason"], "low_audio_quality")

    def test_http_sidecar_exposes_only_current_operations(self) -> None:
        server, thread = start_http_server()
        try:
            base_url = f"http://127.0.0.1:{server.server_port}/voice-id/verifier"
            template_response = post_json(
                f"{base_url}/build-enrollment-template",
                enrollment_request(audio_bytes=enrollment_audio_bytes()),
            )
            verification_response = post_json(
                f"{base_url}/verify-speaker",
                verification_request(
                    audio_bytes=wav_audio_bytes([(240, 1800)]),
                    duration_ms=1800,
                    template_response=template_response,
                ),
            )

            self.assertEqual(template_response["kind"], "built")
            self.assertEqual(verification_response["speaker"]["kind"], "accepted")
        finally:
            stop_http_server(server, thread)

    def test_http_sidecar_rejects_malformed_requests(self) -> None:
        server, thread = start_http_server()
        try:
            with self.assertRaises(HTTPError) as caught:
                post_json(
                    f"http://127.0.0.1:{server.server_port}/voice-id/verifier/build-enrollment-template",
                    {"bad": True},
                )
            self.assertEqual(caught.exception.code, 400)
            body = json.loads(caught.exception.read().decode("utf-8"))
            caught.exception.close()
            self.assertEqual(body["error"]["kind"], "malformed_request")
        finally:
            stop_http_server(server, thread)

    def test_http_sidecar_does_not_expose_browser_cors(self) -> None:
        server, thread = start_http_server()
        try:
            with urlopen(f"http://127.0.0.1:{server.server_port}/health", timeout=5) as response:
                self.assertIsNone(response.headers.get("Access-Control-Allow-Origin"))
        finally:
            stop_http_server(server, thread)

    def test_http_sidecar_reports_warm_runtime_readiness_and_bounded_admission(self) -> None:
        server = VoiceIdVerifierHttpServer(
            ("127.0.0.1", 0),
            maximum_concurrent_inferences=1,
            queue_wait_ms=0,
        )
        try:
            health = server.health_response()
            self.assertEqual(health["readiness"], "ready")
            self.assertEqual(health["runtime"]["maximumConcurrentInferences"], 1)
            self.assertTrue(server.acquire_inference_slot())
            self.assertFalse(server.acquire_inference_slot())
            server.release_inference_slot()
            self.assertTrue(server.acquire_inference_slot())
            server.release_inference_slot()
        finally:
            server.server_close()


def enrollment_request(
    *,
    audio_bytes: bytes,
    duration_ms: int = 12000,
    mime_type: str = "audio/wav",
    sample_rate_hz: int = 16000,
) -> dict[str, object]:
    return {
        "schemaVersion": "voice_id_verifier_v2",
        "requestId": "enrollment_request_1",
        "audio": audio_payload(
            audio_bytes=audio_bytes,
            duration_ms=duration_ms,
            mime_type=mime_type,
            sample_rate_hz=sample_rate_hz,
        ),
        "expectedPromptCount": 4,
    }


def verification_request(
    *,
    audio_bytes: bytes,
    duration_ms: int,
    template_response: dict[str, object],
) -> dict[str, object]:
    return {
        "schemaVersion": "voice_id_verifier_v2",
        "requestId": "verify_request_1",
        "audio": audio_payload(audio_bytes=audio_bytes, duration_ms=duration_ms),
        "template": template_reference(template_response),
        "threshold": 0.5,
    }


def audio_payload(
    *,
    audio_bytes: bytes,
    duration_ms: int,
    mime_type: str = "audio/wav",
    sample_rate_hz: int = 16000,
) -> dict[str, object]:
    return {
        "audioBase64": encode_audio_bytes(audio_bytes),
        "metadata": {
            "mimeType": mime_type,
            "durationMs": duration_ms,
            "sampleRate": {"kind": "known", "hertz": sample_rate_hz},
            "channelCount": {"kind": "known", "count": 1},
            "byteLength": len(audio_bytes),
            "capturedAt": "2026-06-09T00:00:00.000Z",
            "recorder": "MediaRecorder",
        },
    }


def template_reference(template_response: dict[str, object]) -> dict[str, object]:
    return {
        "encryptedTemplate": template_response["encryptedTemplate"],
        "templateVersion": template_response["templateVersion"],
        "modelVersion": template_response["modelVersion"],
        "thresholdVersion": template_response["thresholdVersion"],
    }


def start_http_server() -> tuple[VoiceIdVerifierHttpServer, threading.Thread]:
    server = VoiceIdVerifierHttpServer(("127.0.0.1", 0))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread


def stop_http_server(server: VoiceIdVerifierHttpServer, thread: threading.Thread) -> None:
    server.shutdown()
    server.server_close()
    thread.join(timeout=2)


def post_json(url: str, payload: dict[str, object]) -> dict[str, object]:
    body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    request = Request(url, data=body, headers={"Content-Type": "application/json"}, method="POST")
    with urlopen(request, timeout=5) as response:
        value = json.loads(response.read().decode("utf-8"))
    if not isinstance(value, dict):
        raise AssertionError("HTTP sidecar response must be a JSON object")
    return value


def enrollment_audio_bytes() -> bytes:
    return wav_audio_bytes(
        [(210, 2500), (None, 500), (270, 2500), (None, 500),
         (330, 2500), (None, 500), (410, 2500), (None, 500)]
    )


def wav_audio_bytes(
    segments: Sequence[tuple[int | None, int]],
    *,
    sample_rate_hz: int = 16000,
) -> bytes:
    buffer = io.BytesIO()
    with wave.open(buffer, "wb") as wav_file:
        wav_file.setnchannels(1)
        wav_file.setsampwidth(2)
        wav_file.setframerate(sample_rate_hz)
        frames = bytearray()
        for frequency_hz, duration_ms in segments:
            sample_count = int(sample_rate_hz * duration_ms / 1000)
            for index in range(sample_count):
                value = 0 if frequency_hz is None else int(
                    0.2 * 32767 * math.sin(2 * math.pi * frequency_hz * index / sample_rate_hz)
                )
                frames.extend(struct.pack("<h", value))
        wav_file.writeframes(bytes(frames))
    return buffer.getvalue()


class InspectingEcapaExtractor:
    embedding_dimensions = 192

    def __init__(self) -> None:
        self.sample_references: list[Sequence[float]] = []
        self.vector_references: list[list[float]] = []

    def extract_decoded(self, samples: Sequence[float]) -> ExtractedSpeakerEmbedding:
        vector = [0.1] * self.embedding_dimensions
        self.sample_references.append(samples)
        self.vector_references.append(vector)
        return ExtractedSpeakerEmbedding(vector=vector, speaker_label="unknown_speaker")

class AlternatingSpeakerExtractor(InspectingEcapaExtractor):
    def extract_decoded(self, samples: Sequence[float]) -> ExtractedSpeakerEmbedding:
        embedding = super().extract_decoded(samples)
        label = "speaker_a" if len(self.sample_references) % 2 == 1 else "speaker_b"
        return ExtractedSpeakerEmbedding(vector=embedding.vector, speaker_label=label)


class FailingEcapaExtractor(InspectingEcapaExtractor):
    def extract_decoded(self, samples: Sequence[float]) -> ExtractedSpeakerEmbedding:
        raise AssertionError("speaker extraction should not run for low-quality audio")


if __name__ == "__main__":
    unittest.main()
