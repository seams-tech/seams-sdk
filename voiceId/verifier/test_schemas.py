from __future__ import annotations

import io
import json
import math
import struct
import threading
import time
import unittest
import wave
from collections.abc import Sequence
from concurrent.futures import Future
from http.client import HTTPConnection
from unittest.mock import patch
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from voiceid_verifier.app import (
    BoundedStageExecutor,
    TimedStageResult,
    VoiceIdVerifierHttpServer,
    VerificationStageDeadlines,
    analyze_verification_from_json,
    analyze_speech_from_json,
    build_enrollment_template_from_json,
    resolve_stage,
    verify_speaker_from_json,
)
from voiceid_verifier.embeddings import ExtractedSpeakerEmbedding
from voiceid_verifier.moonshine import (
    MoonshineIntentDecision,
    MoonshinePhraseDecision,
    MoonshineSpeechAnalysis,
)
from voiceid_verifier.pad import PadDecision
from voiceid_verifier.runtime import SpeechBrainEcapaVerifierRuntime
from voiceid_verifier.schemas import (
    MAXIMUM_JSON_REQUEST_BYTES,
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

    def test_analyzes_one_canonical_pcm_buffer_and_returns_intent_separately(self) -> None:
        response = analyze_speech_from_json(
            speech_analysis_request(audio_bytes=wav_audio_bytes([(240, 1800)])),
            recognizer=FakeMoonshineRecognizer(),
        )

        self.assertEqual(response["kind"], "speech_analysis")
        self.assertEqual(response["sampleRateHz"], 16000)
        self.assertEqual(response["phrase"]["kind"], "accepted")
        self.assertEqual(response["intent"]["kind"], "accepted")

    def test_combined_verification_reuses_one_decoded_buffer_and_zeroes_it(self) -> None:
        template_extractor = InspectingEcapaExtractor()
        template_runtime = SpeechBrainEcapaVerifierRuntime(extractor=template_extractor)
        template_response = build_enrollment_template_from_json(
            enrollment_request(audio_bytes=enrollment_audio_bytes()),
            runtime=template_runtime,
        )
        extractor = InspectingEcapaExtractor()
        runtime = SpeechBrainEcapaVerifierRuntime(extractor=extractor)
        response = analyze_verification_from_json(
            verification_analysis_request(
                audio_bytes=wav_audio_bytes([(240, 1800)]),
                template_response=template_response,
            ),
            runtime=runtime,
            recognizer=FakeMoonshineRecognizer(),
        )

        self.assertEqual(response["kind"], "verification_analysis")
        self.assertEqual(response["speech"]["intent"]["kind"], "accepted")
        self.assertEqual(response["speaker"]["kind"], "accepted")
        self.assertTrue(all(value == 0.0 for value in extractor.sample_references[0]))

    def test_combined_verification_runs_speech_and_windowed_speaker_inference_concurrently(
        self,
    ) -> None:
        template_runtime = SpeechBrainEcapaVerifierRuntime(
            extractor=InspectingEcapaExtractor()
        )
        template_response = build_enrollment_template_from_json(
            enrollment_request(audio_bytes=enrollment_audio_bytes()),
            runtime=template_runtime,
        )
        barrier = threading.Barrier(2)
        extractor = CoordinatedEcapaExtractor(barrier)
        runtime = SpeechBrainEcapaVerifierRuntime(extractor=extractor)
        audio_bytes = wav_audio_bytes([(None, 300), (240, 1200), (None, 300)])

        response = analyze_verification_from_json(
            verification_analysis_request(
                audio_bytes=audio_bytes,
                template_response=template_response,
            ),
            runtime=runtime,
            recognizer=CoordinatedMoonshineRecognizer(barrier),
        )

        self.assertEqual(response["speaker"]["kind"], "accepted")
        self.assertEqual(response["speech"]["intent"]["kind"], "accepted")
        self.assertLess(len(extractor.sample_references[0]), 1800 * 16)
        self.assertTrue(all(value == 0.0 for value in extractor.sample_references[0]))

    def test_combined_verification_runs_pad_on_the_same_accepted_speech_region(
        self,
    ) -> None:
        template_runtime = SpeechBrainEcapaVerifierRuntime(
            extractor=InspectingEcapaExtractor()
        )
        template_response = build_enrollment_template_from_json(
            enrollment_request(audio_bytes=enrollment_audio_bytes()),
            runtime=template_runtime,
        )
        barrier = threading.Barrier(3)
        extractor = CoordinatedEcapaExtractor(barrier)
        detector = CoordinatedPadDetector(barrier)
        runtime = SpeechBrainEcapaVerifierRuntime(extractor=extractor)
        audio_bytes = wav_audio_bytes([(None, 300), (240, 1200), (None, 300)])

        response = analyze_verification_from_json(
            verification_analysis_request(
                audio_bytes=audio_bytes,
                template_response=template_response,
            ),
            runtime=runtime,
            recognizer=CoordinatedMoonshineRecognizer(barrier),
            pad_detector=detector,
        )

        self.assertEqual(response["pad"]["kind"], "accepted")
        self.assertEqual(len(detector.sample_references[0]), len(extractor.sample_references[0]))
        self.assertTrue(all(value == 0.0 for value in detector.sample_references[0]))

    def test_combined_verification_fails_closed_at_stage_deadlines(self) -> None:
        template_runtime = SpeechBrainEcapaVerifierRuntime(
            extractor=InspectingEcapaExtractor()
        )
        template_response = build_enrollment_template_from_json(
            enrollment_request(audio_bytes=enrollment_audio_bytes()),
            runtime=template_runtime,
        )

        response = analyze_verification_from_json(
            verification_analysis_request(
                audio_bytes=wav_audio_bytes([(240, 1800)]),
                template_response=template_response,
            ),
            runtime=SpeechBrainEcapaVerifierRuntime(extractor=SlowEcapaExtractor()),
            recognizer=SlowMoonshineRecognizer(),
            pad_detector=SlowPadDetector(),
            stage_deadlines=VerificationStageDeadlines(
                speech_ms=1,
                speaker_ms=1,
                pad_ms=1,
            ),
        )

        self.assertEqual(response["speech"]["phrase"]["kind"], "uncertain")
        self.assertEqual(response["speaker"]["kind"], "uncertain")
        self.assertEqual(response["pad"]["kind"], "uncertain")
        self.assertEqual(response["pad"]["reason"], "deadline_exceeded")

    def test_stage_executor_rejects_work_when_all_model_slots_are_active(self) -> None:
        executor = BoundedStageExecutor(maximum_active_stages=1)
        started = threading.Event()
        release = threading.Event()
        first = executor.submit(blocking_timed_stage, started, release)
        self.assertIsNotNone(first)
        self.assertTrue(started.wait(timeout=1))

        second = executor.submit(blocking_timed_stage, started, release)

        self.assertIsNone(second)
        release.set()
        if first is not None:
            self.assertEqual(first.result(timeout=1).value, "complete")

    def test_stage_executor_releases_slot_after_failed_model_task(self) -> None:
        executor = BoundedStageExecutor(maximum_active_stages=1)
        failed = executor.submit(failing_timed_stage)
        self.assertIsNotNone(failed)
        if failed is not None:
            with self.assertRaisesRegex(RuntimeError, "model task failed"):
                failed.result(timeout=1)

        replacement = executor.submit(successful_timed_stage)

        self.assertIsNotNone(replacement)
        if replacement is not None:
            self.assertEqual(replacement.result(timeout=1).value, "replacement")

    def test_timed_out_running_stage_retains_slot_until_task_completion(self) -> None:
        executor = BoundedStageExecutor(maximum_active_stages=1)
        started = threading.Event()
        release = threading.Event()
        first = executor.submit(blocking_timed_stage, started, release)
        self.assertIsNotNone(first)
        try:
            self.assertTrue(started.wait(timeout=1))
            if first is None:
                self.fail("first stage must be admitted")
            self.assertIsNone(
                resolve_stage(
                    first,
                    started_at=time.monotonic() - 1,
                    deadline_ms=1,
                )
            )
            self.assertIsNone(executor.submit(successful_timed_stage))

            release.set()
            self.assertEqual(first.result(timeout=1).value, "complete")
            replacement = wait_for_stage_admission(executor)
            self.assertEqual(replacement.result(timeout=1).value, "replacement")
        finally:
            release.set()
            executor.shutdown()

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

    def test_malformed_and_truncated_media_fail_closed(self) -> None:
        malformed_captures = (
            b"\x00" * 128,
            b"RIFF\x10\x00\x00\x00WAVEfmt ",
            b"OggS\x00\x02",
            b'{"audio":"not media"}',
        )
        for audio_bytes in malformed_captures:
            with self.subTest(prefix=audio_bytes[:8]):
                response = build_enrollment_template_from_json(
                    enrollment_request(audio_bytes=audio_bytes, duration_ms=12000)
                )
                self.assertEqual(response["kind"], "rejected")
                self.assertEqual(response["reason"], "decoder_failure")

    def test_rejects_audio_beyond_maximum_decoded_duration(self) -> None:
        audio_bytes = wav_audio_bytes([(None, 30100)])

        response = build_enrollment_template_from_json(
            enrollment_request(audio_bytes=audio_bytes, duration_ms=30100)
        )

        self.assertEqual(response["kind"], "rejected")
        self.assertEqual(response["reason"], "decoder_failure")

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

    def test_rejects_leave_one_out_template_instability(self) -> None:
        runtime = SpeechBrainEcapaVerifierRuntime(extractor=UnstableEcapaExtractor())

        response = build_enrollment_template_from_json(
            enrollment_request(audio_bytes=enrollment_audio_bytes()),
            runtime=runtime,
        )

        self.assertEqual(response["kind"], "rejected")
        self.assertEqual(response["reason"], "incoherent_windows")

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

    def test_http_sidecar_rejects_oversized_body_before_reading_it(self) -> None:
        server, thread = start_http_server()
        connection = HTTPConnection("127.0.0.1", server.server_port, timeout=5)
        try:
            connection.request(
                "POST",
                "/voice-id/verifier/build-enrollment-template",
                body=b"{}",
                headers={
                    "Content-Type": "application/json",
                    "Content-Length": str(MAXIMUM_JSON_REQUEST_BYTES + 1),
                },
            )
            response = connection.getresponse()
            body = json.loads(response.read().decode("utf-8"))

            self.assertEqual(response.status, 400)
            self.assertEqual(body["error"]["kind"], "malformed_request")
            self.assertIn("maximum JSON byte length", body["error"]["message"])
        finally:
            connection.close()
            stop_http_server(server, thread)

    def test_http_sidecar_does_not_expose_browser_cors(self) -> None:
        server, thread = start_http_server()
        try:
            with urlopen(f"http://127.0.0.1:{server.server_port}/health", timeout=5) as response:
                self.assertIsNone(response.headers.get("Access-Control-Allow-Origin"))
        finally:
            stop_http_server(server, thread)

    def test_http_sidecar_reports_warm_runtime_readiness_and_bounded_admission(self) -> None:
        with patch(
            "voiceid_verifier.app.configured_moonshine_recognizer",
            return_value=None,
        ):
            server = VoiceIdVerifierHttpServer(
                ("127.0.0.1", 0),
                maximum_concurrent_inferences=2,
                queue_wait_ms=0,
            )
        stage_executor = server.verification_stage_executor
        try:
            health = server.health_response()
            self.assertEqual(health["readiness"], "ready")
            self.assertEqual(health["runtime"]["maximumConcurrentInferences"], 2)
            self.assertEqual(stage_executor.maximum_active_stages, 6)
            self.assertTrue(server.acquire_inference_slot())
            self.assertTrue(server.acquire_inference_slot())
            self.assertFalse(server.acquire_inference_slot())
            server.release_inference_slot()
            server.release_inference_slot()
        finally:
            server.server_close()
        with self.assertRaisesRegex(RuntimeError, "cannot schedule new futures"):
            stage_executor.submit(successful_timed_stage)

    def test_http_sidecar_caps_admission_at_one_when_moonshine_is_configured(self) -> None:
        with patch(
            "voiceid_verifier.app.configured_moonshine_recognizer",
            return_value=FakeMoonshineRecognizer(),
        ):
            server = VoiceIdVerifierHttpServer(
                ("127.0.0.1", 0),
                maximum_concurrent_inferences=3,
                queue_wait_ms=0,
            )
        stage_executor = server.verification_stage_executor
        try:
            health = server.health_response()
            self.assertEqual(health["runtime"]["maximumConcurrentInferences"], 1)
            self.assertEqual(stage_executor.maximum_active_stages, 3)
            self.assertTrue(server.acquire_inference_slot())
            self.assertFalse(server.acquire_inference_slot())
            server.release_inference_slot()
        finally:
            server.server_close()

    def test_http_sidecar_returns_exact_overload_and_recovers_capacity(self) -> None:
        template_runtime = SpeechBrainEcapaVerifierRuntime(
            extractor=InspectingEcapaExtractor()
        )
        template_response = build_enrollment_template_from_json(
            enrollment_request(audio_bytes=enrollment_audio_bytes()),
            runtime=template_runtime,
        )
        started = threading.Event()
        release = threading.Event()
        blocking_runtime = SpeechBrainEcapaVerifierRuntime(
            extractor=BlockingEcapaExtractor(started, release)
        )
        server, server_thread = start_http_server(
            runtime=blocking_runtime,
            maximum_concurrent_inferences=1,
            queue_wait_ms=0,
        )
        first_result: dict[str, object] = {}
        first_thread = threading.Thread(
            target=capture_post_json,
            args=(
                f"http://127.0.0.1:{server.server_port}/voice-id/verifier/verify-speaker",
                verification_request(
                    audio_bytes=wav_audio_bytes([(240, 1800)]),
                    duration_ms=1800,
                    template_response=template_response,
                ),
                first_result,
            ),
            daemon=True,
        )
        try:
            first_thread.start()
            self.assertTrue(started.wait(timeout=2))
            with self.assertRaises(HTTPError) as caught:
                post_json(
                    f"http://127.0.0.1:{server.server_port}/voice-id/verifier/verify-speaker",
                    verification_request(
                        audio_bytes=wav_audio_bytes([(260, 1800)]),
                        duration_ms=1800,
                        template_response=template_response,
                    ),
                )
            overload = json.loads(caught.exception.read().decode("utf-8"))
            caught.exception.close()
            self.assertEqual(caught.exception.code, 503)
            self.assertEqual(
                overload,
                {
                    "kind": "error",
                    "error": {
                        "kind": "overloaded",
                        "message": "verifier queue did not admit the request within 0ms",
                    },
                },
            )

            release.set()
            first_thread.join(timeout=2)
            self.assertFalse(first_thread.is_alive())
            self.assertNotIn("error", first_result)
            first_response = first_result.get("response")
            self.assertIsInstance(first_response, dict)

            recovered = post_json(
                f"http://127.0.0.1:{server.server_port}/voice-id/verifier/verify-speaker",
                verification_request(
                    audio_bytes=wav_audio_bytes([(280, 1800)]),
                    duration_ms=1800,
                    template_response=template_response,
                ),
            )
            self.assertEqual(recovered["speaker"]["kind"], "accepted")
        finally:
            release.set()
            first_thread.join(timeout=2)
            stop_http_server(server, server_thread)


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


def speech_analysis_request(*, audio_bytes: bytes) -> dict[str, object]:
    return {
        "schemaVersion": "voice_id_verifier_v2",
        "requestId": "speech_request_1",
        "audio": audio_payload(audio_bytes=audio_bytes, duration_ms=1800),
        "expectedPhrase": "approve transfer",
        "intentName": "approve",
    }


def verification_analysis_request(
    *,
    audio_bytes: bytes,
    template_response: dict[str, object],
) -> dict[str, object]:
    return {
        "schemaVersion": "voice_id_verifier_v2",
        "requestId": "analysis_request_1",
        "audio": audio_payload(audio_bytes=audio_bytes, duration_ms=1800),
        "template": template_reference(template_response),
        "threshold": 0.5,
        "expectedPhrase": "approve transfer",
        "intentName": "approve",
        "challengeTokens": ["approve", "transfer"],
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


def start_http_server(
    *,
    runtime: SpeechBrainEcapaVerifierRuntime | None = None,
    maximum_concurrent_inferences: int = 1,
    queue_wait_ms: int = 250,
) -> tuple[VoiceIdVerifierHttpServer, threading.Thread]:
    server = VoiceIdVerifierHttpServer(
        ("127.0.0.1", 0),
        runtime=runtime,
        maximum_concurrent_inferences=maximum_concurrent_inferences,
        queue_wait_ms=queue_wait_ms,
    )
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


def capture_post_json(
    url: str,
    payload: dict[str, object],
    result: dict[str, object],
) -> None:
    try:
        result["response"] = post_json(url, payload)
    except Exception as error:
        result["error"] = error


def wait_for_stage_admission(
    executor: BoundedStageExecutor,
    *,
    timeout_seconds: float = 1.0,
) -> Future[TimedStageResult]:
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        future = executor.submit(successful_timed_stage)
        if future is not None:
            return future
        time.sleep(0.001)
    raise AssertionError("stage executor did not release capacity")


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


class UnstableEcapaExtractor(InspectingEcapaExtractor):
    vectors = (
        (1.0, 0.0),
        (0.866, 0.5),
        (0.5, 0.866),
        (0.5, 0.866),
    )

    def extract_decoded(self, samples: Sequence[float]) -> ExtractedSpeakerEmbedding:
        vector = [0.0] * self.embedding_dimensions
        first, second = self.vectors[len(self.sample_references)]
        vector[0] = first
        vector[1] = second
        self.sample_references.append(samples)
        self.vector_references.append(vector)
        return ExtractedSpeakerEmbedding(vector=vector, speaker_label="unknown_speaker")


class FailingEcapaExtractor(InspectingEcapaExtractor):
    def extract_decoded(self, samples: Sequence[float]) -> ExtractedSpeakerEmbedding:
        raise AssertionError("speaker extraction should not run for low-quality audio")


class CoordinatedEcapaExtractor(InspectingEcapaExtractor):
    def __init__(self, barrier: threading.Barrier) -> None:
        super().__init__()
        self.barrier = barrier

    def extract_decoded(self, samples: Sequence[float]) -> ExtractedSpeakerEmbedding:
        self.barrier.wait(timeout=1)
        return super().extract_decoded(samples)


class BlockingEcapaExtractor(InspectingEcapaExtractor):
    def __init__(self, started: threading.Event, release: threading.Event) -> None:
        super().__init__()
        self.started = started
        self.release = release

    def extract_decoded(self, samples: Sequence[float]) -> ExtractedSpeakerEmbedding:
        self.started.set()
        if not self.release.wait(timeout=2):
            raise TimeoutError("test extractor was not released")
        return super().extract_decoded(samples)


class FakeMoonshineRecognizer:
    def analyze(
        self,
        samples: Sequence[float],
        *,
        expected_phrase: str,
        intent_name: str,
        challenge_tokens: Sequence[str],
    ) -> MoonshineSpeechAnalysis:
        return MoonshineSpeechAnalysis(
            transcript="approve transfer",
            phrase=MoonshinePhraseDecision(
                kind="accepted",
                expected_normalized="approve transfer",
                spoken_normalized="approve transfer",
                confidence=0.95,
                reason=None,
            ),
            intent=MoonshineIntentDecision(
                kind="accepted",
                intent="approve",
                canonical_phrase="approve",
                confidence=0.95,
                runner_up_intent="cancel",
                runner_up_confidence=0.2,
                reason=None,
            ),
            sample_rate_hz=16000,
        )


class CoordinatedMoonshineRecognizer(FakeMoonshineRecognizer):
    def __init__(self, barrier: threading.Barrier) -> None:
        self.barrier = barrier

    def analyze(
        self,
        samples: Sequence[float],
        *,
        expected_phrase: str,
        intent_name: str,
        challenge_tokens: Sequence[str],
    ) -> MoonshineSpeechAnalysis:
        self.barrier.wait(timeout=1)
        return super().analyze(
            samples,
            expected_phrase=expected_phrase,
            intent_name=intent_name,
            challenge_tokens=challenge_tokens,
        )


class SlowMoonshineRecognizer(FakeMoonshineRecognizer):
    def analyze(
        self,
        samples: Sequence[float],
        *,
        expected_phrase: str,
        intent_name: str,
        challenge_tokens: Sequence[str],
    ) -> MoonshineSpeechAnalysis:
        time.sleep(0.05)
        return super().analyze(
            samples,
            expected_phrase=expected_phrase,
            intent_name=intent_name,
            challenge_tokens=challenge_tokens,
        )


class CoordinatedPadDetector:
    model_version = "test-pad"
    calibration_version = "test-calibration"
    reject_threshold = 0.35
    accept_threshold = 0.65

    def __init__(self, barrier: threading.Barrier) -> None:
        self.barrier = barrier
        self.sample_references: list[Sequence[float]] = []

    def analyze(self, samples: Sequence[float]) -> PadDecision:
        self.sample_references.append(samples)
        self.barrier.wait(timeout=1)
        return accepted_pad_decision()


class SlowPadDetector:
    model_version = "test-pad"
    calibration_version = "test-calibration"
    reject_threshold = 0.35
    accept_threshold = 0.65

    def analyze(self, samples: Sequence[float]) -> PadDecision:
        time.sleep(0.05)
        return accepted_pad_decision()


class SlowEcapaExtractor(InspectingEcapaExtractor):
    def extract_decoded(self, samples: Sequence[float]) -> ExtractedSpeakerEmbedding:
        time.sleep(0.05)
        return super().extract_decoded(samples)


def accepted_pad_decision() -> PadDecision:
    return PadDecision(
        kind="accepted",
        score=0.9,
        reject_threshold=0.35,
        accept_threshold=0.65,
        model_version="test-pad",
        calibration_version="test-calibration",
        latency_ms=5.0,
        reason=None,
    )


def blocking_timed_stage(
    started: threading.Event,
    release: threading.Event,
) -> TimedStageResult:
    started.set()
    if not release.wait(timeout=1):
        raise TimeoutError("test stage was not released")
    return TimedStageResult(completed_at=time.monotonic(), value="complete")


def failing_timed_stage() -> TimedStageResult:
    raise RuntimeError("model task failed")


def successful_timed_stage() -> TimedStageResult:
    return TimedStageResult(completed_at=time.monotonic(), value="replacement")


if __name__ == "__main__":
    unittest.main()
