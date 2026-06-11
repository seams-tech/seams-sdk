from __future__ import annotations

import unittest

from voiceid_verifier.app import (
    build_template_from_json,
    extract_enrollment_embedding_from_json,
    verify_speaker_from_json,
)
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
        self.assertEqual(verification_response["speaker"]["reason"], "model_low_confidence")

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


if __name__ == "__main__":
    unittest.main()
