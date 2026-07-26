from __future__ import annotations

import tempfile
import unittest
import wave
from pathlib import Path

from elevenlabs_batch import (
    ElevenLabsJob,
    ElevenLabsPlan,
    OwnerClone,
    VoiceDesign,
    generate_plan,
    multipart_body,
)


class ElevenLabsBatchTest(unittest.TestCase):
    def test_generates_designed_and_owner_conditioned_manifest_entries(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            asset_dir = root / "assets"
            output_dir = root / "output"
            asset_dir.mkdir()
            write_reference_wav(asset_dir / "owner.wav")
            client = FakeElevenLabsClient()

            manifest, report = generate_plan(
                sample_plan(),
                client=client,
                asset_dir=asset_dir,
                output_dir=output_dir,
            )

            self.assertEqual(report["voiceIds"]["designed"], "voice-designed")
            self.assertEqual(report["voiceIds"]["owner"], "voice-owner")
            self.assertEqual(manifest["entries"][0]["provenance"]["conditioning"], None)
            self.assertEqual(
                manifest["entries"][1]["provenance"]["conditioning"]["sourceSubjectId"],
                "owner_eval",
            )
            self.assertEqual(client.synthesis_count, 2)
            self.assertTrue((output_dir / "designed.wav").is_file())

    def test_multipart_clone_request_has_one_file_and_terminal_boundary(self) -> None:
        body = multipart_body(
            boundary="voiceid-test",
            fields={"name": "Owner"},
            file_name="owner.wav",
            file_bytes=b"audio",
        )

        self.assertIn(b'name="files"; filename="owner.wav"', body)
        self.assertTrue(body.endswith(b"--voiceid-test--\r\n"))


class FakeElevenLabsClient:
    def __init__(self) -> None:
        self.synthesis_count = 0

    def design_voice(self, spec: VoiceDesign) -> str:
        return "voice-designed"

    def clone_voice(self, spec: OwnerClone, reference_path: Path) -> str:
        self.assert_reference(reference_path)
        return "voice-owner"

    def synthesize(
        self,
        *,
        voice_id: str,
        text: str,
        model_id: str,
        settings: dict[str, float | bool],
        seed: int,
    ) -> bytes:
        self.synthesis_count += 1
        return (b"\x00\x10" * 16000)

    def assert_reference(self, path: Path) -> None:
        if not path.is_file():
            raise AssertionError("owner reference is missing")


def sample_plan() -> ElevenLabsPlan:
    design = VoiceDesign(
        kind="voice_design",
        voice_key="designed",
        name="Designed voice",
        description="A calm designed voice for security evaluation.",
        preview_text="A preview sentence for the generated voice.",
        preview_index=0,
        model_id="eleven_multilingual_ttv_v2",
    )
    owner = OwnerClone(
        kind="owner_clone",
        voice_key="owner",
        name="Owner attack clone",
        description="Authorized owner-conditioned attack fixture.",
        reference_audio_file_name="owner.wav",
        source_subject_id="owner_eval",
        consent_reference="owner-consent",
        retention_class="project_indefinite",
    )
    capture = {
        "platform": "server",
        "microphone": "digital_generation",
        "room": "none",
        "distanceCm": 0,
        "codec": "pcm_s16le",
        "channelCount": 1,
        "language": "en",
        "accent": "synthetic",
        "noiseProfile": "none",
    }
    return ElevenLabsPlan(
        dataset_version="elevenlabs-test-v1",
        tts_model_id="eleven_flash_v2_5",
        settings={
            "stability": 0.5,
            "similarity_boost": 0.75,
            "style": 0.0,
            "speed": 1.0,
            "use_speaker_boost": True,
        },
        capture=capture,
        voices=(design, owner),
        jobs=(
            ElevenLabsJob(
                fixture_id="designed_enrollment",
                audio_file_name="designed.wav",
                subject_id="designed_subject",
                session_id="designed_session",
                partition="development",
                case={"kind": "enrollment"},
                expected_intent=None,
                challenge_tokens=(),
                voice_key="designed",
                text="Enrollment phrase.",
                seed=1,
            ),
            ElevenLabsJob(
                fixture_id="owner_attack",
                audio_file_name="owner_attack.wav",
                subject_id="owner_clone",
                session_id="owner_attack_session",
                partition="evaluation",
                case={
                    "kind": "presentation_attack",
                    "targetSubjectId": "owner_eval",
                    "attackClass": "synthesis",
                    "attackTool": "elevenlabs-owner-clone",
                },
                expected_intent="approve",
                challenge_tokens=("maple", "eight", "star"),
                voice_key="owner",
                text="Approve this request. Maple eight star.",
                seed=2,
            ),
        ),
    )


def write_reference_wav(path: Path) -> None:
    with wave.open(str(path), "wb") as output:
        output.setnchannels(1)
        output.setsampwidth(2)
        output.setframerate(16000)
        output.writeframes(b"\x00\x10" * 16000)


if __name__ == "__main__":
    unittest.main()
