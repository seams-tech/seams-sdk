from __future__ import annotations

import json
import tempfile
import unittest
import wave
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

from elevenlabs_batch import (
    CompletedJobState,
    ElevenLabsJob,
    ElevenLabsPlan,
    ElevenLabsStateError,
    OwnerClone,
    VoiceDesign,
    generate_plan,
    multipart_body,
    publish_materialized_output,
    validate_cli_paths,
    write_pcm_wav,
)

REAL_PUBLISH_MATERIALIZED_OUTPUT = publish_materialized_output


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
                state_path=root / "generation-state.json",
            )

            self.assertEqual(report["voiceIds"]["designed"], "voice-designed")
            self.assertEqual(report["voiceIds"]["owner"], "voice-owner")
            self.assertEqual(manifest["entries"][0]["provenance"]["conditioning"], None)
            self.assertEqual(
                manifest["entries"][1]["provenance"]["conditioning"]["sourceSubjectId"],
                "owner_eval",
            )
            self.assertEqual(client.synthesis_count, 2)
            self.assertEqual(client.design_count, 1)
            self.assertEqual(client.clone_count, 1)
            self.assertTrue((output_dir / "designed.wav").is_file())

    def test_rerun_skips_checkpointed_remote_operations(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            asset_dir = root / "assets"
            output_dir = root / "output"
            state_path = root / "generation-state.json"
            asset_dir.mkdir()
            write_reference_wav(asset_dir / "owner.wav")

            first_manifest, first_report = generate_plan(
                sample_plan(),
                client=FakeElevenLabsClient(),
                asset_dir=asset_dir,
                output_dir=output_dir,
                state_path=state_path,
            )
            resumed_client = FakeElevenLabsClient()
            resumed_manifest, resumed_report = generate_plan(
                sample_plan(),
                client=resumed_client,
                asset_dir=asset_dir,
                output_dir=output_dir,
                state_path=state_path,
            )

            self.assertEqual(resumed_manifest, first_manifest)
            self.assertEqual(resumed_report, first_report)
            self.assertEqual(resumed_client.design_count, 0)
            self.assertEqual(resumed_client.clone_count, 0)
            self.assertEqual(resumed_client.synthesis_count, 0)

    def test_rerun_rejects_an_ambiguous_remote_outcome(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            asset_dir = root / "assets"
            output_dir = root / "output"
            state_path = root / "generation-state.json"
            asset_dir.mkdir()
            write_reference_wav(asset_dir / "owner.wav")
            interrupted_client = FakeElevenLabsClient(fail_on_synthesis=2)

            with self.assertRaisesRegex(RuntimeError, "simulated synthesis failure"):
                generate_plan(
                    sample_plan(),
                    client=interrupted_client,
                    asset_dir=asset_dir,
                    output_dir=output_dir,
                    state_path=state_path,
                )

            state = json.loads(state_path.read_text(encoding="utf-8"))
            self.assertEqual(state["datasetVersion"], "elevenlabs-test-v1")
            self.assertEqual(state["planSha256"], "a" * 64)
            self.assertEqual(len(state["resolvedVoices"]), 2)
            self.assertEqual(len(state["completedJobs"]), 1)
            self.assertEqual(
                state["pendingOperation"]["kind"],
                "synthesize_job",
            )
            self.assertTrue((output_dir / "designed.wav").is_file())
            self.assertFalse((output_dir / "owner_attack.wav").exists())

            resumed_client = FakeElevenLabsClient()
            with self.assertRaisesRegex(
                ElevenLabsStateError,
                "remote operation outcome is ambiguous",
            ):
                generate_plan(
                    sample_plan(),
                    client=resumed_client,
                    asset_dir=asset_dir,
                    output_dir=output_dir,
                    state_path=state_path,
                )

            self.assertEqual(resumed_client.remote_operation_count, 0)

    def test_rerun_adopts_a_materialized_pending_wav(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            asset_dir = root / "assets"
            output_dir = root / "output"
            state_path = root / "generation-state.json"
            asset_dir.mkdir()
            write_reference_wav(asset_dir / "owner.wav")

            with patch(
                "elevenlabs_batch.publish_materialized_output",
                side_effect=fail_materialized_publish,
            ):
                with self.assertRaisesRegex(
                    RuntimeError,
                    "simulated interruption before completed checkpoint",
                ):
                    generate_plan(
                        sample_plan(),
                        client=FakeElevenLabsClient(),
                        asset_dir=asset_dir,
                        output_dir=output_dir,
                        state_path=state_path,
                    )

            state = json.loads(state_path.read_text(encoding="utf-8"))
            self.assertEqual(state["pendingOperation"]["kind"], "materialized_job")
            self.assertFalse((output_dir / ".designed.wav.pending").exists())
            self.assertTrue((output_dir / "designed.wav").is_file())
            resumed_client = FakeElevenLabsClient()

            manifest, report = generate_plan(
                sample_plan(),
                client=resumed_client,
                asset_dir=asset_dir,
                output_dir=output_dir,
                state_path=state_path,
            )

            self.assertEqual(len(manifest["entries"]), 2)
            self.assertEqual(report["fixtureCount"], 2)
            self.assertEqual(resumed_client.design_count, 0)
            self.assertEqual(resumed_client.clone_count, 0)
            self.assertEqual(resumed_client.synthesis_count, 1)

    def test_materialized_publish_never_overwrites_a_new_destination(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            asset_dir = root / "assets"
            output_dir = root / "output"
            state_path = root / "generation-state.json"
            asset_dir.mkdir()
            write_reference_wav(asset_dir / "owner.wav")

            with patch(
                "elevenlabs_batch.publish_materialized_output",
                side_effect=publish_with_conflicting_destination,
            ):
                with self.assertRaisesRegex(
                    ElevenLabsStateError,
                    "does not match state",
                ):
                    generate_plan(
                        sample_plan(),
                        client=FakeElevenLabsClient(),
                        asset_dir=asset_dir,
                        output_dir=output_dir,
                        state_path=state_path,
                    )

            conflicting_output = output_dir / "designed.wav"
            self.assertTrue(conflicting_output.is_file())
            with wave.open(str(conflicting_output), "rb") as audio:
                self.assertEqual(audio.readframes(1), b"\x01\x20")
            self.assertTrue((output_dir / ".designed.wav.pending").is_file())

    def test_rerun_rejects_an_ambiguous_voice_creation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            asset_dir = root / "assets"
            state_path = root / "generation-state.json"
            asset_dir.mkdir()
            write_reference_wav(asset_dir / "owner.wav")

            with self.assertRaisesRegex(RuntimeError, "simulated voice failure"):
                generate_plan(
                    sample_plan(),
                    client=FakeElevenLabsClient(fail_on_design=True),
                    asset_dir=asset_dir,
                    output_dir=root / "output",
                    state_path=state_path,
                )

            state = json.loads(state_path.read_text(encoding="utf-8"))
            self.assertEqual(state["pendingOperation"]["kind"], "provision_voice")
            resumed_client = FakeElevenLabsClient()
            with self.assertRaisesRegex(
                ElevenLabsStateError,
                "remote operation outcome is ambiguous",
            ):
                generate_plan(
                    sample_plan(),
                    client=resumed_client,
                    asset_dir=asset_dir,
                    output_dir=root / "output",
                    state_path=state_path,
                )
            self.assertEqual(resumed_client.remote_operation_count, 0)

    def test_rejects_state_bound_to_a_different_plan(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            asset_dir = root / "assets"
            output_dir = root / "output"
            state_path = root / "generation-state.json"
            asset_dir.mkdir()
            write_reference_wav(asset_dir / "owner.wav")
            generate_plan(
                sample_plan(),
                client=FakeElevenLabsClient(),
                asset_dir=asset_dir,
                output_dir=output_dir,
                state_path=state_path,
            )
            changed_plan = replace(sample_plan(), plan_sha256="b" * 64)
            client = FakeElevenLabsClient()

            with self.assertRaisesRegex(
                ElevenLabsStateError,
                "planSha256 does not match",
            ):
                generate_plan(
                    changed_plan,
                    client=client,
                    asset_dir=asset_dir,
                    output_dir=output_dir,
                    state_path=state_path,
                )

            self.assertEqual(client.remote_operation_count, 0)

    def test_rejects_state_bound_to_a_different_dataset(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            asset_dir = root / "assets"
            output_dir = root / "output"
            state_path = root / "generation-state.json"
            asset_dir.mkdir()
            write_reference_wav(asset_dir / "owner.wav")
            generate_plan(
                sample_plan(),
                client=FakeElevenLabsClient(),
                asset_dir=asset_dir,
                output_dir=output_dir,
                state_path=state_path,
            )
            changed_plan = replace(
                sample_plan(),
                dataset_version="elevenlabs-test-v2",
            )
            client = FakeElevenLabsClient()

            with self.assertRaisesRegex(
                ElevenLabsStateError,
                "datasetVersion does not match",
            ):
                generate_plan(
                    changed_plan,
                    client=client,
                    asset_dir=asset_dir,
                    output_dir=output_dir,
                    state_path=state_path,
                )

            self.assertEqual(client.remote_operation_count, 0)

    def test_rejects_corrupt_state_before_remote_operations(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            asset_dir = root / "assets"
            asset_dir.mkdir()
            write_reference_wav(asset_dir / "owner.wav")
            state_path = root / "generation-state.json"
            state_path.write_text("{", encoding="utf-8")
            client = FakeElevenLabsClient()

            with self.assertRaisesRegex(ElevenLabsStateError, "corrupt"):
                generate_plan(
                    sample_plan(),
                    client=client,
                    asset_dir=asset_dir,
                    output_dir=root / "output",
                    state_path=state_path,
                )

            self.assertEqual(client.remote_operation_count, 0)

    def test_rejects_existing_planned_output_without_completed_state(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            asset_dir = root / "assets"
            output_dir = root / "output"
            asset_dir.mkdir()
            output_dir.mkdir()
            write_reference_wav(asset_dir / "owner.wav")
            write_reference_wav(output_dir / "designed.wav")
            client = FakeElevenLabsClient()

            with self.assertRaisesRegex(
                ElevenLabsStateError,
                "existing output lacks matching completed state",
            ):
                generate_plan(
                    sample_plan(),
                    client=client,
                    asset_dir=asset_dir,
                    output_dir=output_dir,
                    state_path=root / "generation-state.json",
                )

            self.assertEqual(client.remote_operation_count, 0)

    def test_rejects_checkpointed_output_that_was_modified(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            asset_dir = root / "assets"
            output_dir = root / "output"
            state_path = root / "generation-state.json"
            asset_dir.mkdir()
            write_reference_wav(asset_dir / "owner.wav")
            generate_plan(
                sample_plan(),
                client=FakeElevenLabsClient(),
                asset_dir=asset_dir,
                output_dir=output_dir,
                state_path=state_path,
            )
            with (output_dir / "designed.wav").open("ab") as output:
                output.write(b"tampered")
            client = FakeElevenLabsClient()

            with self.assertRaisesRegex(
                ElevenLabsStateError,
                "checkpointed output does not match state",
            ):
                generate_plan(
                    sample_plan(),
                    client=client,
                    asset_dir=asset_dir,
                    output_dir=output_dir,
                    state_path=state_path,
                )

            self.assertEqual(client.remote_operation_count, 0)

    def test_rejects_manifest_path_that_would_overwrite_paid_audio(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)

            with self.assertRaisesRegex(
                ElevenLabsStateError,
                "durable output path conflicts",
            ):
                validate_cli_paths(
                    plan_path=root / "plan.json",
                    plan=sample_plan(),
                    asset_dir=root / "assets",
                    output_dir=root / "output",
                    state_path=root / "generation-state.json",
                    manifest_path=root / "output" / "designed.wav",
                    report_path=root / "generation-report.json",
                )

    def test_output_campaign_rejects_a_second_state_before_remote_work(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            asset_dir = root / "assets"
            output_dir = root / "output"
            asset_dir.mkdir()
            write_reference_wav(asset_dir / "owner.wav")
            first_client = FakeElevenLabsClient(fail_on_design=True)

            with self.assertRaisesRegex(RuntimeError, "simulated voice failure"):
                generate_plan(
                    sample_plan(),
                    client=first_client,
                    asset_dir=asset_dir,
                    output_dir=output_dir,
                    state_path=root / "first-state.json",
                )

            second_client = FakeElevenLabsClient()
            with self.assertRaisesRegex(
                ElevenLabsStateError,
                "different generation campaign",
            ):
                generate_plan(
                    sample_plan(),
                    client=second_client,
                    asset_dir=asset_dir,
                    output_dir=output_dir,
                    state_path=root / "second-state.json",
                )

            self.assertEqual(second_client.remote_operation_count, 0)

    def test_output_campaign_rejects_a_missing_bound_state_before_remote_work(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            asset_dir = root / "assets"
            output_dir = root / "output"
            state_path = root / "generation-state.json"
            asset_dir.mkdir()
            write_reference_wav(asset_dir / "owner.wav")

            with self.assertRaisesRegex(RuntimeError, "simulated synthesis failure"):
                generate_plan(
                    sample_plan(),
                    client=FakeElevenLabsClient(fail_on_synthesis=1),
                    asset_dir=asset_dir,
                    output_dir=output_dir,
                    state_path=state_path,
                )
            state_path.unlink()
            resumed_client = FakeElevenLabsClient()

            with self.assertRaisesRegex(
                ElevenLabsStateError,
                "bound state is missing",
            ):
                generate_plan(
                    sample_plan(),
                    client=resumed_client,
                    asset_dir=asset_dir,
                    output_dir=output_dir,
                    state_path=state_path,
                )

            self.assertEqual(resumed_client.remote_operation_count, 0)

    def test_rejects_a_dangling_final_symlink_before_remote_work(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            asset_dir = root / "assets"
            output_dir = root / "output"
            asset_dir.mkdir()
            output_dir.mkdir()
            write_reference_wav(asset_dir / "owner.wav")
            (output_dir / "designed.wav").symlink_to(".designed.wav.pending")
            client = FakeElevenLabsClient()

            with self.assertRaisesRegex(
                ElevenLabsStateError,
                "planned final output must be a regular file",
            ):
                generate_plan(
                    sample_plan(),
                    client=client,
                    asset_dir=asset_dir,
                    output_dir=output_dir,
                    state_path=root / "generation-state.json",
                )

            self.assertEqual(client.remote_operation_count, 0)

    def test_rejects_planned_audio_that_overlaps_owner_reference(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            write_reference_wav(root / "owner.wav")
            plan = sample_plan()
            overlapping_plan = replace(
                plan,
                jobs=(
                    replace(plan.jobs[0], audio_file_name="owner.wav"),
                    *plan.jobs[1:],
                ),
            )
            client = FakeElevenLabsClient()

            with self.assertRaisesRegex(
                ElevenLabsStateError,
                "conflicts with owner input",
            ):
                generate_plan(
                    overlapping_plan,
                    client=client,
                    asset_dir=root,
                    output_dir=root,
                    state_path=root / "generation-state.json",
                )

            self.assertEqual(client.remote_operation_count, 0)

    def test_rejects_a_too_short_pcm_response_before_writing_stateful_audio(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            output_path = Path(temporary_directory) / "short.wav"

            with self.assertRaisesRegex(
                ValueError,
                "at least 900 ms",
            ):
                write_pcm_wav(output_path, b"\x00\x10")

            self.assertFalse(output_path.exists())

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
    def __init__(
        self,
        *,
        fail_on_design: bool = False,
        fail_on_synthesis: int | None = None,
    ) -> None:
        self.design_count = 0
        self.clone_count = 0
        self.synthesis_count = 0
        self.fail_on_design = fail_on_design
        self.fail_on_synthesis = fail_on_synthesis

    @property
    def remote_operation_count(self) -> int:
        return self.design_count + self.clone_count + self.synthesis_count

    def design_voice(self, spec: VoiceDesign) -> str:
        self.design_count += 1
        if self.fail_on_design:
            raise RuntimeError("simulated voice failure")
        return "voice-designed"

    def clone_voice(
        self,
        spec: OwnerClone,
        reference_path: Path,
        reference_bytes: bytes,
    ) -> str:
        self.clone_count += 1
        self.assert_reference(reference_path)
        if len(reference_bytes) == 0:
            raise AssertionError("owner reference bytes are missing")
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
        if self.synthesis_count == self.fail_on_synthesis:
            raise RuntimeError("simulated synthesis failure")
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
        plan_sha256="a" * 64,
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


def write_reference_wav(path: Path, *, frame: bytes = b"\x00\x10") -> None:
    with wave.open(str(path), "wb") as output:
        output.setnchannels(1)
        output.setsampwidth(2)
        output.setframerate(16000)
        output.writeframes(frame * 16000)


def fail_materialized_publish(
    *,
    completed: CompletedJobState,
    pending_path: Path,
    output_path: Path,
) -> None:
    REAL_PUBLISH_MATERIALIZED_OUTPUT(
        completed=completed,
        pending_path=pending_path,
        output_path=output_path,
    )
    raise RuntimeError("simulated interruption before completed checkpoint")


def publish_with_conflicting_destination(
    *,
    completed: CompletedJobState,
    pending_path: Path,
    output_path: Path,
) -> None:
    write_reference_wav(output_path, frame=b"\x01\x20")
    REAL_PUBLISH_MATERIALIZED_OUTPUT(
        completed=completed,
        pending_path=pending_path,
        output_path=output_path,
    )


if __name__ == "__main__":
    unittest.main()
