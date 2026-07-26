from __future__ import annotations

import json
import struct
import unittest
import wave
from pathlib import Path
from tempfile import TemporaryDirectory

from benchmark import load_benchmark_manifest_fragment
from import_consented_capture import (
    ConsentedCaptureImportError,
    ConsentedEnrollmentImport,
    copy_immutable_audio,
    import_consented_enrollment,
    write_json,
)


class ConsentedCaptureImportTest(unittest.TestCase):
    def test_imports_an_immutable_owner_enrollment_fragment(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source.wav"
            output_dir = root / "output"
            write_wav(source)
            spec = valid_spec()

            manifest = import_consented_enrollment(
                spec,
                source_audio_path=source,
                output_dir=output_dir,
            )
            manifest_path = output_dir / "manifest.json"
            write_json(manifest_path, manifest)
            parsed = load_benchmark_manifest_fragment(manifest_path)

            self.assertEqual(parsed.entries[0].subject_id, "owner_eval")
            self.assertEqual(parsed.entries[0].case.kind, "enrollment")
            self.assertEqual(
                parsed.entries[0].provenance.kind,
                "consented_human_capture",
            )
            self.assertEqual(
                (output_dir / "owner_eval_enrollment.wav").read_bytes(),
                source.read_bytes(),
            )

    def test_rejects_an_existing_output_with_different_audio(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source.wav"
            output_dir = root / "output"
            output_dir.mkdir()
            write_wav(source, sample_value=100)
            write_wav(output_dir / "owner_eval_enrollment.wav", sample_value=200)

            with self.assertRaisesRegex(
                ConsentedCaptureImportError,
                "collision",
            ):
                import_consented_enrollment(
                    valid_spec(),
                    source_audio_path=source,
                    output_dir=output_dir,
                )

    def test_manifest_write_cannot_overwrite_imported_audio(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source.wav"
            output_dir = root / "output"
            write_wav(source)
            manifest = import_consented_enrollment(
                valid_spec(),
                source_audio_path=source,
                output_dir=output_dir,
            )
            audio_path = output_dir / "owner_eval_enrollment.wav"
            original_audio = audio_path.read_bytes()

            with self.assertRaisesRegex(
                ConsentedCaptureImportError,
                "manifest collision",
            ):
                write_json(audio_path, manifest)

            self.assertEqual(audio_path.read_bytes(), original_audio)

    def test_copy_uses_one_immutable_source_snapshot(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source.wav"
            destination = root / "output" / "owner.wav"
            write_wav(source, sample_value=100)
            snapshot = source.read_bytes()
            write_wav(source, sample_value=200)

            audio = copy_immutable_audio(snapshot, destination)

            self.assertEqual(destination.read_bytes(), snapshot)
            self.assertEqual(audio["sampleRateHz"], 16000)

    def test_rejects_noncanonical_sample_rate_before_install(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source.wav"
            output_dir = root / "output"
            write_wav(source, sample_rate_hz=48000)

            with self.assertRaisesRegex(
                ConsentedCaptureImportError,
                "16 kHz",
            ):
                import_consented_enrollment(
                    valid_spec(),
                    source_audio_path=source,
                    output_dir=output_dir,
                )

            self.assertFalse((output_dir / "owner_eval_enrollment.wav").exists())

    def test_rejects_a_symlinked_output_audio(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source.wav"
            output_dir = root / "output"
            output_dir.mkdir()
            write_wav(source)
            destination = output_dir / "owner_eval_enrollment.wav"
            destination.symlink_to(source)

            with self.assertRaisesRegex(
                ConsentedCaptureImportError,
                "output audio must be a regular file",
            ):
                import_consented_enrollment(
                    valid_spec(),
                    source_audio_path=source,
                    output_dir=output_dir,
                )

            self.assertTrue(source.is_file())
            self.assertTrue(destination.is_symlink())


def valid_spec() -> ConsentedEnrollmentImport:
    return ConsentedEnrollmentImport(
        dataset_version="voiceid-owner-evaluation-v1",
        created_at="2026-07-26T12:03:27Z",
        captured_at="2026-07-26T12:03:27Z",
        fixture_id="owner_eval_enrollment",
        audio_file_name="owner_eval_enrollment.wav",
        subject_id="owner_eval",
        session_id="owner_eval_enrollment_session",
        partition="evaluation",
        consent_reference="voiceid-owner-consent-2026-07",
        retention_class="project_indefinite",
        platform="browser",
        microphone="unknown_owner_microphone",
        room="unknown",
        distance_cm=0,
        language="en",
        accent="owner_unspecified",
        noise_profile="unmeasured",
    )


def write_wav(
    path: Path,
    *,
    sample_value: int = 100,
    sample_rate_hz: int = 16000,
) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with wave.open(str(path), "wb") as output:
        output.setnchannels(1)
        output.setsampwidth(2)
        output.setframerate(sample_rate_hz)
        output.writeframes(
            b"".join(
                struct.pack("<h", sample_value)
                for _ in range(sample_rate_hz)
            )
        )


if __name__ == "__main__":
    unittest.main()
