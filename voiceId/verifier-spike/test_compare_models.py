from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from compare_models import (
    AudioStreamProbe,
    FixtureManifestError,
    inventory_summary,
    load_fixture_inventory,
    load_fixture_manifest,
    render_model_selection_report_template,
)


class FixtureManifestLoaderTest(unittest.TestCase):
    def test_loads_exported_fixture_manifest_and_audio_files(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            audio_path = root / "owner-1.webm"
            audio_path.write_bytes(audio_bytes())
            manifest_path = write_manifest(
                root,
                [
                    fixture_entry(
                        fixture_id="fixture_owner_1",
                        audio_file_name=audio_path.name,
                        byte_length=len(audio_bytes()),
                        expected_relation="owner_enrollment",
                    )
                ],
            )

            entries = load_fixture_manifest(manifest_path)
            inventory = load_fixture_inventory(manifest_path)
            summary = inventory_summary(inventory)

            self.assertEqual(len(entries), 1)
            self.assertEqual(entries[0].audio_path, audio_path.resolve())
            self.assertEqual(summary["fixtureCount"], 1)
            self.assertEqual(summary["relationCounts"], {"owner_enrollment": 1})

    def test_rejects_missing_audio_file(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            manifest_path = write_manifest(
                root,
                [
                    fixture_entry(
                        fixture_id="fixture_owner_1",
                        audio_file_name="missing.webm",
                        byte_length=5,
                        expected_relation="owner_enrollment",
                    )
                ],
            )

            with self.assertRaisesRegex(FixtureManifestError, "audio file does not exist"):
                load_fixture_manifest(manifest_path)

    def test_rejects_byte_length_mismatch(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            audio_path = root / "owner-1.webm"
            audio_path.write_bytes(audio_bytes())
            manifest_path = write_manifest(
                root,
                [
                    fixture_entry(
                        fixture_id="fixture_owner_1",
                        audio_file_name=audio_path.name,
                        byte_length=len(audio_bytes()) - 1,
                        expected_relation="owner_enrollment",
                    )
                ],
            )

            with self.assertRaisesRegex(FixtureManifestError, f"manifest says {len(audio_bytes()) - 1}"):
                load_fixture_manifest(manifest_path)

    def test_rejects_header_only_audio_files(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            audio_path = root / "owner-1.webm"
            audio_path.write_bytes(b"0" * 110)
            manifest_path = write_manifest(
                root,
                [
                    fixture_entry(
                        fixture_id="fixture_owner_1",
                        audio_file_name=audio_path.name,
                        byte_length=110,
                        expected_relation="owner_enrollment",
                    )
                ],
            )

            with self.assertRaisesRegex(FixtureManifestError, "expected at least 1024"):
                load_fixture_manifest(manifest_path)

    def test_media_validation_checks_audio_streams(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            audio_path = root / "owner-1.webm"
            audio_path.write_bytes(audio_bytes())
            manifest_path = write_manifest(
                root,
                [
                    fixture_entry(
                        fixture_id="fixture_owner_1",
                        audio_file_name=audio_path.name,
                        byte_length=len(audio_bytes()),
                        expected_relation="owner_enrollment",
                    )
                ],
            )
            probed_paths: list[Path] = []

            inventory = load_fixture_inventory(
                manifest_path,
                check_media=True,
                media_probe=lambda path: successful_probe(path, probed_paths),
            )

            self.assertEqual(len(inventory.entries), 1)
            self.assertEqual(probed_paths, [audio_path.resolve()])

    def test_media_validation_rejects_non_audio_streams(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            audio_path = root / "owner-1.webm"
            audio_path.write_bytes(audio_bytes())
            manifest_path = write_manifest(
                root,
                [
                    fixture_entry(
                        fixture_id="fixture_owner_1",
                        audio_file_name=audio_path.name,
                        byte_length=len(audio_bytes()),
                        expected_relation="owner_enrollment",
                    )
                ],
            )

            with self.assertRaisesRegex(FixtureManifestError, "does not contain an audio stream"):
                load_fixture_inventory(
                    manifest_path,
                    check_media=True,
                    media_probe=lambda _path: AudioStreamProbe(codec_name="vp9", codec_type="video"),
                )

    def test_rejects_invalid_relation_and_duplicate_audio_files(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            (root / "owner-1.webm").write_bytes(audio_bytes())
            malformed_relation = write_manifest(
                root,
                [
                    fixture_entry(
                        fixture_id="fixture_owner_1",
                        audio_file_name="owner-1.webm",
                        byte_length=len(audio_bytes()),
                        expected_relation="same-ish",
                    )
                ],
            )

            with self.assertRaisesRegex(FixtureManifestError, "expectedRelation is invalid"):
                load_fixture_manifest(malformed_relation)

        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            (root / "owner-1.webm").write_bytes(audio_bytes())
            duplicate_audio = write_manifest(
                root,
                [
                    fixture_entry(
                        fixture_id="fixture_owner_1",
                        audio_file_name="owner-1.webm",
                        byte_length=len(audio_bytes()),
                        expected_relation="owner_enrollment",
                    ),
                    fixture_entry(
                        fixture_id="fixture_owner_2",
                        audio_file_name="owner-1.webm",
                        byte_length=len(audio_bytes()),
                        expected_relation="owner_verification",
                    ),
                ],
            )

            with self.assertRaisesRegex(FixtureManifestError, "audioFileName owner-1.webm is duplicated"):
                load_fixture_manifest(duplicate_audio)

    def test_renders_model_selection_report_template_from_inventory(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            audio_path = root / "owner-1.webm"
            audio_path.write_bytes(audio_bytes())
            manifest_path = write_manifest(
                root,
                [
                    fixture_entry(
                        fixture_id="fixture_owner_1",
                        audio_file_name=audio_path.name,
                        byte_length=len(audio_bytes()),
                        expected_relation="owner_enrollment",
                    )
                ],
            )

            report = render_model_selection_report_template(load_fixture_inventory(manifest_path))

            self.assertIn("# VoiceID Model Selection Report", report)
            self.assertIn("- Fixture count: 1", report)
            self.assertIn("speechbrain/spkrec-ecapa-voxceleb", report)
            self.assertIn("False accepts and false rejects", report)
            self.assertIn("- Selected model id: TBD", report)


def write_manifest(root: Path, entries: list[dict[str, object]]) -> Path:
    manifest_path = root / "voiceid-fixture-manifest.json"
    manifest_path.write_text(
        json.dumps(
            {
                "schemaVersion": "voice_id_fixture_manifest_v1",
                "createdAt": "2026-06-09T00:01:00.000Z",
                "entries": entries,
            }
        ),
        encoding="utf-8",
    )
    return manifest_path


def audio_bytes() -> bytes:
    return b"voice" * 300


def successful_probe(path: Path, probed_paths: list[Path]) -> AudioStreamProbe:
    probed_paths.append(path)
    return AudioStreamProbe(codec_name="opus", codec_type="audio")


def fixture_entry(
    *,
    fixture_id: str,
    audio_file_name: str,
    byte_length: int,
    expected_relation: str,
) -> dict[str, object]:
    return {
        "fixtureId": fixture_id,
        "audioFileName": audio_file_name,
        "speakerLabel": "owner",
        "phraseLabel": "Walking on clouds",
        "expectedRelation": expected_relation,
        "captureDevice": "browser microphone",
        "durationMs": 1800,
        "environmentNotes": "quiet room",
        "capturedAt": "2026-06-09T00:00:00.000Z",
        "byteLength": byte_length,
        "mimeType": "audio/webm",
    }


if __name__ == "__main__":
    unittest.main()
