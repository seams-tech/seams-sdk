from __future__ import annotations

import hashlib
import json
import struct
import tempfile
import unittest
import wave
from pathlib import Path

from augment_corpus import TRANSFORMS, augment_manifest
from benchmark import load_benchmark_manifest_fragment


class AugmentCorpusTest(unittest.TestCase):
    def test_creates_four_deterministic_attack_bindings(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            source = write_source_manifest(root)
            output_dir = root / "derived"
            first_report = augment_manifest(
                source,
                output_dir=output_dir,
                manifest_out=output_dir / "manifest.json",
                report_out=root / "report.json",
                created_at="2026-07-31T00:00:00Z",
                seed=7,
            )
            first_manifest = (output_dir / "manifest.json").read_bytes()
            first_audio = {
                path.name: path.read_bytes()
                for path in output_dir.glob("*.wav")
            }

            second_dir = root / "derived-second"
            second_report = augment_manifest(
                source,
                output_dir=second_dir,
                manifest_out=second_dir / "manifest.json",
                report_out=root / "report-second.json",
                created_at="2026-07-31T00:00:00Z",
                seed=7,
            )

            self.assertEqual(first_report["transformCount"], 4)
            self.assertEqual(second_report["bindings"], first_report["bindings"])
            self.assertEqual(
                first_audio,
                {path.name: path.read_bytes() for path in second_dir.glob("*.wav")},
            )
            self.assertEqual(
                len({hashlib.sha256(audio).hexdigest() for audio in first_audio.values()}),
                4,
            )
            self.assertEqual(first_manifest, (second_dir / "manifest.json").read_bytes())
            validated = load_benchmark_manifest_fragment(output_dir / "manifest.json")
            self.assertEqual(
                [entry.case.attack_tool for entry in validated.entries],
                [f"deterministic_{name}_transform_v1" for name in TRANSFORMS],
            )
            resumed = augment_manifest(
                source,
                output_dir=output_dir,
                manifest_out=output_dir / "manifest.json",
                report_out=root / "report.json",
                created_at="2026-07-31T00:00:00Z",
                seed=7,
            )
            self.assertEqual(resumed["bindings"], first_report["bindings"])


def write_source_manifest(root: Path) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    audio_path = root / "source.wav"
    pcm = struct.pack(
        "<16000h",
        *[int(12000 * ((index % 80) / 80 - 0.5)) for index in range(16000)],
    )
    with audio_path.open("wb") as raw_output:
        with wave.open(raw_output, "wb") as output:
            output.setnchannels(1)
            output.setsampwidth(2)
            output.setframerate(16000)
            output.writeframes(pcm)
    audio = audio_path.read_bytes()
    entry = {
        "fixtureId": "dev_subject_verification",
        "audioFileName": audio_path.name,
        "audioSha256": hashlib.sha256(audio).hexdigest(),
        "subjectId": "dev_subject",
        "sessionId": "dev_subject_session",
        "partition": "development",
        "case": {"kind": "genuine_verification"},
        "expectedIntent": "approve",
        "challengeTokens": ["approve"],
        "capture": {
            "platform": "server",
            "microphone": "synthetic",
            "room": "none",
            "distanceCm": 0,
            "codec": "pcm_s16le",
            "sampleRateHz": 16000,
            "channelCount": 1,
            "language": "en",
            "accent": "synthetic",
            "noiseProfile": "none",
        },
        "capturedAt": "2026-07-31T00:00:00Z",
        "durationMs": 1000,
        "byteLength": len(audio),
        "mimeType": "audio/wav",
        "provenance": {
            "kind": "synthetic_generation",
            "generator": "other",
            "model": "fixture",
            "voice": "dev_subject",
            "seed": 1,
            "license": "test",
            "requestHash": hashlib.sha256(b"fixture").hexdigest(),
            "conditioning": None,
        },
    }
    manifest_path = root / "manifest.json"
    manifest_path.write_text(
        json.dumps(
            {
                "schemaVersion": "voice_id_benchmark_manifest_v2",
                "datasetVersion": "fixture-v1",
                "createdAt": "2026-07-31T00:00:00Z",
                "entries": [entry],
            }
        ),
        encoding="utf-8",
    )
    return manifest_path


if __name__ == "__main__":
    unittest.main()
