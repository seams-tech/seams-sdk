#!/usr/bin/env python3
"""Drift check for the independent Phase 5 stream wire KATs."""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
GENERATOR = ROOT / "tools/ed25519-yao-verifier/generate_phase5_stream_kats.py"
ARTIFACT_DIR = ROOT / "crates/ed25519-yao/artifacts/passive-benchmark-v1"
JSON_VECTOR = ARTIFACT_DIR / "phase5-stream-wire-kats-v1.json"
BINARY_VECTOR = ARTIFACT_DIR / "phase5-stream-wire-kats-v1.bin"


class Phase5StreamKatDriftTests(unittest.TestCase):
    def test_generator_source_and_committed_vectors_have_no_drift(self) -> None:
        subprocess.run(
            [sys.executable, str(GENERATOR), "--check"],
            cwd=ROOT,
            check=True,
        )
        json_bytes = JSON_VECTOR.read_bytes()
        document = json.loads(json_bytes)
        self.assertEqual(
            document["generator_sha256"],
            hashlib.sha256(GENERATOR.read_bytes()).hexdigest(),
        )
        binary = BINARY_VECTOR.read_bytes()
        self.assertEqual(binary[:8], b"EY5KAT01")
        self.assertEqual(binary[12:44], hashlib.sha256(json_bytes).digest())


if __name__ == "__main__":
    unittest.main()
