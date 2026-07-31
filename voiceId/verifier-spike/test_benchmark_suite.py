from __future__ import annotations

import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from benchmark_suite import (
    moonshine_intent_model_path,
    native_moonshine_model_path,
    render_benchmark_suite,
)


class BenchmarkSuiteTest(unittest.TestCase):
    def test_renders_machine_report_as_one_human_summary(self) -> None:
        report = {
            "datasetVersion": "solo-v1",
            "corpusManifestSha256": "a" * 64,
            "modelManifestSha256": "b" * 64,
            "inventory": {
                "fixtureCount": 12,
                "measurementReady": True,
                "humanMetricsEligible": False,
            },
            "moonshine": {
                "stageLatencyMs": {
                    "complete": {"p50": 100.0, "p95": 200.0, "p99": 250.0}
                },
                "hybridPhraseAccuracy": 0.95,
                "retryRate": 0.05,
            },
            "ecapa": {
                "latencyMs": {"p50": 50.0, "p95": 75.0, "p99": 90.0},
                "evaluation": {
                    "far": {"rate": 0.01},
                    "frr": {"rate": 0.05},
                    "eer": 0.03,
                },
            },
            "aasist": {
                "evaluation": {
                    "latencyMs": {"p50": 75.0, "p95": 100.0, "p99": 125.0},
                    "apcer": {"rate": 0.02},
                    "bpcer": {"rate": 0.04},
                    "uncertainty": {"rate": 0.03},
                }
            },
        }

        rendered = render_benchmark_suite(report)

        self.assertIn("# VoiceID Benchmark Suite", rendered)
        self.assertIn("Hybrid phrase accuracy: 95.00%", rendered)
        self.assertIn("Evaluation FAR: 1.00%", rendered)
        self.assertIn("APCER: 2.00%", rendered)
        self.assertIn("Human population", rendered)

    def test_resolves_pinned_native_model_payloads_below_download_roots(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            tiny = (
                root
                / "moonshine"
                / "tiny"
                / "download.moonshine.ai"
                / "model"
                / "tiny-streaming-en"
                / "quantized"
            )
            intent = (
                root
                / "moonshine"
                / "intent"
                / "download.moonshine.ai"
                / "model"
                / "embeddinggemma-300m"
            )
            tiny.mkdir(parents=True)
            intent.mkdir(parents=True)
            (tiny / "tokenizer.bin").write_bytes(b"tokenizer")
            (intent / "model_q4.onnx").write_bytes(b"model")

            self.assertEqual(
                native_moonshine_model_path(root, "tiny_streaming"),
                tiny,
            )
            self.assertEqual(moonshine_intent_model_path(root), intent)


if __name__ == "__main__":
    unittest.main()
