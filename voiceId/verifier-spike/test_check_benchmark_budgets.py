from __future__ import annotations

import unittest

from check_benchmark_budgets import (
    BenchmarkBudgets,
    StageBudget,
    check_benchmark_budgets,
)


class BenchmarkBudgetTest(unittest.TestCase):
    def test_accepts_suite_inside_frozen_budgets(self) -> None:
        report = check_benchmark_budgets(suite_report(), budgets())

        self.assertTrue(report["passed"])
        self.assertEqual(report["violations"], [])

    def test_reports_accuracy_latency_memory_and_readiness_regressions(self) -> None:
        suite = suite_report()
        suite["inventory"]["measurementReady"] = False
        suite["moonshine"]["hybridPhraseAccuracy"] = 0.8
        suite["moonshine"]["stageLatencyMs"]["complete"]["p95"] = 900.0
        suite["ecapa"]["peakRssBytes"] = 4_000_000_000
        suite["aasist"]["evaluation"]["releaseReady"] = False

        report = check_benchmark_budgets(suite, budgets())

        self.assertFalse(report["passed"])
        self.assertGreaterEqual(len(report["violations"]), 5)


def budgets() -> BenchmarkBudgets:
    stage = StageBudget(
        maximum_p95_latency_ms=500.0,
        maximum_p99_latency_ms=1000.0,
        maximum_error_rate=0.05,
        maximum_retry_or_uncertainty_rate=0.10,
        minimum_accuracy=0.95,
        maximum_peak_rss_bytes=3_000_000_000,
    )
    return BenchmarkBudgets(
        dataset_version="solo-v1",
        model_manifest_sha256="a" * 64,
        moonshine=stage,
        ecapa=stage,
        aasist=stage,
    )


def suite_report() -> dict:
    latency = {"p50": 100.0, "p95": 200.0, "p99": 300.0}
    rate = {
        "errors": 1,
        "trials": 100,
        "rate": 0.01,
        "confidence_low": 0.0,
        "confidence_high": 0.05,
    }
    return {
        "schemaVersion": "voice_id_benchmark_suite_v1",
        "datasetVersion": "solo-v1",
        "modelManifestSha256": "a" * 64,
        "inventory": {"measurementReady": True},
        "moonshine": {
            "stageLatencyMs": {"complete": dict(latency)},
            "failureRate": 0.01,
            "retryRate": 0.02,
            "hybridPhraseAccuracy": 0.99,
            "resources": {"peakRssBytes": 1_000_000_000},
        },
        "ecapa": {
            "latencyMs": dict(latency),
            "evaluation": {
                "far": dict(rate),
                "frr": dict(rate),
                "eer": 0.01,
            },
            "peakRssBytes": 1_000_000_000,
        },
        "aasist": {
            "evaluation": {
                "releaseReady": True,
                "latencyMs": dict(latency),
                "apcer": dict(rate),
                "bpcer": dict(rate),
                "uncertainty": dict(rate),
                "peakRssBytes": 1_000_000_000,
            }
        },
    }


if __name__ == "__main__":
    unittest.main()
