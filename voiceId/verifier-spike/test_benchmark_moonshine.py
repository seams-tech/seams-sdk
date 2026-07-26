from __future__ import annotations

import unittest
from dataclasses import dataclass

from benchmark_moonshine import (
    decision_accuracy,
    expected_phrase_for_entry,
    latency_summary,
    peak_rss_bytes,
)


@dataclass(frozen=True)
class Entry:
    expected_intent: str
    challenge_tokens: tuple[str, ...]


class MoonshineBenchmarkTest(unittest.TestCase):
    def test_builds_semantic_intent_phrase_with_fresh_tokens(self) -> None:
        entry = Entry(
            expected_intent="approve",
            challenge_tokens=("maple", "eight", "star"),
        )

        self.assertAlmostEqual(
            expected_phrase_for_entry(entry),
            "approve this request maple eight star",
        )

    def test_reports_interpolated_latency_percentiles(self) -> None:
        summary = latency_summary([10.0, 20.0, 30.0])

        self.assertEqual(summary["p50"], 20.0)
        self.assertEqual(summary["p95"], 29.0)
        self.assertEqual(summary["p99"], 29.8)

    def test_reports_peak_rss_in_bytes(self) -> None:
        self.assertGreater(peak_rss_bytes(), 1024)

    def test_reports_policy_accuracy_against_frozen_expected_decisions(self) -> None:
        self.assertAlmostEqual(
            decision_accuracy(
                (
                    ("accepted", "accepted"),
                    ("rejected", "accepted"),
                    ("rejected", "rejected"),
                )
            ),
            2 / 3,
            places=6,
        )


if __name__ == "__main__":
    unittest.main()
