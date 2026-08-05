from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from enrollment_stability import EnrollmentStabilityError, evaluate_stability


class EnrollmentStabilityTest(unittest.TestCase):
    def test_measures_three_days_and_selects_shortest_reliable_session(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            input_path = root / "input.json"
            input_path.write_text(json.dumps(stability_input()), encoding="utf-8")
            report = evaluate_stability(input_path, root / "report.json")
            self.assertEqual(report["sessionCount"], 3)
            self.assertEqual(report["captureDayCount"], 3)
            self.assertEqual(report["shortestReliableDurationMs"], 12000)
            self.assertTrue(report["reliable"])
            self.assertGreaterEqual(report["crossSessionSimilarity"]["minimum"], 0.98)

    def test_rejects_sessions_from_the_same_day(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            value = stability_input()
            value["sessions"][1]["capturedAt"] = "2026-07-31T11:00:00Z"
            value["sessions"][2]["capturedAt"] = "2026-07-31T12:00:00Z"
            input_path = root / "input.json"
            input_path.write_text(json.dumps(value), encoding="utf-8")
            with self.assertRaisesRegex(EnrollmentStabilityError, "three capture days"):
                evaluate_stability(input_path, root / "report.json")


def stability_input() -> dict[str, object]:
    return {
        "schemaVersion": "voice_id_enrollment_stability_input_v1",
        "subjectId": "owner_eval",
        "sessions": [
            session("owner_session_1", "2026-07-29T10:00:00Z", 12000, 1.0),
            session("owner_session_2", "2026-07-30T10:00:00Z", 18000, 1.001),
            session("owner_session_3", "2026-07-31T10:00:00Z", 16000, 0.999),
        ],
    }


def session(session_id: str, captured_at: str, duration_ms: int, offset: float) -> dict[str, object]:
    return {
        "sessionId": session_id,
        "capturedAt": captured_at,
        "durationMs": duration_ms,
        "usableSpeechMs": 9000,
        "promptCount": 4,
        "promptCoverage": 1.0,
        "windows": [
            {"speechMs": 2200, "signalScore": 0.9, "embedding": [offset, 0.0, 0.0, 0.0]},
            {"speechMs": 2200, "signalScore": 0.9, "embedding": [offset, 0.01, 0.0, 0.0]},
            {"speechMs": 2200, "signalScore": 0.9, "embedding": [offset, 0.0, 0.01, 0.0]},
            {"speechMs": 2200, "signalScore": 0.9, "embedding": [offset, 0.0, 0.0, 0.01]},
        ],
    }


if __name__ == "__main__":
    unittest.main()
