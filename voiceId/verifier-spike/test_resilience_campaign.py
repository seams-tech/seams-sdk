from __future__ import annotations

import unittest

from resilience_campaign import (
    run_forced_worker_termination,
    run_model_load_failure,
    run_queue_saturation,
    run_request_timeout,
    run_response_loss,
    run_soak,
)


class ResilienceCampaignTest(unittest.TestCase):
    def test_model_load_failure_fails_closed(self) -> None:
        result = run_model_load_failure()
        self.assertTrue(result["passed"])
        self.assertTrue(result["errorObserved"])

    def test_forced_worker_termination_recovers(self) -> None:
        self.assertTrue(run_forced_worker_termination()["passed"])

    def test_response_loss_fails_closed(self) -> None:
        self.assertTrue(run_response_loss()["passed"])

    def test_request_timeout_recovers(self) -> None:
        self.assertTrue(run_request_timeout()["passed"])

    def test_queue_saturation_recovers(self) -> None:
        self.assertTrue(run_queue_saturation()["passed"])

    def test_soak_tracks_resource_and_latency_drift(self) -> None:
        report = run_soak(32)
        self.assertTrue(report["passed"])
        self.assertEqual(report["workerCount"], 1)
        self.assertEqual(report["iterations"], 32)


if __name__ == "__main__":
    unittest.main()
