from __future__ import annotations

import unittest
from array import array

from fuzz_media import MediaFuzzCase, generate_media_fuzz_cases, run_media_fuzz
from voiceid_verifier.audio_decode import AudioDecodeError, DecodedAudio


class MediaFuzzTest(unittest.TestCase):
    def test_generation_is_seeded_and_bounded(self) -> None:
        first = generate_media_fuzz_cases(
            seed=42,
            case_count=12,
            maximum_case_bytes=256,
        )
        second = generate_media_fuzz_cases(
            seed=42,
            case_count=12,
            maximum_case_bytes=256,
        )

        self.assertEqual(first, second)
        self.assertTrue(all(0 < len(case.payload) <= 256 for case in first))

    def test_report_distinguishes_expected_rejection_from_decoder_failure(self) -> None:
        cases = (
            MediaFuzzCase(case_id="rejected", payload=b"reject"),
            MediaFuzzCase(case_id="decoded", payload=b"decode"),
            MediaFuzzCase(case_id="failed", payload=b"fail"),
        )

        report = run_media_fuzz(
            cases=cases,
            seed=1,
            latency_budget_ms=1000,
            decoder=controlled_decoder,
        )

        self.assertEqual(report["rejectedCount"], 1)
        self.assertEqual(report["decodedBoundedCount"], 1)
        self.assertEqual(report["unexpectedFailureCount"], 1)
        self.assertFalse(report["releaseReady"])


def controlled_decoder(payload: bytes) -> DecodedAudio:
    if payload == b"reject":
        raise AudioDecodeError("expected rejection")
    if payload == b"fail":
        raise RuntimeError("unexpected decoder failure")
    return DecodedAudio(
        samples=array("f", [0.1, -0.1]),
        sample_rate_hz=16000,
        channel_count=1,
        source_codec="pcm_s16le",
        source_sample_rate_hz=16000,
        source_channel_count=1,
        source_duration_ms=1,
        decoded_duration_ms=1,
    )


if __name__ == "__main__":
    unittest.main()
