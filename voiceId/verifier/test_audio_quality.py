from __future__ import annotations

import math
import unittest

from voiceid_verifier.audio_quality import (
    detect_voice_activity,
    evaluate_decoded_audio_quality,
)


class AudioQualityTest(unittest.TestCase):
    def test_vad_accepts_sustained_speech_like_signal(self) -> None:
        samples = sine_samples(duration_ms=1400, speech_start_ms=100, speech_duration_ms=1000)

        quality = evaluate_decoded_audio_quality(
            b"audio",
            1400,
            samples=samples,
            sample_rate_hz=16000,
        )
        activity = detect_voice_activity(samples=samples, sample_rate_hz=16000)

        self.assertEqual(quality.kind, "accepted")
        self.assertGreaterEqual(activity.speech_ms, 900)
        self.assertGreater(activity.speech_ratio, 0.6)

    def test_vad_returns_uncertain_for_short_speech_burst(self) -> None:
        quality = evaluate_decoded_audio_quality(
            b"audio",
            1400,
            samples=sine_samples(duration_ms=1400, speech_start_ms=200, speech_duration_ms=120),
            sample_rate_hz=16000,
        )

        self.assertEqual(quality.kind, "uncertain")
        self.assertEqual(quality.reason, "low_speech")

    def test_vad_returns_uncertain_for_silence(self) -> None:
        samples = [0.0] * int(16000 * 1.4)

        quality = evaluate_decoded_audio_quality(
            b"audio",
            1400,
            samples=samples,
            sample_rate_hz=16000,
        )

        self.assertEqual(quality.kind, "uncertain")
        self.assertEqual(quality.reason, "low_speech")


def sine_samples(
    *,
    duration_ms: int,
    speech_start_ms: int,
    speech_duration_ms: int,
    sample_rate_hz: int = 16000,
) -> list[float]:
    sample_count = int(sample_rate_hz * duration_ms / 1000)
    speech_start = int(sample_rate_hz * speech_start_ms / 1000)
    speech_end = speech_start + int(sample_rate_hz * speech_duration_ms / 1000)
    samples: list[float] = []
    for index in range(sample_count):
        if speech_start <= index < speech_end:
            samples.append(0.2 * math.sin(2 * math.pi * 220 * index / sample_rate_hz))
        else:
            samples.append(0.0)
    return samples


if __name__ == "__main__":
    unittest.main()
