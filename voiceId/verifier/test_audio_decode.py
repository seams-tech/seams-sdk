from __future__ import annotations

import subprocess
import unittest
from unittest.mock import patch

from voiceid_verifier.audio_decode import (
    AudioDecodeError,
    AudioSourceInfo,
    decode_audio_bytes,
)


class AudioDecodeTest(unittest.TestCase):
    def test_decoder_timeout_becomes_bounded_audio_failure(self) -> None:
        source = AudioSourceInfo(
            codec="pcm_s16le",
            sample_rate_hz=16000,
            channel_count=1,
            duration_ms=1000,
        )
        with (
            patch("voiceid_verifier.audio_decode.probe_audio_bytes", return_value=source),
            patch(
                "voiceid_verifier.audio_decode.subprocess.run",
                side_effect=subprocess.TimeoutExpired("ffmpeg", 10),
            ),
        ):
            with self.assertRaisesRegex(AudioDecodeError, "timed out"):
                decode_audio_bytes(b"bounded audio")


if __name__ == "__main__":
    unittest.main()
