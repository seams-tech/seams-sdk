from __future__ import annotations

import subprocess
from dataclasses import dataclass
from typing import Any


class AudioDecodeError(RuntimeError):
    pass


@dataclass(frozen=True)
class DecodedAudio:
    samples: Any
    sample_rate_hz: int


def decode_audio_bytes(audio_bytes: bytes, *, sample_rate_hz: int = 16000) -> DecodedAudio:
    if len(audio_bytes) == 0:
        raise AudioDecodeError("audio bytes are empty")
    try:
        process = subprocess.run(
            [
                "ffmpeg",
                "-hide_banner",
                "-loglevel",
                "error",
                "-i",
                "pipe:0",
                "-f",
                "f32le",
                "-ac",
                "1",
                "-ar",
                str(sample_rate_hz),
                "pipe:1",
            ],
            input=audio_bytes,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
    except FileNotFoundError as exc:
        raise AudioDecodeError("ffmpeg is required to decode verifier audio") from exc
    if process.returncode != 0:
        detail = process.stderr.decode("utf-8", errors="replace").strip()
        raise AudioDecodeError(detail or "ffmpeg failed to decode verifier audio")

    try:
        import numpy as np
    except ImportError as exc:
        raise AudioDecodeError("numpy is required to decode verifier audio") from exc

    samples = np.frombuffer(process.stdout, dtype="<f4").copy()
    if samples.size == 0:
        raise AudioDecodeError("decoded audio has no samples")
    return DecodedAudio(samples=samples, sample_rate_hz=sample_rate_hz)
