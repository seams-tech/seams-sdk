from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class AudioQuality:
    kind: str
    duration_ms: int
    reason: str | None = None
    signal_score: float | None = None


def evaluate_audio_quality(audio_bytes: bytes, duration_ms: int) -> AudioQuality:
    if len(audio_bytes) == 0:
        return AudioQuality(kind="rejected", duration_ms=duration_ms, reason="empty_audio")
    if duration_ms < 900:
        return AudioQuality(kind="uncertain", duration_ms=duration_ms, reason="too_short")
    return AudioQuality(kind="accepted", duration_ms=duration_ms, signal_score=0.9)
