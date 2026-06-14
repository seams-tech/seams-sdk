from __future__ import annotations

from dataclasses import dataclass
from math import sqrt
from typing import Any

MIN_SPEECH_MS = 450
MIN_SPEECH_RATIO = 0.12
MIN_LONGEST_SPEECH_MS = 220
VAD_FRAME_MS = 30
VAD_HOP_MS = 10


@dataclass(frozen=True)
class AudioQuality:
    kind: str
    duration_ms: int
    reason: str | None = None
    signal_score: float | None = None


@dataclass(frozen=True)
class VoiceActivity:
    speech_ms: int
    speech_ratio: float
    longest_speech_ms: int
    active_frame_count: int
    frame_count: int


def evaluate_audio_quality(audio_bytes: bytes, duration_ms: int) -> AudioQuality:
    if len(audio_bytes) == 0:
        return AudioQuality(kind="rejected", duration_ms=duration_ms, reason="empty_audio")
    if duration_ms < 900:
        return AudioQuality(kind="uncertain", duration_ms=duration_ms, reason="too_short")
    return AudioQuality(kind="accepted", duration_ms=duration_ms, signal_score=0.9)


def evaluate_decoded_audio_quality(
    audio_bytes: bytes,
    duration_ms: int,
    *,
    samples: Any,
    sample_rate_hz: int,
) -> AudioQuality:
    if len(audio_bytes) == 0:
        return AudioQuality(kind="rejected", duration_ms=duration_ms, reason="empty_audio")
    if duration_ms < 900:
        return AudioQuality(kind="uncertain", duration_ms=duration_ms, reason="too_short")

    sample_count = len(samples)
    if sample_count == 0:
        return AudioQuality(kind="uncertain", duration_ms=duration_ms, reason="low_speech")

    abs_samples = [abs(float(sample)) for sample in samples]
    peak = max(abs_samples)
    if peak < 0.005:
        return AudioQuality(kind="uncertain", duration_ms=duration_ms, reason="low_speech")

    clipped_count = sum(1 for value in abs_samples if value >= 0.98)
    clipped_ratio = clipped_count / sample_count
    if clipped_ratio > 0.01:
        return AudioQuality(kind="uncertain", duration_ms=duration_ms, reason="clipped_audio")

    rms = sqrt(sum(value * value for value in abs_samples) / sample_count)
    signal_score = max(0.0, min(1.0, rms * 12.0))
    if signal_score < 0.03:
        return AudioQuality(kind="uncertain", duration_ms=duration_ms, reason="low_snr")

    speech_floor = max(0.01, rms * 0.25)
    speech_ratio = sum(1 for value in abs_samples if value >= speech_floor) / sample_count
    if speech_ratio < 0.08:
        return AudioQuality(kind="uncertain", duration_ms=duration_ms, reason="low_speech")

    voice_activity = detect_voice_activity(
        samples=samples,
        sample_rate_hz=sample_rate_hz,
    )
    if (
        voice_activity.speech_ms < MIN_SPEECH_MS
        or voice_activity.speech_ratio < MIN_SPEECH_RATIO
        or voice_activity.longest_speech_ms < MIN_LONGEST_SPEECH_MS
    ):
        return AudioQuality(kind="uncertain", duration_ms=duration_ms, reason="low_speech")

    return AudioQuality(kind="accepted", duration_ms=duration_ms, signal_score=signal_score)


def detect_voice_activity(*, samples: Any, sample_rate_hz: int) -> VoiceActivity:
    sample_count = len(samples)
    frame_size = max(1, int(sample_rate_hz * VAD_FRAME_MS / 1000))
    hop_size = max(1, int(sample_rate_hz * VAD_HOP_MS / 1000))
    if sample_count < frame_size:
        return VoiceActivity(
            speech_ms=0,
            speech_ratio=0.0,
            longest_speech_ms=0,
            active_frame_count=0,
            frame_count=0,
        )

    frame_rms = []
    for start in range(0, sample_count - frame_size + 1, hop_size):
        total = 0.0
        for sample in samples[start : start + frame_size]:
            value = float(sample)
            total += value * value
        frame_rms.append(sqrt(total / frame_size))

    if len(frame_rms) == 0:
        return VoiceActivity(
            speech_ms=0,
            speech_ratio=0.0,
            longest_speech_ms=0,
            active_frame_count=0,
            frame_count=0,
        )

    sorted_rms = sorted(frame_rms)
    noise_floor = sorted_rms[max(0, int(len(sorted_rms) * 0.2) - 1)]
    peak_rms = sorted_rms[-1]
    threshold = voice_activity_threshold(noise_floor=noise_floor, peak_rms=peak_rms)
    active_frames = [rms >= threshold for rms in frame_rms]
    active_frame_count = sum(1 for active in active_frames if active)
    longest_active_frames = longest_true_run(active_frames)
    hop_ms = hop_size * 1000 / sample_rate_hz

    return VoiceActivity(
        speech_ms=round(active_frame_count * hop_ms),
        speech_ratio=active_frame_count / len(active_frames),
        longest_speech_ms=round(longest_active_frames * hop_ms),
        active_frame_count=active_frame_count,
        frame_count=len(active_frames),
    )


def voice_activity_threshold(*, noise_floor: float, peak_rms: float) -> float:
    if peak_rms < 0.005:
        return 1.0
    peak_relative_threshold = peak_rms * 0.12
    if noise_floor > 0.0 and peak_rms / noise_floor >= 2.5:
        return max(0.01, peak_relative_threshold, noise_floor * 2.5)
    return max(0.01, peak_relative_threshold)


def longest_true_run(values: list[bool]) -> int:
    longest = 0
    current = 0
    for value in values:
        if value:
            current += 1
            longest = max(longest, current)
        else:
            current = 0
    return longest
