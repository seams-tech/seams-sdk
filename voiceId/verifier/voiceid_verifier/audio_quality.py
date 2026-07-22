from __future__ import annotations

from array import array
from dataclasses import dataclass
from math import ceil
from math import sqrt
from typing import MutableSequence, Sequence

MIN_SPEECH_MS = 450
MIN_SPEECH_RATIO = 0.12
MIN_LONGEST_SPEECH_MS = 220
VAD_FRAME_MS = 30
VAD_HOP_MS = 10
MAX_SPEECH_WINDOW_MS = 3000
MIN_SPEECH_WINDOW_MS = 600
MAX_INTERIOR_SILENCE_MS = 180


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


@dataclass(frozen=True)
class SpeechWindow:
    start_ms: int
    end_ms: int
    speech_ms: int
    signal_score: float
    samples: MutableSequence[float]


@dataclass(frozen=True)
class FrameActivity:
    frame_starts: tuple[int, ...]
    active_frames: tuple[bool, ...]
    frame_size: int
    hop_size: int


@dataclass(frozen=True)
class CanonicalSpeechAnalysis:
    quality: AudioQuality
    voice_activity: VoiceActivity
    speech_windows: tuple[SpeechWindow, ...]


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
    samples: Sequence[float],
    sample_rate_hz: int,
) -> AudioQuality:
    voice_activity = detect_voice_activity(samples=samples, sample_rate_hz=sample_rate_hz)
    return evaluate_decoded_audio_quality_with_activity(
        audio_bytes,
        duration_ms,
        samples=samples,
        voice_activity=voice_activity,
    )


def analyze_decoded_audio(
    audio_bytes: bytes,
    duration_ms: int,
    *,
    samples: Sequence[float],
    sample_rate_hz: int,
) -> CanonicalSpeechAnalysis:
    frame_activity = calculate_frame_activity(samples=samples, sample_rate_hz=sample_rate_hz)
    voice_activity = voice_activity_from_frames(
        activity=frame_activity,
        sample_rate_hz=sample_rate_hz,
    )
    quality = evaluate_decoded_audio_quality_with_activity(
        audio_bytes,
        duration_ms,
        samples=samples,
        voice_activity=voice_activity,
    )
    speech_windows = extract_speech_windows_from_activity(
        samples=samples,
        sample_rate_hz=sample_rate_hz,
        activity=frame_activity,
    )
    return CanonicalSpeechAnalysis(
        quality=quality,
        voice_activity=voice_activity,
        speech_windows=speech_windows,
    )


def evaluate_decoded_audio_quality_with_activity(
    audio_bytes: bytes,
    duration_ms: int,
    *,
    samples: Sequence[float],
    voice_activity: VoiceActivity,
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

    if (
        voice_activity.speech_ms < MIN_SPEECH_MS
        or voice_activity.speech_ratio < MIN_SPEECH_RATIO
        or voice_activity.longest_speech_ms < MIN_LONGEST_SPEECH_MS
    ):
        return AudioQuality(kind="uncertain", duration_ms=duration_ms, reason="low_speech")

    return AudioQuality(kind="accepted", duration_ms=duration_ms, signal_score=signal_score)


def detect_voice_activity(*, samples: Sequence[float], sample_rate_hz: int) -> VoiceActivity:
    activity = calculate_frame_activity(samples=samples, sample_rate_hz=sample_rate_hz)
    return voice_activity_from_frames(activity=activity, sample_rate_hz=sample_rate_hz)


def voice_activity_from_frames(
    *,
    activity: FrameActivity,
    sample_rate_hz: int,
) -> VoiceActivity:
    if len(activity.active_frames) == 0:
        return VoiceActivity(
            speech_ms=0,
            speech_ratio=0.0,
            longest_speech_ms=0,
            active_frame_count=0,
            frame_count=0,
        )

    active_frame_count = sum(1 for active in activity.active_frames if active)
    longest_active_frames = longest_true_run(activity.active_frames)
    hop_ms = activity.hop_size * 1000 / sample_rate_hz

    return VoiceActivity(
        speech_ms=round(active_frame_count * hop_ms),
        speech_ratio=active_frame_count / len(activity.active_frames),
        longest_speech_ms=round(longest_active_frames * hop_ms),
        active_frame_count=active_frame_count,
        frame_count=len(activity.active_frames),
    )


def extract_speech_windows(
    *,
    samples: Sequence[float],
    sample_rate_hz: int,
) -> tuple[SpeechWindow, ...]:
    activity = calculate_frame_activity(samples=samples, sample_rate_hz=sample_rate_hz)
    return extract_speech_windows_from_activity(
        samples=samples,
        sample_rate_hz=sample_rate_hz,
        activity=activity,
    )


def extract_speech_windows_from_activity(
    *,
    samples: Sequence[float],
    sample_rate_hz: int,
    activity: FrameActivity,
) -> tuple[SpeechWindow, ...]:
    active_regions = collect_active_regions(activity=activity, sample_rate_hz=sample_rate_hz)
    windows: list[SpeechWindow] = []
    for region_start, region_end in active_regions:
        windows.extend(
            split_active_region(
                samples=samples,
                sample_rate_hz=sample_rate_hz,
                activity=activity,
                region_start=region_start,
                region_end=region_end,
            )
        )
    return tuple(windows)


def calculate_frame_activity(*, samples: Sequence[float], sample_rate_hz: int) -> FrameActivity:
    sample_count = len(samples)
    frame_size = max(1, int(sample_rate_hz * VAD_FRAME_MS / 1000))
    hop_size = max(1, int(sample_rate_hz * VAD_HOP_MS / 1000))
    if sample_count < frame_size:
        return FrameActivity(frame_starts=(), active_frames=(), frame_size=frame_size, hop_size=hop_size)
    frame_starts = tuple(range(0, sample_count - frame_size + 1, hop_size))
    frame_rms = tuple(frame_root_mean_square(samples, start, frame_size) for start in frame_starts)
    sorted_rms = sorted(frame_rms)
    noise_floor = sorted_rms[max(0, int(len(sorted_rms) * 0.2) - 1)]
    peak_rms = sorted_rms[-1]
    threshold = voice_activity_threshold(noise_floor=noise_floor, peak_rms=peak_rms)
    return FrameActivity(
        frame_starts=frame_starts,
        active_frames=tuple(rms >= threshold for rms in frame_rms),
        frame_size=frame_size,
        hop_size=hop_size,
    )


def collect_active_regions(
    *,
    activity: FrameActivity,
    sample_rate_hz: int,
) -> tuple[tuple[int, int], ...]:
    maximum_silence_frames = max(1, round(MAX_INTERIOR_SILENCE_MS / VAD_HOP_MS))
    regions: list[tuple[int, int]] = []
    region_start_index: int | None = None
    last_active_index: int | None = None
    for index, active in enumerate(activity.active_frames):
        if active:
            if region_start_index is None:
                region_start_index = index
            last_active_index = index
            continue
        if (
            region_start_index is not None
            and last_active_index is not None
            and index - last_active_index > maximum_silence_frames
        ):
            regions.append(
                region_sample_bounds(
                    activity=activity,
                    start_index=region_start_index,
                    end_index=last_active_index,
                )
            )
            region_start_index = None
            last_active_index = None
    if region_start_index is not None and last_active_index is not None:
        regions.append(
            region_sample_bounds(
                activity=activity,
                start_index=region_start_index,
                end_index=last_active_index,
            )
        )
    minimum_samples = round(sample_rate_hz * MIN_SPEECH_WINDOW_MS / 1000)
    return tuple((start, end) for start, end in regions if end - start >= minimum_samples)


def region_sample_bounds(
    *,
    activity: FrameActivity,
    start_index: int,
    end_index: int,
) -> tuple[int, int]:
    return (
        activity.frame_starts[start_index],
        activity.frame_starts[end_index] + activity.frame_size,
    )


def split_active_region(
    *,
    samples: Sequence[float],
    sample_rate_hz: int,
    activity: FrameActivity,
    region_start: int,
    region_end: int,
) -> list[SpeechWindow]:
    maximum_samples = round(sample_rate_hz * MAX_SPEECH_WINDOW_MS / 1000)
    region_length = region_end - region_start
    window_count = max(1, ceil(region_length / maximum_samples))
    window_length = ceil(region_length / window_count)
    windows: list[SpeechWindow] = []
    for window_index in range(window_count):
        start = region_start + window_index * window_length
        end = min(region_end, start + window_length)
        if end <= start:
            continue
        window_samples = array("f", samples[start:end])
        speech_ms = speech_duration_in_bounds(
            activity=activity,
            sample_rate_hz=sample_rate_hz,
            start=start,
            end=end,
        )
        if speech_ms < MIN_SPEECH_WINDOW_MS:
            zero_float_sequence(window_samples)
            continue
        windows.append(
            SpeechWindow(
                start_ms=round(start * 1000 / sample_rate_hz),
                end_ms=round(end * 1000 / sample_rate_hz),
                speech_ms=speech_ms,
                signal_score=signal_score_for_samples(window_samples),
                samples=window_samples,
            )
        )
    return windows


def speech_duration_in_bounds(
    *,
    activity: FrameActivity,
    sample_rate_hz: int,
    start: int,
    end: int,
) -> int:
    active_count = 0
    for frame_start, active in zip(activity.frame_starts, activity.active_frames, strict=True):
        if active and start <= frame_start < end:
            active_count += 1
    return round(active_count * activity.hop_size * 1000 / sample_rate_hz)


def frame_root_mean_square(samples: Sequence[float], start: int, frame_size: int) -> float:
    total = 0.0
    for sample in samples[start : start + frame_size]:
        value = float(sample)
        total += value * value
    return sqrt(total / frame_size)


def signal_score_for_samples(samples: Sequence[float]) -> float:
    if len(samples) == 0:
        return 0.0
    rms = sqrt(sum(float(sample) * float(sample) for sample in samples) / len(samples))
    return max(0.0, min(1.0, rms * 12.0))


def zero_float_sequence(values: MutableSequence[float]) -> None:
    for index in range(len(values)):
        values[index] = 0.0


def voice_activity_threshold(*, noise_floor: float, peak_rms: float) -> float:
    if peak_rms < 0.005:
        return 1.0
    peak_relative_threshold = peak_rms * 0.12
    if noise_floor > 0.0 and peak_rms / noise_floor >= 2.5:
        return max(0.01, peak_relative_threshold, noise_floor * 2.5)
    return max(0.01, peak_relative_threshold)


def longest_true_run(values: Sequence[bool]) -> int:
    longest = 0
    current = 0
    for value in values:
        if value:
            current += 1
            longest = max(longest, current)
        else:
            current = 0
    return longest
