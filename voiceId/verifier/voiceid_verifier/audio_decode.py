from __future__ import annotations

import json
import subprocess
import sys
from array import array
from dataclasses import dataclass
from typing import MutableSequence


CANONICAL_SAMPLE_RATE_HZ = 16000
CANONICAL_CHANNEL_COUNT = 1
MAXIMUM_DECODE_DURATION_MS = 30000
DECODE_OVERFLOW_PROBE_MS = 100
DECODER_TIMEOUT_SECONDS = 10


class AudioDecodeError(RuntimeError):
    pass


@dataclass(frozen=True)
class DecodedAudio:
    samples: MutableSequence[float]
    sample_rate_hz: int
    channel_count: int
    source_codec: str
    source_sample_rate_hz: int
    source_channel_count: int
    source_duration_ms: int
    decoded_duration_ms: int


def decode_audio_bytes(
    audio_bytes: bytes,
    *,
    sample_rate_hz: int = CANONICAL_SAMPLE_RATE_HZ,
    maximum_duration_ms: int = MAXIMUM_DECODE_DURATION_MS,
) -> DecodedAudio:
    if len(audio_bytes) == 0:
        raise AudioDecodeError("audio bytes are empty")
    source = probe_audio_bytes(audio_bytes)
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
                str(CANONICAL_CHANNEL_COUNT),
                "-ar",
                str(sample_rate_hz),
                "-t",
                f"{(maximum_duration_ms + DECODE_OVERFLOW_PROBE_MS) / 1000:.3f}",
                "pipe:1",
            ],
            input=audio_bytes,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=DECODER_TIMEOUT_SECONDS,
        )
    except FileNotFoundError as exc:
        raise AudioDecodeError("ffmpeg is required to decode verifier audio") from exc
    except subprocess.TimeoutExpired as exc:
        raise AudioDecodeError("ffmpeg timed out while decoding verifier audio") from exc
    if process.returncode != 0:
        detail = process.stderr.decode("utf-8", errors="replace").strip()
        raise AudioDecodeError(detail or "ffmpeg failed to decode verifier audio")

    samples = array("f")
    try:
        samples.frombytes(process.stdout)
    except ValueError as exc:
        raise AudioDecodeError("decoded audio is not aligned f32le data") from exc
    if sys.byteorder != "little":
        samples.byteswap()
    if len(samples) == 0:
        raise AudioDecodeError("decoded audio has no samples")
    decoded_duration_ms = round(len(samples) * 1000 / sample_rate_hz)
    source_duration_ms = source.duration_ms or decoded_duration_ms
    if source_duration_ms > maximum_duration_ms or decoded_duration_ms > maximum_duration_ms:
        zero_float_sequence(samples)
        raise AudioDecodeError("decoded audio exceeds the maximum duration")
    return DecodedAudio(
        samples=samples,
        sample_rate_hz=sample_rate_hz,
        channel_count=CANONICAL_CHANNEL_COUNT,
        source_codec=source.codec,
        source_sample_rate_hz=source.sample_rate_hz,
        source_channel_count=source.channel_count,
        source_duration_ms=source_duration_ms,
        decoded_duration_ms=decoded_duration_ms,
    )


@dataclass(frozen=True)
class AudioSourceInfo:
    codec: str
    sample_rate_hz: int
    channel_count: int
    duration_ms: int | None


def probe_audio_bytes(audio_bytes: bytes) -> AudioSourceInfo:
    try:
        process = subprocess.run(
            [
                "ffprobe",
                "-v",
                "error",
                "-select_streams",
                "a:0",
                "-show_entries",
                "stream=codec_name,sample_rate,channels,duration:format=duration",
                "-of",
                "json",
                "pipe:0",
            ],
            input=audio_bytes,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=DECODER_TIMEOUT_SECONDS,
        )
    except FileNotFoundError as exc:
        raise AudioDecodeError("ffprobe is required to inspect verifier audio") from exc
    except subprocess.TimeoutExpired as exc:
        raise AudioDecodeError("ffprobe timed out while inspecting verifier audio") from exc
    if process.returncode != 0:
        detail = process.stderr.decode("utf-8", errors="replace").strip()
        raise AudioDecodeError(detail or "ffprobe failed to inspect verifier audio")
    try:
        result = json.loads(process.stdout.decode("utf-8"))
        streams = result["streams"]
        stream = streams[0]
        codec = str(stream["codec_name"])
        sample_rate_hz = int(stream["sample_rate"])
        channel_count = int(stream["channels"])
        duration_ms = parse_duration_ms(stream.get("duration"))
        if duration_ms is None:
            duration_ms = parse_duration_ms(result.get("format", {}).get("duration"))
    except (KeyError, IndexError, TypeError, ValueError, json.JSONDecodeError) as exc:
        raise AudioDecodeError("ffprobe returned incomplete audio metadata") from exc
    if len(codec) == 0 or sample_rate_hz <= 0 or channel_count <= 0:
        raise AudioDecodeError("ffprobe returned invalid audio metadata")
    return AudioSourceInfo(
        codec=codec,
        sample_rate_hz=sample_rate_hz,
        channel_count=channel_count,
        duration_ms=duration_ms,
    )


def parse_duration_ms(value: object) -> int | None:
    if value is None or value == "N/A":
        return None
    duration_seconds = float(value)
    if duration_seconds <= 0:
        return None
    return round(duration_seconds * 1000)


def zero_float_sequence(values: MutableSequence[float]) -> None:
    for index in range(len(values)):
        values[index] = 0.0
