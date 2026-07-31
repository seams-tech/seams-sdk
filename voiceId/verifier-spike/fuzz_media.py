from __future__ import annotations

import argparse
import hashlib
import json
import random
import struct
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

from voiceid_verifier.audio_decode import (
    MAXIMUM_DECODE_DURATION_MS,
    AudioDecodeError,
    DecodedAudio,
    decode_audio_bytes,
    zero_float_sequence,
)


REPORT_SCHEMA_VERSION = "voice_id_media_fuzz_report_v1"


@dataclass(frozen=True)
class MediaFuzzCase:
    case_id: str
    payload: bytes


def generate_media_fuzz_cases(
    *,
    seed: int,
    case_count: int,
    maximum_case_bytes: int,
) -> tuple[MediaFuzzCase, ...]:
    if case_count <= 0:
        raise ValueError("case_count must be positive")
    if maximum_case_bytes < 64:
        raise ValueError("maximum_case_bytes must be at least 64")
    generator = random.Random(seed)
    valid_wav = minimal_pcm_wav()
    prefixes = (b"", b"RIFF", b"OggS", b"fLaC", b"ID3", b"\x1aE\xdf\xa3")
    cases: list[MediaFuzzCase] = []
    for index in range(case_count):
        if index % 3 == 0:
            cut = generator.randint(1, min(len(valid_wav) - 1, maximum_case_bytes))
            payload = valid_wav[:cut]
        else:
            length = generator.randint(1, maximum_case_bytes)
            prefix = prefixes[generator.randrange(len(prefixes))]
            remaining = max(0, length - len(prefix))
            payload = prefix + generator.randbytes(remaining)
        cases.append(
            MediaFuzzCase(
                case_id=f"media_fuzz_{index:04d}",
                payload=payload,
            )
        )
    return tuple(cases)


def run_media_fuzz(
    *,
    cases: tuple[MediaFuzzCase, ...],
    seed: int,
    latency_budget_ms: float,
    decoder: Callable[[bytes], DecodedAudio] = decode_audio_bytes,
) -> dict[str, Any]:
    if latency_budget_ms <= 0:
        raise ValueError("latency_budget_ms must be positive")
    observations = []
    unexpected_failures = []
    for case in cases:
        started = time.perf_counter()
        decoded: DecodedAudio | None = None
        try:
            decoded = decoder(case.payload)
            if decoded.decoded_duration_ms > MAXIMUM_DECODE_DURATION_MS:
                raise RuntimeError("decoder returned audio beyond the duration limit")
            outcome = "decoded_bounded"
        except AudioDecodeError:
            outcome = "rejected"
        except Exception as error:
            outcome = "unexpected_failure"
            unexpected_failures.append(
                {
                    "caseId": case.case_id,
                    "errorType": type(error).__name__,
                }
            )
        finally:
            if decoded is not None:
                zero_float_sequence(decoded.samples)
        observations.append(
            {
                "caseId": case.case_id,
                "payloadBytes": len(case.payload),
                "payloadSha256": hashlib.sha256(case.payload).hexdigest(),
                "outcome": outcome,
                "latencyMs": round((time.perf_counter() - started) * 1000, 3),
            }
        )
    latencies = [observation["latencyMs"] for observation in observations]
    latency = latency_summary(latencies)
    return {
        "schemaVersion": REPORT_SCHEMA_VERSION,
        "seed": seed,
        "caseCount": len(cases),
        "rejectedCount": sum(
            observation["outcome"] == "rejected" for observation in observations
        ),
        "decodedBoundedCount": sum(
            observation["outcome"] == "decoded_bounded"
            for observation in observations
        ),
        "unexpectedFailureCount": len(unexpected_failures),
        "maximumPayloadBytes": max(len(case.payload) for case in cases),
        "latencyBudgetMs": latency_budget_ms,
        "latencyMs": latency,
        "releaseReady": (
            len(unexpected_failures) == 0
            and latency["p99"] <= latency_budget_ms
        ),
        "unexpectedFailures": unexpected_failures,
        "observations": observations,
    }


def minimal_pcm_wav() -> bytes:
    samples = tuple(0 for _ in range(800))
    pcm = b"".join(struct.pack("<h", sample) for sample in samples)
    return b"".join(
        (
            b"RIFF",
            struct.pack("<I", 36 + len(pcm)),
            b"WAVEfmt ",
            struct.pack("<IHHIIHH", 16, 1, 1, 16000, 32000, 2, 16),
            b"data",
            struct.pack("<I", len(pcm)),
            pcm,
        )
    )


def latency_summary(values: list[float]) -> dict[str, float]:
    ordered = sorted(values)
    return {
        "p50": round(percentile(ordered, 0.50), 3),
        "p95": round(percentile(ordered, 0.95), 3),
        "p99": round(percentile(ordered, 0.99), 3),
    }


def percentile(values: list[float], quantile: float) -> float:
    if len(values) == 1:
        return values[0]
    position = (len(values) - 1) * quantile
    lower = int(position)
    upper = min(lower + 1, len(values) - 1)
    fraction = position - lower
    return values[lower] + (values[upper] - values[lower]) * fraction


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Run a deterministic malformed-media campaign through the VoiceID decoder."
    )
    parser.add_argument("--seed", type=int, default=20260726)
    parser.add_argument("--cases", type=int, default=64)
    parser.add_argument("--maximum-case-bytes", type=int, default=4096)
    parser.add_argument("--latency-budget-ms", type=float, default=1000.0)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    report = run_media_fuzz(
        cases=generate_media_fuzz_cases(
            seed=args.seed,
            case_count=args.cases,
            maximum_case_bytes=args.maximum_case_bytes,
        ),
        seed=args.seed,
        latency_budget_ms=args.latency_budget_ms,
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    if not report["releaseReady"]:
        raise SystemExit("media fuzz campaign failed")


if __name__ == "__main__":
    main()
