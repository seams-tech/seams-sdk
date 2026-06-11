from __future__ import annotations

import argparse
import json
import math
import shutil
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import numpy as np

from compare_models import FixtureInventory, FixtureManifestEntry, load_fixture_inventory


SAMPLE_RATE = 16_000
FRAME_LENGTH = 400
FRAME_HOP = 160
MEL_BINS = 40
MFCC_COEFFICIENTS = 13


class SpectralBaselineError(ValueError):
    pass


@dataclass(frozen=True)
class DecodedAudio:
    samples: np.ndarray
    sample_rate: int


@dataclass(frozen=True)
class FixtureEmbedding:
    fixture_id: str
    expected_relation: str
    speaker_label: str
    score: float
    latency_ms: float


@dataclass(frozen=True)
class ThresholdDecision:
    threshold: float
    true_accepts: int
    false_rejects: int
    true_rejects: int
    false_accepts: int


@dataclass(frozen=True)
class SpectralBaselineReport:
    adapter_id: str
    inventory: FixtureInventory
    threshold: ThresholdDecision
    scores: tuple[FixtureEmbedding, ...]
    score_counts: dict[str, int]
    score_ranges: dict[str, tuple[float, float]]
    latency_mean_ms: float
    latency_p95_ms: float
    embedding_dimensions: int


def evaluate_spectral_baseline(inventory: FixtureInventory) -> SpectralBaselineReport:
    embeddings: dict[str, np.ndarray] = {}
    latencies: dict[str, float] = {}
    for entry in inventory.entries:
        started = time.perf_counter()
        audio = decode_audio(entry.audio_path)
        embeddings[entry.fixture_id] = extract_mfcc_stats_embedding(audio.samples)
        latencies[entry.fixture_id] = (time.perf_counter() - started) * 1000.0
    return evaluate_embeddings(
        inventory,
        embeddings,
        adapter_id="local-mfcc-stats-baseline",
        latencies_ms=latencies,
    )


def evaluate_embeddings(
    inventory: FixtureInventory,
    embeddings: dict[str, np.ndarray],
    *,
    adapter_id: str,
    latencies_ms: dict[str, float],
) -> SpectralBaselineReport:
    enrollment_entries = [
        entry for entry in inventory.entries if entry.expected_relation == "owner_enrollment"
    ]
    if len(enrollment_entries) == 0:
        raise SpectralBaselineError("at least one owner_enrollment fixture is required")

    enrollment_vectors = [_require_embedding(entry, embeddings) for entry in enrollment_entries]
    template = normalize_vector(np.mean(np.vstack(enrollment_vectors), axis=0))
    scores = tuple(score_entry(entry, embeddings, latencies_ms, template) for entry in inventory.entries)
    threshold = choose_threshold(scores)
    grouped = group_scores_by_relation(scores)
    latencies = np.asarray([score.latency_ms for score in scores], dtype=np.float64)

    return SpectralBaselineReport(
        adapter_id=adapter_id,
        inventory=inventory,
        threshold=threshold,
        scores=scores,
        score_counts={key: len(value) for key, value in grouped.items()},
        score_ranges={
            key: (float(np.min(value)), float(np.max(value))) for key, value in grouped.items()
        },
        latency_mean_ms=float(np.mean(latencies)) if len(latencies) > 0 else 0.0,
        latency_p95_ms=float(np.percentile(latencies, 95)) if len(latencies) > 0 else 0.0,
        embedding_dimensions=int(template.shape[0]),
    )


def decode_audio(path: Path) -> DecodedAudio:
    ffmpeg = shutil.which("ffmpeg")
    if ffmpeg is None:
        raise SpectralBaselineError("ffmpeg is required for audio decoding")
    completed = subprocess.run(
        [
            ffmpeg,
            "-v",
            "error",
            "-i",
            str(path),
            "-ac",
            "1",
            "-ar",
            str(SAMPLE_RATE),
            "-f",
            "f32le",
            "pipe:1",
        ],
        check=False,
        capture_output=True,
    )
    if completed.returncode != 0:
        message = completed.stderr.decode("utf-8", errors="replace").strip()
        raise SpectralBaselineError(f"ffmpeg rejected {path.name}: {message}")
    samples = np.frombuffer(completed.stdout, dtype=np.float32)
    if samples.size == 0:
        raise SpectralBaselineError(f"decoded audio is empty: {path.name}")
    finite_samples = np.nan_to_num(samples.astype(np.float64), nan=0.0, posinf=0.0, neginf=0.0)
    return DecodedAudio(samples=finite_samples, sample_rate=SAMPLE_RATE)


def extract_mfcc_stats_embedding(samples: np.ndarray) -> np.ndarray:
    waveform = normalize_waveform(samples)
    frames = frame_waveform(waveform)
    power = power_spectrum(frames)
    with np.errstate(divide="ignore", invalid="ignore", over="ignore"):
        mel_energies = power @ mel_filter_bank(SAMPLE_RATE, FRAME_LENGTH, MEL_BINS).T
    mel_energies = np.nan_to_num(mel_energies, nan=0.0, posinf=0.0, neginf=0.0)
    log_mel = np.log(np.maximum(mel_energies, 1.0e-10))
    with np.errstate(divide="ignore", invalid="ignore", over="ignore"):
        mfcc = log_mel @ dct_matrix(MEL_BINS, MFCC_COEFFICIENTS).T
    mfcc = np.nan_to_num(mfcc, nan=0.0, posinf=0.0, neginf=0.0)
    speaker_mfcc = mfcc[:, 1:MFCC_COEFFICIENTS]
    deltas = delta_features(speaker_mfcc)
    log_energy = np.log(np.maximum(np.sum(frames * frames, axis=1), 1.0e-10)).reshape(-1, 1)
    features = np.hstack([speaker_mfcc, deltas, log_energy])
    embedding = np.concatenate(
        [
            np.mean(features, axis=0),
            np.std(features, axis=0),
            np.percentile(features, 10, axis=0),
            np.percentile(features, 90, axis=0),
        ]
    )
    return normalize_vector(embedding)


def normalize_waveform(samples: np.ndarray) -> np.ndarray:
    if samples.ndim != 1:
        raise SpectralBaselineError("decoded audio must be mono")
    samples = np.nan_to_num(samples, nan=0.0, posinf=0.0, neginf=0.0)
    centered = samples - float(np.mean(samples))
    peak = float(np.max(np.abs(centered))) if centered.size > 0 else 0.0
    if peak <= 1.0e-8:
        raise SpectralBaselineError("decoded audio is silent")
    return centered / peak


def frame_waveform(samples: np.ndarray) -> np.ndarray:
    if samples.size < FRAME_LENGTH:
        padded = np.zeros(FRAME_LENGTH, dtype=np.float64)
        padded[: samples.size] = samples
        samples = padded
    frame_count = 1 + math.ceil((samples.size - FRAME_LENGTH) / FRAME_HOP)
    padded_length = FRAME_LENGTH + (frame_count - 1) * FRAME_HOP
    padded = np.zeros(padded_length, dtype=np.float64)
    padded[: samples.size] = samples
    indices = np.arange(FRAME_LENGTH)[None, :] + FRAME_HOP * np.arange(frame_count)[:, None]
    window = np.hamming(FRAME_LENGTH)
    return padded[indices] * window


def power_spectrum(frames: np.ndarray) -> np.ndarray:
    spectrum = np.fft.rfft(frames, n=FRAME_LENGTH, axis=1)
    power = (np.abs(spectrum) ** 2) / FRAME_LENGTH
    return np.nan_to_num(power, nan=0.0, posinf=0.0, neginf=0.0)


def mel_filter_bank(sample_rate: int, fft_size: int, mel_bins: int) -> np.ndarray:
    low_mel = hz_to_mel(80.0)
    high_mel = hz_to_mel(sample_rate / 2)
    mel_points = np.linspace(low_mel, high_mel, mel_bins + 2)
    hz_points = np.asarray([mel_to_hz(value) for value in mel_points])
    bin_points = np.floor((fft_size + 1) * hz_points / sample_rate).astype(int)
    bin_points = np.clip(bin_points, 0, fft_size // 2)
    filters = np.zeros((mel_bins, fft_size // 2 + 1), dtype=np.float64)
    for index in range(1, mel_bins + 1):
        left = bin_points[index - 1]
        center = max(bin_points[index], left + 1)
        right = max(bin_points[index + 1], center + 1)
        filters[index - 1, left:center] = np.linspace(0.0, 1.0, center - left, endpoint=False)
        filters[index - 1, center:right] = np.linspace(1.0, 0.0, right - center, endpoint=False)
    return filters


def dct_matrix(input_size: int, output_size: int) -> np.ndarray:
    basis = np.zeros((output_size, input_size), dtype=np.float64)
    scale = math.sqrt(2.0 / input_size)
    for output_index in range(output_size):
        for input_index in range(input_size):
            basis[output_index, input_index] = scale * math.cos(
                math.pi * output_index * (input_index + 0.5) / input_size
            )
    basis[0, :] = math.sqrt(1.0 / input_size)
    return basis


def delta_features(features: np.ndarray) -> np.ndarray:
    if features.shape[0] == 1:
        return np.zeros_like(features)
    previous_frames = np.vstack([features[0:1], features[:-1]])
    next_frames = np.vstack([features[1:], features[-1:]])
    return (next_frames - previous_frames) / 2.0


def hz_to_mel(hz: float) -> float:
    return 2595.0 * math.log10(1.0 + hz / 700.0)


def mel_to_hz(mel: float) -> float:
    return 700.0 * (10.0 ** (mel / 2595.0) - 1.0)


def score_entry(
    entry: FixtureManifestEntry,
    embeddings: dict[str, np.ndarray],
    latencies_ms: dict[str, float],
    template: np.ndarray,
) -> FixtureEmbedding:
    embedding = _require_embedding(entry, embeddings)
    return FixtureEmbedding(
        fixture_id=entry.fixture_id,
        expected_relation=entry.expected_relation,
        speaker_label=entry.speaker_label,
        score=cosine_similarity(template, embedding),
        latency_ms=float(latencies_ms.get(entry.fixture_id, 0.0)),
    )


def choose_threshold(scores: tuple[FixtureEmbedding, ...]) -> ThresholdDecision:
    labeled_scores = [
        score
        for score in scores
        if score.expected_relation in {"owner_verification", "different_speaker"}
    ]
    if len(labeled_scores) == 0:
        return ThresholdDecision(
            threshold=0.0,
            true_accepts=0,
            false_rejects=0,
            true_rejects=0,
            false_accepts=0,
        )
    sorted_scores = sorted({score.score for score in labeled_scores})
    candidates = [-1.0, 1.0]
    candidates.extend(sorted_scores)
    candidates.extend(
        (left + right) / 2.0 for left, right in zip(sorted_scores, sorted_scores[1:])
    )
    decisions = [score_threshold(labeled_scores, threshold) for threshold in candidates]
    return max(
        decisions,
        key=lambda decision: (
            decision.true_accepts + decision.true_rejects,
            decision.true_rejects,
            decision.threshold,
        ),
    )


def score_threshold(
    scores: list[FixtureEmbedding],
    threshold: float,
) -> ThresholdDecision:
    true_accepts = 0
    false_rejects = 0
    true_rejects = 0
    false_accepts = 0
    for score in scores:
        accepted = score.score >= threshold
        if score.expected_relation == "owner_verification":
            if accepted:
                true_accepts += 1
            else:
                false_rejects += 1
        elif score.expected_relation == "different_speaker":
            if accepted:
                false_accepts += 1
            else:
                true_rejects += 1
    return ThresholdDecision(
        threshold=threshold,
        true_accepts=true_accepts,
        false_rejects=false_rejects,
        true_rejects=true_rejects,
        false_accepts=false_accepts,
    )


def group_scores_by_relation(
    scores: tuple[FixtureEmbedding, ...],
) -> dict[str, list[float]]:
    grouped: dict[str, list[float]] = {}
    for score in scores:
        grouped.setdefault(score.expected_relation, []).append(score.score)
    return grouped


def cosine_similarity(left: np.ndarray, right: np.ndarray) -> float:
    left_normalized = normalize_vector(left)
    right_normalized = normalize_vector(right)
    return float(np.dot(left_normalized, right_normalized))


def normalize_vector(vector: np.ndarray) -> np.ndarray:
    vector = np.asarray(vector, dtype=np.float64)
    norm = float(np.linalg.norm(vector))
    if norm <= 1.0e-12:
        raise SpectralBaselineError("cannot normalize a zero vector")
    return vector / norm


def report_to_json(report: SpectralBaselineReport) -> dict[str, Any]:
    return {
        "adapterId": report.adapter_id,
        "fixtureCount": len(report.inventory.entries),
        "embeddingDimensions": report.embedding_dimensions,
        "threshold": {
            "value": report.threshold.threshold,
            "trueAccepts": report.threshold.true_accepts,
            "falseRejects": report.threshold.false_rejects,
            "trueRejects": report.threshold.true_rejects,
            "falseAccepts": report.threshold.false_accepts,
        },
        "scoreCounts": report.score_counts,
        "scoreRanges": {
            key: {"min": value[0], "max": value[1]} for key, value in report.score_ranges.items()
        },
        "latency": {
            "meanMs": report.latency_mean_ms,
            "p95Ms": report.latency_p95_ms,
        },
        "scores": [
            {
                "fixtureId": score.fixture_id,
                "expectedRelation": score.expected_relation,
                "speakerLabel": score.speaker_label,
                "score": score.score,
                "latencyMs": score.latency_ms,
            }
            for score in report.scores
        ],
    }


def render_evaluation_report(report: SpectralBaselineReport) -> str:
    lines = [
        "# VoiceID Spectral Baseline Evaluation",
        "",
        "## Scope",
        "",
        f"- Adapter: `{report.adapter_id}`",
        f"- Fixture count: {len(report.inventory.entries)}",
        f"- Embedding dimensions: {report.embedding_dimensions}",
        "- Model class: local MFCC/log-mel statistics baseline",
        "- Purpose: fixture sanity check and threshold-shape exploration before heavier pretrained models",
        "",
        "## Threshold",
        "",
        f"- Selected threshold: {report.threshold.threshold:.4f}",
        f"- True accepts: {report.threshold.true_accepts}",
        f"- False rejects: {report.threshold.false_rejects}",
        f"- True rejects: {report.threshold.true_rejects}",
        f"- False accepts: {report.threshold.false_accepts}",
        "",
        "## Score Ranges",
        "",
    ]
    for relation, (minimum, maximum) in sorted(report.score_ranges.items()):
        lines.append(f"- `{relation}`: {minimum:.4f} to {maximum:.4f} ({report.score_counts[relation]} clips)")
    lines.extend(
        [
            "",
            "## Latency",
            "",
            f"- Mean decode+embedding latency: {report.latency_mean_ms:.1f} ms",
            f"- P95 decode+embedding latency: {report.latency_p95_ms:.1f} ms",
            "",
            "## Per-Fixture Scores",
            "",
            "| Relation | Speaker | Score | Latency ms | Fixture |",
            "| --- | --- | ---: | ---: | --- |",
        ]
    )
    for score in sorted(report.scores, key=lambda item: (item.expected_relation, item.speaker_label, item.fixture_id)):
        lines.append(
            f"| `{score.expected_relation}` | `{score.speaker_label}` | {score.score:.4f} | {score.latency_ms:.1f} | `{score.fixture_id}` |"
        )
    lines.extend(
        [
            "",
            "## Decision",
            "",
            "This baseline is useful for checking fixture wiring and rough score shape. It is not the production speaker-verification model.",
            "Next compare a pretrained ECAPA/x-vector style model against the same manifest and use this report as the floor.",
        ]
    )
    return "\n".join(lines)


def _require_embedding(
    entry: FixtureManifestEntry,
    embeddings: dict[str, np.ndarray],
) -> np.ndarray:
    embedding = embeddings.get(entry.fixture_id)
    if embedding is None:
        raise SpectralBaselineError(f"missing embedding for fixture {entry.fixture_id}")
    return normalize_vector(embedding)


def main() -> None:
    parser = argparse.ArgumentParser(description="Evaluate a local spectral VoiceID baseline.")
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--json", action="store_true", help="Print JSON instead of Markdown.")
    parser.add_argument(
        "--check-media",
        action="store_true",
        help="Run ffprobe audio-stream checks before evaluation.",
    )
    args = parser.parse_args()
    inventory = load_fixture_inventory(args.manifest, check_media=args.check_media)
    report = evaluate_spectral_baseline(inventory)
    if args.json:
        print(json.dumps(report_to_json(report), indent=2))
    else:
        print(render_evaluation_report(report))


if __name__ == "__main__":
    main()
