from __future__ import annotations

import argparse
import json
import resource
import sys
import time
from collections import defaultdict
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Literal


VERIFIER_ROOT = Path(__file__).resolve().parents[1] / "verifier"
if str(VERIFIER_ROOT) not in sys.path:
    sys.path.insert(0, str(VERIFIER_ROOT))

from benchmark import BenchmarkEntry, BenchmarkManifest, load_benchmark_manifest  # noqa: E402
from evaluate_pad import RateEstimate, rate_estimate  # noqa: E402
from voiceid_verifier.audio_decode import zero_float_sequence  # noqa: E402
from voiceid_verifier.runtime import (  # noqa: E402
    AudioClaims,
    SpeechBrainEcapaVerifierRuntime,
)
from voiceid_verifier.scoring import cosine_score  # noqa: E402


REPORT_SCHEMA_VERSION = "voice_id_ecapa_benchmark_v1"


class EcapaBenchmarkError(RuntimeError):
    pass


@dataclass(frozen=True)
class SpeakerObservation:
    fixture_id: str
    partition: str
    case_kind: str
    attack_class: str | None
    expected_kind: Literal["accepted", "rejected", "attack"]
    score: float
    latency_ms: float


@dataclass(frozen=True)
class SpeakerMetrics:
    threshold: float
    false_acceptance: RateEstimate
    false_rejection: RateEstimate
    equal_error_rate: float


def run_benchmark(
    manifest: BenchmarkManifest,
    *,
    runtime: SpeechBrainEcapaVerifierRuntime,
    model_load_ms: float,
) -> dict[str, Any]:
    templates = build_templates(manifest, runtime)
    try:
        observations = tuple(
            score_entry(entry, templates=templates, runtime=runtime)
            for entry in manifest.entries
            if entry.case.kind != "enrollment"
        )
        calibration = tuple(
            observation
            for observation in observations
            if observation.partition == "calibration"
            and observation.expected_kind in {"accepted", "rejected"}
        )
        threshold = calibrate_threshold(calibration)
        evaluation = tuple(
            observation
            for observation in observations
            if observation.partition == "evaluation"
            and observation.expected_kind in {"accepted", "rejected"}
        )
        metrics = evaluate_threshold(evaluation, threshold)
        attacks = tuple(
            observation
            for observation in observations
            if observation.partition == "evaluation"
            and observation.expected_kind == "attack"
        )
        return {
            "schemaVersion": REPORT_SCHEMA_VERSION,
            "datasetVersion": manifest.dataset_version,
            "modelVersion": runtime.metadata.model_version,
            "modelLoadMs": round(model_load_ms, 3),
            "threshold": threshold,
            "calibration": metrics_to_json(evaluate_threshold(calibration, threshold)),
            "evaluation": metrics_to_json(metrics),
            "attackAcceptanceByClass": attack_acceptance_by_class(attacks, threshold),
            "latencyMs": latency_summary(
                [observation.latency_ms for observation in observations]
            ),
            "peakRssBytes": peak_rss_bytes(),
            "results": [observation_to_json(observation) for observation in observations],
        }
    finally:
        for template in templates.values():
            zero_float_sequence(template)


def build_templates(
    manifest: BenchmarkManifest,
    runtime: SpeechBrainEcapaVerifierRuntime,
) -> dict[tuple[str, str], list[float]]:
    grouped: dict[tuple[str, str], list[list[float]]] = defaultdict(list)
    for entry in manifest.entries:
        if entry.case.kind != "enrollment":
            continue
        embedding, _ = extract_embedding(entry, runtime)
        grouped[(entry.subject_id, entry.partition)].append(embedding)
    templates = {}
    for key, embeddings in grouped.items():
        templates[key] = normalized_mean(embeddings)
        for embedding in embeddings:
            zero_float_sequence(embedding)
    return templates


def score_entry(
    entry: BenchmarkEntry,
    *,
    templates: dict[tuple[str, str], list[float]],
    runtime: SpeechBrainEcapaVerifierRuntime,
) -> SpeakerObservation:
    target_subject_id = entry.case.target_subject_id or entry.subject_id
    template = templates.get((target_subject_id, entry.partition))
    if template is None:
        raise EcapaBenchmarkError(
            f"fixture {entry.fixture_id} has no partition-local target template"
        )
    embedding, latency_ms = extract_embedding(entry, runtime)
    try:
        score = cosine_score(template, embedding)
    finally:
        zero_float_sequence(embedding)
    return SpeakerObservation(
        fixture_id=entry.fixture_id,
        partition=entry.partition,
        case_kind=entry.case.kind,
        attack_class=entry.case.attack_class,
        expected_kind=expected_speaker_kind(entry),
        score=score,
        latency_ms=latency_ms,
    )


def extract_embedding(
    entry: BenchmarkEntry,
    runtime: SpeechBrainEcapaVerifierRuntime,
) -> tuple[list[float], float]:
    audio_bytes = entry.audio_path.read_bytes()
    evaluated = runtime.evaluate_audio(
        audio_bytes,
        AudioClaims(
            mime_type=entry.mime_type,
            duration_ms=entry.duration_ms,
            sample_rate_hz=entry.capture.sample_rate_hz,
            channel_count=entry.capture.channel_count,
        ),
    )
    try:
        if evaluated.quality.kind != "accepted":
            raise EcapaBenchmarkError(
                f"fixture {entry.fixture_id} failed common audio quality gates"
            )
        started = time.perf_counter()
        embedding = runtime.extract_verification_embedding(
            evaluated.speech_windows
        ).vector
        return embedding, (time.perf_counter() - started) * 1000
    finally:
        if evaluated.decoded_audio is not None:
            zero_float_sequence(evaluated.decoded_audio.samples)
        for window in evaluated.speech_windows:
            zero_float_sequence(window.samples)


def expected_speaker_kind(
    entry: BenchmarkEntry,
) -> Literal["accepted", "rejected", "attack"]:
    if entry.case.kind == "zero_effort_impostor":
        return "rejected"
    if entry.case.kind == "presentation_attack":
        return "attack"
    return "accepted"


def calibrate_threshold(
    observations: tuple[SpeakerObservation, ...],
) -> float:
    genuine = tuple(
        observation for observation in observations if observation.expected_kind == "accepted"
    )
    impostors = tuple(
        observation for observation in observations if observation.expected_kind == "rejected"
    )
    if len(genuine) == 0 or len(impostors) == 0:
        raise EcapaBenchmarkError(
            "calibration requires genuine and zero-effort impostor observations"
        )
    scores = sorted({observation.score for observation in observations})
    candidates = [-1.0, 1.0]
    candidates.extend(scores)
    candidates.extend(
        (left + right) / 2 for left, right in zip(scores, scores[1:])
    )
    return min(
        candidates,
        key=lambda threshold: calibration_key(
            genuine,
            impostors,
            threshold,
        ),
    )


def calibration_key(
    genuine: tuple[SpeakerObservation, ...],
    impostors: tuple[SpeakerObservation, ...],
    threshold: float,
) -> tuple[float, float, float]:
    false_rejection = sum(item.score < threshold for item in genuine) / len(genuine)
    false_acceptance = sum(item.score >= threshold for item in impostors) / len(impostors)
    separation_margin = min(
        min(item.score for item in genuine) - threshold,
        threshold - max(item.score for item in impostors),
    )
    return (
        abs(false_acceptance - false_rejection),
        false_acceptance + false_rejection,
        -separation_margin,
    )


def evaluate_threshold(
    observations: tuple[SpeakerObservation, ...],
    threshold: float,
) -> SpeakerMetrics:
    genuine = tuple(
        observation for observation in observations if observation.expected_kind == "accepted"
    )
    impostors = tuple(
        observation for observation in observations if observation.expected_kind == "rejected"
    )
    if len(genuine) == 0 or len(impostors) == 0:
        raise EcapaBenchmarkError(
            "speaker metrics require genuine and zero-effort impostor observations"
        )
    false_rejection = rate_estimate(
        sum(observation.score < threshold for observation in genuine),
        len(genuine),
    )
    false_acceptance = rate_estimate(
        sum(observation.score >= threshold for observation in impostors),
        len(impostors),
    )
    return SpeakerMetrics(
        threshold=threshold,
        false_acceptance=false_acceptance,
        false_rejection=false_rejection,
        equal_error_rate=round(
            (false_acceptance.rate + false_rejection.rate) / 2,
            6,
        ),
    )


def attack_acceptance_by_class(
    attacks: tuple[SpeakerObservation, ...],
    threshold: float,
) -> dict[str, dict[str, Any]]:
    grouped: dict[str, list[SpeakerObservation]] = defaultdict(list)
    for attack in attacks:
        if attack.attack_class is None:
            raise EcapaBenchmarkError("presentation attack requires attack class")
        grouped[attack.attack_class].append(attack)
    return {
        attack_class: asdict(
            rate_estimate(
                sum(observation.score >= threshold for observation in observations),
                len(observations),
            )
        )
        for attack_class, observations in sorted(grouped.items())
    }


def normalized_mean(embeddings: list[list[float]]) -> list[float]:
    if len(embeddings) == 0:
        raise EcapaBenchmarkError("template requires embeddings")
    dimensions = len(embeddings[0])
    if dimensions == 0 or any(len(vector) != dimensions for vector in embeddings):
        raise EcapaBenchmarkError("template embedding dimensions are inconsistent")
    mean = [
        sum(vector[index] for vector in embeddings) / len(embeddings)
        for index in range(dimensions)
    ]
    magnitude = sum(value * value for value in mean) ** 0.5
    if magnitude == 0:
        raise EcapaBenchmarkError("template embedding magnitude is zero")
    return [value / magnitude for value in mean]


def metrics_to_json(metrics: SpeakerMetrics) -> dict[str, Any]:
    return {
        "threshold": metrics.threshold,
        "far": asdict(metrics.false_acceptance),
        "frr": asdict(metrics.false_rejection),
        "eer": metrics.equal_error_rate,
    }


def observation_to_json(observation: SpeakerObservation) -> dict[str, Any]:
    return {
        "fixtureId": observation.fixture_id,
        "partition": observation.partition,
        "caseKind": observation.case_kind,
        "attackClass": observation.attack_class,
        "expectedKind": observation.expected_kind,
        "score": round(observation.score, 6),
        "latencyMs": round(observation.latency_ms, 3),
    }


def latency_summary(values: list[float]) -> dict[str, float]:
    if len(values) == 0:
        raise EcapaBenchmarkError("latency summary requires observations")
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


def peak_rss_bytes() -> int:
    maximum_rss = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    return maximum_rss if sys.platform == "darwin" else maximum_rss * 1024


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Benchmark ECAPA speaker verification over a frozen VoiceID corpus."
    )
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    load_started = time.perf_counter()
    runtime = SpeechBrainEcapaVerifierRuntime()
    model_load_ms = (time.perf_counter() - load_started) * 1000
    report = run_benchmark(
        load_benchmark_manifest(args.manifest),
        runtime=runtime,
        model_load_ms=model_load_ms,
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
