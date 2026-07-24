from __future__ import annotations

import argparse
import json
import statistics
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any


VERIFIER_ROOT = Path(__file__).resolve().parents[1] / "verifier"
if str(VERIFIER_ROOT) not in sys.path:
    sys.path.insert(0, str(VERIFIER_ROOT))

from benchmark import BenchmarkManifest, build_inventory_report, load_benchmark_manifest  # noqa: E402
from voiceid_verifier.audio_decode import decode_audio_bytes  # noqa: E402
from voiceid_verifier.moonshine import MoonshineRecognizer  # noqa: E402


REPORT_SCHEMA_VERSION = "voice_id_moonshine_benchmark_v1"


@dataclass(frozen=True)
class MoonshineFixtureResult:
    fixture_id: str
    partition: str
    cohort: str
    latency_ms: float
    phrase_kind: str
    intent_kind: str
    transcript: str


def run_benchmark(
    manifest: BenchmarkManifest,
    *,
    model_path: Path,
    model_arch: str,
    intent_model_path: Path,
) -> dict[str, Any]:
    load_started = time.perf_counter()
    recognizer = MoonshineRecognizer(
        model_path=str(model_path),
        model_arch=model_arch,
        intent_model_path=str(intent_model_path),
    )
    load_latency_ms = elapsed_ms(load_started)
    results = tuple(
        evaluate_entry(entry, recognizer)
        for entry in manifest.entries
        if entry.case.kind != "enrollment" and len(entry.challenge_tokens) > 0
    )
    if len(results) == 0:
        raise ValueError("benchmark manifest contains no verification entries with challenge tokens")
    latencies = [result.latency_ms for result in results]
    inventory = build_inventory_report(manifest)
    return {
        "schemaVersion": REPORT_SCHEMA_VERSION,
        "datasetVersion": manifest.dataset_version,
        "modelArch": model_arch,
        "fixtureCount": len(results),
        "modelLoadMs": round(load_latency_ms, 3),
        "latencyMs": latency_summary(latencies),
        "phraseCounts": count(result.phrase_kind for result in results),
        "intentCounts": count(result.intent_kind for result in results),
        "cohortCounts": inventory.cohort_counts,
        "syntheticImpostorCount": inventory.synthetic_impostor_count,
        "syntheticAttackClassCounts": inventory.synthetic_attack_class_counts,
        "humanMetricsEligible": inventory.human_metrics_eligible,
        "humanMetricsSuppressionReason": inventory.human_metrics_suppression_reason,
        "results": [result_to_json(result) for result in results],
    }


def evaluate_entry(entry: Any, recognizer: MoonshineRecognizer) -> MoonshineFixtureResult:
    decoded = decode_audio_bytes(entry.audio_path.read_bytes())
    expected_phrase = " ".join(entry.challenge_tokens)
    intent_name = entry.expected_intent or "unrelated"
    started = time.perf_counter()
    analysis = recognizer.analyze(
        decoded.samples,
        expected_phrase=expected_phrase,
        intent_name=intent_name,
    )
    latency_ms = elapsed_ms(started)
    return MoonshineFixtureResult(
        fixture_id=entry.fixture_id,
        partition=entry.partition,
        cohort=entry_cohort(entry),
        latency_ms=latency_ms,
        phrase_kind=analysis.phrase.kind,
        intent_kind=analysis.intent.kind,
        transcript=analysis.transcript,
    )


def render_report(report: dict[str, Any]) -> str:
    latency = report["latencyMs"]
    return "\n".join(
        [
            "# Moonshine Phrase/Intent Benchmark",
            "",
            f"- Dataset: `{report['datasetVersion']}`",
            f"- Model architecture: `{report['modelArch']}`",
            f"- Fixtures: {report['fixtureCount']}",
            f"- Model load: {report['modelLoadMs']} ms",
            f"- Warm latency p50/p95/p99: {latency['p50']} / {latency['p95']} / {latency['p99']} ms",
            f"- Phrase outcomes: {format_counts(report['phraseCounts'])}",
            f"- Intent outcomes: {format_counts(report['intentCounts'])}",
            f"- Cohorts: {format_counts(report['cohortCounts'])}",
            f"- Synthetic impostors: {report['syntheticImpostorCount']}",
            f"- Synthetic attack classes: {format_counts(report['syntheticAttackClassCounts'])}",
            (
                "- Human FAR/FRR/EER: eligible"
                if report["humanMetricsEligible"]
                else f"- Human FAR/FRR/EER: suppressed ({report['humanMetricsSuppressionReason']})"
            ),
            "",
            "This report is a model-selection measurement. It does not establish human",
            "FAR, FRR, or EER and must remain paired with the provenance-safe inventory report.",
        ]
    )


def result_to_json(result: MoonshineFixtureResult) -> dict[str, Any]:
    return {
        "fixtureId": result.fixture_id,
        "partition": result.partition,
        "cohort": result.cohort,
        "latencyMs": round(result.latency_ms, 3),
        "phraseKind": result.phrase_kind,
        "intentKind": result.intent_kind,
        "transcript": result.transcript,
    }


def latency_summary(values: list[float]) -> dict[str, float]:
    ordered = sorted(values)
    return {
        "p50": round(percentile(ordered, 0.50), 3),
        "p95": round(percentile(ordered, 0.95), 3),
        "p99": round(percentile(ordered, 0.99), 3),
        "min": round(ordered[0], 3),
        "max": round(ordered[-1], 3),
        "mean": round(statistics.fmean(ordered), 3),
    }


def percentile(values: list[float], quantile: float) -> float:
    if len(values) == 1:
        return values[0]
    position = (len(values) - 1) * quantile
    lower = int(position)
    upper = min(lower + 1, len(values) - 1)
    fraction = position - lower
    return values[lower] + (values[upper] - values[lower]) * fraction


def count(values: Any) -> dict[str, int]:
    counts: dict[str, int] = {}
    for value in values:
        counts[value] = counts.get(value, 0) + 1
    return dict(sorted(counts.items()))


def entry_cohort(entry: Any) -> str:
    if entry.provenance.kind == "consented_human_capture":
        return "real_human"
    if entry.provenance.conditioning is not None:
        return "owner_conditioned_clone"
    return "fictional_synthetic"


def format_counts(values: dict[str, int]) -> str:
    return ", ".join(f"`{key}`={value}" for key, value in values.items()) or "none"


def elapsed_ms(started: float) -> float:
    return (time.perf_counter() - started) * 1000.0


def main() -> None:
    parser = argparse.ArgumentParser(description="Benchmark Moonshine over a v2 VoiceID benchmark manifest")
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--model-path", type=Path, required=True)
    parser.add_argument("--model-arch", choices=("tiny_streaming", "small_streaming"), required=True)
    parser.add_argument("--intent-model-path", type=Path, required=True)
    parser.add_argument("--json-out", type=Path, required=True)
    parser.add_argument("--report-out", type=Path, required=True)
    args = parser.parse_args()
    report = run_benchmark(
        load_benchmark_manifest(args.manifest),
        model_path=args.model_path,
        model_arch=args.model_arch,
        intent_model_path=args.intent_model_path,
    )
    args.json_out.parent.mkdir(parents=True, exist_ok=True)
    args.report_out.parent.mkdir(parents=True, exist_ok=True)
    args.json_out.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    args.report_out.write_text(render_report(report) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
