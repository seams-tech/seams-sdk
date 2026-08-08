from __future__ import annotations

import argparse
import json
import os
import platform
import resource
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
from voiceid_verifier.moonshine import normalize_transcript  # noqa: E402


REPORT_SCHEMA_VERSION = "voice_id_moonshine_benchmark_v2"


@dataclass(frozen=True)
class MoonshineFixtureResult:
    fixture_id: str
    partition: str
    cohort: str
    decode_ms: float
    phrase_intent_ms: float
    total_ms: float
    cpu_ms: float
    case_kind: str
    challenge_error_kind: str | None
    expected_phrase_kind: str
    exact_phrase_kind: str
    hybrid_phrase_kind: str
    intent_kind: str
    expected_intent: str
    matched_intent: str | None
    intent_confidence: float
    runner_up_intent: str | None
    runner_up_confidence: float
    transcript: str
    failure: str | None


def run_benchmark(
    manifest: BenchmarkManifest,
    *,
    model_path: Path,
    model_arch: str,
    intent_model_path: Path,
    intent_threshold: float = 0.0,
    intent_margin: float = 0.0,
) -> dict[str, Any]:
    benchmark_wall_started = time.perf_counter()
    benchmark_cpu_started = time.process_time()
    peak_rss_before = peak_rss_bytes()
    load_started = time.perf_counter()
    recognizer = MoonshineRecognizer(
        model_path=str(model_path),
        model_arch=model_arch,
        intent_model_path=str(intent_model_path),
        intent_threshold=intent_threshold,
        intent_margin=intent_margin,
    )
    load_latency_ms = elapsed_ms(load_started)
    results = tuple(
        evaluate_entry(entry, recognizer)
        for entry in manifest.entries
        if entry.case.kind != "enrollment" and len(entry.challenge_tokens) > 0
    )
    if len(results) == 0:
        raise ValueError("benchmark manifest contains no verification entries with challenge tokens")
    benchmark_wall_ms = elapsed_ms(benchmark_wall_started)
    benchmark_cpu_ms = elapsed_cpu_ms(benchmark_cpu_started)
    failures = [result for result in results if result.failure is not None]
    uncertain_results = [
        result
        for result in results
        if result.hybrid_phrase_kind == "uncertain" or result.intent_kind == "uncertain"
    ]
    inventory = build_inventory_report(manifest)
    return {
        "schemaVersion": REPORT_SCHEMA_VERSION,
        "datasetVersion": manifest.dataset_version,
        "modelArch": model_arch,
        "intentThreshold": intent_threshold,
        "intentMargin": intent_margin,
        "fixtureCount": len(results),
        "modelLoadMs": round(load_latency_ms, 3),
        "stageLatencyMs": {
            "decode": latency_summary([result.decode_ms for result in results]),
            "phraseIntent": latency_summary([result.phrase_intent_ms for result in results]),
            "complete": latency_summary([result.total_ms for result in results]),
        },
        "resources": {
            "benchmarkWallMs": round(benchmark_wall_ms, 3),
            "processCpuMs": round(benchmark_cpu_ms, 3),
            "processCpuUtilizationPercent": round(
                benchmark_cpu_ms / benchmark_wall_ms * 100 if benchmark_wall_ms > 0 else 0,
                3,
            ),
            "peakRssBytes": max(peak_rss_before, peak_rss_bytes()),
            "logicalCpuCount": os.cpu_count() or 1,
            "platform": platform.system().lower(),
            "architecture": platform.machine().lower(),
        },
        "failureCount": len(failures),
        "failureRate": round(len(failures) / len(results), 6),
        "retryCount": len(uncertain_results) + len(failures),
        "retryRate": round((len(uncertain_results) + len(failures)) / len(results), 6),
        "exactPhraseCounts": count(result.exact_phrase_kind for result in results),
        "hybridPhraseCounts": count(result.hybrid_phrase_kind for result in results),
        "exactPhraseAccuracy": decision_accuracy(
            (result.exact_phrase_kind, result.expected_phrase_kind)
            for result in results
        ),
        "hybridPhraseAccuracy": decision_accuracy(
            (result.hybrid_phrase_kind, result.expected_phrase_kind)
            for result in results
        ),
        "intentCounts": count(result.intent_kind for result in results),
        "cohortCounts": inventory.cohort_counts,
        "syntheticImpostorCount": inventory.synthetic_impostor_count,
        "syntheticAttackClassCounts": inventory.synthetic_attack_class_counts,
        "humanMetricsEligible": inventory.human_metrics_eligible,
        "humanMetricsSuppressionReason": inventory.human_metrics_suppression_reason,
        "results": [result_to_json(result) for result in results],
    }


def evaluate_entry(entry: Any, recognizer: MoonshineRecognizer) -> MoonshineFixtureResult:
    total_started = time.perf_counter()
    cpu_started = time.process_time()
    decode_started = time.perf_counter()
    try:
        decoded = decode_audio_bytes(entry.audio_path.read_bytes())
    except Exception as error:
        return failed_fixture_result(
            entry=entry,
            decode_ms=elapsed_ms(decode_started),
            total_ms=elapsed_ms(total_started),
            cpu_ms=elapsed_cpu_ms(cpu_started),
            error=error,
        )
    decode_ms = elapsed_ms(decode_started)
    expected_phrase = expected_phrase_for_entry(entry)
    intent_name = entry.expected_intent or "unrelated"
    phrase_intent_started = time.perf_counter()
    try:
        analysis = recognizer.analyze(
            decoded.samples,
            expected_phrase=expected_phrase,
            intent_name=intent_name,
            challenge_tokens=entry.challenge_tokens,
        )
        phrase_intent_ms = elapsed_ms(phrase_intent_started)
        exact_phrase_kind = (
            "accepted"
            if normalize_transcript(analysis.transcript)
            == normalize_transcript(expected_phrase)
            else "rejected"
        )
        return MoonshineFixtureResult(
            fixture_id=entry.fixture_id,
            partition=entry.partition,
            cohort=entry_cohort(entry),
            decode_ms=decode_ms,
            phrase_intent_ms=phrase_intent_ms,
            total_ms=elapsed_ms(total_started),
            cpu_ms=elapsed_cpu_ms(cpu_started),
            case_kind=entry.case.kind,
            challenge_error_kind=entry.case.challenge_error_kind,
            expected_phrase_kind=expected_phrase_decision(entry),
            exact_phrase_kind=exact_phrase_kind,
            hybrid_phrase_kind=analysis.phrase.kind,
            intent_kind=analysis.intent.kind,
            expected_intent=intent_name,
            matched_intent=analysis.intent.intent,
            intent_confidence=analysis.intent.confidence,
            runner_up_intent=analysis.intent.runner_up_intent,
            runner_up_confidence=analysis.intent.runner_up_confidence,
            transcript=analysis.transcript,
            failure=None,
        )
    except Exception as error:
        return failed_fixture_result(
            entry=entry,
            decode_ms=decode_ms,
            phrase_intent_ms=elapsed_ms(phrase_intent_started),
            total_ms=elapsed_ms(total_started),
            cpu_ms=elapsed_cpu_ms(cpu_started),
            error=error,
        )
    finally:
        for index in range(len(decoded.samples)):
            decoded.samples[index] = 0.0


def failed_fixture_result(
    *,
    entry: Any,
    decode_ms: float,
    total_ms: float,
    cpu_ms: float,
    error: Exception,
    phrase_intent_ms: float = 0.0,
) -> MoonshineFixtureResult:
    return MoonshineFixtureResult(
        fixture_id=entry.fixture_id,
        partition=entry.partition,
        cohort=entry_cohort(entry),
        decode_ms=decode_ms,
        phrase_intent_ms=phrase_intent_ms,
        total_ms=total_ms,
        cpu_ms=cpu_ms,
        case_kind=entry.case.kind,
        challenge_error_kind=entry.case.challenge_error_kind,
        expected_phrase_kind=expected_phrase_decision(entry),
        exact_phrase_kind="failed",
        hybrid_phrase_kind="failed",
        intent_kind="failed",
        expected_intent=entry.expected_intent or "unrelated",
        matched_intent=None,
        intent_confidence=0.0,
        runner_up_intent=None,
        runner_up_confidence=0.0,
        transcript="",
        failure=type(error).__name__,
    )


def expected_phrase_for_entry(entry: Any) -> str:
    intent_phrases = {
        "approve": "approve this request",
        "reject": "reject this request",
        "cancel": "cancel this request",
        "repeat": "repeat the challenge",
        "unrelated": "unrelated",
    }
    intent_phrase = intent_phrases.get(entry.expected_intent or "unrelated", "unrelated")
    return f"{intent_phrase} {' '.join(entry.challenge_tokens)}"


def expected_phrase_decision(entry: Any) -> str:
    if entry.case.kind != "challenge_error":
        return "accepted"
    if entry.case.challenge_error_kind == "reordering":
        return "accepted"
    return "rejected"


def render_report(report: dict[str, Any]) -> str:
    stage_latency = report["stageLatencyMs"]
    resources = report["resources"]
    return "\n".join(
        [
            "# Moonshine Phrase/Intent Benchmark",
            "",
            f"- Dataset: `{report['datasetVersion']}`",
            f"- Model architecture: `{report['modelArch']}`",
            f"- Fixtures: {report['fixtureCount']}",
            f"- Model load: {report['modelLoadMs']} ms",
            format_latency_line("Decode", stage_latency["decode"]),
            format_latency_line("Phrase + intent", stage_latency["phraseIntent"]),
            format_latency_line("Complete", stage_latency["complete"]),
            f"- Peak RSS: {resources['peakRssBytes']} bytes",
            f"- Process CPU utilization: {resources['processCpuUtilizationPercent']}%",
            f"- Failures: {report['failureCount']} ({report['failureRate']:.2%})",
            f"- Retries: {report['retryCount']} ({report['retryRate']:.2%})",
            f"- Exact phrase outcomes: {format_counts(report['exactPhraseCounts'])}",
            f"- Hybrid phrase outcomes: {format_counts(report['hybridPhraseCounts'])}",
            f"- Exact phrase accuracy: {report['exactPhraseAccuracy']:.2%}",
            f"- Hybrid phrase accuracy: {report['hybridPhraseAccuracy']:.2%}",
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
        "stageLatencyMs": {
            "decode": round(result.decode_ms, 3),
            "phraseIntent": round(result.phrase_intent_ms, 3),
            "complete": round(result.total_ms, 3),
        },
        "cpuMs": round(result.cpu_ms, 3),
        "caseKind": result.case_kind,
        "challengeErrorKind": result.challenge_error_kind,
        "expectedPhraseKind": result.expected_phrase_kind,
        "exactPhraseKind": result.exact_phrase_kind,
        "hybridPhraseKind": result.hybrid_phrase_kind,
        "intentKind": result.intent_kind,
        "expectedIntent": result.expected_intent,
        "matchedIntent": result.matched_intent,
        "intentConfidence": round(result.intent_confidence, 6),
        "runnerUpIntent": result.runner_up_intent,
        "runnerUpConfidence": round(result.runner_up_confidence, 6),
        "transcript": result.transcript,
        "failure": result.failure,
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


def decision_accuracy(decisions: Any) -> float:
    values = tuple(decisions)
    if len(values) == 0:
        return 0.0
    correct = sum(actual == expected for actual, expected in values)
    return round(correct / len(values), 6)


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


def elapsed_cpu_ms(started: float) -> float:
    return (time.process_time() - started) * 1000.0


def peak_rss_bytes() -> int:
    maximum_rss = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    return maximum_rss if sys.platform == "darwin" else maximum_rss * 1024


def format_latency_line(name: str, latency: dict[str, float]) -> str:
    return (
        f"- {name} p50/p95/p99: "
        f"{latency['p50']} / {latency['p95']} / {latency['p99']} ms"
    )


def main() -> None:
    parser = argparse.ArgumentParser(description="Benchmark Moonshine over a v2 VoiceID benchmark manifest")
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--model-path", type=Path, required=True)
    parser.add_argument("--model-arch", choices=("tiny_streaming", "small_streaming"), required=True)
    parser.add_argument("--intent-model-path", type=Path, required=True)
    parser.add_argument("--intent-threshold", type=float, default=0.0)
    parser.add_argument("--intent-margin", type=float, default=0.0)
    parser.add_argument("--json-out", type=Path, required=True)
    parser.add_argument("--report-out", type=Path, required=True)
    args = parser.parse_args()
    report = run_benchmark(
        load_benchmark_manifest(args.manifest),
        model_path=args.model_path,
        model_arch=args.model_arch,
        intent_model_path=args.intent_model_path,
        intent_threshold=args.intent_threshold,
        intent_margin=args.intent_margin,
    )
    args.json_out.parent.mkdir(parents=True, exist_ok=True)
    args.report_out.parent.mkdir(parents=True, exist_ok=True)
    args.json_out.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    args.report_out.write_text(render_report(report) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
