from __future__ import annotations

import argparse
import hashlib
import json
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from benchmark import (
    build_inventory_report,
    load_benchmark_manifest,
    report_to_json as inventory_to_json,
)
from benchmark_aasist import benchmark_aasist
from benchmark_ecapa import run_benchmark as run_ecapa_benchmark
from benchmark_moonshine import run_benchmark as run_moonshine_benchmark
from model_manifest import build_manifest as build_model_manifest
from voiceid_verifier.embeddings import SpeechBrainEcapaEmbeddingExtractor
from voiceid_verifier.runtime import SpeechBrainEcapaVerifierRuntime


REPORT_SCHEMA_VERSION = "voice_id_benchmark_suite_v1"


def run_benchmark_suite(
    *,
    corpus_manifest_path: Path,
    model_manifest_path: Path,
    model_root: Path,
    moonshine_model_arch: str,
    aasist_device: str,
    target_apcer: float,
    target_bpcer: float,
) -> dict[str, Any]:
    verify_model_manifest(model_root, model_manifest_path)
    manifest = load_benchmark_manifest(corpus_manifest_path)
    inventory = inventory_to_json(build_inventory_report(manifest))
    moonshine_model_path = (
        model_root / "moonshine" / "tiny"
        if moonshine_model_arch == "tiny_streaming"
        else model_root / "moonshine" / "small"
    )
    moonshine = run_moonshine_benchmark(
        manifest,
        model_path=moonshine_model_path,
        model_arch=moonshine_model_arch,
        intent_model_path=model_root / "moonshine" / "intent",
    )
    ecapa_load_started = time.perf_counter()
    ecapa_runtime = SpeechBrainEcapaVerifierRuntime(
        extractor=SpeechBrainEcapaEmbeddingExtractor(savedir=model_root / "ecapa")
    )
    ecapa_load_ms = (time.perf_counter() - ecapa_load_started) * 1000
    ecapa = run_ecapa_benchmark(
        manifest,
        runtime=ecapa_runtime,
        model_load_ms=ecapa_load_ms,
    )
    aasist_raw, aasist_evaluation = benchmark_aasist(
        benchmark_manifest_path=corpus_manifest_path,
        source_path=model_root / "aasist" / "AASIST.py",
        checkpoint_path=model_root / "aasist" / "AASIST.pth",
        config_path=model_root / "aasist" / "AASIST.conf",
        device_name=aasist_device,
        target_apcer=target_apcer,
        target_bpcer=target_bpcer,
    )
    return {
        "schemaVersion": REPORT_SCHEMA_VERSION,
        "generatedAt": datetime.now(UTC).isoformat(),
        "datasetVersion": manifest.dataset_version,
        "corpusManifestSha256": sha256_file(corpus_manifest_path),
        "modelManifestSha256": sha256_file(model_manifest_path),
        "inventory": inventory,
        "moonshine": moonshine,
        "ecapa": ecapa,
        "aasist": {
            "raw": aasist_raw,
            "evaluation": aasist_evaluation,
        },
    }


def render_benchmark_suite(report: dict[str, Any]) -> str:
    inventory = report["inventory"]
    moonshine = report["moonshine"]
    ecapa = report["ecapa"]
    aasist = report["aasist"]["evaluation"]
    moonshine_latency = moonshine["stageLatencyMs"]["complete"]
    ecapa_latency = ecapa["latencyMs"]
    pad_latency = aasist["latencyMs"]
    return "\n".join(
        (
            "# VoiceID Benchmark Suite",
            "",
            f"- Dataset: `{report['datasetVersion']}`",
            f"- Corpus manifest SHA-256: `{report['corpusManifestSha256']}`",
            f"- Model manifest SHA-256: `{report['modelManifestSha256']}`",
            f"- Fixtures: {inventory['fixtureCount']}",
            f"- Measurement ready: `{str(inventory['measurementReady']).lower()}`",
            (
                "- Human FAR/FRR/EER eligible: "
                f"`{str(inventory['humanMetricsEligible']).lower()}`"
            ),
            "",
            "## Moonshine",
            "",
            (
                "- Complete p50/p95/p99: "
                f"{moonshine_latency['p50']} / {moonshine_latency['p95']} / "
                f"{moonshine_latency['p99']} ms"
            ),
            f"- Hybrid phrase accuracy: {moonshine['hybridPhraseAccuracy']:.2%}",
            f"- Retry rate: {moonshine['retryRate']:.2%}",
            "",
            "## ECAPA",
            "",
            (
                "- Inference p50/p95/p99: "
                f"{ecapa_latency['p50']} / {ecapa_latency['p95']} / "
                f"{ecapa_latency['p99']} ms"
            ),
            f"- Evaluation FAR: {ecapa['evaluation']['far']['rate']:.2%}",
            f"- Evaluation FRR: {ecapa['evaluation']['frr']['rate']:.2%}",
            f"- Evaluation EER: {ecapa['evaluation']['eer']:.2%}",
            "",
            "## AASIST PAD",
            "",
            (
                "- Inference p50/p95/p99: "
                f"{pad_latency['p50']} / {pad_latency['p95']} / "
                f"{pad_latency['p99']} ms"
            ),
            f"- APCER: {aasist['apcer']['rate']:.2%}",
            f"- BPCER: {aasist['bpcer']['rate']:.2%}",
            f"- Uncertainty: {aasist['uncertainty']['rate']:.2%}",
            "",
            "Synthetic-cohort results are pipeline evidence. Human population",
            "claims remain suppressed unless the inventory marks them eligible.",
        )
    )


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def verify_model_manifest(model_root: Path, manifest_path: Path) -> None:
    expected = json.loads(manifest_path.read_text(encoding="utf-8"))
    if build_model_manifest(model_root) != expected:
        raise ValueError("local model tree does not match the immutable model manifest")


def write_reports(
    *,
    report: dict[str, Any],
    json_path: Path,
    markdown_path: Path,
) -> None:
    json_path.parent.mkdir(parents=True, exist_ok=True)
    markdown_path.parent.mkdir(parents=True, exist_ok=True)
    json_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    markdown_path.write_text(render_benchmark_suite(report) + "\n", encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Run the complete VoiceID benchmark suite and emit paired reports."
    )
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--model-manifest", type=Path, required=True)
    parser.add_argument("--model-root", type=Path, required=True)
    parser.add_argument(
        "--moonshine-model-arch",
        choices=("tiny_streaming", "small_streaming"),
        required=True,
    )
    parser.add_argument(
        "--aasist-device",
        choices=("auto", "cpu", "mps", "cuda"),
        default="auto",
    )
    parser.add_argument("--target-apcer", type=float, default=0.01)
    parser.add_argument("--target-bpcer", type=float, default=0.10)
    parser.add_argument("--json-out", type=Path, required=True)
    parser.add_argument("--report-out", type=Path, required=True)
    args = parser.parse_args()
    report = run_benchmark_suite(
        corpus_manifest_path=args.manifest,
        model_manifest_path=args.model_manifest,
        model_root=args.model_root,
        moonshine_model_arch=args.moonshine_model_arch,
        aasist_device=args.aasist_device,
        target_apcer=args.target_apcer,
        target_bpcer=args.target_bpcer,
    )
    write_reports(
        report=report,
        json_path=args.json_out,
        markdown_path=args.report_out,
    )


if __name__ == "__main__":
    main()
