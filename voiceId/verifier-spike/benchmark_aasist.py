from __future__ import annotations

import argparse
import json
import sys
from array import array
from pathlib import Path
from typing import Any


VERIFIER_ROOT = Path(__file__).resolve().parents[1] / "verifier"
if str(VERIFIER_ROOT) not in sys.path:
    sys.path.insert(0, str(VERIFIER_ROOT))

from benchmark import BenchmarkEntry, load_benchmark_manifest  # noqa: E402
from evaluate_pad import (  # noqa: E402
    PadEvaluationEntry,
    PadEvaluationManifest,
    calibrate_pad_thresholds,
    evaluate_pad,
    report_to_json,
)
from voiceid_verifier.audio_decode import decode_audio_bytes, zero_float_sequence  # noqa: E402
from voiceid_verifier.audio_quality import analyze_decoded_audio  # noqa: E402
from voiceid_verifier.pad import AasistPadDetector  # noqa: E402


RAW_REPORT_SCHEMA_VERSION = "voice_id_aasist_benchmark_v1"


class AasistBenchmarkError(RuntimeError):
    pass


def benchmark_aasist(
    *,
    benchmark_manifest_path: Path,
    source_path: Path,
    checkpoint_path: Path,
    config_path: Path,
    device_name: str,
    target_apcer: float,
    target_bpcer: float,
) -> tuple[dict[str, Any], dict[str, Any]]:
    benchmark = load_benchmark_manifest(benchmark_manifest_path)
    detector = AasistPadDetector(
        source_path=source_path,
        checkpoint_path=checkpoint_path,
        config_path=config_path,
        device_name=device_name,
        reject_threshold=0.35,
        accept_threshold=0.65,
    )
    entries = tuple(
        evaluate_entry(entry, detector)
        for entry in benchmark.entries
        if entry.partition in {"calibration", "evaluation"}
        and entry.case.kind in {"genuine_verification", "presentation_attack"}
    )
    reject_threshold, accept_threshold = calibrate_pad_thresholds(
        entries,
        target_apcer=target_apcer,
        target_bpcer=target_bpcer,
    )
    calibration_version = (
        f"aasist-{benchmark.dataset_version}-apcer-{target_apcer:g}-bpcer-{target_bpcer:g}"
    )
    manifest = PadEvaluationManifest(
        dataset_manifest_version=benchmark.dataset_version,
        model_version=detector.model_version,
        pad_calibration_version=calibration_version,
        reject_threshold=reject_threshold,
        accept_threshold=accept_threshold,
        entries=entries,
    )
    evaluation = evaluate_pad(manifest)
    raw_report = {
        "schemaVersion": RAW_REPORT_SCHEMA_VERSION,
        "datasetVersion": benchmark.dataset_version,
        "modelVersion": detector.model_version,
        "device": device_name,
        "targetApcer": target_apcer,
        "targetBpcer": target_bpcer,
        "rejectThreshold": reject_threshold,
        "acceptThreshold": accept_threshold,
        "entries": [entry_to_json(entry) for entry in entries],
    }
    return raw_report, report_to_json(evaluation)


def evaluate_entry(
    entry: BenchmarkEntry,
    detector: AasistPadDetector,
) -> PadEvaluationEntry:
    audio_bytes = entry.audio_path.read_bytes()
    decoded = decode_audio_bytes(audio_bytes)
    speech_samples = array("f")
    speech_windows = ()
    try:
        analysis = analyze_decoded_audio(
            audio_bytes,
            decoded.decoded_duration_ms,
            samples=decoded.samples,
            sample_rate_hz=decoded.sample_rate_hz,
        )
        if analysis.quality.kind != "accepted" or len(analysis.speech_windows) == 0:
            raise AasistBenchmarkError(
                f"fixture {entry.fixture_id} failed common audio quality gates"
            )
        speech_windows = analysis.speech_windows
        for window in speech_windows:
            speech_samples.extend(window.samples)
        decision = detector.analyze(speech_samples)
        presentation = (
            "attack" if entry.case.kind == "presentation_attack" else "bona_fide"
        )
        return PadEvaluationEntry(
            fixture_id=entry.fixture_id,
            subject_id=entry.subject_id,
            session_id=entry.session_id,
            partition=entry.partition,
            presentation=presentation,
            attack_class=entry.case.attack_class if presentation == "attack" else None,
            capture_profile=capture_profile_id(entry),
            pad_score=decision.score,
            latency_ms=decision.latency_ms,
        )
    finally:
        zero_float_sequence(speech_samples)
        zero_float_sequence(decoded.samples)
        for window in speech_windows:
            zero_float_sequence(window.samples)


def capture_profile_id(entry: BenchmarkEntry) -> str:
    capture = entry.capture
    return "-".join(
        (
            capture.platform,
            capture.microphone,
            capture.codec,
            str(capture.sample_rate_hz),
            capture.noise_profile,
        )
    )


def entry_to_json(entry: PadEvaluationEntry) -> dict[str, Any]:
    return {
        "fixtureId": entry.fixture_id,
        "subjectId": entry.subject_id,
        "sessionId": entry.session_id,
        "partition": entry.partition,
        "presentation": entry.presentation,
        "attackClass": entry.attack_class,
        "captureProfile": entry.capture_profile,
        "padScore": entry.pad_score,
        "latencyMs": entry.latency_ms,
    }


def write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Run pinned AASIST over a frozen VoiceID corpus and calibrate PAD regions."
    )
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--source-path", type=Path, required=True)
    parser.add_argument("--checkpoint-path", type=Path, required=True)
    parser.add_argument("--config-path", type=Path, required=True)
    parser.add_argument("--device", choices=("auto", "cpu", "mps", "cuda"), default="auto")
    parser.add_argument("--target-apcer", type=float, default=0.01)
    parser.add_argument("--target-bpcer", type=float, default=0.10)
    parser.add_argument("--raw-out", type=Path, required=True)
    parser.add_argument("--report-out", type=Path, required=True)
    args = parser.parse_args()
    raw_report, evaluation_report = benchmark_aasist(
        benchmark_manifest_path=args.manifest,
        source_path=args.source_path,
        checkpoint_path=args.checkpoint_path,
        config_path=args.config_path,
        device_name=args.device,
        target_apcer=args.target_apcer,
        target_bpcer=args.target_bpcer,
    )
    write_json(args.raw_out, raw_report)
    write_json(args.report_out, evaluation_report)


if __name__ == "__main__":
    main()
