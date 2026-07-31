from __future__ import annotations

import json
import math
import os
import unittest
from array import array
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any

from check_adapter_stability import (
    AdapterObservation,
    AdapterRun,
    AdapterStabilityError,
    CandidateInput,
    InjectedAdapterFailure,
    assess_adapter_run,
    collect_adapter_run,
    file_binding,
    require_directory_files,
    tree_binding,
    write_json,
)


class AdapterStabilityTest(unittest.TestCase):
    def test_exact_comparison_ignores_latency(self) -> None:
        run = stable_run(numeric_values=())
        report = assess_adapter_run("moonshine", "exact", 0.0, run)

        self.assertTrue(report["stable"])
        self.assertEqual(
            [item["maximumAbsoluteDelta"] for item in report["comparisons"]],
            [0.0, 0.0, 0.0, 0.0],
        )
        latencies = [
            item["latencyMs"]
            for sequence in report["sequences"].values()
            for item in sequence
        ]
        self.assertGreater(len(set(latencies)), 1)

    def test_numeric_comparison_enforces_explicit_tolerance(self) -> None:
        values = (0.5, *([0.25] * 191))
        within = stable_run(numeric_values=values, numeric_drift=0.000001)
        accepted = assess_adapter_run("ecapa", "numeric", 0.000002, within)
        rejected = assess_adapter_run("ecapa", "numeric", 0.0000001, within)

        self.assertTrue(accepted["stable"])
        self.assertFalse(rejected["stable"])
        self.assertIn("exceeds tolerance", rejected["violations"][0])

    def test_rejects_an_unbounded_numeric_tolerance(self) -> None:
        with self.assertRaisesRegex(AdapterStabilityError, "between 0 and 1e-05"):
            assess_adapter_run(
                "ecapa",
                "numeric",
                0.1,
                stable_run(numeric_values=(0.5, *([0.25] * 191))),
            )

    def test_detects_cross_input_contamination_and_failed_recovery(self) -> None:
        stable = observation("A", typed_value={"kind": "accepted"})
        contaminated = observation("A", typed_value={"kind": "rejected"})
        input_b = observation("B", typed_value={"kind": "rejected"})
        run = AdapterRun(
            a_a_a=(stable, stable, stable),
            a_b_a=(stable, input_b, contaminated),
            recovery=(stable, contaminated),
            injected_failure_type="InjectedAdapterFailure",
        )

        report = assess_adapter_run("moonshine", "exact", 0.0, run)

        self.assertFalse(report["stable"])
        self.assertEqual(
            [item["stable"] for item in report["comparisons"]],
            [True, True, False, False],
        )

    def test_collects_required_sequences_and_recovers_after_injected_failure(self) -> None:
        adapter = RecordingAdapter()
        input_a = candidate_input("A", b"input-a")
        input_b = candidate_input("B", b"input-b")
        try:
            run = collect_adapter_run(adapter, input_a, input_b)
        finally:
            input_a.zero()
            input_b.zero()

        self.assertEqual(
            adapter.calls,
            ["A", "A", "A", "A", "B", "A", "A", "FAIL", "A"],
        )
        self.assertEqual(run.injected_failure_type, "InjectedAdapterFailure")
        self.assertTrue(
            assess_adapter_run("fake", "exact", 0.0, run)["stable"]
        )

    def test_requires_an_observed_injected_failure(self) -> None:
        run = stable_run(numeric_values=(), failure_type=None)

        report = assess_adapter_run("moonshine", "exact", 0.0, run)

        self.assertFalse(report["stable"])
        self.assertIn("required InjectedAdapterFailure", report["violations"][0])

    def test_rejects_a_different_failure_type(self) -> None:
        run = stable_run(numeric_values=(), failure_type="ValueError")

        report = assess_adapter_run("moonshine", "exact", 0.0, run)

        self.assertFalse(report["stable"])
        self.assertFalse(report["failureRecovery"]["injectedFailureObserved"])

    def test_rejects_stable_model_unavailable_aasist_results(self) -> None:
        unavailable_a = observation(
            "A",
            typed_value={"kind": "uncertain", "reason": "model_unavailable"},
            numeric_values=(0.0,),
        )
        unavailable_b = observation(
            "B",
            typed_value={"kind": "uncertain", "reason": "model_unavailable"},
            numeric_values=(0.0,),
        )
        run = AdapterRun(
            a_a_a=(unavailable_a, unavailable_a, unavailable_a),
            a_b_a=(unavailable_a, unavailable_b, unavailable_a),
            recovery=(unavailable_a, unavailable_a),
            injected_failure_type="InjectedAdapterFailure",
        )

        report = assess_adapter_run("aasist", "numeric", 0.000001, run)

        self.assertFalse(report["stable"])
        self.assertTrue(
            any("model_unavailable" in value for value in report["violations"])
        )

    def test_requires_input_b_to_change_adapter_output(self) -> None:
        input_a = observation("A", typed_value={"transcript": "approve"})
        input_b = observation("B", typed_value={"transcript": "approve"})
        run = AdapterRun(
            a_a_a=(input_a, input_a, input_a),
            a_b_a=(input_a, input_b, input_a),
            recovery=(input_a, input_a),
            injected_failure_type="InjectedAdapterFailure",
        )

        report = assess_adapter_run("moonshine", "exact", 0.0, run)

        self.assertFalse(report["stable"])
        self.assertIn("distinct adapter output", report["violations"][0])

    def test_rejects_sub_tolerance_numeric_input_b_difference(self) -> None:
        values_a = (0.5, *([0.25] * 191))
        values_b = (0.5000001, *([0.25] * 191))
        input_a = observation(
            "A",
            typed_value={"embeddingDimensions": 192},
            numeric_values=values_a,
        )
        input_b = observation(
            "B",
            typed_value={"embeddingDimensions": 192},
            numeric_values=values_b,
        )
        run = AdapterRun(
            a_a_a=(input_a, input_a, input_a),
            a_b_a=(input_a, input_b, input_a),
            recovery=(input_a, input_a),
            injected_failure_type="InjectedAdapterFailure",
        )

        report = assess_adapter_run("ecapa", "numeric", 0.000001, run)

        self.assertFalse(report["stable"])
        self.assertIn("distinct adapter output", report["violations"][0])

    def test_hash_bindings_change_with_artifact_content(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            model = root / "model"
            model.mkdir()
            artifact = model / "weights.bin"
            artifact.write_bytes(b"first")
            (model / "weights.bin.lock").write_bytes(b"ignored")
            cache = model / ".cache"
            cache.mkdir()
            (cache / "metadata").write_bytes(b"ignored")
            manifest = root / "manifest.json"
            manifest.write_text("{}\n", encoding="utf-8")

            first_tree = tree_binding(model)
            first_file = file_binding(manifest)
            artifact.write_bytes(b"second")
            second_tree = tree_binding(model)
            manifest.write_text('{"changed":true}\n', encoding="utf-8")
            second_file = file_binding(manifest)

        self.assertNotEqual(first_tree["treeSha256"], second_tree["treeSha256"])
        self.assertEqual(first_tree["fileCount"], 1)
        self.assertNotEqual(first_file["sha256"], second_file["sha256"])

    def test_rejects_a_wrapper_directory_instead_of_exact_adapter_path(self) -> None:
        with TemporaryDirectory() as directory:
            wrapper = Path(directory).resolve()
            nested = wrapper / "download.moonshine.ai" / "model"
            nested.mkdir(parents=True)
            (nested / "frontend.ort").write_bytes(b"model")

            with self.assertRaisesRegex(
                AdapterStabilityError,
                "missing exact adapter files",
            ):
                require_directory_files(
                    wrapper,
                    "exact Moonshine adapter directory",
                    ("frontend.ort",),
                )

    def test_rejects_symlinked_model_artifacts(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            model = root / "model"
            model.mkdir()
            target = root / "mutable-weights.bin"
            target.write_bytes(b"first")
            os.symlink(target, model / "weights.bin")

            with self.assertRaisesRegex(
                AdapterStabilityError,
                "mutable symlink",
            ):
                require_directory_files(
                    model,
                    "model directory",
                    ("weights.bin",),
                )
            with self.assertRaisesRegex(
                AdapterStabilityError,
                "mutable symlink",
            ):
                tree_binding(model)
            with self.assertRaisesRegex(
                AdapterStabilityError,
                "mutable symlink",
            ):
                file_binding(model / "weights.bin")

    def test_rejects_a_symlinked_model_ancestor(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            real = root / "real"
            model = real / "model"
            model.mkdir(parents=True)
            artifact = model / "weights.bin"
            artifact.write_bytes(b"weights")
            alias = root / "alias"
            os.symlink(real, alias)

            with self.assertRaisesRegex(
                AdapterStabilityError,
                "mutable symlink component",
            ):
                tree_binding(alias / "model")
            with self.assertRaisesRegex(
                AdapterStabilityError,
                "mutable symlink component",
            ):
                file_binding(alias / "model" / "weights.bin")

    def test_strict_json_rejects_non_finite_values(self) -> None:
        with TemporaryDirectory() as directory:
            output = Path(directory) / "report.json"
            with self.assertRaises(ValueError):
                write_json(output, {"value": math.nan})
            self.assertFalse(output.exists())


class RecordingAdapter:
    name = "fake"
    comparison_mode = "exact"
    absolute_tolerance = 0.0

    def __init__(self) -> None:
        self.calls: list[str] = []

    def evaluate(self, value: CandidateInput) -> AdapterObservation:
        self.calls.append(value.label)
        return observation(
            value.label,
            typed_value={"value": value.label},
        )

    def inject_failure(self, value: CandidateInput) -> None:
        self.calls.append("FAIL")
        raise InjectedAdapterFailure("expected injected failure")


def stable_run(
    *,
    numeric_values: tuple[float, ...],
    numeric_drift: float = 0.0,
    failure_type: str | None = "InjectedAdapterFailure",
) -> AdapterRun:
    if len(numeric_values) == 0:
        baseline_typed = {"transcript": "approve"}
        input_b_typed = {"transcript": "reject"}
    else:
        baseline_typed = {"embeddingDimensions": len(numeric_values)}
        input_b_typed = baseline_typed
    baseline = observation(
        "A",
        typed_value=baseline_typed,
        numeric_values=numeric_values,
        latency_ms=1.0,
    )
    drifted = observation(
        "A",
        typed_value=baseline_typed,
        numeric_values=tuple(value + numeric_drift for value in numeric_values),
        latency_ms=8.0,
    )
    input_b = observation(
        "B",
        typed_value=input_b_typed,
        numeric_values=tuple(-value for value in numeric_values),
        latency_ms=4.0,
    )
    return AdapterRun(
        a_a_a=(baseline, drifted, baseline),
        a_b_a=(baseline, input_b, drifted),
        recovery=(baseline, drifted),
        injected_failure_type=failure_type,
    )


def observation(
    label: str,
    *,
    typed_value: dict[str, Any] | None = None,
    numeric_values: tuple[float, ...] = (),
    latency_ms: float = 1.0,
) -> AdapterObservation:
    return AdapterObservation(
        label=label,
        typed_value=typed_value or {"value": label},
        numeric_values=numeric_values,
        latency_ms=latency_ms,
        summary={"kind": "accepted"},
    )


def candidate_input(label: str, raw: bytes) -> CandidateInput:
    value = float(raw[-1])
    return CandidateInput(
        label=label,
        audio_path=Path(f"{label}.wav"),
        audio_sha256=raw.hex().ljust(64, "0")[:64],
        audio_byte_length=len(raw),
        full_pcm=array("f", [value]),
        speech_pcm=array("f", [value]),
        expected_phrase="approve transfer",
        intent_name="approve",
        challenge_tokens=("approve", "transfer"),
    )


if __name__ == "__main__":
    unittest.main()
