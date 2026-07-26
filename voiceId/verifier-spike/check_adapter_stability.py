from __future__ import annotations

import argparse
import hashlib
import importlib.metadata
import json
import math
import platform
import re
import struct
import sys
import time
from array import array
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal, Protocol, Sequence


REPORT_SCHEMA_VERSION = "voice_id_candidate_adapter_stability_v1"
SEQUENCE_AAA = "A-A-A"
SEQUENCE_ABA = "A-B-A"
SEQUENCE_RECOVERY = "A-FAIL-A"
INTENT_NAMES = ("approve", "reject", "cancel", "repeat", "unrelated")
MAXIMUM_NUMERIC_STABILITY_TOLERANCE = 1.0e-5
ECAPA_EMBEDDING_DIMENSIONS = 192


class AdapterStabilityError(RuntimeError):
    pass


class InjectedAdapterFailure(RuntimeError):
    pass


@dataclass(frozen=True)
class AdapterObservation:
    label: Literal["A", "B"]
    typed_value: dict[str, Any]
    numeric_values: tuple[float, ...]
    latency_ms: float
    summary: dict[str, Any]


@dataclass(frozen=True)
class AdapterRun:
    a_a_a: tuple[AdapterObservation, AdapterObservation, AdapterObservation]
    a_b_a: tuple[AdapterObservation, AdapterObservation, AdapterObservation]
    recovery: tuple[AdapterObservation, AdapterObservation]
    injected_failure_type: str | None


@dataclass(frozen=True)
class StabilityComparison:
    name: str
    stable: bool
    maximum_absolute_delta: float | None
    reason: str | None

    def to_json(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "stable": self.stable,
            "maximumAbsoluteDelta": self.maximum_absolute_delta,
            "reason": self.reason,
        }


@dataclass(frozen=True)
class CandidateInput:
    label: Literal["A", "B"]
    audio_path: Path
    audio_sha256: str
    audio_byte_length: int
    full_pcm: array[float]
    speech_pcm: array[float]
    expected_phrase: str
    intent_name: str
    challenge_tokens: tuple[str, ...]

    def binding(self) -> dict[str, Any]:
        policy = {
            "expectedPhrase": self.expected_phrase,
            "intentName": self.intent_name,
            "challengeTokens": list(self.challenge_tokens),
        }
        return {
            "audioSha256": self.audio_sha256,
            "audioByteLength": self.audio_byte_length,
            "fullPcmSha256": hash_float_sequence(self.full_pcm),
            "fullPcmSampleCount": len(self.full_pcm),
            "speechPcmSha256": hash_float_sequence(self.speech_pcm),
            "speechPcmSampleCount": len(self.speech_pcm),
            "analysisPolicySha256": hash_json(policy),
        }

    def zero(self) -> None:
        zero_float_sequence(self.full_pcm)
        zero_float_sequence(self.speech_pcm)


@dataclass(frozen=True)
class StabilityConfiguration:
    input_a: Path
    input_b: Path
    expected_phrase_a: str
    expected_phrase_b: str
    intent_a: str
    intent_b: str
    challenge_tokens_a: tuple[str, ...]
    challenge_tokens_b: tuple[str, ...]
    model_manifest: Path
    moonshine_model_path: Path
    moonshine_model_arch: str
    moonshine_intent_model_path: Path
    moonshine_intent_threshold: float
    moonshine_intent_margin: float
    ecapa_model_path: Path
    ecapa_absolute_tolerance: float
    aasist_source_path: Path
    aasist_checkpoint_path: Path
    aasist_config_path: Path
    aasist_device: str
    aasist_absolute_tolerance: float
    output_path: Path


@dataclass(frozen=True)
class RealDependencies:
    decode_audio_bytes: Any
    analyze_decoded_audio: Any
    moonshine_recognizer: Any
    ecapa_extractor: Any
    ecapa_runtime: Any
    aasist_detector: Any
    moonshine_module: Any
    speechbrain_module: Any
    torch_module: Any


class CandidateAdapter(Protocol):
    name: str
    comparison_mode: Literal["exact", "numeric"]
    absolute_tolerance: float

    def evaluate(self, candidate_input: CandidateInput) -> AdapterObservation:
        ...

    def inject_failure(self, candidate_input: CandidateInput) -> None:
        ...


class FaultTrigger:
    def __init__(self) -> None:
        self.failure_observed = False
        self.cleanup_observed = False


class ObservedMoonshineTranscriber:
    def __init__(self, delegate: Any, trigger: FaultTrigger) -> None:
        self._delegate = delegate
        self._trigger = trigger

    def transcribe_without_streaming(
        self,
        samples: Sequence[float],
        *,
        sample_rate: int,
    ) -> Any:
        return self._delegate.transcribe_without_streaming(
            samples,
            sample_rate=sample_rate,
        )

    def close(self) -> None:
        self._delegate.close()
        self._trigger.cleanup_observed = True


class ObservedMoonshineTranscriberFactory:
    def __init__(self, delegate: Any, trigger: FaultTrigger) -> None:
        self._delegate = delegate
        self._trigger = trigger

    def __call__(self, *args: Any, **kwargs: Any) -> ObservedMoonshineTranscriber:
        return ObservedMoonshineTranscriber(
            self._delegate(*args, **kwargs),
            self._trigger,
        )


class FaultingMoonshineIntentRecognizer:
    def __init__(self, delegate: Any, trigger: FaultTrigger) -> None:
        self._delegate = delegate
        self._trigger = trigger

    def get_closest_intents(self, *args: Any, **kwargs: Any) -> Any:
        self._delegate.get_closest_intents(*args, **kwargs)
        self._trigger.failure_observed = True
        raise InjectedAdapterFailure("injected after Moonshine intent inference")


class FaultingEcapaEmbedding:
    def __init__(self, delegate: Any, trigger: FaultTrigger) -> None:
        self._delegate = delegate
        self._trigger = trigger

    def detach(self) -> Any:
        self._trigger.failure_observed = True
        raise InjectedAdapterFailure("injected after ECAPA inference")

    def zero_(self) -> None:
        self._delegate.zero_()
        self._trigger.cleanup_observed = True


class FaultingEcapaClassifier:
    def __init__(self, delegate: Any, trigger: FaultTrigger) -> None:
        self._delegate = delegate
        self._trigger = trigger

    def encode_batch(self, waveform: Any) -> FaultingEcapaEmbedding:
        return FaultingEcapaEmbedding(
            self._delegate.encode_batch(waveform),
            self._trigger,
        )

    def __getattr__(self, name: str) -> Any:
        return getattr(self._delegate, name)


class FaultingAasistProbabilities:
    def __init__(self, delegate: Any, trigger: FaultTrigger) -> None:
        self._delegate = delegate
        self._trigger = trigger

    def __getitem__(self, key: Any) -> Any:
        self._trigger.failure_observed = True
        raise InjectedAdapterFailure("injected after AASIST inference")

    def zero_(self) -> None:
        self._delegate.zero_()
        self._trigger.cleanup_observed = True


class FaultingAasistTorch:
    def __init__(self, delegate: Any, trigger: FaultTrigger) -> None:
        self._delegate = delegate
        self._trigger = trigger

    def softmax(self, logits: Any, *, dim: int) -> FaultingAasistProbabilities:
        probabilities = self._delegate.softmax(logits, dim=dim)
        return FaultingAasistProbabilities(probabilities, self._trigger)

    def __getattr__(self, name: str) -> Any:
        return getattr(self._delegate, name)


class MoonshineCandidate:
    name = "moonshine"
    comparison_mode: Literal["exact"] = "exact"
    absolute_tolerance = 0.0

    def __init__(self, recognizer: Any) -> None:
        self._recognizer = recognizer

    def evaluate(self, candidate_input: CandidateInput) -> AdapterObservation:
        started = time.perf_counter()
        analysis = self._recognizer.analyze(
            candidate_input.full_pcm,
            expected_phrase=candidate_input.expected_phrase,
            intent_name=candidate_input.intent_name,
            challenge_tokens=candidate_input.challenge_tokens,
        )
        latency_ms = elapsed_ms(started)
        typed_value = moonshine_analysis_value(analysis)
        return AdapterObservation(
            label=candidate_input.label,
            typed_value=typed_value,
            numeric_values=(),
            latency_ms=latency_ms,
            summary={
                "transcriptSha256": sha256_bytes(
                    analysis.transcript.encode("utf-8")
                ),
                "phraseKind": analysis.phrase.kind,
                "intentKind": analysis.intent.kind,
            },
        )

    def inject_failure(self, candidate_input: CandidateInput) -> None:
        trigger = FaultTrigger()
        transcriber_factory = self._recognizer._transcriber_factory
        intent_recognizer = self._recognizer._intent_recognizer
        self._recognizer._transcriber_factory = ObservedMoonshineTranscriberFactory(
            transcriber_factory,
            trigger,
        )
        self._recognizer._intent_recognizer = FaultingMoonshineIntentRecognizer(
            intent_recognizer,
            trigger,
        )
        try:
            self._recognizer.analyze(
                candidate_input.full_pcm,
                expected_phrase=candidate_input.expected_phrase,
                intent_name=candidate_input.intent_name,
                challenge_tokens=candidate_input.challenge_tokens,
            )
        except InjectedAdapterFailure:
            if not trigger.failure_observed or not trigger.cleanup_observed:
                raise AdapterStabilityError(
                    "Moonshine failure injection did not observe cleanup"
                )
            raise
        finally:
            self._recognizer._transcriber_factory = transcriber_factory
            self._recognizer._intent_recognizer = intent_recognizer


class EcapaCandidate:
    name = "ecapa"
    comparison_mode: Literal["numeric"] = "numeric"

    def __init__(self, runtime: Any, absolute_tolerance: float) -> None:
        self._runtime = runtime
        self.absolute_tolerance = absolute_tolerance

    def evaluate(self, candidate_input: CandidateInput) -> AdapterObservation:
        started = time.perf_counter()
        extracted = self._runtime.extract_window_embedding(candidate_input.speech_pcm)
        latency_ms = elapsed_ms(started)
        try:
            numeric_values = tuple(float(value) for value in extracted.vector)
        finally:
            zero_float_sequence(extracted.vector)
        metadata = self._runtime.metadata
        return AdapterObservation(
            label=candidate_input.label,
            typed_value={
                "adapterId": metadata.adapter_id,
                "modelId": metadata.model_id,
                "modelVersion": metadata.model_version,
                "embeddingDimensions": metadata.embedding_dimensions,
                "speakerLabel": extracted.speaker_label,
            },
            numeric_values=numeric_values,
            latency_ms=latency_ms,
            summary={
                "embeddingDimensions": len(numeric_values),
                "embeddingSha256": hash_float_sequence(numeric_values),
            },
        )

    def inject_failure(self, candidate_input: CandidateInput) -> None:
        trigger = FaultTrigger()
        classifier = self._runtime.extractor.classifier
        self._runtime.extractor.classifier = FaultingEcapaClassifier(
            classifier,
            trigger,
        )
        try:
            self._runtime.extract_window_embedding(candidate_input.speech_pcm)
        except Exception as error:
            if (
                contains_injected_failure(error)
                and trigger.failure_observed
                and trigger.cleanup_observed
            ):
                raise InjectedAdapterFailure(
                    "observed injected ECAPA failure"
                ) from error
            raise
        finally:
            self._runtime.extractor.classifier = classifier


class AasistCandidate:
    name = "aasist"
    comparison_mode: Literal["numeric"] = "numeric"

    def __init__(self, detector: Any, absolute_tolerance: float) -> None:
        self._detector = detector
        self.absolute_tolerance = absolute_tolerance

    def evaluate(self, candidate_input: CandidateInput) -> AdapterObservation:
        decision = self._detector.analyze(candidate_input.speech_pcm)
        return AdapterObservation(
            label=candidate_input.label,
            typed_value={
                "kind": decision.kind,
                "rejectThreshold": decision.reject_threshold,
                "acceptThreshold": decision.accept_threshold,
                "modelVersion": decision.model_version,
                "calibrationVersion": decision.calibration_version,
                "reason": decision.reason,
            },
            numeric_values=(float(decision.score),),
            latency_ms=float(decision.latency_ms),
            summary={
                "decisionKind": decision.kind,
                "score": float(decision.score),
            },
        )

    def inject_failure(self, candidate_input: CandidateInput) -> None:
        trigger = FaultTrigger()
        torch = self._detector._torch
        self._detector._torch = FaultingAasistTorch(torch, trigger)
        try:
            decision = self._detector.analyze(candidate_input.speech_pcm)
        finally:
            self._detector._torch = torch
        if (
            not trigger.failure_observed
            or not trigger.cleanup_observed
            or decision.kind != "uncertain"
            or decision.reason != "model_unavailable"
        ):
            raise AdapterStabilityError(
                "AASIST did not surface the injected post-inference failure"
            )
        raise InjectedAdapterFailure("observed injected AASIST failure")


def moonshine_analysis_value(analysis: Any) -> dict[str, Any]:
    return {
        "transcript": analysis.transcript,
        "sampleRateHz": analysis.sample_rate_hz,
        "phrase": {
            "kind": analysis.phrase.kind,
            "expectedNormalized": analysis.phrase.expected_normalized,
            "spokenNormalized": analysis.phrase.spoken_normalized,
            "confidence": analysis.phrase.confidence,
            "reason": analysis.phrase.reason,
        },
        "intent": {
            "kind": analysis.intent.kind,
            "intent": analysis.intent.intent,
            "canonicalPhrase": analysis.intent.canonical_phrase,
            "confidence": analysis.intent.confidence,
            "runnerUpIntent": analysis.intent.runner_up_intent,
            "runnerUpConfidence": analysis.intent.runner_up_confidence,
            "reason": analysis.intent.reason,
        },
    }


def collect_adapter_run(
    adapter: CandidateAdapter,
    input_a: CandidateInput,
    input_b: CandidateInput,
) -> AdapterRun:
    a_a_a = (
        adapter.evaluate(input_a),
        adapter.evaluate(input_a),
        adapter.evaluate(input_a),
    )
    a_b_a = (
        adapter.evaluate(input_a),
        adapter.evaluate(input_b),
        adapter.evaluate(input_a),
    )
    recovery_before = adapter.evaluate(input_a)
    failure_type = observe_injected_failure(adapter, input_a)
    recovery_after = adapter.evaluate(input_a)
    return AdapterRun(
        a_a_a=a_a_a,
        a_b_a=a_b_a,
        recovery=(recovery_before, recovery_after),
        injected_failure_type=failure_type,
    )


def observe_injected_failure(
    adapter: CandidateAdapter,
    candidate_input: CandidateInput,
) -> str | None:
    try:
        adapter.inject_failure(candidate_input)
    except InjectedAdapterFailure:
        return InjectedAdapterFailure.__name__
    except Exception as error:
        raise AdapterStabilityError(
            f"failure injection raised unexpected {type(error).__name__}"
        ) from error
    return None


def contains_injected_failure(error: BaseException) -> bool:
    current: BaseException | None = error
    visited: set[int] = set()
    while current is not None and id(current) not in visited:
        if isinstance(current, InjectedAdapterFailure):
            return True
        visited.add(id(current))
        current = current.__cause__ or current.__context__
    return False


def assess_adapter_run(
    adapter_name: str,
    comparison_mode: Literal["exact", "numeric"],
    absolute_tolerance: float,
    run: AdapterRun,
) -> dict[str, Any]:
    validate_tolerance(absolute_tolerance, f"{adapter_name} absolute tolerance")
    validate_run_labels(run)
    observations = (*run.a_a_a, *run.a_b_a, *run.recovery)
    for observation in observations:
        validate_observation(observation)
    comparisons = (
        compare_observations(
            "A-A-A first/second",
            run.a_a_a[0],
            run.a_a_a[1],
            absolute_tolerance,
        ),
        compare_observations(
            "A-A-A first/third",
            run.a_a_a[0],
            run.a_a_a[2],
            absolute_tolerance,
        ),
        compare_observations(
            "A-B-A contamination",
            run.a_b_a[0],
            run.a_b_a[2],
            absolute_tolerance,
        ),
        compare_observations(
            "A-FAIL-A recovery",
            run.recovery[0],
            run.recovery[1],
            absolute_tolerance,
        ),
    )
    violations = [
        f"{adapter_name}: {comparison.name}: {comparison.reason}"
        for comparison in comparisons
        if not comparison.stable
    ]
    violations.extend(adapter_health_violations(adapter_name, observations))
    if not adapter_outputs_are_distinct(
        adapter_name,
        run.a_b_a[0],
        run.a_b_a[1],
        absolute_tolerance,
    ):
        violations.append(
            f"{adapter_name}: input B did not produce a distinct adapter output"
        )
    if run.injected_failure_type != InjectedAdapterFailure.__name__:
        violations.append(
            f"{adapter_name}: required {InjectedAdapterFailure.__name__} was not observed"
        )
    stable = len(violations) == 0
    return {
        "stable": stable,
        "comparisonMode": comparison_mode,
        "absoluteTolerance": absolute_tolerance,
        "sequences": {
            "aAa": [
                observation_to_json(observation)
                for observation in run.a_a_a
            ],
            "aBa": [
                observation_to_json(observation)
                for observation in run.a_b_a
            ],
            "recovery": [
                observation_to_json(observation)
                for observation in run.recovery
            ],
        },
        "comparisons": [comparison.to_json() for comparison in comparisons],
        "failureRecovery": {
            "sequence": SEQUENCE_RECOVERY,
            "injectedFailureObserved": (
                run.injected_failure_type == InjectedAdapterFailure.__name__
            ),
            "exceptionType": run.injected_failure_type,
            "stableAfterFailure": comparisons[-1].stable,
        },
        "violations": violations,
    }


def adapter_health_violations(
    adapter_name: str,
    observations: Sequence[AdapterObservation],
) -> list[str]:
    violations: list[str] = []
    for index, observation in enumerate(observations):
        if adapter_name == "moonshine":
            transcript = observation.typed_value.get("transcript")
            if not isinstance(transcript, str) or transcript.strip() == "":
                violations.append(
                    f"moonshine: observation {index} has no transcript"
                )
        elif adapter_name == "ecapa":
            dimensions = observation.typed_value.get("embeddingDimensions")
            if (
                dimensions != ECAPA_EMBEDDING_DIMENSIONS
                or len(observation.numeric_values) != ECAPA_EMBEDDING_DIMENSIONS
            ):
                violations.append(
                    f"ecapa: observation {index} is not a "
                    f"{ECAPA_EMBEDDING_DIMENSIONS}-dimension embedding"
                )
        elif adapter_name == "aasist":
            if observation.typed_value.get("reason") == "model_unavailable":
                violations.append(
                    f"aasist: observation {index} reports model_unavailable"
                )
    return violations


def adapter_outputs_are_distinct(
    adapter_name: str,
    input_a: AdapterObservation,
    input_b: AdapterObservation,
    absolute_tolerance: float,
) -> bool:
    if adapter_name == "moonshine":
        return input_a.typed_value.get("transcript") != input_b.typed_value.get(
            "transcript"
        )
    if adapter_name in ("ecapa", "aasist"):
        if len(input_a.numeric_values) != len(input_b.numeric_values):
            return True
        return (
            maximum_absolute_delta(
                input_a.numeric_values,
                input_b.numeric_values,
            )
            > absolute_tolerance
        )
    return (
        input_a.typed_value != input_b.typed_value
        or input_a.numeric_values != input_b.numeric_values
    )


def compare_observations(
    name: str,
    left: AdapterObservation,
    right: AdapterObservation,
    absolute_tolerance: float,
) -> StabilityComparison:
    if left.label != "A" or right.label != "A":
        return StabilityComparison(
            name=name,
            stable=False,
            maximum_absolute_delta=None,
            reason="comparison requires two A observations",
        )
    if left.typed_value != right.typed_value:
        return StabilityComparison(
            name=name,
            stable=False,
            maximum_absolute_delta=None,
            reason="typed output changed",
        )
    if len(left.numeric_values) != len(right.numeric_values):
        return StabilityComparison(
            name=name,
            stable=False,
            maximum_absolute_delta=None,
            reason="numeric output dimensions changed",
        )
    maximum_delta = maximum_absolute_delta(
        left.numeric_values,
        right.numeric_values,
    )
    if maximum_delta > absolute_tolerance:
        return StabilityComparison(
            name=name,
            stable=False,
            maximum_absolute_delta=maximum_delta,
            reason=(
                f"numeric output delta {maximum_delta:g} exceeds "
                f"tolerance {absolute_tolerance:g}"
            ),
        )
    return StabilityComparison(
        name=name,
        stable=True,
        maximum_absolute_delta=maximum_delta,
        reason=None,
    )


def maximum_absolute_delta(
    left: Sequence[float],
    right: Sequence[float],
) -> float:
    if len(left) != len(right):
        raise AdapterStabilityError("numeric output dimensions differ")
    if len(left) == 0:
        return 0.0
    deltas = tuple(abs(float(a) - float(b)) for a, b in zip(left, right))
    if any(not math.isfinite(value) for value in deltas):
        raise AdapterStabilityError("numeric output delta must be finite")
    return max(deltas)


def validate_run_labels(run: AdapterRun) -> None:
    if tuple(item.label for item in run.a_a_a) != ("A", "A", "A"):
        raise AdapterStabilityError(f"{SEQUENCE_AAA} labels are invalid")
    if tuple(item.label for item in run.a_b_a) != ("A", "B", "A"):
        raise AdapterStabilityError(f"{SEQUENCE_ABA} labels are invalid")
    if tuple(item.label for item in run.recovery) != ("A", "A"):
        raise AdapterStabilityError(f"{SEQUENCE_RECOVERY} labels are invalid")


def validate_observation(observation: AdapterObservation) -> None:
    if not math.isfinite(observation.latency_ms) or observation.latency_ms < 0:
        raise AdapterStabilityError("observation latency must be finite and non-negative")
    if any(not math.isfinite(value) for value in observation.numeric_values):
        raise AdapterStabilityError("numeric adapter output must contain only finite values")
    hash_json(observation.typed_value)
    hash_json(observation.summary)


def observation_to_json(observation: AdapterObservation) -> dict[str, Any]:
    output_value = {
        "typed": observation.typed_value,
        "numeric": list(observation.numeric_values),
    }
    return {
        "label": observation.label,
        "outputSha256": hash_json(output_value),
        "numericValueCount": len(observation.numeric_values),
        "latencyMs": round(observation.latency_ms, 3),
        "summary": observation.summary,
    }


def check_adapter(
    adapter: CandidateAdapter,
    input_a: CandidateInput,
    input_b: CandidateInput,
) -> dict[str, Any]:
    try:
        run = collect_adapter_run(adapter, input_a, input_b)
        return assess_adapter_run(
            adapter.name,
            adapter.comparison_mode,
            adapter.absolute_tolerance,
            run,
        )
    except Exception as error:
        return failed_adapter_report(
            adapter.name,
            adapter.comparison_mode,
            adapter.absolute_tolerance,
            error,
        )


def failed_adapter_report(
    adapter_name: str,
    comparison_mode: Literal["exact", "numeric"],
    absolute_tolerance: float,
    error: Exception,
) -> dict[str, Any]:
    violation = f"{adapter_name}: stability execution failed with {type(error).__name__}"
    return {
        "stable": False,
        "comparisonMode": comparison_mode,
        "absoluteTolerance": absolute_tolerance,
        "sequences": {
            "aAa": [],
            "aBa": [],
            "recovery": [],
        },
        "comparisons": [],
        "failureRecovery": {
            "sequence": SEQUENCE_RECOVERY,
            "injectedFailureObserved": False,
            "exceptionType": None,
            "stableAfterFailure": False,
        },
        "violations": [violation],
    }


def run_real_candidate_check(config: StabilityConfiguration) -> dict[str, Any]:
    validate_configuration(config)
    dependencies = load_real_dependencies()
    input_a = prepare_candidate_input(
        label="A",
        audio_path=config.input_a,
        expected_phrase=config.expected_phrase_a,
        intent_name=config.intent_a,
        challenge_tokens=config.challenge_tokens_a,
        dependencies=dependencies,
    )
    try:
        input_b = prepare_candidate_input(
            label="B",
            audio_path=config.input_b,
            expected_phrase=config.expected_phrase_b,
            intent_name=config.intent_b,
            challenge_tokens=config.challenge_tokens_b,
            dependencies=dependencies,
        )
        try:
            validate_distinct_candidate_inputs(input_a, input_b)
            bindings = build_bindings(config, input_a, input_b)
            recognizer = dependencies.moonshine_recognizer(
                model_path=str(config.moonshine_model_path),
                model_arch=config.moonshine_model_arch,
                intent_model_path=str(config.moonshine_intent_model_path),
                intent_threshold=config.moonshine_intent_threshold,
                intent_margin=config.moonshine_intent_margin,
            )
            extractor = dependencies.ecapa_extractor(
                savedir=config.ecapa_model_path,
            )
            ecapa_runtime = dependencies.ecapa_runtime(extractor=extractor)
            aasist_detector = dependencies.aasist_detector(
                source_path=config.aasist_source_path,
                checkpoint_path=config.aasist_checkpoint_path,
                config_path=config.aasist_config_path,
                device_name=config.aasist_device,
                reject_threshold=0.35,
                accept_threshold=0.65,
            )
            adapters: tuple[CandidateAdapter, ...] = (
                MoonshineCandidate(recognizer),
                EcapaCandidate(ecapa_runtime, config.ecapa_absolute_tolerance),
                AasistCandidate(aasist_detector, config.aasist_absolute_tolerance),
            )
            adapter_reports = {
                adapter.name: check_adapter(adapter, input_a, input_b)
                for adapter in adapters
            }
            violations = flatten_adapter_violations(adapter_reports)
            post_run_bindings = build_bindings(config, input_a, input_b)
            if post_run_bindings != bindings:
                violations.append("bound input or model artifacts changed during execution")
            return {
                "schemaVersion": REPORT_SCHEMA_VERSION,
                "stable": len(violations) == 0,
                "bindings": bindings,
                "runtime": runtime_metadata(
                    config=config,
                    dependencies=dependencies,
                    ecapa_runtime=ecapa_runtime,
                    aasist_detector=aasist_detector,
                ),
                "configuration": {
                    "sequences": [SEQUENCE_AAA, SEQUENCE_ABA, SEQUENCE_RECOVERY],
                    "moonshineComparison": "exact_typed_output",
                    "moonshineIntentThreshold": config.moonshine_intent_threshold,
                    "moonshineIntentMargin": config.moonshine_intent_margin,
                    "ecapaAbsoluteTolerance": config.ecapa_absolute_tolerance,
                    "aasistAbsoluteTolerance": config.aasist_absolute_tolerance,
                },
                "adapters": adapter_reports,
                "violations": violations,
            }
        finally:
            input_b.zero()
    finally:
        input_a.zero()


def load_real_dependencies() -> RealDependencies:
    verifier_root = Path(__file__).resolve().parents[1] / "verifier"
    if str(verifier_root) not in sys.path:
        sys.path.insert(0, str(verifier_root))
    try:
        import moonshine_voice
        import speechbrain
        import torch
        from voiceid_verifier.audio_decode import decode_audio_bytes
        from voiceid_verifier.audio_quality import analyze_decoded_audio
        from voiceid_verifier.embeddings import SpeechBrainEcapaEmbeddingExtractor
        from voiceid_verifier.moonshine import MoonshineRecognizer
        from voiceid_verifier.pad import AasistPadDetector
        from voiceid_verifier.runtime import SpeechBrainEcapaVerifierRuntime
    except ImportError as error:
        raise AdapterStabilityError(
            f"real candidate dependencies are unavailable: {error}"
        ) from error
    return RealDependencies(
        decode_audio_bytes=decode_audio_bytes,
        analyze_decoded_audio=analyze_decoded_audio,
        moonshine_recognizer=MoonshineRecognizer,
        ecapa_extractor=SpeechBrainEcapaEmbeddingExtractor,
        ecapa_runtime=SpeechBrainEcapaVerifierRuntime,
        aasist_detector=AasistPadDetector,
        moonshine_module=moonshine_voice,
        speechbrain_module=speechbrain,
        torch_module=torch,
    )


def prepare_candidate_input(
    *,
    label: Literal["A", "B"],
    audio_path: Path,
    expected_phrase: str,
    intent_name: str,
    challenge_tokens: tuple[str, ...],
    dependencies: RealDependencies,
) -> CandidateInput:
    audio_bytes = audio_path.read_bytes()
    decoded = dependencies.decode_audio_bytes(audio_bytes)
    speech_windows: tuple[Any, ...] = ()
    try:
        analysis = dependencies.analyze_decoded_audio(
            audio_bytes,
            decoded.decoded_duration_ms,
            samples=decoded.samples,
            sample_rate_hz=decoded.sample_rate_hz,
        )
        speech_windows = analysis.speech_windows
        if analysis.quality.kind != "accepted" or len(speech_windows) == 0:
            raise AdapterStabilityError(
                f"input {label} failed common audio quality gates"
            )
        speech_pcm = array("f")
        for window in speech_windows:
            speech_pcm.extend(window.samples)
        return CandidateInput(
            label=label,
            audio_path=audio_path,
            audio_sha256=sha256_bytes(audio_bytes),
            audio_byte_length=len(audio_bytes),
            full_pcm=array("f", decoded.samples),
            speech_pcm=speech_pcm,
            expected_phrase=expected_phrase,
            intent_name=intent_name,
            challenge_tokens=challenge_tokens,
        )
    finally:
        zero_float_sequence(decoded.samples)
        for window in speech_windows:
            zero_float_sequence(window.samples)


def build_bindings(
    config: StabilityConfiguration,
    input_a: CandidateInput,
    input_b: CandidateInput,
) -> dict[str, Any]:
    return {
        "inputs": {
            "A": input_a.binding(),
            "B": input_b.binding(),
        },
        "models": {
            "modelManifest": file_binding(config.model_manifest),
            "moonshine": tree_binding(config.moonshine_model_path),
            "moonshineIntent": tree_binding(config.moonshine_intent_model_path),
            "ecapa": tree_binding(config.ecapa_model_path),
            "aasistSource": file_binding(config.aasist_source_path),
            "aasistCheckpoint": file_binding(config.aasist_checkpoint_path),
            "aasistConfig": file_binding(config.aasist_config_path),
        },
    }


def runtime_metadata(
    *,
    config: StabilityConfiguration,
    dependencies: RealDependencies,
    ecapa_runtime: Any,
    aasist_detector: Any,
) -> dict[str, Any]:
    native_library = moonshine_native_library(dependencies.moonshine_module)
    ecapa_device = getattr(ecapa_runtime.extractor.classifier, "device", None)
    if ecapa_device is None:
        raise AdapterStabilityError("SpeechBrain runtime does not expose its device")
    return {
        "pythonVersion": platform.python_version(),
        "platform": platform.system().lower(),
        "architecture": platform.machine().lower(),
        "moonshine": {
            "packageVersion": package_version("moonshine-voice"),
            "modelArch": config.moonshine_model_arch,
            "provider": "moonshine_native_default_unreported",
            "nativeLibrarySha256": sha256_file(native_library),
        },
        "ecapa": {
            "speechbrainVersion": module_version(
                dependencies.speechbrain_module,
                "speechbrain",
            ),
            "torchVersion": module_version(dependencies.torch_module, "torch"),
            "provider": str(ecapa_device),
        },
        "aasist": {
            "torchVersion": module_version(dependencies.torch_module, "torch"),
            "provider": str(aasist_detector._device),
        },
    }


def moonshine_native_library(module: Any) -> Path:
    module_path = Path(module.__file__).resolve().parent
    candidates = tuple(
        path
        for path in sorted(module_path.glob("libmoonshine.*"))
        if path.is_file()
    )
    if len(candidates) != 1:
        raise AdapterStabilityError(
            "moonshine runtime must expose exactly one native library"
        )
    return candidates[0]


def module_version(module: Any, package_name: str) -> str:
    value = getattr(module, "__version__", None)
    if isinstance(value, str) and value.strip() != "":
        return value
    return package_version(package_name)


def package_version(package_name: str) -> str:
    try:
        return importlib.metadata.version(package_name)
    except importlib.metadata.PackageNotFoundError as error:
        raise AdapterStabilityError(
            f"package version is unavailable for {package_name}"
        ) from error


def validate_distinct_candidate_inputs(
    input_a: CandidateInput,
    input_b: CandidateInput,
) -> None:
    if input_a.audio_sha256 == input_b.audio_sha256:
        raise AdapterStabilityError("inputs A and B must have distinct audio hashes")
    if hash_float_sequence(input_a.full_pcm) == hash_float_sequence(input_b.full_pcm):
        raise AdapterStabilityError("inputs A and B must have distinct canonical PCM")
    if hash_float_sequence(input_a.speech_pcm) == hash_float_sequence(input_b.speech_pcm):
        raise AdapterStabilityError(
            "inputs A and B must have distinct accepted-speech PCM"
        )


def validate_configuration(config: StabilityConfiguration) -> None:
    for name, path in (
        ("input A", config.input_a),
        ("input B", config.input_b),
        ("model manifest", config.model_manifest),
        ("AASIST source", config.aasist_source_path),
        ("AASIST checkpoint", config.aasist_checkpoint_path),
        ("AASIST config", config.aasist_config_path),
    ):
        require_file(path, name)
    require_directory_files(
        config.moonshine_model_path,
        "exact Moonshine adapter directory",
        (
            "adapter.ort",
            "cross_kv.ort",
            "decoder_kv.ort",
            "decoder_kv_with_attention.ort",
            "encoder.ort",
            "frontend.ort",
            "streaming_config.json",
            "tokenizer.bin",
        ),
    )
    require_directory_files(
        config.moonshine_intent_model_path,
        "exact Moonshine intent adapter directory",
        ("model_q4.onnx", "model_q4.onnx_data", "tokenizer.bin"),
    )
    require_directory_files(
        config.ecapa_model_path,
        "ECAPA model directory",
        (
            "embedding_model.ckpt",
            "hyperparams.yaml",
            "mean_var_norm_emb.ckpt",
        ),
    )
    for name, value in (
        ("expected phrase A", config.expected_phrase_a),
        ("expected phrase B", config.expected_phrase_b),
    ):
        if value.strip() == "":
            raise AdapterStabilityError(f"{name} must be non-empty")
    for name, tokens in (
        ("challenge tokens A", config.challenge_tokens_a),
        ("challenge tokens B", config.challenge_tokens_b),
    ):
        if len(tokens) == 0:
            raise AdapterStabilityError(f"{name} must be non-empty")
        if any(re.fullmatch(r"[a-z0-9]+", token) is None for token in tokens):
            raise AdapterStabilityError(
                f"{name} must contain normalized English challenge tokens"
            )
    validate_probability(
        config.moonshine_intent_threshold,
        "Moonshine intent threshold",
    )
    validate_probability(
        config.moonshine_intent_margin,
        "Moonshine intent margin",
    )
    validate_tolerance(
        config.ecapa_absolute_tolerance,
        "ECAPA absolute tolerance",
    )
    validate_tolerance(
        config.aasist_absolute_tolerance,
        "AASIST absolute tolerance",
    )


def validate_tolerance(value: float, field_name: str) -> None:
    if (
        not math.isfinite(value)
        or value < 0
        or value > MAXIMUM_NUMERIC_STABILITY_TOLERANCE
    ):
        raise AdapterStabilityError(
            f"{field_name} must be between 0 and "
            f"{MAXIMUM_NUMERIC_STABILITY_TOLERANCE:g}"
        )


def validate_probability(value: float, field_name: str) -> None:
    if not math.isfinite(value) or value < 0 or value > 1:
        raise AdapterStabilityError(f"{field_name} must be a finite probability")


def require_file(path: Path, label: str) -> None:
    require_no_symlink_components(path, label)
    if path.is_symlink() or not path.is_file():
        raise AdapterStabilityError(f"{label} does not exist: {path}")


def require_directory_files(
    path: Path,
    label: str,
    required_names: tuple[str, ...],
) -> None:
    require_no_symlink_components(path, label)
    if path.is_symlink() or not path.is_dir():
        raise AdapterStabilityError(f"{label} does not exist: {path}")
    symlinks = tuple(child for child in path.rglob("*") if child.is_symlink())
    if len(symlinks) > 0:
        relative = symlinks[0].relative_to(path).as_posix()
        raise AdapterStabilityError(
            f"{label} contains a mutable symlink: {relative}"
        )
    missing = tuple(name for name in required_names if not (path / name).is_file())
    if len(missing) > 0:
        raise AdapterStabilityError(
            f"{label} is missing exact adapter files: {', '.join(missing)}"
        )


def flatten_adapter_violations(
    adapter_reports: dict[str, dict[str, Any]],
) -> list[str]:
    violations = []
    for adapter_name in ("moonshine", "ecapa", "aasist"):
        report = adapter_reports[adapter_name]
        report_violations = report.get("violations")
        if not isinstance(report_violations, list) or any(
            not isinstance(value, str)
            for value in report_violations
        ):
            raise AdapterStabilityError(
                f"{adapter_name} report violations are invalid"
            )
        violations.extend(report_violations)
    return violations


def file_binding(path: Path) -> dict[str, Any]:
    require_no_symlink_components(path, "bound file")
    if path.is_symlink() or not path.is_file():
        raise AdapterStabilityError(f"bound file does not exist: {path}")
    return {
        "sha256": sha256_file(path),
        "byteLength": path.stat().st_size,
    }


def tree_binding(path: Path) -> dict[str, Any]:
    require_no_symlink_components(path, "bound model directory")
    if path.is_symlink() or not path.is_dir():
        raise AdapterStabilityError(f"bound model directory does not exist: {path}")
    symlinks = tuple(child for child in path.rglob("*") if child.is_symlink())
    if len(symlinks) > 0:
        relative = symlinks[0].relative_to(path).as_posix()
        raise AdapterStabilityError(
            f"bound model directory contains a mutable symlink: {relative}"
        )
    files = tuple(
        child
        for child in sorted(path.rglob("*"))
        if included_model_file(path, child)
    )
    if len(files) == 0:
        raise AdapterStabilityError(f"bound model directory is empty: {path}")
    digest = hashlib.sha256()
    total_bytes = 0
    for child in files:
        relative = child.relative_to(path).as_posix()
        size = child.stat().st_size
        file_digest = sha256_file(child)
        digest.update(relative.encode("utf-8"))
        digest.update(b"\0")
        digest.update(str(size).encode("ascii"))
        digest.update(b"\0")
        digest.update(file_digest.encode("ascii"))
        digest.update(b"\n")
        total_bytes += size
    return {
        "treeSha256": digest.hexdigest(),
        "fileCount": len(files),
        "byteLength": total_bytes,
    }


def included_model_file(root: Path, path: Path) -> bool:
    if not path.is_file() or path.is_symlink():
        return False
    relative_parts = path.relative_to(root).parts
    if ".cache" in relative_parts:
        return False
    return not path.name.endswith(".lock")


def require_no_symlink_components(path: Path, label: str) -> None:
    absolute = path.expanduser().absolute()
    current = Path(absolute.anchor)
    for component in absolute.parts[1:]:
        current = current / component
        if current.is_symlink():
            raise AdapterStabilityError(
                f"{label} contains a mutable symlink component: {current}"
            )


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while True:
            chunk = source.read(1024 * 1024)
            if chunk == b"":
                return digest.hexdigest()
            digest.update(chunk)


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def hash_json(value: Any) -> str:
    encoded = json.dumps(
        value,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return sha256_bytes(encoded)


def hash_float_sequence(values: Sequence[float]) -> str:
    digest = hashlib.sha256()
    for value in values:
        numeric = float(value)
        if not math.isfinite(numeric):
            raise AdapterStabilityError("float sequence contains a non-finite value")
        digest.update(struct.pack(">d", numeric))
    return digest.hexdigest()


def zero_float_sequence(values: Any) -> None:
    for index in range(len(values)):
        values[index] = 0.0


def elapsed_ms(started: float) -> float:
    return (time.perf_counter() - started) * 1000


def write_json(path: Path, value: Any) -> None:
    encoded = json.dumps(
        value,
        allow_nan=False,
        indent=2,
        sort_keys=True,
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(encoded + "\n", encoding="utf-8")


def parse_args(argv: Sequence[str] | None = None) -> StabilityConfiguration:
    parser = argparse.ArgumentParser(
        description=(
            "Check warm Moonshine, ECAPA, and AASIST candidates for repeated-run, "
            "cross-input, and failure-recovery stability."
        )
    )
    parser.add_argument("--input-a", type=Path, required=True)
    parser.add_argument("--input-b", type=Path, required=True)
    parser.add_argument("--expected-phrase-a", required=True)
    parser.add_argument("--expected-phrase-b", required=True)
    parser.add_argument("--intent-a", choices=INTENT_NAMES, required=True)
    parser.add_argument("--intent-b", choices=INTENT_NAMES, required=True)
    parser.add_argument("--challenge-token-a", action="append", required=True)
    parser.add_argument("--challenge-token-b", action="append", required=True)
    parser.add_argument("--model-manifest", type=Path, required=True)
    parser.add_argument("--moonshine-model-path", type=Path, required=True)
    parser.add_argument(
        "--moonshine-model-arch",
        choices=("tiny_streaming", "small_streaming"),
        required=True,
    )
    parser.add_argument("--moonshine-intent-model-path", type=Path, required=True)
    parser.add_argument("--moonshine-intent-threshold", type=float, default=0.8)
    parser.add_argument("--moonshine-intent-margin", type=float, default=0.1)
    parser.add_argument("--ecapa-model-path", type=Path, required=True)
    parser.add_argument("--ecapa-absolute-tolerance", type=float, default=1.0e-6)
    parser.add_argument("--aasist-source-path", type=Path, required=True)
    parser.add_argument("--aasist-checkpoint-path", type=Path, required=True)
    parser.add_argument("--aasist-config-path", type=Path, required=True)
    parser.add_argument(
        "--aasist-device",
        choices=("auto", "cpu", "mps", "cuda"),
        default="auto",
    )
    parser.add_argument("--aasist-absolute-tolerance", type=float, default=1.0e-6)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args(argv)
    return StabilityConfiguration(
        input_a=args.input_a,
        input_b=args.input_b,
        expected_phrase_a=args.expected_phrase_a,
        expected_phrase_b=args.expected_phrase_b,
        intent_a=args.intent_a,
        intent_b=args.intent_b,
        challenge_tokens_a=tuple(args.challenge_token_a),
        challenge_tokens_b=tuple(args.challenge_token_b),
        model_manifest=args.model_manifest,
        moonshine_model_path=args.moonshine_model_path,
        moonshine_model_arch=args.moonshine_model_arch,
        moonshine_intent_model_path=args.moonshine_intent_model_path,
        moonshine_intent_threshold=args.moonshine_intent_threshold,
        moonshine_intent_margin=args.moonshine_intent_margin,
        ecapa_model_path=args.ecapa_model_path,
        ecapa_absolute_tolerance=args.ecapa_absolute_tolerance,
        aasist_source_path=args.aasist_source_path,
        aasist_checkpoint_path=args.aasist_checkpoint_path,
        aasist_config_path=args.aasist_config_path,
        aasist_device=args.aasist_device,
        aasist_absolute_tolerance=args.aasist_absolute_tolerance,
        output_path=args.out,
    )


def main(argv: Sequence[str] | None = None) -> int:
    config = parse_args(argv)
    report = run_real_candidate_check(config)
    write_json(config.output_path, report)
    return 0 if report["stable"] is True else 1


if __name__ == "__main__":
    raise SystemExit(main())
