from __future__ import annotations

import base64
import json
import os
import sys
import threading
import time
from array import array
from collections.abc import Sequence
from concurrent.futures import Future, ThreadPoolExecutor, wait
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Callable
from urllib.parse import urlparse

from voiceid_verifier.audio_decode import zero_float_sequence
from voiceid_verifier.audio_quality import AudioQuality, SpeechWindow
from voiceid_verifier.embeddings import EmbeddingExtractionError
from voiceid_verifier.enrollment import BuiltEnrollment, build_continuous_enrollment
from voiceid_verifier.moonshine import MoonshineRecognizer
from voiceid_verifier.pad import AasistPadDetector, PadDecision, PadDetector
from voiceid_verifier.runtime import AudioClaims, VerifierRuntime, create_verifier_runtime_from_env
from voiceid_verifier.schemas import (
    AudioMetadata,
    AudioQualityAccepted,
    AudioQualityRejected,
    AudioQualityResponse,
    AudioQualityUncertain,
    BuiltEnrollmentTemplateResponse,
    EnrollmentAnalysisResponse,
    EnrollmentSpeechWindowResponse,
    KnownChannelCount,
    KnownSampleRate,
    RejectedEnrollmentTemplateResponse,
    SpeakerAccepted,
    SpeakerRejected,
    SpeakerResponse,
    SpeakerUncertain,
    SpeakerVerificationResponse,
    SpeechAnalysisResponse,
    VerificationAnalysisResponse,
    VerifierSchemaError,
    parse_analyze_speech_request,
    parse_analyze_verification_request,
    parse_build_enrollment_template_request,
    parse_verify_speaker_request,
)
from voiceid_verifier.scoring import cosine_score


DEFAULT_RUNTIME: VerifierRuntime | None = None
DEFAULT_RUNTIME_LOCK = threading.Lock()
DEFAULT_MOONSHINE: MoonshineRecognizer | None = None
DEFAULT_MOONSHINE_LOCK = threading.Lock()
DEFAULT_PAD_DETECTOR: PadDetector | None = None
DEFAULT_PAD_LOCK = threading.Lock()


@dataclass(frozen=True)
class VerificationStageDeadlines:
    speech_ms: int
    speaker_ms: int
    pad_ms: int


@dataclass(frozen=True)
class TimedStageResult:
    completed_at: float
    value: Any


class BoundedStageExecutor:
    def __init__(self, maximum_active_stages: int) -> None:
        self._slots = threading.BoundedSemaphore(maximum_active_stages)
        self._executor = ThreadPoolExecutor(
            max_workers=maximum_active_stages,
            thread_name_prefix="voiceid-verification",
        )

    def submit(
        self,
        function: Callable[..., TimedStageResult],
        *args: Any,
    ) -> Future[TimedStageResult] | None:
        if not self._slots.acquire(blocking=False):
            return None
        try:
            future = self._executor.submit(function, *args)
        except Exception:
            self._slots.release()
            raise
        future.add_done_callback(self._release_slot)
        return future

    def _release_slot(self, _: Future[TimedStageResult]) -> None:
        self._slots.release()


VERIFICATION_STAGE_EXECUTOR = BoundedStageExecutor(maximum_active_stages=3)

JSON_HEADERS = {
    "Content-Type": "application/json",
}


def build_enrollment_template_from_json(
    value: dict[str, Any],
    *,
    runtime: VerifierRuntime | None = None,
) -> dict[str, Any]:
    active_runtime = runtime or get_default_runtime()
    request = parse_build_enrollment_template_request(value)
    result = build_continuous_enrollment(
        runtime=active_runtime,
        audio_bytes=request.audio.audio_bytes,
        claims=_audio_claims(request.audio.metadata),
        expected_prompt_count=request.expected_prompt_count,
    )
    if result.kind == "rejected":
        return RejectedEnrollmentTemplateResponse(
            kind="rejected",
            request_id=request.request_id,
            reason=result.reason,
        ).to_json()

    return BuiltEnrollmentTemplateResponse(
        kind="built",
        request_id=request.request_id,
        encrypted_template=result.encrypted_template,
        template_version=active_runtime.metadata.template_version,
        model_version=active_runtime.metadata.model_version,
        threshold_version=active_runtime.metadata.threshold_version,
        quality=_accepted_audio_quality(result),
        analysis=_enrollment_analysis_response(result),
    ).to_json()


def verify_speaker_from_json(
    value: dict[str, Any],
    *,
    runtime: VerifierRuntime | None = None,
) -> dict[str, Any]:
    active_runtime = runtime or get_default_runtime()
    request = parse_verify_speaker_request(value)
    evaluated = active_runtime.evaluate_audio(
        request.audio.audio_bytes,
        _audio_claims(request.audio.metadata),
    )
    runtime_embedding: list[float] = []
    template_embedding: list[float] = []
    try:
        quality = _audio_quality_response(evaluated.quality)
        if quality.kind != "accepted":
            speaker: SpeakerResponse = SpeakerUncertain(
                kind="uncertain",
                reason="low_audio_quality",
                score=0.0,
                threshold=request.threshold,
                model_version=active_runtime.metadata.model_version,
                threshold_version=active_runtime.metadata.threshold_version,
            )
        else:
            try:
                template_embedding = _decode_template_embedding(
                    encrypted_template=request.template.encrypted_template,
                    runtime=active_runtime,
                )
                if evaluated.decoded_audio is None:
                    raise ValueError("accepted verification audio requires decoded samples")
                runtime_embedding = active_runtime.extract_verification_embedding(
                    evaluated.speech_windows
                ).vector
                score = cosine_score(template_embedding, runtime_embedding)
            except (EmbeddingExtractionError, ValueError):
                speaker = SpeakerUncertain(
                    kind="uncertain",
                    reason="verifier_unavailable",
                    score=0.0,
                    threshold=request.threshold,
                    model_version=active_runtime.metadata.model_version,
                    threshold_version=active_runtime.metadata.threshold_version,
                )
            else:
                speaker = _speaker_result(
                    score=score,
                    threshold=request.threshold,
                    runtime=active_runtime,
                )
        return SpeakerVerificationResponse(
            kind="speaker_verification",
            request_id=request.request_id,
            quality=quality,
            speaker=speaker,
        ).to_json()
    finally:
        if evaluated.decoded_audio is not None:
            zero_float_sequence(evaluated.decoded_audio.samples)
        for window in evaluated.speech_windows:
            zero_float_sequence(window.samples)
        zero_float_sequence(runtime_embedding)
        zero_float_sequence(template_embedding)


def analyze_speech_from_json(
    value: dict[str, Any],
    *,
    runtime: VerifierRuntime | None = None,
    recognizer: MoonshineRecognizer | None = None,
) -> dict[str, Any]:
    request = parse_analyze_speech_request(value)
    active_runtime = runtime or get_default_runtime()
    active_recognizer = recognizer or get_default_moonshine()
    evaluated = active_runtime.evaluate_audio(
        request.audio.audio_bytes,
        _audio_claims(request.audio.metadata),
    )
    try:
        if evaluated.decoded_audio is None:
            raise RuntimeError("canonical PCM is unavailable for speech analysis")
        result = active_recognizer.analyze(
            evaluated.decoded_audio.samples,
            expected_phrase=request.expected_phrase,
            intent_name=request.intent_name,
            challenge_tokens=tuple(
                request.expected_phrase.lower().split()
            ),
        )
        return SpeechAnalysisResponse(
            kind="speech_analysis",
            request_id=request.request_id,
            transcript=result.transcript,
            phrase=result.phrase.to_json(),
            intent=result.intent.to_json(),
            sample_rate_hz=result.sample_rate_hz,
        ).to_json()
    finally:
        if evaluated.decoded_audio is not None:
            zero_float_sequence(evaluated.decoded_audio.samples)


def analyze_verification_from_json(
    value: dict[str, Any],
    *,
    runtime: VerifierRuntime | None = None,
    recognizer: MoonshineRecognizer | None = None,
    pad_detector: PadDetector | None = None,
    stage_deadlines: VerificationStageDeadlines | None = None,
) -> dict[str, Any]:
    request = parse_analyze_verification_request(value)
    active_runtime = runtime or get_default_runtime()
    active_recognizer = recognizer or get_default_moonshine()
    active_pad_detector = pad_detector if pad_detector is not None else configured_pad_detector()
    deadlines = stage_deadlines or verification_stage_deadlines_from_env()
    evaluated = active_runtime.evaluate_audio(
        request.audio.audio_bytes,
        _audio_claims(request.audio.metadata),
    )
    try:
        quality = _audio_quality_response(evaluated.quality)
        if quality.kind != "accepted" or evaluated.decoded_audio is None:
            speaker: SpeakerResponse = SpeakerUncertain(
                kind="uncertain",
                reason="low_audio_quality",
                score=0.0,
                threshold=request.threshold,
                model_version=active_runtime.metadata.model_version,
                threshold_version=active_runtime.metadata.threshold_version,
            )
            speech = _unavailable_speech_analysis(request.expected_phrase)
            pad = _unavailable_pad("low_audio_quality", detector=active_pad_detector)
        else:
            speech_samples = array("f", evaluated.decoded_audio.samples)
            shared_speech_samples = accepted_speech_samples(evaluated.speech_windows)
            speaker_samples = array("f", shared_speech_samples)
            pad_samples = array("f", shared_speech_samples)
            zero_float_sequence(shared_speech_samples)
            started_at = time.monotonic()
            speech_future = VERIFICATION_STAGE_EXECUTOR.submit(
                _analyze_speech_timed,
                active_recognizer,
                speech_samples,
                request.expected_phrase,
                request.intent_name,
                request.challenge_tokens,
            )
            speaker_future = VERIFICATION_STAGE_EXECUTOR.submit(
                _analyze_speaker_timed,
                active_runtime,
                speaker_samples,
                request.template.encrypted_template,
                request.threshold,
            )
            pad_future = (
                VERIFICATION_STAGE_EXECUTOR.submit(
                    _analyze_pad_timed,
                    active_pad_detector,
                    pad_samples,
                )
                if active_pad_detector is not None
                else None
            )
            if active_pad_detector is None:
                zero_float_sequence(pad_samples)
            if speech_future is None:
                zero_float_sequence(speech_samples)
            if speaker_future is None:
                zero_float_sequence(speaker_samples)
            if active_pad_detector is not None and pad_future is None:
                zero_float_sequence(pad_samples)
            submitted_futures = tuple(
                future
                for future in (speech_future, speaker_future, pad_future)
                if future is not None
            )
            wait(
                submitted_futures,
                timeout=max(deadlines.speech_ms, deadlines.speaker_ms, deadlines.pad_ms)
                / 1000,
            )
            speech = resolve_speech_stage(
                speech_future,
                started_at=started_at,
                deadline_ms=deadlines.speech_ms,
                expected_phrase=request.expected_phrase,
            )
            speaker = resolve_speaker_stage(
                speaker_future,
                started_at=started_at,
                deadline_ms=deadlines.speaker_ms,
                runtime=active_runtime,
                threshold=request.threshold,
            )
            pad = resolve_pad_stage(
                pad_future,
                started_at=started_at,
                deadline_ms=deadlines.pad_ms,
                detector=active_pad_detector,
            )
        return VerificationAnalysisResponse(
            kind="verification_analysis",
            request_id=request.request_id,
            quality=quality.to_json(),
            speaker=speaker.to_json(),
            speech=speech,
            pad=pad,
        ).to_json()
    finally:
        if evaluated.decoded_audio is not None:
            zero_float_sequence(evaluated.decoded_audio.samples)
        for window in evaluated.speech_windows:
            zero_float_sequence(window.samples)


def _analyze_speaker(
    runtime: VerifierRuntime,
    samples: Sequence[float],
    encrypted_template: str,
    threshold: float,
) -> SpeakerResponse:
    runtime_embedding: list[float] = []
    template_embedding: list[float] = []
    try:
        template_embedding = _decode_template_embedding(
            encrypted_template=encrypted_template,
            runtime=runtime,
        )
        runtime_embedding = runtime.extract_window_embedding(samples).vector
        score = cosine_score(template_embedding, runtime_embedding)
        return _speaker_result(
            score=score,
            threshold=threshold,
            runtime=runtime,
        )
    except Exception:
        return SpeakerUncertain(
            kind="uncertain",
            reason="verifier_unavailable",
            score=0.0,
            threshold=threshold,
            model_version=runtime.metadata.model_version,
            threshold_version=runtime.metadata.threshold_version,
        )
    finally:
        zero_float_sequence(runtime_embedding)
        zero_float_sequence(template_embedding)
        zero_float_sequence(samples)


def _analyze_speech(
    recognizer: MoonshineRecognizer,
    samples: Sequence[float],
    expected_phrase: str,
    intent_name: str,
    challenge_tokens: tuple[str, ...],
) -> dict[str, Any]:
    try:
        return recognizer.analyze(
            samples,
            expected_phrase=expected_phrase,
            intent_name=intent_name,
            challenge_tokens=challenge_tokens,
        ).to_json()
    except Exception:
        return _unavailable_speech_analysis(expected_phrase)
    finally:
        zero_float_sequence(samples)


def _analyze_pad(detector: PadDetector, samples: Sequence[float]) -> dict[str, Any]:
    try:
        return detector.analyze(samples).to_json()
    except Exception:
        return _unavailable_pad("model_unavailable", detector=detector)
    finally:
        zero_float_sequence(samples)


def _analyze_speech_timed(
    recognizer: MoonshineRecognizer,
    samples: Sequence[float],
    expected_phrase: str,
    intent_name: str,
    challenge_tokens: tuple[str, ...],
) -> TimedStageResult:
    value = _analyze_speech(
        recognizer,
        samples,
        expected_phrase,
        intent_name,
        challenge_tokens,
    )
    return TimedStageResult(completed_at=time.monotonic(), value=value)


def _analyze_speaker_timed(
    runtime: VerifierRuntime,
    samples: Sequence[float],
    encrypted_template: str,
    threshold: float,
) -> TimedStageResult:
    value = _analyze_speaker(runtime, samples, encrypted_template, threshold)
    return TimedStageResult(completed_at=time.monotonic(), value=value)


def _analyze_pad_timed(
    detector: PadDetector,
    samples: Sequence[float],
) -> TimedStageResult:
    value = _analyze_pad(detector, samples)
    return TimedStageResult(completed_at=time.monotonic(), value=value)


def accepted_speech_samples(speech_windows: Sequence[SpeechWindow]) -> array:
    if len(speech_windows) == 0:
        raise ValueError("accepted speech windows are required")
    samples = array("f")
    for window in speech_windows:
        samples.extend(window.samples)
    return samples


def resolve_speech_stage(
    future: Future[TimedStageResult] | None,
    *,
    started_at: float,
    deadline_ms: int,
    expected_phrase: str,
) -> dict[str, Any]:
    result = resolve_stage(future, started_at=started_at, deadline_ms=deadline_ms)
    if result is None or not isinstance(result.value, dict):
        return _unavailable_speech_analysis(expected_phrase)
    return result.value


def resolve_speaker_stage(
    future: Future[TimedStageResult] | None,
    *,
    started_at: float,
    deadline_ms: int,
    runtime: VerifierRuntime,
    threshold: float,
) -> SpeakerResponse:
    result = resolve_stage(future, started_at=started_at, deadline_ms=deadline_ms)
    if result is not None and isinstance(
        result.value,
        (SpeakerAccepted, SpeakerRejected, SpeakerUncertain),
    ):
        return result.value
    return SpeakerUncertain(
        kind="uncertain",
        reason="verifier_unavailable",
        score=0.0,
        threshold=threshold,
        model_version=runtime.metadata.model_version,
        threshold_version=runtime.metadata.threshold_version,
    )


def resolve_pad_stage(
    future: Future[TimedStageResult] | None,
    *,
    started_at: float,
    deadline_ms: int,
    detector: PadDetector | None,
) -> dict[str, Any]:
    if detector is None:
        return _unavailable_pad("model_unavailable")
    result = resolve_stage(future, started_at=started_at, deadline_ms=deadline_ms)
    if result is not None and isinstance(result.value, dict):
        return result.value
    reason = "overloaded" if future is None else "deadline_exceeded"
    return _unavailable_pad(reason, detector=detector)


def resolve_stage(
    future: Future[TimedStageResult] | None,
    *,
    started_at: float,
    deadline_ms: int,
) -> TimedStageResult | None:
    if future is None:
        return None
    if not future.done():
        future.cancel()
        return None
    try:
        result = future.result()
    except Exception:
        return None
    elapsed_ms = (result.completed_at - started_at) * 1000
    return result if elapsed_ms <= deadline_ms else None


def _unavailable_pad(
    reason: str,
    *,
    detector: PadDetector | None = None,
) -> dict[str, Any]:
    if detector is None:
        return {"kind": "pad_unavailable", "reason": "ordinary_browser_capture"}
    return {
        "kind": "uncertain",
        "reason": reason,
        "score": 0.0,
        "rejectThreshold": detector.reject_threshold,
        "acceptThreshold": detector.accept_threshold,
        "modelVersion": detector.model_version,
        "calibrationVersion": detector.calibration_version,
        "latencyMs": 0.0,
    }


def _unavailable_speech_analysis(expected_phrase: str) -> dict[str, Any]:
    normalized = " ".join(expected_phrase.lower().split())
    return {
        "kind": "speech_analysis",
        "requestId": "unavailable",
        "transcript": "",
        "phrase": {
            "kind": "uncertain",
            "expectedNormalized": normalized,
            "spokenNormalized": "",
            "confidence": 0.0,
        },
        "intent": {
            "kind": "uncertain",
            "intent": None,
            "canonicalPhrase": None,
            "confidence": 0.0,
            "reason": "intent_unavailable",
        },
        "sampleRateHz": 16000,
    }


def get_default_runtime() -> VerifierRuntime:
    global DEFAULT_RUNTIME
    if DEFAULT_RUNTIME is not None:
        return DEFAULT_RUNTIME
    with DEFAULT_RUNTIME_LOCK:
        if DEFAULT_RUNTIME is None:
            DEFAULT_RUNTIME = create_verifier_runtime_from_env()
    return DEFAULT_RUNTIME


def get_default_moonshine() -> MoonshineRecognizer:
    global DEFAULT_MOONSHINE
    if DEFAULT_MOONSHINE is not None:
        return DEFAULT_MOONSHINE
    with DEFAULT_MOONSHINE_LOCK:
        if DEFAULT_MOONSHINE is None:
            model_path = os.environ.get("VOICEID_MOONSHINE_MODEL_PATH", "").strip()
            intent_model_path = os.environ.get("VOICEID_MOONSHINE_INTENT_MODEL_PATH", "").strip()
            if model_path == "" or intent_model_path == "":
                raise RuntimeError(
                    "VOICEID_MOONSHINE_MODEL_PATH and VOICEID_MOONSHINE_INTENT_MODEL_PATH are required"
                )
            DEFAULT_MOONSHINE = MoonshineRecognizer(
                model_path=model_path,
                model_arch=os.environ.get("VOICEID_MOONSHINE_MODEL_ARCH", "tiny_streaming"),
                intent_model_path=intent_model_path,
                intent_threshold=float(os.environ.get("VOICEID_MOONSHINE_INTENT_THRESHOLD", "0.8")),
                intent_margin=float(os.environ.get("VOICEID_MOONSHINE_INTENT_MARGIN", "0.1")),
            )
    return DEFAULT_MOONSHINE


def get_default_pad_detector() -> PadDetector:
    global DEFAULT_PAD_DETECTOR
    if DEFAULT_PAD_DETECTOR is not None:
        return DEFAULT_PAD_DETECTOR
    with DEFAULT_PAD_LOCK:
        if DEFAULT_PAD_DETECTOR is None:
            source_path = required_path_from_env("VOICEID_PAD_AASIST_SOURCE_PATH")
            checkpoint_path = required_path_from_env("VOICEID_PAD_AASIST_CHECKPOINT_PATH")
            config_path = required_path_from_env("VOICEID_PAD_AASIST_CONFIG_PATH")
            DEFAULT_PAD_DETECTOR = AasistPadDetector(
                source_path=source_path,
                checkpoint_path=checkpoint_path,
                config_path=config_path,
                device_name=os.environ.get("VOICEID_PAD_DEVICE", "auto"),
                reject_threshold=probability_from_env(
                    "VOICEID_PAD_REJECT_THRESHOLD",
                    0.35,
                ),
                accept_threshold=probability_from_env(
                    "VOICEID_PAD_ACCEPT_THRESHOLD",
                    0.65,
                ),
                calibration_version=os.environ.get(
                    "VOICEID_PAD_CALIBRATION_VERSION",
                    "aasist-research-uncalibrated-v1",
                ),
            )
    return DEFAULT_PAD_DETECTOR


def _audio_claims(metadata: AudioMetadata) -> AudioClaims:
    sample_rate_hz = metadata.sample_rate.hertz if isinstance(metadata.sample_rate, KnownSampleRate) else None
    channel_count = metadata.channel_count.count if isinstance(metadata.channel_count, KnownChannelCount) else None
    return AudioClaims(
        mime_type=metadata.mime_type,
        duration_ms=metadata.duration_ms,
        sample_rate_hz=sample_rate_hz,
        channel_count=channel_count,
    )


def _accepted_audio_quality(result: BuiltEnrollment) -> AudioQualityAccepted:
    quality = result.quality
    if quality.kind != "accepted" or quality.signal_score is None:
        raise RuntimeError("built enrollment requires accepted audio quality")
    return AudioQualityAccepted(
        kind="accepted",
        duration_ms=quality.duration_ms,
        signal_score=quality.signal_score,
    )


def _enrollment_analysis_response(result: BuiltEnrollment) -> EnrollmentAnalysisResponse:
    return EnrollmentAnalysisResponse(
        analysis_version="continuous-enrollment-v1",
        source_codec=result.analysis.source_codec,
        source_sample_rate_hz=result.analysis.source_sample_rate_hz,
        source_channel_count=result.analysis.source_channel_count,
        decoded_duration_ms=result.analysis.decoded_duration_ms,
        usable_speech_ms=result.analysis.usable_speech_ms,
        windows=tuple(
            EnrollmentSpeechWindowResponse(
                index=window.index,
                start_ms=window.start_ms,
                end_ms=window.end_ms,
                speech_ms=window.speech_ms,
                signal_score=window.signal_score,
                template_weight=window.template_weight,
            )
            for window in result.analysis.windows
        ),
    )


def _audio_quality_response(quality: AudioQuality) -> AudioQualityResponse:
    if quality.kind == "accepted":
        if quality.signal_score is None:
            raise ValueError("accepted audio quality requires signal score")
        return AudioQualityAccepted(
            kind="accepted",
            duration_ms=quality.duration_ms,
            signal_score=quality.signal_score,
        )
    if quality.kind == "rejected":
        return AudioQualityRejected(
            kind="rejected",
            reason=quality.reason,
            duration_ms=quality.duration_ms,
        )
    return AudioQualityUncertain(
        kind="uncertain",
        reason=quality.reason,
        duration_ms=quality.duration_ms,
    )


def _speaker_result(*, score: float, threshold: float, runtime: VerifierRuntime) -> SpeakerResponse:
    if score >= threshold:
        return SpeakerAccepted(
            kind="accepted",
            score=score,
            threshold=threshold,
            model_version=runtime.metadata.model_version,
            threshold_version=runtime.metadata.threshold_version,
        )
    if score >= threshold - 0.05:
        return SpeakerUncertain(
            kind="uncertain",
            reason="model_low_confidence",
            score=score,
            threshold=threshold,
            model_version=runtime.metadata.model_version,
            threshold_version=runtime.metadata.threshold_version,
        )
    return SpeakerRejected(
        kind="rejected",
        reason="speaker_mismatch",
        score=score,
        threshold=threshold,
        model_version=runtime.metadata.model_version,
        threshold_version=runtime.metadata.threshold_version,
    )


def _decode_template_embedding(
    *,
    encrypted_template: str,
    runtime: VerifierRuntime,
) -> list[float]:
    decoded = json.loads(base64.b64decode(encrypted_template, validate=True).decode("utf-8"))
    if not isinstance(decoded, dict):
        raise ValueError("template payload must be an object")
    expected_keys = {
        "adapterId",
        "modelId",
        "modelVersion",
        "thresholdVersion",
        "templateVersion",
        "sampleCount",
        "embeddingDimensions",
        "embedding",
    }
    if set(decoded.keys()) != expected_keys:
        raise ValueError("template payload contains unexpected or missing fields")
    expected_values = {
        "adapterId": runtime.metadata.adapter_id,
        "modelId": runtime.metadata.model_id,
        "modelVersion": runtime.metadata.model_version,
        "thresholdVersion": runtime.metadata.threshold_version,
        "templateVersion": runtime.metadata.template_version,
    }
    for field_name, expected_value in expected_values.items():
        if decoded[field_name] != expected_value:
            raise ValueError(f"template payload {field_name} does not match verifier runtime")
    embedding = decoded["embedding"]
    dimensions = decoded["embeddingDimensions"]
    sample_count = decoded["sampleCount"]
    if not _is_positive_int(dimensions):
        raise ValueError("template payload embeddingDimensions must be positive")
    if dimensions != runtime.metadata.embedding_dimensions:
        raise ValueError("template payload embeddingDimensions does not match verifier runtime")
    if not _is_positive_int(sample_count):
        raise ValueError("template payload sampleCount must be positive")
    if not isinstance(embedding, list) or len(embedding) != dimensions:
        raise ValueError("template payload embedding dimensions are invalid")
    if not all(_is_number(value) for value in embedding):
        raise ValueError("template payload embedding values must be numbers")
    return [float(value) for value in embedding]


def _is_number(value: object) -> bool:
    return isinstance(value, int | float) and not isinstance(value, bool)


def _is_positive_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value > 0


def main() -> None:
    if len(sys.argv) != 2 or sys.argv[1] != "serve_http":
        raise SystemExit("VoiceID verifier requires the serve_http operation")
    run_http_server_from_env()


def handle_http_operation(
    path: str,
    request: dict[str, Any],
    *,
    runtime: VerifierRuntime | None = None,
    recognizer: MoonshineRecognizer | None = None,
    pad_detector: PadDetector | None = None,
) -> dict[str, Any]:
    operation = _operation_for_path(path)
    if operation == "build_enrollment_template":
        return build_enrollment_template_from_json(request, runtime=runtime)
    if operation == "verify_speaker":
        return verify_speaker_from_json(request, runtime=runtime)
    if operation == "analyze_speech":
        return analyze_speech_from_json(request, runtime=runtime, recognizer=recognizer)
    if operation == "analyze_verification":
        return analyze_verification_from_json(
            request,
            runtime=runtime,
            recognizer=recognizer,
            pad_detector=pad_detector,
        )
    raise ValueError("unknown verifier operation")


class VoiceIdVerifierHttpServer(ThreadingHTTPServer):
    def __init__(
        self,
        server_address: tuple[str, int],
        runtime: VerifierRuntime | None = None,
        *,
        maximum_concurrent_inferences: int = 1,
        queue_wait_ms: int = 250,
    ) -> None:
        if maximum_concurrent_inferences <= 0:
            raise ValueError("maximum_concurrent_inferences must be positive")
        if queue_wait_ms < 0:
            raise ValueError("queue_wait_ms must be non-negative")
        self.verifier_runtime = runtime or get_default_runtime()
        self.maximum_concurrent_inferences = maximum_concurrent_inferences
        self.queue_wait_ms = queue_wait_ms
        self.moonshine_recognizer = configured_moonshine_recognizer()
        self.pad_detector = configured_pad_detector()
        self._inference_slots = threading.BoundedSemaphore(maximum_concurrent_inferences)
        super().__init__(server_address, VoiceIdVerifierHttpHandler)

    def acquire_inference_slot(self) -> bool:
        return self._inference_slots.acquire(timeout=self.queue_wait_ms / 1000)

    def release_inference_slot(self) -> None:
        self._inference_slots.release()

    def health_response(self) -> dict[str, Any]:
        metadata = self.verifier_runtime.metadata
        return {
            "kind": "ok",
            "service": "voice-id-verifier",
            "readiness": "ready",
            "runtime": {
                "backend": metadata.backend,
                "adapterId": metadata.adapter_id,
                "modelId": metadata.model_id,
                "modelVersion": metadata.model_version,
                "thresholdVersion": metadata.threshold_version,
                "templateVersion": metadata.template_version,
                "embeddingDimensions": metadata.embedding_dimensions,
                "maximumConcurrentInferences": self.maximum_concurrent_inferences,
                "queueWaitMs": self.queue_wait_ms,
            },
            "routes": [
                "POST /voice-id/verifier/build-enrollment-template",
                "POST /voice-id/verifier/verify-speaker",
                "POST /voice-id/verifier/analyze-speech",
                "POST /voice-id/verifier/analyze-verification",
            ],
            "moonshine": {
                "readiness": "ready" if self.moonshine_recognizer is not None else "disabled",
                "modelArch": os.environ.get("VOICEID_MOONSHINE_MODEL_ARCH", "tiny_streaming"),
            },
            "pad": {
                "readiness": "ready" if self.pad_detector is not None else "disabled",
                "modelVersion": (
                    self.pad_detector.model_version
                    if self.pad_detector is not None
                    else None
                ),
                "calibrationVersion": (
                    self.pad_detector.calibration_version
                    if self.pad_detector is not None
                    else None
                ),
            },
        }


class VoiceIdVerifierHttpHandler(BaseHTTPRequestHandler):
    server_version = "VoiceIdVerifierHTTP/0.3"

    def do_GET(self) -> None:
        path = urlparse(self.path).path.rstrip("/")
        if path in ("", "/health"):
            self._write_json(200, self._verifier_server().health_response())
            return
        self._write_json(404, {"kind": "error", "error": {"kind": "not_found"}})

    def do_POST(self) -> None:
        server = self._verifier_server()
        admitted = False
        try:
            request = self._read_json_request()
            admitted = server.acquire_inference_slot()
            if not admitted:
                self._write_json(503, verifier_overloaded(server.queue_wait_ms))
                return
            response = handle_http_operation(
                self.path,
                request,
                runtime=server.verifier_runtime,
                recognizer=server.moonshine_recognizer,
                pad_detector=server.pad_detector,
            )
        except VerifierSchemaError as error:
            self._write_json(400, malformed_request(error))
            return
        except (json.JSONDecodeError, ValueError) as error:
            self._write_json(400, malformed_request(error))
            return
        except Exception as error:
            self._write_json(500, verifier_error(error))
            return
        finally:
            if admitted:
                server.release_inference_slot()
        self._write_json(200, response)

    def log_message(self, format: str, *args: Any) -> None:
        return

    def _verifier_server(self) -> VoiceIdVerifierHttpServer:
        if not isinstance(self.server, VoiceIdVerifierHttpServer):
            raise RuntimeError("VoiceID verifier handler requires VoiceIdVerifierHttpServer")
        return self.server

    def _read_json_request(self) -> dict[str, Any]:
        content_length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(content_length)
        value = json.loads(body.decode("utf-8"))
        if not isinstance(value, dict):
            raise ValueError("request body must be a JSON object")
        return value

    def _write_json(self, status: int, value: dict[str, Any]) -> None:
        body = json.dumps(value, separators=(",", ":")).encode("utf-8")
        self.send_response(status)
        for name, header_value in JSON_HEADERS.items():
            self.send_header(name, header_value)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def run_http_server_from_env() -> None:
    host = os.environ.get("VOICEID_VERIFIER_HOST", "127.0.0.1")
    port = int(os.environ.get("VOICEID_VERIFIER_PORT", "5051"))
    maximum_concurrent_inferences = positive_int_from_env(
        "VOICEID_VERIFIER_MAX_CONCURRENT_INFERENCES",
        1,
    )
    queue_wait_ms = non_negative_int_from_env("VOICEID_VERIFIER_QUEUE_WAIT_MS", 250)
    run_http_server(
        host=host,
        port=port,
        maximum_concurrent_inferences=maximum_concurrent_inferences,
        queue_wait_ms=queue_wait_ms,
    )


def configured_moonshine_recognizer() -> MoonshineRecognizer | None:
    model_path = os.environ.get("VOICEID_MOONSHINE_MODEL_PATH", "").strip()
    intent_model_path = os.environ.get("VOICEID_MOONSHINE_INTENT_MODEL_PATH", "").strip()
    if model_path == "" and intent_model_path == "":
        return None
    return get_default_moonshine()


def configured_pad_detector() -> PadDetector | None:
    paths = tuple(
        os.environ.get(name, "").strip()
        for name in (
            "VOICEID_PAD_AASIST_SOURCE_PATH",
            "VOICEID_PAD_AASIST_CHECKPOINT_PATH",
            "VOICEID_PAD_AASIST_CONFIG_PATH",
        )
    )
    if all(path == "" for path in paths):
        return None
    if any(path == "" for path in paths):
        raise RuntimeError(
            "VOICEID_PAD_AASIST_SOURCE_PATH, VOICEID_PAD_AASIST_CHECKPOINT_PATH, "
            "and VOICEID_PAD_AASIST_CONFIG_PATH must be configured together"
        )
    return get_default_pad_detector()


def verification_stage_deadlines_from_env() -> VerificationStageDeadlines:
    return VerificationStageDeadlines(
        speech_ms=positive_int_from_env("VOICEID_SPEECH_DEADLINE_MS", 900),
        speaker_ms=positive_int_from_env("VOICEID_SPEAKER_DEADLINE_MS", 900),
        pad_ms=positive_int_from_env("VOICEID_PAD_DEADLINE_MS", 900),
    )


def run_http_server(
    *,
    host: str,
    port: int,
    maximum_concurrent_inferences: int,
    queue_wait_ms: int,
) -> None:
    server = VoiceIdVerifierHttpServer(
        (host, port),
        maximum_concurrent_inferences=maximum_concurrent_inferences,
        queue_wait_ms=queue_wait_ms,
    )
    print(f"VoiceID verifier sidecar listening on http://{host}:{port}", flush=True)
    server.serve_forever()


def malformed_request(error: Exception) -> dict[str, Any]:
    return {
        "kind": "error",
        "error": {"kind": "malformed_request", "message": str(error)},
    }


def verifier_error(error: Exception) -> dict[str, Any]:
    return {
        "kind": "error",
        "error": {"kind": "verifier_unavailable", "message": str(error)},
    }


def verifier_overloaded(queue_wait_ms: int) -> dict[str, Any]:
    return {
        "kind": "error",
        "error": {
            "kind": "overloaded",
            "message": f"verifier queue did not admit the request within {queue_wait_ms}ms",
        },
    }


def positive_int_from_env(name: str, default: int) -> int:
    value = int(os.environ.get(name, str(default)))
    if value <= 0:
        raise ValueError(f"{name} must be positive")
    return value


def non_negative_int_from_env(name: str, default: int) -> int:
    value = int(os.environ.get(name, str(default)))
    if value < 0:
        raise ValueError(f"{name} must be non-negative")
    return value


def probability_from_env(name: str, default: float) -> float:
    value = float(os.environ.get(name, str(default)))
    if value < 0 or value > 1:
        raise ValueError(f"{name} must be a probability")
    return value


def required_path_from_env(name: str) -> Path:
    value = os.environ.get(name, "").strip()
    if value == "":
        raise RuntimeError(f"{name} is required")
    return Path(value).expanduser().resolve()


def _operation_for_path(path: str) -> str:
    normalized_path = urlparse(path).path.rstrip("/")
    if normalized_path.endswith("/build-enrollment-template"):
        return "build_enrollment_template"
    if normalized_path.endswith("/verify-speaker"):
        return "verify_speaker"
    if normalized_path.endswith("/analyze-speech"):
        return "analyze_speech"
    if normalized_path.endswith("/analyze-verification"):
        return "analyze_verification"
    raise ValueError("unknown verifier operation")


if __name__ == "__main__":
    main()
