from __future__ import annotations

import hashlib
import json
import math
import threading
import time
from array import array
from dataclasses import dataclass
from pathlib import Path
from types import ModuleType
from typing import Any, Literal, Protocol, Sequence

from voiceid_verifier.audio_decode import zero_float_sequence


AASIST_MODEL_VERSION = "aasist-asvspoof2019-la-a04c9863"
AASIST_CALIBRATION_VERSION = "aasist-research-uncalibrated-v1"
AASIST_SOURCE_SHA256 = "9e0d3e80937dd0577beea7883098465a479da23a198ebc0d712abcc59b0bec50"
AASIST_CHECKPOINT_SHA256 = "51d2d9cf0738172f61e2a384ec50a54a55363240f67c971ed55a92435bc1a1c0"
AASIST_CONFIG_SHA256 = "c25023331685027cce90e1b9a0d2df10aa04b2a27d9b27d5afa36e6815b0fe76"
AASIST_SAMPLE_COUNT = 64_600


PadDecisionKind = Literal["accepted", "rejected", "uncertain"]
PadUncertainReason = Literal["model_low_confidence", "model_unavailable"]


@dataclass(frozen=True)
class PadDecision:
    kind: PadDecisionKind
    score: float
    reject_threshold: float
    accept_threshold: float
    model_version: str
    calibration_version: str
    latency_ms: float
    reason: Literal["presentation_attack"] | PadUncertainReason | None

    def to_json(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "kind": self.kind,
            "score": self.score,
            "rejectThreshold": self.reject_threshold,
            "acceptThreshold": self.accept_threshold,
            "modelVersion": self.model_version,
            "calibrationVersion": self.calibration_version,
            "latencyMs": self.latency_ms,
        }
        if self.reason is not None:
            result["reason"] = self.reason
        return result


class PadDetector(Protocol):
    model_version: str
    calibration_version: str
    reject_threshold: float
    accept_threshold: float

    def analyze(self, samples: Sequence[float]) -> PadDecision:
        ...


class AasistPadDetector:
    model_version = AASIST_MODEL_VERSION

    def __init__(
        self,
        *,
        source_path: Path,
        checkpoint_path: Path,
        config_path: Path,
        device_name: str,
        reject_threshold: float,
        accept_threshold: float,
        calibration_version: str = AASIST_CALIBRATION_VERSION,
    ) -> None:
        validate_thresholds(reject_threshold, accept_threshold)
        verify_file(source_path, AASIST_SOURCE_SHA256, "AASIST source")
        verify_file(checkpoint_path, AASIST_CHECKPOINT_SHA256, "AASIST checkpoint")
        verify_file(config_path, AASIST_CONFIG_SHA256, "AASIST config")
        torch = import_torch()
        device = resolve_device(torch, device_name)
        model_config = load_model_config(config_path)
        model_class = load_aasist_model_class(source_path)
        model = model_class(model_config)
        state = torch.load(checkpoint_path, map_location=device, weights_only=True)
        model.load_state_dict(state)
        model.to(device)
        model.eval()
        self._torch = torch
        self._device = device
        self._model = model
        self._lock = threading.Lock()
        self.reject_threshold = reject_threshold
        self.accept_threshold = accept_threshold
        self.calibration_version = calibration_version

    def analyze(self, samples: Sequence[float]) -> PadDecision:
        with self._lock:
            return self._analyze_locked(samples)

    def _analyze_locked(self, samples: Sequence[float]) -> PadDecision:
        started = time.perf_counter()
        prepared = prepare_aasist_samples(samples)
        input_tensor = None
        feature_tensor = None
        logits = None
        probabilities = None
        try:
            input_tensor = self._torch.tensor(
                prepared,
                dtype=self._torch.float32,
                device=self._device,
            ).unsqueeze(0)
            with self._torch.inference_mode():
                feature_tensor, logits = self._model(input_tensor)
                probabilities = self._torch.softmax(logits, dim=1)
                score = float(probabilities[0, 1].item())
            return classify_pad_score(
                score=score,
                reject_threshold=self.reject_threshold,
                accept_threshold=self.accept_threshold,
                model_version=self.model_version,
                calibration_version=self.calibration_version,
                latency_ms=(time.perf_counter() - started) * 1000,
            )
        except Exception:
            return PadDecision(
                kind="uncertain",
                score=0.0,
                reject_threshold=self.reject_threshold,
                accept_threshold=self.accept_threshold,
                model_version=self.model_version,
                calibration_version=self.calibration_version,
                latency_ms=(time.perf_counter() - started) * 1000,
                reason="model_unavailable",
            )
        finally:
            try:
                zero_tensors(
                    self._torch,
                    (probabilities, logits, feature_tensor, input_tensor),
                )
            finally:
                zero_float_sequence(prepared)


def classify_pad_score(
    *,
    score: float,
    reject_threshold: float,
    accept_threshold: float,
    model_version: str,
    calibration_version: str,
    latency_ms: float,
) -> PadDecision:
    validate_thresholds(reject_threshold, accept_threshold)
    if not math.isfinite(score) or score < 0 or score > 1:
        raise ValueError("PAD score must be a finite probability")
    if score <= reject_threshold:
        return PadDecision(
            kind="rejected",
            score=score,
            reject_threshold=reject_threshold,
            accept_threshold=accept_threshold,
            model_version=model_version,
            calibration_version=calibration_version,
            latency_ms=latency_ms,
            reason="presentation_attack",
        )
    if score < accept_threshold:
        return PadDecision(
            kind="uncertain",
            score=score,
            reject_threshold=reject_threshold,
            accept_threshold=accept_threshold,
            model_version=model_version,
            calibration_version=calibration_version,
            latency_ms=latency_ms,
            reason="model_low_confidence",
        )
    return PadDecision(
        kind="accepted",
        score=score,
        reject_threshold=reject_threshold,
        accept_threshold=accept_threshold,
        model_version=model_version,
        calibration_version=calibration_version,
        latency_ms=latency_ms,
        reason=None,
    )


def prepare_aasist_samples(samples: Sequence[float]) -> array[float]:
    if len(samples) == 0:
        raise ValueError("PAD requires accepted speech samples")
    prepared = array("f")
    if len(samples) >= AASIST_SAMPLE_COUNT:
        prepared.extend(samples[:AASIST_SAMPLE_COUNT])
        return prepared
    repeat_count = (AASIST_SAMPLE_COUNT // len(samples)) + 1
    for _ in range(repeat_count):
        prepared.extend(samples)
        if len(prepared) >= AASIST_SAMPLE_COUNT:
            del prepared[AASIST_SAMPLE_COUNT:]
            return prepared
    raise RuntimeError("failed to prepare AASIST input")


def zero_tensors(torch: Any, tensors: Sequence[Any | None]) -> None:
    first_error: Exception | None = None
    with torch.inference_mode():
        for tensor in tensors:
            if tensor is None:
                continue
            try:
                tensor.zero_()
            except Exception as error:
                if first_error is None:
                    first_error = error
    if first_error is not None:
        raise RuntimeError("failed to zero PAD model tensors") from first_error


def validate_thresholds(reject_threshold: float, accept_threshold: float) -> None:
    for name, value in (
        ("reject_threshold", reject_threshold),
        ("accept_threshold", accept_threshold),
    ):
        if not math.isfinite(value) or value < 0 or value > 1:
            raise ValueError(f"{name} must be a finite probability")
    if reject_threshold >= accept_threshold:
        raise ValueError("reject_threshold must be less than accept_threshold")


def verify_file(path: Path, expected_sha256: str, label: str) -> None:
    if not path.is_file():
        raise FileNotFoundError(f"{label} does not exist: {path}")
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    if digest != expected_sha256:
        raise ValueError(f"{label} SHA-256 mismatch")


def load_model_config(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict) or not isinstance(value.get("model_config"), dict):
        raise ValueError("AASIST config requires model_config")
    return value["model_config"]


def load_aasist_model_class(source_path: Path) -> type[Any]:
    module = ModuleType("voiceid_pinned_aasist")
    source = source_path.read_bytes()
    code = compile(source, str(source_path), "exec")
    exec(code, module.__dict__)
    return require_model_class(module)


def require_model_class(module: ModuleType) -> type[Any]:
    model_class = getattr(module, "Model", None)
    if not isinstance(model_class, type):
        raise RuntimeError("pinned AASIST source does not export Model")
    return model_class


def import_torch() -> Any:
    try:
        import torch
    except ImportError as exc:
        raise RuntimeError("torch is required for AASIST PAD") from exc
    return torch


def resolve_device(torch: Any, device_name: str) -> Any:
    normalized = device_name.strip().lower()
    if normalized == "auto":
        if torch.cuda.is_available():
            normalized = "cuda"
        elif hasattr(torch.backends, "mps") and torch.backends.mps.is_available():
            normalized = "mps"
        else:
            normalized = "cpu"
    if normalized not in {"cpu", "cuda", "mps"}:
        raise ValueError("VOICEID_PAD_DEVICE must be auto, cpu, cuda, or mps")
    if normalized == "cuda" and not torch.cuda.is_available():
        raise RuntimeError("VOICEID_PAD_DEVICE=cuda requires CUDA")
    if normalized == "mps" and (
        not hasattr(torch.backends, "mps") or not torch.backends.mps.is_available()
    ):
        raise RuntimeError("VOICEID_PAD_DEVICE=mps requires Apple Metal")
    return torch.device(normalized)
