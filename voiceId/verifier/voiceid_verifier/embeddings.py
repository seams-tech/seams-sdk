from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Sequence


ECAPA_MODEL_ID = "speechbrain/spkrec-ecapa-voxceleb"
ECAPA_ADAPTER_ID = "speechbrain-ecapa-voxceleb"
ECAPA_MODEL_VERSION = "speechbrain-ecapa-voxceleb@2026-06-11"
ECAPA_THRESHOLD_VERSION = "ecapa-local-dev-v1"
ECAPA_TEMPLATE_VERSION = "ecapa-mean-template-v1"
ECAPA_EMBEDDING_DIMENSIONS = 192

PLACEHOLDER_MODEL_VERSION = "python-placeholder-model-v1"
PLACEHOLDER_THRESHOLD_VERSION = "python-placeholder-threshold-v1"
PLACEHOLDER_TEMPLATE_VERSION = "python-placeholder-template-v1"


class EmbeddingExtractionError(RuntimeError):
    pass


@dataclass(frozen=True)
class ExtractedSpeakerEmbedding:
    vector: list[float]
    speaker_label: str


def extract_decoded_embedding(samples: Sequence[float]) -> list[float]:
    if len(samples) == 0:
        return []
    absolute_total = sum(abs(float(sample)) for sample in samples)
    signed_total = sum(float(sample) for sample in samples)
    peak = max(abs(float(sample)) for sample in samples)
    mean = signed_total / len(samples)
    return [
        min(1.0, absolute_total / len(samples) * 8.0),
        max(-1.0, min(1.0, mean * 32.0)),
        min(1.0, peak),
        min(1.0, len(samples) / 48000.0),
    ]


class PlaceholderEmbeddingExtractor:
    embedding_dimensions = 4

    def extract_decoded(self, samples: Sequence[float]) -> ExtractedSpeakerEmbedding:
        return ExtractedSpeakerEmbedding(
            vector=extract_decoded_embedding(samples),
            speaker_label="unknown_speaker",
        )

class SpeechBrainEcapaEmbeddingExtractor:
    embedding_dimensions = ECAPA_EMBEDDING_DIMENSIONS

    def __init__(
        self,
        *,
        model_id: str = ECAPA_MODEL_ID,
        savedir: Path | None = None,
        classifier: Any | None = None,
    ) -> None:
        self.model_id = model_id
        self.savedir = savedir or Path(
            os.environ.get(
                "VOICEID_ECAPA_MODEL_CACHE",
                "verifier/.cache/speechbrain-spkrec-ecapa-voxceleb",
            )
        )
        self.classifier = classifier or self._load_classifier()

    def extract_decoded(self, samples: Sequence[float]) -> ExtractedSpeakerEmbedding:
        try:
            import torch
        except ImportError as exc:
            raise EmbeddingExtractionError("torch is required for ECAPA extraction") from exc

        try:
            waveform = torch.tensor(samples, dtype=torch.float32).unsqueeze(0)
            with torch.no_grad():
                embedding = self.classifier.encode_batch(waveform)
        except Exception as exc:
            raise EmbeddingExtractionError(f"ECAPA embedding extraction failed: {exc}") from exc

        vector = [float(value) for value in embedding.detach().cpu().reshape(-1).tolist()]
        if len(vector) == 0:
            raise EmbeddingExtractionError("ECAPA embedding extraction returned an empty vector")
        return ExtractedSpeakerEmbedding(vector=vector, speaker_label="unknown_speaker")

    def _load_classifier(self) -> Any:
        try:
            from speechbrain.inference.speaker import EncoderClassifier
        except ImportError:
            try:
                from speechbrain.pretrained import EncoderClassifier
            except ImportError as exc:
                raise EmbeddingExtractionError(
                    "SpeechBrain ECAPA requires optional dependencies. Install with: "
                    "python3 -m pip install 'speechbrain>=1.0.0' 'torchaudio==2.6.*'"
                ) from exc
        try:
            return EncoderClassifier.from_hparams(
                source=self.model_id,
                savedir=str(self.savedir),
            )
        except Exception as exc:
            raise EmbeddingExtractionError(f"failed to load SpeechBrain model {self.model_id}: {exc}") from exc
