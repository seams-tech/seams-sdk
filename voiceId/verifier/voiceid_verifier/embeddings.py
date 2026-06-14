from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any


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


def extract_embedding(audio_bytes: bytes) -> list[float]:
    if len(audio_bytes) == 0:
        return []
    total = sum(audio_bytes)
    return [
        float(total % 7) / 7.0,
        float(total % 11) / 11.0,
        float(total % 13) / 13.0,
        float(total % 17) / 17.0,
    ]


class PlaceholderEmbeddingExtractor:
    embedding_dimensions = 4

    def extract(self, audio_bytes: bytes) -> ExtractedSpeakerEmbedding:
        return ExtractedSpeakerEmbedding(
            vector=extract_embedding(audio_bytes),
            speaker_label="unknown_speaker",
        )

    def zero_embedding(self) -> ExtractedSpeakerEmbedding:
        return ExtractedSpeakerEmbedding(
            vector=[0.0] * self.embedding_dimensions,
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

    def extract_decoded(self, samples: Any) -> ExtractedSpeakerEmbedding:
        try:
            import numpy as np
            import torch
        except ImportError as exc:
            raise EmbeddingExtractionError("torch and numpy are required for ECAPA extraction") from exc

        try:
            waveform = torch.from_numpy(samples.astype(np.float32)).unsqueeze(0)
            with torch.no_grad():
                embedding = self.classifier.encode_batch(waveform)
        except Exception as exc:
            raise EmbeddingExtractionError(f"ECAPA embedding extraction failed: {exc}") from exc

        vector = embedding.detach().cpu().numpy().reshape(-1).astype(float).tolist()
        if len(vector) == 0:
            raise EmbeddingExtractionError("ECAPA embedding extraction returned an empty vector")
        return ExtractedSpeakerEmbedding(vector=vector, speaker_label="unknown_speaker")

    def zero_embedding(self) -> ExtractedSpeakerEmbedding:
        return ExtractedSpeakerEmbedding(
            vector=[0.0] * self.embedding_dimensions,
            speaker_label="unknown_speaker",
        )

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
