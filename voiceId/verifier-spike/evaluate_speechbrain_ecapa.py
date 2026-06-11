from __future__ import annotations

import argparse
import json
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

import numpy as np

from compare_models import FixtureInventory, FixtureManifestEntry, load_fixture_inventory
from evaluate_spectral_baseline import (
    decode_audio,
    evaluate_embeddings,
    report_to_json,
)


MODEL_ID = "speechbrain/spkrec-ecapa-voxceleb"
ADAPTER_ID = "speechbrain-ecapa-voxceleb"


class SpeechBrainEcapaError(RuntimeError):
    pass


@dataclass(frozen=True)
class ExtractedEmbedding:
    embedding: np.ndarray
    latency_ms: float


EmbeddingExtractor = Callable[[FixtureManifestEntry], ExtractedEmbedding]


def evaluate_speechbrain_ecapa(
    inventory: FixtureInventory,
    *,
    extractor: EmbeddingExtractor | None = None,
) -> Any:
    active_extractor = extractor or SpeechBrainEcapaExtractor().extract
    embeddings: dict[str, np.ndarray] = {}
    latencies: dict[str, float] = {}
    for entry in inventory.entries:
        extracted = active_extractor(entry)
        embeddings[entry.fixture_id] = extracted.embedding
        latencies[entry.fixture_id] = extracted.latency_ms
    return evaluate_embeddings(
        inventory,
        embeddings,
        adapter_id=ADAPTER_ID,
        latencies_ms=latencies,
    )


class SpeechBrainEcapaExtractor:
    def __init__(self, *, model_id: str = MODEL_ID, savedir: Path | None = None) -> None:
        self.model_id = model_id
        self.savedir = savedir or Path("verifier-spike/.cache/speechbrain-spkrec-ecapa-voxceleb")
        self.classifier = load_encoder_classifier(model_id=self.model_id, savedir=self.savedir)

    def extract(self, entry: FixtureManifestEntry) -> ExtractedEmbedding:
        torch = import_torch()
        audio = decode_audio(entry.audio_path)
        started = time.perf_counter()
        waveform = torch.from_numpy(audio.samples.astype(np.float32)).unsqueeze(0)
        with torch.no_grad():
            embedding = self.classifier.encode_batch(waveform)
        latency_ms = (time.perf_counter() - started) * 1000.0
        vector = embedding.detach().cpu().numpy().reshape(-1).astype(np.float64)
        return ExtractedEmbedding(embedding=vector, latency_ms=latency_ms)


def load_encoder_classifier(*, model_id: str, savedir: Path) -> Any:
    try:
        from speechbrain.inference.speaker import EncoderClassifier
    except ImportError:
        try:
            from speechbrain.pretrained import EncoderClassifier
        except ImportError as exc:
            raise SpeechBrainEcapaError(
                "SpeechBrain ECAPA evaluation requires optional Python dependencies. "
                "Install them with: python3 -m pip install 'speechbrain>=1.0.0' 'torchaudio==2.6.*'"
            ) from exc
    try:
        return EncoderClassifier.from_hparams(
            source=model_id,
            savedir=str(savedir),
        )
    except Exception as exc:  # pragma: no cover - exercised only with live model download/runtime.
        raise SpeechBrainEcapaError(f"failed to load SpeechBrain model {model_id}: {exc}") from exc


def import_torch() -> Any:
    try:
        import torch
    except ImportError as exc:
        raise SpeechBrainEcapaError("SpeechBrain ECAPA evaluation requires torch") from exc
    return torch


def render_speechbrain_report(report: Any) -> str:
    lines = [
        "# VoiceID SpeechBrain ECAPA Evaluation",
        "",
        "## Scope",
        "",
        f"- Adapter: `{report.adapter_id}`",
        f"- Model id: `{MODEL_ID}`",
        f"- Fixture count: {len(report.inventory.entries)}",
        f"- Embedding dimensions: {report.embedding_dimensions}",
        "- Model class: pretrained ECAPA-TDNN speaker embedding model",
        "- Scoring: cosine similarity against the mean owner enrollment template",
        "",
        "## Threshold",
        "",
        f"- Selected threshold: {report.threshold.threshold:.4f}",
        f"- True accepts: {report.threshold.true_accepts}",
        f"- False rejects: {report.threshold.false_rejects}",
        f"- True rejects: {report.threshold.true_rejects}",
        f"- False accepts: {report.threshold.false_accepts}",
        "",
        "## Score Ranges",
        "",
    ]
    for relation, (minimum, maximum) in sorted(report.score_ranges.items()):
        lines.append(f"- `{relation}`: {minimum:.4f} to {maximum:.4f} ({report.score_counts[relation]} clips)")
    lines.extend(
        [
            "",
            "## Latency",
            "",
            f"- Mean embedding latency: {report.latency_mean_ms:.1f} ms",
            f"- P95 embedding latency: {report.latency_p95_ms:.1f} ms",
            "",
            "## Per-Fixture Scores",
            "",
            "| Relation | Speaker | Score | Latency ms | Fixture |",
            "| --- | --- | ---: | ---: | --- |",
        ]
    )
    for score in sorted(report.scores, key=lambda item: (item.expected_relation, item.speaker_label, item.fixture_id)):
        lines.append(
            f"| `{score.expected_relation}` | `{score.speaker_label}` | {score.score:.4f} | {score.latency_ms:.1f} | `{score.fixture_id}` |"
        )
    lines.extend(
        [
            "",
            "## Decision",
            "",
            "Use this report to compare pretrained ECAPA behavior against the local spectral baseline.",
            "Wrong-phrase clips are expected to score like the owner at the speaker layer; phrase correctness belongs to transcript verification.",
        ]
    )
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(description="Evaluate SpeechBrain ECAPA against VoiceID fixtures.")
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--json", action="store_true", help="Print JSON instead of Markdown.")
    parser.add_argument(
        "--check-media",
        action="store_true",
        help="Run ffprobe audio-stream checks before evaluation.",
    )
    args = parser.parse_args()
    inventory = load_fixture_inventory(args.manifest, check_media=args.check_media)
    try:
        report = evaluate_speechbrain_ecapa(inventory)
    except SpeechBrainEcapaError as exc:
        print(f"SpeechBrain ECAPA evaluation failed: {exc}", file=sys.stderr)
        raise SystemExit(2) from exc
    if args.json:
        print(json.dumps(report_to_json(report), indent=2))
    else:
        print(render_speechbrain_report(report))


if __name__ == "__main__":
    main()
