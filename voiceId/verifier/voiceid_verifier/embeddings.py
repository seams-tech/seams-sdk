from __future__ import annotations


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
