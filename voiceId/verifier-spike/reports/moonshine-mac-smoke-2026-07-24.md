# Moonshine Mac warm-path smoke check

This is a runtime smoke check on the approved Apple Silicon development
profile. It is not an accuracy or liveness result.

- Host: Apple Silicon macOS, Python 3.11, `moonshine-voice==0.0.71`
- Input: one second of canonical mono 16 kHz float PCM silence
- Intent model: EmbeddingGemma 300M Q4
- Runs: one model load followed by five warm analyses

| Model | Load | Warm analyses | Observed maximum |
| --- | ---: | ---: | ---: |
| Moonshine Tiny Streaming | 359 ms | 415, 403, 401, 399, 402 ms | 415 ms |
| Moonshine Small Streaming | 376 ms | 415, 402, 417, 408, 403 ms | 417 ms |

The warm Moonshine-only path is below the 500 ms p95 target in this synthetic
silence probe. The complete decision still includes canonical decode, VAD,
ECAPA, PAD, transport, and lifecycle work. Gate E remains open until real
speech, challenge errors, and attack fixtures are measured end to end.
