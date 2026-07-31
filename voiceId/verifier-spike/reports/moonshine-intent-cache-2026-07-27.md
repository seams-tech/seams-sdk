# Moonshine Closed-Intent Cache Benchmark

This engineering check measures the production-shaped Moonshine Tiny adapter
after moving fixed intent registration to sidecar initialization and isolating
each transcription behind a fresh native transcriber handle. It does not make
an accuracy or liveness claim.

- Host: Apple Silicon macOS, Python 3.11, `moonshine-voice==0.0.71`
- Input: 1,042 ms of mono 16 kHz synthetic speech
- Input corpus: local macOS system-voice smoke corpus
- Model: pinned Moonshine Tiny Streaming native quantized
- Intent model: pinned EmbeddingGemma 300M Q4
- Runs: one cold initialization followed by 20 warm analyses

| Measurement | Result |
| --- | ---: |
| Model readiness and closed-intent initialization | 1,920.664 ms |
| Warm p50 | 254.085 ms |
| Warm p95 | 264.268 ms |
| Warm p99 | 268.937 ms |
| Warm minimum / maximum | 245.213 / 270.104 ms |
| Exact repeated typed result | true |

The previous implementation rebuilt five canonical intent embeddings during
every request. Its same-corpus Tiny report measured 653.0 ms p50, 679.1 ms p95,
and 681.4 ms p99. The fixed closed intent set loads once before readiness. A
fresh native transcriber is created and closed around each request because the
Moonshine 0.0.71 native library exhibited cross-input transcript carryover when
one handle was reused. Raw punctuation still varied process-wide on a
long-form A-B-A probe, so the adapter emits its existing lowercase
alphanumeric transcript normalization as the canonical transcript. Challenge
tokens, phrase decisions, and intent matching consume that same canonical
form.

This shifts intent work into sidecar initialization, prevents the observed
word carryover, makes the typed output deterministic for the measured probes,
and keeps the 1,042 ms phrase-plus-intent stage below the 500 ms target.

The canonical transcript was `approved transfer`. The semantic intent and
phrase checks were uncertain/rejected because the old smoke clip does not
contain the current intent phrase or the independent challenge tokens. The
result is retained only as deterministic adapter and latency evidence.
