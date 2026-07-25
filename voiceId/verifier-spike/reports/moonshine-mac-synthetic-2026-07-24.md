# Moonshine Mac Synthetic Speech Benchmark

This is an engineering smoke benchmark over an ephemeral macOS Samantha
system-voice corpus. The audio and manifest remain outside the repository at
`/private/tmp/voiceid-synthetic-benchmark-20260724`; this report does not make
human speaker-accuracy or liveness claims.

The corpus contains three subject-disjoint synthetic partitions, each with one
enrollment and one genuine-verification recording. The manifest uses the v2
`synthetic_generation` branch and is labeled `generator=other`,
`model=macos-say-system-voice`, and `license=local-evaluation-only`.

| Model | Model load | Warm p50 | Warm p95 | Warm p99 | Phrase accepted | Intent accepted |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Moonshine Tiny Streaming native quantized | 388.9 ms | 653.0 ms | 679.1 ms | 681.4 ms | 0/3 | 0/3 |
| Moonshine Small Streaming native quantized | 445.5 ms | 671.0 ms | 696.3 ms | 698.5 ms | 3/3 | 0/3 |

The Tiny and Small runs use the downloaded native streaming assets and the
closed-set EmbeddingGemma intent model from the immutable model manifest. The
intent result is `uncertain` for all three samples, so this corpus is useful for
latency and adapter wiring only. Threshold calibration and product promotion
remain open.

Model tree digests used:

- Tiny native streaming: `80d9333c408a03cf38fecadf3e9babd52eb216df8fce5a1ff1aa843556ad8528`
- Small native streaming: `1788580491f1bc3fa39ad91a90353cfb770ac182b5e154f651c0be308a9ac5e9`
- Intent EmbeddingGemma Q4: `b3352ba88b9193ebf7bd4f0e4a9a15bf411af0bf14a70c5d385bae06b54cd53f`
