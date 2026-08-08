# Candidate Adapter Stability Check

This engineering check runs the real pinned Moonshine Tiny, SpeechBrain ECAPA,
and AASIST candidates through repeated-input, cross-input, and
failure-recovery sequences. It measures deterministic runtime behavior. It
does not establish biometric accuracy, spoof resistance, or release
calibration.

- Host: Apple Silicon macOS, Python 3.11.12
- Runtime: `moonshine-voice==0.0.71`, `speechbrain==1.1.0`,
  `torch==2.6.0`
- Provider: CPU for ECAPA and AASIST; Moonshine native provider is not reported
  by the package
- Sequences: A-A-A, A-B-A, and post-inference A-FAIL-A
- Numeric tolerance: `1e-6` for ECAPA and AASIST
- Moonshine comparison: exact canonical typed output

| Adapter | Repetition | Cross-input recovery | Failure recovery | Result |
| --- | --- | --- | --- | --- |
| Moonshine Tiny | exact | exact | exact | pass |
| SpeechBrain ECAPA | maximum delta 0 | maximum delta 0 | maximum delta 0 | pass |
| AASIST | maximum delta 0 | maximum delta 0 | maximum delta 0 | pass |

The Moonshine probe uses a 9,963 ms A clip and a 4,110 ms B clip. Its observed
per-request latency ranged from 887.963 ms to 1,184.773 ms. Those long-form
inputs exercise state contamination and are outside the short product
challenge profile. The separate 1,042 ms product-shaped check measured
254.085 ms p50 and 268.937 ms p99.

ECAPA latency ranged from 16.751 ms to 55.801 ms over extracted speech windows.
AASIST latency ranged from 97.574 ms to 147.021 ms.

The failure probe executes each real model and the Moonshine intent matcher,
then raises a harness-owned `InjectedAdapterFailure` while request-owned native
or tensor objects are still in the adapter cleanup scope. The harness requires
the corresponding close or zero operation before accepting that failure. The
next A result must match the preceding A result. Baseline observations also
fail if Moonshine returns an empty
transcript, ECAPA returns anything other than 192 finite dimensions, or AASIST
reports `model_unavailable`. Input B must produce a distinct transcript,
embedding, or PAD score.

## Immutable bindings

| Artifact | SHA-256 |
| --- | --- |
| Input A WAV | `e5a26b3d29e5b0bc8dbd72c11d16a3808a4ec0ac45b21f12a27d2a2fe5c5ae61` |
| Input B WAV | `ff0313f1b99468ac425304ba7f8deada003efbada014863a475cb8bda87a6191` |
| Model manifest | `3371ab7cb372a0ad4508b7af17cdc6551bbadc56d489ec90ab2914bba66859e0` |
| Moonshine model tree | `60d6ef32ffd94395c5f1eedf84062d88a73861379419055a475a082b94d7dafa` |
| Moonshine intent tree | `69a66594c12146d1baad78663ceac37fb6fae02b6b4d39d81bebb5a698064fd0` |
| ECAPA model tree | `e9279402ec55f2317ec4dfb3c83c4b7f8808a6ae7dfbb16a087164daf2c75150` |
| AASIST checkpoint | `51d2d9cf0738172f61e2a384ec50a54a55363240f67c971ed55a92435bc1a1c0` |
| Moonshine native library | `a0c19555988386679dda703b3454f8ba3672f4c43f6ba400af991c75263d9705` |

All bound model trees contain regular files only. The ECAPA probe used an
immutable local snapshot because the downloader-created cache included an
external symlink; mutable or dangling model-tree symlinks are rejected.

The machine-readable report was generated at
`/private/tmp/voiceid-adapter-stability-20260727-v3.json`. It remains a local
measurement artifact because its source audio and model payloads are
intentionally outside the repository.
