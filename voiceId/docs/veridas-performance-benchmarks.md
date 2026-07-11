# Veridas VoiceID Public Observations And Research Hypotheses

Status: vendor-claims research note; no signing assurance.

Normative signing requirements:
[VoiceID Signing Security Profile](voiceId-signing-security-profile.md).

This document records public Veridas voice-biometric positioning as input to
experiments. The claims are vendor statements with potentially different data,
channels, denominators, attack sets, and metric definitions. They are not E2
release criteria and do not establish NIST-conformant voice authentication.

Last reviewed: 2026-07-11. Recheck the primary source and record its version or
retrieval date before quoting any number.

## Sources

- [Veridas Voice Authentication](https://veridas.com/en/voice-biometric-authentication/)
- [Veridas das-Peak Introduction](https://docs.veridas.com/das-peak/cloud/v2.20/)
- [Veridas das-Peak Main Features](https://docs.veridas.com/das-peak/cloud/v2.20/main-features/)
- [Veridas Voice Shield](https://veridas.com/en/voice-shield/)
- [Veridas deepfake audio article](https://veridas.com/en/can-deepfake-audio-detected/)

## Vendor Observations And Research Use

| Area                           | Public vendor observation                                                                                        | Our research use                                                                                                                                                                               |
| ------------------------------ | ---------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Short duration                 | das-Peak describes a 3-second minimum verification duration and marketing material describes short enrollment.   | Test 1.5, 2, 3, 4, and 5 seconds of usable verification speech. Use 3–5 seconds provisionally. Shorter captures remain E0 research until end-to-end risk gates pass.                           |
| Speaker latency                | das-Peak describes 0.14 seconds for vector/audio comparison.                                                     | Measure warm p50/p95 decode, VAD, embedding, and scoring separately. Treat 140 ms as a model-stage latency hypothesis.                                                                         |
| PAD latency                    | Voice Shield describes a 0.14-second authenticity verdict.                                                       | Measure PAD by attack class and capture profile after decode/VAD. Return `uncertain` outside calibrated conditions.                                                                            |
| PAD duration                   | Voice Shield describes analysis from 3 seconds of speech.                                                        | Evaluate 3–5 second challenge responses across replay, synthesis, conversion, splicing, injection, and relay. Never infer E2 from duration alone.                                              |
| Speaker vector size            | das-Peak describes a 1.1 KB biometric vector.                                                                    | Measure encrypted normalized-centroid size. Consider quantization only after accuracy, privacy, and rollback tests.                                                                            |
| Text independence              | das-Peak describes text-independent speaker comparison.                                                          | Keep speaker scoring separate from phrase verification. The server-owned challenge and Router binding establish command correctness.                                                           |
| Language coverage              | das-Peak describes language-independent comparison and trained-language coverage.                                | Report every supported language cohort separately before making a coverage claim.                                                                                                              |
| Quality gates                  | das-Peak describes voice and noise quantity checks.                                                              | Require decoded usable speech, SNR, clipping, saturation, codec, channel, duplicate, and single-speaker gates before scoring.                                                                  |
| Calibration                    | das-Peak describes telephone and lossless-audio calibration modes.                                               | Use concrete profiles such as `browser_experimental`, `approved_mobile_v1`, `telephone_pcmu_8khz_v1`, and `approved_robot_microphone_v1`. Ordinary browser capture remains E0 for every codec. |
| Replay and synthetic detection | Public material describes replay, manipulated, and AI-generated audio detection.                                 | Produce separate typed PAD results and per-class reports. Speaker score cannot absorb PAD.                                                                                                     |
| Replay accuracy                | A Veridas article describes about 97% for low/mid-range speaker replay and 92% for high-end speaker replay.      | Record these as undefined vendor observations. Report APCER/BPCER-style results, end-to-end unauthorized acceptance, uncertainty, and 95% confidence bounds on our own attack corpus.          |
| Authentication performance     | The same article describes a 99% performance rate without a clear denominator in this note.                      | Do not create a parity target. Pre-register false-match, false-non-match, false-grant, false-denial, and clean-completion metrics first.                                                       |
| Challenge standing             | das-Peak material describes SdSV 2020 placement and NIST/SdSV evaluation.                                        | Treat this as speaker-model credibility context. It does not imply NIST authenticator conformance or satisfy our capture/PAD/Router gates.                                                     |
| Retention                      | das-Peak material describes immediate deletion of cloud audio recordings and voice credentials after processing. | Verify actual provider configuration and contracts. Our default deletes raw media after the terminal result and records deletion receipts.                                                     |

## Measurement Boundaries

Do not compare a full wallet ceremony with a narrow model-runtime number.
Measure each stage independently:

1. Capture duration and completion time.
2. Upload and authenticated request parsing.
3. Decode and native capture-profile validation.
4. VAD, usable speech, single-speaker, and quality gates.
5. Speaker embedding extraction and template scoring.
6. ASR and exact phrase verification against stored challenge state.
7. Device-proof and exact-media-hash verification.
8. PAD by attack class and capture profile.
9. E0/E1/E2 construction.
10. Server R1 risk policy.
11. Grant issuance and atomic Router reservation.
12. Router/SigningWorker completion.

The 0.14-second observations appear to describe model-side work. Report those
stages separately, then report end-to-end owner ceremony latency.

## Recording Experiment

Enrollment uses one continuous, prompt-segmented ceremony. Candidate usable-
speech targets are 3, 6, 9, 12, and 15 seconds. The provisional product target
is 12 seconds, subject to the pre-registered risk and usability analysis.

Verification uses one continuous challenge response. Candidate usable-speech
targets are 1.5, 2, 3, 4, and 5 seconds. The provisional signing-profile target
is 3–5 seconds with at most one quality retry under a new challenge.

All internal windows from one recording stay in the same dataset split and
count as one session.

## Fixture Requirements

- speaker-disjoint development and locked test cohorts;
- independent human impostors;
- at least three sessions per enrolled speaker across two or more days;
- devices, microphones, codecs, rooms, distances, noise, and supported
  languages;
- wrong-phrase, truncation, reordering, and ambiguous-ASR captures;
- owner illness/variation captures for claimed cohorts;
- smartphone, laptop, and high-fidelity loudspeaker replay;
- direct digital or virtual-microphone injection;
- TTS, voice conversion, splicing, prompt-targeted synthesis, and live relay;
- unseen PAD tools and held-out attack conditions;
- overlapping speakers and background speech;
- the exact deployed retry and rate-limit policy.

## Reporting Format

Every run records:

- immutable fixture manifest hash and subject/session split;
- model, adapter, preprocessing, template aggregation, threshold, PAD,
  calibration, prompt, and capture-profile versions;
- p50/p95 latency by pipeline stage and complete ceremony;
- same-speaker and independent-impostor score distributions;
- false-match, false-non-match, equal-error, false-grant, and false-denial rates
  with subject-level confidence intervals;
- PAD attack-presentation and bona-fide rejection by attack class;
- combined end-to-end unauthorized acceptance with a 95% upper bound;
- quality uncertainty, retry, completion, and accessibility fallback rates;
- results by capture profile, language, demographic cohort where lawful, and
  worst supported cohort.

## Research Hypotheses

1. Three to five seconds of usable verification speech can meet the E0 usability
   target; E2 depends on the complete calibrated system.
2. Warm model-stage speaker scoring can approach the vendor-described 140 ms
   range on the selected deployment hardware.
3. PAD latency and error vary materially by attack class and capture profile.
4. One 12-second guided enrollment ceremony can retain the statistical benefit
   of multiple internal embeddings with less user friction than repeated clips.
5. A channel-specific, confidence-bounded report is more actionable than an
   undefined vendor parity percentage.
