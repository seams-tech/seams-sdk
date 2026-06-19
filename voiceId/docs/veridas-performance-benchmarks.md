# Veridas VoiceID Performance Benchmarks

Status: public-claims benchmark note.

This document records public Veridas voice-biometric performance claims that we
can use as competitive targets for the local VoiceID stack. These are vendor
claims from public product/docs pages, not independently validated benchmark
results. Treat them as target bars to reproduce, measure, and eventually beat
with our own fixture reports.

## Sources

- [Veridas Voice Authentication](https://veridas.com/en/voice-biometric-authentication/)
- [Veridas das-Peak Introduction](https://docs.veridas.com/das-peak/cloud/v2.20/)
- [Veridas das-Peak Main Features](https://docs.veridas.com/das-peak/cloud/v2.20/main-features/)
- [Veridas Voice Shield](https://veridas.com/en/voice-shield/)
- [Veridas deepfake audio article](https://veridas.com/en/can-deepfake-audio-detected/)

## Claims To Beat

| Area | Veridas public claim | Our benchmark target |
| --- | --- | --- |
| Short sample duration | das-Peak claims verification with 3 seconds minimum voice duration. Voice Authentication marketing also says enrollment can create a biometric voiceprint from as little as 3 seconds. | Accept clean owner authentication clips with <= 3 seconds of usable speech, then test whether 2.5s and 2.0s clips remain viable for low-risk wallet tasks. |
| Speaker scoring latency | das-Peak main features claim 0.14 seconds to compare a biometric vector and an audio. | Warm verifier p95 <= 140ms for vector/template speaker scoring after decode and VAD. Track decode, VAD, embedding, scoring, ASR, and policy separately. |
| Voice authenticity latency | Voice Shield claims an authenticity verdict in 0.14 seconds after receiving audio. | Warm authenticity p95 <= 140ms after decode/VAD, measured separately from upload and ASR. |
| Voice Shield sample duration | Voice Shield says 3 seconds of speech is enough to analyze authenticity during a call. | Produce spoof/deepfake/replay verdicts from <= 3 seconds of usable speech, with attack-class-specific false accept and false reject rates. |
| Speaker vector size | das-Peak main features claim a 1.1 KB biometric vector. | Keep persisted speaker templates compact. Measure ECAPA mean-template size now, then evaluate quantized/compressed template targets if storage or transmission matters. |
| Text independence | das-Peak claims text-independent comparison across different phrases. | Keep speaker verification text-independent. Phrase and intent matching stay in ASR/policy, not speaker scoring. |
| Language independence | das-Peak claims language-independent comparison and lists trained language coverage. | Keep wallet phrase parsing language-specific for now, while speaker matching should avoid depending on the command text. Add multilingual fixtures before making language claims. |
| VAD and noise gates | das-Peak says it computes voice quantity and noise quantity to accept verification requests. | Require explicit speech duration, silence, clipping, SNR/noise, and decode quality branches before speaker scoring. |
| Calibration modes | das-Peak documents calibration choices such as telephone channel and lossless audio. | Add typed calibration modes: `browser-lossless`, `mobile-lossless`, `telephone-channel`, and `robot-microphone`. Threshold reports must be channel-specific. |
| Anti-spoof / replay | das-Peak main features claim voice authenticity detection for replay attacks through smartphone or high-fidelity speakers. Voice Shield claims detection of recorded, manipulated, and AI-generated audio. | Add separate `VoiceIdAuthenticityResult` for replay, synthetic voice, voice conversion, injected audio, and multi-speaker suspicion. Do not fold spoof detection into speaker score. |
| Replay detection accuracy | A Veridas deepfake-audio article claims approximately 97% accuracy for low/mid-range speaker replay and 92% for high-end speaker replay after a newer version. | Build replay fixture sets by speaker class and measure attack-class accuracy. Target >97% low/mid speaker replay and >92% high-end speaker replay before claiming parity. |
| Authentication performance | The same article claims 3-second authentication while maintaining a 99% performance rate. The article does not define the exact metric. | Define our own metric explicitly: false accept rate, false reject rate, equal error rate, and accepted-owner rate at each threshold version. Beat 99% only after the metric is precise. |
| Challenge standing | das-Peak docs claim SdSV 2020 third award overall and second single-system placement for short-duration speaker verification. The main-features page also references NIST/SdSV evaluation. | Treat this as credibility context. Our comparable target is a reproducible fixture report with public methodology, model version, threshold version, and manifest hash. |
| Cloud data retention | das-Peak main features say cloud audio recordings and voice credentials are immediately deleted after processing. | Keep raw audio retention disabled by default. Persist encrypted templates and typed audit events only. Diagnostics require explicit opt-in and TTL. |

## Measurement Rules

We should not compare our full wallet flow to a narrow model-runtime claim.
Measure each layer independently:

1. Browser capture duration.
2. Upload and request parsing.
3. Decode and resampling.
4. VAD and quality gates.
5. Speaker embedding extraction.
6. Template/vector comparison.
7. ASR transcript.
8. Phrase and intent digest matching.
9. Authenticity/spoof detection.
10. Owner-presence policy.
11. Wallet signing grant issuance.

The Veridas 0.14 second claim appears to refer to model-side vector/audio
comparison or authenticity analysis. Our public comparison should use the same
scope for parity, then separately report end-to-end wallet confirmation latency.

## Fixture Requirements Before Claiming Parity

- Independent human different-speaker clips.
- Owner clips across days, devices, rooms, and distances.
- Clean 3-second, 2.5-second, and 2-second owner clips.
- Wrong-phrase clips that are still the enrolled speaker.
- Noisy clips with controlled SNR bands.
- Smartphone speaker replay clips.
- High-fidelity speaker replay clips.
- TTS and voice-clone clips for the target command phrases.
- Injected file-upload clips that bypass live microphone timing.
- Multi-speaker and background speech clips.

## Reporting Format

Every benchmark run should write:

- model id and model version
- verifier adapter version
- threshold version
- calibration mode
- capture channel
- fixture manifest hash
- p50/p95 latency by pipeline stage
- same-speaker score distribution
- different-speaker score distribution
- spoof/deepfake/replay distribution by attack class
- false accept rate
- false reject rate
- equal error rate when applicable
- accepted-owner rate for clean clips
- uncertain rate from quality failures

## Current Competitive Targets

The first concrete targets are:

1. Clean owner verification with 3 seconds usable speech.
2. Warm speaker scoring at or below 140ms after decode/VAD.
3. Warm authenticity scoring at or below 140ms after decode/VAD.
4. Channel-specific threshold calibration.
5. Separate branch-level results for quality, speaker, phrase, intent, device,
   and authenticity.
6. Replay detection fixture accuracy above Veridas' stated 97% low/mid-speaker
   and 92% high-end-speaker claims.
7. A clearly defined >99% metric before using any "99%" performance language.
