# VoiceID Research Notes

This folder holds a brief literature review and local PDF copies for the
VoiceID MVP sanity check. The goal is to keep implementation decisions aligned
with modern speaker-verification practice while preserving the product boundary:
ordinary voice capture produces signing-ineligible evidence.

## Research Inventory

| Local PDF | Topic | Why it matters |
| --- | --- | --- |
| `ecapa-tdnn-2020.pdf` | ECAPA-TDNN speaker embeddings | Supports the current ECAPA-first model choice. ECAPA improves TDNN/x-vector style systems with Res2Net blocks, squeeze-and-excitation, feature aggregation, and attentive statistics pooling. |
| `x-vectors-2018.pdf` | x-vector speaker embeddings | Establishes the classic DNN embedding pipeline: train for speaker classification, extract fixed-dimensional embeddings, score with cosine or PLDA. Useful as a fallback baseline. |
| `titanet-2021.pdf` | TitaNet speaker embeddings | Shows a strong convolutional embedding family with global context and channel attention. Relevant if we later evaluate NVIDIA NeMo deployment. |
| `wavlm-2021.pdf` | self-supervised speech foundation model | Useful context for modern speech representation learning. Potentially strong but heavier than ECAPA for an MVP verifier. |
| `speechbrain-2021.pdf` | SpeechBrain toolkit | Supports the current implementation path using SpeechBrain models and a Python verifier boundary. |
| `voxceleb-2017.pdf` | VoxCeleb dataset | Explains the in-the-wild speaker dataset behind many public speaker-verification models. Useful for understanding model domain assumptions. |
| `voxceleb2-2018.pdf` | VoxCeleb2 dataset | Provides the larger speaker-recognition dataset used by many modern embeddings, including SpeechBrain ECAPA model training. |
| `deep-speaker-review-2020.pdf` | deep-learning speaker recognition review | Broad overview of i-vector, x-vector, and neural speaker-recognition trends. Useful for architectural context. |
| `asvspoof-2021-evaluation-plan.pdf` | spoofing and deepfake benchmark | Captures standard threat categories: logical access, physical replay, and deepfake detection. Confirms anti-spoofing should be a separate subsystem. |
| `asvspoof-2024-overview.pdf` | modern ASVspoof/deepfake benchmark | Shows newer challenge focus on crowdsourced speech, modern TTS/VC attacks, adversarial attacks, and calibration metrics. |
| `speaker-aware-antispoofing-2023.pdf` | speaker-aware countermeasures | Reinforces that generic spoof detectors struggle with unseen systems and that speaker/context-aware countermeasures can be useful. |
| `speech-deepfake-detection-survey-2024.pdf` | speech deepfake detection survey | Broad survey of speech deepfake datasets, model families, metrics, generalization problems, and adversarial concerns. |
| `audio-visual-spoofing-detection-2017.pdf` | audio-visual liveness | Supports challenge-response checks using audio/video synchrony and transcript alignment, matching our embedded robot direction. |

## Short Literature Review

Modern speaker verification generally follows an embedding-and-scoring pipeline.
The system converts variable-length speech into a fixed-dimensional speaker
embedding, builds an enrollment template from one or more known-speaker samples,
then scores verification samples against that template with cosine similarity,
PLDA, or another calibrated backend.

The older but still important x-vector pattern trains a neural network to
discriminate speakers, extracts embeddings from an internal layer, and scores
same-speaker likelihood. ECAPA-TDNN is a modernized x-vector family member. It
keeps the TDNN/statistics-pooling shape while adding channel attention,
multi-scale temporal structure, and feature aggregation. That lines up well with
our current `speechbrain/spkrec-ecapa-voxceleb` choice.

Dataset assumptions matter. VoxCeleb and VoxCeleb2 are large, in-the-wild
speaker-recognition datasets, which is useful for robustness, but they are not a
perfect match for browser microphones, robots, close-field commands, noisy
kitchens, or user-specific enrollment. Our threshold must be calibrated with our
own fixture distribution, and templates should carry model and threshold version
metadata.

Speaker verification and phrase verification are separate jobs. Speaker
embeddings answer whether the voice sounds like the enrolled owner. They do not
prove that the command text is correct, current, or intended. The transcript/ASR
boundary should continue to own phrase and intent matching.

Spoofing and deepfake work argues for a separate countermeasure layer. ASVspoof
tracks logical access attacks, physical replay attacks, speech deepfakes, modern
TTS/voice-conversion systems, and newer adversarial attacks. The literature also
shows that generic countermeasures struggle to generalize to unseen vocoders,
domains, codecs, and attack methods. For our product, audio-only VoiceID should
remain evidence for research, UX, and passkey step-up.
Direct authorization requires a protected user-verifying authenticator with
challenge binding, rate limits, replay resistance, PAD, and credential-key
release inside the same evaluated boundary.

Audio-visual liveness is directionally correct for embedded robots. The
audio-visual spoofing paper validates the idea of checking challenge-response
speech together with audio/video synchrony and transcription. For Reachy-style
flows, the useful check is roughly: face present, mouth movement correlates with
speech timing, transcript matches the challenge or command, and speaker
embedding matches the enrolled owner. This does not make spoofing impossible,
but it raises the attack from replaying an audio clip to coordinating a live
multimodal spoof near the device.

## Implementation Implications

Proceed with ECAPA first.

- Integrate `speechbrain/spkrec-ecapa-voxceleb` behind the Python verifier
  boundary.
- Keep x-vector, pyannote, WavLM, and TitaNet/NeMo as comparison paths only if
  ECAPA fails a concrete requirement.
- Do quality gating before speaker scoring: too-short, clipped, low-SNR, or
  low-speech clips should return `uncertain`.
- Keep ASR/transcript matching separate from speaker scoring.
- Store encrypted templates plus model/threshold metadata. Do not persist raw
  audio by default.
- Add independent human different-speaker fixtures before tightening thresholds.
- Add replay, TTS/VC, and speaker-playback fixtures before claiming spoof
  resistance.
- For robotics, add audio-video timing correlation and face/mouth-presence
  signals before using VoiceID for privileged physical actions.

## Current Sanity Check

The current architecture is heading in the right direction:

- ECAPA is a reasonable first model.
- The fake verifier boundary was the right abstraction; the real verifier can
  replace it without changing core lifecycle code.
- Phrase verification, speaker verification, quality checks, and liveness should
  remain separate typed result branches.
- The 30-clip fixture set is enough for wiring and score-shape exploration, but
  it is not enough for a security claim.

The next engineering step remains unchanged: wire ECAPA into the Python verifier
service, keep quality-first decisions explicit, and expand fixtures with true
independent speakers plus spoof/replay cases.

## Source URLs

- ECAPA-TDNN: https://arxiv.org/pdf/2005.07143
- X-vectors: https://www.danielpovey.com/files/2018_icassp_xvectors.pdf
- TitaNet: https://arxiv.org/pdf/2110.04410
- WavLM: https://arxiv.org/pdf/2110.13900
- SpeechBrain: https://arxiv.org/pdf/2106.04624
- VoxCeleb: https://arxiv.org/pdf/1706.08612
- VoxCeleb2: https://arxiv.org/pdf/1806.05622
- Deep-learning speaker recognition review: https://arxiv.org/pdf/1911.06615
- ASVspoof 2021 evaluation plan: https://www.asvspoof.org/asvspoof2021/asvspoof2021_evaluation_plan.pdf
- ASVspoof 2024 overview: https://www.isca-archive.org/asvspoof_2024/wang24_asvspoof.pdf
- Speaker-aware anti-spoofing: https://www.isca-archive.org/interspeech_2023/liu23o_interspeech.pdf
- Speech deepfake detection survey: https://arxiv.org/pdf/2404.13914
- Audio-visual spoofing detection: https://leaschoenherr.me/media/paper/2017_asru.pdf
