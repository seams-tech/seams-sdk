# VoiceID Camera Liveness Future Plan

Status: deferred. This plan is intentionally outside the current VoiceID MVP.

The current MVP focuses on browser/embedded voice capture, speaker
verification, phrase or command transcription, intent digest binding,
owner-presence policy, and Router A/B admission simulation. Camera, face,
mouth, and lip-sync extraction should not block that path.

## Purpose

Add camera-backed liveness after the voice-only owner-presence flow is working
end to end.

The future goal is to strengthen embedded robot flows where the owner is near
the device and a camera is available. The camera signal remains a liveness and
anti-replay signal. It is not a signing secret.

## Scope

This future plan includes:

1. Camera capture adapters for browser and robot runtimes.
2. Face-presence detection near the command window.
3. Mouth movement detection during speech.
4. Rough audio/video correlation.
5. Policy rules for missing camera, low video quality, replay risk, and
   mismatched timing.
6. Fixture capture for replay, phone-speaker playback, TTS, and camera-facing
   spoof attempts.

This future plan does not include:

1. Current VoiceID MVP acceptance criteria.
2. Current fixture threshold calibration.
3. Current wallet/MPC policy simulation.
4. Treating face or mouth signals as cryptographic authorization.

## Architecture

```text
browser or robot camera
  -> camera capture adapter
  -> local frame sampler
  -> face/mouth/lip-sync extractor
  -> typed liveness signals
  -> VoiceID owner-presence policy
  -> wallet/robot policy decision
```

The extractor should produce typed signals only. Raw frames should stay local
unless diagnostic retention is explicitly enabled with a short retention window.

## Tasks

- [ ] Choose first camera runtime target:
  - [ ] browser camera
  - [ ] Reachy/robot camera
- [ ] Add camera permission and lifecycle handling.
- [ ] Add local frame sampling with bounded CPU and memory use.
- [ ] Add face-presence signal extraction.
- [ ] Add mouth-movement signal extraction.
- [ ] Add audio/video timing correlation.
- [ ] Add video-quality and low-light uncertainty branches.
- [ ] Add replay/spoof fixtures:
  - [ ] owner speaking live near camera
  - [ ] owner audio played from a speaker
  - [ ] phone video replay
  - [ ] TTS or voice-clone audio with no matching face
  - [ ] multiple faces in frame
  - [ ] partial or occluded face
- [ ] Add policy tests for accepted, rejected, and uncertain camera liveness.
- [ ] Add documentation for privacy, retention, and user consent.

## Validation

- [ ] Camera-disabled flows do not accidentally claim visual liveness.
- [ ] Missing camera returns `uncertain` for policies that require camera
  liveness.
- [ ] Live owner speech with overlapping face and mouth movement can be
  accepted.
- [ ] Speaker playback without mouth movement is rejected or uncertain.
- [ ] Audio/video timing mismatch is rejected or uncertain.
- [ ] Raw frames are never persisted by default.
- [ ] Browser/mobile bundles do not include heavy model runtimes unless that is
  explicitly chosen for this future plan.

## Current MVP Boundary

The current VoiceID MVP may keep typed liveness result unions and route plumbing
for future compatibility, but active MVP work should not implement camera,
face, mouth, or lip-sync extraction. Current policy experiments should rely on
voice verification, phrase or command matching, intent digest binding,
device/session policy, rate limits, and optional step-up factors.
