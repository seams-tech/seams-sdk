# VoiceID Audio-Visual PAD Future Plan

Status: deferred. This plan is outside the current VoiceID MVP.

Normative security requirements:
[VoiceID Signing Security Profile](voiceId-signing-security-profile.md).

The current MVP implements browser/embedded voice capture, speaker similarity,
phrase transcription, intent-associated policy plumbing, and client-reported
capture context. It does not implement presentation-attack detection, trusted
sensor provenance, visual owner verification, or E2 signing-candidate evidence.

## Purpose

Add an independently measured audio-visual presentation-attack detection path
for embedded devices where an authenticated camera and microphone array are
available. The result estimates whether one nearby bona-fide person produced the
challenge response. It remains probabilistic policy evidence and never becomes
a signing secret.

Face presence, mouth movement, and rough lip/audio correlation can reject simple
speaker playback. They are insufficient for claims of strong liveness because
phone-video replay, synchronized audio/video deepfakes, virtual sensors, and a
compromised endpoint can reproduce those signals.

## Security Properties

The future path separates these properties:

| Property                  | Required evidence                                                             |
| ------------------------- | ----------------------------------------------------------------------------- |
| Capture provenance        | Authenticated device and sensor profile, signed capture session               |
| Challenge freshness       | Server-issued prompt after exact intent construction                          |
| Active speaker            | Face track, mouth motion, speech timing, and audio direction agree            |
| Visual owner match        | Visible person matches the enrolled owner template                            |
| Presentation authenticity | Calibrated PAD result for supported replay and synthesis classes              |
| Transaction binding       | Device signature covers the exact server-canonical operation and media hashes |

An accepted audio-visual result does not prove coercion-free consent or endpoint
integrity. Those risks remain in device trust, transaction UI, policy, and
cryptographic authorization.

## Scope

This plan includes:

1. Camera and microphone-array capture adapters for one embedded target.
2. Device-signed binding between challenge, intent, audio hash, video hash,
   capture interval, sensor profile, and expiry.
3. Face-track and active-speaker association.
4. Mouth/audio synchronization and microphone-array direction consistency.
5. Visual owner comparison when policy requires it.
6. A randomized active challenge selected after the exact intent is fixed.
7. Independent audio and visual PAD results plus a calibrated fusion policy.
8. Explicit rejected and uncertain outcomes for missing, degraded, overlapping,
   or contradictory signals.
9. Attack fixtures and per-class metrics for replay, synthesis, conversion,
   injection, and endpoint substitution.

## Non-Goals

1. Enabling browser VoiceID signing.
2. Treating a browser camera or `deviceId` as attested hardware.
3. Inferring signing intent from PAD.
4. Gating protective stop, pause, freeze, or emergency actions on identity.
5. Allowing uncertain sensor results to degrade into an accepted voice-only
   branch.
6. Claiming resistance to attack classes that were not measured.

## Architecture

```text
canonical Router or robot intent
  -> server challenge + prompt hash + expiry
  -> authenticated embedded capture service
  -> synchronized original audio/video frames
  -> device signature over intent + challenge + media hashes + sensor context
  -> audio quality + speaker + phrase
  -> audio PAD
  -> visual owner + active-speaker association + visual PAD
  -> calibrated fusion
  -> accepted / rejected / uncertain AV evidence
  -> signing-security-profile policy
```

Heavy inference may run on a server during the first experiment. The embedded
device still signs the media hashes and capture context before upload. Server
processing cannot recover capture provenance that was absent at the device.

## Result Shape

```ts
type VoiceIdAudioVisualPadResult =
  | {
      kind: 'accepted';
      deviceProof: VerifiedVoiceIdCaptureProof;
      activeSpeaker: AcceptedActiveSpeakerResult;
      visualOwner: AcceptedVisualOwnerResult;
      audioPad: AcceptedVoiceIdAudioPadResult;
      visualPad: AcceptedVoiceIdVisualPadResult;
      fusionVersion: VoiceIdFusionVersion;
      checkedAt: IsoDateTime;
    }
  | {
      kind: 'rejected';
      reason:
        | 'audio_replay'
        | 'video_replay'
        | 'synthetic_media'
        | 'face_voice_mismatch'
        | 'active_speaker_mismatch'
        | 'sensor_proof_invalid';
      fusionVersion: VoiceIdFusionVersion;
    }
  | {
      kind: 'uncertain';
      reason:
        | 'no_face'
        | 'mouth_occluded'
        | 'low_light'
        | 'noisy_audio'
        | 'multiple_speakers'
        | 'direction_ambiguous'
        | 'model_out_of_domain';
      fusionVersion: VoiceIdFusionVersion;
    };
```

This result can enter `VoiceIdSigningCandidateEvidence` only through the E2
branch-specific builder defined by the signing security profile.

## Capture And Retention

1. Capture synchronized original audio and video with monotonic timestamps.
2. Record actual sample rate, channel layout, codec, camera mode, audio DSP,
   beamforming, and device/sensor version.
3. Derive model-specific inputs after hashing the original capture.
4. Keep raw frames in memory or bounded temporary storage for the verification
   window.
5. Delete raw media after the result unless explicit diagnostic consent and TTL
   are active.
6. Store encrypted, relying-party-scoped templates and coarse audit bands.
7. Provide template deletion and cryptographic erasure.

## Attack Matrix

The initial evaluation includes:

- owner speaking live near the device;
- owner recording replayed through phone, laptop, and high-quality speakers;
- phone display replay of owner video;
- synchronized owner audio/video replay;
- TTS and voice-conversion audio with no matching face;
- audio deepfake combined with prerecorded owner video;
- generated or manipulated audio/video when lawful fixtures are available;
- virtual or substituted audio and camera sources;
- multiple faces, overlapping speakers, partial faces, occluded mouths, and low
  light;
- capture-channel and codec changes;
- compromised-client simulations that submit valid media with forged metadata.

Metrics are reported per attack class, capture channel, model version, threshold
version, and fusion version. Aggregate accuracy cannot replace per-class false
accept, false reject, and uncertainty rates.

## Tasks

- [ ] Select one embedded hardware profile with a documented camera, microphone
      array, device key, and attestation story.
- [ ] Define `VerifiedVoiceIdCaptureProof` and its canonical signed payload.
- [ ] Add synchronized capture with bounded CPU and memory use.
- [ ] Add face-track and active-speaker association.
- [ ] Add mouth/audio synchronization and direction-of-arrival checks.
- [ ] Spike one visual PAD component and one audio-visual fusion policy.
- [ ] Build the attack matrix before enabling an accepted result.
- [ ] Calibrate subject-disjoint thresholds on the target hardware and rooms.
- [ ] Add policy tests for accepted, rejected, and uncertain results.
- [ ] Add deletion, consent, and diagnostic-retention tests.
- [ ] Obtain security review before connecting accepted evidence to Router
      admission.

## Validation Gates

- [ ] Browser and unattested-device results cannot construct
      `VoiceIdSigningCandidateEvidence`.
- [ ] Missing camera, sensor proof, audio PAD, or visual PAD returns `uncertain`
      when the policy requires audio-visual evidence.
- [ ] Speaker playback without a matching active speaker is rejected or
      uncertain.
- [ ] Phone-video and synchronized replay are represented in the measured attack
      set.
- [ ] Audio/video timing or direction mismatch is rejected or uncertain.
- [ ] A changed challenge, intent, media hash, sensor profile, or expiry
      invalidates the device proof.
- [ ] Raw media is absent from default persistence and audit logs.
- [ ] No product claim exceeds the measured hardware, channel, population, and
      attack classes.

## Current MVP Boundary

The active MVP may preserve result unions and adapter seams for this future work.
It must label browser timestamps, microphone identifiers, and replay-risk flags
as client-reported capture context. Those values remain experimental and cannot
authorize signing.
