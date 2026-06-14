# Chat 6: VoiceID Browser MVP Handoff

Date: June 14, 2026

Status: active implementation thread. This document summarizes the VoiceID
discussion and implementation state after the browser MVP, ECAPA verifier,
Cloudflare deployment, policy, intent-binding, VAD, and demo UX passes.

## Current Direction

VoiceID is being built as an owner-presence signal, not as a standalone
cryptographic authenticator.

The durable product framing is:

```text
user speaks near a trusted client or embedded device
  -> client captures audio
  -> server or local sidecar verifies phrase, quality, speaker, and policy
  -> accepted owner presence is bound to a typed intentDigest
  -> Router A/B and MPC policy admit only that bound intent
  -> signing worker signs after policy admission
```

For the current phase, the scope is deliberately narrower:

```text
browser records enrollment samples
  -> VoiceID server stores an enrolled speaker template
  -> browser records verification samples
  -> verifier checks audio quality, phrase, and speaker match
  -> server returns accepted, rejected, or uncertain
```

Camera, face, mouth, and lip-sync extraction are deferred. The current MVP is
browser voice only.

## Security Position

The security model settled in this chat:

- VoiceID is analogous to TouchID or FaceID: a local biometric owner-presence
  and liveness signal.
- VoiceID never directly signs and never acts as a bearer secret.
- Cryptographic authority remains in device-bound key material, server policy,
  and MPC signing.
- Voice matching, spoken phrase/content verification, audio quality, liveness,
  and intent binding are separate checks.
- Deepfake and replay risk are handled through layered policy, not by pretending
  raw voice biometrics are cryptographic secrets.
- For risky wallet actions, policy can require step-up factors. The ideal low-
  friction flow remains: owner speaks and the trusted device responds.

The embedded robotics framing remains useful, but implementation is now
browser-first. Robot and camera work should resume only after the browser voice
path proves useful.

## Architecture Decisions

The `voiceId/` workspace remains standalone while the API, lifecycle, and
verifier boundary are still changing.

Current architecture:

```text
voiceId/demo
  -> browser UI for enrollment, verification, and fixture capture

voiceId/client
  -> API client, browser recording, fixture capture helpers

voiceId/shared
  -> domain types, ids, fixtures, results, policy, liveness, intents

voiceId/server
  -> route handlers, request parsing, service lifecycle, stores, verifier
     adapters, Cloudflare entrypoints, relay extension

voiceId/verifier
  -> Python verifier service with fake and ECAPA-capable runtime paths

voiceId/verifier-spike
  -> fixture evaluation and model comparison scripts
```

Deployment stance:

- Cloudflare is the primary hosted deployment target.
- Browser clients call a server-side VoiceID API.
- Embedded devices can run a robot-local Python sidecar and report typed owner-
  presence evidence to Cloudflare-hosted policy and signing flows.
- AWS ordinary servers or Nitro Enclaves remain optional SDK portability
  references, not the production deployment path for this MVP.
- The next SDK test should use the normal SDK relay/module path. Cloudflare MPC
  server-share signing and Router A/B integration remain later signing work
  after that path proves useful.

## Implemented State

The VoiceID workspace now has a substantial browser MVP scaffold:

- Typed enrollment and verification lifecycle in `voiceId/shared`.
- Browser `MediaRecorder` capture in `voiceId/client`.
- `VoiceIdClient` route client with bound `fetch` behavior.
- Server route handlers and typed request parsing.
- Fake verifier path for fast deterministic local testing.
- Python verifier adapter boundary behind `VoiceIdVerifier`.
- Python HTTP and subprocess transport paths.
- Cloudflare Worker boundary guards and Cloudflare factory setup.
- Cloudflare D1-compatible row serializers and store adapter.
- AES-GCM wrapping for enrolled templates at the storage boundary.
- Route extension and relay module hooks so VoiceID routes can be mounted
  without importing concrete VoiceID code into SDK router core.
- Typed owner-presence policy result surface.
- `POST /voice-id/owner-presence/authorize` for combining a completed
  verification record, `intentDigest`, use case, and liveness/owner-presence
  signals into one policy decision.

## Verifier And Fixture Progress

The verifier work now includes:

- JSON request/response schemas for the Python verifier.
- Audio decode and resampling through `ffmpeg`.
- Quality-first gates.
- Basic frame-energy VAD in the Python verifier.
- ECAPA embedding extraction through SpeechBrain when selected.
- Mean enrollment templates.
- Cosine speaker scoring.
- Fake verifier mode for deterministic tests.

Model selection direction:

- `speechbrain/spkrec-ecapa-voxceleb` is the recommended first real speaker-
  embedding model.
- ECAPA is the baseline for the real verifier path.
- The current fixture-calibrated ECAPA threshold defaults to `0.6352` unless
  `VOICEID_SPEAKER_SCORE_THRESHOLD` overrides it.
- Fake mode defaults to `0.82`.

Fixture progress:

- Browser fixture capture and export tooling exists.
- Fixture manifests can be validated.
- Optional `ffprobe` media-stream validation catches malformed audio files.
- Owner enrollment, owner verification, wrong-phrase, too-short, voice-variant,
  synthetic different-speaker, and noisy owner clips have been collected.
- Later laptop-microphone captures replaced unstable iPhone/Continuity-mic
  captures for the main owner sample set.
- The spectral baseline accepts the refreshed owner verification clips and
  rejects the current different-speaker clips.
- ECAPA evaluation has been run against the same fixture set.

Still needed:

- True independent human different-speaker clips.
- More noisy/environmental clips.
- Repeat fixture evaluation after any verifier or threshold change.

## ASR And Phrase Verification

ASR means automatic speech recognition: converting audio into text.

Current direction:

- For the early hosted MVP, prefer Cloudflare Workers AI ASR because the product
  is targeting Cloudflare infrastructure and early cost matters.
- Deepgram and ElevenLabs remain useful references or fallback providers.
- A local Hugging Face speech model remains possible for self-hosted or robot-
  local deployments, but it is not the cheapest first hosted path.

Phrase verification should stay separate from speaker verification:

```text
speaker verification: does this sound like the enrolled owner?
phrase or command verification: did the user say the expected phrase or command?
intent binding: does that phrase or command map to the exact authorized action?
```

## Intent Binding

The browser/shared intent-binding path now exists.

Implemented in `voiceId/shared/src/intents.ts`:

- typed intent structures
- `token_transfer` intent
- `wallet_session` intent
- `robot_command` intent
- spoken-command parser boundary
- canonical intent JSON
- WebCrypto-backed SHA-256 `intentDigest`
- `buildVoiceIdSpokenIntentBinding()`

Supported command examples:

```text
send 1 USDC to Bob
send 50 USDC to bob.near
authorize wallet session for device X
command robot to stir the pot
```

Validation now covers:

- equivalent commands produce the same canonical intent and digest
- amount, recipient, device, expiry, and nonce changes alter the digest
- unsupported or malformed commands are rejected
- type fixtures reject invalid branch combinations

Intent-binding follow-up state:

- [x] Store `intentDigest`, expiry, and nonce/replay state on verification records.
- [x] Have the browser verification flow submit the exact intent it is authorizing.
- [x] Enforce one-use, non-expired owner-presence evidence.
- [x] Ensure Router A/B admission checks require matching `intentDigest`.

Router A/B intent-binding update:

- `NormalSigningRequestV1` now requires an `intent_digest`.
- Normal-signing JWT admission must carry `intentDigest` as an unpadded
  base64url 32-byte digest string and match the request.
- Router-owned normal-signing admission-store requests carry both
  `intent_digest` and Router request digest.
- Router forwards an admitted normal-signing wrapper to SigningWorker.
- SigningWorker validates accepted Router admission and matching `intent_digest`
  before materialized handler execution.

Wallet policy update:

- `VoiceIdWalletPolicyInput` carries accepted owner presence, transcript,
  speaker, liveness, `intentDigest`, model version, threshold version, and
  policy version.
- Wallet policy input also carries the local device/sidecar boundary:
  `deviceId`, `sidecarId`, local liveness policy version, and evaluated time.
- Policy tiers cover low-risk robot commands, low-value known-recipient
  payments, new-recipient payments, and high-value or anomalous payments.
- New-recipient and high-value/anomalous payment tiers return
  `step_up_required`.
- Owner-presence authorization now requires `policyVersion` and emits an
  `owner_presence_authorized` audit event with result kind, decision kind,
  decision reason, and no raw capture fields.
- `docs/voiceID/voiceId-router-policy-issuer.md` now captures the issuer
  contract: accepted wallet policy decisions can issue one short-lived Router
  JWT for the bound intent, while step-up-required decisions stay non-signing.
- Current sequencing keeps the first SDK test on the normal SDK relay/module
  path. Router A/B issuer implementation is deferred until that path works.

## Browser Demo UX

The demo UI was revised in `voiceId/demo/src/main.ts`.

Current UX:

- The main panel shows the spoken prompt, enrollment sample progress, status,
  diagnostics, and grouped enrollment/verification controls.
- Recording now has an active banner and progress indicator.
- Controls that conflict with active recording or saving are disabled.
- Fixture capture shows the next clip metadata before recording.
- Captured fixture rows show relation, filename, speaker, duration, byte size,
  capture device, and an audio preview.
- Fixture rows can be downloaded or removed individually.
- The fixture set can be cleared.
- `Save set` writes the manifest and audio files to a chosen folder when the
  browser supports the File System Access API.
- When folder save is unavailable, `Save set` falls back to queueing the
  manifest and audio downloads.

The demo server was live at:

```text
http://127.0.0.1:5173/
```

The UI was checked in the in-app browser at desktop and mobile widths. Mic
capture was not re-tested during the UX pass because accepting browser
microphone permissions is an explicit side effect.

## Camera And Visual Liveness

Camera work is intentionally out of scope for the current browser VoiceID MVP.

Deferred plan:

```text
docs/voiceID/voiceId-camera-liveness-future.md
```

Do not mix camera tasks back into MVP 1 unless the user explicitly asks to
resume visual liveness.

## Validation Run Recently

Recent checks that passed during this thread:

```sh
rtk pnpm -C voiceId type-check
rtk pnpm -C voiceId test
rtk pnpm -C voiceId bundle:guard
rtk pnpm -C voiceId worker:guard
rtk pnpm -C voiceId verifier:test
rtk pnpm -C voiceId smoke:python-http
```

The latest frontend UX pass specifically re-ran:

```sh
rtk pnpm -C voiceId type-check
rtk pnpm -C voiceId test
rtk pnpm -C voiceId bundle:guard
rtk git diff --check -- voiceId/demo/src/main.ts
```

## Important Files

Primary plans:

- `docs/voiceID/voiceId-mvp-1.md`
- `docs/voiceID/voiceId-mvp-1-tasks.md`
- `docs/voiceID/voiceId-mvp-2.md`
- `docs/voiceID/voiceId-camera-liveness-future.md`
- `docs/voiceID/voiceId-router-policy-issuer.md`
- `docs/voiceID/readme.md`
- `voiceId/README.md`

Core code:

- `voiceId/demo/src/main.ts`
- `voiceId/client/src/VoiceIdClient.ts`
- `voiceId/client/src/VoiceIdCapability.ts`
- `voiceId/client/src/VoiceIdRecorder.ts`
- `voiceId/client/src/fixtures/fixtureCapture.ts`
- `voiceId/shared/src/intents.ts`
- `voiceId/shared/src/policy.ts`
- `voiceId/shared/src/authPolicy.ts`
- `voiceId/shared/src/livenessPolicy.ts`
- `voiceId/server/src/VoiceIdService.ts`
- `voiceId/server/src/routes.ts`
- `voiceId/server/src/cloudflare.ts`
- `voiceId/server/src/sdkRelayExtension.ts`
- `voiceId/server/src/transcript/CloudflareWorkersAiTranscriptProvider.ts`
- `voiceId/verifier/voiceid_verifier/app.py`
- `voiceId/verifier/voiceid_verifier/audio_quality.py`
- `voiceId/verifier/voiceid_verifier/embeddings.py`
- `voiceId/verifier/voiceid_verifier/runtime.py`

Relevant tests:

- `voiceId/tests/unit/intents.test.ts`
- `voiceId/tests/unit/policy.test.ts`
- `voiceId/tests/unit/authPolicy.test.ts`
- `voiceId/tests/unit/livenessPolicy.test.ts`
- `voiceId/tests/unit/routes.test.ts`
- `voiceId/tests/unit/service.test.ts`
- `voiceId/tests/unit/transcriptProvider.test.ts`
- `voiceId/verifier/test_audio_quality.py`
- `voiceId/verifier/test_schemas.py`

## Current Open Work

Recommended next work queue:

1. [x] Wire `intentDigest`, expiry, and replay protection into verification records.
2. [x] Update browser verification so the user can authorize a concrete spoken
   intent, not just the fixed phrase `Walking on clouds`.
3. [x] Connect completed verification results to
   `POST /voice-id/owner-presence/authorize` from the browser demo.
4. [x] Enforce one-use owner-presence evidence with matching `intentDigest`.
5. [x] Add route tests for expired, replayed, mismatched, and accepted intent-bound
   verification evidence.
6. [ ] Run another fixture evaluation pass after any verifier or threshold change.
7. [ ] Collect true independent different-speaker clips.
8. [x] Keep camera and face/lip-sync extraction deferred.
9. [x] Continue preserving Cloudflare Worker compatibility and Python sidecar
   boundaries.
10. [x] Wire accepted, intent-matching Router policy evidence into Router A/B
    normal-signing admission and SigningWorker checks.
11. [x] Document the Router A/B policy issuer contract and align normal-signing
    JWT `intentDigest` with the VoiceID base64url wire shape.
12. [x] Test VoiceID through the normal SDK relay/module path before Router A/B
    signing integration.
13. [x] Add normal SDK coverage for mount, enroll, verify, and owner-presence
    authorization.
14. [ ] Add normal SDK coverage for typed wallet policy consumption after
    owner-presence authorization.
15. [ ] Implement the concrete policy issuer service and key-management path.
16. [ ] Add an end-to-end test from accepted VoiceID wallet policy decision to
    Router JWT to admitted normal-signing request.

## Resume Instructions

To resume this work:

1. Read `docs/voiceID/voiceId-mvp-1-tasks.md`.
2. Inspect `voiceId/` diff before editing because the worktree may contain
   unrelated in-progress VoiceID changes.
3. Keep work scoped to VoiceID unless the user explicitly asks to touch the main
   wallet/auth SDK.
4. Do not start `docs/refactor-70-korg-secrets.md` work unless the user asks.
5. Prefer `rtk` for exploratory commands and validation.
6. Use `pnpm -C voiceId dev` for the browser-only demo, or
   `pnpm -C voiceId dev:all:verifier` when the API and Python verifier are
   needed.
