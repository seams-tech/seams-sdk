# Chat 2: Voice Auth Progress Snapshot

Status: active implementation thread. This document captures the current state
of the VoiceID discussion and code work so a later session can resume without
reconstructing the chat.

## Current Direction

We are exploring VoiceID as an owner-presence signal for wallets and embedded
devices. The highest-value target has shifted from generic wallet login toward
robotics and embedded transaction signing.

The product goal is:

```text
owner speaks near robot or embedded device
  -> device recognizes the command
  -> device verifies local owner presence using voice, and later video
  -> command is bound to a typed intent digest
  -> server policy authorizes the session
  -> MPC signs only the bound intent
```

For the browser MVP, the scope is narrower:

```text
browser records owner samples
  -> server enrolls a voice template
  -> browser records a verification sample
  -> server checks phrase, audio quality, and speaker match
  -> server returns accepted, rejected, or uncertain
```

The browser MVP is intentionally isolated from the wallet/auth SDK while the
VoiceID lifecycle, API, verifier boundary, and fixture flow are still changing.

## Security Position

The durable framing is:

> VoiceID is a local biometric owner-presence signal for an embedded device,
> combined with intent binding, liveness checks, device-bound key material, and
> MPC/server policy.

Important security decisions:

- VoiceID is treated like TouchID or FaceID: a local presence/liveness check.
- VoiceID never directly produces a wallet signature.
- The signing authority remains cryptographic: device-bound key material,
  server co-signer policy, and MPC participation.
- Voice matching and phrase/content verification are separate checks.
- Audio/video liveness is required before using VoiceID for embedded wallet
  actions.
- Phone, watch, OTP, or passkey step-up remains available for risky flows, but
  it is outside the ideal happy path for local robot commands.
- For low-risk owner commands, the target UX is: user simply speaks and the
  robot responds.

This framing was written into `voiceId/docs/readme.md`.

## Robotics Use Case

The motivating robotics flow is based on
`pollen-robotics/reachy_mini`.

Example owner flow:

```text
owner says: "send 1 usdc to bob"
Reachy captures audio and camera context
Reachy/sidecar parses the command into a typed payment intent
VoiceID checks owner presence
server verifies policy and intent binding
MPC signs the transaction
Reachy confirms the action
```

The robot scenario matters because TouchID and FaceID are awkward or unsafe
when the robot is moving, cooking, using tools, or physically distant from the
owner. Voice is the natural command interface.

The sidecar architecture discussed so far:

```text
reachy_app.py
  -> Python hardware glue for Reachy sensors, microphone, camera, and robot UX

wallet_sidecar
  -> Rust process running locally on the embedded Linux device or companion SBC
  -> owns command parsing, VoiceID client policy, intent construction, and MPC
     client-share participation

server
  -> remote or local policy service
  -> stores enrolled templates for the MVP path
  -> verifies phrase, speaker, and later liveness signals
  -> participates as MPC co-signer only for authorized intent digests
```

Preferred implementation stance:

- Keep performance-sensitive embedded code close to the metal.
- Prefer Rust for the robot-local sidecar and wallet logic.
- Keep Python thin for hardware integration where Reachy libraries require it.
- Browser-first VoiceID is phase 1; embedded audio/video liveness is later.

## x402 / Paid Command Idea

The chat also introduced a paid public-command flow:

```text
owner voice
  -> owner-only command path

non-owner voice
  -> Reachy returns payment required
  -> user pays through a URL, QR code, wallet link, or x402-compatible flow
  -> Reachy checks payment settlement
  -> Reachy executes the paid command if policy allows it
```

Open UX question: the simplest non-owner path should avoid forcing Alice to
type a URL. A QR code, local payment link, or wallet deep link should be
preferred for demos.

## Speaker Verification Model

The working technical model for speaker verification is:

1. Capture audio.
2. Normalize and resample audio.
3. Run voice activity detection.
4. Convert audio to log-mel or MFCC-like features.
5. Extract a speaker embedding with a modern model such as x-vector or
   ECAPA-TDNN.
6. Compare the live embedding with enrolled owner templates using cosine or
   PLDA-style scoring.
7. Combine the speaker score with phrase/content verification and audio quality.

Phrase/content verification is a separate subsystem:

- The system may verify an OTP-style phrase, such as digit code `116554`.
- The system may verify a command intent, such as `send 50 usdc to bob.near`.
- The recognized content should bind to an `intentDigest` before signing.

Transcript provider boundary:

- Added as `VoiceIdTranscriptProvider`.
- Fake provider currently handles phrase matching.
- Future adapters may use Deepgram, ElevenLabs, or Wispr Flow if those APIs fit
  latency, privacy, and accuracy requirements.

External services discussion:

- Deepgram may be useful for ASR and low-latency transcript experiments.
- ElevenLabs may be useful for voice-agent UX and speech output, and less
  central for speaker verification unless its APIs expose the right verifier
  semantics.
- Wispr Flow looks relevant to low-latency dictation/voice-agent behavior, but
  API access appeared private during the discussion.

## Current Code State

The standalone `voiceId/` workspace has been scaffolded and is wired into
`pnpm-workspace.yaml`.

Implemented structure:

```text
voiceId/
  shared/src/
    assertNever.ts
    audio.ts
    ids.ts
    index.ts
    parsers.ts
    prompts.ts
    records.ts
    results.ts
    samples.ts
    states.ts

  server/src/
    VoiceIdService.ts
    devServer.ts
    index.ts
    routes.ts
    http/
    store/
    transcript/
    verifier/

  client/src/
    VoiceIdClient.ts
    VoiceIdRecorder.ts
    capture/

  demo/
    index.html
    src/main.ts

  verifier-spike/
    README.md
    compare_models.py
    pyproject.toml

  verifier/
    pyproject.toml
    voiceid_verifier/

  tests/
    unit/
    type-fixtures/
```

Implemented behavior:

- Shared domain types use discriminated unions and branded IDs.
- Route boundaries parse raw request data into typed domain objects.
- Server service owns enrollment and verification lifecycle.
- In-memory stores back the standalone MVP.
- Fake verifier handles audio quality and speaker scoring.
- Fake transcript provider handles phrase matching.
- Browser client records audio and posts multipart samples.
- Demo exposes enrollment and verification actions.
- Demo disables actions until lifecycle prerequisites are satisfied.
- Demo displays status, prompt, message, quality, phrase, speaker, and final
  result.

Important fix already made:

- `VoiceIdClient.postJson` previously failed with
  `TypeError: Failed to execute 'fetch' on 'Window': Illegal invocation`.
- The fix binds `fetch` to the browser runtime before storing it on the client.

Code style cleanup already made:

- ECMAScript private `#field` / `#method` syntax was removed from the VoiceID
  client/server/shared/test code.
- TypeScript `private` fields and methods are used instead.

## Current Demo State

The demo has successfully completed the fake enrollment and verification flow
in the browser.

Known successful UI state:

```text
Status: accepted
Prompt: Walking on clouds
Message: VoiceID accepted
Quality: accepted; about 1805ms; signal 0.94
Phrase: accepted; walking on clouds; confidence 0.98
Speaker: accepted; score 0.94 / threshold 0.82
Final: accepted
```

Demo URLs:

```sh
pnpm -C voiceId dev:all
```

Then open:

```text
API:  http://127.0.0.1:8787
Demo: http://127.0.0.1:5173
```

Environment caveat:

- In this Codex environment, the dev server is reliable when run in a live
  foreground session.
- Prior detached/nohup attempts were cleaned up, so the demo may become
  unavailable after a tool/session boundary.

## Validation So Far

Last known successful checks from the implementation thread:

```sh
pnpm -C voiceId type-check
pnpm -C voiceId test
git diff --check
```

The test suite had 19 passing tests at that point, covering:

- prompt normalization
- route happy paths and malformed input
- service enrollment and verification branches
- phrase mismatch
- speaker mismatch
- noisy/too-short handling
- expired verification
- transcript provider unavailable returning `uncertain`
- browser fetch binding regression
- type fixtures for invalid state construction

Because this file is a documentation snapshot, code validation should be rerun
after future implementation changes.

## Live Task Plan

The live implementation plan is:

```text
voiceId/docs/voiceId-mvp-1-tasks.md
```

Current plan state:

- Phases 0-6 are implemented for the fake-verifier browser MVP.
- Phase 13 transcript provider boundary is partially complete.
- Phase 14 fixture capture and export is the immediate next implementation
  phase.
- Real model selection remains blocked on real browser-recorded fixtures.
- Python verifier service has scaffolding and still needs real model logic plus
  TypeScript adapter parsing.
- Durable storage, SDK integration, intent binding, liveness, and MPC policy
  integration remain later phases.

## Immediate Next Steps

Next implementation track:

1. Add fixture capture mode to the demo.
2. Add fixture manifest structures and parser.
3. Add export actions for captured audio clips and manifest.
4. Add fixture loader tests that reject missing or malformed entries.
5. Collect owner, different-speaker, wrong-phrase, noisy, and too-short browser
   clips.
6. Run the verifier spike against real fixtures.
7. Select a model and threshold policy.
8. Implement the Python verifier behind the existing `VoiceIdVerifier`
   interface.

Likely Phase 14 implementation shape:

```text
voiceId/shared/src/fixtures.ts
  -> manifest entry types, relation unions, parser, builder

voiceId/client/src/fixtures/
  -> browser fixture capture state and download helpers

voiceId/demo/src/main.ts
  -> fixture capture controls and fixture list

voiceId/tests/unit/
  -> manifest parser and fixture loader tests
```

Keep dependencies minimal. For the first fixture export, downloading individual
audio files plus a JSON manifest is enough. A zip dependency can wait.

## Chat-Specific Terms

The user added shorthand for this repo:

- `MOCT`: mark off completed tasks.
- `ONSAP`: outline next steps and proceed.
- `MOCT ONSAP`: update the live task plan, outline next steps, and keep
  implementing.

When the user says to update the plan, treat
`voiceId/docs/voiceId-mvp-1-tasks.md` as the progress surface.

## Resume Notes

When resuming:

1. Inspect `voiceId/docs/voiceId-mvp-1-tasks.md`.
2. Inspect the current `voiceId/` diff before editing.
3. Ignore unrelated dirty files outside the VoiceID work.
4. Keep VoiceID isolated from the main wallet/auth SDK until the module boundary
   phase.
5. Prefer typed domain builders and route-boundary parsers over raw object
   shapes.
6. Run the cheapest relevant validation after each scoped change.

