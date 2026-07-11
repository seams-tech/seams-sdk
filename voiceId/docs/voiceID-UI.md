# VoiceID UI/UX Plan

Status: product and implementation requirements.

Related docs:

- [VoiceID signing security profile](voiceId-signing-security-profile.md)
- [VoiceID SDK auth method integration](voiceId-sdk-auth-method-integration.md)
- [VoiceID normal SDK transaction signing plan](voiceId-normal-sdk-transaction-signing.md)
- [VoiceID MVP 1 tasks](voiceId-mvp-1-tasks.md)
- [VoiceID MVP 2](voiceId-mvp-2.md)

## Goal

Make VoiceID easy to enroll, easy to verify during transaction signing, and
hard to trigger accidentally.

The UI should make three things obvious:

1. Which device is enrolled.
2. Which phrase the user must say.
3. Which action the recording is bound to and which factor will authorize it.

The browser UX is an experimental speaker and spoken-intent flow. Browser voice
evidence cannot issue a signing grant. Browser transaction signing uses a
user-verified passkey bound to the exact transaction. A future embedded flow may
issue one-use low-risk grants only after every gate in the signing security
profile is implemented and calibrated.

## UX Principles

- Always show the action before recording starts.
- Use press-and-hold recording for transaction confirmation.
- Provide tap-to-start/tap-to-stop and keyboard alternatives.
- Keep enrollment guided and linear.
- Make progress visible with accepted speech segments inside one guided capture.
- Show user-facing quality feedback, then keep model details behind a developer
  diagnostics toggle.
- Keep fixture capture and model-evaluation tools separate from user-facing
  enrollment and signing flows.
- Treat device binding as part of the visible product model: VoiceID works on
  this enrolled device.

## Design References

Use voice-dictation products as interaction references, then adapt them for
wallet security.

| Reference                                                                                                                                 | Useful pattern                                                                                                  | VoiceID adaptation                                                                                      |
| ----------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------- |
| [Wispr Flow](https://wisprflow.ai/)                                                                                                       | Lightweight voice entry across apps, visible listening state, mobile keyboard/start-flow model.                 | Keep recording entry simple and obvious. Show one active listening state and a clear completion action. |
| [Wispr Flow via Zapier](https://zapier.com/blog/wispr-flow/)                                                                              | Desktop hotkey starts recording, recorder animation appears while active, mobile flow uses a microphone button. | Use hold-to-record as the default wallet confirmation control, with tap and keyboard fallbacks.         |
| [Wispr Flow iOS review](https://9to5mac.com/2025/06/30/wispr-flow-is-an-ai-that-transcribes-what-you-say-right-from-the-iphone-keyboard/) | Flow sessions have explicit start and end controls, including a check mark to finish.                           | VoiceID should make recording boundaries explicit: hold starts, release submits, cancel discards.       |
| [Aqua Voice](https://aquavoice.com/)                                                                                                      | Prominent `Hold Space` affordance, compact voice pill, waveform feedback.                                       | Use a compact hold button with waveform/level feedback in the transaction modal.                        |
| [Superwhisper assets](https://superwhisper.com/assets)                                                                                    | Simple recording button, processing state, and mode-specific voice workflows.                                   | Keep enrollment, transaction confirmation, and diagnostics as separate modes with distinct UI states.   |

Do not copy long-running dictation flows directly. VoiceID is a bounded auth
ceremony, so the UI should emphasize scope, consent, and completion rather than
continuous transcription.

## Surfaces

VoiceID should have four UI surfaces.

| Surface                  | Purpose                                                       | Shape                                     |
| ------------------------ | ------------------------------------------------------------- | ----------------------------------------- |
| Setup screen             | Enroll VoiceID on the current device                          | Full-page or settings-panel flow          |
| Transaction confirmation | Verify a spoken command for a specific transaction            | Modal or mobile sheet                     |
| Step-up handoff          | Continue browser, risky, or unsupported tasks through passkey | Inline branch from the confirmation modal |
| Developer diagnostics    | Debug verifier behavior and fixture quality                   | Hidden panel or dev-only route            |

The user-facing app should default to setup and transaction confirmation. The
developer route can expose scores, thresholds, fixture capture, and raw
diagnostic bands.

## Enrollment Flow

Enrollment should feel like setting up a device-bound auth method.

```text
Start VoiceID setup
  -> authenticate with passkey or owner-admin method
  -> confirm current device and consent
  -> request microphone permission
  -> start one guided recording
  -> read several short prompted fragments
  -> recorder segments and quality-checks speech automatically
  -> submit one complete capture
  -> retry the complete capture once only if evidence is insufficient
  -> finalize enrollment
```

Recommended evidence policy:

- One microphone-open and one start/finish interaction.
- Provisional experiment target: 12 seconds of usable speech.
- At least three coherent, non-duplicate prompt segments.
- Retry budget: one full-capture quality retry under a new enrollment challenge
  before suggesting a quieter room, another microphone, or a non-voice method.
- Reject silence, clipping, saturation, low speech, prompt mismatch,
  multi-speaker audio, duplicates, spoof risk, and embedding outliers.

The server configures minimum usable speech, segment count, prompt coverage,
quality, and coherence. The UI renders progress from those requirements. A fixed
number of recording button presses is not part of the security policy.

### Enrollment Screen

Layout:

```text
VoiceID setup

This device
MacBook Pro - Safari

Usable speech 6.4 of 12 seconds
[ accepted ][ speaking ][ waiting ]

Read aloud
"Silver boats cross quiet water"

[ Start guided recording ]

Current fragment
"Seven green lanterns glow nearby"

Status
Good quality - continue
```

Required controls:

- `Start setup`
- `Start guided recording`
- `Stop and discard`
- `Discard and try again`
- `Cancel setup`
- `Finalize VoiceID`

`Finalize VoiceID` is enabled only after the server reports sufficient usable
speech, prompt coverage, quality, and template coherence.

### Enrollment Prompts

Use short, randomized, phonetically varied prompt fragments. They should sound
natural and avoid pretending to authorize a real payment. Static prompt sets
must not become reusable authentication phrases.

Example prompt set:

1. `Silver boats cross quiet water`
2. `Seven green lanterns glow nearby`
3. `Morning clouds drift beyond the station`

The prompt generator and phonetic-coverage policy should be versioned. Store the
prompt policy id with enrollment and template metadata. The server verifies each
segment transcript before including its embedding.

## Transaction Confirmation Flow

Transaction confirmation should use a modal on desktop and a sheet on mobile.
It should present the action first, then ask for one voice recording.

```text
VoiceID Confirmation

Send
50 USDC

To
bob.near

From
pta.near

Say this phrase
"Send 50 USDC to Bob. River seven."

[ Hold to record ]

[ Use passkey instead ]
```

The hold control should be disabled until:

- transaction details are rendered
- the server has persisted the canonical Router binding
- the server challenge is ready
- microphone permission is available or can be requested

## Hold-To-Record Behavior

Primary behavior:

```text
press and hold
  -> recording starts
  -> level meter and countdown animate
release
  -> recording stops
  -> capture submits
```

Requirements:

- Minimum hold duration: 1.5 seconds.
- Preferred usable-speech duration: 3–5 seconds.
- Maximum capture duration: 6 seconds before auto-stop.
- Release before minimum duration discards the capture.
- Escape or cancel stops recording and discards the capture.
- Spacebar should work for keyboard users.
- Tap-to-start/tap-to-stop should be available as an accessibility fallback and
  for devices where press-and-hold is unreliable.
- The UI must stop media tracks after recording.
- A short ready cue and bounded pre-roll/trailing buffer should prevent clipped
  initial and final phonemes.
- One accepted capture completes verification. One quality retry is available
  only under a new challenge.

Recording feedback:

- microphone permission state
- live level meter
- elapsed time
- minimum-duration reached state
- auto-stop countdown
- clear retry reason after rejection or uncertainty

## Verification States

Model verification as a discriminated UI state. Avoid boolean flags.

```ts
export type VoiceIdConfirmationUiState =
  | { kind: 'idle' }
  | { kind: 'preparing_challenge' }
  | { kind: 'ready_to_record'; phrase: string }
  | {
      kind: 'recording';
      startedAtMs: number;
      minDurationMs: number;
      maxDurationMs: number;
    }
  | { kind: 'submitting_capture' }
  | { kind: 'browser_evidence_observed'; next: 'passkey_required' }
  | { kind: 'passkey_in_progress' }
  | { kind: 'embedded_e2_observed'; next: 'server_r1_policy' }
  | { kind: 'signing' }
  | { kind: 'signed'; receipt: VoiceIdSigningReceiptDisplay }
  | { kind: 'step_up_required'; methods: readonly ['passkey'] }
  | { kind: 'rejected'; reason: VoiceIdUiRejectionReason }
  | { kind: 'uncertain'; reason: VoiceIdUiUncertainReason }
  | { kind: 'expired' }
  | { kind: 'device_mismatch' }
  | { kind: 'failed'; message: VoiceIdUiFailureMessage };
```

User-facing result handling:

- `browser_evidence_observed`: show passkey as the authorizing action.
- `embedded_e2_observed`: request server R1 policy and keep the modal open until
  signing succeeds or a terminal result returns.
- `step_up_required`: show passkey handoff in the same modal.
- `rejected`: keep the transaction visible and offer passkey; a new VoiceID
  attempt remains subject to rate limits.
- `uncertain`: suggest a quieter room, one quality retake, or passkey.
- `expired`: regenerate challenge and phrase binding.
- `device_mismatch`: require passkey or enroll VoiceID on this device.
- `failed`: show a recoverable error and retain fallback methods.

## Step-Up Handoff

Step-up should stay inside the same confirmation surface.

```text
VoiceID needs another check

This transaction requires passkey confirmation.

[ Continue with passkey ]
```

Step-up triggers:

- key export
- wallet recovery
- new device enrollment
- high-value transaction signing
- new-recipient transaction signing
- suspicious device or session context
- repeated failed VoiceID attempts
- low-confidence or noisy audio

## Device Binding UI

Enrollment should show the current device as part of the setup.

Required display data:

- device label
- browser or app label
- enrollment date
- last used date
- wallet/account scope

Device settings should support:

- rename device
- disable VoiceID on this device
- re-enroll VoiceID on this device
- view last successful use

If device proof fails during verification, the modal should show:

```text
VoiceID is not active on this device.

[ Use passkey ]
[ Set up VoiceID on this device ]
```

## Playback And Retake

Playback is useful during enrollment and diagnostics. It should be optional
during transaction confirmation.

Enrollment:

- keep playback disabled by default to avoid creating a convenient replay asset
- allow the user to discard the full ceremony before finalization
- retry the complete ceremony once when the server reports insufficient
  quality, prompt coverage, or coherence
- auto-advance between server-provided prompt fragments

Transaction confirmation:

- submit automatically after release
- show playback only after rejection, uncertainty, or developer diagnostics
- avoid extra confirmation clicks after an accepted capture; browser signing
  still performs the explicit passkey ceremony

## Privacy And Retention

The UI should communicate the retention model briefly in setup:

```text
Voice samples are used to build your VoiceID on this device.
Raw recordings are not stored by default.
```

Requirements:

- Do not display raw verifier scores in the default user flow.
- Do not persist raw audio in wallet/session state.
- Do not include raw audio, templates, or private signing material in UI logs.
- Show diagnostic score bands only in developer mode.
- Provide a clear delete/disable path for device-bound VoiceID.

## Accessibility

Requirements:

- Keyboard support for all controls.
- Spacebar hold-to-record support.
- Tap-to-start/tap-to-stop fallback.
- Visible text for every spoken phrase.
- `aria-live` status updates for recording, submitting, accepted, retry, and
  step-up states.
- Clear focus management when modals open, close, or switch to step-up.
- Button text must fit on mobile without overlapping.
- Progress cannot rely on color alone.

## Component Requirements

Add UI components around adapters, rather than binding UI directly to VoiceID
service internals.

Suggested components:

```text
VoiceIdEnrollmentPanel
VoiceIdRecordButton
VoiceIdConfirmationModal
VoiceIdStepUpPanel
VoiceIdDeviceSettingsPanel
VoiceIdDiagnosticsPanel
```

Suggested recorder adapter:

```ts
export type VoiceIdRecorderAdapter = {
  requestPermission(): Promise<VoiceIdRecorderPermissionResult>;
  recordGuidedEnrollment(args: {
    prompts: readonly string[];
    minUsableSpeechMs: number;
    maxDurationMs: number;
  }): Promise<VoiceIdGuidedEnrollmentRecordingResult>;
  recordVerification(args: {
    minDurationMs: number;
    maxDurationMs: number;
  }): Promise<VoiceIdRecordedClipResult>;
  stop(): Promise<void>;
};
```

The React hook should accept capture callbacks or a recorder adapter. It should
not hardwire demo UI into SDK auth logic.

## Phased TODO List

This is the UI implementation plan. It should ship in small slices: first the
recording control, then enrollment, then transaction confirmation, then SDK
integration.

### Phase 0: Reference Translation

Goal: turn the design references into VoiceID-specific UI rules.

- [ ] Convert the Wispr Flow reference into a compact active-recording state:
      idle, listening, processing, complete.
- [ ] Convert the Aqua `Hold Space` reference into a wallet-safe
      `Hold to record` control with visible scope and cancel behavior.
- [ ] Convert the Superwhisper mode reference into separate VoiceID modes:
      enrollment, transaction confirmation, settings, and diagnostics.
- [ ] Add rough wireframes for desktop modal, mobile sheet, and settings-panel
      setup.
- [ ] Decide whether the demo keeps a single page or splits setup and
      confirmation into separate panels.

Validation:

- [ ] Each wireframe shows the device, spoken phrase, and authorized action.
- [ ] No user-facing flow exposes verifier scores by default.

### Phase 1: Recorder Control Foundation

Goal: build the shared interaction primitive used by enrollment and
confirmation.

Candidate surfaces:

- `VoiceIdRecordButton`
- `VoiceIdRecorderAdapter`
- `voiceId/client/src/VoiceIdRecorder.ts`
- `voiceId/demo/src/main.ts`

Tasks:

- [ ] Define `VoiceIdRecordButtonState` as a discriminated union.
- [ ] Add hold-to-record pointer behavior.
- [ ] Add tap-to-start/tap-to-stop fallback.
- [ ] Add Spacebar keyboard fallback.
- [ ] Add minimum duration, maximum duration, auto-stop, and cancel behavior.
- [ ] Show live recording state: elapsed time, level meter, and countdown.
- [ ] Stop media tracks after every recording attempt.
- [ ] Add recorder errors for microphone denied, timeout, too short, cancelled,
      and unsupported browser.

Validation:

- [ ] Unit or browser test proves too-short recordings are discarded.
- [ ] Unit or browser test proves cancel discards the sample.
- [ ] Manual desktop test covers mouse hold, keyboard hold, and tap fallback.
- [ ] Manual mobile test covers touch hold and tap fallback.

### Phase 2: Enrollment UI

Goal: make enrollment a guided device-bound setup flow.

Candidate surfaces:

- `VoiceIdEnrollmentPanel`
- `VoiceIdEnrollmentProgress`
- `VoiceIdEnrollmentPromptCard`
- `voiceId/demo/src/main.ts`

Tasks:

- [ ] Render current device label and enrollment scope.
- [ ] Require recent passkey or owner-admin authentication before capture.
- [ ] Render server-provided usable-speech, segment, prompt-coverage, and
      coherence requirements.
- [ ] Open the microphone once for one guided enrollment recording.
- [ ] Render segmented prompt and usable-speech progress.
- [ ] Show one randomized enrollment prompt fragment at a time.
- [ ] Submit one complete recording; offer one complete quality retry under a
      new challenge when evidence is insufficient.
- [ ] Auto-advance after accepted segments.
- [ ] Show clear retry guidance for silence, clipping, noisy audio, too-short
      speech, prompt mismatch, multiple speakers, duplicate audio, spoof risk,
      outlier embeddings, and verifier uncertainty.
- [ ] Enable finalize only when the server accepts all configured evidence
      requirements.

Validation:

- [ ] Enrollment cannot finalize below the configured evidence requirements.
- [ ] Rejected internal windows do not advance progress or become template
      input.
- [ ] One guided recording produces several independently checked segments.
- [ ] Mobile layout keeps prompt, progress, and hold button visible without
      overlap.

### Phase 3: Transaction Confirmation Modal

Goal: make VoiceID confirmation usable for `send 50 USDC to bob`.

Candidate surfaces:

- `VoiceIdConfirmationModal`
- `VoiceIdTransactionSummary`
- `VoiceIdStepUpPanel`
- `voiceId/demo/src/main.ts`

Tasks:

- [ ] Render transaction summary before enabling recording.
- [ ] Render a short unpredictable phrase derived from the server challenge and
      bound to the full Router transaction digest tuple.
- [ ] Disable recording until the canonical Router transaction, server
      challenge, approved capture profile display, and transaction display are
      ready.
- [ ] Submit the capture on release.
- [ ] Show `submitting_capture` and `processing` states.
- [ ] Handle browser evidence, embedded E2 observation, passkey, signing,
      signed, rejected, uncertain, expired, device mismatch, failed, and
      step-up-required states.
- [ ] Keep passkey available before capture and on every eligible fallback
      branch.
- [ ] In browser mode, complete passkey user verification before calling the
      signing continuation.
- [ ] In an eligible embedded mode, call the signing continuation only after an
      E2 observation, server R1 policy, and atomic grant reservation.

Validation:

- [ ] Recording cannot start before transaction details are visible.
- [ ] Experimental browser evidence cannot call the signing continuation.
- [ ] A fake passkey admission can call a fake signing continuation in browser
      tests; fake voice cannot.
- [ ] A test-only synthetic E2 builder can exercise server policy and grant
      tests without appearing in production routes or bundles.
- [ ] Rejected, uncertain, expired, failed, and step-up-required branches do not
      call the signing continuation.
- [ ] The modal can be dismissed without submitting a sample.

### Phase 4: Device-Bound Settings

Goal: expose enough device context for users to understand where VoiceID works.

Candidate surfaces:

- `VoiceIdDeviceSettingsPanel`
- `VoiceIdDeviceRow`

Tasks:

- [ ] Show enrolled device label.
- [ ] Show browser or app label.
- [ ] Show enrollment date and last-used date.
- [ ] Add rename device flow.
- [ ] Add disable VoiceID on this device.
- [ ] Add re-enroll VoiceID on this device.
- [ ] Add device mismatch copy and recovery path.

Validation:

- [ ] Device mismatch routes to passkey or setup on the current device.
- [ ] Disable flow prevents future VoiceID verification on that device.
- [ ] Re-enroll flow creates a fresh enrollment lifecycle.

### Phase 5: SDK React Integration

Goal: move the UI primitives behind SDK-friendly hooks and adapters.

Candidate surfaces:

- `packages/sdk-web/src/react/hooks/useVoiceIdTransactionAuthorization.ts`
- `packages/sdk-web/src/react/index.ts`
- `packages/sdk-web/src/SeamsWeb/publicApi/types.ts`

Tasks:

- [ ] Add `useVoiceIdTransactionAuthorization(...)` with `start(...)`, `busy`,
      and `error`.
- [ ] Accept a recorder adapter or capture callbacks.
- [ ] Return enrollment and confirmation flow objects with narrow lifecycle
      branches.
- [ ] Export public VoiceID UI/auth types from the React entrypoint.
- [ ] Keep demo UI code out of SDK auth logic.

Validation:

- [ ] Type fixture proves enrollment-only flows cannot submit transaction
      confirmation samples.
- [ ] Type fixture proves confirmation-only flows cannot finalize enrollment.
- [ ] React hook test covers busy/error state transitions.

### Phase 6: Developer Diagnostics

Goal: preserve model debugging without polluting the production auth UI.

Candidate surfaces:

- `VoiceIdDiagnosticsPanel`
- `voiceId/demo/src/main.ts`
- fixture capture route or dev-only panel

Tasks:

- [ ] Move score bands, thresholds, model version, threshold version, prompt set
      id, and quality reasons behind a developer diagnostics toggle.
- [ ] Keep fixture capture out of the transaction confirmation modal.
- [ ] Keep raw audio export behind explicit developer tooling.
- [ ] Add a compact event log for enrollment, verification, owner-presence
      authorization, policy result, and signing continuation.

Validation:

- [ ] Default user flow hides verifier internals.
- [ ] Developer mode can still collect useful fixture/debug evidence.
- [ ] Event log excludes raw audio, templates, private keys, and full secrets.

### Phase 7: Visual And Accessibility QA

Goal: verify the UI works across desktop, mobile, keyboard, touch, and screen
reader paths.

Tasks:

- [ ] Add Playwright screenshots for enrollment desktop and mobile.
- [ ] Add Playwright screenshots for confirmation modal desktop and mobile.
- [ ] Add accessibility checks for focus trap, aria labels, aria-live status,
      keyboard fallback, and color-independent progress.
- [ ] Verify button text fits on narrow mobile widths.
- [ ] Verify no overlapping text in prompt, progress, modal actions, or status.
- [ ] Verify reduced-motion mode disables nonessential animation.

Validation:

- [ ] Desktop enrollment screenshot approved.
- [ ] Mobile enrollment screenshot approved.
- [ ] Desktop confirmation modal screenshot approved.
- [ ] Mobile confirmation modal screenshot approved.
- [ ] Keyboard-only flow can enroll, cancel, retry, and confirm.

## Acceptance Criteria

- A user can enroll VoiceID through one guided continuous capture with
  server-configured usable-speech and coherence requirements.
- Enrollment rejects poor, duplicate, incoherent, multi-speaker, or spoof-risk
  internal windows and offers at most one complete-capture quality retry.
- A user can confirm `send 50 USDC to bob` through a transaction modal.
- The modal shows transaction details before recording starts.
- Press-and-hold recording works on desktop and mobile.
- Keyboard and tap fallbacks work.
- Experimental browser VoiceID never continues the signing path by itself.
- Browser signing continues only after passkey user verification for the exact
  transaction.
- Eligible embedded signing continues only after E2, server R1 policy, and
  atomic one-use grant reservation.
- Step-up keeps the user in the same confirmation surface.
- Device mismatch routes to passkey or setup on the current device.
- The default UI hides verifier internals and raw diagnostic details.
- Developer diagnostics stay separate from the user-facing auth flow.
