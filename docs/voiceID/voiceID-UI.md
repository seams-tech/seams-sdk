# VoiceID UI/UX Plan

Status: product and implementation requirements.

Related docs:

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
3. Which action the voice sample will authorize.

The first production UX target is device-bound VoiceID as an email-OTP-equivalent
wallet auth method. VoiceID can issue a one-use grant for low-risk, intent-bound
signing. Riskier tasks route to email OTP or passkey step-up.

## UX Principles

- Always show the action before recording starts.
- Use press-and-hold recording for transaction confirmation.
- Provide tap-to-start/tap-to-stop and keyboard alternatives.
- Keep enrollment guided and linear.
- Make progress visible with accepted sample segments.
- Show user-facing quality feedback, then keep model details behind a developer
  diagnostics toggle.
- Keep fixture capture and model-evaluation tools separate from user-facing
  enrollment and signing flows.
- Treat device binding as part of the visible product model: VoiceID works on
  this enrolled device.

## Design References

Use voice-dictation products as interaction references, then adapt them for
wallet security.

| Reference | Useful pattern | VoiceID adaptation |
| --- | --- | --- |
| [Wispr Flow](https://wisprflow.ai/) | Lightweight voice entry across apps, visible listening state, mobile keyboard/start-flow model. | Keep recording entry simple and obvious. Show one active listening state and a clear completion action. |
| [Wispr Flow via Zapier](https://zapier.com/blog/wispr-flow/) | Desktop hotkey starts recording, recorder animation appears while active, mobile flow uses a microphone button. | Use hold-to-record as the default wallet confirmation control, with tap and keyboard fallbacks. |
| [Wispr Flow iOS review](https://9to5mac.com/2025/06/30/wispr-flow-is-an-ai-that-transcribes-what-you-say-right-from-the-iphone-keyboard/) | Flow sessions have explicit start and end controls, including a check mark to finish. | VoiceID should make recording boundaries explicit: hold starts, release submits, cancel discards. |
| [Aqua Voice](https://aquavoice.com/) | Prominent `Hold Space` affordance, compact voice pill, waveform feedback. | Use a compact hold button with waveform/level feedback in the transaction modal. |
| [Superwhisper assets](https://superwhisper.com/assets) | Simple recording button, processing state, and mode-specific voice workflows. | Keep enrollment, transaction confirmation, and diagnostics as separate modes with distinct UI states. |

Do not copy long-running dictation flows directly. VoiceID is a bounded auth
ceremony, so the UI should emphasize scope, consent, and completion rather than
continuous transcription.

## Surfaces

VoiceID should have four UI surfaces.

| Surface | Purpose | Shape |
| --- | --- | --- |
| Setup screen | Enroll VoiceID on the current device | Full-page or settings-panel flow |
| Transaction confirmation | Verify a spoken command for a specific transaction | Modal or mobile sheet |
| Step-up handoff | Continue risky tasks through email OTP or passkey | Inline branch from the confirmation modal |
| Developer diagnostics | Debug verifier behavior and fixture quality | Hidden panel or dev-only route |

The user-facing app should default to setup and transaction confirmation. The
developer route can expose scores, thresholds, fixture capture, and raw
diagnostic bands.

## Enrollment Flow

Enrollment should feel like setting up a device-bound auth method.

```text
Start VoiceID setup
  -> confirm current device
  -> request microphone permission
  -> record accepted sample 1
  -> record accepted sample 2
  -> record accepted sample 3
  -> record accepted sample 4
  -> record accepted sample 5
  -> finalize enrollment
```

Recommended sample policy:

- Production default: 5 accepted samples.
- Developer/demo default: 3 accepted samples.
- Maximum attempts: 8 before suggesting a quieter room or different microphone.
- Sample duration: 2-5 seconds of detected speech.
- Reject silence, clipping, saturation, too-short speech, and excessive noise.

The sample count should be server-configured and surfaced to the UI through the
enrollment record. The UI should render progress from the record instead of
hardcoding the production count.

### Enrollment Screen

Layout:

```text
VoiceID Setup

This device
MacBook Pro - Safari

Sample 2 of 5
[ accepted ][ current ][ empty ][ empty ][ empty ]

Read aloud
"My voice confirms this wallet on this device"

[ Hold to record ]

Last sample
[ Playback ] [ Retake ]

Status
Accepted
```

Required controls:

- `Start setup`
- `Hold to record`
- `Playback last sample`
- `Retake last sample`
- `Cancel setup`
- `Finalize VoiceID`

`Finalize VoiceID` is enabled only after the configured accepted sample count is
met.

### Enrollment Prompts

Use short stable prompts for enrollment. They should sound natural and avoid
pretending to authorize a real payment.

Example prompt set:

1. `My voice confirms this wallet on this device`
2. `This device can recognize my voice`
3. `I am setting up VoiceID for my wallet`
4. `VoiceID will ask before signing`
5. `Only my enrolled voice should pass`

The prompt set should be versioned. Store the prompt set id with the enrollment
record and template metadata.

## Transaction Confirmation Flow

Transaction confirmation should use a modal on desktop and a sheet on mobile.
It should present the action first, then ask for a voice sample.

```text
VoiceID Confirmation

Send
50 USDC

To
bob.near

From
pta.near

Say this phrase
"send 50 USDC to bob"

[ Hold to record ]

[ Use email OTP ] [ Use passkey ]
```

The hold control should be disabled until:

- transaction details are rendered
- `intentDigest` has been computed
- the server challenge is ready
- the enrolled device proof is available
- microphone permission is available or can be requested

## Hold-To-Record Behavior

Primary behavior:

```text
press and hold
  -> recording starts
  -> level meter and countdown animate
release
  -> recording stops
  -> sample submits
```

Requirements:

- Minimum hold duration: 1.5 seconds.
- Preferred capture duration: 2-5 seconds.
- Maximum capture duration: 6 seconds before auto-stop.
- Release before minimum duration discards the sample.
- Escape or cancel stops recording and discards the sample.
- Spacebar should work for keyboard users.
- Tap-to-start/tap-to-stop should be available as an accessibility fallback and
  for devices where press-and-hold is unreliable.
- The UI must stop media tracks after recording.

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
  | { kind: 'recording'; startedAtMs: number; minDurationMs: number; maxDurationMs: number }
  | { kind: 'submitting_sample' }
  | { kind: 'accepted'; grantId: string }
  | { kind: 'step_up_required'; methods: readonly ['email_otp' | 'passkey'] }
  | { kind: 'rejected'; reason: string }
  | { kind: 'uncertain'; reason: string }
  | { kind: 'expired' }
  | { kind: 'device_mismatch' }
  | { kind: 'failed'; message: string };
```

User-facing result handling:

- `accepted`: close modal and continue signing.
- `step_up_required`: show email OTP/passkey handoff in the same modal.
- `rejected`: allow retry and keep the transaction visible.
- `uncertain`: suggest a quieter room, retake, email OTP, or passkey.
- `expired`: regenerate challenge and phrase binding.
- `device_mismatch`: require passkey/email OTP or enroll VoiceID on this device.
- `failed`: show a recoverable error and retain fallback methods.

## Step-Up Handoff

Step-up should stay inside the same confirmation surface.

```text
VoiceID needs another check

This transaction requires email OTP or passkey.

[ Continue with email OTP ]
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

[ Use email OTP ]
[ Use passkey ]
[ Set up VoiceID on this device ]
```

## Playback And Retake

Playback is useful during enrollment and diagnostics. It should be optional
during transaction confirmation.

Enrollment:

- show playback for the last sample
- allow retake before finalization
- auto-advance after accepted samples

Transaction confirmation:

- submit automatically after release
- show playback only after rejection, uncertainty, or developer diagnostics
- avoid extra confirmation clicks after an accepted sample

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
  recordClip(args: {
    minDurationMs: number;
    maxDurationMs: number;
    expectedPhrase: string;
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
- [ ] Render server-provided required accepted sample count.
- [ ] Use 5 accepted samples for production config and 3 for demo/dev config.
- [ ] Render segmented sample progress.
- [ ] Show one enrollment prompt at a time.
- [ ] Add playback for the last sample.
- [ ] Add retake for the last sample before finalization.
- [ ] Auto-advance after accepted samples.
- [ ] Show clear retry guidance for silence, clipping, noisy audio, too-short
      speech, and verifier uncertainty.
- [ ] Enable finalize only when the accepted sample count reaches the configured
      minimum.

Validation:

- [ ] Enrollment cannot finalize below the configured accepted sample count.
- [ ] Rejected samples do not advance progress.
- [ ] Playback is local UI only and does not imply raw-audio persistence.
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
- [ ] Render exact spoken phrase derived from the transaction intent.
- [ ] Disable recording until `intentDigest`, server challenge, device proof,
      and transaction display are ready.
- [ ] Submit the sample on release.
- [ ] Show `submitting_sample` and `processing` states.
- [ ] Handle accepted, rejected, uncertain, expired, device mismatch, failed,
      and step-up-required states.
- [ ] Keep email OTP and passkey fallback buttons available.
- [ ] Close the modal and call the signing continuation only after an accepted
      one-use grant.

Validation:

- [ ] Recording cannot start before transaction details are visible.
- [ ] Accepted grant path calls the fake signing continuation in demo mode.
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

- [ ] Device mismatch routes to email OTP, passkey, or setup on the current
      device.
- [ ] Disable flow prevents future VoiceID verification on that device.
- [ ] Re-enroll flow creates a fresh enrollment lifecycle.

### Phase 5: SDK React Integration

Goal: move the UI primitives behind SDK-friendly hooks and adapters.

Candidate surfaces:

- `packages/sdk-web/src/react/hooks/useVoiceIdWalletAuth.ts`
- `packages/sdk-web/src/react/index.ts`
- `packages/sdk-web/src/SeamsWeb/publicApi/types.ts`

Tasks:

- [ ] Add `useVoiceIdWalletAuth(...)` with `start(...)`, `busy`, and `error`.
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

- A user can enroll VoiceID on the current device with the configured number of
  accepted samples.
- Enrollment rejects poor samples with clear retry guidance.
- A user can confirm `send 50 USDC to bob` through a transaction modal.
- The modal shows transaction details before recording starts.
- Press-and-hold recording works on desktop and mobile.
- Keyboard and tap fallbacks work.
- Accepted VoiceID closes the modal and continues the existing signing path.
- Step-up keeps the user in the same confirmation surface.
- Device mismatch routes to email OTP, passkey, or setup on the current device.
- The default UI hides verifier internals and raw diagnostic details.
- Developer diagnostics stay separate from the user-facing auth flow.
