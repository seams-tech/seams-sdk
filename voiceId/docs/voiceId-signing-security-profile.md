# VoiceID Signing Security Profile

Status: normative security profile and phased implementation plan.

Related implementation documents:

- [VoiceID MVP 1](voiceId-mvp-1.md)
- [VoiceID MVP 2](voiceId-mvp-2.md)
- [Voice biometrics design](voice-biometrics.md)
- [SDK auth-method integration](voiceId-sdk-auth-method-integration.md)
- [Normal SDK transaction signing](voiceId-normal-sdk-transaction-signing.md)
- [Router admission adapter](voiceId-router-policy-issuer.md)
- [Router A/B signer architecture](../../docs/router-a-b-SPEC.md)

This document is the authority for deciding whether VoiceID evidence may reach
transaction signing. VoiceID research, UI, verifier, auth-method, Router, and
robotics documents remain useful implementation references. Where their
signing-eligibility rules differ from this profile, this profile takes
precedence.

The current browser MVP is E0 experimental evidence under this profile. No
current browser VoiceID result is eligible for direct signing.

The key words **MUST**, **MUST NOT**, **REQUIRED**, **SHOULD**, **SHOULD NOT**,
and **MAY** describe requirements for conformance to this profile.

## Security Objective

VoiceID may supply probabilistic owner-presence evidence for one short-lived,
canonical operation. Router policy remains the signing admission boundary, and
the active SigningWorker remains the MPC participant.

The complete authorization chain is:

```text
server-canonical Router intent and signing payload
  -> server-issued unpredictable voice challenge
  -> one continuous device-bound audio capture
  -> speaker + phrase + quality + freshness + PAD verification
  -> risk policy
  -> one-use grant for the exact Router digest tuple
  -> atomic Router reservation
  -> existing Router A/B MPC signing flow
```

Every arrow is a security boundary. Success at one boundary MUST NOT imply
success at another.

This is a custom risk-based R1 control. It does not claim that remote voice
comparison is a NIST-conformant authenticator. NIST SP 800-63B-4 excludes voice
biometric comparison from its biometric authenticator model. Browser and R2/R3
wallet flows use passkey user verification.

The following invariants apply:

1. VoiceID MUST NOT create a general signing session or reusable bearer
   credential.
2. Browser-captured experimental evidence MUST NOT issue or consume a signing
   grant.
3. Client-reported timestamps, microphone labels, source trust, replay risk,
   transcripts, or policy choices MUST NOT establish signing eligibility.
4. A signing candidate MUST contain accepted speaker, phrase, quality, capture
   freshness, PAD, device-proof, capture-profile, and intent-binding results.
5. Missing, rejected, expired, or uncertain checks fail closed or require an
   independent step-up factor.
6. One challenge binds one capture. One accepted capture may issue one grant.
   One grant may reserve one Router request.
7. MPC protects key custody and produces the signature. It cannot repair an
   incorrect biometric or policy decision.

## Threat Assumptions

The profile assumes an attacker can obtain recordings of the owner, generate
targeted synthetic or converted speech, replay or relay media, inject audio into
ordinary browser capture, control browser application code, mutate client
requests, observe prompts, submit many attempts, and race or replay grants. A
stolen or revoked enrolled device is also an expected policy input.

The server challenge service, Router admission boundary, active SigningWorker,
approved device-key boundary, and configured cryptographic primitives follow
their existing trust models. Compromise of one of those trusted services
requires a wider wallet-security response; speaker or PAD scores cannot contain
that compromise.

## Terms And Independent Guarantees

The word `liveness` is too broad for a core signing decision. Core types and
policy MUST represent the following checks separately.

| Term                                | Precise guarantee                                                                                                                                                                                   | Explicit limit                                                                                                                                      |
| ----------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------- |
| Speaker verification                | A probabilistic comparison between speech in the current capture and an enrolled speaker template.                                                                                                  | It does not establish phrase content, freshness, physical presence, or intent.                                                                      |
| Phrase verification                 | The server expected prompt was spoken with sufficient confidence and in the required order.                                                                                                         | It does not establish speaker identity or bona-fide capture.                                                                                        |
| Capture quality                     | The decoded speech satisfies the calibrated duration, SNR, clipping, codec, channel, and single-speaker constraints.                                                                                | Quality is an eligibility gate. It is not identity or PAD evidence.                                                                                 |
| Capture freshness                   | The capture responds to a live, unexpired, server-owned challenge and arrives within its one-use timing window.                                                                                     | Freshness resists cached fixed-phrase replay. It does not stop prompt-targeted synthesis or live relay.                                             |
| Presentation attack detection (PAD) | A probabilistic authenticity decision for the attack classes covered by the active PAD calibration, including replay, synthesis, voice conversion, splicing, and digital injection where supported. | PAD only covers measured attacks and capture profiles. It is never described as proof of a live human.                                              |
| Device proof                        | A signature from an enrolled device key over the challenge, Router binding, prompt hash, exact uploaded-audio hash, capture interval, and capture profile.                                          | It proves key participation and byte binding. It is not microphone attestation unless the approved profile supplies independent sensor attestation. |
| Canonical intent binding            | The VoiceID challenge, device proof, grant, Router request, and prepared signing payload carry the same Router-derived digest tuple.                                                                | Spoken text and a client-created digest cannot substitute for Router canonicalization.                                                              |
| MPC signing                         | The existing Router A/B and active SigningWorker flow produces a signature after admission.                                                                                                         | MPC is downstream of VoiceID and must receive only an admitted, reserved operation.                                                                 |

An audit or UI layer MAY summarize the ceremony as “voice verification.”
Internal policy MUST consume the separate results.

## Evidence Tiers

VoiceID evidence has three tiers. A higher tier requires a distinct typed
construction path; runtime flags MUST NOT upgrade a lower-tier object.

| Tier                      | Meaning                                                                                                                    | Permitted use                                                                                    |
| ------------------------- | -------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------ |
| E0 — experimental browser | Audio came from an ordinary browser capture path, or freshness/source/PAD claims remain client-reported or uncalibrated.   | Research, UX evaluation, verifier fixtures, and policy shadowing only.                           |
| E1 — step-up-only         | The server verified useful voice evidence, while at least one signing requirement or approved capture guarantee is absent. | Offer or inform an independent passkey or equivalent step-up. It confers no signing authority.   |
| E2 — signing candidate    | Every required check is server-verified and accepted under an approved capture, model, threshold, PAD, and policy version. | Input to Router risk policy for one exact operation. Router may still reject or require step-up. |

`MediaRecorder`, Web Audio, browser `deviceId`, browser timestamps, and a
browser-held application key remain E0 inputs. A passkey performed after an E0
voice interaction MAY authorize the operation through the passkey path; the
voice evidence remains E0.

The target domain split is:

```ts
export type VoiceIdEvidence =
  | VoiceIdExperimentalBrowserEvidence
  | VoiceIdStepUpOnlyEvidence
  | VoiceIdSigningCandidateEvidence;

export type VoiceIdExperimentalBrowserEvidence = {
  kind: 'experimental_browser_evidence';
  verificationId: VoiceIdVerificationId;
  observedChecks: VoiceIdObservedChecks;
  signingCandidate?: never;
  signingGrant?: never;
};

export type VoiceIdStepUpOnlyEvidence = {
  kind: 'step_up_only_evidence';
  verificationId: VoiceIdVerificationId;
  routerBinding: RouterVoiceIntentBinding;
  reason: VoiceIdStepUpReason;
  signingCandidate?: never;
  signingGrant?: never;
};

export type VoiceIdSigningCandidateEvidence = {
  kind: 'signing_candidate_evidence';
  verificationId: VoiceIdVerificationId;
  enrollmentId: VoiceIdEnrollmentId;
  routerBinding: RouterVoiceIntentBinding;
  speaker: VoiceIdAcceptedSpeaker;
  phrase: VoiceIdAcceptedPhrase;
  quality: VoiceIdAcceptedQuality;
  captureFreshness: VoiceIdAcceptedCaptureFreshness;
  pad: VoiceIdAcceptedPad;
  deviceProof: VoiceIdVerifiedDeviceProof;
  captureProfile: VoiceIdApprovedCaptureProfile;
  calibration: VoiceIdApprovedCalibration;
};
```

Only the narrow E2 type may enter grant policy:

```ts
declare function evaluateVoiceIdSigningPolicy(
  evidence: VoiceIdSigningCandidateEvidence,
  risk: VoiceIdRiskDecision,
): VoiceIdSigningPolicyResult;

declare const browserEvidence: VoiceIdExperimentalBrowserEvidence;
declare const riskDecision: VoiceIdRiskDecision;

// @ts-expect-error Browser evidence cannot enter signing policy.
evaluateVoiceIdSigningPolicy(browserEvidence, riskDecision);
```

The cutover deletes branches such as `liveness: { kind: 'not_required' }` from
signing-facing types, tests, and fixtures. If persisted records require a data
rewrite, that parser exists only at the storage boundary and is deleted after
the rewrite completes. Untrusted current inputs parse directly to E0/E1,
rejection, or uncertainty before core policy runs.

## Server-Owned Intent And Challenge

### Canonical Router binding

The server MUST fix the complete transaction before issuing the voice
challenge. It MUST use the same typed Router A/B builders used by normal
signing, then persist this immutable binding:

```ts
export type RouterVoiceIntentBinding = {
  kind: 'router_voice_intent_binding_v1';
  subjectId: WalletSubjectId;
  walletId: WalletId;
  sessionId: WalletSessionId;
  organizationId: OrganizationId;
  projectId: ProjectId;
  environmentId: EnvironmentId;
  operationId: RouterAbOperationId;
  operationFingerprint: RouterAbOperationFingerprint;
  intentDigest: PublicDigest32;
  signingPayloadDigest: PublicDigest32;
  admittedSigningDigest: PublicDigest32;
  accountId: AccountId;
  networkId: NetworkId;
  expiresAtMs: number;
};
```

The binding corresponds to the canonical
`RouterAbEd25519NormalSigningIntentV2`, typed signing payload, and
`RouterAbEd25519NormalSigningAdmissionMaterialV2`. A client MAY submit raw
transaction fields at a request boundary. It MUST NOT submit an authoritative
digest or choose the canonicalization version.

VoiceID signing MUST NOT maintain a second independently canonicalized signing
intent. Any voice-specific challenge digest is a domain-separated derivative
of `RouterVoiceIntentBinding`, never a parallel source of authority.

The user-facing summary MUST be deterministically derived from the same binding
and its resolved transaction data. It SHOULD include the action, display
amount, asset, network, recipient label, and a short address suffix where
applicable. A changed transaction requires a new binding and challenge.

### Challenge creation

After persisting the Router binding, the server creates an unpredictable,
single-use prompt. The prompt combines the human-checkable transaction summary
with a short random fragment:

```text
Send 50 USDC on Base to Bob, address ending 7F3A. River seven.
```

The server owns the text, nonce, timing, capture profile, and expected phrase.
The client only renders the challenge and captures the response.

```ts
export type VoiceIdServerChallenge = {
  kind: 'voice_id_server_challenge_v1';
  verificationId: VoiceIdVerificationId;
  challengeNonce: VoiceIdChallengeNonce;
  routerBinding: RouterVoiceIntentBinding;
  promptText: VoiceIdPromptText;
  promptHash: PublicDigest32;
  captureProfileId: VoiceIdCaptureProfileId;
  issuedAtMs: number;
  captureNotBeforeMs: number;
  expiresAtMs: number;
};
```

Challenge state MUST be stored server-side. A challenge expires after one
submission attempt, expiry, cancellation, or transaction mutation. A quality
retry receives a new `verificationId`, nonce, random fragment, and expiry.

## Capture And Device Proof

### Capture protocol

For every attempt, an approved capture agent MUST:

1. Receive the server challenge over an authenticated channel.
2. Start one continuous recording after receiving the challenge.
3. Capture the complete prompt in the challenge-approved format.
4. Hash the exact media bytes that will be uploaded, before transcoding or
   server normalization.
5. Sign the canonical capture statement with the enrolled device key.
6. Upload the media, statement, and signature as one submission.

The signed statement is:

```ts
export type VoiceIdDeviceCaptureStatementV1 = {
  kind: 'voice_id_device_capture_statement_v1';
  deviceId: VoiceIdDeviceId;
  verificationId: VoiceIdVerificationId;
  challengeNonce: VoiceIdChallengeNonce;
  routerBindingDigest: PublicDigest32;
  promptHash: PublicDigest32;
  audioHash: PublicDigest32;
  captureProfileId: VoiceIdCaptureProfileId;
  captureStartedAtMs: number;
  captureEndedAtMs: number;
};
```

The signature payload MUST use a versioned domain separator and deterministic
encoding. The server MUST recompute `audioHash`, `promptHash`, and
`routerBindingDigest`; verify every statement field against stored challenge
state; verify the device signature; and enforce the server receipt window.
Client capture times provide consistency evidence only. Server issue, receipt,
and consumption times control freshness.

An approved signing capture profile MUST define:

- capture agent identity and integrity assumptions;
- device-key algorithm, protection class, attestation requirements, and
  revocation behavior;
- accepted codecs, sample rates, channel layouts, duration bounds, and maximum
  upload size;
- preprocessing, VAD, resampling, and normalization versions;
- minimum usable speech, SNR, clipping, and single-speaker requirements;
- supported languages, devices, microphones, and acoustic environments;
- PAD coverage and calibration report identifiers;
- whether physical microphone or application integrity is attested.

Unknown codecs, channel changes, missing metadata, hash mismatches, multiple
speakers, excessive silence, clipping, or out-of-window uploads MUST yield
rejection or uncertainty. Diagnostics MUST NOT influence the result after the
typed verification boundary.

### Verification recording

One verification attempt uses one continuous recording with an initial target
of 3–5 seconds of usable speech. VAD MAY create several non-overlapping scoring
windows internally without adding user recording ceremonies.

The verifier MAY combine window-level evidence within that attempt under a
calibrated aggregation rule. It MUST NOT average audio or scores across retries.
One quality retry is the default maximum. Risk policy MAY allow zero retries and
MUST cap total attempts across sessions, devices, accounts, and network origin.

## Enrollment And Template Evolution

### Signing-grade enrollment

Signing-grade enrollment requires recent passkey or equivalent owner
authentication, an enrolled device key, an approved capture profile, and
accepted enrollment PAD. Browser E0 enrollment creates a research template and
cannot later be relabeled as signing-grade.

The verification capture protocol also applies to signing-grade enrollment.
The signed enrollment statement replaces the Router binding with the
server-owned enrollment challenge and still covers the exact uploaded-audio
hash, prompt hash, timing, device, and capture profile.

Enrollment SHOULD use one guided continuous recording instead of several
button-driven clips:

1. The server issues three to five randomized, phonetically varied prompt
   fragments.
2. The user completes one recording with an initial target of 10–15 seconds of
   usable speech.
3. VAD segments the recording into non-overlapping speech windows.
4. The server checks prompt coverage, single-speaker consistency, quality, PAD,
   duplicate fingerprints, and embedding coherence.
5. It rejects outlier windows and creates a normalized, quality-weighted
   template under a versioned aggregation policy.
6. It deletes the raw recording after template extraction and persistence
   verification.

Several windows preserve the statistical benefit of multiple embeddings while
keeping one capture ceremony. Immediate clips from the same room and minute add
little channel diversity. Later, strongly authenticated sessions provide more
useful diversity.

The enrollment lifecycle MUST keep invalid states unrepresentable:

```ts
export type VoiceIdEnrollmentState =
  | {
      kind: 'capture_pending';
      enrollmentId: VoiceIdEnrollmentId;
      challenge: VoiceIdEnrollmentChallenge;
      template?: never;
    }
  | {
      kind: 'enrolled';
      enrollmentId: VoiceIdEnrollmentId;
      template: VoiceIdEncryptedTemplate;
      assurance: 'signing_grade';
      challenge?: never;
    }
  | {
      kind: 'disabled';
      enrollmentId: VoiceIdEnrollmentId;
      disabledAtMs: number;
      challenge?: never;
      template?: never;
    };
```

### Progressive adaptation

The initial signing template is an immutable anchor. Voice-only successes MUST
NOT update it during the research, shadow, or step-up phases.

Later adaptation MAY be enabled by a separately versioned policy after an
adaptation-poisoning evaluation passes. Each candidate update MUST:

- come from an E2 capture followed by successful independent passkey owner
  verification;
- come from a different session and satisfy minimum elapsed-time and channel
  diversity rules;
- pass stricter speaker, PAD, quality, and drift thresholds than ordinary
  verification;
- enter quarantine before promotion;
- have a bounded influence weight and a maximum cumulative drift from the
  immutable anchor;
- create a new encrypted template version with audit provenance and rollback;
- be excluded after retries, anomalies, recovery, device replacement,
  uncertain checks, or policy fallback.

Promotion MUST be atomic. Revocation or deletion MUST remove pending candidates
and active adapted versions. The anchor is replaced only through a new
strongly authenticated enrollment ceremony.

## Verification And Policy Outcomes

Component results MUST be parsed once at verifier, device, ASR, storage, and
Router boundaries. Core policy receives precise internal types. It MUST NOT
accept raw model scores, raw strings, partial records, client diagnostics, or
compatibility objects.

An exhaustive verification result should have this shape:

```ts
export type VoiceIdVerificationResult =
  | {
      kind: 'signing_candidate';
      evidence: VoiceIdSigningCandidateEvidence;
    }
  | {
      kind: 'step_up_required';
      evidence: VoiceIdStepUpOnlyEvidence;
      allowedMethod: 'passkey';
    }
  | {
      kind: 'rejected';
      verificationId: VoiceIdVerificationId;
      reason: VoiceIdRejectionReason;
    }
  | {
      kind: 'uncertain';
      verificationId: VoiceIdVerificationId;
      reason: VoiceIdUncertainReason;
    }
  | {
      kind: 'expired';
      verificationId: VoiceIdVerificationId;
    };

export function assertNever(value: never): never {
  throw new Error(`Unexpected VoiceID branch: ${String(value)}`);
}
```

Speaker mismatch, phrase mismatch, failed device proof, hash mismatch, replay,
and PAD rejection produce `rejected`. Low quality, unavailable calibrated
models, borderline scores, and unsupported capture conditions produce
`uncertain`. Neither branch may carry a Router continuation or grant.

## Risk Tiers

Risk is server-derived after E2 construction. Client labels are display hints.
Limits, allowlists, anomaly rules, and monetary conversions MUST be versioned
server policy.

| Tier                      | Typical operations                                                                                                                                                                  | VoiceID result                                                                                    |
| ------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------- |
| R0 — no signing authority | Read-only queries, local UI commands, research simulations                                                                                                                          | No signing grant.                                                                                 |
| R1 — voice eligible       | Low-value transfer below conservative per-operation and rolling caps, established recipient, healthy enrolled device/session, approved capture profile                              | E2 may issue one exact-operation grant after Router policy accepts.                               |
| R2 — independent step-up  | New or recently changed recipient, elevated value, unusual location/device/session, degraded sensors, recent failures, policy anomaly                                               | Passkey or equivalent cryptographic user verification is required. Voice may supply context only. |
| R3 — voice prohibited     | Key export, wallet recovery, device enrollment or replacement, biometric reset, policy/admin changes, security-factor changes, uncapped sessions, and safety-critical robot actions | Voice cannot unlock or reduce the required factors.                                               |

Uncertainty, missing telemetry, policy-version mismatch, clock anomalies, model
outage, or a stricter overlapping rule can only raise the tier. Repeated attempts
MUST raise the tier or lock VoiceID for a bounded period. Recipient age, value
caps, and anomaly thresholds are deployment policy; they require explicit
values before an R1 pilot.

Robot command authorization additionally requires an independent safety
controller. Voice admission MUST NOT bypass workspace, motion, force, tool,
proximity, or emergency-stop policy.

## One-Use Signing Grant

An E2 result remains evidence until risk policy accepts it. The issued grant is
a server-side record or a signed reference backed by a server-side one-use
record. A self-contained bearer token alone is insufficient.

The grant MUST bind:

- grant, verification, enrollment, user, wallet, account, device, session,
  project, environment, and policy identifiers;
- the complete `RouterVoiceIntentBinding`;
- capture, speaker, phrase, quality, PAD, model, threshold, calibration, and
  capture-profile versions;
- issue and expiry times;
- maximum risk tier `R1`;
- exactly one Router request digest once reserved.

Grant state is a discriminated union:

```ts
export type VoiceIdSigningGrantState =
  | {
      kind: 'issued';
      grant: VoiceIdSigningGrant;
      reservation?: never;
      terminal?: never;
    }
  | {
      kind: 'reserved';
      grant: VoiceIdSigningGrant;
      reservation: VoiceIdRouterReservation;
      terminal?: never;
    }
  | {
      kind: 'consumed';
      grant: VoiceIdSigningGrant;
      reservation: VoiceIdRouterReservation;
      terminal: VoiceIdSigningReceipt;
    }
  | {
      kind: 'failed_closed';
      grant: VoiceIdSigningGrant;
      reservation: VoiceIdRouterReservation;
      terminal: VoiceIdTerminalFailure;
    }
  | {
      kind: 'expired';
      grant: VoiceIdSigningGrant;
      reservation?: never;
      terminal: VoiceIdTerminalReason;
    }
  | {
      kind: 'revoked';
      grant: VoiceIdSigningGrant;
      reservation?: never;
      terminal: VoiceIdTerminalReason;
    };
```

Router admission MUST perform one atomic compare-and-set transaction that:

1. loads the `issued` grant;
2. verifies expiry, revocation, user/session/account scope, policy versions,
   Router digest tuple, request digest, risk tier, and replay state;
3. transitions `issued` to `reserved` with the exact Router request digest.

Only the process holding that reservation may call the SigningWorker. A
reserved grant never returns to `issued`. Successful finalization transitions
to `consumed`. Timeout, worker failure, response loss, or cancellation
transitions to `failed_closed`; a retry starts a new VoiceID challenge. This
rule prefers an extra owner ceremony over replayable authorization.

The Router and SigningWorker MUST independently validate the Router digest
tuple and normal-signing transcript fields already required by the Router A/B
specification. The VoiceID layer MUST NOT call Deriver roles or handle signing
shares.

## Calibration And Release Gates

A model being available is insufficient for E2. Each combination of speaker
model, speaker threshold, PAD model, PAD threshold, aggregation rule, capture
profile, language cohort, and retry policy requires an immutable approved
calibration record.

### Speaker and phrase gate

Before E2 enablement, evaluation MUST include:

- independent speakers and enrollment/verification sessions collected across
  days;
- speaker-disjoint development and held-out test cohorts;
- supported microphones, devices, codecs, distances, languages, noise, and
  channel conditions;
- genuine user variation, including illness or aging where the target rollout
  claims coverage;
- look-alike and deliberately imitated voices;
- per-channel and worst-cohort false-accept and false-reject reporting with
  confidence intervals;
- the deployed maximum attempt and retry policy;
- phrase substitution, truncation, reordering, ASR ambiguity, and random-code
  tests.

Altered owner clips, synthetic voices, and a small set of generated negatives
do not count as independent human impostors. Zero observed errors in a small
fixture set MUST NOT be presented as a production error rate.

### PAD gate

PAD evaluation MUST include bona-fide captures and, at minimum:

- ordinary replay over multiple speakers, rooms, playback devices, distances,
  and volume levels;
- direct digital or virtual-microphone injection where the profile can receive
  it;
- text-to-speech and voice conversion from short and long attacker training
  material;
- phrase splicing and prompt-targeted generation;
- live relay and re-recording;
- attacks tuned against both the speaker verifier and PAD;
- unseen attack tools and held-out attack conditions.

Reports MUST show attack-presentation acceptance and bona-fide rejection by
attack class and capture profile, plus the combined end-to-end unauthorized
acceptance rate. The 95% upper confidence bound of the combined result MUST fit
the explicit R1 per-operation risk budget. A pooled average cannot hide a
failing device, language, demographic, or attack cohort.

### Operational gate

E2 remains disabled until all of these hold:

- the exact build passes speaker, phrase, PAD, device-proof, intent-mutation,
  replay, grant-race, and deletion tests;
- a shadow deployment reproduces expected score and latency distributions;
- rate limits, value caps, allowlists, monitoring, step-up, revocation, and a
  kill switch work end to end;
- model, threshold, policy, capture, and calibration versions appear in audit
  records;
- an independent security review approves the R1 scope.

A model, threshold, preprocessing, prompt, capture-agent, device-key, retry,
or risk-policy change invalidates the affected approval until the relevant
gates rerun. A failing cohort disables that capture profile or scope.

## Privacy, Retention, And Deletion

Voice recordings and templates are biometric personal data. They MUST remain
outside logs, analytics events, crash reports, traces, support payloads, and
signing grants.

Production rules are:

1. Raw enrollment and verification media is transient by default and deleted
   immediately after the terminal result and template write verification. A
   processing sweeper MUST enforce a short hard TTL for abandoned attempts.
2. Diagnostic media retention requires explicit per-capture owner consent, a
   stated purpose, encryption, separate access control, an object-level expiry,
   and a maximum seven-day TTL. It MUST be disabled for ordinary production
   requests.
3. External verifier and ASR providers MUST have retention and training disabled
   contractually and technically. Provider failures MUST preserve deletion
   obligations.
4. Templates and adaptation candidates MUST use envelope encryption with AAD
   bound to subject, enrollment, template, model, threshold, and key-rotation
   versions.
5. Services receive the minimum template access required for one operation.
   Raw embeddings MUST NOT cross into wallet, Router, SigningWorker, or audit
   domains.
6. Audit records store identifiers, policy/model versions, coarse score bands,
   reason codes, digests, timing bands, and deletion receipts. They exclude
   audio, embeddings, full transcripts, and raw model responses.
7. Enrollment disablement immediately revokes pending challenges and grants.
   Deletion removes active templates, prior adapted versions, quarantined
   candidates, and diagnostic media through an idempotent workflow.
8. Backup expiry and vendor deletion schedules MUST be documented. The user
   receives a deletion receipt once live stores are purged and backup expiry is
   scheduled.

Consent, regional biometric-data requirements, access/export rights, and
retention policy require product and legal approval before collecting
production enrollment audio.

## Phased Rollout Plan

### Phase 0 — Contract correction

- Replace the ambiguous core `liveness` acceptance branch with separate
  freshness, PAD, device-proof, and capture-profile results.
- Introduce E0/E1/E2 evidence types and compile-time fixtures that reject
  cross-tier construction, broad object spreads, invalid branches, and
  `not_required` signing evidence.
- Make the server own challenge creation and Router typed canonicalization.
- Bind device proof to the exact audio hash and Router digest tuple.
- Add atomic grant-state storage and concurrency tests.

Exit gate: all browser paths produce E0, and no E0/E1 value can call a signing
continuation.

### Phase 1 — Recording and enrollment redesign

- Implement one continuous guided enrollment with VAD segmentation, coherence,
  outlier, quality, single-speaker, and deletion checks.
- Implement one continuous 3–5 second verification attempt with a fresh random
  fragment and one quality retry.
- Separate research and signing-grade enrollment assurance in storage and
  types.
- Keep adaptation disabled.

Exit gate: live capture usability, prompt compliance, audio hashing, and deletion
pass on every supported channel. Signing remains disabled.

### Phase 2 — Device and PAD foundation

- Build an approved device capture agent with protected device keys and the
  signed capture statement.
- Add PAD behind the verifier boundary and collect the attack corpus required
  by this profile.
- Produce channel-specific speaker, phrase, quality, and PAD calibration
  reports.
- Exercise device revocation, injected audio, challenge mutation, and model
  outage paths.

Exit gate: at least one non-browser capture profile satisfies the calibration
and release gates. Browser evidence remains E0.

### Phase 3 — Step-up-only production shadow

- Run VoiceID in E1 while passkey authorizes every signing operation.
- Compare VoiceID decisions with passkey outcomes without treating passkey
  success as biometric ground truth.
- Validate telemetry minimization, rate limits, support recovery, revocation,
  kill switch, and policy rollback.

Exit gate: the shadow period meets the approved reliability, privacy, latency,
and attack-monitoring criteria with no unresolved high-severity finding.

### Phase 4 — Capped R1 pilot

- Enable E2 for an allowlisted user cohort, approved devices, established
  recipients, explicit low per-operation and rolling value caps, and a short
  grant lifetime.
- Keep new recipients, elevated value, anomalous sessions, and security changes
  in R2/R3.
- Monitor by capture profile and policy version. Any gate regression activates
  the kill switch and returns the flow to step-up-only.

Exit gate: a time-bounded pilot stays within its approved fraud, false-reject,
privacy, and operational risk budgets.

### Phase 5 — Controlled expansion and adaptation study

- Expand only cohorts and capture profiles that independently pass the gates.
- Re-run red-team, calibration, and grant-race testing on every material change.
- Study progressive adaptation with passkey-confirmed, quarantined candidates;
  keep it disabled for signing until its poisoning and rollback gates pass.
- Maintain permanent R2/R3 step-up rules and an independent robot safety case.

## External Assurance Baseline

The implementation and release review use these external baselines:

- [NIST SP 800-63B-4, Authentication and Authenticator Management](https://pages.nist.gov/800-63-4/sp800-63b/authenticators/)
  for authenticator, biometric, rate-limit, and replay-resistance posture;
- [FIDO Biometrics Requirements 4.1](https://fidoalliance.org/specs/biometric/requirements/Biometrics-Requirements-v4.1-fd-20250106.html)
  for biometric performance, presentation-attack, and protected-boundary
  expectations;
- [ISO/IEC 30107-3:2023](https://www.iso.org/standard/79520.html) for biometric
  presentation-attack testing and reporting;
- [WebAuthn Level 3](https://www.w3.org/TR/webauthn-3/) for browser passkey user
  verification and exact-operation challenge binding;
- [ASVspoof 5 evaluation plan](https://www.asvspoof.org/file/ASVspoof5___Evaluation_Plan_Phase2.pdf)
  for speaker-verification spoof and deepfake evaluation structure.

Meeting this profile requires deployment-specific evidence. Referencing a
standard, pretrained model, vendor claim, or benchmark dataset does not satisfy
a release gate by itself.

## Conformance Checklist

A deployment conforms to this profile only when:

- [ ] browser evidence is structurally unable to issue a signing grant;
- [ ] the server creates the challenge after fixing the canonical Router intent
      and signing payload;
- [ ] the device signature covers the exact uploaded-audio hash, prompt, timing,
      capture profile, and Router binding;
- [ ] speaker, phrase, quality, freshness, PAD, and device proof are independent
      accepted types in E2;
- [ ] one recording is used per verification attempt and every retry has a new
      challenge;
- [ ] enrollment uses one continuous segmented recording and records its
      assurance class;
- [ ] risk policy permits embedded VoiceID admission only for explicit R1
      scope;
- [ ] Router reserves each grant atomically and terminal failures cannot replay;
- [ ] calibration and PAD gates pass for the exact deployed versions and
      capture profile;
- [ ] raw media deletion, template encryption, consent, revocation, and audit
      minimization work end to end;
- [ ] every domain union has exhaustive switches and static rejection fixtures;
- [ ] a tested kill switch returns all signing flows to independent step-up.
