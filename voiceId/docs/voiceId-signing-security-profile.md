# VoiceID Signing Security Profile

Status: normative security profile and phased implementation plan.

Related implementation documents:

- [VoiceID MVP 1](voiceId-mvp-1.md)
- [VoiceID MVP 1 tasks](voiceId-mvp-1-tasks.md)
- [Router A/B signer architecture](../../docs/router-ab/protocol.md)

This document is the authority for deciding whether VoiceID evidence may reach
transaction signing. VoiceID research, UI, verifier, auth-method, Router, and
robotics documents remain useful implementation references. Where their
signing-eligibility rules differ from this profile, this profile takes
precedence.

The current browser MVP is E0 experimental evidence under this profile. No
current browser VoiceID result is eligible for direct signing. The direct
VoiceID target is a local user-verifying authenticator as defined by the
platform plan.

The key words **MUST**, **MUST NOT**, **REQUIRED**, **SHOULD**, **SHOULD NOT**,
and **MAY** describe requirements for conformance to this profile.

## Security Objective

VoiceID evidence and VoiceID signing authorization are disjoint. Browser,
server-scored, App Attest, and TPM/IMA paths may produce evidence for research,
policy shadowing, passkey step-up, and robot authority policy. Only an approved
local VoiceID authenticator may perform user verification and return a signed
assertion for a wallet operation. Router policy remains the signing admission
boundary, and the active SigningWorker remains the MPC participant.

The target VoiceID authenticator chain is:

```text
server-canonical Router intent and WebAuthn challenge
  -> protected local microphone capture
  -> authenticator derives the fresh phrase from clientDataHash
  -> local speaker + phrase + quality + freshness + PAD verification
  -> protected local rate limit and credential-key release
  -> signed UP + UV assertion for the Router digest tuple
  -> Router assertion verification and atomic admission
  -> existing Router A/B MPC signing flow
```

Every arrow is a security boundary. Success at one boundary MUST NOT imply
success at another. The local authenticator path may become a direct alternative
only after the exact hardware, firmware, capture path, matcher, PAD, enrollment,
recovery, and credential-release system passes this profile and the
platform-plan release gates.

The following invariants apply:

1. VoiceID MUST NOT create a general signing session or reusable bearer
   credential.
2. E0, E1, and E2 evidence MUST NOT construct or consume wallet signing
   authorization.
3. Client-reported timestamps, microphone labels, source trust, replay risk,
   transcripts, or policy choices MUST NOT establish signing eligibility.
4. Evidence policy MUST keep speaker, phrase, quality, capture freshness, PAD,
   device-proof, capture-profile, and intent-binding results independent.
5. Missing, rejected, expired, or uncertain checks fail closed or require an
   independent step-up factor.
6. One challenge binds one capture. Evidence replay or reuse cannot create
   signing authority.
7. An iframe, app attestation, TPM quote, protected key, or local matcher alone
   MUST NOT be represented as authenticator user verification.
8. A direct VoiceID assertion MUST come from an approved authenticator whose
   protected boundary owns capture, matching, PAD, rate limits, templates, and
   credential-key release.
9. MPC protects key custody and produces the signature. It cannot repair an
   incorrect biometric or policy decision.

## Threat Assumptions

The profile assumes an attacker can obtain recordings of the owner, generate
targeted synthetic or converted speech, replay or relay media, inject audio into
ordinary browser capture, control browser application code, mutate client
requests, observe prompts, submit many attempts, and race or replay assertions. A
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
| Canonical intent binding            | The VoiceID challenge, device proof, authenticator assertion, Router request, and prepared signing payload carry the same Router-derived digest tuple.                                              | Spoken text and a client-created digest cannot substitute for Router canonicalization.                                                              |
| MPC signing                         | The existing Router A/B and active SigningWorker flow produces a signature after admission.                                                                                                         | MPC is downstream of VoiceID and must receive only a cryptographically admitted operation.                                                          |

An audit or UI layer MAY summarize the ceremony as “voice verification.”
Internal policy MUST consume the separate results.

## Evidence Tiers

VoiceID evidence has three tiers. A higher tier requires a distinct typed
construction path; runtime flags MUST NOT upgrade a lower-tier object.

| Tier                      | Meaning                                                                                                                  | Permitted use                                                                                                |
| ------------------------- | ------------------------------------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------ |
| E0 — experimental browser | Audio came from an ordinary browser capture path, or freshness/source/PAD claims remain client-reported or uncalibrated. | Research, UX evaluation, verifier fixtures, and policy shadowing.                                            |
| E1 — step-up-only         | The server verified useful voice evidence, while an approved capture guarantee is absent.                                | Offer or inform an independent passkey or equivalent step-up.                                                |
| E2 — attested evidence    | Every required evidence check is server-verified under an approved capture, model, threshold, PAD, and policy version.   | Authenticator research, attack evaluation, robot authority policy, and passkey-backed wallet policy context. |

Every tier is signing-ineligible. Higher-quality evidence cannot be promoted to
wallet authorization by risk policy, a feature flag, or a server-issued token.

`MediaRecorder`, Web Audio, browser `deviceId`, browser timestamps, and a
browser-held application key remain E0 inputs. A passkey performed after an E0
voice interaction MAY authorize the operation through the passkey path; the
voice evidence remains E0.

The target domain split is:

```ts
export type VoiceIdEvidence =
  | VoiceIdExperimentalBrowserEvidence
  | VoiceIdStepUpOnlyEvidence
  | VoiceIdAttestedEvidence;

export type VoiceIdExperimentalBrowserEvidence = {
  kind: 'experimental_browser_evidence';
  verificationId: VoiceIdVerificationId;
  enrollmentId: VoiceIdEnrollmentId;
  observedChecks: VoiceIdObservedChecks;
  modelVersion: VoiceIdModelVersion;
  thresholdVersion: VoiceIdThresholdVersion;
  completedAt: IsoDateTime;
  signingAuthorization?: never;
};

export type VoiceIdStepUpOnlyEvidence = {
  kind: 'step_up_only_evidence';
  verificationId: VoiceIdVerificationId;
  reason:
    | 'browser_capture_boundary'
    | 'pad_unavailable'
    | 'device_proof_unavailable';
  source: VoiceIdExperimentalBrowserEvidence;
  signingAuthorization?: never;
};

export type VoiceIdAttestedEvidence = {
  readonly [attestedEvidenceBrand]: true;
  kind: 'attested_evidence';
  verificationId: VoiceIdVerificationId;
  enrollmentId: VoiceIdEnrollmentId;
  speaker: VoiceIdAcceptedSpeaker;
  phrase: VoiceIdAcceptedPhrase;
  quality: VoiceIdAcceptedQuality;
  captureFreshness: VoiceIdAcceptedCaptureFreshness;
  pad: VoiceIdAcceptedPad;
  deviceProof: VoiceIdVerifiedDeviceProof;
  captureProfile: VoiceIdApprovedCaptureProfile;
  calibration: VoiceIdApprovedCalibration;
  modelVersion: VoiceIdModelVersion;
  thresholdVersion: VoiceIdThresholdVersion;
  completedAt: IsoDateTime;
  signingAuthorization?: never;
};
```

No evidence type may enter signing:

```ts
declare function signAfterAdmissionAccepted(
  authorization: WalletSigningAuthorization,
): Promise<NormalSigningReceipt>;

declare const attestedEvidence: VoiceIdAttestedEvidence;

// @ts-expect-error Attested evidence is not signing authorization.
signAfterAdmissionAccepted(attestedEvidence);
```

The cutover deletes branches such as `liveness: { kind: 'not_required' }` from
signing-facing types, tests, and fixtures. If persisted records require a data
rewrite, that parser exists only at the storage boundary and is deleted after
the rewrite completes. Untrusted current inputs parse directly to E0/E1,
rejection, or uncertainty before core policy runs.

## Signing Authorization Classes

The signing boundary accepts one of two disjoint admitted states:

```ts
export type WalletSigningAuthorization =
  | PasskeyAdmittedTransaction
  | VoiceIdAuthenticatorAdmittedTransaction;

export type VoiceIdAuthenticatorAdmittedTransaction = {
  kind: 'voice_id_authenticator_admitted_transaction';
  routerBinding: RouterVoiceIntentBinding;
  credential: VerifiedVoiceIdCredential;
  assertion: VerifiedVoiceIdUserVerificationAssertion;
  authenticator: ApprovedVoiceIdAuthenticator;
};
```

`VoiceIdAuthenticatorAdmittedTransaction` is the direct alternative. A trusted
boundary parser verifies the signed assertion, RP ID, origin, challenge, UP and
UV flags, counter policy, credential state, approved authenticator identity,
and exact Router binding before constructing it. The approved authenticator
registry proves that the attested model performs voice UV; client metadata
cannot choose that classification.

Browser evidence, App Attest payloads, TPM quotes, raw verifier results, and E2
evidence are structurally unable to construct the authenticator branch. The
platform plan defines the browser, embedded Linux, external hardware, and iOS
implementation requirements.

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

1. The server issues four randomized, phonetically varied prompt fragments.
2. The user completes one recording with a 12-second minimum, an 18-second
   usable-speech target, and a 30-second wall-clock capture cap.
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

- come from an E2 attested capture followed by successful passkey owner
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
request-boundary objects.

An exhaustive verification result should have this shape:

```ts
export type VoiceIdVerificationResult =
  | {
      kind: 'attested_evidence';
      evidence: VoiceIdAttestedEvidence;
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
`uncertain`. No branch may carry a Router continuation or signing authorization.

## Wallet Signing Eligibility

Wallet signing requires either a verified passkey admission or a verified
VoiceID authenticator admission. E0/E1/E2 evidence may influence whether the UI
offers a passkey, locks VoiceID research, or rejects a session. It cannot reduce
the cryptographic authorization requirement.

The Router and SigningWorker MUST independently validate the Router digest
tuple and normal-signing transcript fields already required by the Router A/B
specification. The VoiceID layer MUST NOT call Deriver roles or handle signing
shares.

Robot command authorization additionally requires an independent safety
controller. Voice authority MUST NOT bypass workspace, motion, force, tool,
proximity, or emergency-stop policy.

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

The reproducible synthesis corpus MUST include pinned
[Dia2](https://github.com/nari-labs/dia2) 1B and 2B checkpoints producing both
generic-voice and audio-conditioned attacks from consented reference
recordings. Each Dia2 fixture records the repository revision, weight hashes,
architecture, reference-audio consent handle and duration, script, challenge
tokens, seed, sampling configuration, output duration, generation latency, and
every injection, replay, codec, noise, or room-response transformation. Dia2
and other attack generators remain offline fixture tools outside production
VoiceID packages, verifier images, and runtime dependencies.

Dia2 coverage does not satisfy the unseen-tool requirement. The held-out set
MUST include unrelated text-to-speech and voice-conversion families. The
evaluation MUST also determine whether prompt-targeted synthesis containing the
fresh challenge tokens can complete inside the deployed challenge validity
window.

Reports MUST show attack-presentation acceptance and bona-fide rejection by
attack class and capture profile, plus the combined end-to-end unauthorized
acceptance rate. The 95% upper confidence bound of the combined result MUST fit
the approved evidence or authenticator attack budget. A pooled average cannot hide a
failing device, language, demographic, or attack cohort.

### Operational gate

E2 attested evidence remains disabled until all of these hold:

- the exact build passes speaker, phrase, PAD, device-proof, intent-mutation,
  replay, and deletion tests;
- a shadow deployment reproduces expected score and latency distributions;
- rate limits, allowlists, monitoring, step-up, revocation, and a kill switch
  work end to end;
- model, threshold, policy, capture, and calibration versions appear in audit
  records;
- an independent security review approves the evidence scope.

A model, threshold, preprocessing, prompt, capture-agent, device-key, retry,
or risk-policy change invalidates the affected approval until the relevant
gates rerun. A failing cohort disables that capture profile or scope.

## Privacy, Retention, And Deletion

Voice recordings and templates are biometric personal data. They MUST remain
outside logs, analytics events, crash reports, traces, support payloads, and
signing authorization records.

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
7. Enrollment disablement immediately revokes pending challenges and registered
   VoiceID credentials.
   Deletion removes active templates, prior adapted versions, quarantined
   candidates, and diagnostic media through an idempotent workflow.
8. Backup expiry and vendor deletion schedules MUST be documented. The user
   receives a deletion receipt once live stores are purged and backup expiry is
   scheduled.

Consent, regional biometric-data requirements, access/export rights, and
retention policy require product and legal approval before collecting
production enrollment audio.

## Phased Rollout Plan

This rollout is deferred while the standalone engine follows the active plan
in [VoiceID MVP 1 Tasks](voiceId-mvp-1-tasks.md). This profile is the single
long-term source for browser containment, attested evidence, protected
authenticator, WebAuthn/CTAP2, Router, wallet, recovery, and rollout
requirements. The current work establishes the reproducible benchmark, shared
inference runtime, selected models, PAD, template stability, optimized builds,
and runtime resilience required before a platform rollout begins.

### Phase 0 — Contract correction

- Replace the ambiguous core `liveness` acceptance branch with separate
  freshness, PAD, device-proof, and capture-profile results.
- Introduce E0/E1/E2 evidence types and compile-time fixtures that reject
  cross-tier construction, broad object spreads, invalid branches, and
  `not_required` signing evidence.
- Delete every server evidence-to-signing continuation and its Router adapter.
- Make the server own challenge creation and Router typed canonicalization.
- Bind device proof to the exact audio hash and Router digest tuple.

Exit gate: no E0/E1/E2 value can call a signing continuation.

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
  by this profile, including pinned Dia2 prompt-targeted fixtures and unrelated
  held-out synthesis and voice-conversion families.
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

### Phase 4 — Embedded attested evidence shadow

- Enable E2 evidence for an allowlisted device cohort while passkey authorizes
  every wallet operation.
- Measure capture, PAD, device, model, privacy, and reliability performance by
  profile and policy version.
- Keep E2 structurally outside Router and SigningWorker admission.

Exit gate: the shadow supplies the evidence needed to design and evaluate the
protected local authenticator.

### Phase 5 — Controlled expansion and adaptation study

- Expand only cohorts and capture profiles that independently pass the gates.
- Re-run red-team and calibration testing on every material change.
- Study progressive adaptation with passkey-confirmed, quarantined candidates;
  keep it disabled for authenticator templates until its poisoning and rollback
  gates pass.
- Maintain passkey step-up rules and an independent robot safety case.

### Phase 6 — Voice user-verifying authenticator

- Build the dedicated microphone/MCU/secure-element CTAP2 authenticator from
  the platform plan, or qualify an equivalent production TEE with a protected
  microphone path.
- Keep capture, templates, speaker/phrase/PAD decisions, attempt counters, and
  credential-key release inside the evaluated boundary.
- Verify attestation identity and signed UP + UV assertions at Router admission.
- Complete independent biometric, presentation-attack, hardware, firmware,
  protocol, enrollment, recovery, and supply-chain review.
- Enable `VoiceIdAuthenticatorAdmittedTransaction` only for approved hardware
  and firmware allowlists after every release gate passes.

Exit gate: a compromised host cannot obtain an assertion without a successful
current voice ceremony, and the measured end-to-end unauthorized-signing risk
meets the approved platform-biometric comparator budget.

## External Assurance Baseline

The implementation and release review use these external baselines:

- [FIDO Biometrics Requirements 4.1](https://fidoalliance.org/specs/biometric/requirements/Biometrics-Requirements-v4.1-fd-20250106.html)
  for biometric performance, presentation-attack, and protected-boundary
  expectations;
- [ISO/IEC 30107-3:2023](https://www.iso.org/standard/79520.html) for biometric
  presentation-attack testing and reporting;
- [WebAuthn Level 3](https://www.w3.org/TR/webauthn-3/) for browser passkey user
  verification and exact-operation challenge binding;
- [Apple platform biometric security](https://support.apple.com/guide/security/face-id-touch-id-passcodes-and-passwords-sec9479035f1/web)
  as a comparator for protected local matching, failure limits, and measured
  system-level biometric performance;
- [ASVspoof 5 evaluation plan](https://www.asvspoof.org/file/ASVspoof5___Evaluation_Plan_Phase2.pdf)
  for speaker-verification spoof and deepfake evaluation structure.

Meeting this profile requires deployment-specific evidence. Referencing a
standard, pretrained model, vendor claim, or benchmark dataset does not satisfy
a release gate by itself.

## Conformance Checklist

A deployment conforms to this profile only when:

- [ ] E0/E1/E2 evidence is structurally unable to construct wallet signing
      authorization;
- [ ] direct VoiceID admission accepts only a verified assertion from an
      allowlisted voice-UV authenticator model;
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
- [ ] calibration and PAD gates pass for the exact deployed versions and
      capture profile;
- [ ] raw media deletion, template encryption, consent, revocation, and audit
      minimization work end to end;
- [ ] every domain union has exhaustive switches and static rejection fixtures;
- [ ] a tested kill switch returns all signing flows to independent step-up.
