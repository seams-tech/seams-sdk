import type {
  RouterAbEd25519YaoRegistrationSideEffectRecordV1,
  RouterAbEd25519YaoRegistrationSideEffectRunInputV1,
  RouterAbEd25519YaoRegistrationSideEffectRunResultV1,
} from './routerAbEd25519YaoRegistrationSideEffectBoundary';

const claim = {
  kind: 'router_ab_ed25519_yao_registration_side_effect_claim_v1',
  operation: 'finalize',
  requestFingerprint: 'fingerprint',
  claimedAtMs: 1,
} satisfies RouterAbEd25519YaoRegistrationSideEffectRecordV1<{ readonly ok: true }>;

void claim;

const completion = {
  kind: 'router_ab_ed25519_yao_registration_side_effect_completion_v1',
  operation: 'finalize',
  requestFingerprint: 'fingerprint',
  claimedAtMs: 1,
  completedAtMs: 2,
  response: { ok: true },
} satisfies RouterAbEd25519YaoRegistrationSideEffectRecordV1<{ readonly ok: true }>;

void completion;

const completionWithoutResponse = {
  kind: 'router_ab_ed25519_yao_registration_side_effect_completion_v1',
  operation: 'finalize',
  requestFingerprint: 'fingerprint',
  claimedAtMs: 1,
  completedAtMs: 2,
  // @ts-expect-error completed side effects require their exact response
} satisfies RouterAbEd25519YaoRegistrationSideEffectRecordV1<{ readonly ok: true }>;

void completionWithoutResponse;

const uncertainWithValue = {
  kind: 'uncertain',
  phase: 'effect',
  message: 'response lost',
  // @ts-expect-error uncertain effects cannot carry a replayable value
  value: { ok: true },
} satisfies RouterAbEd25519YaoRegistrationSideEffectRunResultV1<{ readonly ok: true }>;

void uncertainWithValue;

const invalidNonResumableInput = {
  kind: 'non_resumable',
  operation: 'start',
  key: 'registration-start:fixture',
  requestFingerprint: 'fingerprint',
  nowMs: () => 1,
  // @ts-expect-error non-resumable effects cannot carry a preparation hook
  prepare: async () => ({ ok: true }),
  execute: async () => ({ ok: true }),
} satisfies RouterAbEd25519YaoRegistrationSideEffectRunInputV1<{ readonly ok: true }>;

void invalidNonResumableInput;

const invalidPreparedInput = {
  kind: 'prepared_resumable',
  resumeAfterMs: 1,
  operation: 'finalize',
  key: 'registration-finalize:fixture',
  requestFingerprint: 'fingerprint',
  nowMs: () => 1,
  execute: async (prepared: { readonly token: string }) => ({ ok: prepared.token.length > 0 }),
  // @ts-expect-error prepared-resumable effects require a preparation hook
} satisfies RouterAbEd25519YaoRegistrationSideEffectRunInputV1<
  { readonly ok: boolean },
  { readonly token: string }
>;

void invalidPreparedInput;
