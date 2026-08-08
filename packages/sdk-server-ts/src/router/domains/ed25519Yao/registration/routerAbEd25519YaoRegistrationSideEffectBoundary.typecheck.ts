import type {
  RouterAbEd25519YaoRegistrationSideEffectRecordV1,
  RouterAbEd25519YaoRegistrationSideEffectRunInputV1,
  RouterAbEd25519YaoRegistrationSideEffectRunResultV1,
} from './routerAbEd25519YaoRegistrationSideEffectBoundary';

type Prepared = { readonly token: string };
type Response = { readonly ok: true };

const claim = {
  kind: 'router_ab_ed25519_yao_registration_side_effect_claim_v1',
  operation: 'finalize',
  requestFingerprint: 'fingerprint',
  preparedArtifactFingerprint: 'artifact-fingerprint',
  claimedAtMs: 1,
  prepared: { token: 'prepared-token' },
} satisfies RouterAbEd25519YaoRegistrationSideEffectRecordV1<Response, Prepared>;

void claim;

const claimWithoutPrepared = {
  kind: 'router_ab_ed25519_yao_registration_side_effect_claim_v1',
  operation: 'finalize',
  requestFingerprint: 'fingerprint',
  preparedArtifactFingerprint: 'artifact-fingerprint',
  claimedAtMs: 1,
  // @ts-expect-error resumable claims require their exact prepared artifact
} satisfies RouterAbEd25519YaoRegistrationSideEffectRecordV1<Response, Prepared>;

void claimWithoutPrepared;

const completion = {
  kind: 'router_ab_ed25519_yao_registration_side_effect_completion_v1',
  operation: 'finalize',
  requestFingerprint: 'fingerprint',
  preparedArtifactFingerprint: 'artifact-fingerprint',
  claimedAtMs: 1,
  completedAtMs: 2,
  prepared: { token: 'prepared-token' },
  response: { ok: true },
} satisfies RouterAbEd25519YaoRegistrationSideEffectRecordV1<Response, Prepared>;

void completion;

const completionWithoutArtifactFingerprint = {
  kind: 'router_ab_ed25519_yao_registration_side_effect_completion_v1',
  operation: 'finalize',
  requestFingerprint: 'fingerprint',
  claimedAtMs: 1,
  completedAtMs: 2,
  prepared: { token: 'prepared-token' },
  response: { ok: true },
  // @ts-expect-error completions retain the prepared artifact fingerprint
} satisfies RouterAbEd25519YaoRegistrationSideEffectRecordV1<Response, Prepared>;

void completionWithoutArtifactFingerprint;

const uncertainWithValue = {
  kind: 'uncertain',
  phase: 'effect',
  message: 'response lost',
  // @ts-expect-error uncertain effects cannot carry a replayable value
  value: { ok: true },
} satisfies RouterAbEd25519YaoRegistrationSideEffectRunResultV1<Response, Prepared>;

void uncertainWithValue;

const preparedInput = {
  kind: 'prepared_resumable',
  operation: 'finalize',
  key: 'registration-finalize:fixture',
  requestFingerprint: 'fingerprint',
  resumeAfterMs: 1,
  nowMs: () => 1,
  prepare: async (): Promise<Prepared> => ({ token: 'prepared-token' }),
  derivePreparedArtifactFingerprint: async () => 'artifact-fingerprint',
  execute: async (prepared: Prepared): Promise<Response> => {
    void prepared;
    return { ok: true };
  },
} satisfies RouterAbEd25519YaoRegistrationSideEffectRunInputV1<Response, Prepared>;

void preparedInput;

const inputWithoutLifecycleKind = {
  operation: 'finalize',
  key: 'registration-finalize:fixture',
  requestFingerprint: 'fingerprint',
  resumeAfterMs: 1,
  nowMs: () => 1,
  prepare: async (): Promise<Prepared> => ({ token: 'prepared-token' }),
  derivePreparedArtifactFingerprint: async () => 'artifact-fingerprint',
  execute: async (prepared: Prepared): Promise<Response> => {
    void prepared;
    return { ok: true };
  },
  // @ts-expect-error prepared-resumable inputs require an explicit lifecycle kind
} satisfies RouterAbEd25519YaoRegistrationSideEffectRunInputV1<Response, Prepared>;

void inputWithoutLifecycleKind;

const inputWithoutPreparation = {
  kind: 'prepared_resumable',
  operation: 'finalize',
  key: 'registration-finalize:fixture',
  requestFingerprint: 'fingerprint',
  resumeAfterMs: 1,
  nowMs: () => 1,
  derivePreparedArtifactFingerprint: async () => 'artifact-fingerprint',
  execute: async (prepared: Prepared): Promise<Response> => {
    void prepared;
    return { ok: true };
  },
  // @ts-expect-error every side effect requires a preparation hook
} satisfies RouterAbEd25519YaoRegistrationSideEffectRunInputV1<Response, Prepared>;

void inputWithoutPreparation;

const obsoleteNonResumableInput = {
  // @ts-expect-error non-resumable side effects are outside this boundary
  kind: 'non_resumable',
  operation: 'finalize',
  key: 'registration-finalize:fixture',
  requestFingerprint: 'fingerprint',
  resumeAfterMs: 1,
  nowMs: () => 1,
  prepare: async (): Promise<Prepared> => ({ token: 'prepared-token' }),
  derivePreparedArtifactFingerprint: async () => 'artifact-fingerprint',
  execute: async (): Promise<Response> => ({ ok: true }),
} satisfies RouterAbEd25519YaoRegistrationSideEffectRunInputV1<Response, Prepared>;

void obsoleteNonResumableInput;
