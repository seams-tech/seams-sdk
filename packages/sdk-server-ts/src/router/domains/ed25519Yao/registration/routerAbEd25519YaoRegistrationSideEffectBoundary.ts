import type {
  VersionedJsonRecordPutResult,
  VersionedJsonRecordReadResult,
} from '../../../framework/versionedJsonRecordStore';

export type RouterAbEd25519YaoRegistrationSideEffectOperationV1 =
  | 'finalize'
  /* 94C: the single Gateway operation row for activate-with-finalize. */
  | 'registration_activate'
  /* 94C: deferred NEAR provisioning is a separate effect with its own row. */
  | 'near_provisioning'
  | 'registration_start'
  | 'add_signer_start'
  | 'add_signer_finalize';

export type RouterAbEd25519YaoRetryableSideEffectFailureV1 = {
  readonly ok: false;
  readonly code: string;
  readonly message: string;
  readonly retryAfterMs?: number;
};

export function throwIfRouterAbEd25519YaoRetryableSideEffectFailureV1<
  T extends RouterAbEd25519YaoRetryableSideEffectFailureV1,
>(failure: T): T {
  if (failure.retryAfterMs !== undefined) throw new Error(failure.message);
  switch (failure.code) {
    case 'internal':
    case 'not_configured':
    case 'execution_in_progress':
    case 'admission_in_progress':
    case 'admission_uncertain':
    case 'temporarily_unavailable':
    case 'timeout':
    case 'uncertain':
      throw new Error(failure.message);
    default:
      return failure;
  }
}

/**
 * The semantic request fingerprint detects idempotency conflicts before
 * preparation. The prepared artifact fingerprint binds the exact durable
 * bytes that execution may replay after an ambiguous outcome.
 */
export type RouterAbEd25519YaoRegistrationSideEffectClaimV1<P> = {
  readonly kind: 'router_ab_ed25519_yao_registration_side_effect_claim_v1';
  readonly operation: RouterAbEd25519YaoRegistrationSideEffectOperationV1;
  readonly requestFingerprint: string;
  readonly preparedArtifactFingerprint: string;
  readonly claimedAtMs: number;
  readonly prepared: P;
};

export type RouterAbEd25519YaoRegistrationSideEffectCompletionV1<T, P> = {
  readonly kind: 'router_ab_ed25519_yao_registration_side_effect_completion_v1';
  readonly operation: RouterAbEd25519YaoRegistrationSideEffectOperationV1;
  readonly requestFingerprint: string;
  readonly preparedArtifactFingerprint: string;
  readonly claimedAtMs: number;
  readonly completedAtMs: number;
  readonly prepared: P;
  readonly response: T;
};

export type RouterAbEd25519YaoRegistrationSideEffectRecordV1<T, P> =
  | RouterAbEd25519YaoRegistrationSideEffectClaimV1<P>
  | RouterAbEd25519YaoRegistrationSideEffectCompletionV1<T, P>;

export interface RouterAbEd25519YaoRegistrationSideEffectStoreV1<T, P> {
  read(
    key: string,
  ): Promise<
    VersionedJsonRecordReadResult<RouterAbEd25519YaoRegistrationSideEffectRecordV1<T, P>>
  >;
  put(
    key: string,
    value: RouterAbEd25519YaoRegistrationSideEffectRecordV1<T, P>,
    expectedVersion: string | null,
  ): Promise<VersionedJsonRecordPutResult>;
}

export function parseRouterAbEd25519YaoRegistrationSideEffectRecordV1<T, P>(
  raw: unknown,
  input: {
    readonly operation: RouterAbEd25519YaoRegistrationSideEffectOperationV1;
    readonly parsePrepared: (value: unknown) => P | null;
    readonly parseResponse: (value: unknown) => T | null;
  },
): RouterAbEd25519YaoRegistrationSideEffectRecordV1<T, P> | null {
  if (!isRecord(raw) || raw.operation !== input.operation) return null;
  const requestFingerprint = parseFingerprint(raw.requestFingerprint);
  const preparedArtifactFingerprint = parsePreparedFingerprint(raw.preparedArtifactFingerprint);
  const claimedAtMs = parseTimestamp(raw.claimedAtMs);
  const prepared = input.parsePrepared(raw.prepared);
  if (
    requestFingerprint === null ||
    preparedArtifactFingerprint === null ||
    claimedAtMs === null ||
    prepared === null
  ) {
    return null;
  }
  if (raw.kind === 'router_ab_ed25519_yao_registration_side_effect_claim_v1') {
    return {
      kind: 'router_ab_ed25519_yao_registration_side_effect_claim_v1',
      operation: input.operation,
      requestFingerprint,
      preparedArtifactFingerprint,
      claimedAtMs,
      prepared,
    };
  }
  if (raw.kind !== 'router_ab_ed25519_yao_registration_side_effect_completion_v1') return null;
  const completedAtMs = parseTimestamp(raw.completedAtMs);
  const response = input.parseResponse(raw.response);
  if (completedAtMs === null || response === null) return null;
  return {
    kind: 'router_ab_ed25519_yao_registration_side_effect_completion_v1',
    operation: input.operation,
    requestFingerprint,
    preparedArtifactFingerprint,
    claimedAtMs,
    completedAtMs,
    prepared,
    response,
  };
}

/**
 * `resumed` means a prior attempt persisted this exact artifact and may have
 * broadcast it without observing the outcome. Execution must reconcile before
 * it repeats any network effect.
 */
export type RouterAbEd25519YaoRegistrationSideEffectAttemptV1 = 'fresh' | 'resumed';

export type RouterAbEd25519YaoRegistrationSideEffectRunInputV1<T, P> = {
  readonly kind: 'prepared_resumable';
  readonly operation: RouterAbEd25519YaoRegistrationSideEffectOperationV1;
  readonly key: string;
  readonly requestFingerprint: string;
  readonly resumeAfterMs: number;
  readonly nowMs: () => number;
  readonly prepare: () => Promise<P>;
  readonly derivePreparedArtifactFingerprint: (prepared: P) => Promise<string>;
  readonly execute: (
    prepared: P,
    attempt: RouterAbEd25519YaoRegistrationSideEffectAttemptV1,
  ) => Promise<T>;
};

export type RouterAbEd25519YaoRegistrationSideEffectExecutionV1<T, P> =
  RouterAbEd25519YaoRegistrationSideEffectRunInputV1<T, P>['execute'];

export type RouterAbEd25519YaoRegistrationSideEffectRunResultV1<T, P> =
  | { readonly kind: 'executed'; readonly value: T }
  | { readonly kind: 'exact_replay'; readonly value: T }
  | {
      readonly kind: 'in_progress';
      readonly prepared: P;
      readonly preparedArtifactFingerprint: string;
    }
  | { readonly kind: 'request_conflict' }
  | {
      readonly kind: 'uncertain';
      readonly phase: 'claim' | 'effect' | 'terminal_commit';
      readonly message: string;
    };

/**
 * Persists an exact prepared artifact before its one-use effect. A stale claim
 * resumes from that artifact without running preparation again. Claim and
 * completion reads verify the artifact fingerprint before returning a result
 * or allowing a network effect.
 */
export async function runRouterAbEd25519YaoRegistrationSideEffectV1<T, P>(
  store: RouterAbEd25519YaoRegistrationSideEffectStoreV1<T, P>,
  input: RouterAbEd25519YaoRegistrationSideEffectRunInputV1<T, P>,
): Promise<RouterAbEd25519YaoRegistrationSideEffectRunResultV1<T, P>> {
  const key = requireOpaqueKey(input.key);
  const requestFingerprint = requireRequestFingerprint(input.requestFingerprint);
  const resumeAfterMs = requirePositiveDuration(input.resumeAfterMs, 'resumeAfterMs');

  let existing: VersionedJsonRecordReadResult<
    RouterAbEd25519YaoRegistrationSideEffectRecordV1<T, P>
  >;
  let disposition: ExistingDisposition<T, P>;
  try {
    existing = await store.read(key);
    disposition = await existingDisposition(
      existing,
      requestFingerprint,
      input.derivePreparedArtifactFingerprint,
    );
  } catch (error: unknown) {
    return uncertainResult('claim', error);
  }

  const resumable =
    disposition.kind === 'in_progress' &&
    existing.kind === 'present' &&
    existing.value.kind === 'router_ab_ed25519_yao_registration_side_effect_claim_v1' &&
    input.nowMs() - existing.value.claimedAtMs >= resumeAfterMs;
  if (disposition.kind !== 'fresh' && !resumable) return disposition;

  let preparedForExecution: P;
  let preparedArtifactFingerprint: string;
  let claimedAtMs: number;
  let claimVersion: string;
  if (
    resumable &&
    existing.kind === 'present' &&
    existing.value.kind === 'router_ab_ed25519_yao_registration_side_effect_claim_v1'
  ) {
    preparedForExecution = existing.value.prepared;
    preparedArtifactFingerprint = existing.value.preparedArtifactFingerprint;
    const takeoverClaim: RouterAbEd25519YaoRegistrationSideEffectClaimV1<P> = {
      kind: 'router_ab_ed25519_yao_registration_side_effect_claim_v1',
      operation: input.operation,
      requestFingerprint,
      preparedArtifactFingerprint,
      claimedAtMs: requireTimestamp(input.nowMs(), 'claimedAtMs'),
      prepared: preparedForExecution,
    };
    let takeover: VersionedJsonRecordPutResult;
    try {
      takeover = await store.put(key, takeoverClaim, existing.version);
    } catch (error: unknown) {
      return uncertainResult('claim', error);
    }
    if (takeover.kind === 'version_mismatch') {
      try {
        const reconciled = await readDisposition(
          store,
          key,
          requestFingerprint,
          input.derivePreparedArtifactFingerprint,
        );
        return reconciled.kind === 'fresh'
          ? {
              kind: 'uncertain',
              phase: 'claim',
              message: 'registration side-effect takeover could not be reconciled',
            }
          : reconciled;
      } catch (error: unknown) {
        return uncertainResult('claim', error);
      }
    }
    claimedAtMs = takeoverClaim.claimedAtMs;
    claimVersion = takeover.version;
  } else {
    try {
      preparedForExecution = requirePrepared(await input.prepare());
      preparedArtifactFingerprint = requirePreparedArtifactFingerprint(
        await input.derivePreparedArtifactFingerprint(preparedForExecution),
      );
    } catch (error: unknown) {
      return uncertainResult('claim', error);
    }
    const claim: RouterAbEd25519YaoRegistrationSideEffectClaimV1<P> = {
      kind: 'router_ab_ed25519_yao_registration_side_effect_claim_v1',
      operation: input.operation,
      requestFingerprint,
      preparedArtifactFingerprint,
      claimedAtMs: requireTimestamp(input.nowMs(), 'claimedAtMs'),
      prepared: preparedForExecution,
    };
    claimedAtMs = claim.claimedAtMs;

    let claimed: VersionedJsonRecordPutResult;
    try {
      claimed = await store.put(key, claim, null);
    } catch (error: unknown) {
      return uncertainResult('claim', error);
    }
    if (claimed.kind === 'version_mismatch') {
      let reconciledClaim: ExistingDisposition<T, P>;
      try {
        reconciledClaim = await readDisposition(
          store,
          key,
          requestFingerprint,
          input.derivePreparedArtifactFingerprint,
        );
      } catch (error: unknown) {
        return uncertainResult('claim', error);
      }
      return reconciledClaim.kind === 'fresh'
        ? {
            kind: 'uncertain',
            phase: 'claim',
            message: 'registration side-effect claim could not be reconciled',
          }
        : reconciledClaim;
    }
    claimVersion = claimed.version;
  }

  let response: T;
  try {
    response = await input.execute(preparedForExecution, resumable ? 'resumed' : 'fresh');
  } catch (error: unknown) {
    return uncertainResult('effect', error);
  }

  const completion: RouterAbEd25519YaoRegistrationSideEffectCompletionV1<T, P> = {
    kind: 'router_ab_ed25519_yao_registration_side_effect_completion_v1',
    operation: input.operation,
    requestFingerprint,
    preparedArtifactFingerprint,
    claimedAtMs,
    completedAtMs: requireTimestamp(input.nowMs(), 'completedAtMs'),
    prepared: preparedForExecution,
    response,
  };
  let committed: VersionedJsonRecordPutResult;
  try {
    committed = await store.put(key, completion, claimVersion);
  } catch (error: unknown) {
    return uncertainResult('terminal_commit', error);
  }
  if (committed.kind === 'stored') return { kind: 'executed', value: response };

  let reconciled: ExistingDisposition<T, P>;
  try {
    reconciled = await readDisposition(
      store,
      key,
      requestFingerprint,
      input.derivePreparedArtifactFingerprint,
    );
  } catch (error: unknown) {
    return uncertainResult('terminal_commit', error);
  }
  if (reconciled.kind === 'exact_replay') return reconciled;
  return {
    kind: 'uncertain',
    phase: 'terminal_commit',
    message: 'registration side-effect completion could not be reconciled',
  };
}

type ExistingDisposition<T, P> =
  | { readonly kind: 'fresh' }
  | Exclude<
      RouterAbEd25519YaoRegistrationSideEffectRunResultV1<T, P>,
      { readonly kind: 'executed' }
    >;

async function readDisposition<T, P>(
  store: RouterAbEd25519YaoRegistrationSideEffectStoreV1<T, P>,
  key: string,
  requestFingerprint: string,
  derivePreparedArtifactFingerprint: (prepared: P) => Promise<string>,
): Promise<ExistingDisposition<T, P>> {
  return await existingDisposition(
    await store.read(key),
    requestFingerprint,
    derivePreparedArtifactFingerprint,
  );
}

async function existingDisposition<T, P>(
  record: VersionedJsonRecordReadResult<
    RouterAbEd25519YaoRegistrationSideEffectRecordV1<T, P>
  >,
  requestFingerprint: string,
  derivePreparedArtifactFingerprint: (prepared: P) => Promise<string>,
): Promise<ExistingDisposition<T, P>> {
  if (record.kind === 'missing') return { kind: 'fresh' };
  if (record.value.requestFingerprint !== requestFingerprint) {
    return { kind: 'request_conflict' };
  }
  const derivedFingerprint = requirePreparedArtifactFingerprint(
    await derivePreparedArtifactFingerprint(record.value.prepared),
  );
  if (derivedFingerprint !== record.value.preparedArtifactFingerprint) {
    throw new Error('registration side-effect prepared artifact fingerprint is invalid');
  }
  switch (record.value.kind) {
    case 'router_ab_ed25519_yao_registration_side_effect_claim_v1':
      return {
        kind: 'in_progress',
        prepared: record.value.prepared,
        preparedArtifactFingerprint: record.value.preparedArtifactFingerprint,
      };
    case 'router_ab_ed25519_yao_registration_side_effect_completion_v1':
      return { kind: 'exact_replay', value: record.value.response };
    default:
      return assertNever(record.value);
  }
}

function requireOpaqueKey(value: string): string {
  const key = value.trim();
  if (!key || key.length > 512 || !/^[\x21-\x7e]+$/u.test(key)) {
    throw new Error('registration side-effect key is invalid');
  }
  return key;
}

function requireRequestFingerprint(value: string): string {
  const fingerprint = value.trim();
  if (!/^[a-zA-Z0-9_-]{32,128}$/u.test(fingerprint)) {
    throw new Error('registration side-effect request fingerprint is invalid');
  }
  return fingerprint;
}

function requirePreparedArtifactFingerprint(value: string): string {
  const fingerprint = value.trim();
  if (!/^[a-zA-Z0-9:_-]{32,192}$/u.test(fingerprint)) {
    throw new Error('registration side-effect prepared artifact fingerprint is invalid');
  }
  return fingerprint;
}

function requirePrepared<P>(value: P): P {
  if (value === undefined || value === null) {
    throw new Error('registration side-effect prepared artifact is missing');
  }
  return value;
}

function requireTimestamp(value: number, label: string): number {
  if (!Number.isSafeInteger(value) || value < 0) {
    throw new Error(`registration side-effect ${label} is invalid`);
  }
  return value;
}

function requirePositiveDuration(value: number, label: string): number {
  if (!Number.isSafeInteger(value) || value <= 0) {
    throw new Error(`registration side-effect ${label} is invalid`);
  }
  return value;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function parseFingerprint(value: unknown): string | null {
  return typeof value === 'string' && /^[a-zA-Z0-9_-]{32,128}$/u.test(value) ? value : null;
}

function parsePreparedFingerprint(value: unknown): string | null {
  return typeof value === 'string' && /^[a-zA-Z0-9:_-]{32,192}$/u.test(value) ? value : null;
}

function parseTimestamp(value: unknown): number | null {
  return typeof value === 'number' && Number.isSafeInteger(value) && value >= 0 ? value : null;
}

function uncertainResult(
  phase: 'claim' | 'effect' | 'terminal_commit',
  error: unknown,
): Extract<
  RouterAbEd25519YaoRegistrationSideEffectRunResultV1<never, never>,
  { readonly kind: 'uncertain' }
> {
  return {
    kind: 'uncertain',
    phase,
    message: error instanceof Error ? error.message : String(error),
  };
}

function assertNever(value: never): never {
  throw new Error(`Unhandled registration side-effect record: ${String(value)}`);
}
