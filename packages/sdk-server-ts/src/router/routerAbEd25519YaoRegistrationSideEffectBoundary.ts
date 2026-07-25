import type {
  CloudflareVersionedJsonRecordPutResult,
  CloudflareVersionedJsonRecordReadResult,
} from './cloudflare/versionedJsonRecordStore';

export type RouterAbEd25519YaoRegistrationSideEffectOperationV1 = 'start' | 'finalize';

/**
 * `prepared` carries the exact artifact the effect will act on — for
 * finalization, the signed sponsored transaction and its hash. It is persisted
 * with the claim, before the effect runs, so an ambiguous outcome can be
 * reconciled by replaying that exact artifact instead of building a new one.
 */
type RouterAbEd25519YaoRegistrationSideEffectClaimBaseV1 = {
  readonly kind: 'router_ab_ed25519_yao_registration_side_effect_claim_v1';
  readonly operation: RouterAbEd25519YaoRegistrationSideEffectOperationV1;
  readonly requestFingerprint: string;
  readonly claimedAtMs: number;
};

export type RouterAbEd25519YaoRegistrationSideEffectClaimV1<P = never> =
  | RouterAbEd25519YaoRegistrationSideEffectClaimBaseV1
  | (RouterAbEd25519YaoRegistrationSideEffectClaimBaseV1 & { readonly prepared: P });

export type RouterAbEd25519YaoRegistrationSideEffectCompletionV1<T> = {
  readonly kind: 'router_ab_ed25519_yao_registration_side_effect_completion_v1';
  readonly operation: RouterAbEd25519YaoRegistrationSideEffectOperationV1;
  readonly requestFingerprint: string;
  readonly claimedAtMs: number;
  readonly completedAtMs: number;
  readonly response: T;
};

export type RouterAbEd25519YaoRegistrationSideEffectRecordV1<T, P = never> =
  | RouterAbEd25519YaoRegistrationSideEffectClaimV1<P>
  | RouterAbEd25519YaoRegistrationSideEffectCompletionV1<T>;

export interface RouterAbEd25519YaoRegistrationSideEffectStoreV1<T, P = never> {
  read(
    key: string,
  ): Promise<
    CloudflareVersionedJsonRecordReadResult<RouterAbEd25519YaoRegistrationSideEffectRecordV1<T, P>>
  >;
  put(
    key: string,
    value: RouterAbEd25519YaoRegistrationSideEffectRecordV1<T, P>,
    expectedVersion: string | null,
  ): Promise<CloudflareVersionedJsonRecordPutResult>;
}

/**
 * `attempt` is `resumed` when a prior attempt already persisted this artifact
 * and broadcast an effect whose outcome was never observed. A replay-safe
 * effect should reconcile before repeating itself.
 */
export type RouterAbEd25519YaoRegistrationSideEffectAttemptV1 = 'fresh' | 'resumed';

type RouterAbEd25519YaoRegistrationSideEffectRunInputBaseV1 = {
  readonly operation: RouterAbEd25519YaoRegistrationSideEffectOperationV1;
  readonly key: string;
  readonly requestFingerprint: string;
  readonly nowMs: () => number;
};

export type RouterAbEd25519YaoRegistrationSideEffectRunInputV1<T, P = never> =
  | (RouterAbEd25519YaoRegistrationSideEffectRunInputBaseV1 & {
      readonly kind: 'non_resumable';
      readonly prepare?: never;
      readonly execute: (attempt: 'fresh') => Promise<T>;
    })
  | (RouterAbEd25519YaoRegistrationSideEffectRunInputBaseV1 & {
      readonly kind: 'prepared_resumable';
      readonly prepare: () => Promise<P>;
      readonly execute: (
        prepared: P,
        attempt: RouterAbEd25519YaoRegistrationSideEffectAttemptV1,
      ) => Promise<T>;
    });

export type RouterAbEd25519YaoRegistrationSideEffectExecutionV1<T, P = never> =
  RouterAbEd25519YaoRegistrationSideEffectRunInputV1<T, P>['execute'];

export type RouterAbEd25519YaoRegistrationSideEffectRunResultV1<T, P = never> =
  | { readonly kind: 'executed'; readonly value: T }
  | { readonly kind: 'exact_replay'; readonly value: T }
  /**
   * A claim exists for this exact request but no completion. `prepared` is the
   * durable artifact from the original attempt; a caller that can replay it
   * safely should do so rather than constructing a new one.
   */
  | { readonly kind: 'in_progress'; readonly prepared?: P }
  | { readonly kind: 'request_conflict' }
  | {
      readonly kind: 'uncertain';
      readonly phase: 'claim' | 'effect' | 'terminal_commit';
      readonly message: string;
    };

/**
 * Claims a start/finalize request before any one-use effect. Prepared effects
 * may resume from the durable artifact after response loss; their execution
 * must therefore be idempotent. The first terminal CAS wins, and every
 * competing request returns that exact committed response.
 */
export async function runRouterAbEd25519YaoRegistrationSideEffectV1<T, P = never>(
  store: RouterAbEd25519YaoRegistrationSideEffectStoreV1<T, P>,
  input: RouterAbEd25519YaoRegistrationSideEffectRunInputV1<T, P>,
): Promise<RouterAbEd25519YaoRegistrationSideEffectRunResultV1<T, P>> {
  const key = requireOpaqueKey(input.key);
  const requestFingerprint = requireRequestFingerprint(input.requestFingerprint);
  let existing: CloudflareVersionedJsonRecordReadResult<
    RouterAbEd25519YaoRegistrationSideEffectRecordV1<T, P>
  >;
  try {
    existing = await store.read(key);
  } catch (error: unknown) {
    return uncertainResult('claim', error);
  }
  const disposition = existingDisposition(existing, input.operation, requestFingerprint);
  const resumable =
    input.kind === 'prepared_resumable' &&
    disposition.kind === 'in_progress' &&
    disposition.prepared !== undefined &&
    existing.kind === 'present';
  if (disposition.kind !== 'fresh' && !resumable) return disposition;

  let preparedForExecution: P | undefined;
  let claimedAtMs: number;
  let claimVersion: string;
  if (resumable && existing.kind === 'present') {
    // Resume the interrupted attempt: replay its persisted artifact under the
    // original claim rather than building a second one.
    if (
      existing.value.kind !== 'router_ab_ed25519_yao_registration_side_effect_claim_v1' ||
      !('prepared' in existing.value)
    ) {
      return {
        kind: 'uncertain',
        phase: 'claim',
        message: 'prepared side-effect claim could not be reconciled',
      };
    }
    preparedForExecution = existing.value.prepared;
    claimedAtMs = existing.value.claimedAtMs;
    claimVersion = existing.version;
  } else {
    let claim: RouterAbEd25519YaoRegistrationSideEffectClaimV1<P>;
    if (input.kind === 'prepared_resumable') {
      try {
        preparedForExecution = await input.prepare();
      } catch (error: unknown) {
        return uncertainResult('claim', error);
      }
      claim = {
        kind: 'router_ab_ed25519_yao_registration_side_effect_claim_v1',
        operation: input.operation,
        requestFingerprint,
        claimedAtMs: requireTimestamp(input.nowMs(), 'claimedAtMs'),
        prepared: preparedForExecution,
      };
    } else {
      claim = {
        kind: 'router_ab_ed25519_yao_registration_side_effect_claim_v1',
        operation: input.operation,
        requestFingerprint,
        claimedAtMs: requireTimestamp(input.nowMs(), 'claimedAtMs'),
      };
    }

    claimedAtMs = claim.claimedAtMs;
    let claimed: CloudflareVersionedJsonRecordPutResult;
    try {
      claimed = await store.put(key, claim, null);
    } catch (error: unknown) {
      return uncertainResult('claim', error);
    }
    if (claimed.kind === 'version_mismatch') {
      let reconciledRecord: CloudflareVersionedJsonRecordReadResult<
        RouterAbEd25519YaoRegistrationSideEffectRecordV1<T, P>
      >;
      try {
        reconciledRecord = await store.read(key);
      } catch (error: unknown) {
        return uncertainResult('claim', error);
      }
      const reconciledClaim = existingDisposition(
        reconciledRecord,
        input.operation,
        requestFingerprint,
      );
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
    if (input.kind === 'prepared_resumable') {
      if (preparedForExecution === undefined) {
        throw new Error('prepared side-effect execution artifact is missing');
      }
      response = await input.execute(preparedForExecution, resumable ? 'resumed' : 'fresh');
    } else {
      response = await input.execute('fresh');
    }
  } catch (error: unknown) {
    return uncertainResult('effect', error);
  }

  const completion: RouterAbEd25519YaoRegistrationSideEffectCompletionV1<T> = {
    kind: 'router_ab_ed25519_yao_registration_side_effect_completion_v1',
    operation: input.operation,
    requestFingerprint,
    claimedAtMs,
    completedAtMs: requireTimestamp(input.nowMs(), 'completedAtMs'),
    response,
  };
  let committed: CloudflareVersionedJsonRecordPutResult;
  try {
    committed = await store.put(key, completion, claimVersion);
  } catch (error: unknown) {
    return uncertainResult('terminal_commit', error);
  }
  if (committed.kind === 'stored') return { kind: 'executed', value: response };

  let terminalRecord: CloudflareVersionedJsonRecordReadResult<
    RouterAbEd25519YaoRegistrationSideEffectRecordV1<T, P>
  >;
  try {
    terminalRecord = await store.read(key);
  } catch (error: unknown) {
    return uncertainResult('terminal_commit', error);
  }
  const reconciled = existingDisposition(terminalRecord, input.operation, requestFingerprint);
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

function existingDisposition<T, P>(
  record: CloudflareVersionedJsonRecordReadResult<
    RouterAbEd25519YaoRegistrationSideEffectRecordV1<T, P>
  >,
  operation: RouterAbEd25519YaoRegistrationSideEffectOperationV1,
  requestFingerprint: string,
): ExistingDisposition<T, P> {
  if (record.kind === 'missing') return { kind: 'fresh' };
  if (
    record.value.operation !== operation ||
    record.value.requestFingerprint !== requestFingerprint
  ) {
    return { kind: 'request_conflict' };
  }
  switch (record.value.kind) {
    case 'router_ab_ed25519_yao_registration_side_effect_claim_v1':
      return 'prepared' in record.value
        ? { kind: 'in_progress', prepared: record.value.prepared }
        : { kind: 'in_progress' };
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

function requireTimestamp(value: number, label: string): number {
  if (!Number.isSafeInteger(value) || value < 0) {
    throw new Error(`registration side-effect ${label} is invalid`);
  }
  return value;
}

function uncertainResult(
  phase: 'claim' | 'effect' | 'terminal_commit',
  error: unknown,
): Extract<
  RouterAbEd25519YaoRegistrationSideEffectRunResultV1<never>,
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
