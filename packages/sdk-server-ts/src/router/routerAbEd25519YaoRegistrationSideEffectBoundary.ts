import type {
  CloudflareVersionedJsonRecordPutResult,
  CloudflareVersionedJsonRecordReadResult,
} from './cloudflare/versionedJsonRecordStore';

export type RouterAbEd25519YaoRegistrationSideEffectOperationV1 = 'start' | 'finalize';

export type RouterAbEd25519YaoRegistrationSideEffectClaimV1 = {
  readonly kind: 'router_ab_ed25519_yao_registration_side_effect_claim_v1';
  readonly operation: RouterAbEd25519YaoRegistrationSideEffectOperationV1;
  readonly requestFingerprint: string;
  readonly claimedAtMs: number;
};

export type RouterAbEd25519YaoRegistrationSideEffectCompletionV1<T> = {
  readonly kind: 'router_ab_ed25519_yao_registration_side_effect_completion_v1';
  readonly operation: RouterAbEd25519YaoRegistrationSideEffectOperationV1;
  readonly requestFingerprint: string;
  readonly claimedAtMs: number;
  readonly completedAtMs: number;
  readonly response: T;
};

export type RouterAbEd25519YaoRegistrationSideEffectRecordV1<T> =
  | RouterAbEd25519YaoRegistrationSideEffectClaimV1
  | RouterAbEd25519YaoRegistrationSideEffectCompletionV1<T>;

export interface RouterAbEd25519YaoRegistrationSideEffectStoreV1<T> {
  read(
    key: string,
  ): Promise<
    CloudflareVersionedJsonRecordReadResult<RouterAbEd25519YaoRegistrationSideEffectRecordV1<T>>
  >;
  put(
    key: string,
    value: RouterAbEd25519YaoRegistrationSideEffectRecordV1<T>,
    expectedVersion: string | null,
  ): Promise<CloudflareVersionedJsonRecordPutResult>;
}

export type RouterAbEd25519YaoRegistrationSideEffectExecutionV1<T> = () => Promise<T>;

export type RouterAbEd25519YaoRegistrationSideEffectRunInputV1<T> = {
  readonly operation: RouterAbEd25519YaoRegistrationSideEffectOperationV1;
  readonly key: string;
  readonly requestFingerprint: string;
  readonly nowMs: () => number;
  readonly execute: RouterAbEd25519YaoRegistrationSideEffectExecutionV1<T>;
};

export type RouterAbEd25519YaoRegistrationSideEffectRunResultV1<T> =
  | { readonly kind: 'executed'; readonly value: T }
  | { readonly kind: 'exact_replay'; readonly value: T }
  | { readonly kind: 'in_progress' }
  | { readonly kind: 'request_conflict' }
  | {
      readonly kind: 'uncertain';
      readonly phase: 'claim' | 'effect' | 'terminal_commit';
      readonly message: string;
    };

/**
 * Claims a start/finalize request before any one-use effect. A claimed request
 * is never executed again. Its exact terminal response is replayed after a
 * successful commit, including when a competing request committed it first.
 */
export async function runRouterAbEd25519YaoRegistrationSideEffectV1<T>(
  store: RouterAbEd25519YaoRegistrationSideEffectStoreV1<T>,
  input: RouterAbEd25519YaoRegistrationSideEffectRunInputV1<T>,
): Promise<RouterAbEd25519YaoRegistrationSideEffectRunResultV1<T>> {
  const key = requireOpaqueKey(input.key);
  const requestFingerprint = requireRequestFingerprint(input.requestFingerprint);
  let existing: CloudflareVersionedJsonRecordReadResult<
    RouterAbEd25519YaoRegistrationSideEffectRecordV1<T>
  >;
  try {
    existing = await store.read(key);
  } catch (error: unknown) {
    return uncertainResult('claim', error);
  }
  const disposition = existingDisposition(existing, input.operation, requestFingerprint);
  if (disposition.kind !== 'fresh') return disposition;

  const claimedAtMs = requireTimestamp(input.nowMs(), 'claimedAtMs');
  const claim: RouterAbEd25519YaoRegistrationSideEffectClaimV1 = {
    kind: 'router_ab_ed25519_yao_registration_side_effect_claim_v1',
    operation: input.operation,
    requestFingerprint,
    claimedAtMs,
  };
  let claimed: CloudflareVersionedJsonRecordPutResult;
  try {
    claimed = await store.put(key, claim, null);
  } catch (error: unknown) {
    return uncertainResult('claim', error);
  }
  if (claimed.kind === 'version_mismatch') {
    let reconciledRecord: CloudflareVersionedJsonRecordReadResult<
      RouterAbEd25519YaoRegistrationSideEffectRecordV1<T>
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

  let response: T;
  try {
    response = await input.execute();
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
    committed = await store.put(key, completion, claimed.version);
  } catch (error: unknown) {
    return uncertainResult('terminal_commit', error);
  }
  if (committed.kind === 'stored') return { kind: 'executed', value: response };

  let terminalRecord: CloudflareVersionedJsonRecordReadResult<
    RouterAbEd25519YaoRegistrationSideEffectRecordV1<T>
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

type ExistingDisposition<T> =
  | { readonly kind: 'fresh' }
  | Exclude<RouterAbEd25519YaoRegistrationSideEffectRunResultV1<T>, { readonly kind: 'executed' }>;

function existingDisposition<T>(
  record: CloudflareVersionedJsonRecordReadResult<
    RouterAbEd25519YaoRegistrationSideEffectRecordV1<T>
  >,
  operation: RouterAbEd25519YaoRegistrationSideEffectOperationV1,
  requestFingerprint: string,
): ExistingDisposition<T> {
  if (record.kind === 'missing') return { kind: 'fresh' };
  if (
    record.value.operation !== operation ||
    record.value.requestFingerprint !== requestFingerprint
  ) {
    return { kind: 'request_conflict' };
  }
  switch (record.value.kind) {
    case 'router_ab_ed25519_yao_registration_side_effect_claim_v1':
      return { kind: 'in_progress' };
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
