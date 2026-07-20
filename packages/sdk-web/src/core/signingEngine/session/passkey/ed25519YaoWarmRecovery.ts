import type {
  CurrentEd25519SealedSessionRecord,
  CurrentEd25519RestoreMetadata,
} from '@/core/signingEngine/session/persistence/sealedSessionStore';
import { listExactSealedSessionsForWallet } from '@/core/signingEngine/session/persistence/sealedSessionStore';
import { parseSigningSessionSealKeyVersion } from '@/core/signingEngine/session/keyMaterialBrands';
import type {
  DurableSealedSessionPort,
  VolatileWarmMaterialPort,
} from '@/core/signingEngine/uiConfirm/uiConfirm.types';
import {
  assertEd25519YaoRecoveryDescriptorContinuity,
  parseEd25519YaoRecoveryCapabilityV1,
  type ParsedPasskeyEd25519YaoRecoveryDescriptorV1,
} from '@/core/signingEngine/flows/recovery/passkeyEd25519YaoRecovery';
import { toAccountId } from '@/core/types/accountIds';
import { base58Encode } from '@shared/utils/base58';
import {
  normalizeRuntimePolicyScope,
  signingRootScopeFromRuntimePolicyScope,
} from '@shared/threshold/signingRootScope';
import {
  ROUTER_AB_ED25519_YAO_WARM_RECOVERY_BOOTSTRAP_PATH_V1,
  parseRouterAbEd25519YaoWarmRecoveryBootstrapRequestV1,
  type RouterAbEd25519YaoWarmRecoveryBootstrapRequestV1,
} from '@shared/utils/routerAbEd25519Yao';
import { parseRouterAbEd25519NormalSigningState } from '@shared/utils/signingSessionSeal';
import {
  buildPasskeyWalletAuthAuthority,
  parsePasskeyWalletAuthAuthority,
  walletAuthAuthoritiesMatch,
} from '@shared/utils/walletAuthAuthority';
import { walletIdFromString } from '@shared/utils/registrationIntent';
import { isPlainObject } from '@shared/utils/validation';
import {
  getSessionJwtExpiresAtMs,
  isSessionJwtUnexpired,
  isWalletSessionJwt,
} from '@shared/utils/sessionTokens';

type PasskeyEd25519WarmRecoveryPorts = Pick<
  DurableSealedSessionPort & VolatileWarmMaterialPort,
  'rehydrateWarmSessionMaterial' | 'claimWarmSessionMaterial'
>;

export type PasskeyEd25519RecordRuntimePorts = {
  readonly listExactSealedSessionsForWallet: typeof listExactSealedSessionsForWallet;
  readonly nowMs: () => number;
};

export type PasskeyEd25519WarmRecoverySubject = {
  readonly walletId: string;
  readonly nearAccountId: string;
  readonly signerSlot: number | null;
  readonly thresholdSessionId: string | null;
};

export type PasskeyEd25519YaoWarmRecoveryUnavailableReason =
  | 'sealed_session_missing'
  | 'sealed_session_expired'
  | 'sealed_session_exhausted'
  | 'wallet_session_expired';

export type PasskeyEd25519YaoLocalPrfRestoreResultV1 =
  | {
      readonly kind: 'ready';
      readonly record: CurrentEd25519SealedSessionRecord;
      readonly prfFirstB64u: string;
    }
  | {
      readonly kind: 'unavailable';
      readonly reason: Exclude<
        PasskeyEd25519YaoWarmRecoveryUnavailableReason,
        'wallet_session_expired'
      >;
    };

export type PasskeyEd25519YaoExportContextV1 = {
  readonly kind: 'passkey_ed25519_yao_export_context_v1';
  readonly descriptor: ParsedPasskeyEd25519YaoRecoveryDescriptorV1;
  readonly relayerUrl: string;
  readonly rpId: string;
};

export type PasskeyEd25519YaoExportContextResolutionV1 =
  | {
      readonly kind: 'ready';
      readonly context: PasskeyEd25519YaoExportContextV1;
    }
  | {
      readonly kind: 'capability_recovery_required';
      readonly reason: PasskeyEd25519YaoWarmRecoveryUnavailableReason;
    };

type WarmRecoveryRecordResult =
  | { readonly kind: 'ready'; readonly record: CurrentEd25519SealedSessionRecord }
  | {
      readonly kind: 'unavailable';
      readonly reason: Exclude<
        PasskeyEd25519YaoWarmRecoveryUnavailableReason,
        'wallet_session_expired'
      >;
    };

type WarmRecoveryPrfResult =
  | { readonly kind: 'ready'; readonly prfFirstB64u: string }
  | {
      readonly kind: 'unavailable';
      readonly reason: Exclude<
        PasskeyEd25519YaoWarmRecoveryUnavailableReason,
        'wallet_session_expired'
      >;
    };

type WarmRecoveryBootstrapResult =
  | { readonly kind: 'ready'; readonly response: Record<string, unknown> }
  | { readonly kind: 'unavailable'; readonly reason: 'wallet_session_expired' };

function requireRecord(value: unknown, label: string): Record<string, unknown> {
  if (!isPlainObject(value)) throw new Error(`${label} must be an object`);
  return value;
}

function requireString(value: unknown, label: string): string {
  const parsed = typeof value === 'string' ? value.trim() : '';
  if (!parsed) throw new Error(`${label} is required`);
  return parsed;
}

function requirePositiveInteger(value: unknown, label: string): number {
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < 1) {
    throw new Error(`${label} must be a positive integer`);
  }
  return value;
}

function requireParticipantIds(value: unknown): readonly [number, number] {
  if (
    !Array.isArray(value) ||
    value.length !== 2 ||
    !Number.isSafeInteger(value[0]) ||
    !Number.isSafeInteger(value[1]) ||
    value[0] < 1 ||
    value[1] < 1 ||
    value[0] === value[1]
  ) {
    throw new Error('warm recovery participantIds must contain two distinct positive integers');
  }
  return [Number(value[0]), Number(value[1])];
}

function exactResponseKeys(record: Record<string, unknown>): void {
  const expected = [
    'authority',
    'authorityScope',
    'capability',
    'kind',
    'nearAccountId',
    'nearEd25519SigningKeyId',
    'participantIds',
    'routerAbNormalSigning',
    'runtimePolicyScope',
    'signerSlot',
    'signingGrantId',
    'signingWorkerId',
    'thresholdExpiresAtMs',
    'thresholdSessionId',
    'walletId',
  ].sort();
  const actual = Object.keys(record).sort();
  if (actual.length !== expected.length) {
    throw new Error('warm recovery bootstrap response fields are invalid');
  }
  for (let index = 0; index < actual.length; index += 1) {
    if (actual[index] !== expected[index]) {
      throw new Error('warm recovery bootstrap response fields are invalid');
    }
  }
}

function sealedRecordMatchesSubject(
  record: CurrentEd25519SealedSessionRecord,
  subject: PasskeyEd25519WarmRecoverySubject,
): boolean {
  if (record.authMethod !== 'passkey') return false;
  const restore = record.ed25519Restore;
  if (!restore.credentialIdB64u || restore.sessionKind !== 'jwt') return false;
  return (
    record.walletId === subject.walletId &&
    restore.nearAccountId === subject.nearAccountId &&
    (subject.signerSlot === null || restore.signerSlot === subject.signerSlot) &&
    (subject.thresholdSessionId === null ||
      record.thresholdSessionIds.ed25519 === subject.thresholdSessionId)
  );
}

async function resolveExactWarmRecoveryRecord(
  subject: PasskeyEd25519WarmRecoverySubject,
  runtime: PasskeyEd25519RecordRuntimePorts,
): Promise<WarmRecoveryRecordResult> {
  const records = await runtime.listExactSealedSessionsForWallet({
    walletId: subject.walletId,
    filter: { authMethod: 'passkey', curve: 'ed25519' },
  });
  const matches: CurrentEd25519SealedSessionRecord[] = [];
  for (const record of records) {
    if (record.curve !== 'ed25519' || !sealedRecordMatchesSubject(record, subject)) continue;
    matches.push(record);
  }
  if (matches.length > 1) {
    throw new Error('[SigningEngine][near] exact persisted Ed25519 warm recovery is ambiguous');
  }
  const record = matches[0];
  if (!record) return { kind: 'unavailable', reason: 'sealed_session_missing' };
  if (record.expiresAtMs <= runtime.nowMs()) {
    return { kind: 'unavailable', reason: 'sealed_session_expired' };
  }
  if (record.remainingUses < 1) {
    return { kind: 'unavailable', reason: 'sealed_session_exhausted' };
  }
  return { kind: 'ready', record };
}

function unavailableReasonForWarmMaterialCode(
  code: string,
): Exclude<PasskeyEd25519YaoWarmRecoveryUnavailableReason, 'wallet_session_expired'> | null {
  switch (code) {
    case 'not_found':
    case 'missing':
      return 'sealed_session_missing';
    case 'expired':
      return 'sealed_session_expired';
    case 'exhausted':
      return 'sealed_session_exhausted';
    default:
      return null;
  }
}

function passkeyWalletSessionJwt(restore: CurrentEd25519RestoreMetadata): string {
  if (restore.sessionKind !== 'jwt') {
    throw new Error('passkey Ed25519 warm recovery requires a JWT Wallet Session');
  }
  return requireString(restore.walletSessionJwt, 'ed25519Restore.walletSessionJwt');
}

async function restoreAndClaimWarmRecoveryPrf(args: {
  readonly record: CurrentEd25519SealedSessionRecord;
  readonly ports: PasskeyEd25519WarmRecoveryPorts;
}): Promise<WarmRecoveryPrfResult> {
  const record = args.record;
  const thresholdSessionId = record.thresholdSessionIds.ed25519;
  const shamirPrimeB64u = requireString(record.shamirPrimeB64u, 'shamirPrimeB64u');
  const rehydrated = await args.ports.rehydrateWarmSessionMaterial({
    sessionId: thresholdSessionId,
    sealedSecretB64u: record.sealedSecretB64u,
    signingSessionSealKeyVersion: parseSigningSessionSealKeyVersion(record.keyVersion),
    expiresAtMs: record.expiresAtMs,
    remainingUses: Math.max(1_000_000, record.remainingUses),
    transport: {
      curve: 'ed25519',
      authMethod: 'passkey',
      walletId: record.walletId,
      relayerUrl: record.relayerUrl,
      signingGrantId: record.signingGrantId,
      walletSessionJwt: passkeyWalletSessionJwt(record.ed25519Restore),
      signingSessionSealKeyVersion: parseSigningSessionSealKeyVersion(record.keyVersion),
      shamirPrimeB64u,
    },
  });
  if (!rehydrated.ok) {
    const unavailable = unavailableReasonForWarmMaterialCode(rehydrated.code);
    if (unavailable) return { kind: 'unavailable', reason: unavailable };
    throw new Error(
      `[SigningEngine][near] Ed25519 sealed-session restore failed (${rehydrated.code}): ${rehydrated.message}`,
    );
  }
  const claimed = await args.ports.claimWarmSessionMaterial({
    sessionId: thresholdSessionId,
    uses: 1,
    consume: false,
    curve: 'ed25519',
    chain: 'near',
  });
  if (!claimed.ok) {
    const unavailable = unavailableReasonForWarmMaterialCode(claimed.code);
    if (unavailable) return { kind: 'unavailable', reason: unavailable };
    throw new Error(
      `[SigningEngine][near] Ed25519 warm PRF claim failed (${claimed.code}): ${claimed.message}`,
    );
  }
  return {
    kind: 'ready',
    prfFirstB64u: requireString(claimed.prfFirstB64u, 'claimed PRF.first'),
  };
}

function warmRecoveryBootstrapRequest(
  record: CurrentEd25519SealedSessionRecord,
): RouterAbEd25519YaoWarmRecoveryBootstrapRequestV1 {
  const restore = record.ed25519Restore;
  const parsed = parseRouterAbEd25519YaoWarmRecoveryBootstrapRequestV1({
    kind: 'router_ab_ed25519_yao_warm_recovery_bootstrap_request_v1',
    walletId: record.walletId,
    nearAccountId: restore.nearAccountId,
    nearEd25519SigningKeyId: restore.nearEd25519SigningKeyId,
    signerSlot: restore.signerSlot,
    thresholdSessionId: record.thresholdSessionIds.ed25519,
    signingGrantId: record.signingGrantId,
    signingWorkerId: restore.routerAbNormalSigning.signingWorkerId,
    participantIds: restore.participantIds,
  });
  if (!parsed.ok) throw new Error(parsed.message);
  return parsed.value;
}

async function fetchWarmRecoveryBootstrap(args: {
  readonly record: CurrentEd25519SealedSessionRecord;
  readonly relayerUrl: string;
  readonly fetch: typeof fetch;
}): Promise<WarmRecoveryBootstrapResult> {
  const response = await args.fetch(
    `${new URL(args.relayerUrl).origin}${ROUTER_AB_ED25519_YAO_WARM_RECOVERY_BOOTSTRAP_PATH_V1}`,
    {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${passkeyWalletSessionJwt(args.record.ed25519Restore)}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(warmRecoveryBootstrapRequest(args.record)),
    },
  );
  const body = await parseJsonResponseOrNull(response);
  const parsedBody = isPlainObject(body) ? body : null;
  if (!response.ok) {
    const code = parsedBody ? String(parsedBody.code || '').trim() : '';
    if (response.status === 401 && code === 'wallet_session_expired') {
      return { kind: 'unavailable', reason: 'wallet_session_expired' };
    }
    const message = parsedBody ? String(parsedBody.message || '').trim() : '';
    throw new Error(
      `[SigningEngine][near] Ed25519 warm recovery bootstrap failed (HTTP ${response.status}${code ? `, ${code}` : ''}): ${message || 'invalid response'}`,
    );
  }
  if (!parsedBody) throw new Error('Ed25519 warm recovery bootstrap returned invalid JSON');
  return { kind: 'ready', response: parsedBody };
}

async function parseJsonResponseOrNull(response: Response): Promise<unknown> {
  try {
    return await response.json();
  } catch {
    return null;
  }
}

function sameRuntimePolicyScope(
  left: ReturnType<typeof normalizeRuntimePolicyScope>,
  right: ReturnType<typeof normalizeRuntimePolicyScope>,
): boolean {
  return (
    left.orgId === right.orgId &&
    left.projectId === right.projectId &&
    left.envId === right.envId &&
    left.signingRootVersion === right.signingRootVersion
  );
}

function parseWarmRecoveryDescriptor(args: {
  readonly record: CurrentEd25519SealedSessionRecord;
  readonly response: Record<string, unknown>;
}): ParsedPasskeyEd25519YaoRecoveryDescriptorV1 {
  const record = args.record;
  const response = args.response;
  exactResponseKeys(response);
  if (response.kind !== 'router_ab_ed25519_yao_warm_recovery_bootstrap_v1') {
    throw new Error('warm recovery bootstrap response kind is invalid');
  }
  const restore = record.ed25519Restore;
  const credentialIdB64u = requireString(
    restore.credentialIdB64u,
    'ed25519Restore.credentialIdB64u',
  );
  const walletId = requireString(response.walletId, 'response.walletId');
  const nearAccountId = requireString(response.nearAccountId, 'response.nearAccountId');
  const nearEd25519SigningKeyId = requireString(
    response.nearEd25519SigningKeyId,
    'response.nearEd25519SigningKeyId',
  );
  const signerSlot = requirePositiveInteger(response.signerSlot, 'response.signerSlot');
  const thresholdSessionId = requireString(
    response.thresholdSessionId,
    'response.thresholdSessionId',
  );
  const signingGrantId = requireString(response.signingGrantId, 'response.signingGrantId');
  const signingWorkerId = requireString(response.signingWorkerId, 'response.signingWorkerId');
  const thresholdExpiresAtMs = requirePositiveInteger(
    response.thresholdExpiresAtMs,
    'response.thresholdExpiresAtMs',
  );
  const participantIds = requireParticipantIds(response.participantIds);
  const authority = parsePasskeyWalletAuthAuthority(response.authority);
  const expectedAuthority = buildPasskeyWalletAuthAuthority({
    walletId: record.walletId,
    rpId: restore.rpId,
    credentialIdB64u,
  });
  const authorityScope = requireRecord(response.authorityScope, 'response.authorityScope');
  const responseRuntimePolicyScope = normalizeRuntimePolicyScope(
    requireRecord(response.runtimePolicyScope, 'response.runtimePolicyScope'),
  );
  const sealedRuntimePolicyScope = normalizeRuntimePolicyScope(
    requireRecord(restore.runtimePolicyScope, 'ed25519Restore.runtimePolicyScope'),
  );
  const routerAbNormalSigning = parseRouterAbEd25519NormalSigningState(
    response.routerAbNormalSigning,
  );
  if (
    !authority ||
    !walletAuthAuthoritiesMatch(authority, expectedAuthority) ||
    authorityScope.kind !== 'passkey_rp' ||
    authorityScope.rpId !== restore.rpId ||
    !routerAbNormalSigning ||
    walletId !== record.walletId ||
    nearAccountId !== restore.nearAccountId ||
    nearEd25519SigningKeyId !== restore.nearEd25519SigningKeyId ||
    signerSlot !== restore.signerSlot ||
    thresholdSessionId !== record.thresholdSessionIds.ed25519 ||
    signingGrantId !== record.signingGrantId ||
    signingWorkerId !== restore.relayerKeyId ||
    signingWorkerId !== restore.routerAbNormalSigning.signingWorkerId ||
    routerAbNormalSigning.signingWorkerId !== signingWorkerId ||
    thresholdExpiresAtMs !== record.expiresAtMs ||
    participantIds[0] !== restore.participantIds[0] ||
    participantIds[1] !== restore.participantIds[1] ||
    !sameRuntimePolicyScope(responseRuntimePolicyScope, sealedRuntimePolicyScope)
  ) {
    throw new Error('warm recovery bootstrap does not match the exact sealed Ed25519 lane');
  }
  const capability = parseEd25519YaoRecoveryCapabilityV1(response.capability);
  const signingRoot = signingRootScopeFromRuntimePolicyScope(responseRuntimePolicyScope);
  if (!signingRoot) throw new Error('warm recovery bootstrap signing-root scope is invalid');
  return {
    walletId: walletIdFromString(walletId),
    nearAccountId: toAccountId(nearAccountId),
    nearEd25519SigningKeyId,
    signerSlot,
    operationalPublicKey: `ed25519:${base58Encode(Uint8Array.from(capability.registeredPublicKey))}`,
    relayerKeyId: signingWorkerId,
    credentialIdB64u,
    session: {
      walletSessionJwt: passkeyWalletSessionJwt(restore),
      thresholdSessionId,
      signingGrantId,
      expiresAtMs: thresholdExpiresAtMs,
      remainingUses: record.remainingUses,
      runtimePolicyScope: responseRuntimePolicyScope,
      participantIds,
      routerAbNormalSigning,
    },
    capability,
  };
}

export async function restorePasskeyEd25519YaoLocalPrfV1(input: {
  readonly subject: PasskeyEd25519WarmRecoverySubject;
  readonly ports: PasskeyEd25519WarmRecoveryPorts;
}): Promise<PasskeyEd25519YaoLocalPrfRestoreResultV1> {
  const exactRecord = await resolveExactWarmRecoveryRecord(input.subject, {
    listExactSealedSessionsForWallet,
    nowMs: Date.now,
  });
  if (exactRecord.kind === 'unavailable') return exactRecord;
  const prf = await restoreAndClaimWarmRecoveryPrf({
    record: exactRecord.record,
    ports: input.ports,
  });
  if (prf.kind === 'unavailable') return prf;
  return {
    kind: 'ready',
    record: exactRecord.record,
    prfFirstB64u: prf.prfFirstB64u,
  };
}

export async function resolvePasskeyEd25519YaoExportContextV1(input: {
  readonly subject: PasskeyEd25519WarmRecoverySubject;
  readonly relayerUrl: string;
  readonly fetch: typeof fetch;
}): Promise<PasskeyEd25519YaoExportContextResolutionV1> {
  return await resolvePasskeyEd25519YaoExportContextWithRuntimeV1(input, {
    listExactSealedSessionsForWallet,
    nowMs: Date.now,
  });
}

export async function resolvePasskeyEd25519WalletSessionRouteAuthV1(
  walletId: string,
): Promise<{ kind: 'wallet_session'; jwt: string } | null> {
  const records = await listExactSealedSessionsForWallet({
    walletId,
    filter: { authMethod: 'passkey', curve: 'ed25519' },
  });
  let selected: { jwt: string; expiresAtMs: number } | null = null;
  for (const record of records) {
    if (
      record.curve !== 'ed25519' ||
      record.expiresAtMs <= Date.now() ||
      record.remainingUses < 1 ||
      record.ed25519Restore.sessionKind !== 'jwt'
    ) {
      continue;
    }
    const jwt = String(record.ed25519Restore.walletSessionJwt || '').trim();
    const expiresAtMs = getSessionJwtExpiresAtMs(jwt);
    if (
      !jwt ||
      !expiresAtMs ||
      !isWalletSessionJwt(jwt) ||
      !isSessionJwtUnexpired(jwt, { skewMs: 30_000 })
    ) {
      continue;
    }
    if (!selected || expiresAtMs > selected.expiresAtMs) {
      selected = { jwt, expiresAtMs };
    }
  }
  return selected ? { kind: 'wallet_session', jwt: selected.jwt } : null;
}

export async function resolvePasskeyEd25519YaoExportContextWithRuntimeV1(
  input: {
    readonly subject: PasskeyEd25519WarmRecoverySubject;
    readonly relayerUrl: string;
    readonly fetch: typeof fetch;
  },
  runtime: PasskeyEd25519RecordRuntimePorts,
): Promise<PasskeyEd25519YaoExportContextResolutionV1> {
  const exactRecord = await resolveExactWarmRecoveryRecord(input.subject, runtime);
  if (exactRecord.kind === 'unavailable') {
    return {
      kind: 'capability_recovery_required',
      reason: exactRecord.reason,
    };
  }
  const bootstrap = await fetchWarmRecoveryBootstrap({
    record: exactRecord.record,
    relayerUrl: input.relayerUrl,
    fetch: input.fetch,
  });
  if (bootstrap.kind === 'unavailable') {
    return {
      kind: 'capability_recovery_required',
      reason: bootstrap.reason,
    };
  }
  const descriptor = parseWarmRecoveryDescriptor({
    record: exactRecord.record,
    response: bootstrap.response,
  });
  assertEd25519YaoRecoveryDescriptorContinuity(descriptor);
  return {
    kind: 'ready',
    context: {
      kind: 'passkey_ed25519_yao_export_context_v1',
      descriptor,
      relayerUrl: input.relayerUrl,
      rpId: exactRecord.record.ed25519Restore.rpId,
    },
  };
}
