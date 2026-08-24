import type { CurrentEd25519SealedSessionRecord } from '@/core/signingEngine/session/persistence/sealedSessionStore';
import type { PasskeyCustodyEnvelopeRecord } from '@shared/passkey-custody';
import { readExactEd25519SealedSession } from '@/core/signingEngine/session/persistence/sealedSessionStore';
import { ed25519DurableMaterialLocator } from '../sealedRecovery/materialActivationKey';
import { parseSigningSessionSealKeyVersion } from '@/core/signingEngine/session/keyMaterialBrands';
import {
  assertEd25519YaoWarmRecoveryDescriptorStableMaterialContinuity,
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
  parsePasskeyWalletAuthAuthority,
  parseWalletAuthAuthorityRef,
  walletAuthAuthorityRef,
  type WalletAuthAuthorityRef,
} from '@shared/utils/walletAuthAuthority';
import { walletIdFromString } from '@shared/utils/registrationIntent';
import { isPlainObject } from '@shared/utils/validation';
import { IndexedDBManager } from '@/core/indexedDB';
import { walletSessionFailureErrorFromPayload } from '../lifecycle/walletSessionFailure';
import {
  parseMpcWalletSigningQuotaId,
  parseWalletSessionId,
} from '@shared/authorization/capabilityKinds';
import {
  walletSessionAuthorizations,
  walletSessionAuthorizationIdForCurve,
  walletSessionTokenForCurve,
  walletSessionThresholdSessionIdForCurve,
  type ActiveWalletSessionAuthorizationProjection,
  type WalletSessionAuthorizationReadResult,
} from '@/core/indexedDB/seamsWalletDB/walletSessionAuthorizationStore';
import {
  mpcMaterialActivationRefsEqual,
  parseWalletId,
  type MpcMaterialActivationRef,
  type ThresholdEd25519SessionId,
  type WalletId,
} from '@shared/utils/domainIds';
import { decodeJwtPayloadRecord } from '@shared/utils/sessionTokens';
import { readPasskeyCustodySessionEnvelope } from './passkeyCustodySessionCache';

export type PasskeyEd25519RecordRuntimePorts = {
  readonly readExactEd25519SealedSession: typeof readExactEd25519SealedSession;
  readonly readPasskeyCustodySessionEnvelope: typeof readPasskeyCustodySessionEnvelope;
  readonly resolveExactPasskeyWalletAuthAuthorityRef: (args: {
    readonly walletId: WalletId;
    readonly rpId: string;
    readonly credentialIdB64u: string;
  }) => Promise<WalletAuthAuthorityRef | null>;
  readonly readActiveWalletSessionAuthorization: (
    walletId: WalletId,
  ) => Promise<WalletSessionAuthorizationReadResult<ActiveWalletSessionAuthorizationProjection>>;
  readonly nowMs: () => number;
};

export type PasskeyEd25519WarmRecoverySubject = {
  readonly kind: 'owner_sealed_runtime';
  readonly walletId: string;
  readonly nearAccountId: string;
  readonly nearEd25519SigningKeyId: string;
  readonly signerSlot: number;
  readonly thresholdSessionId: ThresholdEd25519SessionId;
  readonly materialActivation: MpcMaterialActivationRef;
};

export type PasskeyEd25519YaoWarmRecoveryUnavailableReason =
  | 'sealed_session_missing'
  | 'sealed_session_expired'
  | 'sealed_session_exhausted'
  | 'wallet_session_expired'
  | 'wallet_custody_envelope_missing';

export type PasskeyEd25519YaoExportMaterialV1 = Omit<
  ParsedPasskeyEd25519YaoRecoveryDescriptorV1,
  'session' | 'capability'
> & {
  readonly capability: Pick<
    ParsedPasskeyEd25519YaoRecoveryDescriptorV1['capability'],
    | 'materialActivation'
    | 'activeCapabilityBinding'
    | 'registeredPublicKey'
    | 'nearAccountId'
    | 'applicationBinding'
    | 'participantIds'
    | 'runtimePolicyScope'
    | 'lifecycle'
    | 'stateEpoch'
  >;
};

export type PasskeyEd25519YaoExportContextV1 = {
  readonly kind: 'passkey_ed25519_yao_export_context_v1';
  readonly selectedLaneMaterialActivation: MpcMaterialActivationRef;
  readonly material: PasskeyEd25519YaoExportMaterialV1;
  readonly authorization: ActiveWalletSessionAuthorizationProjection;
  readonly relayerUrl: string;
  readonly rpId: string;
  readonly walletCustodyEnvelope: PasskeyCustodyEnvelopeRecord;
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

const OWNER_WARM_RECOVERY_RESPONSE_KEYS = [
  'authority',
  'authorityRef',
  'authorityScope',
  'capability',
  'kind',
  'nearAccountId',
  'nearEd25519SigningKeyId',
  'participantIds',
  'quotaId',
  'routerAbNormalSigning',
  'runtimePolicyScope',
  'signerSlot',
  'signingWorkerId',
  'thresholdExpiresAtMs',
  'thresholdSessionId',
  'walletId',
  'walletSessionId',
] as const;

function exactResponseKeys(
  record: Record<string, unknown>,
  expectedFields: readonly string[],
): void {
  const expected = [...expectedFields].sort();
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
  subject: Extract<PasskeyEd25519WarmRecoverySubject, { readonly kind: 'owner_sealed_runtime' }>,
): boolean {
  if (record.authMethod !== 'passkey') return false;
  const restore = record.ed25519Restore;
  if (!restore.credentialIdB64u) return false;
  return (
    record.walletId === subject.walletId &&
    restore.nearAccountId === subject.nearAccountId &&
    restore.nearEd25519SigningKeyId === subject.nearEd25519SigningKeyId &&
    restore.signerSlot === subject.signerSlot
  );
}

async function resolveExactWarmRecoveryRecord(
  subject: Extract<PasskeyEd25519WarmRecoverySubject, { readonly kind: 'owner_sealed_runtime' }>,
  runtime: PasskeyEd25519RecordRuntimePorts,
): Promise<WarmRecoveryRecordResult> {
  const record = await runtime.readExactEd25519SealedSession(
    ed25519DurableMaterialLocator({
      authMethod: 'passkey',
      materialActivation: subject.materialActivation,
    }),
  );
  if (
    record &&
    (record.curve !== 'ed25519' ||
      !sealedRecordMatchesSubject(record, subject) ||
      !mpcMaterialActivationRefsEqual(
        record.ed25519Restore.materialActivation,
        subject.materialActivation,
      ))
  ) {
    return { kind: 'unavailable', reason: 'sealed_session_missing' };
  }
  if (!record) return { kind: 'unavailable', reason: 'sealed_session_missing' };
  if (record.expiresAtMs <= runtime.nowMs()) {
    return { kind: 'unavailable', reason: 'sealed_session_expired' };
  }
  if (record.remainingUses < 1) {
    return { kind: 'unavailable', reason: 'sealed_session_exhausted' };
  }
  return { kind: 'ready', record };
}

async function resolveExactPasskeyWalletAuthAuthorityRefFromV2(args: {
  readonly walletId: WalletId;
  readonly rpId: string;
  readonly credentialIdB64u: string;
}): Promise<WalletAuthAuthorityRef | null> {
  const records = await IndexedDBManager.listWalletAuthMethodsV2ForWallet(String(args.walletId));
  const matches = records.filter(
    (record) =>
      record.kind === 'passkey' &&
      record.status === 'active' &&
      record.walletId === args.walletId &&
      String(record.rpId) === args.rpId &&
      String(record.credentialIdB64u) === args.credentialIdB64u,
  );
  const [record] = matches;
  if (matches.length !== 1 || !record || record.kind !== 'passkey') return null;
  return await walletAuthAuthorityRef({
    authority: {
      walletId: record.walletId,
      factor: {
        kind: 'passkey',
        credentialIdB64u: record.credentialIdB64u,
      },
      verifier: {
        kind: 'webauthn',
        rpId: record.rpId,
      },
      bindingId: record.walletAuthMethodId,
    },
  });
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

export async function requirePasskeyEd25519RestoreAuthorization(args: {
  readonly record: CurrentEd25519SealedSessionRecord;
  readonly authorizationRead: WalletSessionAuthorizationReadResult<ActiveWalletSessionAuthorizationProjection>;
  readonly expectedAuthorityRef: WalletAuthAuthorityRef;
  readonly nowMs: number;
}): Promise<ActiveWalletSessionAuthorizationProjection | null> {
  if (args.authorizationRead.kind !== 'found') return null;
  const authorization = args.authorizationRead.projection;
  if (
    authorization.authMethod !== 'passkey' ||
    String(authorization.walletId) !== args.record.walletId ||
    authorization.authority.walletId !== args.expectedAuthorityRef.walletId ||
    authorization.authority.walletAuthMethodId !== args.expectedAuthorityRef.walletAuthMethodId ||
    authorization.authority.authorityDigest !== args.expectedAuthorityRef.authorityDigest ||
    authorization.expiresAtMs <= args.nowMs
  ) {
    return null;
  }
  if (!walletSessionTokenForCurve(authorization, 'ed25519')) return null;
  return authorization;
}

function ownerWarmRecoveryBootstrapRequest(
  record: CurrentEd25519SealedSessionRecord,
  thresholdSessionId: ThresholdEd25519SessionId,
): RouterAbEd25519YaoWarmRecoveryBootstrapRequestV1 {
  const restore = record.ed25519Restore;
  const parsed = parseRouterAbEd25519YaoWarmRecoveryBootstrapRequestV1({
    kind: 'router_ab_ed25519_yao_warm_recovery_bootstrap_request_v1',
    walletId: record.walletId,
    nearAccountId: restore.nearAccountId,
    nearEd25519SigningKeyId: restore.nearEd25519SigningKeyId,
    signerSlot: restore.signerSlot,
    thresholdSessionId,
    signingWorkerId: restore.routerAbNormalSigning.signingWorkerId,
    participantIds: restore.participantIds,
  });
  if (!parsed.ok) throw new Error(parsed.message);
  return parsed.value;
}

async function fetchWarmRecoveryBootstrap(args: {
  readonly request: RouterAbEd25519YaoWarmRecoveryBootstrapRequestV1;
  readonly authorization: ActiveWalletSessionAuthorizationProjection;
  readonly relayerUrl: string;
  readonly fetch: typeof fetch;
}): Promise<WarmRecoveryBootstrapResult> {
  const walletSessionToken = walletSessionTokenForCurve(args.authorization, 'ed25519');
  if (!walletSessionToken) {
    throw new Error('[SigningEngine][near] active Wallet Session authorization is unavailable');
  }
  if (
    args.authorization.walletId !== args.request.walletId ||
    args.authorization.authMethod !== 'passkey' ||
    !args.authorization.walletSessionId ||
    !args.authorization.quotaId
  ) {
    throw new Error(
      '[SigningEngine][near] active Wallet Session authorization does not match sealed material',
    );
  }
  const response = await args.fetch(
    `${new URL(args.relayerUrl).origin}${ROUTER_AB_ED25519_YAO_WARM_RECOVERY_BOOTSTRAP_PATH_V1}`,
    {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${walletSessionToken}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(args.request),
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
    const tokenClaims = decodeJwtPayloadRecord(walletSessionToken);
    const tokenKind = String(tokenClaims?.kind || 'opaque');
    throw new Error(
      `[SigningEngine][near] Ed25519 warm recovery bootstrap failed (HTTP ${response.status}${code ? `, ${code}` : ''}, token ${tokenKind}): ${message || 'invalid response'}`,
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

async function parseWarmRecoveryDescriptor(args: {
  readonly record: CurrentEd25519SealedSessionRecord;
  readonly authorization: ActiveWalletSessionAuthorizationProjection;
  readonly expectedAuthorityRef: WalletAuthAuthorityRef;
  readonly response: Record<string, unknown>;
}): Promise<ParsedPasskeyEd25519YaoRecoveryDescriptorV1> {
  const record = args.record;
  const response = args.response;
  exactResponseKeys(response, OWNER_WARM_RECOVERY_RESPONSE_KEYS);
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
  const signingWorkerId = requireString(response.signingWorkerId, 'response.signingWorkerId');
  const thresholdExpiresAtMs = requirePositiveInteger(
    response.thresholdExpiresAtMs,
    'response.thresholdExpiresAtMs',
  );
  const participantIds = requireParticipantIds(response.participantIds);
  const authority = parsePasskeyWalletAuthAuthority(response.authority);
  const authorityRef = parseWalletAuthAuthorityRef(response.authorityRef);
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
  const walletSessionId = parseWalletSessionId(response.walletSessionId);
  const authorizationId = walletSessionAuthorizationIdForCurve(args.authorization, 'ed25519');
  const quotaId = parseMpcWalletSigningQuotaId(response.quotaId);
  const capability = parseEd25519YaoRecoveryCapabilityV1(response.capability);
  const walletSessionToken = walletSessionTokenForCurve(args.authorization, 'ed25519');
  const authorizationThresholdSessionId = walletSessionThresholdSessionIdForCurve(
    args.authorization,
    'ed25519',
  );
  const responseAuthorityRef = authority ? await walletAuthAuthorityRef({ authority }) : null;
  if (
    !authority ||
    !authorityRef ||
    !responseAuthorityRef ||
    authorityRef.walletId !== responseAuthorityRef.walletId ||
    authorityRef.walletAuthMethodId !== responseAuthorityRef.walletAuthMethodId ||
    authorityRef.authorityDigest !== responseAuthorityRef.authorityDigest ||
    authority.walletId !== record.walletId ||
    authority.factor.credentialIdB64u !== credentialIdB64u ||
    authority.verifier.rpId !== restore.rpId ||
    authority.bindingId !== args.expectedAuthorityRef.walletAuthMethodId ||
    authorityRef.walletId !== args.expectedAuthorityRef.walletId ||
    authorityRef.walletAuthMethodId !== args.expectedAuthorityRef.walletAuthMethodId ||
    authorityRef.authorityDigest !== args.expectedAuthorityRef.authorityDigest ||
    authorityScope.kind !== 'passkey_rp' ||
    !walletSessionId.ok ||
    !authorizationId ||
    !quotaId.ok ||
    String(walletSessionId.value) !== String(args.authorization.walletSessionId) ||
    String(quotaId.value) !== String(args.authorization.quotaId) ||
    authorityRef.authorityDigest !== args.authorization.authority.authorityDigest ||
    authorityScope.rpId !== restore.rpId ||
    !routerAbNormalSigning ||
    walletId !== record.walletId ||
    nearAccountId !== restore.nearAccountId ||
    nearEd25519SigningKeyId !== restore.nearEd25519SigningKeyId ||
    signerSlot !== restore.signerSlot ||
    !authorizationThresholdSessionId ||
    thresholdSessionId !== String(authorizationThresholdSessionId) ||
    !walletSessionToken ||
    signingWorkerId !== restore.relayerKeyId ||
    signingWorkerId !== restore.routerAbNormalSigning.signingWorkerId ||
    routerAbNormalSigning.signingWorkerId !== signingWorkerId ||
    // A renewed Wallet Session may outlive the sealed material. The material
    // expiry remains the upper bound for this restore lane.
    record.expiresAtMs > thresholdExpiresAtMs ||
    participantIds[0] !== restore.participantIds[0] ||
    participantIds[1] !== restore.participantIds[1] ||
    !sameRuntimePolicyScope(responseRuntimePolicyScope, sealedRuntimePolicyScope)
  ) {
    throw new Error('warm recovery bootstrap does not match the exact sealed Ed25519 lane');
  }
  const signingRoot = signingRootScopeFromRuntimePolicyScope(responseRuntimePolicyScope);
  if (!signingRoot) throw new Error('warm recovery bootstrap signing-root scope is invalid');
  if (!walletSessionToken) {
    throw new Error('[SigningEngine][near] active Wallet Session authorization is unavailable');
  }
  const descriptor: ParsedPasskeyEd25519YaoRecoveryDescriptorV1 = {
    authority: authorityRef,
    walletId: walletIdFromString(walletId),
    nearAccountId: toAccountId(nearAccountId),
    nearEd25519SigningKeyId,
    signerSlot,
    operationalPublicKey: `ed25519:${base58Encode(Uint8Array.from(capability.registeredPublicKey))}`,
    relayerKeyId: signingWorkerId,
    credentialIdB64u,
    session: {
      sessionKind: 'opaque',
      walletSessionToken,
      thresholdSessionId,
      walletSessionId: walletSessionId.value,
      authorizationId,
      quotaId: quotaId.value,
      expiresAtMs: thresholdExpiresAtMs,
      remainingUses: record.remainingUses,
      runtimePolicyScope: responseRuntimePolicyScope,
      participantIds,
      routerAbNormalSigning,
    },
    capability,
  };
  assertEd25519YaoWarmRecoveryDescriptorStableMaterialContinuity(
    descriptor,
    restore.materialActivation,
  );
  return descriptor;
}

export async function resolvePasskeyEd25519YaoExportContextV1(input: {
  readonly subject: PasskeyEd25519WarmRecoverySubject;
  readonly relayerUrl: string;
  readonly fetch: typeof fetch;
}): Promise<PasskeyEd25519YaoExportContextResolutionV1> {
  return await resolvePasskeyEd25519YaoExportContextWithRuntimeV1(input, {
    readExactEd25519SealedSession,
    readPasskeyCustodySessionEnvelope,
    resolveExactPasskeyWalletAuthAuthorityRef: resolveExactPasskeyWalletAuthAuthorityRefFromV2,
    readActiveWalletSessionAuthorization: walletSessionAuthorizations.readActiveForWallet.bind(
      walletSessionAuthorizations,
    ),
    nowMs: Date.now,
  });
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
  const walletId = parseWalletId(exactRecord.record.walletId);
  if (!walletId.ok) {
    throw new Error('[SigningEngine][near] sealed Ed25519 wallet identity is invalid');
  }
  const authorizationRead = await runtime.readActiveWalletSessionAuthorization(walletId.value);
  const expectedAuthorityRef = await runtime.resolveExactPasskeyWalletAuthAuthorityRef({
    walletId: walletId.value,
    rpId: exactRecord.record.ed25519Restore.rpId,
    credentialIdB64u: requireString(
      exactRecord.record.ed25519Restore.credentialIdB64u,
      'ed25519Restore.credentialIdB64u',
    ),
  });
  if (!expectedAuthorityRef) {
    return {
      kind: 'capability_recovery_required',
      reason: 'wallet_session_expired',
    };
  }
  const authorization = await requirePasskeyEd25519RestoreAuthorization({
    record: exactRecord.record,
    authorizationRead,
    expectedAuthorityRef,
    nowMs: runtime.nowMs(),
  });
  if (!authorization) {
    return {
      kind: 'capability_recovery_required',
      reason: 'wallet_session_expired',
    };
  }
  const thresholdSessionId = walletSessionThresholdSessionIdForCurve(authorization, 'ed25519');
  if (!thresholdSessionId) {
    return {
      kind: 'capability_recovery_required',
      reason: 'wallet_session_expired',
    };
  }
  const bootstrap = await fetchWarmRecoveryBootstrap({
    request: ownerWarmRecoveryBootstrapRequest(exactRecord.record, thresholdSessionId),
    authorization,
    relayerUrl: input.relayerUrl,
    fetch: input.fetch,
  });
  if (bootstrap.kind === 'unavailable') {
    return {
      kind: 'capability_recovery_required',
      reason: bootstrap.reason,
    };
  }
  const descriptor = await parseWarmRecoveryDescriptor({
    record: exactRecord.record,
    authorization,
    expectedAuthorityRef,
    response: bootstrap.response,
  });
  const walletCustodyEnvelope = await runtime.readPasskeyCustodySessionEnvelope({
    walletId: String(descriptor.walletId),
    credentialIdB64u: descriptor.credentialIdB64u,
  });
  if (!walletCustodyEnvelope || walletCustodyEnvelope.binding.kind !== 'wallet_custody_seed_v1') {
    return {
      kind: 'capability_recovery_required',
      reason: 'wallet_custody_envelope_missing',
    };
  }
  return {
    kind: 'ready',
    context: {
      kind: 'passkey_ed25519_yao_export_context_v1',
      selectedLaneMaterialActivation: descriptor.capability.materialActivation,
      material: {
        authority: descriptor.authority,
        walletId: descriptor.walletId,
        nearAccountId: descriptor.nearAccountId,
        nearEd25519SigningKeyId: descriptor.nearEd25519SigningKeyId,
        signerSlot: descriptor.signerSlot,
        operationalPublicKey: descriptor.operationalPublicKey,
        relayerKeyId: descriptor.relayerKeyId,
        credentialIdB64u: descriptor.credentialIdB64u,
        capability: descriptor.capability,
      },
      authorization,
      relayerUrl: input.relayerUrl,
      rpId: exactRecord.record.ed25519Restore.rpId,
      walletCustodyEnvelope,
    },
  };
}
