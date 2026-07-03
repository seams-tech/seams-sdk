import { ActionType, type ActionArgsWasm } from '@shared/near/actions';
import {
  parseRouterAbEd25519NormalSigningState,
  type RouterAbEd25519NormalSigningState,
} from '@shared/utils/signingSessionSeal';
import { ensureEd25519Prefix, toOptionalTrimmedString } from '@shared/utils/validation';
import type {
  EcdsaHssClientBootstrapRequest,
  EcdsaHssServerBootstrapResponse,
  ThresholdEd25519AuthorityScope,
  ThresholdRuntimePolicyScope
} from '../types';
import type {
  WalletRegistrationEcdsaClientBootstrap,
  WalletRegistrationEcdsaPreparePayload,
  WalletRegistrationEcdsaWalletKey
} from '../registrationContracts';
import {
  parseThresholdEd25519AuthorityScope,
} from '../ThresholdService/validation';
import type { WebAuthnCredentialBindingStore } from '../WebAuthnCredentialBindingStore';
import type { ThresholdEcdsaChainTarget } from '../thresholdEcdsaChainTarget';
import { isObject } from './record';
import {
  normalizeThresholdRuntimePolicyScope,
  thresholdRuntimePolicyScopesEqual,
} from './thresholdRuntimePolicy';

export type ThresholdEd25519RegistrationInput = {
  keyVersion: string;
  recoveryExportCapable?: boolean;
  publicKey: string;
  relayerKeyId: string;
  sessionPolicy: Record<string, unknown> | null;
  sessionKind: string;
};

export type ThresholdEd25519BootstrapSession = {
  sessionKind: 'jwt' | 'cookie';
  walletId: string;
  nearAccountId: string;
  nearEd25519SigningKeyId: string;
  authorityScope: ThresholdEd25519AuthorityScope;
  thresholdSessionId: string;
  signingGrantId: string;
  expiresAtMs: number;
  expiresAt?: string;
  participantIds?: number[];
  remainingUses?: number;
  runtimePolicyScope?: ThresholdRuntimePolicyScope;
  routerAbNormalSigning?: RouterAbEd25519NormalSigningState;
  jwt?: string;
};

export function parseThresholdEd25519RegistrationInput(
  raw: unknown,
): ThresholdEd25519RegistrationInput {
  const body = isObject(raw) ? (raw as Record<string, unknown>) : null;
  return {
    keyVersion: String(body?.key_version || '').trim(),
    recoveryExportCapable:
      typeof body?.recovery_export_capable === 'boolean'
        ? Boolean(body.recovery_export_capable)
        : undefined,
    publicKey: String(body?.public_key || '').trim(),
    relayerKeyId: String(body?.relayer_key_id || '').trim(),
    sessionPolicy: isObject(body?.session_policy)
      ? (body!.session_policy as Record<string, unknown>)
      : null,
    sessionKind: String(body?.session_kind || '')
      .trim()
      .toLowerCase(),
  };
}

export function buildFullAccessAddKeyAction(publicKey: string): ActionArgsWasm {
  return {
    action_type: ActionType.AddKey,
    public_key: publicKey,
    access_key: JSON.stringify({
      nonce: 0,
      permission: { FullAccess: {} },
    }),
  };
}

export function normalizeBootstrapPublicKeys(args: {
  publicKey: string;
  recoveryPublicKey?: string;
}): {
  publicKey: string;
  recoveryPublicKey?: string;
  expectedPublicKeys: string[];
} {
  const publicKey = ensureEd25519Prefix(toOptionalTrimmedString(args.publicKey) || '');
  if (!publicKey) {
    throw new Error('Missing or invalid bootstrap operational public key');
  }
  const recoveryPublicKey = ensureEd25519Prefix(
    toOptionalTrimmedString(args.recoveryPublicKey) || '',
  );
  if (recoveryPublicKey && recoveryPublicKey === publicKey) {
    throw new Error('Bootstrap recovery public key must differ from the operational public key');
  }
  return {
    publicKey,
    ...(recoveryPublicKey ? { recoveryPublicKey } : {}),
    expectedPublicKeys: recoveryPublicKey ? [publicKey, recoveryPublicKey] : [publicKey],
  };
}

export async function resolveBoundThresholdRuntimePolicyScope(args: {
  bindingStore: WebAuthnCredentialBindingStore;
  userId: string;
  rpId: string;
}): Promise<ThresholdRuntimePolicyScope | undefined> {
  if (typeof args.bindingStore.listByUserId !== 'function') return undefined;
  const bindings = await args.bindingStore.listByUserId({
    userId: args.userId,
    rpId: args.rpId,
  });
  for (const binding of bindings) {
    const scope = normalizeThresholdRuntimePolicyScope(binding.runtimePolicyScope);
    if (scope) return scope;
  }
  return undefined;
}

export type EcdsaWalletKeyBuildResult =
  | { ok: true; walletKeys: WalletRegistrationEcdsaWalletKey[] }
  | { ok: false; code: 'incomplete_ecdsa_wallet_key'; message: string };

export function buildEcdsaWalletKeysFromBootstrap(args: {
  bootstrap: EcdsaHssServerBootstrapResponse;
  chainTargets: readonly ThresholdEcdsaChainTarget[];
  errorContext: string;
}): EcdsaWalletKeyBuildResult {
  const bootstrap = args.bootstrap;
  const required = {
    walletId: toOptionalTrimmedString(bootstrap.walletId),
    evmFamilySigningKeySlotId: toOptionalTrimmedString(bootstrap.evmFamilySigningKeySlotId),
    keyHandle: toOptionalTrimmedString(bootstrap.keyHandle),
    ecdsaThresholdKeyId: toOptionalTrimmedString(bootstrap.ecdsaThresholdKeyId),
    signingRootId: toOptionalTrimmedString(bootstrap.signingRootId),
    signingRootVersion: toOptionalTrimmedString(bootstrap.signingRootVersion),
    thresholdEcdsaPublicKeyB64u: toOptionalTrimmedString(bootstrap.thresholdEcdsaPublicKeyB64u),
    thresholdOwnerAddress: toOptionalTrimmedString(bootstrap.ethereumAddress),
    relayerKeyId: toOptionalTrimmedString(bootstrap.relayerKeyId),
    relayerVerifyingShareB64u: toOptionalTrimmedString(bootstrap.relayerVerifyingShareB64u),
  };
  const missingField = Object.entries(required).find(([, value]) => !value)?.[0];
  if (missingField) {
    return {
      ok: false,
      code: 'incomplete_ecdsa_wallet_key',
      message: `${args.errorContext} returned incomplete ECDSA wallet key material: ${missingField}`,
    };
  }
  const participantIds = Array.isArray(bootstrap.participantIds)
    ? bootstrap.participantIds
        .map((participantId) => Number(participantId))
        .filter((participantId) => Number.isSafeInteger(participantId) && participantId > 0)
    : [];
  if (participantIds.length === 0) {
    return {
      ok: false,
      code: 'incomplete_ecdsa_wallet_key',
      message: `${args.errorContext} returned incomplete ECDSA wallet key material: participantIds`,
    };
  }
  if (!Array.isArray(args.chainTargets) || args.chainTargets.length === 0) {
    return {
      ok: false,
      code: 'incomplete_ecdsa_wallet_key',
      message: `${args.errorContext} has no ECDSA chain targets`,
    };
  }
  return {
    ok: true,
    walletKeys: args.chainTargets.map((chainTarget) => ({
      keyScope: 'evm-family',
      chainTarget,
      walletId: required.walletId,
      evmFamilySigningKeySlotId: required.evmFamilySigningKeySlotId,
      keyHandle: required.keyHandle,
      ecdsaThresholdKeyId: required.ecdsaThresholdKeyId,
      signingRootId: required.signingRootId,
      signingRootVersion: required.signingRootVersion,
      thresholdEcdsaPublicKeyB64u: required.thresholdEcdsaPublicKeyB64u,
      thresholdOwnerAddress: required.thresholdOwnerAddress,
      relayerKeyId: required.relayerKeyId,
      relayerVerifyingShareB64u: required.relayerVerifyingShareB64u,
      participantIds,
    })),
  };
}

export function isMatchingEcdsaClientBootstrap(
  expected: WalletRegistrationEcdsaPreparePayload['prepare'],
  actual: WalletRegistrationEcdsaClientBootstrap,
): boolean {
  return (
    actual.formatVersion === expected.formatVersion &&
    actual.walletId === expected.walletId &&
    actual.evmFamilySigningKeySlotId === expected.evmFamilySigningKeySlotId &&
    actual.ecdsaThresholdKeyId === expected.ecdsaThresholdKeyId &&
    actual.signingRootId === expected.signingRootId &&
    actual.signingRootVersion === expected.signingRootVersion &&
    actual.keyScope === expected.keyScope &&
    actual.relayerKeyId === expected.relayerKeyId &&
    actual.registrationPreparationId === expected.registrationPreparationId &&
    actual.requestId === expected.requestId &&
    actual.thresholdSessionId === expected.thresholdSessionId &&
    actual.signingGrantId === expected.signingGrantId &&
    actual.ttlMs === expected.ttlMs &&
    actual.remainingUses === expected.remainingUses &&
    JSON.stringify(actual.participantIds) === JSON.stringify(expected.participantIds) &&
    thresholdRuntimePolicyScopesEqual(actual.runtimePolicyScope, expected.runtimePolicyScope)
  );
}

export function toEcdsaHssClientBootstrapRequest(
  clientBootstrap: WalletRegistrationEcdsaClientBootstrap,
): EcdsaHssClientBootstrapRequest {
  return {
    formatVersion: clientBootstrap.formatVersion,
    walletId: clientBootstrap.walletId,
    evmFamilySigningKeySlotId: clientBootstrap.evmFamilySigningKeySlotId,
    ecdsaThresholdKeyId: clientBootstrap.ecdsaThresholdKeyId,
    signingRootId: clientBootstrap.signingRootId,
    signingRootVersion: clientBootstrap.signingRootVersion,
    keyScope: clientBootstrap.keyScope,
    relayerKeyId: clientBootstrap.relayerKeyId,
    ...(clientBootstrap.registrationPreparationId
      ? { registrationPreparationId: clientBootstrap.registrationPreparationId }
      : {}),
    hssClientSharePublicKey33B64u: clientBootstrap.hssClientSharePublicKey33B64u,
    clientShareRetryCounter: clientBootstrap.clientShareRetryCounter,
    contextBinding32B64u: clientBootstrap.contextBinding32B64u,
    requestId: clientBootstrap.requestId,
    sessionId: clientBootstrap.thresholdSessionId,
    signingGrantId: clientBootstrap.signingGrantId,
    ttlMs: clientBootstrap.ttlMs,
    remainingUses: clientBootstrap.remainingUses,
    participantIds: clientBootstrap.participantIds,
    ...(clientBootstrap.runtimePolicyScope
      ? { runtimePolicyScope: clientBootstrap.runtimePolicyScope }
      : {}),
  };
}

export function toThresholdEd25519BootstrapSession(session: {
  walletId?: unknown;
  nearAccountId?: unknown;
  nearEd25519SigningKeyId?: unknown;
  authorityScope?: unknown;
  thresholdSessionId?: unknown;
  signingGrantId?: unknown;
  expiresAtMs?: unknown;
  expiresAt?: unknown;
  participantIds?: unknown;
  remainingUses?: unknown;
  runtimePolicyScope?: unknown;
  routerAbNormalSigning?: unknown;
  jwt?: unknown;
}): ThresholdEd25519BootstrapSession | null {
  const walletId = String(session.walletId || '').trim();
  const nearAccountId = String(session.nearAccountId || '').trim();
  const nearEd25519SigningKeyId = String(session.nearEd25519SigningKeyId || '').trim();
  const authorityScope = parseThresholdEd25519AuthorityScope(session.authorityScope);
  const thresholdSessionId = String(session.thresholdSessionId || '').trim();
  const signingGrantId = String(session.signingGrantId || '').trim();
  const expiresAtMs = Number(session.expiresAtMs);
  const runtimePolicyScope = normalizeThresholdRuntimePolicyScope(session.runtimePolicyScope);
  const routerAbNormalSigning = parseRouterAbEd25519NormalSigningState(
    session.routerAbNormalSigning,
  );
  if (
    !walletId ||
    !nearAccountId ||
    !nearEd25519SigningKeyId ||
    !authorityScope ||
    !thresholdSessionId ||
    !signingGrantId ||
    !Number.isFinite(expiresAtMs) ||
    expiresAtMs <= 0
  )
    return null;
  return {
    sessionKind: 'jwt',
    walletId,
    nearAccountId,
    nearEd25519SigningKeyId,
    authorityScope,
    thresholdSessionId,
    signingGrantId,
    expiresAtMs: Number(expiresAtMs),
    ...(typeof session.expiresAt === 'string' && session.expiresAt.trim()
      ? { expiresAt: session.expiresAt.trim() }
      : {}),
    ...(Array.isArray(session.participantIds) ? { participantIds: session.participantIds } : {}),
    ...(Number.isFinite(Number(session.remainingUses))
      ? { remainingUses: Number(session.remainingUses) }
      : {}),
    ...(runtimePolicyScope ? { runtimePolicyScope } : {}),
    ...(routerAbNormalSigning ? { routerAbNormalSigning } : {}),
    ...(typeof session.jwt === 'string' && session.jwt.trim() ? { jwt: session.jwt.trim() } : {}),
  };
}
