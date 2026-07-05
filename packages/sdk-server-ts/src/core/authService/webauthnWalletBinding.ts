import { toOptionalTrimmedString } from '@shared/utils/validation';
import { walletIdFromString } from '@shared/utils/registrationIntent';
import { parseRouterAbEd25519NormalSigningState } from '@shared/utils/signingSessionSeal';
import type {
  WebAuthnCredentialBindingRecord,
  WebAuthnCredentialBindingStore,
} from '../WebAuthnCredentialBindingStore';
import type { EmailRecoveryResolvedWalletBinding } from '../EmailRecoveryPreparationStore';
import type { Ed25519SessionPolicy, ThresholdRuntimePolicyScope } from '../types';
import { parseWebAuthnRpId } from '@shared/utils/domainIds';
import {
  buildPasskeyWalletAuthAuthority,
  isPasskeyWalletAuthAuthority,
  parseWalletAuthAuthority,
  walletAuthAuthoritiesMatch,
} from '@shared/utils/walletAuthAuthority';
import { normalizeThresholdRuntimePolicyScope } from './thresholdRuntimePolicy';

export async function resolveExistingThresholdEd25519Binding(args: {
  bindingStore: WebAuthnCredentialBindingStore;
  userId: string;
  rpId: string;
}): Promise<WebAuthnCredentialBindingRecord | undefined> {
  if (typeof args.bindingStore.listByUserId !== 'function') return undefined;
  const bindings = await args.bindingStore.listByUserId({
    userId: args.userId,
    rpId: args.rpId,
  });
  return bindings.find((binding) => {
    return Boolean(
      toOptionalTrimmedString(binding.relayerKeyId) &&
        toOptionalTrimmedString(binding.publicKey) &&
        toOptionalTrimmedString(binding.keyVersion) &&
        binding.recoveryExportCapable === true,
    );
  });
}

export function parseBoundaryWalletId(raw: unknown): string | null {
  const value = toOptionalTrimmedString(raw);
  if (!value) return null;
  try {
    return String(walletIdFromString(value));
  } catch {
    return null;
  }
}

export function resolvedEd25519WalletBindingFromCredentialBinding(args: {
  binding: WebAuthnCredentialBindingRecord;
  signerSlot?: number;
}): EmailRecoveryResolvedWalletBinding {
  return {
    walletId: args.binding.userId,
    nearAccountId: args.binding.nearAccountId,
    nearEd25519SigningKeyId: args.binding.nearEd25519SigningKeyId,
    rpId: args.binding.rpId,
    credentialIdB64u: args.binding.credentialIdB64u,
    signerSlot:
      Number.isSafeInteger(args.signerSlot) && Number(args.signerSlot) > 0
        ? Math.floor(Number(args.signerSlot))
        : args.binding.signerSlot,
  };
}

export function resolveThresholdEd25519SessionPolicyForBinding(args: {
  requestedSessionPolicy: Record<string, unknown>;
  binding: EmailRecoveryResolvedWalletBinding;
  relayerKeyId: string;
  persistedRuntimePolicyScope?: ThresholdRuntimePolicyScope;
}): { sessionPolicy: Ed25519SessionPolicy; runtimePolicyScope?: ThresholdRuntimePolicyScope } {
  if (Object.prototype.hasOwnProperty.call(args.requestedSessionPolicy, 'rpId')) {
    throw new Error('threshold-ed25519 session policy rpId belongs in authority');
  }
  if (Object.prototype.hasOwnProperty.call(args.requestedSessionPolicy, 'authorityScope')) {
    throw new Error('threshold-ed25519 session policy authorityScope is obsolete; use authority');
  }
  const requestedWalletId = toOptionalTrimmedString(args.requestedSessionPolicy.walletId);
  if (requestedWalletId && requestedWalletId !== args.binding.walletId) {
    throw new Error('threshold-ed25519 session policy walletId mismatch');
  }
  const requestedNearAccountId = toOptionalTrimmedString(
    args.requestedSessionPolicy.nearAccountId,
  );
  if (requestedNearAccountId && requestedNearAccountId !== args.binding.nearAccountId) {
    throw new Error('threshold-ed25519 session policy nearAccountId mismatch');
  }
  const requestedNearEd25519SigningKeyId = toOptionalTrimmedString(
    args.requestedSessionPolicy.nearEd25519SigningKeyId,
  );
  if (
    requestedNearEd25519SigningKeyId &&
    requestedNearEd25519SigningKeyId !== args.binding.nearEd25519SigningKeyId
  ) {
    throw new Error('threshold-ed25519 session policy nearEd25519SigningKeyId mismatch');
  }
  const runtimePolicyScope =
    normalizeThresholdRuntimePolicyScope(args.requestedSessionPolicy.runtimePolicyScope) ||
    args.persistedRuntimePolicyScope;
  const rpId = parseWebAuthnRpId(args.binding.rpId);
  if (!rpId.ok) {
    throw new Error('threshold-ed25519 session binding rpId is invalid');
  }
  const thresholdSessionId = toOptionalTrimmedString(args.requestedSessionPolicy.thresholdSessionId);
  const signingGrantId = toOptionalTrimmedString(args.requestedSessionPolicy.signingGrantId);
  const ttlMs = Number(args.requestedSessionPolicy.ttlMs);
  const remainingUses = Number(args.requestedSessionPolicy.remainingUses);
  const participantIds = Array.isArray(args.requestedSessionPolicy.participantIds)
    ? args.requestedSessionPolicy.participantIds
        .map((participantId) => Number(participantId))
        .filter((participantId) => Number.isSafeInteger(participantId) && participantId > 0)
    : undefined;
  const routerAbNormalSigning = parseRouterAbEd25519NormalSigningState(
    args.requestedSessionPolicy.routerAbNormalSigning,
  );
  const expectedAuthority = buildPasskeyWalletAuthAuthority({
    walletId: args.binding.walletId,
    rpId: rpId.value,
    credentialIdB64u: args.binding.credentialIdB64u,
  });
  const requestedAuthority = parseWalletAuthAuthority(args.requestedSessionPolicy.authority);
  if (!requestedAuthority) {
    throw new Error('threshold-ed25519 session policy authority is required');
  }
  if (!walletAuthAuthoritiesMatch(requestedAuthority, expectedAuthority)) {
    throw new Error('threshold-ed25519 session policy authority mismatch');
  }
  if (
    args.requestedSessionPolicy.version !== 'threshold_session_v1' ||
    !thresholdSessionId ||
    !signingGrantId ||
    !Number.isFinite(ttlMs) ||
    ttlMs <= 0 ||
    !Number.isFinite(remainingUses) ||
    remainingUses <= 0
  ) {
    throw new Error('threshold-ed25519 session policy is incomplete');
  }
  const sessionPolicy: Ed25519SessionPolicy = {
    version: 'threshold_session_v1',
    nearAccountId: args.binding.nearAccountId,
    nearEd25519SigningKeyId: args.binding.nearEd25519SigningKeyId,
    authority: expectedAuthority,
    relayerKeyId: args.relayerKeyId,
    thresholdSessionId,
    signingGrantId,
    ...(runtimePolicyScope ? { runtimePolicyScope } : {}),
    ...(routerAbNormalSigning ? { routerAbNormalSigning } : {}),
    ...(participantIds && participantIds.length > 0 ? { participantIds } : {}),
    ttlMs: Math.floor(ttlMs),
    remainingUses: Math.floor(remainingUses),
  };
  return {
    sessionPolicy,
    ...(runtimePolicyScope ? { runtimePolicyScope } : {}),
  };
}

export function resolveRecoveryThresholdEd25519SessionPolicyForBinding(args: {
  requestedSessionPolicy: Record<string, unknown>;
  binding: EmailRecoveryResolvedWalletBinding;
  relayerKeyId: string;
  persistedRuntimePolicyScope?: ThresholdRuntimePolicyScope;
}): { sessionPolicy: Ed25519SessionPolicy; runtimePolicyScope?: ThresholdRuntimePolicyScope } {
  if (Object.prototype.hasOwnProperty.call(args.requestedSessionPolicy, 'rpId')) {
    throw new Error('threshold-ed25519 session policy rpId belongs in authority');
  }
  if (Object.prototype.hasOwnProperty.call(args.requestedSessionPolicy, 'authorityScope')) {
    throw new Error('threshold-ed25519 session policy authorityScope is obsolete; use authority');
  }
  const requestedWalletId = toOptionalTrimmedString(args.requestedSessionPolicy.walletId);
  if (requestedWalletId && requestedWalletId !== args.binding.walletId) {
    throw new Error('threshold-ed25519 session policy walletId mismatch');
  }
  const requestedNearAccountId = toOptionalTrimmedString(
    args.requestedSessionPolicy.nearAccountId,
  );
  if (requestedNearAccountId && requestedNearAccountId !== args.binding.nearAccountId) {
    throw new Error('threshold-ed25519 session policy nearAccountId mismatch');
  }
  const requestedNearEd25519SigningKeyId = toOptionalTrimmedString(
    args.requestedSessionPolicy.nearEd25519SigningKeyId,
  );
  if (
    requestedNearEd25519SigningKeyId &&
    requestedNearEd25519SigningKeyId !== args.binding.nearEd25519SigningKeyId
  ) {
    throw new Error('threshold-ed25519 session policy nearEd25519SigningKeyId mismatch');
  }
  const requestedAuthority = parseWalletAuthAuthority(args.requestedSessionPolicy.authority);
  if (!requestedAuthority) {
    throw new Error('threshold-ed25519 session policy authority is required');
  }
  if (!isPasskeyWalletAuthAuthority(requestedAuthority)) {
    throw new Error('email recovery threshold session authority must be passkey');
  }
  if (requestedAuthority.walletId !== args.binding.walletId) {
    throw new Error('email recovery threshold session authority walletId mismatch');
  }
  if (requestedAuthority.verifier.rpId !== args.binding.rpId) {
    throw new Error('email recovery threshold session authority rpId mismatch');
  }
  const runtimePolicyScope =
    normalizeThresholdRuntimePolicyScope(args.requestedSessionPolicy.runtimePolicyScope) ||
    args.persistedRuntimePolicyScope;
  const thresholdSessionId = toOptionalTrimmedString(args.requestedSessionPolicy.thresholdSessionId);
  const signingGrantId = toOptionalTrimmedString(args.requestedSessionPolicy.signingGrantId);
  const ttlMs = Number(args.requestedSessionPolicy.ttlMs);
  const remainingUses = Number(args.requestedSessionPolicy.remainingUses);
  const participantIds = Array.isArray(args.requestedSessionPolicy.participantIds)
    ? args.requestedSessionPolicy.participantIds
        .map((participantId) => Number(participantId))
        .filter((participantId) => Number.isSafeInteger(participantId) && participantId > 0)
    : undefined;
  const routerAbNormalSigning = parseRouterAbEd25519NormalSigningState(
    args.requestedSessionPolicy.routerAbNormalSigning,
  );
  if (
    args.requestedSessionPolicy.version !== 'threshold_session_v1' ||
    !thresholdSessionId ||
    !signingGrantId ||
    !Number.isFinite(ttlMs) ||
    ttlMs <= 0 ||
    !Number.isFinite(remainingUses) ||
    remainingUses <= 0
  ) {
    throw new Error('threshold-ed25519 session policy is incomplete');
  }
  const sessionPolicy: Ed25519SessionPolicy = {
    version: 'threshold_session_v1',
    nearAccountId: args.binding.nearAccountId,
    nearEd25519SigningKeyId: args.binding.nearEd25519SigningKeyId,
    authority: requestedAuthority,
    relayerKeyId: args.relayerKeyId,
    thresholdSessionId,
    signingGrantId,
    ...(runtimePolicyScope ? { runtimePolicyScope } : {}),
    ...(routerAbNormalSigning ? { routerAbNormalSigning } : {}),
    ...(participantIds && participantIds.length > 0 ? { participantIds } : {}),
    ttlMs: Math.floor(ttlMs),
    remainingUses: Math.floor(remainingUses),
  };
  return {
    sessionPolicy,
    ...(runtimePolicyScope ? { runtimePolicyScope } : {}),
  };
}
