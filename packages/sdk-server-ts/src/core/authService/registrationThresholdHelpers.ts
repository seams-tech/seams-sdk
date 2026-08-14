import { ActionType, type ActionArgsWasm } from '@shared/near/actions';
import { ensureEd25519Prefix, toOptionalTrimmedString } from '@shared/utils/validation';
import type { RouterAbEcdsaDerivationPublicCapabilityV1 } from '@shared/utils/routerAbEcdsaDerivation';
import type {
  EcdsaDerivationClientBootstrapRequest,
  EcdsaDerivationServerBootstrapResponse,
  ThresholdRuntimePolicyScope,
} from '../types';
import type {
  WalletRegistrationEcdsaClientBootstrap,
  WalletRegistrationEcdsaPrepareContext,
  WalletRegistrationEcdsaPreparePayload,
  WalletRegistrationEcdsaWalletKey,
} from '../registrationContracts';
import type { WebAuthnCredentialBindingStore } from '../WebAuthnCredentialBindingStore';
import type { ThresholdEcdsaChainTarget } from '../thresholdEcdsaChainTarget';
import {
  normalizeThresholdRuntimePolicyScope,
  thresholdRuntimePolicyScopesEqual,
} from './thresholdRuntimePolicy';
import { parseEvmFamilySigningKeySlotId } from '@shared/signing-lanes';

function requireEvmFamilySigningKeySlotId(value: unknown) {
  const parsed = parseEvmFamilySigningKeySlotId(value);
  if (!parsed.ok) throw new Error(parsed.error.message);
  return parsed.value;
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
  bootstrap: EcdsaDerivationServerBootstrapResponse;
  chainTargets: readonly ThresholdEcdsaChainTarget[];
  publicCapability: RouterAbEcdsaDerivationPublicCapabilityV1;
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
    contextBinding32B64u: toOptionalTrimmedString(bootstrap.contextBinding32B64u),
    derivationClientSharePublicKey33B64u: toOptionalTrimmedString(
      bootstrap.publicIdentity.derivationClientSharePublicKey33B64u,
    ),
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
  if (
    participantIds.length !== 2 ||
    participantIds[0] !== 1 ||
    participantIds[1] !== 2
  ) {
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
      contextBinding32B64u: required.contextBinding32B64u,
      derivationClientSharePublicKey33B64u:
        bootstrap.publicIdentity.derivationClientSharePublicKey33B64u,
      clientShareRetryCounter: bootstrap.clientShareRetryCounter,
      relayerShareRetryCounter: bootstrap.relayerShareRetryCounter,
      participantIds: [1, 2],
      publicCapability: args.publicCapability,
    })),
  };
}

export function isMatchingEcdsaClientBootstrap(
  expected: WalletRegistrationEcdsaPrepareContext,
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
    actual.ttlMs === expected.ttlMs &&
    actual.remainingUses === expected.remainingUses &&
    JSON.stringify(actual.participantIds) === JSON.stringify(expected.participantIds) &&
    thresholdRuntimePolicyScopesEqual(actual.runtimePolicyScope, expected.runtimePolicyScope)
  );
}

export function toEcdsaDerivationClientBootstrapRequest(
  clientBootstrap: WalletRegistrationEcdsaClientBootstrap,
): EcdsaDerivationClientBootstrapRequest {
  return {
    formatVersion: clientBootstrap.formatVersion,
    walletId: clientBootstrap.walletId,
    evmFamilySigningKeySlotId: requireEvmFamilySigningKeySlotId(
      clientBootstrap.evmFamilySigningKeySlotId,
    ),
    ecdsaThresholdKeyId: clientBootstrap.ecdsaThresholdKeyId,
    signingRootId: clientBootstrap.signingRootId,
    signingRootVersion: clientBootstrap.signingRootVersion,
    keyScope: clientBootstrap.keyScope,
    relayerKeyId: clientBootstrap.relayerKeyId,
    registrationPreparationId: clientBootstrap.registrationPreparationId,
    derivationClientSharePublicKey33B64u: clientBootstrap.derivationClientSharePublicKey33B64u,
    clientShareRetryCounter: clientBootstrap.clientShareRetryCounter,
    contextBinding32B64u: clientBootstrap.contextBinding32B64u,
    requestId: clientBootstrap.requestId,
    sessionId: clientBootstrap.thresholdSessionId,
    ttlMs: clientBootstrap.ttlMs,
    remainingUses: clientBootstrap.remainingUses,
    participantIds: [...clientBootstrap.participantIds],
    runtimePolicyScope: clientBootstrap.runtimePolicyScope,
  };
}
