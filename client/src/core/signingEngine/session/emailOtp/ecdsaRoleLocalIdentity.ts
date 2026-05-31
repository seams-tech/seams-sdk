import {
  computeEcdsaHssRoleLocalRelayerKeyId,
  computeEcdsaHssRoleLocalThresholdKeyId,
} from '@shared/threshold/ecdsaHssRoleLocalBootstrap';
import { signingRootScopeFromRuntimePolicyScope } from '@shared/threshold/signingRootScope';
import type { ThresholdRuntimePolicyScope } from '@/core/signingEngine/threshold/sessionPolicy';
import { deriveEvmFamilyEcdsaKeyHandle } from '../identity/evmFamilyEcdsaIdentity';

export type EmailOtpEcdsaRoleLocalKeyIdentity = {
  ecdsaThresholdKeyId: string;
  signingRootId: string;
  signingRootVersion: string;
  relayerKeyId: string;
};

function nonEmptyString(value: unknown, field: string): string {
  const normalized = String(value ?? '').trim();
  if (!normalized) throw new Error(`${field} is required`);
  return normalized;
}

export async function resolveEmailOtpEcdsaRoleLocalKeyIdentityForHandle(args: {
  keyHandle?: string;
  walletId: string;
  rpId: string;
  runtimePolicyScope?: ThresholdRuntimePolicyScope;
}): Promise<EmailOtpEcdsaRoleLocalKeyIdentity | undefined> {
  const keyHandle = String(args.keyHandle || '').trim();
  if (!keyHandle) return undefined;
  if (!args.runtimePolicyScope) return undefined;
  return await resolveRequiredEmailOtpEcdsaRoleLocalKeyIdentity({
    keyHandle,
    walletId: args.walletId,
    rpId: args.rpId,
    runtimePolicyScope: args.runtimePolicyScope,
  });
}

export async function resolveRequiredEmailOtpEcdsaRoleLocalKeyIdentity(args: {
  keyHandle?: string;
  walletId: string;
  rpId: string;
  runtimePolicyScope: ThresholdRuntimePolicyScope;
}): Promise<EmailOtpEcdsaRoleLocalKeyIdentity> {
  const keyHandle = String(args.keyHandle || '').trim();
  const signingRootScope = signingRootScopeFromRuntimePolicyScope(args.runtimePolicyScope);
  const signingRootId = nonEmptyString(signingRootScope.signingRootId, 'signingRootId');
  const signingRootVersion = nonEmptyString(
    signingRootScope.signingRootVersion,
    'signingRootVersion',
  );
  const walletId = nonEmptyString(args.walletId, 'walletId');
  const rpId = nonEmptyString(args.rpId, 'rpId');
  const ecdsaThresholdKeyId = await computeEcdsaHssRoleLocalThresholdKeyId({
    walletId,
    rpId,
    signingRootId,
    signingRootVersion,
  });
  const expectedKeyHandle = await deriveEvmFamilyEcdsaKeyHandle({
    ecdsaThresholdKeyId,
    signingRootId,
    signingRootVersion,
  });
  if (keyHandle && String(expectedKeyHandle) !== keyHandle) {
    throw new Error('Email OTP ECDSA keyHandle does not match runtime policy key identity');
  }
  return {
    ecdsaThresholdKeyId,
    signingRootId,
    signingRootVersion,
    relayerKeyId: await computeEcdsaHssRoleLocalRelayerKeyId({
      walletId,
      rpId,
    }),
  };
}
