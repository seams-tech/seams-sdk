import type { ThresholdEcdsaChainTarget } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import { claimWarmSessionPrfFirst, type PasskeyWarmSessionRecoveryPorts } from './prfClaim';

type PasskeySessionRestoreIdentity = {
  touchConfirm: PasskeyWarmSessionRecoveryPorts;
  walletId: string;
  walletSigningSessionId: string;
  thresholdSessionId: string;
};

export type PasskeyEcdsaPrfClaimArgs = PasskeySessionRestoreIdentity & {
  chainTarget: ThresholdEcdsaChainTarget;
  errorContext: string;
  uses?: number;
  consume?: boolean;
};

export async function restorePasskeyEcdsaSessionBeforeClaim(
  args: PasskeySessionRestoreIdentity & { chainTarget: ThresholdEcdsaChainTarget },
): Promise<void> {
  if (typeof args.touchConfirm.restorePersistedSessionForSigning !== 'function') return;
  await args.touchConfirm.restorePersistedSessionForSigning({
    walletId: String(args.walletId).trim(),
    authMethod: 'passkey',
    curve: 'ecdsa',
    chainTarget: args.chainTarget,
    walletSigningSessionId: String(args.walletSigningSessionId).trim(),
    thresholdSessionId: String(args.thresholdSessionId).trim(),
    reason: 'transaction',
  });
}

export async function claimPasskeyEcdsaPrfFirst(args: PasskeyEcdsaPrfClaimArgs): Promise<string> {
  return await claimWarmSessionPrfFirst({
    touchConfirm: args.touchConfirm,
    thresholdSessionId: args.thresholdSessionId,
    errorContext: args.errorContext,
    uses: args.uses,
    ...(typeof args.consume === 'boolean' ? { consume: args.consume } : {}),
    curve: 'ecdsa',
    chainTarget: args.chainTarget,
    restoreBeforeClaim: () =>
      restorePasskeyEcdsaSessionBeforeClaim({
        touchConfirm: args.touchConfirm,
        walletId: args.walletId,
        walletSigningSessionId: args.walletSigningSessionId,
        thresholdSessionId: args.thresholdSessionId,
        chainTarget: args.chainTarget,
      }),
  });
}
