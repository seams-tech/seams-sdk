import type { ThresholdEd25519VerifiedWalletAuth } from '../core/types';
import type {
  AppSessionClaims,
  RouterAbEcdsaHssWalletSessionClaims,
} from '../core/ThresholdService/validation';

export function buildThresholdEd25519VerifiedWalletAuth(input: {
  appSessionClaims: AppSessionClaims | null;
  ecdsaSessionClaims: RouterAbEcdsaHssWalletSessionClaims | null;
}): ThresholdEd25519VerifiedWalletAuth | undefined {
  if (input.appSessionClaims) {
    return {
      kind: 'app_session',
      claims: input.appSessionClaims,
      sessionWalletId: input.appSessionClaims.walletId || input.appSessionClaims.sub,
    };
  }
  if (input.ecdsaSessionClaims) {
    return {
      kind: 'threshold_ecdsa_session',
      claims: input.ecdsaSessionClaims,
    };
  }
  return undefined;
}
