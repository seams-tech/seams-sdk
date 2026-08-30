import { parseWalletSessionMintId } from '@shared/authorization/capabilityKinds';
import type { RouterAbEcdsaPostRegistrationSessionActivationPolicyV1 } from '@shared/utils/routerAbEcdsaDerivation';

type EmailOtpEcdsaUnlockMaterial =
  | {
      readonly kind: 'ecdsa';
      readonly ecdsaSessionPolicy?: RouterAbEcdsaPostRegistrationSessionActivationPolicyV1;
    }
  | {
      readonly kind: 'wallet_unlock_capabilities';
      readonly ecdsa: {
        readonly sessionPolicy: RouterAbEcdsaPostRegistrationSessionActivationPolicyV1;
      };
    };

export function bindEmailOtpEcdsaSessionPolicyToUnlockChallenge(
  material: EmailOtpEcdsaUnlockMaterial,
  unlockChallengeId: string,
): RouterAbEcdsaPostRegistrationSessionActivationPolicyV1 | null {
  const parsedMintId = parseWalletSessionMintId(unlockChallengeId);
  if (!parsedMintId.ok) {
    throw new Error('Email OTP unlock challenge is not a valid Wallet Session mint identity');
  }
  const policy =
    material.kind === 'ecdsa'
      ? (material.ecdsaSessionPolicy ?? null)
      : material.ecdsa.sessionPolicy;
  return policy
    ? {
        ...policy,
        session_policy: {
          ...policy.session_policy,
          wallet_session_mint_id: parsedMintId.value,
        },
      }
    : null;
}
