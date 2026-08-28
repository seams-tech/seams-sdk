import type { WebAuthnAllowCredential } from '@/core/signingEngine/webauthnAuth/credentials/collectAuthenticationCredentialForChallengeB64u';
import type { WalletAuthMethodRecordV2 } from '@shared/utils/registrationIntent';

type ActivePasskeyWalletAuthMethod = Extract<
  WalletAuthMethodRecordV2,
  { readonly kind: 'passkey'; readonly status: 'active' }
>;

export function addAuthMethodSourcePasskeyAllowCredentials(
  sourceAuthMethod: ActivePasskeyWalletAuthMethod,
): [WebAuthnAllowCredential] {
  return [
    {
      id: sourceAuthMethod.credentialIdB64u,
      type: 'public-key',
      transports: [],
    },
  ];
}
