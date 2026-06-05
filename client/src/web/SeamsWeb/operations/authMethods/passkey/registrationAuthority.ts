import type { RegistrationHooksOptions } from '@/core/types/sdkSentEvents';
import type { WebAuthnRegistrationCredential } from '@/core/types/webauthn';
import type { ConfirmationConfig } from '@/core/types/signer-worker';
import type { WebAuthnRegistrationConfirmationSurface } from '@/web/SeamsWeb/signingSurface/types';
import {
  redactedPasskeyRegistrationCredential,
  requirePasskeyPrfFirstB64u,
} from '@/web/SeamsWeb/operations/authMethods/passkey/ecdsaBootstrap';

export type PasskeyRegistrationAuthorityMaterial = {
  kind: 'passkey';
  credential: WebAuthnRegistrationCredential;
  webauthnRegistration: WebAuthnRegistrationCredential;
  prfFirstB64u: string;
};

export async function collectPasskeyRegistrationAuthority(args: {
  context: { signingEngine: WebAuthnRegistrationConfirmationSurface };
  walletId: string;
  signerSlot: number;
  registrationIntentDigestB64u: string;
  options: RegistrationHooksOptions;
  confirmationConfigOverride: Partial<ConfirmationConfig>;
}): Promise<PasskeyRegistrationAuthorityMaterial> {
  const registrationSession =
    await args.context.signingEngine.requestRegistrationCredentialConfirmation({
      nearAccountId: args.walletId,
      signerSlot: args.signerSlot,
      confirmerText: args.options.confirmerText,
      confirmationConfigOverride: args.confirmationConfigOverride,
      challengeB64u: args.registrationIntentDigestB64u,
  });
  const credential = registrationSession.credential;
  const prfFirstB64u = requirePasskeyPrfFirstB64u(
    credential,
    'Passkey registration authority',
  );
  const webauthnRegistration = redactedPasskeyRegistrationCredential(credential);
  return {
    kind: 'passkey',
    credential,
    webauthnRegistration,
    prfFirstB64u,
  };
}
