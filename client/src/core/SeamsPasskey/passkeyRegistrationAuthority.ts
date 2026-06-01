import type { RegistrationHooksOptions } from '../types/sdkSentEvents';
import type { WebAuthnRegistrationCredential } from '../types/webauthn';
import type { ConfirmationConfig } from '../types/signer-worker';
import type { PasskeyManagerContext } from './index';
import { normalizeRegistrationCredential } from '../signingEngine/webauthnAuth/credentials/helpers';
import {
  getPrfFirstB64uFromCredential,
  redactCredentialExtensionOutputs,
} from '../signingEngine/threshold/crypto/webauthn';

export type PasskeyRegistrationAuthorityMaterial = {
  kind: 'passkey';
  credential: WebAuthnRegistrationCredential;
  webauthnRegistration: WebAuthnRegistrationCredential;
  prfFirstB64u: string;
};

export function requirePasskeyPrfFirstB64u(credential: unknown): string {
  const prfFirstB64u = String(getPrfFirstB64uFromCredential(credential) || '').trim();
  if (!prfFirstB64u) {
    throw new Error('Missing PRF.first output from passkey credential');
  }
  return prfFirstB64u;
}

export async function collectPasskeyRegistrationAuthority(args: {
  context: PasskeyManagerContext;
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
  const prfFirstB64u = requirePasskeyPrfFirstB64u(credential);
  const webauthnRegistration = redactCredentialExtensionOutputs<WebAuthnRegistrationCredential>(
    normalizeRegistrationCredential(credential),
  );
  if (!Array.isArray(webauthnRegistration.response.transports)) {
    webauthnRegistration.response.transports = [];
  }
  return {
    kind: 'passkey',
    credential,
    webauthnRegistration,
    prfFirstB64u,
  };
}
