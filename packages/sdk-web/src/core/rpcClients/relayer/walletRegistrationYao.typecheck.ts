import {
  buildWalletRegistrationFinalizeBody,
  isEmailOtpWalletRegistrationFinalizeResponse,
  type FinalizeWalletRegistrationArgs,
  type WalletRegistrationFinalizeResponse,
  type WalletRegistrationFinalizeResponseAuthority,
} from './walletRegistration';

declare const activationReference: Extract<
  FinalizeWalletRegistrationArgs,
  { kind: 'near_ed25519' }
>['ed25519']['activationReference'];

void buildWalletRegistrationFinalizeBody({
  relayerUrl: 'http://127.0.0.1:8787',
  registrationCeremonyId: 'registration-1',
  kind: 'near_ed25519',
  ed25519: { activationReference },
});

// @ts-expect-error Ed25519 finalize requires its discriminant.
const missingKind: FinalizeWalletRegistrationArgs = {
  relayerUrl: 'http://127.0.0.1:8787',
  registrationCeremonyId: 'registration-1',
  ed25519: { activationReference },
};
void missingKind;

// @ts-expect-error Ed25519-only finalize cannot carry ECDSA work.
const extraEcdsa: FinalizeWalletRegistrationArgs = {
  relayerUrl: 'http://127.0.0.1:8787',
  registrationCeremonyId: 'registration-1',
  kind: 'near_ed25519',
  ed25519: { activationReference },
  ecdsa: {},
};
void extraEcdsa;

const callerSuppliedReceipt: FinalizeWalletRegistrationArgs = {
  relayerUrl: 'http://127.0.0.1:8787',
  registrationCeremonyId: 'registration-1',
  kind: 'near_ed25519',
  ed25519: {
    activationReference,
    // @ts-expect-error The browser cannot submit Yao public output during finalize.
    publicReceipt: { registeredPublicKey: 'substituted' },
  },
};
void callerSuppliedReceipt;

// @ts-expect-error Email OTP finalize responses require the server-issued final-wallet session.
const missingEmailOtpAppSession: WalletRegistrationFinalizeResponseAuthority = {
  authMethod: {
    kind: 'email_otp',
    registrationAuthorityId: 'registration-authority-1',
  },
};
void missingEmailOtpAppSession;

// @ts-expect-error Passkey finalize responses cannot carry an Email OTP app session.
const passkeyWithEmailOtpSession: WalletRegistrationFinalizeResponseAuthority = {
  rpId: 'example.test',
  authMethod: {
    kind: 'passkey',
    credentialIdB64u: 'credential-1',
    credentialPublicKeyB64u: 'public-key-1',
  },
  appSessionJwt: 'app-session-1',
};
void passkeyWithEmailOtpSession;

export function requireFinalizedEmailOtpAppSession(
  response: WalletRegistrationFinalizeResponse,
): string | null {
  if (!isEmailOtpWalletRegistrationFinalizeResponse(response)) return null;
  return response.appSessionJwt;
}
