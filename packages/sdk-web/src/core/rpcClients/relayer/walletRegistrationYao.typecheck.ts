import {
  buildWalletRegistrationFinalizeBody,
  type FinalizeWalletRegistrationArgs,
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
