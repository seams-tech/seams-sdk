import {
  activateWalletRegistration,
  respondWalletRegistration,
} from './walletRegistration';

type RespondArgs = Parameters<typeof respondWalletRegistration>[0];
type ActivateArgs = Parameters<typeof activateWalletRegistration>[0];

declare const validRespondEcdsa: RespondArgs & { signerPlanKind: 'evm_family_ecdsa' };
declare const validRespondNear: RespondArgs & { signerPlanKind: 'near_ed25519' };
declare const validActivateEcdsa: ActivateArgs & { signerPlanKind: 'evm_family_ecdsa' };
declare const validActivateNear: ActivateArgs & { signerPlanKind: 'near_ed25519' };

const validRespond: RespondArgs = validRespondEcdsa;
const validNearRespond: RespondArgs = validRespondNear;
const validActivate: ActivateArgs = validActivateEcdsa;
const validNearActivate: ActivateArgs = validActivateNear;

// @ts-expect-error Ed25519-only respond requests cannot carry ECDSA proof bundles.
const mixedRespond: RespondArgs = {
  ...validRespond,
  signerPlanKind: 'near_ed25519',
};

// @ts-expect-error ECDSA respond requests must carry their proof bundle.
const missingRespondEcdsa: RespondArgs = {
  ...validNearRespond,
  signerPlanKind: 'evm_family_ecdsa',
};

// @ts-expect-error Ed25519-only activation requests cannot carry ECDSA activation facts.
const mixedActivate: ActivateArgs = {
  ...validActivate,
  signerPlanKind: 'near_ed25519',
};

// @ts-expect-error ECDSA activation requests must carry their activation facts.
const missingActivateEcdsa: ActivateArgs = {
  ...validNearActivate,
  signerPlanKind: 'evm_family_ecdsa',
};

void mixedRespond;
void missingRespondEcdsa;
void mixedActivate;
void missingActivateEcdsa;
