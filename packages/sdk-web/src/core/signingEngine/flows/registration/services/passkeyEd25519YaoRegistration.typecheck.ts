import type {
  PasskeyRegistrationAuthMethodInput,
  RegistrationIntentGrant,
  RegistrationIntentV1,
  WalletId,
} from '@shared/utils/registrationIntent';
import {
  prepareVerifiedPasskeyEd25519YaoRegistrationV1,
  registerVerifiedPasskeyEd25519YaoV1,
  type PasskeyRegistrationIntentV1,
  type VerifiedPasskeyEd25519YaoRegistrationInputV1,
} from './passkeyEd25519YaoRegistration';
import type { RouterAbEd25519YaoRegistrationAdmissionRequestV1 } from '@shared/utils/routerAbEd25519Yao';

declare const passkeyAuthMethod: PasskeyRegistrationAuthMethodInput;
declare const genericIntent: RegistrationIntentV1;
declare const passkeyIntent: PasskeyRegistrationIntentV1;
declare const walletId: WalletId;
declare const registrationIntentGrant: RegistrationIntentGrant;
declare const admissionRequest: RouterAbEd25519YaoRegistrationAdmissionRequestV1;
declare const fetchFn: typeof fetch;

const validInput: VerifiedPasskeyEd25519YaoRegistrationInputV1 = {
  kind: 'verified_passkey_ed25519_yao_registration_input_v1',
  verifiedIntent: {
    kind: 'verified_passkey_registration_intent_v1',
    intent: passkeyIntent,
    registrationIntentDigestB64u: 'digest',
    registrationIntentGrant,
    registrationCeremonyId: 'ceremony',
  },
  verifiedAuthority: {
    kind: 'verified_passkey_registration_authority_v1',
    walletId,
    registrationIntentDigestB64u: 'digest',
    credentialIdB64u: 'credential',
    ownedPasskeyPrfFirst: new Uint8Array(32),
  },
  admissionRequest,
  httpTransport: {
    kind: 'passkey_ed25519_yao_http_transport_v1',
    routerOrigin: 'http://router.local',
    fetch: fetchFn,
  },
};

prepareVerifiedPasskeyEd25519YaoRegistrationV1(validInput);
registerVerifiedPasskeyEd25519YaoV1(validInput);

// @ts-expect-error only passkey registration intents enter this orchestration boundary.
const invalidIntent: PasskeyRegistrationIntentV1 = genericIntent;
void invalidIntent;

// @ts-expect-error the exact server-authorized admission request is required.
const missingAdmission: VerifiedPasskeyEd25519YaoRegistrationInputV1 = {
  kind: 'verified_passkey_ed25519_yao_registration_input_v1',
  verifiedIntent: validInput.verifiedIntent,
  verifiedAuthority: validInput.verifiedAuthority,
  httpTransport: validInput.httpTransport,
};
void missingAdmission;
void passkeyAuthMethod;
