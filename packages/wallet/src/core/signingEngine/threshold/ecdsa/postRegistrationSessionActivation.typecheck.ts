import type {
  EcdsaCredentialFreeSessionActivationAuthorization,
  EcdsaPreauthorizedSessionActivation,
  ActivateStrictEcdsaPostRegistrationSessionInput,
} from './postRegistrationSessionActivation';
import type {
  RouterAbEcdsaCredentialFreeSessionActivationResponseV1,
  RouterAbEcdsaPostRegistrationSessionActivationResponseV1,
} from '@shared/utils/routerAbEcdsaDerivation';
import type { ExactWalletSessionAuthorization } from '../../session/persistence/walletSessionAuthorizationProjection';

declare const validInput: ActivateStrictEcdsaPostRegistrationSessionInput;

validInput.routeAuth satisfies
  {
    readonly kind: 'opaque_wallet_session_operation_credential_v1';
    readonly token: string;
    readonly walletSessionId: string;
  };

declare const credentialFreeActivation: RouterAbEcdsaCredentialFreeSessionActivationResponseV1;
declare const exactAuthorization: ExactWalletSessionAuthorization;
declare const directActivation: RouterAbEcdsaPostRegistrationSessionActivationResponseV1;

const validCredentialFreeActivationAuthorization: EcdsaCredentialFreeSessionActivationAuthorization = {
  kind: 'credential_free_ecdsa_session_activation_authorization_v1',
  activation: credentialFreeActivation,
  authorization: exactAuthorization,
};
void validCredentialFreeActivationAuthorization;

const validDirectActivation: EcdsaPreauthorizedSessionActivation = directActivation;
void validDirectActivation;

// @ts-expect-error Credential-free activation must carry the separately-owned exact authorization.
const invalidCredentialFreeActivation: EcdsaPreauthorizedSessionActivation = credentialFreeActivation;
void invalidCredentialFreeActivation;
