import type { ActivateStrictEcdsaPostRegistrationSessionInput } from './postRegistrationSessionActivation';

declare const validInput: ActivateStrictEcdsaPostRegistrationSessionInput;

validInput.routeAuth satisfies
  {
    readonly kind: 'opaque_wallet_session_operation_credential_v1';
    readonly token: string;
    readonly walletSessionId: string;
  };
