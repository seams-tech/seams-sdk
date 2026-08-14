import type { ActivateStrictEcdsaPostRegistrationSessionInput } from './postRegistrationSessionActivation';

declare const validInput: ActivateStrictEcdsaPostRegistrationSessionInput;

validInput.routeAuth satisfies
  { readonly kind: 'opaque_wallet_session'; readonly walletSessionToken: string };
