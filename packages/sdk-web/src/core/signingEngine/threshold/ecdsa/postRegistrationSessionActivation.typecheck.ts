import type { ActivateStrictEcdsaPostRegistrationSessionInput } from './postRegistrationSessionActivation';

declare const validInput: ActivateStrictEcdsaPostRegistrationSessionInput;

validInput.routeAuth satisfies { readonly kind: 'wallet_session'; readonly jwt: string };

const appSessionRouteAuth = {
  kind: 'app_session',
  jwt: 'app-session-jwt',
} as const;

const invalidInput: ActivateStrictEcdsaPostRegistrationSessionInput = {
  ...validInput,
  // @ts-expect-error additional target activation requires the Wallet Session minted by unlock
  routeAuth: appSessionRouteAuth,
};

void invalidInput;
