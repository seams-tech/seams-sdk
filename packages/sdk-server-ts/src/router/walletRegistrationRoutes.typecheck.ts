import { handleRouterApiWalletRegistrationPrepare } from './walletRegistrationRoutes';

type WalletRegistrationPrepareInput = Parameters<typeof handleRouterApiWalletRegistrationPrepare>[0];
type GenericWalletRegistrationInput = Omit<WalletRegistrationPrepareInput, 'services'> & {
  services: Omit<WalletRegistrationPrepareInput['services'], 'registrationPrepareAuthService'>;
};

declare const prepareInput: WalletRegistrationPrepareInput;
declare const genericInput: GenericWalletRegistrationInput;

void handleRouterApiWalletRegistrationPrepare(prepareInput);

// @ts-expect-error wallet_registration_prepare requires its structural route capability.
void handleRouterApiWalletRegistrationPrepare(genericInput);

export {};
