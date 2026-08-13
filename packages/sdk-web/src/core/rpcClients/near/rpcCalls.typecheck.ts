import type { WebAuthnAuthenticationCredential } from '../../types/webauthn';
import type { RouterAbEcdsaPostRegistrationSessionActivationPolicyV1 } from '@shared/utils/routerAbEcdsaDerivation';
import type { PasskeySessionExchangeInputWithEcdsaActivation } from './rpcCalls';
import { exchangeSession } from './rpcCalls';

declare const credential: WebAuthnAuthenticationCredential;
declare const activationPolicy: RouterAbEcdsaPostRegistrationSessionActivationPolicyV1;

const activatedInput: PasskeySessionExchangeInputWithEcdsaActivation = {
  type: 'passkey_assertion',
  challengeId: 'challenge-1',
  webauthn_authentication: credential,
  ecdsaSessionPolicy: activationPolicy,
  walletId: 'wallet.testnet',
};

const activatedExchange = exchangeSession(
  'https://relay.example',
  '/session/exchange',
  'jwt',
  activatedInput,
  { kind: 'unscoped' },
);

void activatedExchange.then((result) => {
  if (result.success) {
    result.ecdsaSession.session.wallet_session_jwt satisfies string;
  }
});
