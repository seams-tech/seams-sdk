import type { WebAuthnAuthenticationCredential } from '../../types/webauthn';
import type { RouterAbEcdsaPostRegistrationSessionActivationRequestV1 } from '@shared/utils/routerAbEcdsaDerivation';
import { exchangeSession } from './rpcCalls';

declare const credential: WebAuthnAuthenticationCredential;
declare const activationRequest: RouterAbEcdsaPostRegistrationSessionActivationRequestV1;

const activatedExchange = exchangeSession(
  'https://relay.example',
  '/session/exchange',
  'jwt',
  {
    type: 'passkey_assertion',
    challengeId: 'challenge-1',
    webauthn_authentication: credential,
    ecdsaSessionActivation: activationRequest,
  },
  { kind: 'unscoped' },
);

void activatedExchange.then((result) => {
  if (result.success) {
    result.ecdsaSession.session.wallet_session_jwt satisfies string;
  }
});

void exchangeSession(
  'https://relay.example',
  '/session/exchange',
  'jwt',
  // @ts-expect-error OIDC exchange cannot activate an ECDSA Wallet Session.
  {
    type: 'oidc_jwt',
    token: 'oidc-token',
    ecdsaSessionActivation: activationRequest,
  },
  { kind: 'unscoped' },
);
