import type { WebAuthnAuthenticationCredential } from '../../types/webauthn';
import type { RouterAbEcdsaPostRegistrationSessionActivationPolicyV1 } from '@shared/utils/routerAbEcdsaDerivation';
import type {
  PasskeyWalletUnlockEd25519Session,
  PasskeyWalletUnlockInputWithEcdsaActivation,
} from './rpcCalls';
import { verifyPasskeyWalletUnlock } from './rpcCalls';

declare const credential: WebAuthnAuthenticationCredential;
declare const activationPolicy: RouterAbEcdsaPostRegistrationSessionActivationPolicyV1;
declare const ed25519Session: PasskeyWalletUnlockEd25519Session;

if (ed25519Session.sessionKind === 'issued_exact_wallet_session') {
  ed25519Session.operationCredential.token satisfies string;
} else {
  // @ts-expect-error Reused sessions are credential-free at this boundary.
  ed25519Session.operationCredential.token;
}

const activatedInput: PasskeyWalletUnlockInputWithEcdsaActivation = {
  type: 'passkey_assertion',
  challengeId: 'challenge-1',
  webauthn_authentication: credential,
  ed25519SessionRequest: { kind: 'not_requested' },
  ecdsaSessionPolicy: activationPolicy,
  walletId: 'wallet.testnet',
};

const activatedUnlock = verifyPasskeyWalletUnlock('https://relay.example', activatedInput);

void activatedUnlock.then((result) => {
  if (result.success) {
    result.ecdsaSession.session.operation_credential.token satisfies string;
  }
});
