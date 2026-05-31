import type { WebAuthnAuthenticationCredential } from '@/core/types/webauthn';
import type {
  ThresholdIndexedDbPort,
  ThresholdWebAuthnPromptPort,
} from '../crypto/webauthn';
import type { ThresholdEcdsaClientRootShareRequest } from './clientSecretSource';

declare const credential: WebAuthnAuthenticationCredential;
declare const indexedDB: ThresholdIndexedDbPort;
declare const touchIdPrompt: ThresholdWebAuthnPromptPort;

const webauthnRequest = {
  kind: 'provided_webauthn_prf_credential',
  credential,
  rpId: 'localhost',
} satisfies ThresholdEcdsaClientRootShareRequest;
void webauthnRequest;

const collectRequest = {
  kind: 'collect_webauthn_prf_credential',
  indexedDB,
  touchIdPrompt,
  walletId: 'wallet.testnet',
  challengeB64u: 'challenge',
  rpId: 'localhost',
} satisfies ThresholdEcdsaClientRootShareRequest;
void collectRequest;

const optionalBagRequest = {
  indexedDB,
  touchIdPrompt,
  walletId: 'wallet.testnet',
  challengeB64u: 'challenge',
};
// @ts-expect-error client-root share resolution uses exact branch-specific requests.
optionalBagRequest satisfies ThresholdEcdsaClientRootShareRequest;

const mixedRawAndCredentialRequest = {
  kind: 'provided_webauthn_prf_credential',
  credential,
  rpId: 'localhost',
  clientRootShare32B64u: 'raw-share',
};
// @ts-expect-error WebAuthn credential requests cannot also pass raw root-share material.
mixedRawAndCredentialRequest satisfies ThresholdEcdsaClientRootShareRequest;
