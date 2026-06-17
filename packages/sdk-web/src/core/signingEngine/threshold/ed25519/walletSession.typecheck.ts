import type { WebAuthnAuthenticationCredential } from '@/core/types/webauthn';
import type {
  ThresholdEd25519ProvidedPrfSecretSource,
  Ed25519WalletSessionMintAuthorization,
  ThresholdEd25519WebAuthnPrfSecretSource,
} from './walletSession';
import type { ProvisionWarmEd25519CapabilityArgs } from '../../session/warmCapabilities/types';

declare const credential: WebAuthnAuthenticationCredential;
declare const webauthnPrfSource: ThresholdEd25519WebAuthnPrfSecretSource;
declare const providedPrfSource: ThresholdEd25519ProvidedPrfSecretSource;

const validAppSessionJwtAuth = {
  kind: 'app_session_jwt',
  appSessionJwt: 'app-session-jwt',
  localSecretSource: webauthnPrfSource,
} satisfies Ed25519WalletSessionMintAuthorization;
void validAppSessionJwtAuth;

const validAppSessionCookieAuth = {
  kind: 'app_session_cookie',
  localSecretSource: webauthnPrfSource,
} satisfies Ed25519WalletSessionMintAuthorization;
void validAppSessionCookieAuth;

const validThresholdPolicyWebAuthnAuth = {
  kind: 'threshold_session_policy_webauthn',
  policySecretSource: webauthnPrfSource,
} satisfies Ed25519WalletSessionMintAuthorization;
void validThresholdPolicyWebAuthnAuth;

const validThresholdEcdsaSessionJwtAuth = {
  kind: 'threshold_ecdsa_session_jwt',
  thresholdEcdsaSessionJwt: 'threshold-ecdsa-session-jwt',
  localSecretSource: providedPrfSource,
} satisfies Ed25519WalletSessionMintAuthorization;
void validThresholdEcdsaSessionJwtAuth;

const invalidAppSessionJwtWithThresholdAssertion: Ed25519WalletSessionMintAuthorization = {
  kind: 'app_session_jwt',
  appSessionJwt: 'app-session-jwt',
  localSecretSource: webauthnPrfSource,
  // @ts-expect-error app-session JWT auth cannot carry a Wallet Session WebAuthn assertion.
  webauthnAuthentication: credential,
};
void invalidAppSessionJwtWithThresholdAssertion;

// @ts-expect-error app-session cookie auth cannot carry a JWT.
const invalidAppSessionCookieWithJwt: Ed25519WalletSessionMintAuthorization = {
  kind: 'app_session_cookie',
  localSecretSource: webauthnPrfSource,
  appSessionJwt: 'app-session-jwt',
};
void invalidAppSessionCookieWithJwt;

// @ts-expect-error Wallet Session policy WebAuthn auth cannot carry app-session PRF material.
const invalidThresholdPolicyWithLocalPrf: Ed25519WalletSessionMintAuthorization = {
  kind: 'threshold_session_policy_webauthn',
  policySecretSource: webauthnPrfSource,
  localSecretSource: webauthnPrfSource,
};
void invalidThresholdPolicyWithLocalPrf;

const invalidThresholdEcdsaSessionWithWebAuthn: Ed25519WalletSessionMintAuthorization = {
  kind: 'threshold_ecdsa_session_jwt',
  thresholdEcdsaSessionJwt: 'threshold-ecdsa-session-jwt',
  localSecretSource: providedPrfSource,
  // @ts-expect-error ECDSA Wallet Session auth must not carry a WebAuthn assertion.
  webauthnAuthentication: credential,
};
void invalidThresholdEcdsaSessionWithWebAuthn;

const invalidProvisionWithLooseAppSessionJwt = {
  kind: 'fresh_ed25519_provisioning',
  nearAccountId: 'alice.testnet',
  relayerKeyId: 'ed25519:relayer',
  participantIds: [1, 2],
  sessionKind: 'jwt',
  source: 'login',
  // @ts-expect-error Ed25519 provisioning requires discriminated auth instead of loose appSessionJwt.
  appSessionJwt: 'app-session-jwt',
} satisfies ProvisionWarmEd25519CapabilityArgs;
void invalidProvisionWithLooseAppSessionJwt;

const invalidProvisionWithLooseLocalPrf = {
  kind: 'fresh_ed25519_provisioning',
  nearAccountId: 'alice.testnet',
  relayerKeyId: 'ed25519:relayer',
  participantIds: [1, 2],
  sessionKind: 'jwt',
  source: 'login',
  // @ts-expect-error Ed25519 provisioning requires discriminated auth instead of loose localPrfCredential.
  localPrfCredential: credential,
} satisfies ProvisionWarmEd25519CapabilityArgs;
void invalidProvisionWithLooseLocalPrf;
