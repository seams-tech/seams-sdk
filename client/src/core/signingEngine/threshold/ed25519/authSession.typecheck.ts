import type { WebAuthnAuthenticationCredential } from '@/core/types/webauthn';
import type {
  ThresholdEd25519ProvidedPrfSecretSource,
  ThresholdEd25519SessionMintAuthorization,
  ThresholdEd25519WebAuthnPrfSecretSource,
} from './authSession';
import type { ProvisionWarmEd25519CapabilityArgs } from '../../session/warmCapabilities/types';

declare const credential: WebAuthnAuthenticationCredential;
declare const webauthnPrfSource: ThresholdEd25519WebAuthnPrfSecretSource;
declare const providedPrfSource: ThresholdEd25519ProvidedPrfSecretSource;

const validAppSessionJwtAuth = {
  kind: 'app_session_jwt',
  appSessionJwt: 'app-session-jwt',
  localSecretSource: webauthnPrfSource,
} satisfies ThresholdEd25519SessionMintAuthorization;
void validAppSessionJwtAuth;

const validAppSessionCookieAuth = {
  kind: 'app_session_cookie',
  localSecretSource: webauthnPrfSource,
} satisfies ThresholdEd25519SessionMintAuthorization;
void validAppSessionCookieAuth;

const validThresholdPolicyWebAuthnAuth = {
  kind: 'threshold_session_policy_webauthn',
  policySecretSource: webauthnPrfSource,
} satisfies ThresholdEd25519SessionMintAuthorization;
void validThresholdPolicyWebAuthnAuth;

const validThresholdEcdsaSessionJwtAuth = {
  kind: 'threshold_ecdsa_session_jwt',
  thresholdEcdsaSessionJwt: 'threshold-ecdsa-session-jwt',
  localSecretSource: providedPrfSource,
} satisfies ThresholdEd25519SessionMintAuthorization;
void validThresholdEcdsaSessionJwtAuth;

const invalidAppSessionJwtWithThresholdAssertion: ThresholdEd25519SessionMintAuthorization = {
  kind: 'app_session_jwt',
  appSessionJwt: 'app-session-jwt',
  localSecretSource: webauthnPrfSource,
  // @ts-expect-error app-session JWT auth cannot carry a threshold-session WebAuthn assertion.
  webauthnAuthentication: credential,
};
void invalidAppSessionJwtWithThresholdAssertion;

// @ts-expect-error app-session cookie auth cannot carry a JWT.
const invalidAppSessionCookieWithJwt: ThresholdEd25519SessionMintAuthorization = {
  kind: 'app_session_cookie',
  localSecretSource: webauthnPrfSource,
  appSessionJwt: 'app-session-jwt',
};
void invalidAppSessionCookieWithJwt;

// @ts-expect-error threshold session-policy WebAuthn auth cannot carry app-session PRF material.
const invalidThresholdPolicyWithLocalPrf: ThresholdEd25519SessionMintAuthorization = {
  kind: 'threshold_session_policy_webauthn',
  policySecretSource: webauthnPrfSource,
  localSecretSource: webauthnPrfSource,
};
void invalidThresholdPolicyWithLocalPrf;

const invalidThresholdEcdsaSessionWithWebAuthn: ThresholdEd25519SessionMintAuthorization = {
  kind: 'threshold_ecdsa_session_jwt',
  thresholdEcdsaSessionJwt: 'threshold-ecdsa-session-jwt',
  localSecretSource: providedPrfSource,
  // @ts-expect-error threshold ECDSA session auth must not carry a WebAuthn assertion.
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
