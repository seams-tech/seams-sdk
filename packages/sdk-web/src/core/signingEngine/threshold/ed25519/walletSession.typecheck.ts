import type { WebAuthnAuthenticationCredential } from '@/core/types/webauthn';
import type {
  Ed25519WalletSessionMintAuthorization,
  ThresholdEd25519WebAuthnPrfSecretSource,
} from './walletSession';
import type { ProvisionWarmEd25519CapabilityArgs } from '../../session/warmCapabilities/types';

declare const credential: WebAuthnAuthenticationCredential;
declare const webauthnPrfSource: ThresholdEd25519WebAuthnPrfSecretSource;

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

const validYaoBudgetRefreshAuth = {
  kind: 'router_ab_ed25519_yao_budget_refresh_v1',
  policySecretSource: webauthnPrfSource,
} satisfies Ed25519WalletSessionMintAuthorization;
void validYaoBudgetRefreshAuth;

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

const invalidYaoBudgetRefreshWithPriorSession: Ed25519WalletSessionMintAuthorization = {
  kind: 'router_ab_ed25519_yao_budget_refresh_v1',
  policySecretSource: webauthnPrfSource,
  // @ts-expect-error Yao budget refresh cannot reuse an expired Wallet Session as authorization.
  priorWalletSessionJwt: 'prior-wallet-session-jwt',
};
void invalidYaoBudgetRefreshWithPriorSession;

// @ts-expect-error Yao budget refresh cannot carry a second authorization bearer.
const invalidYaoBudgetRefreshWithAppSession: Ed25519WalletSessionMintAuthorization = {
  kind: 'router_ab_ed25519_yao_budget_refresh_v1',
  policySecretSource: webauthnPrfSource,
  appSessionJwt: 'app-session-jwt',
};
void invalidYaoBudgetRefreshWithAppSession;

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
