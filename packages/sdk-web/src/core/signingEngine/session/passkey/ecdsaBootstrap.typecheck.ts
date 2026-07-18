import type { EmailOtpWorkerIssuedSessionHandle } from '@/core/platform';
import type { WebAuthnAuthenticationCredential } from '@/core/types/webauthn';
import type { WalletId } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type { ThresholdEcdsaChainTarget } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type { EcdsaBootstrapRequest } from './ecdsaBootstrap';
import { buildEcdsaSessionIdentity } from '../warmCapabilities/ecdsaProvisionPlan';
import { buildEmailOtpAuthContextForWalletAuthMethod } from '../identity/laneIdentity';
import type {
  EvmFamilyEcdsaKeyHandle,
  EvmFamilyEcdsaKeyIdentity,
  EvmFamilyEcdsaSessionLanePolicy,
} from '../identity/evmFamilyEcdsaIdentity';
import type { RouterAbEcdsaDerivationPublicCapabilityV1 } from '@shared/utils/routerAbEcdsaDerivation';

declare const walletId: WalletId;
declare const subjectId: WalletId;
declare const chainTarget: ThresholdEcdsaChainTarget;
declare const webauthnAuthentication: WebAuthnAuthenticationCredential;
declare const emailOtpWorkerSessionHandle: Extract<
  EmailOtpWorkerIssuedSessionHandle,
  { action: 'threshold_ecdsa_bootstrap' }
>;
declare const keyHandle: EvmFamilyEcdsaKeyHandle;
declare const key: EvmFamilyEcdsaKeyIdentity;
declare const lanePolicy: EvmFamilyEcdsaSessionLanePolicy;
declare const passkeyCredentialIdB64u: string;
declare const publicCapability: RouterAbEcdsaDerivationPublicCapabilityV1;

const sessionIdentity = buildEcdsaSessionIdentity({
  thresholdSessionId: 'threshold-session-id',
  signingGrantId: 'signing-grant-id',
});

const validReuseBootstrap = {
  kind: 'reuse_warm_ecdsa_bootstrap',
  walletId,
  chainTarget,
  source: 'manual-bootstrap',
} satisfies EcdsaBootstrapRequest;

const forbiddenProjectionField = ['smart', 'Account'].join('') as `${'smart'}${'Account'}`;
const invalidReuseBootstrapWithProjectionField = {
  kind: 'reuse_warm_ecdsa_bootstrap',
  walletId,
  chainTarget,
  // @ts-expect-error Base ECDSA bootstrap rejects projection fields.
  [forbiddenProjectionField]: { chainId: 1313 },
} satisfies EcdsaBootstrapRequest;
void invalidReuseBootstrapWithProjectionField;

const invalidReuseBootstrapWithSubjectId: EcdsaBootstrapRequest = {
  kind: 'reuse_warm_ecdsa_bootstrap',
  walletId,
  chainTarget,
  // @ts-expect-error base ECDSA warm bootstrap derives subject from walletId.
  subjectId,
};
void invalidReuseBootstrapWithSubjectId;

const validPasskeyFreshBootstrap = {
  kind: 'passkey_fresh_ecdsa_bootstrap',
  walletId,
  chainTarget,
  source: 'registration',
  sessionKind: 'jwt',
  sessionIdentity,
  passkeyPrfFirstB64u: 'passkey-prf-first',
  passkeyCredentialIdB64u,
  routeAuth: {
    kind: 'wallet_session',
    jwt: 'threshold-session-jwt',
  },
} satisfies EcdsaBootstrapRequest;

const validPasskeyFreshWebAuthnBootstrap = {
  kind: 'passkey_fresh_ecdsa_bootstrap',
  walletId,
  chainTarget,
  source: 'login',
  sessionKind: 'jwt',
  sessionIdentity,
  passkeyPrfFirstB64u: 'passkey-prf-first',
  webauthnAuthentication,
} satisfies EcdsaBootstrapRequest;

const invalidPasskeyFreshCookieBootstrap = {
  kind: 'passkey_fresh_ecdsa_bootstrap',
  walletId,
  chainTarget,
  source: 'login',
  // @ts-expect-error passkey fresh ECDSA bootstrap must mint JWT Wallet Sessions.
  sessionKind: 'cookie',
  sessionIdentity,
  passkeyPrfFirstB64u: 'passkey-prf-first',
  passkeyCredentialIdB64u,
} satisfies EcdsaBootstrapRequest;

const invalidPasskeyFreshRegistrationWithExactSessionField: EcdsaBootstrapRequest = {
  kind: 'passkey_fresh_ecdsa_bootstrap',
  walletId,
  chainTarget,
  source: 'registration',
  sessionKind: 'jwt',
  sessionIdentity,
  passkeyPrfFirstB64u: 'passkey-prf-first',
  passkeyCredentialIdB64u,
  routeAuth: {
    kind: 'wallet_session',
    jwt: 'threshold-session-jwt',
  },
  // @ts-expect-error target enrollment rejects exact-session key handles.
  keyHandle,
};
void invalidPasskeyFreshRegistrationWithExactSessionField;

const validWalletSessionReconnectBootstrap = {
  kind: 'wallet_session_reconnect_ecdsa_bootstrap',
  keyHandle,
  key,
  lanePolicy,
  publicCapability,
  passkeyPrfFirstB64u: 'passkey-prf-first',
  passkeyCredentialIdB64u,
  routeAuth: {
    kind: 'wallet_session',
    jwt: 'threshold-session-jwt',
  },
} satisfies EcdsaBootstrapRequest;

const invalidCookieWalletSessionReconnectBootstrap: EcdsaBootstrapRequest = {
  kind: 'wallet_session_reconnect_ecdsa_bootstrap',
  keyHandle,
  key,
  lanePolicy,
  publicCapability,
  passkeyPrfFirstB64u: 'passkey-prf-first',
  passkeyCredentialIdB64u,
  routeAuth: {
    // @ts-expect-error Wallet Session reconnect requires bearer route auth.
    kind: 'cookie',
  },
};
void invalidCookieWalletSessionReconnectBootstrap;

// @ts-expect-error Wallet Session reconnect requires the primed ECDSA passkey PRF.first
const invalidWalletSessionReconnectWithoutPasskeyPrfFirst: EcdsaBootstrapRequest = {
  kind: 'wallet_session_reconnect_ecdsa_bootstrap',
  keyHandle,
  key,
  lanePolicy,
  publicCapability,
  routeAuth: {
    kind: 'wallet_session',
    jwt: 'threshold-session-jwt',
  },
};

const validEmailOtpBootstrap = {
  kind: 'email_otp_ecdsa_bootstrap',
  walletId,
  chainTarget,
  source: 'email_otp',
  sessionKind: 'jwt',
  sessionIdentity,
  emailOtpWorkerSessionHandle,
  emailOtpAuthContext: buildEmailOtpAuthContextForWalletAuthMethod({
walletId: 'wallet.testnet',
emailHashHex: 'email-hash',
policy: 'session',
    retention: 'session',
    reason: 'sign',
    provider: 'google',
    providerUserId: 'google-subject-1',
  }),
} satisfies EcdsaBootstrapRequest;

void validReuseBootstrap;
void validPasskeyFreshBootstrap;
void validPasskeyFreshWebAuthnBootstrap;
void invalidPasskeyFreshCookieBootstrap;
void validWalletSessionReconnectBootstrap;
void validEmailOtpBootstrap;

const validPasskeyFreshWithWalletSessionAuth: EcdsaBootstrapRequest = {
  kind: 'passkey_fresh_ecdsa_bootstrap',
  walletId,
  chainTarget,
  sessionKind: 'jwt',
  sessionIdentity,
  passkeyPrfFirstB64u: 'passkey-prf-first',
  passkeyCredentialIdB64u,
  routeAuth: {
    kind: 'wallet_session',
    jwt: 'threshold-session-jwt',
  },
};
void validPasskeyFreshWithWalletSessionAuth;

// @ts-expect-error jwt passkey fresh bootstrap requires route auth or WebAuthn auth
const invalidPasskeyFreshWithoutJwtAuth: EcdsaBootstrapRequest = {
  kind: 'passkey_fresh_ecdsa_bootstrap',
  walletId,
  chainTarget,
  sessionKind: 'jwt',
  sessionIdentity,
  passkeyPrfFirstB64u: 'passkey-prf-first',
  passkeyCredentialIdB64u,
};

const validPasskeyFreshWithRouteAndWebauthn: EcdsaBootstrapRequest = {
  kind: 'passkey_fresh_ecdsa_bootstrap',
  walletId,
  chainTarget,
  sessionKind: 'jwt',
  sessionIdentity,
  passkeyPrfFirstB64u: 'passkey-prf-first',
  routeAuth: {
    kind: 'app_session',
    jwt: 'app-session-jwt',
  },
  webauthnAuthentication,
};
void validPasskeyFreshWithRouteAndWebauthn;

const validPasskeyFreshWithWebauthnCredentialOnly: EcdsaBootstrapRequest = {
  kind: 'passkey_fresh_ecdsa_bootstrap',
  walletId,
  chainTarget,
  sessionKind: 'jwt',
  sessionIdentity,
  routeAuth: {
    kind: 'app_session',
    jwt: 'app-session-jwt',
  },
  webauthnAuthentication,
};
void validPasskeyFreshWithWebauthnCredentialOnly;

// @ts-expect-error Wallet Session reconnect rejects WebAuthn authentication
const invalidWalletSessionReconnectWithWebauthn: EcdsaBootstrapRequest = {
  kind: 'wallet_session_reconnect_ecdsa_bootstrap',
  keyHandle,
  key,
  lanePolicy,
  publicCapability,
  passkeyPrfFirstB64u: 'passkey-prf-first',
  routeAuth: {
    kind: 'wallet_session',
    jwt: 'threshold-session-jwt',
  },
  webauthnAuthentication,
};

// @ts-expect-error exact reconnect requires its persisted public capability
const invalidWalletSessionReconnectWithoutPublicCapability: EcdsaBootstrapRequest = {
  kind: 'wallet_session_reconnect_ecdsa_bootstrap',
  keyHandle,
  key,
  lanePolicy,
  passkeyPrfFirstB64u: 'passkey-prf-first',
  passkeyCredentialIdB64u,
  routeAuth: {
    kind: 'wallet_session',
    jwt: 'threshold-session-jwt',
  },
};
void invalidWalletSessionReconnectWithoutPublicCapability;

// @ts-expect-error Email OTP bootstrap requires Email OTP auth context
const invalidEmailOtpBootstrapWithoutAuthContext: EcdsaBootstrapRequest = {
  kind: 'email_otp_ecdsa_bootstrap',
  walletId,
  chainTarget,
  sessionKind: 'jwt',
  sessionIdentity,
  emailOtpWorkerSessionHandle,
};

const invalidPasskeyFreshBootstrapWithSubjectId: EcdsaBootstrapRequest = {
  kind: 'passkey_fresh_ecdsa_bootstrap',
  walletId,
  // @ts-expect-error target-branch passkey bootstrap derives subject from walletId.
  subjectId,
  chainTarget,
  source: 'registration',
  sessionKind: 'jwt',
  sessionIdentity,
  passkeyPrfFirstB64u: 'passkey-prf-first',
  passkeyCredentialIdB64u,
  routeAuth: {
    kind: 'wallet_session',
    jwt: 'threshold-session-jwt',
  },
};
void invalidPasskeyFreshBootstrapWithSubjectId;

const invalidEmailOtpBootstrapWithSubjectId: EcdsaBootstrapRequest = {
  kind: 'email_otp_ecdsa_bootstrap',
  walletId,
  // @ts-expect-error target-branch Email OTP bootstrap derives subject from walletId.
  subjectId,
  chainTarget,
  source: 'email_otp',
  sessionKind: 'jwt',
  sessionIdentity,
  emailOtpWorkerSessionHandle,
  emailOtpAuthContext: buildEmailOtpAuthContextForWalletAuthMethod({
walletId: 'wallet.testnet',
emailHashHex: 'email-hash',
policy: 'session',
    retention: 'session',
    reason: 'sign',
    provider: 'google',
    providerUserId: 'google-subject-1',
  }),
};
void invalidEmailOtpBootstrapWithSubjectId;

// @ts-expect-error reuse bootstrap rejects passkey PRF.first material
const invalidReuseBootstrapWithPasskeyPrfFirst: EcdsaBootstrapRequest = {
  kind: 'reuse_warm_ecdsa_bootstrap',
  walletId,
  chainTarget,
  passkeyPrfFirstB64u: 'passkey-prf-first',
};
