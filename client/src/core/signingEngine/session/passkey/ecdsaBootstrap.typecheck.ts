import type { AccountId } from '@/core/types/accountIds';
import type { WebAuthnAuthenticationCredential } from '@/core/types/webauthn';
import type { WalletSubjectId } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type { ThresholdEcdsaChainTarget } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type {
  EcdsaBootstrapRequest,
  ThresholdEcdsaSmartAccountBootstrapInput,
} from './ecdsaBootstrap';

declare const nearAccountId: AccountId;
declare const subjectId: WalletSubjectId;
declare const chainTarget: ThresholdEcdsaChainTarget;
declare const webauthnAuthentication: WebAuthnAuthenticationCredential;
declare const smartAccount: ThresholdEcdsaSmartAccountBootstrapInput;

const validReuseBootstrap = {
  kind: 'reuse_warm_ecdsa_bootstrap',
  nearAccountId,
  subjectId,
  chainTarget,
  source: 'manual-bootstrap',
  smartAccount,
} satisfies EcdsaBootstrapRequest;

const validPasskeyFreshBootstrap = {
  kind: 'passkey_fresh_ecdsa_bootstrap',
  nearAccountId,
  subjectId,
  chainTarget,
  source: 'registration',
  sessionKind: 'jwt',
  sessionIdentity: {
    thresholdSessionId: 'threshold-session-id',
    walletSigningSessionId: 'wallet-signing-session-id',
  },
  clientRootShare32B64u: 'client-root-share',
  routeAuth: {
    kind: 'registration_continuation',
    token: 'registration-token',
  },
} satisfies EcdsaBootstrapRequest;

const validPasskeyFreshWebAuthnBootstrap = {
  kind: 'passkey_fresh_ecdsa_bootstrap',
  nearAccountId,
  subjectId,
  chainTarget,
  source: 'login',
  sessionKind: 'jwt',
  sessionIdentity: {
    thresholdSessionId: 'threshold-session-id',
    walletSigningSessionId: 'wallet-signing-session-id',
  },
  clientRootShare32B64u: 'client-root-share',
  webauthnAuthentication,
} satisfies EcdsaBootstrapRequest;

const validPasskeyFreshCookieBootstrap = {
  kind: 'passkey_fresh_ecdsa_bootstrap',
  nearAccountId,
  subjectId,
  chainTarget,
  source: 'login',
  sessionKind: 'cookie',
  sessionIdentity: {
    thresholdSessionId: 'threshold-session-id',
    walletSigningSessionId: 'wallet-signing-session-id',
  },
  clientRootShare32B64u: 'client-root-share',
} satisfies EcdsaBootstrapRequest;

const validCookieReconnectBootstrap = {
  kind: 'passkey_cookie_reconnect_ecdsa_bootstrap',
  nearAccountId,
  subjectId,
  chainTarget,
  sessionKind: 'cookie',
  sessionIdentity: {
    thresholdSessionId: 'threshold-session-id',
    walletSigningSessionId: 'wallet-signing-session-id',
  },
} satisfies EcdsaBootstrapRequest;

const validThresholdSessionReconnectBootstrap = {
  kind: 'threshold_session_auth_reconnect_ecdsa_bootstrap',
  nearAccountId,
  subjectId,
  chainTarget,
  sessionKind: 'jwt',
  sessionIdentity: {
    thresholdSessionId: 'threshold-session-id',
    walletSigningSessionId: 'wallet-signing-session-id',
  },
  routeAuth: {
    kind: 'threshold_session',
    jwt: 'threshold-session-jwt',
  },
} satisfies EcdsaBootstrapRequest;

const validEmailOtpBootstrap = {
  kind: 'email_otp_ecdsa_bootstrap',
  nearAccountId,
  subjectId,
  chainTarget,
  source: 'email_otp',
  sessionKind: 'jwt',
  sessionIdentity: {
    thresholdSessionId: 'threshold-session-id',
    walletSigningSessionId: 'wallet-signing-session-id',
  },
  clientRootShare32B64u: 'client-root-share',
  emailOtpAuthContext: {
    policy: 'session',
    retention: 'session',
    reason: 'sign',
    authMethod: 'email_otp',
  },
} satisfies EcdsaBootstrapRequest;

void validReuseBootstrap;
void validPasskeyFreshBootstrap;
void validPasskeyFreshWebAuthnBootstrap;
void validPasskeyFreshCookieBootstrap;
void validCookieReconnectBootstrap;
void validThresholdSessionReconnectBootstrap;
void validEmailOtpBootstrap;

// @ts-expect-error passkey fresh bootstrap rejects threshold-session auth reconnect material
const invalidPasskeyFreshWithThresholdSessionAuth: EcdsaBootstrapRequest = {
  kind: 'passkey_fresh_ecdsa_bootstrap',
  nearAccountId,
  subjectId,
  chainTarget,
  sessionKind: 'jwt',
  sessionIdentity: {
    thresholdSessionId: 'threshold-session-id',
    walletSigningSessionId: 'wallet-signing-session-id',
  },
  clientRootShare32B64u: 'client-root-share',
  routeAuth: {
    kind: 'threshold_session',
    jwt: 'threshold-session-jwt',
  },
};

// @ts-expect-error jwt passkey fresh bootstrap requires route auth or WebAuthn auth
const invalidPasskeyFreshWithoutJwtAuth: EcdsaBootstrapRequest = {
  kind: 'passkey_fresh_ecdsa_bootstrap',
  nearAccountId,
  subjectId,
  chainTarget,
  sessionKind: 'jwt',
  sessionIdentity: {
    thresholdSessionId: 'threshold-session-id',
    walletSigningSessionId: 'wallet-signing-session-id',
  },
  clientRootShare32B64u: 'client-root-share',
};

const invalidPasskeyFreshWithMixedAuth: EcdsaBootstrapRequest = {
  kind: 'passkey_fresh_ecdsa_bootstrap',
  nearAccountId,
  subjectId,
  chainTarget,
  sessionKind: 'jwt',
  sessionIdentity: {
    thresholdSessionId: 'threshold-session-id',
    walletSigningSessionId: 'wallet-signing-session-id',
  },
  clientRootShare32B64u: 'client-root-share',
  routeAuth: {
    // @ts-expect-error passkey fresh bootstrap accepts one auth branch
    kind: 'registration_continuation',
    token: 'registration-token',
  },
  webauthnAuthentication,
};

const invalidCookieReconnectWithoutWalletSession: EcdsaBootstrapRequest = {
  kind: 'passkey_cookie_reconnect_ecdsa_bootstrap',
  nearAccountId,
  subjectId,
  chainTarget,
  sessionKind: 'cookie',
  // @ts-expect-error cookie reconnect bootstrap requires walletSigningSessionId
  sessionIdentity: {
    thresholdSessionId: 'threshold-session-id',
  },
};

// @ts-expect-error threshold-session reconnect rejects WebAuthn authentication
const invalidThresholdSessionReconnectWithWebauthn: EcdsaBootstrapRequest = {
  kind: 'threshold_session_auth_reconnect_ecdsa_bootstrap',
  nearAccountId,
  subjectId,
  chainTarget,
  sessionKind: 'jwt',
  sessionIdentity: {
    thresholdSessionId: 'threshold-session-id',
    walletSigningSessionId: 'wallet-signing-session-id',
  },
  routeAuth: {
    kind: 'threshold_session',
    jwt: 'threshold-session-jwt',
  },
  webauthnAuthentication,
};

// @ts-expect-error Email OTP bootstrap requires Email OTP auth context
const invalidEmailOtpBootstrapWithoutAuthContext: EcdsaBootstrapRequest = {
  kind: 'email_otp_ecdsa_bootstrap',
  nearAccountId,
  subjectId,
  chainTarget,
  sessionKind: 'jwt',
  sessionIdentity: {
    thresholdSessionId: 'threshold-session-id',
    walletSigningSessionId: 'wallet-signing-session-id',
  },
  clientRootShare32B64u: 'client-root-share',
};

// @ts-expect-error reuse bootstrap rejects client root share material
const invalidReuseBootstrapWithClientRootShare: EcdsaBootstrapRequest = {
  kind: 'reuse_warm_ecdsa_bootstrap',
  nearAccountId,
  subjectId,
  chainTarget,
  clientRootShare32B64u: 'client-root-share',
};
