import type { AccountId } from '@/core/types/accountIds';
import type { WebAuthnAuthenticationCredential } from '@/core/types/webauthn';
import type { WalletSubjectId } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type { ThresholdEcdsaChainTarget } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type {
  EcdsaBootstrapRequest,
  PasskeyCookieReconnectEcdsaBootstrapRequest,
} from './ecdsaBootstrap';
import { buildEcdsaSessionIdentity } from '../warmCapabilities/ecdsaProvisionPlan';
import type {
  EvmFamilyEcdsaKeyHandle,
  EvmFamilyEcdsaKeyIdentity,
  EvmFamilyEcdsaSessionLanePolicy,
} from '../identity/evmFamilyEcdsaIdentity';

declare const walletId: AccountId;
declare const subjectId: WalletSubjectId;
declare const chainTarget: ThresholdEcdsaChainTarget;
declare const webauthnAuthentication: WebAuthnAuthenticationCredential;
declare const keyHandle: EvmFamilyEcdsaKeyHandle;
declare const key: EvmFamilyEcdsaKeyIdentity;
declare const lanePolicy: EvmFamilyEcdsaSessionLanePolicy;

const sessionIdentity = buildEcdsaSessionIdentity({
  thresholdSessionId: 'threshold-session-id',
  walletSigningSessionId: 'wallet-signing-session-id',
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
  clientRootShare32B64u: 'client-root-share',
  routeAuth: {
    kind: 'bootstrap_grant',
    token: 'bootstrap-grant-token',
  },
} satisfies EcdsaBootstrapRequest;

const validPasskeyFreshWebAuthnBootstrap = {
  kind: 'passkey_fresh_ecdsa_bootstrap',
  walletId,
  chainTarget,
  source: 'login',
  sessionKind: 'jwt',
  sessionIdentity,
  clientRootShare32B64u: 'client-root-share',
  webauthnAuthentication,
} satisfies EcdsaBootstrapRequest;

const validPasskeyFreshCookieBootstrap = {
  kind: 'passkey_fresh_ecdsa_bootstrap',
  walletId,
  chainTarget,
  source: 'login',
  sessionKind: 'cookie',
  sessionIdentity,
  clientRootShare32B64u: 'client-root-share',
} satisfies EcdsaBootstrapRequest;

const invalidPasskeyFreshRegistrationWithExactSessionField: EcdsaBootstrapRequest = {
  kind: 'passkey_fresh_ecdsa_bootstrap',
  walletId,
  chainTarget,
  source: 'registration',
  sessionKind: 'jwt',
  sessionIdentity,
  clientRootShare32B64u: 'client-root-share',
  routeAuth: {
    kind: 'bootstrap_grant',
    token: 'bootstrap-grant-token',
  },
  // @ts-expect-error target enrollment rejects exact-session key handles.
  keyHandle,
};
void invalidPasskeyFreshRegistrationWithExactSessionField;

const validCookieReconnectBootstrap = {
  kind: 'passkey_cookie_reconnect_ecdsa_bootstrap',
  keyHandle,
  key,
  lanePolicy,
} satisfies EcdsaBootstrapRequest;

const invalidCookieReconnectBootstrapWithKeyIntent: PasskeyCookieReconnectEcdsaBootstrapRequest = {
  kind: 'passkey_cookie_reconnect_ecdsa_bootstrap',
  keyHandle,
  key,
  lanePolicy,
  // @ts-expect-error exact activation rejects registration key intents.
  keyIntent: {
    kind: 'existing_ecdsa_key',
    ecdsaThresholdKeyId: 'ecdsa-key-1',
    participantIds: [1, 2],
  },
};
void invalidCookieReconnectBootstrapWithKeyIntent;

const validThresholdSessionReconnectBootstrap = {
  kind: 'threshold_session_auth_reconnect_ecdsa_bootstrap',
  keyHandle,
  key,
  lanePolicy,
  clientRootShare32B64u: 'client-root-share',
  routeAuth: {
    kind: 'threshold_session',
    jwt: 'threshold-session-jwt',
  },
} satisfies EcdsaBootstrapRequest;

const validCookieThresholdSessionReconnectBootstrap = {
  kind: 'threshold_session_auth_reconnect_ecdsa_bootstrap',
  keyHandle,
  key,
  lanePolicy,
  clientRootShare32B64u: 'client-root-share',
  routeAuth: {
    kind: 'cookie',
  },
} satisfies EcdsaBootstrapRequest;

// @ts-expect-error threshold-session reconnect requires the primed ECDSA client root share
const invalidThresholdSessionReconnectWithoutClientRootShare: EcdsaBootstrapRequest = {
  kind: 'threshold_session_auth_reconnect_ecdsa_bootstrap',
  keyHandle,
  key,
  lanePolicy,
  routeAuth: {
    kind: 'threshold_session',
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
  walletId,
  chainTarget,
  sessionKind: 'jwt',
  sessionIdentity,
  clientRootShare32B64u: 'client-root-share',
  routeAuth: {
    kind: 'threshold_session',
    jwt: 'threshold-session-jwt',
  },
};

// @ts-expect-error jwt passkey fresh bootstrap requires route auth or WebAuthn auth
const invalidPasskeyFreshWithoutJwtAuth: EcdsaBootstrapRequest = {
  kind: 'passkey_fresh_ecdsa_bootstrap',
  walletId,
  chainTarget,
  sessionKind: 'jwt',
  sessionIdentity,
  clientRootShare32B64u: 'client-root-share',
};

const invalidPasskeyFreshWithMixedAuth: EcdsaBootstrapRequest = {
  kind: 'passkey_fresh_ecdsa_bootstrap',
  walletId,
  chainTarget,
  sessionKind: 'jwt',
  sessionIdentity,
  clientRootShare32B64u: 'client-root-share',
  routeAuth: {
    // @ts-expect-error passkey fresh bootstrap accepts one auth branch
    kind: 'bootstrap_grant',
    token: 'bootstrap-grant-token',
  },
  webauthnAuthentication,
};

// @ts-expect-error cookie reconnect uses exact key and lane identity.
const invalidCookieReconnectWithTargetIdentity: EcdsaBootstrapRequest = {
  kind: 'passkey_cookie_reconnect_ecdsa_bootstrap',
  walletId,
  chainTarget,
};
void invalidCookieReconnectWithTargetIdentity;

// @ts-expect-error threshold-session reconnect rejects WebAuthn authentication
const invalidThresholdSessionReconnectWithWebauthn: EcdsaBootstrapRequest = {
  kind: 'threshold_session_auth_reconnect_ecdsa_bootstrap',
  keyHandle,
  key,
  lanePolicy,
  clientRootShare32B64u: 'client-root-share',
  routeAuth: {
    kind: 'threshold_session',
    jwt: 'threshold-session-jwt',
  },
  webauthnAuthentication,
};

// @ts-expect-error Email OTP bootstrap requires Email OTP auth context
const invalidEmailOtpBootstrapWithoutAuthContext: EcdsaBootstrapRequest = {
  kind: 'email_otp_ecdsa_bootstrap',
  walletId,
  chainTarget,
  sessionKind: 'jwt',
  sessionIdentity,
  clientRootShare32B64u: 'client-root-share',
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
  clientRootShare32B64u: 'client-root-share',
  routeAuth: {
    kind: 'bootstrap_grant',
    token: 'bootstrap-grant-token',
  },
};
void invalidPasskeyFreshBootstrapWithSubjectId;

const invalidCookieReconnectBootstrapWithSubjectId: EcdsaBootstrapRequest = {
  kind: 'passkey_cookie_reconnect_ecdsa_bootstrap',
  keyHandle,
  key,
  lanePolicy,
  // @ts-expect-error exact cookie reconnect derives subject from key identity.
  subjectId,
};
void invalidCookieReconnectBootstrapWithSubjectId;

const invalidEmailOtpBootstrapWithSubjectId: EcdsaBootstrapRequest = {
  kind: 'email_otp_ecdsa_bootstrap',
  walletId,
  // @ts-expect-error target-branch Email OTP bootstrap derives subject from walletId.
  subjectId,
  chainTarget,
  source: 'email_otp',
  sessionKind: 'jwt',
  sessionIdentity,
  clientRootShare32B64u: 'client-root-share',
  emailOtpAuthContext: {
    policy: 'session',
    retention: 'session',
    reason: 'sign',
    authMethod: 'email_otp',
  },
};
void invalidEmailOtpBootstrapWithSubjectId;

// @ts-expect-error reuse bootstrap rejects client root share material
const invalidReuseBootstrapWithClientRootShare: EcdsaBootstrapRequest = {
  kind: 'reuse_warm_ecdsa_bootstrap',
  walletId,
  chainTarget,
  clientRootShare32B64u: 'client-root-share',
};
