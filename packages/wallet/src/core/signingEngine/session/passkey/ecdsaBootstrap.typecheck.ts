import type { EmailOtpWorkerIssuedSessionHandle } from '@/core/platform';
import type {
  ThresholdEcdsaChainTarget,
  WalletId,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type {
  RouterAbEcdsaDerivationPublicCapabilityV1,
  RouterAbEcdsaPostRegistrationSessionActivationResponseV1,
} from '@shared/utils/routerAbEcdsaDerivation';
import { buildEmailOtpAuthContextForCanonicalWallet } from '../identity/laneIdentity';
import type {
  EvmFamilyEcdsaKeyHandle,
  EvmFamilyEcdsaKeyIdentity,
  EvmFamilyEcdsaSessionLanePolicy,
} from '../identity/evmFamilyEcdsaIdentity';
import type { PersistedEcdsaRoleLocalMaterial } from '../material/ecdsaRoleLocalMaterialResolver';
import type { EcdsaBootstrapRequest } from './ecdsaBootstrap';
import { requireOpaqueWalletSessionToken } from '@shared/utils/sessionTokens';
import type { WalletAuthAuthorityRef } from '@shared/utils/walletAuthAuthority';

declare const walletId: WalletId;
declare const subjectId: WalletId;
declare const chainTarget: ThresholdEcdsaChainTarget;
declare const emailOtpWorkerSessionHandle: Extract<
  EmailOtpWorkerIssuedSessionHandle,
  { action: 'threshold_ecdsa_bootstrap' }
>;
declare const keyHandle: EvmFamilyEcdsaKeyHandle;
declare const key: EvmFamilyEcdsaKeyIdentity;
declare const lanePolicy: EvmFamilyEcdsaSessionLanePolicy;
declare const passkeyCredentialIdB64u: string;
declare const publicCapability: RouterAbEcdsaDerivationPublicCapabilityV1;
declare const sessionActivation: RouterAbEcdsaPostRegistrationSessionActivationResponseV1;
declare const existingRoleLocalMaterial: PersistedEcdsaRoleLocalMaterial;
declare const authorizationAuthority: WalletAuthAuthorityRef;

const validReuseBootstrap = {
  kind: 'reuse_warm_ecdsa_bootstrap',
  walletId,
  chainTarget,
  source: 'manual-bootstrap',
} satisfies EcdsaBootstrapRequest;
void validReuseBootstrap;

const invalidReuseBootstrapWithSubjectId: EcdsaBootstrapRequest = {
  kind: 'reuse_warm_ecdsa_bootstrap',
  walletId,
  chainTarget,
  // @ts-expect-error Warm discovery derives its subject from walletId.
  subjectId,
};
void invalidReuseBootstrapWithSubjectId;

const validPasskeyFreshBootstrap = {
  kind: 'passkey_fresh_ecdsa_bootstrap',
  keyHandle,
  key,
  lanePolicy,
  publicCapability,
  existingRoleLocalMaterial,
  source: 'login',
  passkeyCredentialIdB64u,
  routeAuth: {
    kind: 'opaque_wallet_session',
    walletSessionToken: requireOpaqueWalletSessionToken('threshold-session-token'),
  },
} satisfies EcdsaBootstrapRequest;
void validPasskeyFreshBootstrap;

const validPasskeyPreauthorizedBootstrap = {
  kind: 'passkey_preauthorized_ecdsa_bootstrap',
  keyHandle,
  key,
  lanePolicy,
  publicCapability,
  existingRoleLocalMaterial,
  authorizationAuthority,
  source: 'login',
  passkeyCredentialIdB64u,
  sessionActivation,
} satisfies EcdsaBootstrapRequest;
void validPasskeyPreauthorizedBootstrap;

// @ts-expect-error Preauthorized bootstrap requires the already-authorized session activation.
const invalidPasskeyPreauthorizedBootstrapWithoutActivation: EcdsaBootstrapRequest = {
  kind: 'passkey_preauthorized_ecdsa_bootstrap',
  keyHandle,
  key,
  lanePolicy,
  publicCapability,
  existingRoleLocalMaterial,
  authorizationAuthority,
  source: 'login',
  passkeyCredentialIdB64u,
};
void invalidPasskeyPreauthorizedBootstrapWithoutActivation;

const invalidPasskeyPreauthorizedBootstrapWithRouteAuth: EcdsaBootstrapRequest = {
  kind: 'passkey_preauthorized_ecdsa_bootstrap',
  keyHandle,
  key,
  lanePolicy,
  publicCapability,
  existingRoleLocalMaterial,
  authorizationAuthority,
  source: 'login',
  passkeyCredentialIdB64u,
  sessionActivation,
  routeAuth: {
    // @ts-expect-error Preauthorized bootstrap cannot trigger another route authorization.
    kind: 'opaque_wallet_session',
    walletSessionToken: requireOpaqueWalletSessionToken('threshold-session-token'),
  },
};
void invalidPasskeyPreauthorizedBootstrapWithRouteAuth;

// @ts-expect-error Fresh passkey bootstrap requires an exact existing key and material.
const invalidTargetPasskeyFreshBootstrap: EcdsaBootstrapRequest = {
  kind: 'passkey_fresh_ecdsa_bootstrap',
  walletId,
  chainTarget,
  passkeyCredentialIdB64u,
};
void invalidTargetPasskeyFreshBootstrap;

const validWalletSessionReconnectBootstrap = {
  kind: 'wallet_session_reconnect_ecdsa_bootstrap',
  keyHandle,
  key,
  lanePolicy,
  publicCapability,
  existingRoleLocalMaterial,
  authorizationAuthority,
  passkeyCredentialIdB64u,
  routeAuth: {
    kind: 'opaque_wallet_session',
    walletSessionToken: requireOpaqueWalletSessionToken('threshold-session-token'),
  },
} satisfies EcdsaBootstrapRequest;
void validWalletSessionReconnectBootstrap;

const emailOtpAuthContext = buildEmailOtpAuthContextForCanonicalWallet({
  walletId: 'wallet.testnet',
  emailHashHex: 'email-hash',
  policy: 'session',
  retention: 'session',
  reason: 'sign',
  provider: 'google',
  providerUserId: 'google-subject-1',
});

const validEmailOtpBootstrap = {
  kind: 'email_otp_ecdsa_bootstrap',
  keyHandle,
  key,
  lanePolicy,
  publicCapability,
  existingRoleLocalMaterial,
  source: 'email_otp',
  emailOtpWorkerSessionHandle,
  emailOtpAuthContext,
} satisfies EcdsaBootstrapRequest;
void validEmailOtpBootstrap;

// @ts-expect-error Email OTP bootstrap requires an exact existing key and material.
const invalidTargetEmailOtpBootstrap: EcdsaBootstrapRequest = {
  kind: 'email_otp_ecdsa_bootstrap',
  walletId,
  chainTarget,
  source: 'email_otp',
  emailOtpWorkerSessionHandle,
  emailOtpAuthContext,
};
void invalidTargetEmailOtpBootstrap;

// @ts-expect-error Email OTP bootstrap requires its verified auth context.
const invalidEmailOtpBootstrapWithoutAuthContext: EcdsaBootstrapRequest = {
  kind: 'email_otp_ecdsa_bootstrap',
  keyHandle,
  key,
  lanePolicy,
  publicCapability,
  existingRoleLocalMaterial,
  source: 'email_otp',
  emailOtpWorkerSessionHandle,
};
void invalidEmailOtpBootstrapWithoutAuthContext;
