import { thresholdEcdsaChainTargetFromChainFamily, toWalletSubjectId } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type { WebAuthnAuthenticationCredential } from '@/core/types/webauthn';
import type { ThresholdEcdsaEmailOtpAuthContext } from '../identity/laneIdentity';
import {
  buildEcdsaSessionIdentity,
  type VerifiedEcdsaThresholdSessionAuth,
} from '../warmCapabilities/ecdsaProvisionPlan';
import type {
  ThresholdEcdsaCookieReconnectRequest,
  ThresholdEcdsaEmailOtpActivationRequest,
  ThresholdEcdsaPasskeyActivationRequest,
  ThresholdEcdsaThresholdSessionAuthReconnectRequest,
} from './ecdsaSessionProvision';

const nearAccountId = 'wallet.testnet';
const subjectId = toWalletSubjectId(nearAccountId);
const chainTarget = thresholdEcdsaChainTargetFromChainFamily({
  chain: 'evm',
  chainId: 11155111,
});
const sessionIdentity = buildEcdsaSessionIdentity({
  thresholdSessionId: 'threshold-session-1',
  walletSigningSessionId: 'wallet-signing-session-1',
});
const runtimePolicy = { kind: 'default_policy' } as const;
declare const webauthnAuthentication: WebAuthnAuthenticationCredential;

const thresholdSessionAuth = {
  kind: 'threshold_session',
  curve: 'ecdsa',
  identity: sessionIdentity,
  thresholdSessionAuthToken: 'jwt-token',
  expiresAtMs: 1,
  ecdsaThresholdKeyId: 'ecdsa-key-1',
  relayerKeyId: 'relayer-key-1',
} satisfies VerifiedEcdsaThresholdSessionAuth;

const emailOtpAuthContext = {
  policy: 'session',
  retention: 'session',
  reason: 'sign',
  authMethod: 'email_otp',
} satisfies ThresholdEcdsaEmailOtpAuthContext;

const activationCommon = {
  nearAccountId,
  subjectId,
  chainTarget,
  relayerUrl: 'https://relay.example',
  source: 'login' as const,
  ecdsaThresholdKeyId: 'ecdsa-key-1',
  participantIds: [1, 2] as const,
  sessionBudgetUses: 1,
  runtimePolicy,
};

void ({
  ...activationCommon,
  kind: 'passkey_ecdsa_activation',
  sessionIdentity,
  sessionKind: 'jwt',
  clientRootShare32B64u: 'client-root',
  webauthnAuthentication,
} satisfies ThresholdEcdsaPasskeyActivationRequest);

void ({
  ...activationCommon,
  kind: 'email_otp_ecdsa_activation',
  sessionIdentity,
  sessionKind: 'jwt',
  clientRootShare32B64u: 'client-root',
  emailOtpAuthContext,
} satisfies ThresholdEcdsaEmailOtpActivationRequest);

void ({
  ...activationCommon,
  kind: 'threshold_session_auth_reconnect',
  sessionIdentity,
  sessionKind: 'jwt',
  thresholdSessionAuth,
} satisfies ThresholdEcdsaThresholdSessionAuthReconnectRequest);

void ({
  ...activationCommon,
  kind: 'cookie_reconnect',
  sessionIdentity,
  sessionKind: 'cookie',
} satisfies ThresholdEcdsaCookieReconnectRequest);

void ({
  ...activationCommon,
  kind: 'passkey_ecdsa_activation',
  sessionIdentity,
  sessionKind: 'jwt',
  clientRootShare32B64u: 'client-root',
  webauthnAuthentication,
  // @ts-expect-error passkey activation must not accept threshold-session auth
  thresholdSessionAuth,
} satisfies ThresholdEcdsaPasskeyActivationRequest);

void ({
  ...activationCommon,
  kind: 'email_otp_ecdsa_activation',
  sessionIdentity,
  sessionKind: 'jwt',
  clientRootShare32B64u: 'client-root',
  emailOtpAuthContext,
  // @ts-expect-error Email OTP activation must not accept WebAuthn auth
  webauthnAuthentication,
} satisfies ThresholdEcdsaEmailOtpActivationRequest);

void ({
  ...activationCommon,
  kind: 'cookie_reconnect',
  sessionIdentity,
  sessionKind: 'cookie',
  // @ts-expect-error cookie reconnect must not accept fresh client root share material
  clientRootShare32B64u: 'client-root',
} satisfies ThresholdEcdsaCookieReconnectRequest);

void ({
  ...activationCommon,
  kind: 'threshold_session_auth_reconnect',
  sessionIdentity,
  // @ts-expect-error threshold-session-auth reconnect must stay on jwt sessionKind
  sessionKind: 'cookie',
  thresholdSessionAuth,
} satisfies ThresholdEcdsaThresholdSessionAuthReconnectRequest);

export {};
