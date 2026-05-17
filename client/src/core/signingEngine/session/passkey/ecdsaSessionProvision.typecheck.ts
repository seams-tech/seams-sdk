import { thresholdEcdsaChainTargetFromChainFamily, toWalletSubjectId } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type { WebAuthnAuthenticationCredential } from '@/core/types/webauthn';
import type { ThresholdEcdsaEmailOtpAuthContext } from '../identity/laneIdentity';
import {
  buildEvmFamilyEcdsaKeyIdentity,
  buildEvmFamilyEcdsaSessionLanePolicy,
} from '../identity/evmFamilyEcdsaIdentity';
import {
  buildEcdsaSessionIdentity,
  type VerifiedEcdsaThresholdSessionAuth,
} from '../warmCapabilities/ecdsaProvisionPlan';
import {
  buildCookieReconnectEcdsaActivation,
  buildEcdsaExportActivation,
  buildEmailOtpPerOperationReauthEcdsaActivation,
  buildEmailOtpSessionBootstrapEcdsaActivation,
  buildPasskeyReconnectEcdsaActivation,
  buildPasskeyRegistrationEcdsaActivation,
  buildThresholdSessionReconnectEcdsaActivation,
} from './ecdsaSessionProvision';

const walletId = 'wallet.testnet';
const subjectId = toWalletSubjectId(walletId);
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

const emailOtpSessionAuthContext = {
  policy: 'session',
  retention: 'session',
  reason: 'sign',
  authMethod: 'email_otp',
} satisfies ThresholdEcdsaEmailOtpAuthContext & { retention: 'session' };

const emailOtpSingleUseAuthContext = {
  policy: 'per_operation',
  retention: 'single_use',
  reason: 'sign',
  authMethod: 'email_otp',
} satisfies ThresholdEcdsaEmailOtpAuthContext & { retention: 'single_use' };

const key = buildEvmFamilyEcdsaKeyIdentity({
  walletId,
  subjectId,
  rpId: 'wallet.example.test',
  ecdsaThresholdKeyId: 'ecdsa-key-1',
  signingRootId: 'signing-root-1',
  signingRootVersion: 'default',
  participantIds: [1, 2],
  thresholdOwnerAddress: '0x1111111111111111111111111111111111111111',
});

const lanePolicy = buildEvmFamilyEcdsaSessionLanePolicy({
  chainTarget,
  thresholdSessionId: 'threshold-session-1',
  walletSigningSessionId: 'wallet-signing-session-1',
  thresholdSessionKind: 'jwt',
  ttlMs: 60_000,
  remainingUses: 1,
});

const broadActivationCommon = {
  walletId,
  subjectId,
  chainTarget,
  relayerUrl: 'https://relay.example',
  source: 'login' as const,
  ecdsaThresholdKeyId: 'ecdsa-key-1',
  participantIds: [1, 2] as const,
  sessionBudgetUses: 1,
  runtimePolicy,
};

const exactActivationCommon = {
  source: 'login' as const,
  relayerUrl: 'https://relay.example',
  sessionBudgetUses: 1,
  runtimePolicy,
  key,
  lanePolicy,
};

void buildPasskeyRegistrationEcdsaActivation({
  ...exactActivationCommon,
  sessionIdentity,
  sessionKind: 'jwt',
  clientRootShare32B64u: 'client-root',
  webauthnAuthentication,
});

void buildPasskeyReconnectEcdsaActivation({
  ...exactActivationCommon,
  sessionIdentity,
  sessionKind: 'jwt',
  clientRootShare32B64u: 'client-root',
  webauthnAuthentication,
});

void buildEmailOtpSessionBootstrapEcdsaActivation({
  ...exactActivationCommon,
  sessionIdentity,
  sessionKind: 'jwt',
  clientRootShare32B64u: 'client-root',
  emailOtpAuthContext: emailOtpSessionAuthContext,
});

void buildEmailOtpPerOperationReauthEcdsaActivation({
  ...exactActivationCommon,
  sessionIdentity,
  sessionKind: 'jwt',
  clientRootShare32B64u: 'client-root',
  emailOtpAuthContext: emailOtpSingleUseAuthContext,
});

void buildThresholdSessionReconnectEcdsaActivation({
  ...exactActivationCommon,
  sessionIdentity,
  sessionKind: 'jwt',
  thresholdSessionAuth,
  clientRootShare32B64u: 'client-root',
});

void buildCookieReconnectEcdsaActivation({
  ...exactActivationCommon,
  sessionIdentity,
  sessionKind: 'cookie',
});

void buildEcdsaExportActivation({
  ...exactActivationCommon,
  sessionIdentity,
  sessionKind: 'jwt',
  clientRootShare32B64u: 'client-root',
  webauthnAuthentication,
});

// @ts-expect-error activation builders require canonical key and lane policy
void buildPasskeyRegistrationEcdsaActivation({
  ...broadActivationCommon,
  sessionIdentity,
  sessionKind: 'jwt',
  clientRootShare32B64u: 'client-root',
  webauthnAuthentication,
});

void buildPasskeyReconnectEcdsaActivation({
  ...exactActivationCommon,
  sessionIdentity,
  sessionKind: 'jwt',
  clientRootShare32B64u: 'client-root',
  webauthnAuthentication,
  // @ts-expect-error passkey activation must not accept threshold-session auth
  thresholdSessionAuth,
});

void buildPasskeyReconnectEcdsaActivation({
  ...exactActivationCommon,
  sessionIdentity,
  sessionKind: 'jwt',
  clientRootShare32B64u: 'client-root',
  webauthnAuthentication,
  // @ts-expect-error exact activation derives walletId from key
  walletId,
});

void buildEmailOtpSessionBootstrapEcdsaActivation({
  ...exactActivationCommon,
  sessionIdentity,
  sessionKind: 'jwt',
  clientRootShare32B64u: 'client-root',
  // @ts-expect-error session Email OTP bootstrap must use session-retained auth
  emailOtpAuthContext: emailOtpSingleUseAuthContext,
});

void buildEmailOtpPerOperationReauthEcdsaActivation({
  ...exactActivationCommon,
  sessionIdentity,
  sessionKind: 'jwt',
  clientRootShare32B64u: 'client-root',
  // @ts-expect-error per-operation Email OTP reauth must use single-use auth
  emailOtpAuthContext: emailOtpSessionAuthContext,
});

void buildEmailOtpSessionBootstrapEcdsaActivation({
  ...exactActivationCommon,
  sessionIdentity,
  sessionKind: 'jwt',
  clientRootShare32B64u: 'client-root',
  emailOtpAuthContext,
  // @ts-expect-error Email OTP builder must not accept WebAuthn auth
  webauthnAuthentication,
});

void buildCookieReconnectEcdsaActivation({
  ...exactActivationCommon,
  sessionIdentity,
  sessionKind: 'cookie',
  // @ts-expect-error cookie reconnect must not accept fresh client root share material
  clientRootShare32B64u: 'client-root',
});

void buildThresholdSessionReconnectEcdsaActivation({
  ...exactActivationCommon,
  sessionIdentity,
  // @ts-expect-error threshold-session-auth reconnect must stay on jwt sessionKind
  sessionKind: 'cookie',
  thresholdSessionAuth,
  clientRootShare32B64u: 'client-root',
});

// @ts-expect-error exact activation key requires a lane policy
void buildPasskeyReconnectEcdsaActivation({
  source: 'login',
  relayerUrl: 'https://relay.example',
  sessionBudgetUses: 1,
  runtimePolicy,
  key,
  sessionIdentity,
  sessionKind: 'jwt',
  clientRootShare32B64u: 'client-root',
  webauthnAuthentication,
});

// @ts-expect-error exact activation lane policy requires a key
void buildPasskeyReconnectEcdsaActivation({
  source: 'login',
  relayerUrl: 'https://relay.example',
  sessionBudgetUses: 1,
  runtimePolicy,
  lanePolicy,
  sessionIdentity,
  sessionKind: 'jwt',
  clientRootShare32B64u: 'client-root',
  webauthnAuthentication,
});

export {};
