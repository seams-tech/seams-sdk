import {
  thresholdEcdsaChainTargetFromChainFamily,
  toWalletId,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type { EmailOtpWorkerIssuedSessionHandle } from '@/core/platform';
import type { WebAuthnAuthenticationCredential } from '@/core/types/webauthn';
import type { ThresholdEcdsaEmailOtpAuthContext } from '../identity/laneIdentity';
import {
  buildBaseEvmFamilyEcdsaKeyIdentity,
  buildEvmFamilyEcdsaWalletKey,
  buildEvmFamilyEcdsaSessionLanePolicy,
  toEvmFamilyEcdsaKeyHandle,
} from '../identity/evmFamilyEcdsaIdentity';
import {
  buildEcdsaSessionIdentity,
  type VerifiedEcdsaWalletSessionAuth,
} from '../warmCapabilities/ecdsaProvisionPlan';
import {
  buildEcdsaExportActivation,
  buildEmailOtpPerOperationReauthEcdsaActivation,
  buildEmailOtpSessionBootstrapEcdsaActivation,
  buildPasskeyReconnectEcdsaActivation,
  buildPasskeyRegistrationEcdsaActivation,
  buildWalletSessionReconnectEcdsaActivation,
  type EcdsaBootstrapLifecycleCommand,
} from './ecdsaSessionProvision';

const walletId = 'wallet.testnet';
const subjectId = toWalletId(walletId);
const chainTarget = thresholdEcdsaChainTargetFromChainFamily({
  chain: 'evm',
  chainId: 11155111,
});
const sessionIdentity = buildEcdsaSessionIdentity({
  thresholdSessionId: 'threshold-session-1',
  walletSigningSessionId: 'wallet-signing-session-1',
});
const runtimePolicy = { kind: 'default_policy' } as const;
const passkeyCredentialIdB64u = 'passkey-credential-id';
declare const webauthnAuthentication: WebAuthnAuthenticationCredential;
declare const emailOtpWorkerSessionHandle: Extract<
  EmailOtpWorkerIssuedSessionHandle,
  { action: 'threshold_ecdsa_bootstrap' }
>;

const walletSessionAuth = {
  kind: 'wallet_session',
  curve: 'ecdsa',
  identity: sessionIdentity,
  walletSessionJwt: 'jwt-token',
  expiresAtMs: 1,
  ecdsaThresholdKeyId: 'ecdsa-key-1',
  relayerKeyId: 'relayer-key-1',
} satisfies VerifiedEcdsaWalletSessionAuth;

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

const key = buildBaseEvmFamilyEcdsaKeyIdentity({
  walletId,
  rpId: 'wallet.example.test',
  ecdsaThresholdKeyId: 'ecdsa-key-1',
  signingRootId: 'signing-root-1',
  signingRootVersion: 'default',
  participantIds: [1, 2],
  thresholdOwnerAddress: '0x1111111111111111111111111111111111111111',
});
const walletKey = buildEvmFamilyEcdsaWalletKey({
  walletId: key.walletId,
  rpId: key.rpId,
  keyHandle: toEvmFamilyEcdsaKeyHandle('ehss-key-1'),
  chainTarget,
  ecdsaThresholdKeyId: key.ecdsaThresholdKeyId,
  signingRootId: key.signingRootId,
  signingRootVersion: key.signingRootVersion,
  participantIds: key.participantIds,
  thresholdOwnerAddress: key.thresholdOwnerAddress,
  thresholdEcdsaPublicKeyB64u: 'AgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
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
  requestId: 'request-1',
  runtimePolicy,
  walletKey,
  lanePolicy,
};

void buildPasskeyRegistrationEcdsaActivation({
  ...exactActivationCommon,
  sessionIdentity,
  sessionKind: 'jwt',
  passkeyPrfFirstB64u: 'client-root',
  webauthnAuthentication,
});

void buildPasskeyReconnectEcdsaActivation({
  ...exactActivationCommon,
  sessionIdentity,
  sessionKind: 'jwt',
  passkeyPrfFirstB64u: 'client-root',
  webauthnAuthentication,
});

void buildEmailOtpSessionBootstrapEcdsaActivation({
  ...exactActivationCommon,
  sessionIdentity,
  sessionKind: 'jwt',
  emailOtpWorkerSessionHandle,
  emailOtpAuthContext: emailOtpSessionAuthContext,
});

void buildEmailOtpPerOperationReauthEcdsaActivation({
  ...exactActivationCommon,
  sessionIdentity,
  sessionKind: 'jwt',
  emailOtpWorkerSessionHandle,
  emailOtpAuthContext: emailOtpSingleUseAuthContext,
});

void buildWalletSessionReconnectEcdsaActivation({
  ...exactActivationCommon,
  sessionIdentity,
  sessionKind: 'jwt',
  walletSessionAuth,
  passkeyPrfFirstB64u: 'client-root',
  passkeyCredentialIdB64u,
});

void buildEcdsaExportActivation({
  ...exactActivationCommon,
  sessionIdentity,
  sessionKind: 'jwt',
  passkeyPrfFirstB64u: 'client-root',
  webauthnAuthentication,
});

// @ts-expect-error activation builders require canonical key and lane policy
void buildPasskeyRegistrationEcdsaActivation({
  ...broadActivationCommon,
  sessionIdentity,
  sessionKind: 'jwt',
  passkeyPrfFirstB64u: 'client-root',
  webauthnAuthentication,
});

void buildPasskeyReconnectEcdsaActivation({
  ...exactActivationCommon,
  sessionIdentity,
  sessionKind: 'jwt',
  passkeyPrfFirstB64u: 'client-root',
  webauthnAuthentication,
  // @ts-expect-error passkey activation must not accept Wallet Session auth
  walletSessionAuth,
});

void buildPasskeyReconnectEcdsaActivation({
  ...exactActivationCommon,
  sessionIdentity,
  sessionKind: 'jwt',
  passkeyPrfFirstB64u: 'client-root',
  webauthnAuthentication,
  // @ts-expect-error exact activation derives walletId from key
  walletId,
});

void buildEmailOtpSessionBootstrapEcdsaActivation({
  ...exactActivationCommon,
  sessionIdentity,
  sessionKind: 'jwt',
  emailOtpWorkerSessionHandle,
  // @ts-expect-error session Email OTP bootstrap must use session-retained auth
  emailOtpAuthContext: emailOtpSingleUseAuthContext,
});

void buildEmailOtpPerOperationReauthEcdsaActivation({
  ...exactActivationCommon,
  sessionIdentity,
  sessionKind: 'jwt',
  emailOtpWorkerSessionHandle,
  // @ts-expect-error per-operation Email OTP reauth must use single-use auth
  emailOtpAuthContext: emailOtpSessionAuthContext,
});

void buildEmailOtpSessionBootstrapEcdsaActivation({
  ...exactActivationCommon,
  sessionIdentity,
  sessionKind: 'jwt',
  emailOtpWorkerSessionHandle,
  emailOtpAuthContext,
  // @ts-expect-error Email OTP builder must not accept WebAuthn auth
  webauthnAuthentication,
});

void buildWalletSessionReconnectEcdsaActivation({
  ...exactActivationCommon,
  sessionIdentity,
  // @ts-expect-error Wallet Session reconnect must stay on jwt sessionKind
  sessionKind: 'cookie',
  walletSessionAuth,
  passkeyPrfFirstB64u: 'client-root',
  passkeyCredentialIdB64u,
});

// @ts-expect-error exact activation key requires a lane policy
void buildPasskeyReconnectEcdsaActivation({
  source: 'login',
  relayerUrl: 'https://relay.example',
  sessionBudgetUses: 1,
  requestId: 'request-1',
  runtimePolicy,
  walletKey,
  sessionIdentity,
  sessionKind: 'jwt',
  passkeyPrfFirstB64u: 'client-root',
  webauthnAuthentication,
});

// @ts-expect-error exact activation lane policy requires a key
void buildPasskeyReconnectEcdsaActivation({
  source: 'login',
  relayerUrl: 'https://relay.example',
  sessionBudgetUses: 1,
  requestId: 'request-1',
  runtimePolicy,
  lanePolicy,
  sessionIdentity,
  sessionKind: 'jwt',
  passkeyPrfFirstB64u: 'client-root',
  webauthnAuthentication,
});

void buildPasskeyReconnectEcdsaActivation({
  ...exactActivationCommon,
  sessionIdentity,
  sessionKind: 'jwt',
  passkeyPrfFirstB64u: 'client-root',
  webauthnAuthentication,
  // @ts-expect-error exact activation requires walletKey; separate key identity projection is rejected.
  key,
});

void buildPasskeyReconnectEcdsaActivation({
  ...exactActivationCommon,
  sessionIdentity,
  sessionKind: 'jwt',
  passkeyPrfFirstB64u: 'client-root',
  webauthnAuthentication,
  // @ts-expect-error exact activation requires walletKey; separate keyHandle projection is rejected.
  keyHandle: toEvmFamilyEcdsaKeyHandle('ehss-key-1'),
});

const validPasskeyLifecycleCommand = {
  kind: 'passkey_existing_session_activation',
  request: buildPasskeyReconnectEcdsaActivation({
    ...exactActivationCommon,
    sessionIdentity,
    sessionKind: 'jwt',
    passkeyPrfFirstB64u: 'client-root',
    webauthnAuthentication,
  }),
} satisfies EcdsaBootstrapLifecycleCommand;
void validPasskeyLifecycleCommand;

const invalidLifecycleCommandWithBroadIdentity = {
  kind: 'passkey_existing_session_activation',
  // @ts-expect-error lifecycle bootstrap commands require exact keyHandle/key/lanePolicy state.
  request: {
    kind: 'passkey_ecdsa_activation',
    ...broadActivationCommon,
    sessionIdentity,
    sessionKind: 'jwt',
    passkeyPrfFirstB64u: 'client-root',
    webauthnAuthentication,
  },
} satisfies EcdsaBootstrapLifecycleCommand;
void invalidLifecycleCommandWithBroadIdentity;

const invalidLifecycleCommandWithTargetIntent = {
  kind: 'wallet_session_existing_session_reconnect',
  request: {
    kind: 'wallet_session_reconnect',
    ...exactActivationCommon,
    // @ts-expect-error lifecycle bootstrap commands cannot carry target keyIntent state.
    keyIntent: {
      kind: 'existing_ecdsa_key',
      ecdsaThresholdKeyId: 'ecdsa-key-1',
      participantIds: [1, 2],
    },
    sessionIdentity,
    sessionKind: 'jwt',
    walletSessionAuth,
    passkeyPrfFirstB64u: 'client-root',
    passkeyCredentialIdB64u,
  },
} satisfies EcdsaBootstrapLifecycleCommand;
void invalidLifecycleCommandWithTargetIntent;

export {};
