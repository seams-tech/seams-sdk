import {
  thresholdEcdsaChainTargetFromChainFamily,
  toWalletId,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type { EmailOtpWorkerIssuedSessionHandle } from '@/core/platform';
import type { WebAuthnAuthenticationCredential } from '@/core/types/webauthn';
import type { RouterAbEcdsaDerivationPublicCapabilityV1 } from '@shared/utils/routerAbEcdsaDerivation';
import { buildEmailOtpAuthContextForWalletAuthMethod } from '../identity/laneIdentity';
import {
  buildBaseEvmFamilyEcdsaKeyIdentity,
  buildEvmFamilyEcdsaWalletKey,
  buildEvmFamilyEcdsaSessionLanePolicy,
  toEvmFamilyEcdsaKeyHandle,
} from '../identity/evmFamilyEcdsaIdentity';
import { buildEcdsaSessionIdentity } from '../warmCapabilities/ecdsaProvisionPlan';
import {
  buildEcdsaExportActivation,
  buildEmailOtpPerOperationReauthEcdsaActivation,
  buildEmailOtpSessionBootstrapEcdsaActivation,
  buildPasskeyRegistrationEcdsaActivation,
  type EcdsaBootstrapLifecycleCommand,
} from './ecdsaSessionProvision';
import type { PersistedEcdsaRoleLocalMaterial } from '../material/ecdsaRoleLocalMaterialResolver';
import type { EcdsaExplicitExportOperationAuthorization } from '../../threshold/ecdsa/activation';

const walletId = 'wallet.testnet';
const subjectId = toWalletId(walletId);
const chainTarget = thresholdEcdsaChainTargetFromChainFamily({
  chain: 'evm',
  chainId: 11155111,
});
const sessionIdentity = buildEcdsaSessionIdentity({
  thresholdSessionId: 'threshold-session-1',
});
const runtimePolicy = { kind: 'default_policy' } as const;
const runtimePolicyScope = {
  orgId: 'org-1',
  projectId: 'project-1',
  envId: 'env-1',
  signingRootVersion: 'default',
};
declare const webauthnAuthentication: WebAuthnAuthenticationCredential;
declare const publicCapability: RouterAbEcdsaDerivationPublicCapabilityV1;
declare const existingRoleLocalMaterial: PersistedEcdsaRoleLocalMaterial;
declare const explicitExportAuthorization: EcdsaExplicitExportOperationAuthorization;
declare const emailOtpWorkerSessionHandle: Extract<
  EmailOtpWorkerIssuedSessionHandle,
  { action: 'threshold_ecdsa_bootstrap' }
>;

const emailOtpAuthContext = buildEmailOtpAuthContextForWalletAuthMethod({
  walletId: 'wallet.testnet',
  emailHashHex: 'email-hash',
  policy: 'session',
  retention: 'session',
  reason: 'sign',
  provider: 'google',
  providerUserId: 'google-subject-1',
});

const emailOtpSessionAuthContext = buildEmailOtpAuthContextForWalletAuthMethod({
  walletId: 'wallet.testnet',
  emailHashHex: 'email-hash',
  policy: 'session',
  retention: 'session',
  reason: 'sign',
  provider: 'google',
  providerUserId: 'google-subject-1',
});

const emailOtpSingleUseAuthContext = buildEmailOtpAuthContextForWalletAuthMethod({
  walletId: 'wallet.testnet',
  emailHashHex: 'email-hash',
  policy: 'per_operation',
  retention: 'single_use',
  provider: 'google',
  providerUserId: 'google-subject-1',
});

const key = buildBaseEvmFamilyEcdsaKeyIdentity({
  walletId,
  ecdsaThresholdKeyId: 'ecdsa-key-1',
  signingRootId: 'signing-root-1',
  signingRootVersion: 'default',
  participantIds: [1, 2],
  thresholdOwnerAddress: '0x1111111111111111111111111111111111111111',
});
const walletKey = buildEvmFamilyEcdsaWalletKey({
  walletId: key.walletId,
  keyHandle: toEvmFamilyEcdsaKeyHandle('ederivation-key-1'),
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
  thresholdSessionKind: 'jwt',
  ttlMs: 60_000,
  remainingUses: 1,
  runtimePolicyScope,
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
  publicCapability,
  existingRoleLocalMaterial,
};
const walletSessionRouteAuth = {
  kind: 'wallet_session',
  jwt: 'wallet-session-jwt',
} as const;

void buildPasskeyRegistrationEcdsaActivation({
  ...exactActivationCommon,
  sessionIdentity,
  sessionKind: 'jwt',
  webauthnAuthentication,
  walletSessionRouteAuth,
});

void buildPasskeyRegistrationEcdsaActivation({
  ...exactActivationCommon,
  sessionIdentity,
  sessionKind: 'jwt',
  webauthnAuthentication,
  walletSessionRouteAuth,
});

// @ts-expect-error persisted ECDSA activation requires its exact public capability
void buildPasskeyRegistrationEcdsaActivation({
  source: 'login',
  relayerUrl: 'https://relay.example',
  sessionBudgetUses: 1,
  requestId: 'missing-public-capability',
  runtimePolicy,
  walletKey,
  lanePolicy,
  sessionIdentity,
  sessionKind: 'jwt',
  webauthnAuthentication,
  walletSessionRouteAuth,
});

void buildEmailOtpSessionBootstrapEcdsaActivation({
  ...exactActivationCommon,
  sessionIdentity,
  sessionKind: 'jwt',
  emailOtpWorkerSessionHandle,
  emailOtpAuthContext: emailOtpSessionAuthContext,
  walletSessionRouteAuth,
});

void buildEmailOtpPerOperationReauthEcdsaActivation({
  ...exactActivationCommon,
  sessionIdentity,
  sessionKind: 'jwt',
  emailOtpWorkerSessionHandle,
  emailOtpAuthContext: emailOtpSingleUseAuthContext,
  walletSessionRouteAuth,
});

void buildEcdsaExportActivation({
  relayerUrl: 'https://relay.example',
  existingRoleLocalMaterial,
  authorization: explicitExportAuthorization,
});

// @ts-expect-error activation builders require canonical key and lane policy
void buildPasskeyRegistrationEcdsaActivation({
  ...broadActivationCommon,
  sessionIdentity,
  sessionKind: 'jwt',
  webauthnAuthentication,
  walletSessionRouteAuth,
});

void buildPasskeyRegistrationEcdsaActivation({
  ...exactActivationCommon,
  sessionIdentity,
  sessionKind: 'jwt',
  webauthnAuthentication,
  walletSessionRouteAuth,
  // @ts-expect-error passkey activation must not accept Wallet Session auth
  walletSessionAuth,
});

void buildPasskeyRegistrationEcdsaActivation({
  ...exactActivationCommon,
  sessionIdentity,
  sessionKind: 'jwt',
  webauthnAuthentication,
  walletSessionRouteAuth,
  // @ts-expect-error exact activation derives walletId from key
  walletId,
});

void buildEmailOtpSessionBootstrapEcdsaActivation({
  ...exactActivationCommon,
  sessionIdentity,
  sessionKind: 'jwt',
  emailOtpWorkerSessionHandle,
  walletSessionRouteAuth,
  // @ts-expect-error session Email OTP bootstrap must use session-retained auth
  emailOtpAuthContext: emailOtpSingleUseAuthContext,
});

void buildEmailOtpPerOperationReauthEcdsaActivation({
  ...exactActivationCommon,
  sessionIdentity,
  sessionKind: 'jwt',
  emailOtpWorkerSessionHandle,
  walletSessionRouteAuth,
  // @ts-expect-error per-operation Email OTP reauth must use single-use auth
  emailOtpAuthContext: emailOtpSessionAuthContext,
});

void buildEmailOtpSessionBootstrapEcdsaActivation({
  ...exactActivationCommon,
  sessionIdentity,
  sessionKind: 'jwt',
  emailOtpWorkerSessionHandle,
  emailOtpAuthContext,
  walletSessionRouteAuth,
  // @ts-expect-error Email OTP builder must not accept WebAuthn auth
  webauthnAuthentication,
});

// @ts-expect-error exact activation key requires a lane policy
void buildPasskeyRegistrationEcdsaActivation({
  source: 'login',
  relayerUrl: 'https://relay.example',
  sessionBudgetUses: 1,
  requestId: 'request-1',
  runtimePolicy,
  walletKey,
  sessionIdentity,
  sessionKind: 'jwt',
  webauthnAuthentication,
  walletSessionRouteAuth,
});

// @ts-expect-error exact activation lane policy requires a key
void buildPasskeyRegistrationEcdsaActivation({
  source: 'login',
  relayerUrl: 'https://relay.example',
  sessionBudgetUses: 1,
  requestId: 'request-1',
  runtimePolicy,
  lanePolicy,
  sessionIdentity,
  sessionKind: 'jwt',
  webauthnAuthentication,
  walletSessionRouteAuth,
});

void buildPasskeyRegistrationEcdsaActivation({
  ...exactActivationCommon,
  sessionIdentity,
  sessionKind: 'jwt',
  webauthnAuthentication,
  walletSessionRouteAuth,
  // @ts-expect-error exact activation requires walletKey; separate key identity projection is rejected.
  key,
});

void buildPasskeyRegistrationEcdsaActivation({
  ...exactActivationCommon,
  sessionIdentity,
  sessionKind: 'jwt',
  webauthnAuthentication,
  walletSessionRouteAuth,
  // @ts-expect-error exact activation requires walletKey; separate keyHandle projection is rejected.
  keyHandle: toEvmFamilyEcdsaKeyHandle('ederivation-key-1'),
});

const validPasskeyLifecycleCommand = {
  kind: 'passkey_existing_session_activation',
  request: buildPasskeyRegistrationEcdsaActivation({
    ...exactActivationCommon,
    sessionIdentity,
    sessionKind: 'jwt',
    webauthnAuthentication,
    walletSessionRouteAuth,
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
    webauthnAuthentication,
  },
} satisfies EcdsaBootstrapLifecycleCommand;
void invalidLifecycleCommandWithBroadIdentity;

export {};
