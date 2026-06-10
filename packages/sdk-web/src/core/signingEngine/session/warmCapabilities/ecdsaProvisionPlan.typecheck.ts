import {
  thresholdEcdsaChainTargetFromChainFamily,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type { EmailOtpWorkerIssuedSessionHandle } from '@/core/platform';
import { toAccountId } from '@/core/types/accountIds';
import type { ThresholdEcdsaSecp256k1KeyRef } from '../../interfaces/signing';
import type { EcdsaRoleLocalReadyRecord } from '@/core/platform/types';
import type { WebAuthnAuthenticationCredential } from '@/core/types/webauthn';
import type { ThresholdEcdsaEmailOtpAuthContext } from '../identity/laneIdentity';
import {
  buildEvmFamilyEcdsaKeyIdentityFromRecord,
  toEvmFamilyEcdsaKeyHandle,
} from '../identity/evmFamilyEcdsaIdentity';
import {
  thresholdEcdsaRecordRpId,
  type ThresholdEcdsaSessionRecord,
} from '../persistence/records';
import {
  buildEcdsaReconnectMaterial,
  buildEcdsaSessionIdentity,
  buildEcdsaSessionProvisionPlan,
  buildEmailOtpEcdsaProvisionSecretSource,
  buildEmailOtpEcdsaSessionProvision,
  buildPasskeyEcdsaProvisionSecretSource,
  buildPasskeyEcdsaSessionProvision,
  buildThresholdSessionAuthEcdsaReconnect,
  type EcdsaSessionProvisionPlan,
  type PasskeyEcdsaProvisionSecretSource,
  type VerifiedEcdsaThresholdSessionAuth,
} from './ecdsaProvisionPlan';

const chainTarget = thresholdEcdsaChainTargetFromChainFamily({
  chain: 'evm',
  chainId: 11155111,
});
const identity = buildEcdsaSessionIdentity({
  thresholdSessionId: 'threshold-session-1',
  walletSigningSessionId: 'wallet-signing-session-1',
});
const signingKeyContext = {
  ecdsaThresholdKeyId: 'ecdsa-key-1',
  signingRootId: 'signing-root-1',
  signingRootVersion: 'v1',
  participantIds: [1, 2] as const,
};
const keyHandle = toEvmFamilyEcdsaKeyHandle('key-handle-1');
declare const webauthnAuthentication: WebAuthnAuthenticationCredential;
declare const emailOtpWorkerHandle: Extract<
  EmailOtpWorkerIssuedSessionHandle,
  { action: 'threshold_ecdsa_bootstrap' }
>;
declare const roleLocalReadyRecord: EcdsaRoleLocalReadyRecord;
const thresholdSessionAuth = {
  kind: 'threshold_session',
  curve: 'ecdsa',
  identity,
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
const passkeyProvisionSecretSource = buildPasskeyEcdsaProvisionSecretSource({
  passkeyPrfFirstB64u: 'prf-first',
  webauthnAuthentication,
});
const invalidUnbrandedPasskeyProvisionSecretSource: PasskeyEcdsaProvisionSecretSource = {
  kind: 'webauthn_prf_first_v1',
  // @ts-expect-error PRF.first must be normalized by buildPasskeyEcdsaProvisionSecretSource.
  passkeyPrfFirstB64u: 'prf-first',
  webauthnAuthentication,
};
void invalidUnbrandedPasskeyProvisionSecretSource;
const emailOtpProvisionSecretSource = buildEmailOtpEcdsaProvisionSecretSource({
  workerHandle: emailOtpWorkerHandle,
  emailOtpAuthContext,
});
const reconnectKeyRef = {
  type: 'threshold-ecdsa-secp256k1',
  userId: 'alice.testnet',
  chainTarget,
  relayerUrl: 'https://relayer.test',
  keyHandle,
  ecdsaThresholdKeyId: 'ecdsa-key-1',
  signingRootId: 'signing-root-1',
  signingRootVersion: 'v1',
  backendBinding: {
    materialKind: 'metadata_only',
    relayerKeyId: 'relayer-key-1',
    clientVerifyingShareB64u: 'share',
  },
  participantIds: [1, 2],
  thresholdSessionKind: 'jwt',
  thresholdSessionAuthToken: 'jwt-token',
  thresholdSessionId: identity.thresholdSessionId,
  walletSigningSessionId: identity.walletSigningSessionId,
} satisfies ThresholdEcdsaSecp256k1KeyRef;
const reconnectRecord = {
  walletId: toAccountId('alice.testnet'),
  authMetadata: { rpId: 'example.localhost' },
  chainTarget,
  relayerUrl: 'https://relayer.test',
  keyHandle,
  ecdsaThresholdKeyId: 'ecdsa-key-1',
  signingRootId: 'signing-root-1',
  signingRootVersion: 'v1',
  relayerKeyId: 'relayer-key-1',
  clientVerifyingShareB64u: 'share',
  ecdsaRoleLocalReadyRecord: roleLocalReadyRecord,
  participantIds: [1, 2],
  thresholdSessionKind: 'jwt',
  thresholdSessionAuthToken: 'jwt-token',
  thresholdSessionId: identity.thresholdSessionId,
  walletSigningSessionId: identity.walletSigningSessionId,
  expiresAtMs: 1,
  remainingUses: 1,
  ethereumAddress: `0x${'11'.repeat(20)}`,
  updatedAtMs: 1,
  source: 'login',
} satisfies ThresholdEcdsaSessionRecord;
const exactKey = buildEvmFamilyEcdsaKeyIdentityFromRecord({
  record: reconnectRecord,
  rpId: thresholdEcdsaRecordRpId(reconnectRecord),
});

void buildPasskeyEcdsaSessionProvision({
  key: exactKey,
  chainTarget,
  newSessionIdentity: identity,
  signingKeyContext,
  sessionKind: 'jwt',
  sessionBudgetUses: 1,
  requestId: 'request-1',
  provisionSecretSource: passkeyProvisionSecretSource,
});

void buildPasskeyEcdsaSessionProvision({
  key: exactKey,
  chainTarget,
  newSessionIdentity: identity,
  signingKeyContext,
  sessionKind: 'jwt',
  sessionBudgetUses: 1,
  requestId: 'request-1',
  provisionSecretSource: passkeyProvisionSecretSource,
  // @ts-expect-error passkey provision PRF.first must be wrapped in provisionSecretSource
  passkeyPrfFirstB64u: 'prf-first',
});

void buildPasskeyEcdsaSessionProvision({
  key: exactKey,
  chainTarget,
  newSessionIdentity: identity,
  signingKeyContext,
  sessionKind: 'jwt',
  sessionBudgetUses: 1,
  requestId: 'request-1',
  provisionSecretSource: passkeyProvisionSecretSource,
  // @ts-expect-error passkey provision must not accept threshold-session auth
  thresholdSessionAuth,
});

void buildPasskeyEcdsaSessionProvision({
  key: exactKey,
  // @ts-expect-error passkey provision derives subject from exact key identity
  subjectId,
  chainTarget,
  newSessionIdentity: identity,
  signingKeyContext,
  sessionKind: 'jwt',
  sessionBudgetUses: 1,
  requestId: 'request-1',
  provisionSecretSource: passkeyProvisionSecretSource,
});

void buildThresholdSessionAuthEcdsaReconnect({
  chainTarget,
  existingSessionIdentity: identity,
  sessionBudgetUses: 1,
  reconnectMaterial: buildEcdsaReconnectMaterial({
    record: reconnectRecord,
  }),
  // @ts-expect-error reconnect must not accept WebAuthn auth material
  webauthnAuthentication,
});

// @ts-expect-error reconnect material requires a persisted ECDSA record
void buildEcdsaReconnectMaterial({ keyRef: reconnectKeyRef });

void buildEcdsaReconnectMaterial({ record: reconnectRecord });

void buildEcdsaReconnectMaterial({
  record: reconnectRecord,
  // @ts-expect-error reconnect material derives key refs from the session record
  keyRef: reconnectKeyRef,
});

void buildEmailOtpEcdsaSessionProvision({
  key: exactKey,
  chainTarget,
  newSessionIdentity: identity,
  signingKeyContext,
  sessionKind: 'jwt',
  sessionBudgetUses: 1,
  provisionSecretSource: emailOtpProvisionSecretSource,
  // @ts-expect-error Email OTP provision must not accept WebAuthn auth
  webauthnAuthentication,
});

void buildEmailOtpEcdsaSessionProvision({
  key: exactKey,
  // @ts-expect-error Email OTP provision derives subject from exact key identity
  subjectId,
  chainTarget,
  newSessionIdentity: identity,
  signingKeyContext,
  sessionKind: 'jwt',
  sessionBudgetUses: 1,
  provisionSecretSource: emailOtpProvisionSecretSource,
});

void buildEmailOtpEcdsaSessionProvision({
  key: exactKey,
  chainTarget,
  newSessionIdentity: identity,
  signingKeyContext,
  sessionKind: 'jwt',
  sessionBudgetUses: 1,
  provisionSecretSource: emailOtpProvisionSecretSource,
  // @ts-expect-error Email OTP auth context must be wrapped in provisionSecretSource
  emailOtpAuthContext,
});

void buildEcdsaSessionProvisionPlan({
  kind: 'ecdsa_session_reconnect',
  chainTarget,
  sessionIdentity: identity,
  sessionBudgetUses: 1,
  // @ts-expect-error reconnect planning requires record material
  reconnectMaterial: {},
});

void buildEcdsaSessionProvisionPlan({
  kind: 'ecdsa_session_reconnect',
  chainTarget,
  sessionIdentity: identity,
  sessionBudgetUses: 1,
  reconnectMaterial: buildEcdsaReconnectMaterial({
    record: reconnectRecord,
  }),
});

const invalidReconnectPlanWithSubjectId: EcdsaSessionProvisionPlan = buildEcdsaSessionProvisionPlan({
  kind: 'ecdsa_session_reconnect',
  // @ts-expect-error reconnect planning derives subject from exact paired material
  subjectId,
  chainTarget,
  sessionIdentity: identity,
  sessionBudgetUses: 1,
  reconnectMaterial: buildEcdsaReconnectMaterial({
    record: reconnectRecord,
  }),
});
void invalidReconnectPlanWithSubjectId;

// @ts-expect-error passkey planning must not accept reconnect material
void buildEcdsaSessionProvisionPlan({
  kind: 'passkey_ecdsa_session_provision',
  key: exactKey,
  chainTarget,
  sessionIdentity: identity,
  signingKeyContext,
  sessionKind: 'jwt',
  sessionBudgetUses: 1,
  requestId: 'request-1',
  provisionSecretSource: passkeyProvisionSecretSource,
  reconnectMaterial: buildEcdsaReconnectMaterial({
    record: reconnectRecord,
  }),
});

void buildEcdsaSessionProvisionPlan({
  kind: 'passkey_ecdsa_session_provision',
  key: exactKey,
  chainTarget,
  sessionIdentity: identity,
  signingKeyContext,
  sessionKind: 'jwt',
  sessionBudgetUses: 1,
  requestId: 'request-1',
  provisionSecretSource: passkeyProvisionSecretSource,
});

void buildEcdsaSessionProvisionPlan({
  kind: 'passkey_ecdsa_session_provision',
  key: exactKey,
  chainTarget,
  sessionIdentity: identity,
  signingKeyContext,
  sessionKind: 'jwt',
  sessionBudgetUses: 1,
  requestId: 'request-1',
  provisionSecretSource: passkeyProvisionSecretSource,
  // @ts-expect-error passkey planning must not accept top-level WebAuthn credentials
  webauthnAuthentication,
});

void buildEcdsaSessionProvisionPlan({
  kind: 'passkey_ecdsa_session_provision',
  key: exactKey,
  // @ts-expect-error passkey planning derives subject from exact key identity
  subjectId,
  chainTarget,
  sessionIdentity: identity,
  signingKeyContext,
  sessionKind: 'jwt',
  sessionBudgetUses: 1,
  provisionSecretSource: passkeyProvisionSecretSource,
});

export {};
