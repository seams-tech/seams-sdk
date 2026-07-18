import {
  thresholdEcdsaChainTargetFromChainFamily,
  toWalletId,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import { deriveEvmFamilySigningKeySlotId } from '@shared/signing-lanes';
import type { EmailOtpWorkerIssuedSessionHandle } from '@/core/platform';
import type { ThresholdEcdsaSecp256k1KeyRef } from '../../interfaces/signing';
import type { EcdsaRoleLocalReadyRecord } from '@/core/platform/types';
import type { WebAuthnAuthenticationCredential } from '@/core/types/webauthn';
import { buildEmailOtpAuthContextForWalletAuthMethod } from '../identity/laneIdentity';
import { parseEcdsaThresholdKeyId } from '../keyMaterialBrands';
import {
  buildEvmFamilyEcdsaKeyIdentityFromRecord,
  toEvmFamilyEcdsaKeyHandle,
} from '../identity/evmFamilyEcdsaIdentity';
import { thresholdEcdsaRecordRpId, type ThresholdEcdsaSessionRecord } from '../persistence/records';
import {
  buildEcdsaReconnectMaterial,
  buildEcdsaSessionIdentity,
  buildEcdsaSessionProvisionPlan,
  buildEmailOtpEcdsaProvisionSecretSource,
  buildEmailOtpEcdsaSessionProvision,
  buildPasskeyEcdsaProvisionSecretSource,
  buildPasskeyEcdsaSessionProvision,
  buildWalletSessionEcdsaReconnect,
  getEcdsaFreshProvisionSessionIdentity,
  getEcdsaProvisionPlanLaneIdentity,
  getEcdsaReconnectSessionIdentity,
  type EcdsaReconnectMaterial,
  type EcdsaSigningKeyContext,
  type EcdsaSessionProvisionPlan,
  type PasskeyEcdsaProvisionSecretSource,
  type VerifiedEcdsaWalletSessionAuth,
} from './ecdsaProvisionPlan';

const chainTarget = thresholdEcdsaChainTargetFromChainFamily({
  chain: 'evm',
  chainId: 11155111,
});
const identity = buildEcdsaSessionIdentity({
  thresholdSessionId: 'threshold-session-1',
  signingGrantId: 'signing-grant-1',
});
const signingKeyContext = {
  ecdsaThresholdKeyId: 'ecdsa-key-1',
  participantIds: [1, 2] as const,
};
const signingKeyContextWithSigningRoot = {
  ...signingKeyContext,
  // @ts-expect-error signing-root identity belongs to key facts, records, and protocol boundaries.
  signingRootId: 'signing-root-1',
} satisfies EcdsaSigningKeyContext;
void signingKeyContextWithSigningRoot;
const keyHandle = toEvmFamilyEcdsaKeyHandle('key-handle-1');
const evmFamilySigningKeySlotId = deriveEvmFamilySigningKeySlotId({
  walletId: toWalletId('alice.testnet'),
  signingRootId: 'signing-root-1',
  signingRootVersion: 'v1',
});
declare const webauthnAuthentication: WebAuthnAuthenticationCredential;
declare const emailOtpWorkerHandle: Extract<
  EmailOtpWorkerIssuedSessionHandle,
  { action: 'threshold_ecdsa_bootstrap' }
>;
declare const roleLocalReadyRecord: EcdsaRoleLocalReadyRecord;
const walletSessionAuth = {
  kind: 'wallet_session',
  curve: 'ecdsa',
  identity,
  walletSessionJwt: 'jwt-token',
  expiresAtMs: 1,
  ecdsaThresholdKeyId: 'ecdsa-key-1',
  relayerKeyId: 'relayer-key-1',
} satisfies VerifiedEcdsaWalletSessionAuth;
const emailOtpAuthContext = buildEmailOtpAuthContextForWalletAuthMethod({
walletId: 'wallet.testnet',
emailHashHex: 'email-hash',
policy: 'session',
  retention: 'session',
  reason: 'sign',
  provider: 'google',
  providerUserId: 'google-subject-1',
});
const passkeyProvisionSecretSource = buildPasskeyEcdsaProvisionSecretSource({
  passkeyPrfFirstB64u: 'prf-first',
  webauthnAuthentication,
});
const recordBackedPasskeyActivationMaterial = { kind: 'session_record' } as const;
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
  evmFamilySigningKeySlotId,
  chainTarget,
  relayerUrl: 'https://relayer.test',
  keyHandle,
  ecdsaThresholdKeyId: parseEcdsaThresholdKeyId('ecdsa-key-1'),
  backendBinding: {
    materialKind: 'metadata_only',
    relayerKeyId: 'relayer-key-1',
    clientVerifyingShareB64u: 'share',
  },
  participantIds: [1, 2],
  thresholdSessionKind: 'jwt',
  walletSessionJwt: 'jwt-token',
  thresholdSessionId: identity.thresholdSessionId,
  signingGrantId: identity.signingGrantId,
} satisfies ThresholdEcdsaSecp256k1KeyRef;
const invalidReconnectKeyRefThresholdSessionAuth = {
  ...reconnectKeyRef,
  // @ts-expect-error current ECDSA key refs carry Wallet Session JWT auth.
  thresholdSessionAuthToken: 'jwt-token',
} satisfies ThresholdEcdsaSecp256k1KeyRef;
void invalidReconnectKeyRefThresholdSessionAuth;
const reconnectRecord = {
  purpose: 'transaction_signing',
  walletId: toWalletId('alice.testnet'),
  evmFamilySigningKeySlotId,
  chainTarget,
  relayerUrl: 'https://relayer.test',
  keyHandle,
  ecdsaThresholdKeyId: 'ecdsa-key-1',
  signingRootId: 'signing-root-1',
  signingRootVersion: 'v1',
  relayerKeyId: 'relayer-key-1',
  clientVerifyingShareB64u: 'share',
  ecdsaRoleLocalReadyRecord: roleLocalReadyRecord,
  ecdsaRoleLocalAuthMethod: roleLocalReadyRecord.authMethod,
  ecdsaRoleLocalPublicFacts: roleLocalReadyRecord.publicFacts,
  participantIds: [1, 2],
  thresholdSessionKind: 'jwt',
  walletSessionJwt: 'jwt-token',
  thresholdSessionId: identity.thresholdSessionId,
  signingGrantId: identity.signingGrantId,
  expiresAtMs: 1,
  remainingUses: 1,
  ethereumAddress: `0x${'11'.repeat(20)}`,
  updatedAtMs: 1,
  source: 'login',
} satisfies ThresholdEcdsaSessionRecord;
const exactKey = buildEvmFamilyEcdsaKeyIdentityFromRecord({
  record: reconnectRecord,
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
  activationMaterial: recordBackedPasskeyActivationMaterial,
});

void buildPasskeyEcdsaSessionProvision({
  key: exactKey,
  chainTarget,
  newSessionIdentity: identity,
  signingKeyContext,
  // @ts-expect-error passkey ECDSA provision must stay on Wallet Session JWT auth
  sessionKind: 'cookie',
  sessionBudgetUses: 1,
  requestId: 'request-1',
  provisionSecretSource: passkeyProvisionSecretSource,
  activationMaterial: recordBackedPasskeyActivationMaterial,
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
  activationMaterial: recordBackedPasskeyActivationMaterial,
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
  activationMaterial: recordBackedPasskeyActivationMaterial,
  // @ts-expect-error passkey provision must not accept Wallet Session auth
  walletSessionAuth,
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
  activationMaterial: recordBackedPasskeyActivationMaterial,
});

void buildWalletSessionEcdsaReconnect({
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

const invalidDirectReconnectMaterial = {
  kind: 'ecdsa_session_record',
  record: reconnectRecord,
  // @ts-expect-error reconnect material carries verified wallet-session auth from its builder.
} satisfies EcdsaReconnectMaterial;
void invalidDirectReconnectMaterial;

const invalidDirectReconnectMaterialWithJwt = {
  kind: 'ecdsa_session_record',
  record: reconnectRecord,
  walletSessionAuth,
  // @ts-expect-error reconnect material must not expose raw walletSessionJwt beside verified auth.
  walletSessionJwt: 'jwt-token',
} satisfies EcdsaReconnectMaterial;
void invalidDirectReconnectMaterialWithJwt;

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

const validReconnectPlan = buildEcdsaSessionProvisionPlan({
  kind: 'ecdsa_session_reconnect',
  chainTarget,
  sessionIdentity: identity,
  sessionBudgetUses: 1,
  reconnectMaterial: buildEcdsaReconnectMaterial({
    record: reconnectRecord,
  }),
});
if (validReconnectPlan.kind !== 'wallet_session_ecdsa_reconnect') {
  throw new Error('expected wallet_session_ecdsa_reconnect');
}
getEcdsaReconnectSessionIdentity(validReconnectPlan);
getEcdsaProvisionPlanLaneIdentity(validReconnectPlan);

const invalidReconnectPlanWithSubjectId: EcdsaSessionProvisionPlan = buildEcdsaSessionProvisionPlan(
  {
    kind: 'ecdsa_session_reconnect',
    // @ts-expect-error reconnect planning derives subject from exact paired material
    subjectId,
    chainTarget,
    sessionIdentity: identity,
    sessionBudgetUses: 1,
    reconnectMaterial: buildEcdsaReconnectMaterial({
      record: reconnectRecord,
    }),
  },
);
void invalidReconnectPlanWithSubjectId;

// @ts-expect-error passkey planning must not accept reconnect material
const validPasskeyProvisionPlan = buildEcdsaSessionProvisionPlan({
  kind: 'passkey_ecdsa_session_provision',
  key: exactKey,
  chainTarget,
  sessionIdentity: identity,
  signingKeyContext,
  sessionKind: 'jwt',
  sessionBudgetUses: 1,
  requestId: 'request-1',
  provisionSecretSource: passkeyProvisionSecretSource,
  activationMaterial: recordBackedPasskeyActivationMaterial,
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
  activationMaterial: recordBackedPasskeyActivationMaterial,
});
if (validPasskeyProvisionPlan.kind !== 'passkey_ecdsa_session_provision') {
  throw new Error('expected passkey_ecdsa_session_provision');
}
getEcdsaFreshProvisionSessionIdentity(validPasskeyProvisionPlan);
getEcdsaProvisionPlanLaneIdentity(validPasskeyProvisionPlan);
// @ts-expect-error fresh provision plans must not enter reconnect identity validation.
getEcdsaReconnectSessionIdentity(validPasskeyProvisionPlan);

void buildEcdsaSessionProvisionPlan({
  kind: 'passkey_ecdsa_session_provision',
  key: exactKey,
  chainTarget,
  sessionIdentity: identity,
  signingKeyContext,
  // @ts-expect-error passkey ECDSA provision plan must stay on Wallet Session JWT auth
  sessionKind: 'cookie',
  sessionBudgetUses: 1,
  requestId: 'request-1',
  provisionSecretSource: passkeyProvisionSecretSource,
  activationMaterial: recordBackedPasskeyActivationMaterial,
});

// @ts-expect-error passkey planning requires explicit activation material
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
  activationMaterial: recordBackedPasskeyActivationMaterial,
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
  activationMaterial: recordBackedPasskeyActivationMaterial,
});

export {};
