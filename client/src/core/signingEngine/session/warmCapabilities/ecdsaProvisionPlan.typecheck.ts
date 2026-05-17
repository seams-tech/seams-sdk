import { toWalletSubjectId, thresholdEcdsaChainTargetFromChainFamily } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import { toAccountId } from '@/core/types/accountIds';
import type { ThresholdEcdsaSecp256k1KeyRef } from '../../interfaces/signing';
import type { WebAuthnAuthenticationCredential } from '@/core/types/webauthn';
import type { ThresholdEcdsaEmailOtpAuthContext } from '../identity/laneIdentity';
import type { ThresholdEcdsaSessionRecord } from '../persistence/records';
import {
  buildEcdsaReconnectMaterial,
  buildEcdsaSessionIdentity,
  buildEcdsaSessionProvisionPlan,
  buildEmailOtpEcdsaSessionProvision,
  buildPasskeyEcdsaSessionProvision,
  buildThresholdSessionAuthEcdsaReconnect,
  type VerifiedEcdsaThresholdSessionAuth,
} from './ecdsaProvisionPlan';

const subjectId = toWalletSubjectId('wallet.testnet');
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
declare const webauthnAuthentication: WebAuthnAuthenticationCredential;
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
const reconnectKeyRef = {
  type: 'threshold-ecdsa-secp256k1',
  userId: 'alice.testnet',
  subjectId,
  chainTarget,
  relayerUrl: 'https://relayer.test',
  ecdsaThresholdKeyId: 'ecdsa-key-1',
  signingRootId: 'signing-root-1',
  signingRootVersion: 'v1',
  backendBinding: {
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
  subjectId,
  rpId: 'example.localhost',
  chainTarget,
  relayerUrl: 'https://relayer.test',
  ecdsaThresholdKeyId: 'ecdsa-key-1',
  signingRootId: 'signing-root-1',
  signingRootVersion: 'v1',
  relayerKeyId: 'relayer-key-1',
  clientVerifyingShareB64u: 'share',
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

void buildPasskeyEcdsaSessionProvision({
  subjectId,
  chainTarget,
  newSessionIdentity: identity,
  signingKeyContext,
  sessionKind: 'jwt',
  sessionBudgetUses: 1,
  clientRootShare32B64u: 'client-root',
  webauthnAuthentication,
});

void buildPasskeyEcdsaSessionProvision({
  subjectId,
  chainTarget,
  newSessionIdentity: identity,
  signingKeyContext,
  sessionKind: 'jwt',
  sessionBudgetUses: 1,
  clientRootShare32B64u: 'client-root',
  webauthnAuthentication,
  // @ts-expect-error passkey provision must not accept threshold-session auth
  thresholdSessionAuth,
});

void buildThresholdSessionAuthEcdsaReconnect({
  subjectId,
  chainTarget,
  existingSessionIdentity: identity,
  sessionBudgetUses: 1,
  reconnectMaterial: buildEcdsaReconnectMaterial({
    keyRef: reconnectKeyRef,
    record: reconnectRecord,
  }),
  // @ts-expect-error reconnect must not accept WebAuthn auth material
  webauthnAuthentication,
});

// @ts-expect-error reconnect material requires a persisted ECDSA record
void buildEcdsaReconnectMaterial({ keyRef: reconnectKeyRef });

// @ts-expect-error reconnect material requires an ECDSA key ref
void buildEcdsaReconnectMaterial({ record: reconnectRecord });

void buildEmailOtpEcdsaSessionProvision({
  subjectId,
  chainTarget,
  newSessionIdentity: identity,
  signingKeyContext,
  sessionKind: 'jwt',
  sessionBudgetUses: 1,
  emailOtpAuthContext,
  clientRootShare32B64u: 'client-root',
  // @ts-expect-error Email OTP provision must not accept WebAuthn auth
  webauthnAuthentication,
});

void buildEcdsaSessionProvisionPlan({
  kind: 'ecdsa_session_reconnect',
  subjectId,
  chainTarget,
  sessionIdentity: identity,
  sessionBudgetUses: 1,
  // @ts-expect-error reconnect planning requires record or key-ref material
  reconnectMaterial: {},
});

// @ts-expect-error passkey planning must not accept reconnect material
void buildEcdsaSessionProvisionPlan({
  kind: 'passkey_ecdsa_session_provision',
  subjectId,
  chainTarget,
  sessionIdentity: identity,
  signingKeyContext,
  sessionKind: 'jwt',
  sessionBudgetUses: 1,
  clientRootShare32B64u: 'client-root',
  webauthnAuthentication,
  reconnectMaterial: buildEcdsaReconnectMaterial({
    keyRef: reconnectKeyRef,
    record: reconnectRecord,
  }),
});

export {};
