import { toWalletSubjectId, thresholdEcdsaChainTargetFromChainFamily } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type { WebAuthnAuthenticationCredential } from '@/core/types/webauthn';
import type { ThresholdEcdsaEmailOtpAuthContext } from '../identity/laneIdentity';
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
  signingKeyContext,
  sessionBudgetUses: 1,
  reconnectMaterial: buildEcdsaReconnectMaterial({
    keyRef: {
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
    },
  }),
  // @ts-expect-error reconnect must not accept WebAuthn auth material
  webauthnAuthentication,
});

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
  signingKeyContext,
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
    keyRef: {
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
    },
  }),
});

export {};
