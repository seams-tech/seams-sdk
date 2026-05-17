import { expect, test } from '@playwright/test';
import { toAccountId } from '@/core/types/accountIds';
import { toWalletId, toWalletSubjectId } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import { buildEvmFamilyEcdsaKeyIdentity } from '@/core/signingEngine/session/identity/evmFamilyEcdsaIdentity';
import { buildTempoTransactionSigningLane } from '@/core/signingEngine/session/operationState/lanes';
import { SigningSessionIds } from '@/core/signingEngine/session/operationState/types';
import { createEmailOtpEcdsaTransactionSigningBridge } from '@/core/signingEngine/flows/signEvmFamily/emailOtpSigningSession';
import { buildCurrentSealedSessionRecord } from '@/core/signingEngine/session/persistence/sealedSessionStore';
import { emailOtpEcdsaSigningSessionAuthLaneFromSealedRecord } from '@/core/signingEngine/session/emailOtp/sealedSigningSessionAuth';
import { EMAIL_OTP_SIGNING_SESSION_AUTH_UNAVAILABLE } from '@/core/signingEngine/session/emailOtp/exportRecovery';
import {
  toAuthorizingWalletSigningSessionId,
  type EmailOtpAuthLane,
} from '@/core/signingEngine/stepUpConfirmation/otpPrompt/authLane';
import type { EmailOtpEcdsaSigningBootstrapResult } from '@/core/signingEngine/interfaces/operationDeps';

const sourceChainTarget = {
  kind: 'evm' as const,
  namespace: 'eip155' as const,
  chainId: 5042002,
  networkSlug: 'arc-testnet',
};

const tempoChainTarget = {
  kind: 'tempo' as const,
  chainId: 42431,
  networkSlug: 'tempo-testnet',
};

test('Email OTP ECDSA bridge uses selected sealed-lane authority when hot material is missing', async () => {
  const walletId = toAccountId('otp-refresh.testnet');
  const ecdsaWalletId = toWalletId(walletId);
  const subjectId = toWalletSubjectId('otp-refresh.testnet');
  const thresholdSessionId = SigningSessionIds.thresholdEcdsaSession('tsess-sealed-ecdsa');
  const walletSigningSessionId = SigningSessionIds.walletSigningSession('wsess-sealed-wallet');
  const authLane: EmailOtpAuthLane = {
    kind: 'signing_session',
    jwt: 'threshold-session-jwt',
    thresholdSessionId,
    authorizingWalletSigningSessionId: toAuthorizingWalletSigningSessionId(walletSigningSessionId),
    curve: 'ecdsa',
    chainTarget: sourceChainTarget,
  };
  const challengeCalls: EmailOtpAuthLane[] = [];
  const loginCalls: EmailOtpAuthLane[] = [];
  const bridge = createEmailOtpEcdsaTransactionSigningBridge({
    walletId,
    walletSession: { walletId: ecdsaWalletId, walletSessionUserId: walletId },
    chain: 'tempo',
    chainTarget: tempoChainTarget,
    selectedLane: buildTempoTransactionSigningLane({
      key: buildEvmFamilyEcdsaKeyIdentity({
        walletId: ecdsaWalletId,
        subjectId,
        rpId: 'example.localhost',
        ecdsaThresholdKeyId: 'ehss-email-otp',
        signingRootId: 'proj_local:dev',
        signingRootVersion: 'default',
        participantIds: [1, 2],
        thresholdOwnerAddress: `0x${'aa'.repeat(20)}`,
      }),
      walletId,
      subjectId,
      authMethod: 'email_otp',
      chainTarget: tempoChainTarget,
      ecdsaThresholdKeyId: 'ehss-email-otp',
      signingRootId: 'proj_local:dev',
      signingRootVersion: 'default',
      walletSigningSessionId,
      thresholdSessionId,
    }),
    signingSessionRecord: null,
    reauthSource: {
      kind: 'selection',
      authority: {
        kind: 'email_otp_signing_session',
        thresholdSessionId,
        chainTarget: sourceChainTarget,
      },
    },
    requestEmailOtpTransactionSigningChallenge: async ({ authLane: receivedAuthLane }) => {
      if (!receivedAuthLane) throw new Error('missing auth lane');
      challengeCalls.push(receivedAuthLane);
      return { challengeId: 'challenge-1', emailHint: 'o***@example.test' };
    },
    resolveEmailOtpSigningSessionAuthLane: ({
      walletId: resolvedWalletId,
      thresholdSessionId: sessionId,
      chainTarget,
    }) => {
      expect(resolvedWalletId).toBe(walletId);
      expect(sessionId).toBe(thresholdSessionId);
      expect(chainTarget).toEqual(sourceChainTarget);
      return authLane;
    },
    loginWithEmailOtpEcdsaCapabilityForSigning: async ({
      authLane: receivedAuthLane,
      chainTarget,
    }) => {
      if (!receivedAuthLane) throw new Error('missing login auth lane');
      expect(chainTarget).toEqual(sourceChainTarget);
      loginCalls.push(receivedAuthLane);
      return { clientRootShare32B64u: 'client-root-share' } as EmailOtpEcdsaSigningBootstrapResult;
    },
  });

  const challenge = await bridge.challenge();
  await bridge.complete({ challengeId: challenge.challengeId, code: '123456' });

  expect(challengeCalls).toEqual([authLane]);
  expect(loginCalls).toEqual([authLane]);
});

test('Email OTP ECDSA selected-lane reauth requires signing-session authority', async () => {
  const walletId = toAccountId('otp-refresh.testnet');
  const ecdsaWalletId = toWalletId(walletId);
  const subjectId = toWalletSubjectId('otp-refresh.testnet');
  const thresholdSessionId = SigningSessionIds.thresholdEcdsaSession('tsess-sealed-ecdsa');
  const walletSigningSessionId = SigningSessionIds.walletSigningSession('wsess-sealed-wallet');
  let challengeCalls = 0;
  const bridge = createEmailOtpEcdsaTransactionSigningBridge({
    walletId,
    walletSession: { walletId: ecdsaWalletId, walletSessionUserId: walletId },
    chain: 'tempo',
    chainTarget: tempoChainTarget,
    selectedLane: buildTempoTransactionSigningLane({
      key: buildEvmFamilyEcdsaKeyIdentity({
        walletId: ecdsaWalletId,
        subjectId,
        rpId: 'example.localhost',
        ecdsaThresholdKeyId: 'ehss-email-otp',
        signingRootId: 'proj_local:dev',
        signingRootVersion: 'default',
        participantIds: [1, 2],
        thresholdOwnerAddress: `0x${'aa'.repeat(20)}`,
      }),
      walletId,
      subjectId,
      authMethod: 'email_otp',
      chainTarget: tempoChainTarget,
      ecdsaThresholdKeyId: 'ehss-email-otp',
      signingRootId: 'proj_local:dev',
      signingRootVersion: 'default',
      walletSigningSessionId,
      thresholdSessionId,
    }),
    signingSessionRecord: null,
    reauthSource: {
      kind: 'selection',
      authority: {
        kind: 'email_otp_signing_session',
        thresholdSessionId,
        chainTarget: sourceChainTarget,
      },
    },
    requestEmailOtpTransactionSigningChallenge: async () => {
      challengeCalls += 1;
      return { challengeId: 'challenge-1', emailHint: 'o***@example.test' };
    },
    resolveEmailOtpSigningSessionAuthLane: () => null,
  });

  await expect(bridge.challenge()).rejects.toThrow(EMAIL_OTP_SIGNING_SESSION_AUTH_UNAVAILABLE);
  expect(challengeCalls).toBe(0);
});

test('sealed Email OTP ECDSA auth lane remains available after wallet signing budget exhaustion', () => {
  const thresholdSessionId = SigningSessionIds.thresholdEcdsaSession('tsess-exhausted-ecdsa');
  const walletSigningSessionId = SigningSessionIds.walletSigningSession('wsess-exhausted-wallet');
  const sealedRecord = buildCurrentSealedSessionRecord({
    thresholdSessionId,
    thresholdSessionIds: { ecdsa: thresholdSessionId },
    sealedSecretB64u: 'sealed-secret',
    authMethod: 'email_otp',
    walletSigningSessionId,
    curve: 'ecdsa',
    subjectId: 'otp-refresh.testnet',
    walletId: 'otp-refresh.testnet',
    signingRootId: 'proj_local:dev',
    signingRootVersion: 'default',
    relayerUrl: 'https://relay.example.test',
    ecdsaRestore: {
      chainTarget: sourceChainTarget,
      rpId: 'example.localhost',
      thresholdSessionAuthToken: 'threshold-session-jwt',
      sessionKind: 'jwt',
      ecdsaThresholdKeyId: 'ehss-email-otp',
      ethereumAddress: `0x${'aa'.repeat(20)}`,
      relayerKeyId: 'relayer-ecdsa',
      participantIds: [1, 2],
    },
    issuedAtMs: Date.now() - 1_000,
    expiresAtMs: Date.now() + 60_000,
    remainingUses: 0,
    updatedAtMs: Date.now(),
  });
  if (!sealedRecord) throw new Error('failed to build sealed record fixture');

  const authLane = emailOtpEcdsaSigningSessionAuthLaneFromSealedRecord({
    thresholdSessionId,
    chainTarget: sourceChainTarget,
    sealedRecord,
  });

  expect(authLane).toEqual({
    kind: 'signing_session',
    jwt: 'threshold-session-jwt',
    thresholdSessionId,
    authorizingWalletSigningSessionId: walletSigningSessionId,
    curve: 'ecdsa',
    chainTarget: sourceChainTarget,
  });
});
