import { expect, test } from '@playwright/test';
import { toAccountId } from '@/core/types/accountIds';
import { toWalletId } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import { buildEvmFamilyEcdsaKeyIdentity } from '@/core/signingEngine/session/identity/evmFamilyEcdsaIdentity';
import {
  buildEvmTransactionSigningLane,
  buildTempoTransactionSigningLane,
} from '@/core/signingEngine/session/operationState/lanes';
import { SigningSessionIds } from '@/core/signingEngine/session/operationState/types';
import { createEmailOtpEcdsaTransactionSigningBridge } from '@/core/signingEngine/flows/signEvmFamily/emailOtpSigningSession';
import { buildCurrentSealedSessionRecord } from '@/core/signingEngine/session/persistence/sealedSessionStore';
import { emailOtpEcdsaSigningSessionAuthLaneFromSealedRecord } from '@/core/signingEngine/session/emailOtp/sealedSigningSessionAuth';
import { EMAIL_OTP_SIGNING_SESSION_AUTH_UNAVAILABLE } from '@/core/signingEngine/session/emailOtp/exportRecovery';
import { THRESHOLD_ECDSA_SESSION_AUTH_TOKEN_KIND } from '@shared/utils/sessionTokens';
import {
  toAuthorizingWalletSigningSessionId,
  type EmailOtpAuthLane,
} from '@/core/signingEngine/stepUpConfirmation/otpPrompt/authLane';
import type { EmailOtpEcdsaSigningBootstrapResult } from '@/core/signingEngine/interfaces/operationDeps';
import { createEvmFamilySigningDeps } from '@/core/signingEngine/assembly/ports/evmFamily';
import { createBrowserPlatformRuntime } from '@/core/platform';
import {
  exactSigningLaneIdentity,
  exactSigningLaneIdentityKey,
} from '@/core/signingEngine/session/identity/exactSigningLaneIdentity';
import type { ReauthAnchorIdentity } from '@/core/signingEngine/session/operationState/transactionState';

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

function unsignedJwt(payload: Record<string, unknown>): string {
  const header = Buffer.from(JSON.stringify({ alg: 'none', typ: 'JWT' })).toString('base64url');
  const body = Buffer.from(JSON.stringify(payload)).toString('base64url');
  return `${header}.${body}.`;
}

function thresholdEcdsaSessionJwt(args: {
  thresholdSessionId: string;
  walletSigningSessionId: string;
  walletId: string;
  keyHandle: string;
}) {
  return unsignedJwt({
    kind: THRESHOLD_ECDSA_SESSION_AUTH_TOKEN_KIND,
    sub: args.walletId,
    walletId: args.walletId,
    keyHandle: args.keyHandle,
    chainTarget: sourceChainTarget,
    sessionId: args.thresholdSessionId,
    walletSigningSessionId: args.walletSigningSessionId,
  });
}

function reauthAnchorForLane(
  lane: ReturnType<typeof buildEvmTransactionSigningLane> | ReturnType<typeof buildTempoTransactionSigningLane>,
): ReauthAnchorIdentity {
  const laneIdentity = exactSigningLaneIdentity(lane);
  const laneIdentityKey = exactSigningLaneIdentityKey(laneIdentity);
  return {
    kind: 'reauth_anchor_identity',
    laneIdentity,
    laneIdentityKey,
    sourceState: {
      kind: 'reauth_anchor_source_state',
      availabilitySource: 'runtime_and_durable',
      storeSource: 'email_otp',
      retention: 'single_use',
      remainingUses: 0,
      expiry: { kind: 'known', expiresAtMs: 1 },
      projection: { kind: 'known', version: 'test' },
    },
    freshness: {
      kind: 'fresh_step_up_required',
      walletId: lane.walletId,
      operationId: SigningSessionIds.signingOperation('email-otp-reauth-test'),
      operationFingerprint: SigningSessionIds.signingOperationFingerprint(
        'email-otp-reauth-fingerprint',
      ),
      authMethod: 'email_otp',
      curve: 'ecdsa',
      laneIdentity,
      laneIdentityKey,
      walletSigningSessionId: laneIdentity.walletSigningSessionId,
      thresholdSessionIds: [laneIdentity.thresholdSessionId],
      projection: { kind: 'known', version: 'test' },
      expiry: { kind: 'known', expiresAtMs: 1 },
      provenance: {
        kind: 'restored_sealed_record_status',
        recordVersion: 'test',
        updatedAtMs: 1,
      },
      reason: 'threshold_session_exhausted',
    },
  };
}

function emptyEmailOtpEcdsaSigningBootstrapResult(): EmailOtpEcdsaSigningBootstrapResult {
  return {
    bootstrap: {} as EmailOtpEcdsaSigningBootstrapResult['bootstrap'],
    warmCapability: {
      capability: 'ecdsa',
      record: null,
      key: null,
      lane: null,
      auth: null,
      prfClaim: null,
      state: 'missing',
    },
  };
}

test('Email OTP ECDSA bridge uses reauth-anchor authority when hot material is missing', async () => {
  const walletId = toAccountId('otp-refresh.testnet');
  const ecdsaWalletId = toWalletId(walletId);
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
  const key = buildEvmFamilyEcdsaKeyIdentity({
    walletId: ecdsaWalletId,
    rpId: 'example.localhost',
    ecdsaThresholdKeyId: 'ehss-email-otp',
    signingRootId: 'proj_local:dev',
    signingRootVersion: 'default',
    participantIds: [1, 2],
    thresholdOwnerAddress: `0x${'aa'.repeat(20)}`,
  });
  const selectedLane = buildTempoTransactionSigningLane({
    key,
    keyHandle: 'key-handle-email-otp',
    walletId,
    authMethod: 'email_otp',
    chainTarget: tempoChainTarget,
    walletSigningSessionId,
    thresholdSessionId,
  });
  const anchorLane = buildEvmTransactionSigningLane({
    key,
    keyHandle: 'key-handle-email-otp',
    walletId,
    authMethod: 'email_otp',
    chainTarget: sourceChainTarget,
    walletSigningSessionId,
    thresholdSessionId,
  });
  const bridge = createEmailOtpEcdsaTransactionSigningBridge({
    walletId,
    walletSession: { walletId: ecdsaWalletId, walletSessionUserId: walletId },
    chain: 'tempo',
    chainTarget: tempoChainTarget,
    selectedLane,
    signingSessionRecord: null,
    reauthSource: {
      kind: 'reauth_anchor',
      anchor: reauthAnchorForLane(anchorLane),
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
      expect(resolvedWalletId).toBe(ecdsaWalletId);
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
      return emptyEmailOtpEcdsaSigningBootstrapResult();
    },
  });

  const challenge = await bridge.challenge();
  await bridge.complete({ challengeId: challenge.challengeId, code: '123456' });

  expect(challengeCalls).toEqual([authLane]);
  expect(loginCalls).toEqual([authLane]);
});

test('Email OTP ECDSA reauth anchor requires signing-session authority', async () => {
  const walletId = toAccountId('otp-refresh.testnet');
  const ecdsaWalletId = toWalletId(walletId);
  const thresholdSessionId = SigningSessionIds.thresholdEcdsaSession('tsess-sealed-ecdsa');
  const walletSigningSessionId = SigningSessionIds.walletSigningSession('wsess-sealed-wallet');
  let challengeCalls = 0;
  const key = buildEvmFamilyEcdsaKeyIdentity({
    walletId: ecdsaWalletId,
    rpId: 'example.localhost',
    ecdsaThresholdKeyId: 'ehss-email-otp',
    signingRootId: 'proj_local:dev',
    signingRootVersion: 'default',
    participantIds: [1, 2],
    thresholdOwnerAddress: `0x${'aa'.repeat(20)}`,
  });
  const anchorLane = buildEvmTransactionSigningLane({
    key,
    keyHandle: 'key-handle-email-otp',
    walletId,
    authMethod: 'email_otp',
    chainTarget: sourceChainTarget,
    walletSigningSessionId,
    thresholdSessionId,
  });
  const bridge = createEmailOtpEcdsaTransactionSigningBridge({
    walletId,
    walletSession: { walletId: ecdsaWalletId, walletSessionUserId: walletId },
    chain: 'tempo',
    chainTarget: tempoChainTarget,
    selectedLane: buildTempoTransactionSigningLane({
      key,
      keyHandle: 'key-handle-email-otp',
      walletId,
      authMethod: 'email_otp',
      chainTarget: tempoChainTarget,
      walletSigningSessionId,
      thresholdSessionId,
    }),
    signingSessionRecord: null,
    reauthSource: {
      kind: 'reauth_anchor',
      anchor: reauthAnchorForLane(anchorLane),
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

test('EVM-family signing deps preserve one-use Email OTP step-up budget', async () => {
  const forwardedRemainingUses: unknown[] = [];
  const deps = createEvmFamilySigningDeps({
    createArgs: {
      seamsPasskeyConfigs: { network: { chains: [] }, signing: {} },
      platformRuntime: createBrowserPlatformRuntime(),
      nonceCoordinator: {},
      ensureSealedRefreshStartupParity: async () => undefined,
      signerWorkerManager: { getContext: () => ({}) },
      loginWithEmailOtpEcdsaCapabilityForSigning: async ({
        remainingUses,
      }: {
        remainingUses?: number;
      }) => {
        forwardedRemainingUses.push(remainingUses);
        return emptyEmailOtpEcdsaSigningBootstrapResult();
      },
    } as never,
    signingSessionCoordinator: {} as never,
    getEmailOtpWarmSessionStatus: async () => ({ status: 'active' }) as never,
  });

  await deps.loginWithEmailOtpEcdsaCapabilityForSigning?.({
    walletSession: {
      walletId: toWalletId(toAccountId('otp-refresh.testnet')),
      walletSessionUserId: toAccountId('otp-refresh.testnet'),
    },
    chainTarget: sourceChainTarget,
    challengeId: 'challenge-1',
    otpCode: '123456',
    remainingUses: 1,
  });

  expect(forwardedRemainingUses).toEqual([1]);
});

test('sealed Email OTP ECDSA auth lane remains available after wallet signing budget exhaustion', () => {
  const thresholdSessionId = SigningSessionIds.thresholdEcdsaSession('tsess-exhausted-ecdsa');
  const walletSigningSessionId = SigningSessionIds.walletSigningSession('wsess-exhausted-wallet');
  const walletId = 'otp-refresh.testnet';
  const keyHandle = 'key-handle-email-otp';
  const sealedRecord = buildCurrentSealedSessionRecord({
    thresholdSessionId,
    thresholdSessionIds: { ecdsa: thresholdSessionId },
    sealedSecretB64u: 'sealed-secret',
    authMethod: 'email_otp',
    walletSigningSessionId,
    curve: 'ecdsa',
    walletId,
    signingRootId: 'proj_local:dev',
    signingRootVersion: 'default',
    relayerUrl: 'https://relay.example.test',
    ecdsaRestore: {
      chainTarget: sourceChainTarget,
      rpId: 'example.localhost',
      thresholdSessionAuthToken: thresholdEcdsaSessionJwt({
        thresholdSessionId,
        walletSigningSessionId,
        walletId,
        keyHandle,
      }),
      sessionKind: 'jwt',
      keyHandle,
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
    jwt: thresholdEcdsaSessionJwt({
      thresholdSessionId,
      walletSigningSessionId,
      walletId,
      keyHandle,
    }),
    thresholdSessionId,
    authorizingWalletSigningSessionId: walletSigningSessionId,
    curve: 'ecdsa',
    chainTarget: sourceChainTarget,
  });
});
