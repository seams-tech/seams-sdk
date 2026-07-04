import { expect, test } from '@playwright/test';
import { deriveEvmFamilySigningKeySlotId } from '@shared/signing-lanes';
import { toAccountId } from '@/core/types/accountIds';
import { toWalletId } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import {
  buildEvmFamilyEcdsaKeyIdentity,
  toEvmFamilyEcdsaKeyHandle,
} from '@/core/signingEngine/session/identity/evmFamilyEcdsaIdentity';
import {
  buildEvmTransactionSigningLane,
  buildTempoTransactionSigningLane,
} from '@/core/signingEngine/session/operationState/lanes';
import { SigningSessionIds } from '@/core/signingEngine/session/operationState/types';
import { createEmailOtpEcdsaTransactionSigningBridge } from '@/core/signingEngine/flows/signEvmFamily/emailOtpSigningSession';
import {
  requireResolvedEvmFamilyEcdsaSigningLane,
  type ResolvedEvmFamilyEcdsaSigningLane,
} from '@/core/signingEngine/flows/signEvmFamily/ecdsaLanes';
import type { EmailOtpEcdsaCommittedLane } from '@/core/signingEngine/flows/signEvmFamily/ecdsaSelection';
import { buildCurrentSealedSessionRecord } from '@/core/signingEngine/session/persistence/sealedSessionStore';
import { emailOtpEcdsaSigningSessionAuthLaneFromSealedRecord } from '@/core/signingEngine/session/emailOtp/sealedSigningSessionAuth';
import { ROUTER_AB_ECDSA_HSS_WALLET_SESSION_JWT_KIND } from '@shared/utils/sessionTokens';
import { buildEmailOtpWalletAuthAuthority } from '@shared/utils/walletAuthAuthority';
import {
  toAuthorizingSigningGrantId,
  type EmailOtpAuthLane,
} from '@/core/signingEngine/stepUpConfirmation/otpPrompt/authLane';
import type { EmailOtpEcdsaSigningBootstrapResult } from '@/core/signingEngine/interfaces/operationDeps';
import { createEvmFamilySigningDeps } from '@/core/signingEngine/assembly/ports/evmFamily';
import { createBrowserPlatformRuntime } from '@/core/platform';
import {
  buildEvmFamilyEcdsaSignerBinding,
  exactEcdsaSigningLaneIdentity,
  exactSigningLaneIdentityFromSelectedLane,
  exactSigningLaneIdentityKey,
} from '@/core/signingEngine/session/identity/exactSigningLaneIdentity';
import type { ReauthAnchorIdentity } from '@/core/signingEngine/session/operationState/transactionState';
import { buildEcdsaSessionIdentity } from '@/core/signingEngine/session/warmCapabilities/ecdsaProvisionPlan';
import type { EcdsaLaneCandidate } from '@/core/signingEngine/session/identity/laneIdentity';
import type { ThresholdEcdsaSessionRecord } from '@/core/signingEngine/session/persistence/records';

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
const signingRootId = 'proj_local:dev';
const signingRootVersion = 'default';
const emailOtpAuth = {
  kind: 'email_otp',
  providerSubjectId: 'google:otp-refresh',
} as const;
const emailOtpEmailHashHex = '44'.repeat(32);

function testEvmFamilySigningKeySlotId(walletId: unknown) {
  return deriveEvmFamilySigningKeySlotId({
    walletId,
    signingRootId,
    signingRootVersion,
  });
}

function unsignedJwt(payload: Record<string, unknown>): string {
  const header = Buffer.from(JSON.stringify({ alg: 'none', typ: 'JWT' })).toString('base64url');
  const body = Buffer.from(JSON.stringify(payload)).toString('base64url');
  return `${header}.${body}.`;
}

function thresholdEcdsaSessionJwt(args: {
  thresholdSessionId: string;
  signingGrantId: string;
  walletId: string;
  keyHandle: string;
}) {
  return unsignedJwt({
    kind: ROUTER_AB_ECDSA_HSS_WALLET_SESSION_JWT_KIND,
    sub: args.walletId,
    walletId: args.walletId,
    keyHandle: args.keyHandle,
    chainTarget: sourceChainTarget,
    thresholdSessionId: args.thresholdSessionId,
    signingGrantId: args.signingGrantId,
    runtimePolicyScope: {
      orgId: 'org-local',
      projectId: 'proj_local',
      envId: 'dev',
      signingRootVersion: 'default',
    },
  });
}

function reauthAnchorForLane(
  lane:
    | ReturnType<typeof buildEvmTransactionSigningLane>
    | ReturnType<typeof buildTempoTransactionSigningLane>,
): ReauthAnchorIdentity {
  const laneIdentity = exactSigningLaneIdentityFromSelectedLane(lane);
  const laneIdentityKey = exactSigningLaneIdentityKey(laneIdentity);
  return {
    kind: 'reauth_anchor_identity',
    laneIdentity,
    laneIdentityKey,
    sourceState: {
      kind: 'reauth_anchor_source_state',
      availabilitySource: 'runtime_session_record',
      storeSource: 'email_otp',
      retention: 'single_use',
      remainingUses: 0,
      expiry: { kind: 'known', expiresAtMs: 1 },
      projection: { kind: 'known', version: 'test' },
    },
    freshness: {
      kind: 'fresh_step_up_required',
      walletId: lane.identity.signer.walletId,
      operationId: SigningSessionIds.signingOperation('email-otp-reauth-test'),
      operationFingerprint: SigningSessionIds.signingOperationFingerprint(
        'email-otp-reauth-fingerprint',
      ),
      authMethod: 'email_otp',
      curve: 'ecdsa',
      laneIdentity,
      laneIdentityKey,
      signingGrantId: laneIdentity.signingGrantId,
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

function candidateForResolvedEcdsaLane(
  lane: ResolvedEvmFamilyEcdsaSigningLane,
): EcdsaLaneCandidate {
  return {
    kind: 'lane_candidate',
    auth: lane.auth,
    curve: 'ecdsa',
    chain: lane.chain,
    walletId: lane.identity.signer.walletId,
    key: lane.key,
    keyHandle: lane.keyHandle,
    chainTarget: lane.chainTarget,
    signingGrantId: String(lane.signingGrantId),
    thresholdSessionId: String(lane.thresholdSessionId),
    state: 'exhausted',
    remainingUses: 0,
    expiresAtMs: null,
    updatedAtMs: null,
    source: 'durable_sealed_record',
  };
}

function committedLaneForAuth(args: {
  lane: ResolvedEvmFamilyEcdsaSigningLane;
  authLane: Extract<EmailOtpAuthLane, { kind: 'signing_session'; curve: 'ecdsa' }>;
}): EmailOtpEcdsaCommittedLane {
  const authority = buildEmailOtpWalletAuthAuthority({
    walletId: args.lane.identity.signer.walletId,
    provider: 'google',
    providerUserId: emailOtpAuth.providerSubjectId,
    emailHashHex: emailOtpEmailHashHex,
  });
  return {
    source: 'record_backed',
    lane: args.lane,
    candidate: candidateForResolvedEcdsaLane(args.lane),
    authority,
    authLane: args.authLane,
    walletSessionAuthority: {
      kind: 'wallet_session_authority',
      walletSessionJwt: args.authLane.jwt,
      thresholdSessionId: args.authLane.thresholdSessionId,
      signingGrantId: String(args.authLane.authorizingSigningGrantId),
    },
    material: {
      kind: 'public_identity_unavailable',
      authMethod: 'email_otp',
      source: 'email_otp',
      chainTarget: args.lane.chainTarget,
      identity: buildEcdsaSessionIdentity({
        thresholdSessionId: args.authLane.thresholdSessionId,
        signingGrantId: String(args.authLane.authorizingSigningGrantId),
      }),
      hasRecord: false,
    },
    record: {
      source: 'email_otp',
      chainTarget: args.lane.chainTarget,
    } as ThresholdEcdsaSessionRecord,
    durableRestore: 'record_restore_metadata',
  };
}

test('Email OTP ECDSA bridge uses source authority while refreshing the selected target', async () => {
  const walletId = toAccountId('otp-refresh.testnet');
  const ecdsaWalletId = toWalletId(walletId);
  const thresholdSessionId = SigningSessionIds.thresholdEcdsaSession('tsess-sealed-ecdsa');
  const signingGrantId = SigningSessionIds.signingGrant('wsess-sealed-wallet');
  const authLane: EmailOtpAuthLane = {
    kind: 'signing_session',
    jwt: 'threshold-session-jwt',
    thresholdSessionId,
    authorizingSigningGrantId: toAuthorizingSigningGrantId(signingGrantId),
    curve: 'ecdsa',
    chainTarget: sourceChainTarget,
  };
  const challengeCalls: EmailOtpAuthLane[] = [];
  const loginCalls: EmailOtpAuthLane[] = [];
  const key = buildEvmFamilyEcdsaKeyIdentity({
    walletId: ecdsaWalletId,
    evmFamilySigningKeySlotId: testEvmFamilySigningKeySlotId(ecdsaWalletId),
    ecdsaThresholdKeyId: 'ehss-email-otp',
    signingRootId,
    signingRootVersion,
    participantIds: [1, 2],
    thresholdOwnerAddress: `0x${'aa'.repeat(20)}`,
  });
  const selectedLane = buildTempoTransactionSigningLane({
    key,
    keyHandle: 'key-handle-email-otp',
    walletId: ecdsaWalletId,
    auth: emailOtpAuth,
    chainTarget: tempoChainTarget,
    signingGrantId,
    thresholdSessionId,
  });
  const resolvedSelectedLane = requireResolvedEvmFamilyEcdsaSigningLane({
    lane: selectedLane,
    chain: 'tempo',
    context: 'Email OTP bridge test',
  });
  const anchorLane = buildEvmTransactionSigningLane({
    key,
    keyHandle: 'key-handle-email-otp',
    walletId: ecdsaWalletId,
    auth: emailOtpAuth,
    chainTarget: sourceChainTarget,
    signingGrantId,
    thresholdSessionId,
  });
  const anchorResolvedLane = requireResolvedEvmFamilyEcdsaSigningLane({
    lane: anchorLane,
    chain: 'evm',
    context: 'Email OTP bridge anchor authority test',
  });
  const committedLane = committedLaneForAuth({ lane: anchorResolvedLane, authLane });
  const bridge = createEmailOtpEcdsaTransactionSigningBridge({
    walletId: ecdsaWalletId,
    walletSession: { walletId: ecdsaWalletId, walletSessionUserId: walletId },
    chain: 'tempo',
    chainTarget: tempoChainTarget,
    selectedLane: resolvedSelectedLane,
    committedLane,
    reauthSource: {
      kind: 'reauth_anchor',
      anchor: reauthAnchorForLane(anchorLane),
    },
    requestEmailOtpTransactionSigningChallenge: async ({ authLane: receivedAuthLane }) => {
      if (!receivedAuthLane) throw new Error('missing auth lane');
      challengeCalls.push(receivedAuthLane);
      return { challengeId: 'challenge-1', emailHint: 'o***@example.test' };
    },
    loginWithEmailOtpEcdsaCapabilityForSigning: async ({
      committedLane: receivedCommittedLane,
      chainTarget,
    }) => {
      expect(chainTarget).toEqual(tempoChainTarget);
      loginCalls.push(receivedCommittedLane.authLane);
      return emptyEmailOtpEcdsaSigningBootstrapResult();
    },
  });

  const challenge = await bridge.challenge();
  await bridge.complete({ challengeId: challenge.challengeId, code: '123456' });

  expect(challengeCalls).toEqual([authLane]);
  expect(loginCalls).toEqual([authLane]);
});

test('Email OTP ECDSA bridge uses selected reauth authority lane directly', async () => {
  const walletId = toAccountId('otp-refresh.testnet');
  const ecdsaWalletId = toWalletId(walletId);
  const thresholdSessionId = SigningSessionIds.thresholdEcdsaSession('tsess-current-ecdsa');
  const signingGrantId = SigningSessionIds.signingGrant('wsess-current-wallet');
  const authLane: EmailOtpAuthLane = {
    kind: 'signing_session',
    jwt: 'current-threshold-session-jwt',
    thresholdSessionId,
    authorizingSigningGrantId: toAuthorizingSigningGrantId(signingGrantId),
    curve: 'ecdsa',
    chainTarget: tempoChainTarget,
  };
  const key = buildEvmFamilyEcdsaKeyIdentity({
    walletId: ecdsaWalletId,
    evmFamilySigningKeySlotId: testEvmFamilySigningKeySlotId(ecdsaWalletId),
    ecdsaThresholdKeyId: 'ehss-email-otp',
    signingRootId,
    signingRootVersion,
    participantIds: [1, 2],
    thresholdOwnerAddress: `0x${'aa'.repeat(20)}`,
  });
  const selectedLane = requireResolvedEvmFamilyEcdsaSigningLane({
    lane: buildTempoTransactionSigningLane({
      key,
      keyHandle: 'key-handle-email-otp',
      walletId: ecdsaWalletId,
      auth: emailOtpAuth,
      chainTarget: tempoChainTarget,
      signingGrantId,
      thresholdSessionId,
    }),
    chain: 'tempo',
    context: 'Email OTP bridge direct authority test',
  });
  const committedLane = committedLaneForAuth({ lane: selectedLane, authLane });
  const bridge = createEmailOtpEcdsaTransactionSigningBridge({
    walletId: ecdsaWalletId,
    walletSession: { walletId: ecdsaWalletId, walletSessionUserId: walletId },
    chain: 'tempo',
    chainTarget: tempoChainTarget,
    selectedLane,
    committedLane,
    reauthSource: {
      kind: 'reauth_anchor',
      anchor: reauthAnchorForLane(selectedLane),
    },
    requestEmailOtpTransactionSigningChallenge: async ({ authLane: receivedAuthLane }) => {
      expect(receivedAuthLane).toBe(authLane);
      return { challengeId: 'challenge-1', emailHint: 'o***@example.test' };
    },
  });

  await expect(bridge.challenge()).resolves.toEqual({
    challengeId: 'challenge-1',
    email: 'o***@example.test',
  });
});

test('EVM-family signing deps preserve one-use Email OTP step-up budget', async () => {
  const forwardedRemainingUses: unknown[] = [];
  const walletId = toAccountId('otp-refresh.testnet');
  const ecdsaWalletId = toWalletId(walletId);
  const thresholdSessionId = SigningSessionIds.thresholdEcdsaSession('tsess-budget-ecdsa');
  const signingGrantId = SigningSessionIds.signingGrant('wsess-budget-wallet');
  const authLane = {
    kind: 'signing_session' as const,
    jwt: 'budget-threshold-session-jwt',
    thresholdSessionId,
    authorizingSigningGrantId: toAuthorizingSigningGrantId(signingGrantId),
    curve: 'ecdsa' as const,
    chainTarget: sourceChainTarget,
  };
  const key = buildEvmFamilyEcdsaKeyIdentity({
    walletId: ecdsaWalletId,
    evmFamilySigningKeySlotId: testEvmFamilySigningKeySlotId(ecdsaWalletId),
    ecdsaThresholdKeyId: 'ehss-email-otp',
    signingRootId,
    signingRootVersion,
    participantIds: [1, 2],
    thresholdOwnerAddress: `0x${'aa'.repeat(20)}`,
  });
  const lane = requireResolvedEvmFamilyEcdsaSigningLane({
    lane: buildEvmTransactionSigningLane({
      key,
      keyHandle: 'key-handle-email-otp',
      walletId: ecdsaWalletId,
      auth: emailOtpAuth,
      chainTarget: sourceChainTarget,
      signingGrantId,
      thresholdSessionId,
    }),
    chain: 'evm',
    context: 'Email OTP ECDSA budget forwarding test',
  });
  const deps = createEvmFamilySigningDeps({
    createArgs: {
      seamsWebConfigs: { network: { chains: [] }, signing: {} },
      runtimePorts: createBrowserPlatformRuntime(),
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
    walletSignerStore: {} as never,
    passkeyAuthenticatorStore: {} as never,
    signingSessionCoordinator: {} as never,
    getEmailOtpWarmSessionStatus: async () => ({ status: 'active' }) as never,
  });

  await deps.loginWithEmailOtpEcdsaCapabilityForSigning?.({
    walletSession: {
      walletId: ecdsaWalletId,
      walletSessionUserId: walletId,
    },
    chainTarget: sourceChainTarget,
    challengeId: 'challenge-1',
    otpCode: '123456',
    committedLane: committedLaneForAuth({ lane, authLane }),
    remainingUses: 1,
  });

  expect(forwardedRemainingUses).toEqual([1]);
});

test('sealed Email OTP ECDSA auth lane remains available after wallet signing budget exhaustion', () => {
  const thresholdSessionId = SigningSessionIds.thresholdEcdsaSession('tsess-exhausted-ecdsa');
  const signingGrantId = SigningSessionIds.signingGrant('wsess-exhausted-wallet');
  const walletId = 'otp-refresh.testnet';
  const keyHandle = 'key-handle-email-otp';
  const sealedRecord = buildCurrentSealedSessionRecord({
    thresholdSessionId,
    thresholdSessionIds: { ecdsa: thresholdSessionId },
    sealedSecretB64u: 'sealed-secret',
    authMethod: 'email_otp',
    signingGrantId,
    curve: 'ecdsa',
    walletId,
    relayerUrl: 'https://relay.example.test',
    ecdsaRestore: {
      chainTarget: sourceChainTarget,
      source: 'email_otp',
      evmFamilySigningKeySlotId: testEvmFamilySigningKeySlotId(walletId),
      providerSubjectId: emailOtpAuth.providerSubjectId,
      emailHashHex: emailOtpEmailHashHex,
      walletSessionJwt: thresholdEcdsaSessionJwt({
        thresholdSessionId,
        signingGrantId,
        walletId,
        keyHandle,
      }),
      sessionKind: 'jwt',
      keyHandle,
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
  const sealedKey = buildEvmFamilyEcdsaKeyIdentity({
    walletId: toWalletId(walletId),
    evmFamilySigningKeySlotId: testEvmFamilySigningKeySlotId(walletId),
    ecdsaThresholdKeyId: 'ehss-email-otp',
    signingRootId,
    signingRootVersion,
    participantIds: [1, 2],
    thresholdOwnerAddress: `0x${'aa'.repeat(20)}`,
  });
  const sealedLane = exactEcdsaSigningLaneIdentity({
    signer: buildEvmFamilyEcdsaSignerBinding({
      walletId: toWalletId(walletId),
      chainTarget: sourceChainTarget,
      keyHandle: toEvmFamilyEcdsaKeyHandle(keyHandle),
      key: sealedKey,
    }),
    auth: emailOtpAuth,
    signingGrantId,
    thresholdSessionId,
  });

  const authLane = emailOtpEcdsaSigningSessionAuthLaneFromSealedRecord({
    lane: sealedLane,
    sealedRecord,
  });

  expect(authLane).toEqual({
    kind: 'signing_session',
    jwt: thresholdEcdsaSessionJwt({
      thresholdSessionId,
      signingGrantId,
      walletId,
      keyHandle,
    }),
    thresholdSessionId,
    authorizingSigningGrantId: signingGrantId,
    curve: 'ecdsa',
    chainTarget: sourceChainTarget,
  });
});
