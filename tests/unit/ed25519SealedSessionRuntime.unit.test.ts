import { expect, test } from '@playwright/test';
import {
  resolveExactEd25519SealedSessionRuntimeForLaneWithResolver,
  resolveExactEd25519SealedSessionRuntimeForWalletWithResolver,
  resolveExactEd25519SealedSessionRuntimeForWalletSubjectWithResolver,
  resolveExactEd25519SealedSessionRuntimeForWalletSubjectAndActivationWithResolver,
} from '@/core/signingEngine/session/warmCapabilities/ed25519SealedSessionRuntime';
import { rebindRouterAbEd25519WalletSessionStateFromExactRuntime } from '@/core/signingEngine/session/warmCapabilities/routerAbEd25519WalletSessionState';
import { buildEd25519PasskeySigningLane } from '@/core/signingEngine/session/operationState/lanes';
import { SigningSessionIds } from '@/core/signingEngine/session/operationState/types';
import { toWalletId } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import { toAccountId } from '@/core/types/accountIds';
import { nearEd25519SigningKeyIdFromString } from '@shared/utils/registrationIntent';
import { toRpId } from '@/core/signingEngine/session/identity/evmFamilyEcdsaIdentity';
import {
  buildPasskeyExactEd25519AuthorizationFixture,
  buildEmailOtpEd25519SealedSessionRecordFixture,
  buildPasskeyEd25519SealedSessionRecordFixture,
} from './helpers/sealedSigningSession.fixtures';
import { buildMpcMaterialActivationRefFixture } from './helpers/ecdsaMaterialRef.fixtures';
import {
  buildPromotedActiveWalletSessionFixture,
  extendFixtureAuthorityWithEcdsaSigner,
} from './helpers/linkedDeviceManagement.fixtures';
import {
  buildActiveNearEd25519WalletSessionAuthorization,
  buildAuthorizedNearEd25519YaoSigningPreparation,
} from '@/core/signingEngine/session/material/nearEd25519YaoSigningPreparation';
import { walletAuthAuthorityRef } from '@shared/utils/walletAuthAuthority';
import { buildUseLiveRuntimeHydrationPlan } from '@/core/signingEngine/session/material/mpcCapabilityHydration';
import { nearEd25519YaoRuntimeRef } from '@/core/signingEngine/session/material/nearEd25519YaoMaterialActivation';

const RECORD = buildPasskeyEd25519SealedSessionRecordFixture();
const AUTHORIZATION = buildPasskeyExactEd25519AuthorizationFixture(RECORD);
const LANE = buildEd25519PasskeySigningLane({
  walletId: toWalletId(RECORD.walletId),
  nearAccountId: toAccountId(RECORD.ed25519Restore.nearAccountId),
  nearEd25519SigningKeyId: nearEd25519SigningKeyIdFromString(
    RECORD.ed25519Restore.nearEd25519SigningKeyId,
  ),
  signerSlot: 1,
  auth: {
    kind: 'passkey',
    rpId: toRpId('wallet.example.test'),
    credentialIdB64u: 'ed25519-sealed-runtime-credential',
  },
  walletSessionId: AUTHORIZATION.operationCredential.walletSessionId,
  quotaId: AUTHORIZATION.session.quotaId,
  thresholdSessionId: SigningSessionIds.thresholdEd25519Session(RECORD.thresholdSessionIds.ed25519),
  storageSource: 'login',
});

test('resolves one exact sealed Ed25519 session without a composite record', async () => {
  const resolution = await resolveExactEd25519SealedSessionRuntimeForLaneWithResolver(
    {
      walletId: toWalletId(RECORD.walletId),
      laneIdentity: LANE.identity,
    },
    {
      listExactSealedSessionsForWallet: async () => [RECORD],
    },
  );

  expect(resolution).toEqual({
    kind: 'resolved',
    runtime: expect.objectContaining({
      kind: 'exact_ed25519_sealed_session_runtime',
      walletId: RECORD.walletId,
      thresholdSessionId: RECORD.thresholdSessionIds.ed25519,
      participantIds: [1, 2],
      remainingUses: 3,
    }),
  });
  if (resolution.kind === 'resolved') {
    expect(resolution.runtime).not.toHaveProperty('walletSessionToken');
  }
});

test('builds passkey hydration state from the exact sealed runtime and active Wallet Session', async () => {
  const resolution = await resolveExactEd25519SealedSessionRuntimeForLaneWithResolver(
    {
      walletId: toWalletId(RECORD.walletId),
      laneIdentity: LANE.identity,
    },
    {
      listExactSealedSessionsForWallet: async () => [RECORD],
    },
  );
  expect(resolution.kind).toBe('resolved');
  if (resolution.kind !== 'resolved') return;

  const state = await rebindRouterAbEd25519WalletSessionStateFromExactRuntime({
    runtime: resolution.runtime,
    authorization: AUTHORIZATION,
    nowMs: resolution.runtime.expiresAtMs - 1,
  });

  expect(state.thresholdSessionId).toBe(RECORD.thresholdSessionIds.ed25519);
  expect(state.walletSessionId).toBe(AUTHORIZATION.operationCredential.walletSessionId);
  expect(state.quotaId).toBe(AUTHORIZATION.session.quotaId);
  expect(state.signingLane.identity.signer.nearEd25519SigningKeyId).toBe(
    RECORD.ed25519Restore.nearEd25519SigningKeyId,
  );
});

test('rebinds sealed Ed25519 material to a promoted full wallet authority', async () => {
  const resolution = await resolveExactEd25519SealedSessionRuntimeForLaneWithResolver(
    {
      walletId: toWalletId(RECORD.walletId),
      laneIdentity: LANE.identity,
    },
    {
      listExactSealedSessionsForWallet: async () => [RECORD],
    },
  );
  expect(resolution.kind).toBe('resolved');
  if (resolution.kind !== 'resolved') return;
  const promotedAuthority = await extendFixtureAuthorityWithEcdsaSigner(
    AUTHORIZATION.selectedAuthority,
  );
  const promotedSession = buildPromotedActiveWalletSessionFixture({
    source: AUTHORIZATION.session,
    authority: promotedAuthority,
  });
  const factorAuthorityRef = await walletAuthAuthorityRef({
    authority: AUTHORIZATION.selectedFactorAuthority,
  });
  const promotedAuthorization = buildActiveNearEd25519WalletSessionAuthorization({
    selectedAuthority: promotedAuthority,
    selectedAuthMethod: AUTHORIZATION.selectedAuthMethod,
    selectedFactorAuthority: AUTHORIZATION.selectedFactorAuthority,
    session: promotedSession,
    operationCredential: AUTHORIZATION.operationCredential,
    status: {
      status: 'active',
      walletSessionId: AUTHORIZATION.status.walletSessionId,
      quotaId: AUTHORIZATION.status.quotaId,
      remainingUses: AUTHORIZATION.status.remainingUses,
      expiresAtMs: AUTHORIZATION.status.expiresAtMs,
      quotaLifecycle: 'active',
      authorization: promotedSession,
    },
    nowMs: resolution.runtime.expiresAtMs - 1,
  });
  expect(promotedAuthority.authorityDigestB64u).not.toBe(factorAuthorityRef.authorityDigest);

  const state = await rebindRouterAbEd25519WalletSessionStateFromExactRuntime({
    runtime: resolution.runtime,
    authorization: promotedAuthorization,
    nowMs: resolution.runtime.expiresAtMs - 1,
  });

  expect(state.authority).toEqual(factorAuthorityRef);
  expect(state.walletSessionId).toBe(AUTHORIZATION.operationCredential.walletSessionId);

  const preparation = await buildAuthorizedNearEd25519YaoSigningPreparation({
    hydration: buildUseLiveRuntimeHydrationPlan({
      authority: factorAuthorityRef,
      runtime: nearEd25519YaoRuntimeRef(RECORD.ed25519Restore.materialActivation),
      materialActivation: RECORD.ed25519Restore.materialActivation,
    }),
    requirement: LANE.identity.auth,
    authorization: promotedAuthorization,
  });
  expect(preparation.authorization.kind).toBe('authorized');
});

test('keeps missing and conflicting sealed Ed25519 sessions distinct', async () => {
  const args = {
    walletId: toWalletId(RECORD.walletId),
    laneIdentity: LANE.identity,
  };
  await expect(
    resolveExactEd25519SealedSessionRuntimeForLaneWithResolver(args, {
      listExactSealedSessionsForWallet: async () => [],
    }),
  ).resolves.toEqual({ kind: 'missing' });
  await expect(
    resolveExactEd25519SealedSessionRuntimeForLaneWithResolver(args, {
      listExactSealedSessionsForWallet: async () => [RECORD, RECORD],
    }),
  ).resolves.toEqual({ kind: 'conflict' });
});

test('resolves wallet-scoped Ed25519 material across factor stores', async () => {
  const walletId = toWalletId(RECORD.walletId);
  const resolution = await resolveExactEd25519SealedSessionRuntimeForWalletWithResolver(walletId, {
    listExactSealedSessionsForWallet: async ({ filter }) =>
      filter.authMethod === 'passkey' ? [RECORD] : [],
  });

  expect(resolution.kind).toBe('resolved');
  if (resolution.kind !== 'resolved') return;
  expect(resolution.runtime.thresholdSessionId).toBe(RECORD.thresholdSessionIds.ed25519);
});

test('reports wallet-scoped Ed25519 conflicts and corruption explicitly', async () => {
  const walletId = toWalletId(RECORD.walletId);
  await expect(
    resolveExactEd25519SealedSessionRuntimeForWalletWithResolver(walletId, {
      listExactSealedSessionsForWallet: async () => [RECORD],
    }),
  ).resolves.toEqual({ kind: 'conflict' });

  const corruptRecord = {
    ...RECORD,
    expiresAtMs: 0,
  };
  await expect(
    resolveExactEd25519SealedSessionRuntimeForWalletWithResolver(walletId, {
      listExactSealedSessionsForWallet: async ({ filter }) =>
        filter.authMethod === 'passkey' ? [corruptRecord] : [],
    }),
  ).resolves.toEqual({ kind: 'corrupt' });
});

test('selects an exact Ed25519 wallet subject when a wallet has multiple signers', async () => {
  const sibling = buildPasskeyEd25519SealedSessionRecordFixture({
    walletId: RECORD.walletId,
    nearAccountId: 'ed25519-sealed-runtime-sibling.testnet',
    nearEd25519SigningKeyId: 'ed25519-sealed-runtime-sibling-key',
    thresholdSessionId: 'ed25519-sealed-runtime-sibling-session',
  });
  const resolution = await resolveExactEd25519SealedSessionRuntimeForWalletSubjectWithResolver(
    {
      walletId: toWalletId(RECORD.walletId),
      nearAccountId: toAccountId(RECORD.ed25519Restore.nearAccountId),
      nearEd25519SigningKeyId: nearEd25519SigningKeyIdFromString(
        RECORD.ed25519Restore.nearEd25519SigningKeyId,
      ),
    },
    {
      listExactSealedSessionsForWallet: async ({ filter }) =>
        filter.authMethod === 'passkey' ? [RECORD, sibling] : [],
    },
  );

  expect(resolution.kind).toBe('resolved');
  if (resolution.kind !== 'resolved') return;
  expect(resolution.runtime.nearAccountId).toBe(RECORD.ed25519Restore.nearAccountId);
});

test('selects the current Ed25519 runtime by material activation across stale records', async () => {
  const currentActivation = buildMpcMaterialActivationRefFixture(
    'ed25519-sealed-runtime-material-current',
    RECORD.walletId,
  );
  const staleRecord = buildPasskeyEd25519SealedSessionRecordFixture({
    walletId: RECORD.walletId,
    thresholdSessionId: 'ed25519-sealed-runtime-session-stale',
  });
  const currentRecord = buildPasskeyEd25519SealedSessionRecordFixture({
    walletId: RECORD.walletId,
    thresholdSessionId: 'ed25519-sealed-runtime-session-current',
    materialActivation: currentActivation,
  });
  const emailOtpRecord = buildEmailOtpEd25519SealedSessionRecordFixture({
    walletId: RECORD.walletId,
    nearAccountId: RECORD.ed25519Restore.nearAccountId,
    nearEd25519SigningKeyId: RECORD.ed25519Restore.nearEd25519SigningKeyId,
    thresholdSessionId: 'ed25519-sealed-runtime-session-email-otp',
    materialActivation: currentActivation,
  });
  const resolution =
    await resolveExactEd25519SealedSessionRuntimeForWalletSubjectAndActivationWithResolver(
      {
        walletId: toWalletId(RECORD.walletId),
        nearAccountId: toAccountId(RECORD.ed25519Restore.nearAccountId),
        nearEd25519SigningKeyId: nearEd25519SigningKeyIdFromString(
          RECORD.ed25519Restore.nearEd25519SigningKeyId,
        ),
        materialActivation: currentActivation,
        authMethod: 'passkey',
      },
      {
        listExactSealedSessionsForWallet: async () => [staleRecord, currentRecord, emailOtpRecord],
      },
    );

  expect(resolution.kind).toBe('resolved');
  if (resolution.kind !== 'resolved') return;
  expect(resolution.runtime.thresholdSessionId).toBe(currentRecord.thresholdSessionIds.ed25519);
  expect(resolution.runtime.sealedRecord.ed25519Restore.materialActivation).toEqual(
    currentActivation,
  );
});
