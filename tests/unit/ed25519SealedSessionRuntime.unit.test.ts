import { expect, test } from '@playwright/test';
import {
  resolveExactEd25519SealedSessionRuntimeForLaneWithResolver,
  resolveExactEd25519SealedSessionRuntimeForWalletWithResolver,
  resolveExactEd25519SealedSessionRuntimeForWalletSubjectWithResolver,
} from '@/core/signingEngine/session/warmCapabilities/ed25519SealedSessionRuntime';
import { buildEd25519PasskeySigningLane } from '@/core/signingEngine/session/operationState/lanes';
import { SigningSessionIds } from '@/core/signingEngine/session/operationState/types';
import { toWalletId } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import { toAccountId } from '@/core/types/accountIds';
import { nearEd25519SigningKeyIdFromString } from '@shared/utils/registrationIntent';
import { toRpId } from '@/core/signingEngine/session/identity/evmFamilyEcdsaIdentity';
import { buildPasskeyEd25519SealedSessionRecordFixture } from './helpers/sealedSigningSession.fixtures';

const RECORD = buildPasskeyEd25519SealedSessionRecordFixture();
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
  signingGrantId: SigningSessionIds.signingGrant(RECORD.signingGrantId),
  thresholdSessionId: SigningSessionIds.thresholdEd25519Session(
    RECORD.thresholdSessionIds.ed25519,
  ),
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
      signingGrantId: RECORD.signingGrantId,
      participantIds: [1, 2],
      remainingUses: 3,
    }),
  });
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
  const resolution =
    await resolveExactEd25519SealedSessionRuntimeForWalletWithResolver(
      walletId,
      {
        listExactSealedSessionsForWallet: async ({ filter }) =>
          filter.authMethod === 'passkey' ? [RECORD] : [],
      },
    );

  expect(resolution.kind).toBe('resolved');
  if (resolution.kind !== 'resolved') return;
  expect(resolution.runtime.thresholdSessionId).toBe(
    RECORD.thresholdSessionIds.ed25519,
  );
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
    signingGrantId: 'ed25519-sealed-runtime-sibling-grant',
  });
  const resolution =
    await resolveExactEd25519SealedSessionRuntimeForWalletSubjectWithResolver(
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
  expect(resolution.runtime.nearAccountId).toBe(
    RECORD.ed25519Restore.nearAccountId,
  );
});
