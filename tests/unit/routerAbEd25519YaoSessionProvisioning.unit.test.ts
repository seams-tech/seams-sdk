import { expect, test } from '@playwright/test';
import { parseWebAuthnRpId } from '@shared/utils/domainIds';
import type {
  RouterAbEd25519YaoNormalSigningSessionProvisionInput,
  RouterAbNormalSigningRuntime,
} from '../../packages/sdk-server-ts/src/core/routerAbSigning/RouterAbNormalSigningRuntime';
import { walletSigningBudgetSessionId } from '../../packages/sdk-server-ts/src/core/ThresholdService/walletSigningBudget';
import { createThresholdSigningServiceForUnitTests } from '../helpers/thresholdServiceTestUtils';

const FORBIDDEN_SECRET_FIELD = /(share|scalar|prf|package|garbled|seed|private)/i;

function webAuthnRpId(value: string) {
  const parsed = parseWebAuthnRpId(value);
  if (!parsed.ok) throw new Error(parsed.error.message);
  return parsed.value;
}

function assertNoSecretFields(value: unknown): void {
  if (!value || typeof value !== 'object') return;
  for (const [key, nested] of Object.entries(value)) {
    expect(key).not.toMatch(FORBIDDEN_SECRET_FIELD);
    assertNoSecretFields(nested);
  }
}

function provisionInput(args: {
  expiresAtMs: number;
  walletId: string;
  thresholdSessionId: string;
}): RouterAbEd25519YaoNormalSigningSessionProvisionInput {
  return {
    kind: 'router_ab_ed25519_yao_normal_signing_session_v1',
    walletId: args.walletId,
    nearAccountId: '11'.repeat(32),
    nearEd25519SigningKeyId: 'near-ed25519-key-1',
    authorityScope: { kind: 'passkey_rp', rpId: webAuthnRpId('wallet.example.test') },
    thresholdSessionId: args.thresholdSessionId,
    signingGrantId: 'signing-grant-yao-1',
    signingWorkerId: 'signing-worker.local',
    expiresAtMs: args.expiresAtMs,
    participantIds: [1, 2],
    remainingUses: 3,
  };
}

function primaryProvisionInput(): RouterAbEd25519YaoNormalSigningSessionProvisionInput {
  return provisionInput({
    expiresAtMs: Date.now() + 60_000,
    walletId: 'wallet-yao-1',
    thresholdSessionId: 'threshold-session-yao-1',
  });
}

function waitUntilAfter(deadlineMs: number): void {
  while (Date.now() <= deadlineMs) {
    // This fixture needs the in-memory TTL boundary to pass before the refresh call.
  }
}

async function publicStateProvisioningPreservesConsumedBudget(): Promise<void> {
  const { routerAbNormalSigningRuntime, walletSessionStore, walletBudgetSessionStore } =
    createThresholdSigningServiceForUnitTests({});
  const input = primaryProvisionInput();

  await expect(
    routerAbNormalSigningRuntime.provisionRouterAbEd25519YaoNormalSigningSession(input),
  ).resolves.toMatchObject({
    ok: true,
    thresholdSessionId: input.thresholdSessionId,
    signingGrantId: input.signingGrantId,
    remainingUses: 3,
  });

  const session = await walletSessionStore.getSession(input.thresholdSessionId);
  const budgetId = walletSigningBudgetSessionId({ signingGrantId: input.signingGrantId });
  const budget = await walletBudgetSessionStore.getSession(budgetId);
  expect(session).toMatchObject({
    walletId: input.walletId,
    nearAccountId: input.nearAccountId,
    nearEd25519SigningKeyId: input.nearEd25519SigningKeyId,
    relayerKeyId: input.signingWorkerId,
    participantIds: [1, 2],
  });
  expect(budget).toMatchObject({
    kind: 'wallet_signing_budget_session',
    walletId: input.walletId,
    bindings: {
      kind: 'ed25519_only',
      ed25519: {
        thresholdSessionId: input.thresholdSessionId,
        authorityScope: input.authorityScope,
        participantIds: [1, 2],
      },
    },
  });
  assertNoSecretFields(session);
  assertNoSecretFields(budget);

  const reservation = await routerAbNormalSigningRuntime.reserveBudget({
    curve: 'ed25519',
    thresholdSessionId: input.thresholdSessionId,
    signingGrantId: input.signingGrantId,
    signingWorkerId: input.signingWorkerId,
    operationId: 'operation-1',
    requestDigest: 'digest-1',
    signatureUses: 1,
    expiresAtMs: Date.now() + 30_000,
  });
  expect(reservation).toMatchObject({ ok: true, remainingUses: 3, reservedUses: 1 });
  if (!reservation.ok) throw new Error(reservation.message);
  await expect(
    routerAbNormalSigningRuntime.validateBudget({
      curve: 'ed25519',
      thresholdSessionId: input.thresholdSessionId,
      signingGrantId: input.signingGrantId,
      reservationId: reservation.reservationId,
      signingWorkerId: input.signingWorkerId,
      operationId: 'operation-1',
      requestDigest: 'digest-1',
    }),
  ).resolves.toMatchObject({ ok: true, remainingUses: 3 });
  await expect(
    routerAbNormalSigningRuntime.commitBudget({
      curve: 'ed25519',
      thresholdSessionId: input.thresholdSessionId,
      signingGrantId: input.signingGrantId,
      reservationId: reservation.reservationId,
      signingWorkerId: input.signingWorkerId,
      operationId: 'operation-1',
      requestDigest: 'digest-1',
    }),
  ).resolves.toMatchObject({ ok: true, remainingUses: 2 });

  await expect(
    routerAbNormalSigningRuntime.provisionRouterAbEd25519YaoNormalSigningSession(input),
  ).resolves.toMatchObject({
    ok: true,
    remainingUses: 2,
  });
}

async function sessionProvisioningRejectsIdentityCollision(): Promise<void> {
  const { routerAbNormalSigningRuntime } = createThresholdSigningServiceForUnitTests({});
  const input = primaryProvisionInput();
  await expect(
    routerAbNormalSigningRuntime.provisionRouterAbEd25519YaoNormalSigningSession(input),
  ).resolves.toMatchObject({ ok: true });

  await expect(
    routerAbNormalSigningRuntime.provisionRouterAbEd25519YaoNormalSigningSession(
      provisionInput({
        expiresAtMs: input.expiresAtMs,
        walletId: 'wallet-yao-2',
        thresholdSessionId: input.thresholdSessionId,
      }),
    ),
  ).resolves.toMatchObject({ ok: false, code: 'conflict' });
}

async function authenticatedBudgetRefreshPreservesYaoLifecycleIdentity(): Promise<void> {
  const { routerAbNormalSigningRuntime, walletSessionStore, walletBudgetSessionStore } =
    createThresholdSigningServiceForUnitTests({});
  const input = provisionInput({
    expiresAtMs: Date.now() + 5_000,
    walletId: 'wallet-yao-1',
    thresholdSessionId: 'threshold-session-yao-1',
  });
  const provisioned =
    await routerAbNormalSigningRuntime.provisionRouterAbEd25519YaoNormalSigningSession({
      ...input,
      remainingUses: 2,
    });
  expect(provisioned).toMatchObject({ ok: true, remainingUses: 2 });
  if (!provisioned.ok) throw new Error(provisioned.message);
  const originalSession = await walletSessionStore.getSession(input.thresholdSessionId);
  const budgetId = walletSigningBudgetSessionId({ signingGrantId: input.signingGrantId });
  await expect(walletBudgetSessionStore.consumeUseCount(budgetId)).resolves.toMatchObject({
    ok: true,
    remainingUses: 1,
  });
  await expect(walletBudgetSessionStore.consumeUseCount(budgetId)).resolves.toMatchObject({
    ok: true,
    remainingUses: 0,
  });

  const refreshed = await routerAbNormalSigningRuntime.refreshRouterAbEd25519YaoNormalSigningBudget(
    {
      kind: 'router_ab_ed25519_yao_normal_signing_budget_refresh_v1',
      walletId: input.walletId,
      nearAccountId: input.nearAccountId,
      nearEd25519SigningKeyId: input.nearEd25519SigningKeyId,
      authorityScope: input.authorityScope,
      thresholdSessionId: input.thresholdSessionId,
      signingGrantId: input.signingGrantId,
      signingWorkerId: input.signingWorkerId,
      participantIds: input.participantIds,
      ttlMs: 30_000,
      remainingUses: 3,
    },
  );

  expect(refreshed).toMatchObject({
    ok: true,
    thresholdSessionId: input.thresholdSessionId,
    signingGrantId: input.signingGrantId,
    remainingUses: 3,
  });
  const refreshedSession = await walletSessionStore.getSession(input.thresholdSessionId);
  expect(refreshedSession).toMatchObject({
    walletId: originalSession?.walletId,
    nearAccountId: originalSession?.nearAccountId,
    nearEd25519SigningKeyId: originalSession?.nearEd25519SigningKeyId,
    authorityScope: originalSession?.authorityScope,
    participantIds: originalSession?.participantIds,
  });
  expect(refreshedSession?.expiresAtMs).toBeGreaterThan(input.expiresAtMs);
  const refreshedBudget = await walletBudgetSessionStore.getSessionStatus(budgetId);
  expect(refreshedBudget?.remainingUses).toBe(3);
  expect(refreshedBudget?.expiresAtMs).toBeGreaterThan(input.expiresAtMs);
}

async function authenticatedBudgetRefreshRecreatesExpiredPublicState(): Promise<void> {
  const { routerAbNormalSigningRuntime, walletSessionStore, walletBudgetSessionStore } =
    createThresholdSigningServiceForUnitTests({});
  const input = provisionInput({
    expiresAtMs: Date.now() + 5,
    walletId: 'wallet-yao-expired',
    thresholdSessionId: 'threshold-session-yao-expired',
  });
  const provisioned =
    await routerAbNormalSigningRuntime.provisionRouterAbEd25519YaoNormalSigningSession(input);
  expect(provisioned).toMatchObject({ ok: true });
  waitUntilAfter(input.expiresAtMs);
  expect(await walletSessionStore.getSession(input.thresholdSessionId)).toBeNull();

  const refreshed = await routerAbNormalSigningRuntime.refreshRouterAbEd25519YaoNormalSigningBudget(
    {
      kind: 'router_ab_ed25519_yao_normal_signing_budget_refresh_v1',
      walletId: input.walletId,
      nearAccountId: input.nearAccountId,
      nearEd25519SigningKeyId: input.nearEd25519SigningKeyId,
      authorityScope: input.authorityScope,
      thresholdSessionId: input.thresholdSessionId,
      signingGrantId: input.signingGrantId,
      signingWorkerId: input.signingWorkerId,
      participantIds: input.participantIds,
      ttlMs: 30_000,
      remainingUses: 3,
    },
  );

  expect(refreshed).toMatchObject({
    ok: true,
    thresholdSessionId: input.thresholdSessionId,
    signingGrantId: input.signingGrantId,
    remainingUses: 3,
  });
  expect(await walletSessionStore.getSession(input.thresholdSessionId)).toMatchObject({
    walletId: input.walletId,
    nearAccountId: input.nearAccountId,
    nearEd25519SigningKeyId: input.nearEd25519SigningKeyId,
    participantIds: input.participantIds,
  });
  const budgetId = walletSigningBudgetSessionId({ signingGrantId: input.signingGrantId });
  expect(await walletBudgetSessionStore.getSessionStatus(budgetId)).toMatchObject({
    remainingUses: 3,
  });
}

async function authenticatedBudgetRefreshRejectsCurveBindingSubstitution(): Promise<void> {
  const { routerAbNormalSigningRuntime } = createThresholdSigningServiceForUnitTests({});
  const input = primaryProvisionInput();
  await expect(
    routerAbNormalSigningRuntime.provisionRouterAbEd25519YaoNormalSigningSession(input),
  ).resolves.toMatchObject({ ok: true });

  await expect(
    routerAbNormalSigningRuntime.refreshRouterAbEd25519YaoNormalSigningBudget({
      kind: 'router_ab_ed25519_yao_normal_signing_budget_refresh_v1',
      walletId: input.walletId,
      nearAccountId: input.nearAccountId,
      nearEd25519SigningKeyId: input.nearEd25519SigningKeyId,
      authorityScope: {
        kind: 'passkey_rp',
        rpId: webAuthnRpId('substituted.example.test'),
      },
      thresholdSessionId: input.thresholdSessionId,
      signingGrantId: input.signingGrantId,
      signingWorkerId: input.signingWorkerId,
      participantIds: input.participantIds,
      ttlMs: 30_000,
      remainingUses: 3,
    }),
  ).resolves.toMatchObject({ ok: false, code: 'conflict' });
}

async function consumeSharedSigningBudgetUse(input: {
  readonly runtime: RouterAbNormalSigningRuntime;
  readonly curve: 'ed25519' | 'ecdsa';
  readonly thresholdSessionId: string;
  readonly signingGrantId: string;
  readonly operationId: string;
}): Promise<number> {
  const requestDigest = `${input.operationId}-digest`;
  const reservation = await input.runtime.reserveBudget({
    curve: input.curve,
    thresholdSessionId: input.thresholdSessionId,
    signingGrantId: input.signingGrantId,
    signingWorkerId: 'signing-worker.local',
    operationId: input.operationId,
    requestDigest,
    signatureUses: 1,
    expiresAtMs: Date.now() + 30_000,
  });
  if (!reservation.ok) throw new Error(reservation.message);
  const committed = await input.runtime.commitBudget({
    curve: input.curve,
    thresholdSessionId: input.thresholdSessionId,
    signingGrantId: input.signingGrantId,
    reservationId: reservation.reservationId,
    signingWorkerId: 'signing-worker.local',
    operationId: input.operationId,
    requestDigest,
  });
  if (!committed.ok) throw new Error(committed.message);
  return committed.remainingUses;
}

async function mixedCurveRegistrationSharesOneThreeUseBudget(): Promise<void> {
  const { routerAbNormalSigningRuntime, ecdsaWalletSessionStore, walletBudgetSessionStore } =
    createThresholdSigningServiceForUnitTests({});
  const ed25519Input = primaryProvisionInput();
  const ecdsaThresholdSessionId = 'threshold-session-ecdsa-1';
  const ecdsaKeySlotId = 'wallet-key:evm-family:wallet-yao-1:root-1:v1';
  const ecdsaSessionExpiresAtMs = Date.now() + 60_000;
  await ecdsaWalletSessionStore.putSession(
    ecdsaThresholdSessionId,
    {
      expiresAtMs: ecdsaSessionExpiresAtMs,
      relayerKeyId: 'signing-worker.local',
      walletId: ed25519Input.walletId,
      evmFamilySigningKeySlotId: ecdsaKeySlotId,
      participantIds: [1, 2, 3],
    },
    { ttlMs: 60_000, remainingUses: 3 },
  );
  const ecdsaBudget = await routerAbNormalSigningRuntime.ensureSigningGrantBudget({
    signingGrantId: ed25519Input.signingGrantId,
    curve: 'ecdsa',
    thresholdSessionId: ecdsaThresholdSessionId,
    userId: ed25519Input.walletId,
    evmFamilySigningKeySlotId: ecdsaKeySlotId,
    participantIds: [1, 2, 3],
    ttlMs: 60_000,
    remainingUses: 3,
    operation: 'provision_curve_binding',
  });
  if (!ecdsaBudget.ok) throw new Error(ecdsaBudget.message);

  await expect(
    routerAbNormalSigningRuntime.provisionRouterAbEd25519YaoNormalSigningSession(
      provisionInput({
        walletId: ed25519Input.walletId,
        thresholdSessionId: ed25519Input.thresholdSessionId,
        expiresAtMs: ecdsaBudget.expiresAtMs,
      }),
    ),
  ).resolves.toMatchObject({ ok: true, remainingUses: 3 });

  const budgetId = walletSigningBudgetSessionId({
    signingGrantId: ed25519Input.signingGrantId,
  });
  expect(await walletBudgetSessionStore.getSession(budgetId)).toMatchObject({
    bindings: {
      kind: 'ed25519_and_ecdsa',
      ed25519: { thresholdSessionId: ed25519Input.thresholdSessionId },
      ecdsa: [
        {
          thresholdSessionId: ecdsaThresholdSessionId,
          evmFamilySigningKeySlotId: ecdsaKeySlotId,
          participantIds: [1, 2, 3],
        },
      ],
    },
  });

  await expect(
    consumeSharedSigningBudgetUse({
      runtime: routerAbNormalSigningRuntime,
      curve: 'ed25519',
      thresholdSessionId: ed25519Input.thresholdSessionId,
      signingGrantId: ed25519Input.signingGrantId,
      operationId: 'near-operation',
    }),
  ).resolves.toBe(2);
  await expect(
    consumeSharedSigningBudgetUse({
      runtime: routerAbNormalSigningRuntime,
      curve: 'ecdsa',
      thresholdSessionId: ecdsaThresholdSessionId,
      signingGrantId: ed25519Input.signingGrantId,
      operationId: 'tempo-operation',
    }),
  ).resolves.toBe(1);
  await expect(
    consumeSharedSigningBudgetUse({
      runtime: routerAbNormalSigningRuntime,
      curve: 'ecdsa',
      thresholdSessionId: ecdsaThresholdSessionId,
      signingGrantId: ed25519Input.signingGrantId,
      operationId: 'arc-operation',
    }),
  ).resolves.toBe(0);
  await expect(
    routerAbNormalSigningRuntime.reserveBudget({
      curve: 'ed25519',
      thresholdSessionId: ed25519Input.thresholdSessionId,
      signingGrantId: ed25519Input.signingGrantId,
      signingWorkerId: ed25519Input.signingWorkerId,
      operationId: 'exhausted-near-operation',
      requestDigest: 'exhausted-near-digest',
      signatureUses: 1,
      expiresAtMs: Date.now() + 30_000,
    }),
  ).resolves.toMatchObject({ ok: false, code: 'wallet_budget_exhausted' });
}

test(
  'Yao session provisioning stores public authority state and preserves consumed budget on retry',
  publicStateProvisioningPreservesConsumedBudget,
);

test(
  'Yao session provisioning rejects a threshold-session identity collision',
  sessionProvisioningRejectsIdentityCollision,
);

test(
  'fresh authorization refreshes the exhausted budget without changing Yao lifecycle identity',
  authenticatedBudgetRefreshPreservesYaoLifecycleIdentity,
);

test(
  'fresh authorization recreates expired Yao Wallet Session public state',
  authenticatedBudgetRefreshRecreatesExpiredPublicState,
);

test(
  'Yao budget refresh rejects authority-scope substitution',
  authenticatedBudgetRefreshRejectsCurveBindingSubstitution,
);

test(
  'mixed Ed25519 and ECDSA registration consumes one shared three-use budget',
  mixedCurveRegistrationSharesOneThreeUseBudget,
);
