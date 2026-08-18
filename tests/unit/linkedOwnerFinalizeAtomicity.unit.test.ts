import { expect, test } from '@playwright/test';
import { LinkedDeviceSessionServiceV1 } from '../../packages/wallet-server/src/core/deviceLinking/linkedDeviceSession';
import { buildR103DeviceLinkFixture } from './helpers/deviceLinkContracts.fixtures';
import { buildR103AwaitingTargetPasskeySessionRecordV1 } from './helpers/deviceLinkingServer.fixtures';
import {
  buildCancelledClaimedPrecommitLinkedDeviceSessionState,
  buildExpiredClaimedLinkedDeviceSessionState,
} from '../../packages/shared-ts/src/device-linking/parsers';

/**
 * Finalizing Device 2's owner credential and reserving its link session must be
 * one commit.
 *
 * Finalize is irreversible — one transaction registers the passkey, the custody
 * envelope, and the owner binding — so if the session advance were a second
 * round trip, a cancel or an expiry landing between them would leave the wallet
 * holding a live owner credential for a session that had already terminated,
 * with nothing downstream accounting for it.
 *
 * These own the decision half of closing that window: whether the session may
 * be reserved is settled before any credential exists, and a legal reservation is
 * prepared against the exact revision it was read at, so the CAS the store
 * builds from it fails the batch if the session moved in between.
 */
async function planFor(
  record: Awaited<ReturnType<typeof buildR103AwaitingTargetPasskeySessionRecordV1>>,
  input: { readonly expectedRevision: number; readonly nowMs: number },
) {
  const service = new LinkedDeviceSessionServiceV1({
    store: { getSessionV1: async () => record },
  } as never);
  return await service.prepareLinkedOwnerEnrollmentCompletionV1({
    linkSessionId: record.linkSessionId,
    expectedRevision: input.expectedRevision,
    nowMs: input.nowMs,
  });
}

test('a session that cannot be reserved is refused before any credential exists', async () => {
  const fixture = buildR103DeviceLinkFixture();
  const base = await buildR103AwaitingTargetPasskeySessionRecordV1(fixture);
  // Each of these has already left the only state a linked owner finalize may
  // commit from, so the credential must never be created.
  const identity = {
    linkSessionId: base.linkSessionId,
    walletId: fixture.approval.walletId,
    enrollmentId: fixture.approval.enrollmentId,
  };
  const terminal = [
    buildCancelledClaimedPrecommitLinkedDeviceSessionState({ ...identity, cancelledAtMs: 2_000 }),
    buildExpiredClaimedLinkedDeviceSessionState({ ...identity, expiredAtMs: 2_000 }),
  ];
  for (const state of terminal) {
    const record = await buildR103AwaitingTargetPasskeySessionRecordV1(fixture, { state });
    const plan = await planFor(record, { expectedRevision: base.revision, nowMs: 2_500 });
    expect(plan.outcome, state.state).toBe('invalid_state');
  }

  // Past its own credential deadline the session is expired even in the right
  // state: the link can no longer complete, so nothing should be minted for it.
  const stale = await buildR103AwaitingTargetPasskeySessionRecordV1(fixture, {
    credentialDeadlineMs: 2_000,
  });
  expect((await planFor(stale, { expectedRevision: 3, nowMs: 2_500 })).outcome).toBe('expired');
});

test('a legal reservation preserves state and advances only the revision', async () => {
  const fixture = buildR103DeviceLinkFixture();
  const record = await buildR103AwaitingTargetPasskeySessionRecordV1(fixture, {
    credentialDeadlineMs: 9_000,
  });
  const plan = await planFor(record, { expectedRevision: record.revision, nowMs: 2_000 });
  if (plan.outcome !== 'prepared') throw new Error(`expected prepared, got ${plan.outcome}`);
  // The store turns this into `UPDATE ... WHERE revision = expectedRevision`
  // plus a guard, so carrying the revision it was read at is what makes a
  // concurrent cancel or expiry fail the whole batch instead of being ignored.
  expect(plan.expectedRevision).toBe(record.revision);
  expect(plan.nextRecord.revision).toBe(record.revision + 1);
  expect(plan.nextRecord.state).toEqual(record.state);
});

test('a lost finalize response can retry against the current awaiting revision', async () => {
  const fixture = buildR103DeviceLinkFixture();
  const base = await buildR103AwaitingTargetPasskeySessionRecordV1(fixture);
  const reserved = await buildR103AwaitingTargetPasskeySessionRecordV1(fixture, {
    revision: base.revision + 1,
  });
  const plan = await planFor(reserved, {
    expectedRevision: reserved.revision,
    nowMs: 2_000,
  });
  if (plan.outcome !== 'prepared') throw new Error(`expected prepared, got ${plan.outcome}`);
  expect(plan.expectedRevision).toBe(reserved.revision);
  expect(plan.nextRecord.state).toEqual(reserved.state);
  expect(plan.nextRecord.revision).toBe(reserved.revision + 1);
});
