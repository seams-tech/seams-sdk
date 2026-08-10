import { expect, test } from '@playwright/test';
import { buildLinkedDeviceSigningLaneRecord } from '../../packages/shared-ts/src/signing-lanes/recordParsers';
import { parseLinkedDeviceId } from '../../packages/shared-ts/src/signing-lanes/ids';
import {
  admitAndDispatchOwnerWalletExecution,
  prepareOwnerWalletExecution,
} from '../../packages/sdk-server-ts/src/router/domains/signingOperations/walletExecutionAdmission';
import {
  buildCompletedAuthorizedOperationFixture,
  buildReusableAuthorizationCoreFixture,
} from './helpers/authorizationCore.fixtures';
import { buildOwnerWalletExecutionEvidenceFixture } from './helpers/walletExecutionLane.fixtures';

test.describe('R101 wallet execution admission', () => {
  test('dispatches only a claimed operation bound to the exact active owner lane', async () => {
    const authorization = await buildReusableAuthorizationCoreFixture();
    const evidence = await buildOwnerWalletExecutionEvidenceFixture();
    let dispatchCount = 0;
    const result = await admitAndDispatchOwnerWalletExecution({
      authorizedOperation: authorization.authorizedOperation,
      resolveEvidence: async () => evidence,
      dispatch: async (execution) => {
        dispatchCount += 1;
        return execution.lane.laneId;
      },
    });

    expect(result).toEqual({ kind: 'dispatched', result: evidence.lane.laneId });
    expect(dispatchCount).toBe(1);
  });

  test('refuses linked-device lanes before dispatch until R103 owns their admission', async () => {
    const authorization = await buildReusableAuthorizationCoreFixture();
    const evidence = await buildOwnerWalletExecutionEvidenceFixture();
    const linkedDeviceId = parseLinkedDeviceId('linked-device:wallet-authorization');
    if (!linkedDeviceId.ok) throw new Error(linkedDeviceId.error.message);
    const linkedLane = buildLinkedDeviceSigningLaneRecord({
      walletId: evidence.lane.walletId,
      walletKeyId: evidence.lane.walletKeyId,
      laneId: evidence.lane.laneId,
      laneShareEpoch: evidence.lane.laneShareEpoch,
      participantBindingDigestB64u: evidence.lane.participantBindingDigestB64u,
      holderParticipant: evidence.lane.holderParticipant,
      serverParticipant: evidence.lane.serverParticipant,
      lifecycle: evidence.lane.lifecycle,
      linkedDeviceId: linkedDeviceId.value,
    });
    let dispatchCount = 0;
    const result = await admitAndDispatchOwnerWalletExecution({
      authorizedOperation: authorization.authorizedOperation,
      resolveEvidence: async () => ({ ...evidence, lane: linkedLane }),
      dispatch: async () => {
        dispatchCount += 1;
      },
    });

    expect(result).toEqual({ kind: 'refused', reason: 'unsupported_lane' });
    expect(dispatchCount).toBe(0);
  });

  test('refuses stale material activation before dispatch', async () => {
    const authorization = await buildReusableAuthorizationCoreFixture();
    const evidence = await buildOwnerWalletExecutionEvidenceFixture();
    const result = await prepareOwnerWalletExecution({
      authorizedOperation: authorization.authorizedOperation,
      evidence: {
        ...evidence,
        expectedMaterialActivation: {
          ...evidence.expectedMaterialActivation,
          activationId: 'activation:stale',
        },
      },
    });

    expect(result).toEqual({ kind: 'refused', reason: 'material_activation_mismatch' });
  });

  test('does not resolve lane evidence after operation completion', async () => {
    const authorization = await buildReusableAuthorizationCoreFixture();
    const completed = await buildCompletedAuthorizedOperationFixture(authorization);
    let resolutionCount = 0;
    let dispatchCount = 0;
    const result = await admitAndDispatchOwnerWalletExecution({
      authorizedOperation: completed,
      resolveEvidence: async () => {
        resolutionCount += 1;
        return await buildOwnerWalletExecutionEvidenceFixture();
      },
      dispatch: async () => {
        dispatchCount += 1;
      },
    });

    expect(result).toEqual({ kind: 'refused', reason: 'operation_not_claimed' });
    expect(resolutionCount).toBe(0);
    expect(dispatchCount).toBe(0);
  });
});
