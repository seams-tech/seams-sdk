import type {
  CommitLaneEnrollmentRevocationV1,
  CompleteSigningLaneRevocationV1,
  LaneSigningLaneRevocationResultV1,
  LaneSigningLaneRevocationFenceResultV1,
  LaneEnrollmentRevocationResultV1,
  LaneEnrollmentGatewayV1,
  RevokeLaneEnrollmentV1,
  RevokeSigningLaneV1,
} from '@shared/signing-lanes';
import { computeRevokeSigningLaneDigestV1 } from '@shared/signing-lanes/rotationDigests';
import type { LaneLifecycleStore } from './LaneLifecycleStore';

/**
 * Revocation is intentionally separate from activation. The fence write must
 * land before any caller asks a participant to retire material; this class
 * only owns the Gateway-side lifecycle boundary.
 */
export class LaneEnrollmentRevocation {
  constructor(private readonly lifecycleStore: LaneLifecycleStore) {}

  async fenceEnrollment(input: RevokeLaneEnrollmentV1): Promise<void> {
    const result = await this.lifecycleStore.fenceEnrollmentRevocation(input);
    if (result.outcome === 'conflict') {
      throw new Error(
        `lane enrollment revocation fence conflicted at version ${result.actualVersion}`,
      );
    }
  }

  async commitEnrollment(input: {
    readonly command: CommitLaneEnrollmentRevocationV1;
    readonly expectedVersion: number;
    readonly commandDigestB64u: string;
  }): Promise<LaneEnrollmentRevocationResultV1> {
    const result = await this.lifecycleStore.commitEnrollmentRevocation(input);
    if (result.outcome === 'conflict')
      return { kind: 'lane_enrollment_revocation_result_v1', ...result };
    const productEpochs = result.productEpochs.filter(
      (epoch): epoch is Extract<(typeof result.productEpochs)[number], { state: 'revoked' }> =>
        epoch.state === 'revoked',
    );
    const first = productEpochs[0];
    if (!first) throw new Error('lane revocation returned no revoked product epochs');
    return {
      kind: 'lane_enrollment_revocation_result_v1',
      outcome: result.outcome,
      enrollmentId: input.command.enrollmentId,
      version: result.version,
      commandDigestB64u: result.commandDigestB64u,
      receipt: result.receipt,
      lifecycle: result.lifecycle,
      productEpochs: [first, ...productEpochs.slice(1)],
    };
  }

  async fenceSigningLaneRevocationV1(
    input: RevokeSigningLaneV1,
  ): Promise<LaneSigningLaneRevocationFenceResultV1> {
    const commandDigestB64u = await computeRevokeSigningLaneDigestV1(input);
    const result = await this.lifecycleStore.fenceLaneRevocation(input);
    if (result.outcome === 'conflict') {
      return {
        kind: 'lane_signing_lane_revocation_fence_result_v1',
        outcome: 'conflict',
        walletKeyId: input.walletKeyId,
        laneId: input.laneId,
        laneShareEpoch: input.laneShareEpoch,
        expectedVersion: result.expectedVersion,
        actualVersion: result.actualVersion,
        requestedCommandDigestB64u: result.requestedCommandDigestB64u,
        storedCommandDigestB64u: result.storedCommandDigestB64u,
      };
    }
    if (result.outcome === 'already_completed') {
      return {
        kind: 'lane_signing_lane_revocation_fence_result_v1',
        outcome: 'already_completed',
        walletKeyId: input.walletKeyId,
        laneId: input.laneId,
        laneShareEpoch: input.laneShareEpoch,
        version: result.version,
        commandDigestB64u,
        productEpoch: result.productEpoch,
        retirementReceipt: result.retirementReceipt,
      };
    }
    return {
      kind: 'lane_signing_lane_revocation_fence_result_v1',
      outcome: result.outcome,
      walletKeyId: input.walletKeyId,
      laneId: input.laneId,
      laneShareEpoch: input.laneShareEpoch,
      version: result.version,
      commandDigestB64u,
      productEpoch: result.productEpoch,
    };
  }

  async completeSigningLaneRevocationV1(
    input: CompleteSigningLaneRevocationV1,
  ): Promise<LaneSigningLaneRevocationResultV1> {
    const result = await this.lifecycleStore.commitLaneRevocation({ completion: input });
    if (result.outcome === 'conflict') {
      return {
        kind: 'lane_signing_lane_revocation_result_v1',
        outcome: 'conflict',
        walletKeyId: input.command.walletKeyId,
        laneId: input.command.laneId,
        laneShareEpoch: input.command.laneShareEpoch,
        expectedVersion: result.expectedVersion,
        actualVersion: result.actualVersion,
        requestedCommandDigestB64u: result.requestedCommandDigestB64u,
        storedCommandDigestB64u: result.storedCommandDigestB64u,
      };
    }
    return {
      kind: 'lane_signing_lane_revocation_result_v1',
      outcome: result.outcome,
      walletKeyId: input.command.walletKeyId,
      laneId: input.command.laneId,
      laneShareEpoch: input.command.laneShareEpoch,
      version: result.version,
      commandDigestB64u: result.commandDigestB64u,
      productEpoch: result.productEpoch,
      retirementReceipt: result.retirementReceipt,
    };
  }
}
