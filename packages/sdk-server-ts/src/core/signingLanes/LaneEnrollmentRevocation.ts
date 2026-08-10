import type {
  CommitLaneEnrollmentRevocationV1,
  CompleteSigningLaneRevocationV1,
  AggregateLaneRevocationReceiptV1,
  LaneSigningLaneRevocationResultV1,
  LaneSigningLaneRevocationFenceResultV1,
  LaneEnrollmentRevocationResultV1,
  LaneEnrollmentGatewayV1,
  RevokeLaneEnrollmentV1,
  RevokeSigningLaneV1,
  LaneProductEpochRecordV1,
} from '@shared/signing-lanes';
import {
  computeAggregateLaneRevocationReceiptDigestV1,
  computeLaneEnrollmentManifestDigestV1,
  computeRevokeSigningLaneDigestV1,
} from '@shared/signing-lanes/rotationDigests';
import { base64UrlEncode } from '@shared/utils/base64';
import { sha256BytesUtf8 } from '@shared/utils/digests';
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

  async revokeLaneEnrollmentV1(
    input: RevokeLaneEnrollmentV1,
  ): Promise<LaneEnrollmentRevocationResultV1> {
    const admission = await this.lifecycleStore.getEnrollment(input.enrollmentId);
    if (!admission || String(admission.value.manifest.walletId) !== String(input.walletId)) {
      return {
        kind: 'lane_enrollment_revocation_result_v1',
        outcome: 'conflict',
        enrollmentId: input.enrollmentId,
        expectedVersion: 1,
        actualVersion: admission?.version ?? 0,
        requestedCommandDigestB64u: input.manifestDigestB64u,
        storedCommandDigestB64u: admission?.commandDigestB64u ?? '',
      };
    }
    const manifestDigest = await computeLaneEnrollmentManifestDigestV1(admission.value.manifest);
    if (manifestDigest !== input.manifestDigestB64u) {
      return {
        kind: 'lane_enrollment_revocation_result_v1',
        outcome: 'conflict',
        enrollmentId: input.enrollmentId,
        expectedVersion: admission.version,
        actualVersion: admission.version,
        requestedCommandDigestB64u: input.manifestDigestB64u,
        storedCommandDigestB64u: manifestDigest,
      };
    }
    const fence = await this.lifecycleStore.fenceEnrollmentRevocation(input);
    if (fence.outcome === 'conflict') {
      return {
        kind: 'lane_enrollment_revocation_result_v1',
        outcome: 'conflict',
        enrollmentId: input.enrollmentId,
        expectedVersion: fence.expectedVersion ?? 0,
        actualVersion: fence.actualVersion,
        requestedCommandDigestB64u: fence.requestedCommandDigestB64u,
        storedCommandDigestB64u: fence.storedCommandDigestB64u,
      };
    }
    const epochs = (
      await this.lifecycleStore.listEnrollmentProductEpochs(input.enrollmentId)
    ).filter(
      (
        epoch,
      ): epoch is Extract<
        LaneProductEpochRecordV1,
        { state: 'pending_visibility' | 'active' | 'revoked' }
      > => epoch.state !== 'retired',
    );
    const orderedEpochs = admission.value.manifest.orderedChildren.map((child) => {
      const epoch = epochs.find(
        (candidate) => String(candidate.operationId) === String(child.operationId),
      );
      if (!epoch)
        throw new Error(
          `lane enrollment revocation is missing product epoch ${String(child.operationId)}`,
        );
      return epoch;
    });
    const children = await Promise.all(
      orderedEpochs.map(async (epoch) => ({
        operationId: epoch.operationId,
        walletKeyId: epoch.walletKeyId,
        targetLaneId: epoch.laneId,
        targetLaneShareEpoch: epoch.laneShareEpoch,
        targetMaterialActivation: epoch.materialActivation,
        revocationEpoch: epoch.state === 'revoked' ? epoch.revocationEpoch : 1,
        retirementReceiptDigestB64u:
          epoch.state === 'revoked'
            ? epoch.revocationReceiptDigestB64u
            : await digestRetirementBinding(input, epoch),
      })),
    );
    const first = children[0];
    if (!first) throw new Error('lane enrollment revocation requires product epochs');
    const receipt: AggregateLaneRevocationReceiptV1 = {
      kind: 'aggregate_lane_revocation_receipt_v1',
      enrollmentId: input.enrollmentId,
      walletId: input.walletId,
      manifestDigestB64u: input.manifestDigestB64u,
      orderedChildReceipts: [first, ...children.slice(1)],
      revokedAtMs: input.requestedAtMs,
    };
    const digest = await computeAggregateLaneRevocationReceiptDigestV1(receipt);
    const command: CommitLaneEnrollmentRevocationV1 = {
      kind: 'commit_lane_enrollment_revocation_v1',
      enrollmentId: input.enrollmentId,
      walletId: input.walletId,
      manifestDigestB64u: input.manifestDigestB64u,
      receipt,
      revokedAtMs: input.requestedAtMs,
    };
    return await this.commitEnrollment({
      command,
      expectedVersion: fence.version,
      commandDigestB64u: digest,
    });
  }
}

async function digestRetirementBinding(
  input: RevokeLaneEnrollmentV1,
  epoch: Extract<LaneProductEpochRecordV1, { state: 'pending_visibility' | 'active' }>,
): Promise<string> {
  const activation = epoch.materialActivation;
  const encoded = [
    'seams/rotatable-signing-lanes/server-retirement-binding/v1',
    String(input.enrollmentId),
    String(input.walletId),
    input.manifestDigestB64u,
    input.reason,
    String(input.requestedAtMs),
    String(epoch.operationId),
    String(epoch.walletKeyId),
    String(epoch.laneId),
    String(epoch.laneShareEpoch),
    String(activation.activationId),
    String(activation.capability),
    String(activation.materialOwner),
    String(activation.keyBinding),
    String(activation.lifecycleBinding),
    String(activation.signingWorker),
  ].join('\u0000');
  return base64UrlEncode(await sha256BytesUtf8(encoded));
}
