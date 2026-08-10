import type {
  CommitLaneEnrollmentRevocationV1,
  CompleteSigningLaneRevocationV1,
  LaneProductEpochRecordV1,
  LaneSigningLaneRevocationResultV1,
  LaneSigningLaneRevocationFenceResultV1,
  LaneEnrollmentRevocationResultV1,
  RevokeLaneEnrollmentV1,
  RevokeSigningLaneV1,
} from '@shared/signing-lanes';
import {
  computeLaneEnrollmentManifestDigestV1,
  computeRevokeSigningLaneDigestV1,
} from '@shared/signing-lanes/rotationDigests';
import {
  buildAggregateLaneRevocationReceiptV1,
  buildCommitLaneEnrollmentRevocationV1,
  parseRevokeLaneEnrollmentV1,
} from '@shared/signing-lanes/rotationParsers';
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

  async completeLaneEnrollmentRevocationV1(input: {
    readonly command: RevokeLaneEnrollmentV1;
    readonly expectedVersion: number;
  }): Promise<LaneEnrollmentRevocationResultV1> {
    const command = parseRevokeLaneEnrollmentV1(input.command);
    const admission = await this.lifecycleStore.getEnrollment(command.enrollmentId);
    if (!admission) throw new Error('lane enrollment is not admitted');
    if (String(admission.value.manifest.walletId) !== String(command.walletId)) {
      throw new Error('lane enrollment revocation wallet differs from its manifest');
    }
    const manifestDigest = await computeLaneEnrollmentManifestDigestV1(admission.value.manifest);
    if (manifestDigest !== command.manifestDigestB64u) {
      throw new Error('lane enrollment revocation manifest differs from its admission');
    }

    const productEpochs = await this.lifecycleStore.listEnrollmentProductEpochs(
      command.enrollmentId,
    );
    if (productEpochs.length !== admission.value.manifest.orderedChildren.length) {
      throw new Error('lane enrollment revocation product count differs from its manifest');
    }
    const productsByOperation = new Map(
      productEpochs.map((product) => [String(product.operationId), product]),
    );
    const orderedProducts = admission.value.manifest.orderedChildren.map((child) => {
      const product = productsByOperation.get(String(child.operationId));
      if (!product)
        throw new Error(`lane enrollment product is missing ${String(child.operationId)}`);
      return product;
    });
    if (productsByOperation.size !== productEpochs.length) {
      throw new Error('lane enrollment revocation product operation ids are duplicated');
    }
    const first = orderedProducts[0];
    if (!first) throw new Error('lane enrollment revocation requires product epochs');
    const revokedAtMs = first.state === 'revoked' ? first.revokedAtMs : undefined;
    if (revokedAtMs === undefined || revokedAtMs !== command.requestedAtMs) {
      throw new Error('lane enrollment revocation timestamp differs from its product epochs');
    }
    const orderedChildReceipts = orderedProducts.map((product, index) => {
      const child = admission.value.manifest.orderedChildren[index];
      if (product.state !== 'revoked') {
        throw new Error(
          `lane enrollment product ${String(child.operationId)} is not durably revoked`,
        );
      }
      assertRevokedProductMatchesManifest(product, child, command.walletId, command.enrollmentId);
      if (product.revokedAtMs !== revokedAtMs) {
        throw new Error('lane enrollment product revocation timestamps differ');
      }
      return {
        operationId: product.operationId,
        walletKeyId: product.walletKeyId,
        targetLaneId: product.laneId,
        targetLaneShareEpoch: product.laneShareEpoch,
        targetMaterialActivation: product.materialActivation,
        revocationEpoch: product.revocationEpoch,
        retirementReceiptDigestB64u: product.revocationReceiptDigestB64u,
      };
    });
    const firstChildReceipt = orderedChildReceipts[0];
    if (!firstChildReceipt) throw new Error('lane enrollment revocation requires child receipts');
    const receipt = buildAggregateLaneRevocationReceiptV1({
      enrollmentId: command.enrollmentId,
      walletId: command.walletId,
      manifestDigestB64u: command.manifestDigestB64u,
      orderedChildReceipts: [firstChildReceipt, ...orderedChildReceipts.slice(1)],
      revokedAtMs,
    });
    const commit: CommitLaneEnrollmentRevocationV1 = buildCommitLaneEnrollmentRevocationV1({
      enrollmentId: command.enrollmentId,
      walletId: command.walletId,
      manifestDigestB64u: command.manifestDigestB64u,
      receipt,
      revokedAtMs,
    });
    return await this.commitEnrollment({
      command: commit,
      expectedVersion: input.expectedVersion,
      commandDigestB64u: await digestLaneEnrollmentRevocationCommand(command),
    });
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

function assertRevokedProductMatchesManifest(
  product: Extract<LaneProductEpochRecordV1, { state: 'revoked' }>,
  child: import('@shared/signing-lanes').LaneEnrollmentManifestChildV1,
  walletId: RevokeLaneEnrollmentV1['walletId'],
  enrollmentId: RevokeLaneEnrollmentV1['enrollmentId'],
): void {
  if (
    String(product.walletId) !== String(walletId) ||
    String(product.enrollmentId) !== String(enrollmentId) ||
    String(product.operationId) !== String(child.operationId) ||
    String(product.walletKeyId) !== String(child.walletKeyId) ||
    product.keyFamily !== child.keyFamily ||
    String(product.laneId) !== String(child.targetLaneId) ||
    String(product.laneShareEpoch) !== String(child.targetLaneShareEpoch) ||
    String(product.targetMaterialActivationId) !== String(child.targetMaterialActivationId) ||
    String(product.materialActivation.activationId) !== String(child.targetMaterialActivationId) ||
    product.holderParticipant.participantBindingDigestB64u !==
      child.holderParticipantBindingDigestB64u ||
    product.signingWorkerParticipant.participantBindingDigestB64u !==
      child.signingWorkerParticipantBindingDigestB64u
  ) {
    throw new Error('lane enrollment product differs from its admitted manifest child');
  }
}

async function digestLaneEnrollmentRevocationCommand(
  input: RevokeLaneEnrollmentV1,
): Promise<string> {
  const encoded = [
    'seams/rotatable-signing-lanes/revoke-enrollment/v1',
    String(input.enrollmentId),
    String(input.walletId),
    input.manifestDigestB64u,
    input.reason,
    String(input.requestedAtMs),
  ].join('\u0000');
  return base64UrlEncode(await sha256BytesUtf8(encoded));
}
