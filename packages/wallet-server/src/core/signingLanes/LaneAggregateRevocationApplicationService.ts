import type {
  LaneEnrollmentManifestChildV1,
  LaneEnrollmentRevocationResultV1,
  LaneProductEpochRecordV1,
  RevokeLaneEnrollmentV1,
  RevokeSigningLaneV1,
} from '@shared/signing-lanes';
import { computeLaneEnrollmentManifestDigestV1 } from '@shared/signing-lanes/rotationDigests';
import { parseRevokeLaneEnrollmentV1 } from '@shared/signing-lanes/rotationParsers';
import type { LaneLifecycleRevocationRequestV1 } from './LaneLifecycleApplicationService';
import { LaneEnrollmentRevocation } from './LaneEnrollmentRevocation';
import type { LaneLifecycleStore } from './LaneLifecycleStore';

export type LaneAggregateRevocationRequestV1 = {
  readonly command: RevokeLaneEnrollmentV1;
  readonly orderedChildren: readonly [
    LaneLifecycleRevocationRequestV1,
    ...LaneLifecycleRevocationRequestV1[],
  ];
};

export type LaneAggregateRevocationApplicationServiceOptionsV1 = {
  readonly lifecycleStore: Pick<
    LaneLifecycleStore,
    'getEnrollment' | 'fenceEnrollmentRevocation' | 'listEnrollmentProductEpochs'
  >;
  readonly laneLifecycle: LaneAggregateChildRevocationPortV1;
  readonly enrollmentRevocation: Pick<
    LaneEnrollmentRevocation,
    'completeLaneEnrollmentRevocationV1'
  >;
};

export interface LaneAggregateChildRevocationPortV1 {
  revokeSigningLaneV1(input: LaneLifecycleRevocationRequestV1): Promise<{
    readonly outcome: 'applied' | 'replayed' | 'conflict';
  }>;
}

export class LaneAggregateRevocationApplicationService {
  constructor(private readonly options: LaneAggregateRevocationApplicationServiceOptionsV1) {}

  /**
   * Establish the enrollment lifecycle fence before management revokes any
   * child authorization. The full aggregate path calls the same durable fence
   * again, so retries remain idempotent.
   */
  async fenceLaneEnrollmentV1(
    input: LaneAggregateRevocationRequestV1['command'],
  ): Promise<{ readonly kind: 'applied' | 'replayed' | 'conflict' }> {
    const command = parseRevokeLaneEnrollmentV1(input);
    const admission = await this.options.lifecycleStore.getEnrollment(command.enrollmentId);
    if (!admission) return { kind: 'conflict' };
    const manifestDigest = await computeLaneEnrollmentManifestDigestV1(admission.value.manifest);
    if (
      admission.value.manifest.walletId !== command.walletId ||
      manifestDigest !== command.manifestDigestB64u
    ) {
      return { kind: 'conflict' };
    }
    const fenced = await this.options.lifecycleStore.fenceEnrollmentRevocation(command);
    return fenced.outcome === 'conflict' ? { kind: 'conflict' } : { kind: fenced.outcome };
  }

  async revokeLaneEnrollmentV1(
    input: LaneAggregateRevocationRequestV1,
  ): Promise<LaneEnrollmentRevocationResultV1> {
    const command = parseRevokeLaneEnrollmentV1(input.command);
    const admission = await this.options.lifecycleStore.getEnrollment(command.enrollmentId);
    if (!admission) throw new Error('lane enrollment revocation target is missing');
    const manifestDigest = await computeLaneEnrollmentManifestDigestV1(admission.value.manifest);
    if (
      admission.value.manifest.walletId !== command.walletId ||
      manifestDigest !== command.manifestDigestB64u
    ) {
      throw new Error('lane enrollment revocation differs from its admitted manifest');
    }
    if (input.orderedChildren.length !== admission.value.manifest.orderedChildren.length) {
      throw new Error('lane enrollment revocation child count differs from its manifest');
    }

    const fenced = await this.options.lifecycleStore.fenceEnrollmentRevocation(command);
    if (fenced.outcome === 'conflict') {
      throw new Error(
        `lane enrollment revocation fence conflicted at version ${fenced.actualVersion}`,
      );
    }

    const products = await this.options.lifecycleStore.listEnrollmentProductEpochs(
      command.enrollmentId,
    );
    const productsByOperation = indexProducts(products);
    for (let index = 0; index < admission.value.manifest.orderedChildren.length; index += 1) {
      const manifestChild = admission.value.manifest.orderedChildren[index];
      const childRequest = input.orderedChildren[index];
      if (!manifestChild || !childRequest) {
        throw new Error('lane enrollment revocation child ordering is incomplete');
      }
      const product = productsByOperation.get(String(manifestChild.operationId));
      if (!product) {
        throw new Error(
          `lane enrollment revocation product is missing ${String(manifestChild.operationId)}`,
        );
      }
      assertAggregateChildMatches(command, manifestChild, product, childRequest);
      const result = await this.options.laneLifecycle.revokeSigningLaneV1(childRequest);
      if (result.outcome === 'conflict') {
        throw new Error(
          `lane enrollment child revocation conflicted for ${String(manifestChild.operationId)}`,
        );
      }
    }

    return await this.options.enrollmentRevocation.completeLaneEnrollmentRevocationV1({
      command,
      expectedVersion: fenced.version,
    });
  }
}

function indexProducts(
  products: readonly LaneProductEpochRecordV1[],
): ReadonlyMap<string, LaneProductEpochRecordV1> {
  const indexed = new Map<string, LaneProductEpochRecordV1>();
  for (const product of products) {
    const key = String(product.operationId);
    if (indexed.has(key)) throw new Error('lane enrollment product operation ids are duplicated');
    indexed.set(key, product);
  }
  return indexed;
}

function assertAggregateChildMatches(
  parent: RevokeLaneEnrollmentV1,
  manifest: LaneEnrollmentManifestChildV1,
  product: LaneProductEpochRecordV1,
  request: LaneLifecycleRevocationRequestV1,
): void {
  const command = request.command;
  const expectedCurve = manifest.keyFamily === 'ed25519' ? 'ed25519_yao' : 'ecdsa_additive';
  if (
    request.curve !== expectedCurve ||
    command.walletId !== parent.walletId ||
    command.walletKeyId !== manifest.walletKeyId ||
    command.laneId !== manifest.targetLaneId ||
    command.laneShareEpoch !== manifest.targetLaneShareEpoch ||
    command.requestedAtMs !== parent.requestedAtMs ||
    command.reason !== childReason(parent.reason) ||
    product.enrollmentId !== parent.enrollmentId ||
    product.operationId !== manifest.operationId ||
    product.walletId !== parent.walletId ||
    product.walletKeyId !== manifest.walletKeyId ||
    product.keyFamily !== manifest.keyFamily ||
    product.laneId !== manifest.targetLaneId ||
    product.laneShareEpoch !== manifest.targetLaneShareEpoch ||
    product.targetMaterialActivationId !== manifest.targetMaterialActivationId ||
    product.holderParticipant.participantBindingDigestB64u !==
      manifest.holderParticipantBindingDigestB64u ||
    product.signingWorkerParticipant.participantBindingDigestB64u !==
      manifest.signingWorkerParticipantBindingDigestB64u ||
    command.expectedRevocationEpoch !== expectedSourceRevocationEpoch(product)
  ) {
    throw new Error('lane enrollment child revocation differs from its admitted product');
  }
  if (
    (product.state === 'revocation_pending' || product.state === 'revoked') &&
    product.retirementEffectBindingDigestB64u !== command.retirementEffectBindingDigestB64u
  ) {
    throw new Error('lane enrollment child revocation changed its authorized effect binding');
  }
}

function expectedSourceRevocationEpoch(product: LaneProductEpochRecordV1): number {
  switch (product.state) {
    case 'pending_visibility':
    case 'active':
      return product.revocationEpoch;
    case 'revocation_pending':
    case 'revoked':
      if (product.revocationEpoch < 1) {
        throw new Error('lane enrollment child revocation epoch is invalid');
      }
      return product.revocationEpoch - 1;
    case 'retired':
      throw new Error('retired lane products cannot be revoked through an active enrollment');
  }
}

function childReason(reason: RevokeLaneEnrollmentV1['reason']): RevokeSigningLaneV1['reason'] {
  switch (reason) {
    case 'user_revoked':
      return 'user_revoked';
    case 'device_compromise':
      return 'device_compromise';
    case 'agent_compromise':
      return 'agent_compromise';
    case 'cancelled_after_commit':
    case 'expired_after_commit':
    case 'revoked_during_activation':
      return 'policy_revoked';
  }
}
