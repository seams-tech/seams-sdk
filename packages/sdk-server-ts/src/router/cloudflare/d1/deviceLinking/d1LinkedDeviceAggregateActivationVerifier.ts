import { parseLaneEnrollmentId } from '@shared/signing-lanes/ids';
import { computeLaneEnrollmentManifestDigestV1 } from '@shared/signing-lanes/rotationDigests';
import { computeLaneParticipantSetBindingDigestV1 } from '@shared/signing-lanes/participantDigest';
import type {
  LaneEnrollmentManifestChildV1,
  LaneEnrollmentManifestV1,
  LaneProductEpochRecordV1,
} from '@shared/signing-lanes';
import { mpcMaterialActivationRefsEqual } from '@shared/utils/domainIds';
import type { LaneLifecycleStore } from '../../../../core/signingLanes/LaneLifecycleStore';
import type {
  LinkedDeviceAggregateActivationVerifierV1,
} from '../../../../core/deviceLinking/linkedDeviceSession';
import type { LinkedDeviceEnrollmentChildReceiptV1 } from '@shared/device-linking/contracts';

type ActiveLaneProductEpochV1 = Extract<LaneProductEpochRecordV1, { readonly state: 'active' }>;

export type D1LinkedDeviceAggregateActivationVerifierOptionsV1 = {
  readonly lifecycleStore: Pick<
    LaneLifecycleStore,
    'getEnrollment' | 'getProtocol' | 'listEnrollmentProductEpochs'
  >;
};

export class D1LinkedDeviceAggregateActivationVerifierV1
  implements LinkedDeviceAggregateActivationVerifierV1
{
  private readonly lifecycleStore: D1LinkedDeviceAggregateActivationVerifierOptionsV1['lifecycleStore'];

  constructor(options: D1LinkedDeviceAggregateActivationVerifierOptionsV1) {
    this.lifecycleStore = options.lifecycleStore;
  }

  async verifyAggregateActivationV1(
    input: Parameters<
      LinkedDeviceAggregateActivationVerifierV1['verifyAggregateActivationV1']
    >[0],
  ): Promise<Awaited<ReturnType<LinkedDeviceAggregateActivationVerifierV1['verifyAggregateActivationV1']>>> {
    try {
      const parsedEnrollmentId = parseLaneEnrollmentId(String(input.enrollmentId));
      if (!parsedEnrollmentId.ok) return rejected('R102 lane enrollment id is invalid');
      const enrollment = await this.lifecycleStore.getEnrollment(parsedEnrollmentId.value);
      if (!enrollment) return rejected('R102 lane enrollment is not admitted');
      const { manifest, lifecycle } = enrollment.value;
      const manifestDigestB64u = await computeLaneEnrollmentManifestDigestV1(manifest);
      if (
        manifestDigestB64u !== input.manifestDigestB64u ||
        String(manifest.enrollmentId) !== String(parsedEnrollmentId.value) ||
        manifest.walletId !== input.walletId
      ) {
        return rejected('R102 lane enrollment manifest identity or digest differs');
      }
      if (
        manifest.authorization.kind !== 'linked_device_enrollment' ||
        manifest.authorization.linkedDeviceEnrollmentId !== input.enrollmentId
      ) {
        return rejected('R102 lane enrollment is not bound to the linked device');
      }
      if (lifecycle.state !== 'active' || lifecycle.manifestDigestB64u !== manifestDigestB64u) {
        return rejected('R102 lane enrollment is not active for linked-device activation');
      }
      const products = await this.lifecycleStore.listEnrollmentProductEpochs(parsedEnrollmentId.value);
      await verifyProductsAndProtocols({
        lifecycleStore: this.lifecycleStore,
        manifest,
        products,
        enrollmentId: parsedEnrollmentId.value,
        walletId: input.walletId,
        manifestDigestB64u,
        aggregateReceiptDigestB64u: lifecycle.aggregateReceiptDigestB64u,
        linkedDevicePermissionDigestB64u: manifest.authorization.linkedDevicePermissionDigestB64u,
        orderedChildReceipts: input.orderedChildReceipts,
      });
      return { kind: 'verified' };
    } catch (error: unknown) {
      return rejected(error instanceof Error ? error.message : String(error));
    }
  }
}

async function verifyProductsAndProtocols(input: {
  readonly lifecycleStore: D1LinkedDeviceAggregateActivationVerifierOptionsV1['lifecycleStore'];
  readonly manifest: LaneEnrollmentManifestV1;
  readonly products: readonly LaneProductEpochRecordV1[];
  readonly enrollmentId: LaneEnrollmentManifestV1['enrollmentId'];
  readonly walletId: LaneEnrollmentManifestV1['walletId'];
  readonly manifestDigestB64u: string;
  readonly aggregateReceiptDigestB64u: string;
  readonly linkedDevicePermissionDigestB64u: string;
  readonly orderedChildReceipts: readonly LinkedDeviceEnrollmentChildReceiptV1[];
}): Promise<void> {
  if (
    input.products.length !== input.manifest.orderedChildren.length ||
    input.orderedChildReceipts.length !== input.manifest.orderedChildren.length
  ) {
    throw new Error('R102 target coverage does not match the approved manifest count');
  }

  const productsByOperation = new Map<string, ActiveLaneProductEpochV1>();
  const productCoverage = new Set<string>();
  for (const product of input.products) {
    if (product.state !== 'active') throw new Error('R102 target product is not active');
    if (product.aggregateManifestDigestB64u !== input.manifestDigestB64u) {
      throw new Error('R102 target product manifest digest differs');
    }
    const operationKey = String(product.operationId);
    if (productsByOperation.has(operationKey)) {
      throw new Error('R102 target products contain duplicate operations');
    }
    productsByOperation.set(operationKey, product);
    const coverageKey = targetCoverageKey(
      product.walletKeyId,
      product.laneId,
      product.laneShareEpoch,
    );
    if (productCoverage.has(coverageKey)) throw new Error('R102 target products contain duplicate coverage');
    productCoverage.add(coverageKey);
  }

  const manifestOperations = new Set<string>();
  const manifestCoverage = new Set<string>();
  const receiptCoverage = new Set<string>();
  const receiptMaterialIds = new Set<string>();
  for (let index = 0; index < input.manifest.orderedChildren.length; index += 1) {
    const manifestChild = input.manifest.orderedChildren[index];
    const receiptChild = input.orderedChildReceipts[index];
    if (!manifestChild || !receiptChild) throw new Error('R102 target coverage order is invalid');
    const operationKey = String(manifestChild.operationId);
    if (manifestOperations.has(operationKey)) {
      throw new Error('R102 manifest contains duplicate operations');
    }
    manifestOperations.add(operationKey);
    const coverageKey = targetCoverageKey(
      manifestChild.walletKeyId,
      manifestChild.targetLaneId,
      manifestChild.targetLaneShareEpoch,
    );
    if (manifestCoverage.has(coverageKey)) throw new Error('R102 manifest contains duplicate coverage');
    manifestCoverage.add(coverageKey);
    const receiptKey = targetCoverageKey(
      receiptChild.walletKeyId,
      receiptChild.targetLaneId,
      receiptChild.targetLaneShareEpoch,
    );
    if (receiptCoverage.has(receiptKey)) throw new Error('linked-device receipt contains duplicate coverage');
    receiptCoverage.add(receiptKey);
    const materialId = String(receiptChild.materialActivation.activationId);
    if (receiptMaterialIds.has(materialId)) {
      throw new Error('linked-device receipt contains duplicate material activation');
    }
    receiptMaterialIds.add(materialId);
    const product = productsByOperation.get(operationKey);
    if (!product) throw new Error('R102 target product is missing for manifest child');
    await verifyProtocolAndProduct({
      lifecycleStore: input.lifecycleStore,
      manifestChild,
      receiptChild,
      product,
      enrollmentId: input.enrollmentId,
      walletId: input.walletId,
      manifestDigestB64u: input.manifestDigestB64u,
      aggregateReceiptDigestB64u: input.aggregateReceiptDigestB64u,
      linkedDevicePermissionDigestB64u: input.linkedDevicePermissionDigestB64u,
    });
  }
}

async function verifyProtocolAndProduct(input: {
  readonly lifecycleStore: D1LinkedDeviceAggregateActivationVerifierOptionsV1['lifecycleStore'];
  readonly manifestChild: LaneEnrollmentManifestChildV1;
  readonly receiptChild: LinkedDeviceEnrollmentChildReceiptV1;
  readonly product: ActiveLaneProductEpochV1;
  readonly enrollmentId: LaneEnrollmentManifestV1['enrollmentId'];
  readonly walletId: LaneEnrollmentManifestV1['walletId'];
  readonly manifestDigestB64u: string;
  readonly aggregateReceiptDigestB64u: string;
  readonly linkedDevicePermissionDigestB64u: string;
}): Promise<void> {
  const { manifestChild, receiptChild, product } = input;
  const participantSetBindingDigestB64u = await computeLaneParticipantSetBindingDigestV1({
    holderParticipant: product.holderParticipant,
    signingWorkerParticipant: product.signingWorkerParticipant,
  });
  if (
    product.enrollmentId !== input.enrollmentId ||
    product.walletId !== input.walletId ||
    product.walletKeyId !== manifestChild.walletKeyId ||
    product.keyFamily !== manifestChild.keyFamily ||
    product.laneKind !== 'linked_device' ||
    product.laneId !== manifestChild.targetLaneId ||
    product.laneShareEpoch !== manifestChild.targetLaneShareEpoch ||
    product.targetMaterialActivationId !== manifestChild.targetMaterialActivationId ||
    product.materialActivation.activationId !== manifestChild.targetMaterialActivationId ||
    product.holderParticipant.participantBindingDigestB64u !==
      manifestChild.holderParticipantBindingDigestB64u ||
    product.signingWorkerParticipant.participantBindingDigestB64u !==
      manifestChild.signingWorkerParticipantBindingDigestB64u ||
    product.participantSetBindingDigestB64u !== participantSetBindingDigestB64u
  ) {
    throw new Error('R102 target product does not match manifest child');
  }
  if (
    String(receiptChild.enrollmentId) !== String(input.enrollmentId) ||
    receiptChild.walletId !== input.walletId ||
    receiptChild.walletKeyId !== manifestChild.walletKeyId ||
    receiptChild.keyFamily !== manifestChild.keyFamily ||
    receiptChild.targetLaneId !== manifestChild.targetLaneId ||
    receiptChild.targetLaneShareEpoch !== manifestChild.targetLaneShareEpoch ||
    receiptChild.materialActivation.activationId !== manifestChild.targetMaterialActivationId ||
    !mpcMaterialActivationRefsEqual(product.materialActivation, receiptChild.materialActivation)
  ) {
    throw new Error('linked-device receipt does not match R102 target material');
  }
  const protocol = await input.lifecycleStore.getProtocol(manifestChild.operationId);
  if (!protocol || protocol.value.lifecycle.state !== 'active') {
    throw new Error('R102 target protocol is not active');
  }
  const job = protocol.value.job;
  if (
    job.operationId !== manifestChild.operationId ||
    job.enrollmentId !== input.enrollmentId ||
    job.walletId !== input.walletId ||
    job.walletKeyId !== manifestChild.walletKeyId ||
    job.keyFamily !== manifestChild.keyFamily ||
    job.target.laneId !== manifestChild.targetLaneId ||
    job.target.laneShareEpoch !== manifestChild.targetLaneShareEpoch ||
    job.targetMaterialActivationId !== manifestChild.targetMaterialActivationId ||
    job.source.laneId !== manifestChild.sourceLaneId ||
    job.source.laneShareEpoch !== manifestChild.sourceLaneShareEpoch ||
    job.source.revocationEpoch !== manifestChild.sourceRevocationEpoch ||
    !mpcMaterialActivationRefsEqual(job.source.materialActivation, manifestChild.sourceMaterialActivation) ||
    job.targetHolder.participantBindingDigestB64u !== manifestChild.holderParticipantBindingDigestB64u ||
    job.targetSigningWorker.participantBindingDigestB64u !==
      manifestChild.signingWorkerParticipantBindingDigestB64u ||
    job.authorization.kind !== 'linked_device_enrollment' ||
    String(job.authorization.linkedDeviceEnrollmentId) !== String(input.enrollmentId) ||
    job.authorization.linkedDevicePermissionDigestB64u !==
      input.linkedDevicePermissionDigestB64u ||
    product.aggregateManifestDigestB64u !== input.manifestDigestB64u ||
    product.aggregateActivationReceiptDigestB64u !== input.aggregateReceiptDigestB64u ||
    protocol.value.lifecycle.aggregateActivationReceiptDigestB64u !== input.aggregateReceiptDigestB64u
  ) {
    throw new Error('R102 target protocol does not match manifest or activation');
  }
}

function targetCoverageKey(walletKeyId: unknown, laneId: unknown, laneShareEpoch: unknown): string {
  return [String(walletKeyId), String(laneId), String(laneShareEpoch)].join('\u0000');
}

function rejected(message: string): { readonly kind: 'rejected'; readonly message: string } {
  return { kind: 'rejected', message };
}
