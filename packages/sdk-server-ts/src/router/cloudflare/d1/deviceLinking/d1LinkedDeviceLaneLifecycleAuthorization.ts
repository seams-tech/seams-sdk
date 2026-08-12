import { linkedDeviceEnrollmentBindingMatchesSourceV1 } from '@shared/device-linking/contracts';
import type {
  EcdsaAdditiveLaneJobV1,
  Ed25519YaoLaneJobV1,
  LaneProductEpochRecordV1,
  LaneOperationId,
  RotatableSigningLaneJobV1,
} from '@shared/signing-lanes';
import { parseLaneOperationId } from '@shared/signing-lanes/ids';
import { alphabetizeStringify } from '@shared/utils/digests';
import { mpcMaterialActivationRefsEqual } from '@shared/utils/domainIds';
import type {
  LaneLifecycleAuthorizationPortV1,
  LaneLifecycleAuthorizationRequestV1,
} from '../../../../core/signingLanes/LaneLifecycleApplicationService';
import type { LaneLifecycleStore } from '../../../../core/signingLanes/LaneLifecycleStore';
import type { D1LinkedDeviceOwnerPlanningSnapshotV1 } from './d1LinkedDeviceOwnerPlanningSnapshotStore';
import type { LinkedDeviceOwnerSourceChildResolutionV1 } from './d1LinkedDeviceTargetPlanner';

type SnapshotLookupV1 = {
  getByAuthorizedOperationV1(
    operationId: LaneOperationId,
  ): Promise<D1LinkedDeviceOwnerPlanningSnapshotV1 | null>;
};

type LifecycleLookupV1 = Pick<LaneLifecycleStore, 'getProductEpoch' | 'getProtocol'>;

export function createD1LinkedDeviceLaneLifecycleAuthorizationV1(input: {
  readonly snapshots: SnapshotLookupV1;
  readonly lifecycle: LifecycleLookupV1;
}): LaneLifecycleAuthorizationPortV1 {
  return new D1LinkedDeviceLaneLifecycleAuthorizationV1(input.snapshots, input.lifecycle);
}

class D1LinkedDeviceLaneLifecycleAuthorizationV1 implements LaneLifecycleAuthorizationPortV1 {
  constructor(
    private readonly snapshots: SnapshotLookupV1,
    private readonly lifecycle: LifecycleLookupV1,
  ) {}

  async authorizeLaneLifecycleV1(input: LaneLifecycleAuthorizationRequestV1): Promise<void> {
    switch (input.kind) {
      case 'record_lane_protocol_commit_v1':
      case 'activate_lane_server_material_v1':
        await authorizeLinkedJobV1(this.snapshots, input.job);
        return;
      case 'revoke_signing_lane_v1':
        await authorizeLinkedRevocationV1(this.lifecycle, input.curve, input.command);
        return;
    }
  }
}

async function authorizeLinkedJobV1(
  snapshots: SnapshotLookupV1,
  job: RotatableSigningLaneJobV1,
): Promise<void> {
  if (job.authorization.kind !== 'linked_device_enrollment') {
    throw new Error('linked-device lane execution requires linked-device enrollment authority');
  }
  const operationId = parseLaneOperationId(String(job.authorization.authorizedOperationId));
  if (!operationId.ok) throw new Error('linked-device authorized operation identity is invalid');
  const snapshot = await snapshots.getByAuthorizedOperationV1(operationId.value);
  if (!snapshot) throw new Error('linked-device owner planning snapshot is unavailable');
  const childIndex = snapshot.metadata.orderedKeyBindings.findIndex(
    (binding) =>
      binding.walletKeyId === job.walletKeyId &&
      binding.keyFamily === job.keyFamily &&
      binding.targetLaneId === job.target.laneId &&
      binding.targetLaneShareEpoch === job.target.laneShareEpoch,
  );
  if (childIndex < 0) throw new Error('linked-device lane job is absent from the owner plan');
  const binding = snapshot.metadata.orderedKeyBindings[childIndex];
  const child = snapshot.sourceChildren[childIndex];
  if (!binding || !child) throw new Error('linked-device owner plan child is incomplete');
  assertCommonJobMatchesPlanV1(snapshot, child, childIndex, job);
  assertCurveJobMatchesPlanV1(child, job);
}

function assertCommonJobMatchesPlanV1(
  snapshot: D1LinkedDeviceOwnerPlanningSnapshotV1,
  child: LinkedDeviceOwnerSourceChildResolutionV1,
  childIndex: number,
  job: RotatableSigningLaneJobV1,
): void {
  const binding = snapshot.metadata.orderedKeyBindings[childIndex];
  if (
    !binding ||
    snapshot.walletId !== job.walletId ||
    String(snapshot.metadata.operationId) !== String(job.authorization.authorizedOperationId) ||
    snapshot.metadata.idempotencyKey !== job.idempotencyKey ||
    snapshot.metadata.policyDigestB64u !== job.authorization.linkedDevicePermissionDigestB64u ||
    child.authorization.authorizedOperationId !== job.authorization.authorizedOperationId ||
    child.authorization.idempotencyKey !== job.idempotencyKey ||
    child.authorization.linkedDevicePermissionDigestB64u !==
      job.authorization.linkedDevicePermissionDigestB64u ||
    child.walletKeyId !== job.walletKeyId ||
    child.keyFamily !== job.keyFamily ||
    binding.sourceLaneId !== job.source.laneId ||
    binding.sourceLaneShareEpoch !== job.source.laneShareEpoch ||
    binding.sourceRevocationEpoch !== job.source.revocationEpoch ||
    !linkedDeviceEnrollmentBindingMatchesSourceV1(binding, job.source) ||
    binding.targetLaneId !== job.target.laneId ||
    binding.targetLaneShareEpoch !== job.target.laneShareEpoch ||
    !mpcMaterialActivationRefsEqual(child.source.materialActivation, job.source.materialActivation)
  ) {
    throw new Error('linked-device lane job differs from the persisted owner plan');
  }
}

function assertCurveJobMatchesPlanV1(
  child: LinkedDeviceOwnerSourceChildResolutionV1,
  job: RotatableSigningLaneJobV1,
): void {
  if (child.keyFamily === 'ed25519' && job.keyFamily === 'ed25519') {
    assertEd25519JobMatchesPlanV1(child, job);
    return;
  }
  if (child.keyFamily === 'ecdsa_secp256k1' && job.keyFamily === 'ecdsa_secp256k1') {
    assertEcdsaJobMatchesPlanV1(child, job);
    return;
  }
  throw new Error('linked-device lane curve differs from the persisted owner plan');
}

function assertEd25519JobMatchesPlanV1(
  child: Extract<LinkedDeviceOwnerSourceChildResolutionV1, { keyFamily: 'ed25519' }>,
  job: Ed25519YaoLaneJobV1,
): void {
  if (
    job.yaoRequestKind !== 'lane_provisioning' ||
    child.registeredPublicKeyB64u !== job.registeredPublicKeyB64u ||
    child.nearEd25519SigningKeyId !== job.nearEd25519SigningKeyId ||
    child.keyCreationSignerSlot !== job.keyCreationSignerSlot ||
    child.stableContextBindingB64u !== job.stableContextBindingB64u
  ) {
    throw new Error('linked-device Ed25519 lane job differs from the persisted owner plan');
  }
}

function assertEcdsaJobMatchesPlanV1(
  child: Extract<LinkedDeviceOwnerSourceChildResolutionV1, { keyFamily: 'ecdsa_secp256k1' }>,
  job: EcdsaAdditiveLaneJobV1,
): void {
  if (
    child.evmFamilySigningKeySlotId !== job.evmFamilySigningKeySlotId ||
    child.thresholdPublicKey33B64u !== job.thresholdPublicKey33B64u ||
    child.evmAddress !== job.evmAddress ||
    alphabetizeStringify(child.sourceCapability) !== alphabetizeStringify(job.sourceCapability) ||
    child.sourceHolderVerifyingShare33B64u !== job.sourceHolderVerifyingShare33B64u ||
    child.sourceServerVerifyingShare33B64u !== job.sourceServerVerifyingShare33B64u
  ) {
    throw new Error('linked-device ECDSA lane job differs from the persisted owner plan');
  }
}

async function authorizeLinkedRevocationV1(
  lifecycle: LifecycleLookupV1,
  curve: 'ed25519_yao' | 'ecdsa_additive',
  command: Parameters<LaneLifecycleStore['getProductEpoch']>[0] & {
    readonly expectedRevocationEpoch: number;
  },
): Promise<void> {
  const product = await lifecycle.getProductEpoch(command);
  if (!product) throw new Error('linked-device lane product is unavailable for revocation');
  assertLinkedProductMatchesRevocationV1(product, curve, command.expectedRevocationEpoch);
  const protocol = await lifecycle.getProtocol(product.operationId);
  if (
    !protocol ||
    protocol.value.job.authorization.kind !== 'linked_device_enrollment' ||
    protocol.value.job.walletId !== command.walletId ||
    protocol.value.job.walletKeyId !== command.walletKeyId ||
    protocol.value.job.target.laneId !== command.laneId ||
    protocol.value.job.target.laneShareEpoch !== command.laneShareEpoch
  ) {
    throw new Error('linked-device lane protocol does not authorize revocation');
  }
}

function assertLinkedProductMatchesRevocationV1(
  product: LaneProductEpochRecordV1,
  curve: 'ed25519_yao' | 'ecdsa_additive',
  expectedRevocationEpoch: number,
): void {
  const expectedFamily = curve === 'ed25519_yao' ? 'ed25519' : 'ecdsa_secp256k1';
  if (
    product.laneKind !== 'linked_device' ||
    product.keyFamily !== expectedFamily ||
    product.revocationEpoch !== expectedRevocationEpoch ||
    (product.state !== 'active' && product.state !== 'revocation_pending')
  ) {
    throw new Error('lane revocation target is not the exact linked-device product epoch');
  }
}
