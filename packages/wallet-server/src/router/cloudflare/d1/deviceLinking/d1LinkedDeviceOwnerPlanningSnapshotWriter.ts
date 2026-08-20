import type {
  LinkedDeviceOwnerSourceLaneV1,
  QrLinkedDeviceSessionPayloadV5,
} from '@shared/device-linking/contracts';
import {
  parseLinkedDeviceOwnerSourceLaneV1,
  parseQrLinkedDeviceSessionPayloadV5,
} from '@shared/device-linking/parsers';
import { parseAuthorizedOperationId } from '@shared/authorization/capabilityKinds';
import { parseDigestB64u } from '@shared/utils/canonicalPrimitives';
import type { EcdsaSourceCapabilityBindingV1 } from '@shared/signing-lanes/rotation';
import type { WalletId } from '@shared/utils/domainIds';
import type {
  ActiveOwnerWalletExecutionLaneProjection,
  WalletExecutionLaneProjectionResult,
} from '../../../../core/signingLanes/WalletExecutionLaneProjection';
import type { RouterApiWalletRegistrationService } from '../../../framework/authServicePort';
import type { DeviceLinkingOwnerWalletSessionContextV1 } from '../../../../router/transport/fetch/routes/deviceLinkingOwnerAuthorization';
import type {
  D1LinkedDeviceOwnerPlanningSnapshotMutationV1,
  D1LinkedDeviceOwnerPlanningSnapshotStoreV1,
  D1LinkedDeviceOwnerPlanningSnapshotInputV1,
} from './d1LinkedDeviceOwnerPlanningSnapshotStore';
import type { D1LinkedDeviceOwnerAuthorizationMetadataV1 } from './d1LinkedDeviceOwnerAuthorizationProvider';
import type { LinkedDeviceOwnerSourceChildResolutionV1 } from './d1LinkedDeviceTargetPlanner';

type NonEmpty<T> = readonly [T, ...T[]];

type DeploymentChildBaseV1 = {
  readonly keyFamily: 'ed25519' | 'ecdsa_secp256k1';
};

export type D1LinkedDeviceOwnerPlanningDeploymentChildV1 =
  | (DeploymentChildBaseV1 & {
      readonly keyFamily: 'ed25519';
      readonly applicationBindingDigestB64u: string;
      readonly stableContextBindingB64u: string;
    })
  | (DeploymentChildBaseV1 & {
      readonly keyFamily: 'ecdsa_secp256k1';
      readonly sourceCapability: EcdsaSourceCapabilityBindingV1;
      readonly sourceHolderVerifyingShare33B64u: string;
      readonly sourceServerVerifyingShare33B64u: string;
    });

export type D1LinkedDeviceOwnerPlanningDeploymentPlanV1 = {
  readonly metadata: D1LinkedDeviceOwnerAuthorizationMetadataV1;
  readonly orderedChildren: NonEmpty<D1LinkedDeviceOwnerPlanningDeploymentChildV1>;
};

export type D1LinkedDeviceOwnerPlanningDeploymentPortV1 = {
  planOwnerPlanningV1(input: {
    readonly owner: DeviceLinkingOwnerWalletSessionContextV1;
    readonly payload: QrLinkedDeviceSessionPayloadV5;
    /** Browser ECDSA manifest identity is authenticated against the D1 projection before use. */
    readonly orderedOwnerSourceLaneHints: NonEmpty<LinkedDeviceOwnerSourceLaneV1>;
    /** Every projection was resolved from the D1 wallet signer/auth records. */
    readonly projections: NonEmpty<ActiveOwnerWalletExecutionLaneProjection>;
  }): Promise<D1LinkedDeviceOwnerPlanningDeploymentPlanV1>;
};

export type D1LinkedDeviceOwnerPlanningSnapshotWriterOptionsV1 = {
  readonly snapshotStore: Pick<D1LinkedDeviceOwnerPlanningSnapshotStoreV1, 'insertOrReplayV1'>;
  readonly walletRegistration: Pick<
    RouterApiWalletRegistrationService,
    'resolveActiveOwnerWalletExecutionLane'
  >;
  readonly deployment: D1LinkedDeviceOwnerPlanningDeploymentPortV1;
};

export class D1LinkedDeviceOwnerPlanningSnapshotWriterV1 {
  private readonly snapshotStore: D1LinkedDeviceOwnerPlanningSnapshotWriterOptionsV1['snapshotStore'];
  private readonly walletRegistration: D1LinkedDeviceOwnerPlanningSnapshotWriterOptionsV1['walletRegistration'];
  private readonly deployment: D1LinkedDeviceOwnerPlanningDeploymentPortV1;

  constructor(options: D1LinkedDeviceOwnerPlanningSnapshotWriterOptionsV1) {
    this.snapshotStore = options.snapshotStore;
    this.walletRegistration = options.walletRegistration;
    this.deployment = options.deployment;
  }

  async writeV1(input: {
    readonly owner: DeviceLinkingOwnerWalletSessionContextV1;
    readonly payload: QrLinkedDeviceSessionPayloadV5;
    readonly orderedOwnerSourceLaneHints: NonEmpty<LinkedDeviceOwnerSourceLaneV1>;
  }): Promise<D1LinkedDeviceOwnerPlanningSnapshotMutationV1> {
    const payload = parseQrLinkedDeviceSessionPayloadV5(input.payload);
    const hints = normalizeHints(input.orderedOwnerSourceLaneHints, input.owner.walletId);
    const projections = await resolveAuthoritativeProjections(this.walletRegistration, hints);
    const deploymentPlan = await this.deployment.planOwnerPlanningV1({
      owner: input.owner,
      payload,
      orderedOwnerSourceLaneHints: hints,
      projections,
    });
    const snapshot = buildSnapshotInput({
      owner: input.owner,
      payload,
      hints,
      projections,
      deploymentPlan,
    });
    return await this.snapshotStore.insertOrReplayV1(snapshot);
  }
}

function normalizeHints(
  hints: NonEmpty<LinkedDeviceOwnerSourceLaneV1>,
  ownerWalletId: WalletId,
): NonEmpty<LinkedDeviceOwnerSourceLaneV1> {
  const normalized = hints.map((hint, index) => {
    const parsed = parseLinkedDeviceOwnerSourceLaneV1(hint, `ownerSourceLaneHints[${index}]`);
    if (parsed.walletKey.walletId !== ownerWalletId) {
      throw new Error(`owner source lane hint ${index} wallet differs from owner`);
    }
    return parsed;
  });
  return [normalized[0]!, ...normalized.slice(1)];
}

async function resolveAuthoritativeProjections(
  walletRegistration: D1LinkedDeviceOwnerPlanningSnapshotWriterOptionsV1['walletRegistration'],
  hints: NonEmpty<LinkedDeviceOwnerSourceLaneV1>,
): Promise<NonEmpty<ActiveOwnerWalletExecutionLaneProjection>> {
  const projections: ActiveOwnerWalletExecutionLaneProjection[] = [];
  for (let index = 0; index < hints.length; index += 1) {
    const hint = hints[index]!;
    const result: WalletExecutionLaneProjectionResult =
      await walletRegistration.resolveActiveOwnerWalletExecutionLane({
        walletId: hint.walletKey.walletId,
        authorization: {
          kind: 'wallet_auth_method',
          walletAuthMethodId: hint.lane.walletAuthMethodId,
        },
        expectedMaterialActivation: hint.materialActivation,
      });
    if (result.kind !== 'projected') {
      throw new Error(`owner source lane ${index} projection refused: ${result.reason}`);
    }
    assertProjectionMatchesHint(result.projection, hint, index);
    projections.push(result.projection);
  }
  return [projections[0]!, ...projections.slice(1)];
}

function assertProjectionMatchesHint(
  projection: ActiveOwnerWalletExecutionLaneProjection,
  hint: LinkedDeviceOwnerSourceLaneV1,
  index: number,
): void {
  if (
    projection.walletKey.walletId !== hint.walletKey.walletId ||
    projection.walletKey.walletKeyId !== hint.walletKey.walletKeyId ||
    projection.walletKey.keyFamily !== hint.keyFamily ||
    projection.lane.laneId !== hint.lane.laneId ||
    projection.lane.laneShareEpoch !== hint.lane.laneShareEpoch ||
    projection.lane.participantBindingDigestB64u !== hint.lane.participantBindingDigestB64u ||
    String(projection.materialActivation.activationId) !==
      String(hint.materialActivation.activationId) ||
    projection.verifiedActivationReceiptDigestB64u !== hint.verifiedActivationReceiptDigestB64u
  ) {
    throw new Error(`owner source lane hint ${index} differs from D1 wallet projection`);
  }
}

function buildSnapshotInput(input: {
  readonly owner: DeviceLinkingOwnerWalletSessionContextV1;
  readonly payload: QrLinkedDeviceSessionPayloadV5;
  readonly hints: NonEmpty<LinkedDeviceOwnerSourceLaneV1>;
  readonly projections: NonEmpty<ActiveOwnerWalletExecutionLaneProjection>;
  readonly deploymentPlan: D1LinkedDeviceOwnerPlanningDeploymentPlanV1;
}): D1LinkedDeviceOwnerPlanningSnapshotInputV1 {
  const { metadata, orderedChildren: deploymentChildren } = input.deploymentPlan;
  if (
    metadata.walletId !== input.owner.walletId ||
    metadata.orderedKeyBindings.length !== input.hints.length ||
    metadata.protocolVersions.length !== input.hints.length ||
    deploymentChildren.length !== input.hints.length
  ) {
    throw new Error('owner planning deployment facts do not cover the ordered source lanes');
  }
  const sourceChildren = deploymentChildren.map((deploymentChild, index) => {
    const projection = input.projections[index]!;
    const hint = input.hints[index]!;
    const binding = metadata.orderedKeyBindings[index]!;
    assertBindingMatchesProjection(binding, projection, index);
    assertDeploymentChildIdentity(deploymentChild, binding, projection, index);
    const authorizedOperationId = parseRequired(
      parseAuthorizedOperationId(String(metadata.operationId)),
      `owner planning metadata operationId ${index}`,
    );
    const authorization = {
      authorizedOperationId,
      idempotencyKey: metadata.idempotencyKey,
      linkedDevicePermissionDigestB64u: metadata.policyDigestB64u,
    } as const;
    const source = {
      sourceKind: 'owner_registration' as const,
      laneId: projection.lane.laneId,
      laneKind: projection.lane.laneKind,
      laneShareEpoch: projection.lane.laneShareEpoch,
      revocationEpoch: projection.lane.lifecycle.revocationEpoch,
      ownerParticipantContinuity: projection.lane.ownerParticipantContinuity,
      participantBindingDigestB64u: projection.lane.participantBindingDigestB64u,
      materialActivation: projection.materialActivation,
    };
    const common = {
      walletKeyId: projection.walletKey.walletKeyId,
      source,
      authorization,
    } as const;
    if (deploymentChild.keyFamily === 'ed25519') {
      if (projection.walletKey.keyFamily !== 'ed25519') {
        throw new Error(`owner planning source child ${index} key family differs from projection`);
      }
      return {
        ...common,
        keyFamily: 'ed25519' as const,
        registeredPublicKeyB64u: projection.walletKey.registeredPublicKeyB64u,
        applicationBindingDigestB64u: parseDigestB64u(
          deploymentChild.applicationBindingDigestB64u,
        ),
        nearEd25519SigningKeyId: projection.walletKey.nearEd25519SigningKeyId,
        keyCreationSignerSlot: projection.walletKey.keyCreationSignerSlot,
        stableContextBindingB64u: deploymentChild.stableContextBindingB64u,
      } satisfies Extract<LinkedDeviceOwnerSourceChildResolutionV1, { keyFamily: 'ed25519' }>;
    }
    if (projection.walletKey.keyFamily !== 'ecdsa_secp256k1') {
      throw new Error(`owner planning source child ${index} key family differs from projection`);
    }
    return {
      ...common,
      keyFamily: 'ecdsa_secp256k1' as const,
      evmFamilySigningKeySlotId: projection.walletKey.evmFamilySigningKeySlotId,
      thresholdPublicKey33B64u: projection.walletKey.thresholdPublicKey33B64u,
      evmAddress: projection.walletKey.evmAddress,
      sourceCapability: deploymentChild.sourceCapability,
      sourceHolderVerifyingShare33B64u: deploymentChild.sourceHolderVerifyingShare33B64u,
      sourceServerVerifyingShare33B64u: deploymentChild.sourceServerVerifyingShare33B64u,
    } satisfies Extract<LinkedDeviceOwnerSourceChildResolutionV1, { keyFamily: 'ecdsa_secp256k1' }>;
  });
  return {
    kind: 'linked_device_owner_planning_snapshot_v1',
    linkSessionId: String(input.payload.linkSessionId),
    walletId: input.owner.walletId,
    owner: input.owner,
    payload: input.payload,
    metadata,
    sourceChildren: [sourceChildren[0]!, ...sourceChildren.slice(1)],
    orderedOwnerSourceLaneHints: input.hints,
  };
}

function parseRequired<T>(
  result:
    | { readonly ok: true; readonly value: T }
    | { readonly ok: false; readonly error: { readonly message: string } },
  label: string,
): T {
  if (result.ok) return result.value;
  throw new Error(`${label}: ${result.error.message}`);
}

function assertBindingMatchesProjection(
  binding: D1LinkedDeviceOwnerAuthorizationMetadataV1['orderedKeyBindings'][number],
  projection: ActiveOwnerWalletExecutionLaneProjection,
  index: number,
): void {
  if (
    binding.walletKeyId !== projection.walletKey.walletKeyId ||
    binding.keyFamily !== projection.walletKey.keyFamily ||
    binding.sourceLaneId !== projection.lane.laneId ||
    binding.sourceLaneKind !== projection.lane.laneKind ||
    binding.sourceKind !== 'owner_registration' ||
    binding.sourceLaneShareEpoch !== projection.lane.laneShareEpoch ||
    binding.sourceRevocationEpoch !== projection.lane.lifecycle.revocationEpoch ||
    binding.ownerParticipantContinuity.sourceIdentityDigestB64u !==
      projection.lane.ownerParticipantContinuity.sourceIdentityDigestB64u
  ) {
    throw new Error(`owner planning key binding ${index} differs from D1 wallet projection`);
  }
}

function assertDeploymentChildIdentity(
  child: D1LinkedDeviceOwnerPlanningDeploymentChildV1,
  binding: D1LinkedDeviceOwnerAuthorizationMetadataV1['orderedKeyBindings'][number],
  projection: ActiveOwnerWalletExecutionLaneProjection,
  index: number,
): void {
  if (
    child.keyFamily !== projection.walletKey.keyFamily ||
    binding.sourceKind !== 'owner_registration' ||
    binding.sourceLaneKind !== projection.lane.laneKind ||
    binding.ownerParticipantContinuity.sourceIdentityDigestB64u !==
      projection.lane.ownerParticipantContinuity.sourceIdentityDigestB64u
  ) {
    throw new Error(`owner planning deployment child ${index} has invalid participant identity`);
  }
}
