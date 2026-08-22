import type { AuthorizedOperationId } from '@shared/authorization/capabilityKinds';
import { hasDelegatedWalletPermissionV1 } from '@shared/authorization/delegatedAuthority';
import { linkedDeviceEnrollmentBindingMatchesSourceV1 } from '@shared/device-linking/contracts';
import type {
  LinkedDeviceApprovalV1,
  LinkedDeviceEnrollmentKeyBindingV1,
  LinkedDeviceTargetCredentialRegistrationV1,
  LinkedDeviceTargetPreparationChildV1,
  LinkedDeviceTargetPreparationV1,
} from '@shared/device-linking/contracts';
import { buildLinkedDeviceTargetPreparationV1 } from '@shared/device-linking/parsers';
import type { DigestB64u } from '@shared/utils/canonicalPrimitives';
import { secureRandomBase36 } from '@shared/utils/secureRandomId';
import {
  parseLaneEnrollmentId,
  parseLaneOperationId,
  type LinkedDeviceEnrollmentId,
  type LaneOperationId,
  type LaneOperationIdempotencyKey,
} from '@shared/signing-lanes/ids';
import {
  parseMpcMaterialActivationId,
  parseWebAuthnCredentialIdB64u,
  type MpcMaterialActivationId,
  type WebAuthnCredentialIdB64u,
} from '@shared/utils/domainIds';
import type {
  ActiveLaneProtocolSourceV1,
  EcdsaSourceCapabilityBindingV1,
  EcdsaTargetCapabilityBindingV1,
  LaneTargetSigningWorkerV1,
  RotatableSigningLaneJobV1,
} from '@shared/signing-lanes/rotation';
import type { LinkedDeviceTargetDeploymentDescriptorV1 } from '@shared/device-linking/targetDeploymentDescriptor';
import {
  buildRotatableSigningLaneJobV1,
} from '@shared/signing-lanes/rotationParsers';
import type {
  LaneHolderParticipantId,
  LaneHolderParticipantRecordV1,
} from '@shared/signing-lanes/participants';
import { parseLaneHolderParticipantId } from '@shared/signing-lanes/participants';
import type { EvmFamilySigningKeySlotId } from '@shared/signing-lanes/evmFamilySigningKeySlotId';
import type { KeyCreationSignerSlot } from '@shared/passkey-custody/primitives';
import type { Ed25519PublicKeyB64u } from '@shared/passkey-custody/primitives';
import type { NearEd25519SigningKeyId } from '@shared/utils/registrationIntent';
import type { LinkedDeviceSessionRecordV1 } from '../../../../core/deviceLinking/linkedDeviceSession';
import type {
  LinkedDeviceTargetPlannerV1,
  VerifiedLinkedDeviceTargetFactorEvidenceV1,
} from './d1LinkedDeviceTargetCredentialProvider';
import type { LinkedDeviceTargetDeploymentDescriptorProviderV1 } from './d1LinkedDeviceTargetDeploymentDescriptorProvider';

const DEFAULT_TARGET_PREPARATION_TTL_MS = 5 * 60 * 1_000;

type ParseResult<T> =
  | { readonly ok: true; readonly value: T }
  | { readonly ok: false; readonly error: { readonly message: string } };

export type LinkedDeviceTargetAuthorizationFactsV1 = {
  readonly authorizedOperationId: AuthorizedOperationId;
  readonly idempotencyKey: LaneOperationIdempotencyKey;
  readonly linkedDevicePermissionDigestB64u: DigestB64u;
};

type LinkedDeviceOwnerSourceChildResolutionBaseV1 = {
  readonly walletKeyId: LinkedDeviceEnrollmentKeyBindingV1['walletKeyId'];
  readonly source: ActiveLaneProtocolSourceV1;
  readonly authorization: LinkedDeviceTargetAuthorizationFactsV1;
};

/** Facts authenticated from Device 1's owner lane projection. Target
 * participant and capability material is intentionally absent until Device 2
 * returns its credential and holder registration. */
type LinkedDeviceOwnerEd25519SourceChildResolutionV1 =
  LinkedDeviceOwnerSourceChildResolutionBaseV1 & {
    readonly keyFamily: 'ed25519';
    readonly applicationBindingDigestB64u: DigestB64u;
    readonly registeredPublicKeyB64u: Ed25519PublicKeyB64u;
    readonly nearEd25519SigningKeyId: NearEd25519SigningKeyId;
    readonly keyCreationSignerSlot: KeyCreationSignerSlot;
    readonly stableContextBindingB64u: string;
  };

type LinkedDeviceOwnerEcdsaSourceChildResolutionV1 =
  LinkedDeviceOwnerSourceChildResolutionBaseV1 & {
    readonly keyFamily: 'ecdsa_secp256k1';
    readonly evmFamilySigningKeySlotId: EvmFamilySigningKeySlotId;
    readonly thresholdPublicKey33B64u: string;
    readonly evmAddress: string;
    readonly sourceCapability: EcdsaSourceCapabilityBindingV1;
    readonly sourceHolderVerifyingShare33B64u: string;
    readonly sourceServerVerifyingShare33B64u: string;
  };

export type LinkedDeviceOwnerSourceChildResolutionV1 =
  | LinkedDeviceOwnerEd25519SourceChildResolutionV1
  | LinkedDeviceOwnerEcdsaSourceChildResolutionV1;

export type LinkedDeviceTargetEnrichedChildResolutionV1 =
  | (LinkedDeviceOwnerEd25519SourceChildResolutionV1 & {
      readonly targetHolderParticipantId: LaneHolderParticipantId;
      readonly targetSigningWorker: LaneTargetSigningWorkerV1;
      readonly yaoSuiteId: import('@shared/signing-lanes/ids').Ed25519YaoSuiteId;
      readonly circuitDigestB64u: string;
    })
  | (LinkedDeviceOwnerEcdsaSourceChildResolutionV1 & {
      readonly targetHolderParticipantId: LaneHolderParticipantId;
      readonly targetSigningWorker: LaneTargetSigningWorkerV1;
      readonly targetCapability: EcdsaTargetCapabilityBindingV1;
      readonly reshareChannelBindingDigestB64u: string;
    });

export type LinkedDeviceTargetPreparationResolutionV1 = LinkedDeviceOwnerSourceChildResolutionV1;

export type LinkedDeviceOwnerSourceChildResolutionRequestV1 =
  | {
      readonly kind: 'preparation';
      readonly session: LinkedDeviceSessionRecordV1;
      readonly approval: LinkedDeviceApprovalV1;
      readonly binding: LinkedDeviceEnrollmentKeyBindingV1;
      readonly childIndex: number;
    }
  | {
      readonly kind: 'commit';
      readonly preparation: LinkedDeviceTargetPreparationV1;
      readonly registration: LinkedDeviceTargetCredentialRegistrationV1;
      readonly evidence: VerifiedLinkedDeviceTargetFactorEvidenceV1;
      readonly childIndex: number;
    };

export type LinkedDeviceOwnerSourceChildResolverV1 = {
  resolveOwnerSourceChildV1(
    input: LinkedDeviceOwnerSourceChildResolutionRequestV1,
  ): Promise<LinkedDeviceTargetPreparationResolutionV1>;
};

export type D1LinkedDeviceTargetPlannerOptionsV1 = {
  readonly resolveOwnerSourceChildV1: LinkedDeviceOwnerSourceChildResolverV1['resolveOwnerSourceChildV1'];
  readonly targetDeploymentDescriptorProvider: LinkedDeviceTargetDeploymentDescriptorProviderV1;
  readonly preparationTtlMs?: number;
};

/**
 * Builds the one durable target preparation and the exact R102 jobs consumed
 * after Device 2 returns its verified credential and holder records.
 */
export class D1LinkedDeviceTargetPlannerV1 implements LinkedDeviceTargetPlannerV1 {
  private readonly resolveOwnerSourceChildV1: LinkedDeviceOwnerSourceChildResolverV1['resolveOwnerSourceChildV1'];
  private readonly targetDeploymentDescriptorProvider: LinkedDeviceTargetDeploymentDescriptorProviderV1;
  private readonly preparationTtlMs: number;

  constructor(input: D1LinkedDeviceTargetPlannerOptionsV1) {
    this.resolveOwnerSourceChildV1 = input.resolveOwnerSourceChildV1;
    this.targetDeploymentDescriptorProvider = input.targetDeploymentDescriptorProvider;
    const ttlMs = input.preparationTtlMs ?? DEFAULT_TARGET_PREPARATION_TTL_MS;
    if (!Number.isSafeInteger(ttlMs) || ttlMs <= 0) {
      throw new Error('linked-device target preparation TTL must be a positive safe integer');
    }
    this.preparationTtlMs = ttlMs;
  }

  async createTargetPreparationV1(input: {
    readonly session: LinkedDeviceSessionRecordV1;
    readonly approval: LinkedDeviceApprovalV1;
    readonly requestedAtMs: number;
  }): Promise<LinkedDeviceTargetPreparationV1> {
    assertPreparationInput(input.session, input.approval, input.requestedAtMs);
    // Clamped to the ceremony as well as the approval: a preparation that
    // outlived its ceremony would send Device 2 to create a credential nothing
    // could finalize.
    const expiresAtMs = Math.min(
      input.approval.expiresAtMs,
      input.approval.ownerEnrollment.expiresAtMs,
      input.requestedAtMs + this.preparationTtlMs,
    );
    if (expiresAtMs <= input.requestedAtMs) {
      throw new Error('linked-device target preparation has no remaining lifetime');
    }

    const children: LinkedDeviceTargetPreparationChildV1[] = [];
    let ed25519ExportRoot: LinkedDeviceTargetPreparationV1['ed25519ExportRoot'] = null;
    for (
      let childIndex = 0;
      childIndex < input.approval.orderedKeyBindings.length;
      childIndex += 1
    ) {
      const binding = input.approval.orderedKeyBindings[childIndex];
      if (!binding) throw new Error(`linked-device approval child ${childIndex} is missing`);
      const resolution = await this.resolveOwnerSourceChildV1({
        kind: 'preparation',
        session: input.session,
        approval: input.approval,
        binding,
        childIndex,
      });
      assertResolutionMatchesBinding(resolution, binding, childIndex);
      assertResolutionAuthorizationMatchesApproval(resolution.authorization, input.approval);
      if (
        resolution.keyFamily === 'ed25519' &&
        hasDelegatedWalletPermissionV1(input.approval.permission, 'export_keys')
      ) {
        if (ed25519ExportRoot !== null) {
          throw new Error('linked-device approval contains multiple Ed25519 source children');
        }
        ed25519ExportRoot = {
          kind: 'linked_device_ed25519_export_root_preparation_v1',
          walletKeyId: resolution.walletKeyId,
          applicationBindingDigestB64u: resolution.applicationBindingDigestB64u,
          registeredPublicKeyB64u: resolution.registeredPublicKeyB64u,
          revocationEpoch: resolution.source.revocationEpoch,
        };
      }
      children.push({
        kind: 'linked_device_target_preparation_child_v1',
        operationId: createChildOperationId(input.approval.operationId, childIndex),
        walletKeyId: binding.walletKeyId,
        keyFamily: binding.keyFamily,
        targetLaneId: binding.targetLaneId,
        targetLaneShareEpoch: binding.targetLaneShareEpoch,
        targetMaterialActivationId: createTargetMaterialActivationId(childIndex),
        targetHolderParticipantId: createTargetHolderParticipantId(
          input.approval.enrollmentId,
          childIndex,
        ),
      });
    }

    return buildLinkedDeviceTargetPreparationV1({
      linkSessionId: input.approval.linkSessionId,
      walletId: input.approval.walletId,
      enrollmentId: input.approval.enrollmentId,
      deviceId: input.approval.deviceId,
      ed25519ExportRoot,
      targetFactor: input.approval.targetFactor,
      // The planner no longer mints a relying party, challenge, or user handle
      // of its own. They come from the ceremony Device 1 started during
      // owner-authenticated approval, which is the only registration Device 2
      // can finalize — a second set here could only ever disagree with it.
      ownerEnrollment: input.approval.ownerEnrollment,
      orderedChildren: requireNonEmpty(children, 'linked-device target preparation children'),
      issuedAtMs: input.requestedAtMs,
      expiresAtMs,
    });
  }

}

function assertPreparationInput(
  session: LinkedDeviceSessionRecordV1,
  approval: LinkedDeviceApprovalV1,
  requestedAtMs: number,
): void {
  if (
    session.state.state !== 'awaiting_target_factor' ||
    session.linkSessionId !== approval.linkSessionId ||
    session.claimTranscript?.value.walletId !== approval.walletId ||
    session.claimTranscript?.value.enrollmentId !== approval.enrollmentId ||
    requestedAtMs < approval.approvedAtMs ||
    requestedAtMs >= approval.expiresAtMs
  ) {
    throw new Error('linked-device target preparation input is not an awaiting approved session');
  }
}

function assertResolutionMatchesBinding(
  resolution: LinkedDeviceOwnerSourceChildResolutionV1,
  binding: LinkedDeviceEnrollmentKeyBindingV1,
  childIndex: number,
): void {
  if (
    resolution.walletKeyId !== binding.walletKeyId ||
    resolution.keyFamily !== binding.keyFamily ||
    resolution.source.laneId !== binding.sourceLaneId ||
    resolution.source.laneShareEpoch !== binding.sourceLaneShareEpoch ||
    resolution.source.revocationEpoch !== binding.sourceRevocationEpoch ||
    !linkedDeviceEnrollmentBindingMatchesSourceV1(binding, resolution.source)
  ) {
    throw new Error(`linked-device source resolution ${childIndex} differs from approval`);
  }
}

function assertResolutionAuthorizationMatchesApproval(
  authorization: LinkedDeviceTargetAuthorizationFactsV1,
  approval: LinkedDeviceApprovalV1,
): void {
  if (
    String(authorization.authorizedOperationId) !== String(approval.operationId) ||
    authorization.idempotencyKey !== approval.idempotencyKey ||
    authorization.linkedDevicePermissionDigestB64u !== approval.policyDigestB64u
  ) {
    throw new Error('linked-device source resolution authorization differs from approval');
  }
}

function createChildOperationId(parent: LaneOperationId, childIndex: number): LaneOperationId {
  return parseRequired(
    parseLaneOperationId(
      `linked-device-target:${String(parent)}:${childIndex}:${secureRandomBase36(16)}`,
    ),
    'target child operationId',
  );
}

function createTargetMaterialActivationId(childIndex: number): MpcMaterialActivationId {
  return parseRequired(
    parseMpcMaterialActivationId(
      `linked-device-target-material:${childIndex}:${secureRandomBase36(20)}`,
    ),
    'target material activation id',
  );
}

function createTargetHolderParticipantId(
  enrollmentId: LinkedDeviceEnrollmentId,
  childIndex: number,
): LaneHolderParticipantId {
  return parseRequired(
    parseLaneHolderParticipantId(`holder:linked-device:${String(enrollmentId)}:${childIndex}`),
    'target holder participant id',
  );
}

function requireNonEmpty<T>(values: readonly T[], label: string): readonly [T, ...T[]] {
  const [first, ...rest] = values;
  if (first === undefined) throw new Error(`${label} must not be empty`);
  return [first, ...rest];
}

function parseRequired<T>(result: ParseResult<T>, label: string): T {
  if (!result.ok) throw new Error(`${label}: ${result.error.message}`);
  return result.value;
}
