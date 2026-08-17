import type { AuthorizedOperationId } from '@shared/authorization/capabilityKinds';
import { linkedDeviceEnrollmentBindingMatchesSourceV1 } from '@shared/device-linking/contracts';
import type {
  LinkedDeviceApprovalV1,
  LinkedDeviceEnrollmentKeyBindingV1,
  LinkedDeviceTargetCredentialRegistrationV1,
  LinkedDeviceTargetPreparationChildV1,
  LinkedDeviceTargetPreparationV1,
  LinkedDeviceTargetReadyR102InputV1,
} from '@shared/device-linking/contracts';
import {
  buildLinkedDeviceTargetPreparationV1,
  parseLinkedDeviceTargetReadyR102InputV1,
} from '@shared/device-linking/parsers';
import { computeLinkedDeviceTargetPreparationDigestV1 } from '@shared/device-linking/digests';
import type { DigestB64u } from '@shared/utils/canonicalPrimitives';
import { parseDigestB64u } from '@shared/utils/canonicalPrimitives';
import { secureRandomBase36, secureRandomBase64Url } from '@shared/utils/secureRandomId';
import {
  parseLaneEnrollmentId,
  parseLaneOperationId,
  parseSigningLaneId,
  type LinkedDeviceEnrollmentId,
  type LaneOperationId,
  type LaneOperationIdempotencyKey,
} from '@shared/signing-lanes/ids';
import {
  parseMpcMaterialActivationId,
  parseWebAuthnRpId,
  parseWebAuthnCredentialIdB64u,
  type MpcMaterialActivationId,
  type WebAuthnRpId,
} from '@shared/utils/domainIds';
import type {
  ActiveLaneProtocolSourceV1,
  EcdsaSourceCapabilityBindingV1,
  EcdsaTargetCapabilityBindingV1,
  LaneTargetSigningWorkerV1,
  RotatableSigningLaneJobV1,
} from '@shared/signing-lanes/rotation';
import {
  buildLinkedDeviceTargetDeploymentDescriptorRequestV1,
  type LinkedDeviceTargetDeploymentDescriptorV1,
} from '@shared/device-linking/targetDeploymentDescriptor';
import {
  buildLaneEnrollmentManifestV1,
  buildRotatableSigningLaneJobV1,
} from '@shared/signing-lanes/rotationParsers';
import { computeLaneEnrollmentManifestDigestV1 } from '@shared/signing-lanes/rotationDigests';
import type {
  LaneHolderParticipantId,
  LaneHolderParticipantRecordV1,
} from '@shared/signing-lanes/participants';
import { parseLaneHolderParticipantId } from '@shared/signing-lanes/participants';
import type { EvmFamilySigningKeySlotId } from '@shared/signing-lanes/evmFamilySigningKeySlotId';
import type { KeyCreationSignerSlot } from '@shared/passkey-custody/primitives';
import type { NearEd25519SigningKeyId } from '@shared/utils/registrationIntent';
import type { Ed25519YaoSuiteId } from '@shared/signing-lanes/ids';
import type { LinkedDeviceSessionRecordV1 } from '../../../../core/deviceLinking/linkedDeviceSession';
import type {
  LinkedDeviceTargetPlannerV1,
  VerifiedLinkedDeviceWebAuthnCredentialV1,
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
    readonly registeredPublicKeyB64u: string;
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
      readonly yaoSuiteId: Ed25519YaoSuiteId;
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
      readonly credential: VerifiedLinkedDeviceWebAuthnCredentialV1;
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

  async commitVerifiedTargetV1(input: {
    readonly preparation: LinkedDeviceTargetPreparationV1;
    readonly registration: LinkedDeviceTargetCredentialRegistrationV1;
    readonly credential: VerifiedLinkedDeviceWebAuthnCredentialV1;
    readonly registrationDigestB64u: DigestB64u;
    readonly requestedAtMs: number;
  }): Promise<{
    readonly keyManifestDigestB64u: DigestB64u;
    readonly targetReady: LinkedDeviceTargetReadyR102InputV1;
  }> {
    const registrationDigestB64u = parseDigestB64u(input.registrationDigestB64u);
    if (input.requestedAtMs >= input.preparation.expiresAtMs) {
      throw new Error('linked-device target preparation is expired');
    }
    if (
      input.registration.linkSessionId !== input.preparation.linkSessionId ||
      input.registration.walletId !== input.preparation.walletId ||
      input.registration.enrollmentId !== input.preparation.enrollmentId ||
      input.registration.deviceId !== input.preparation.deviceId ||
      input.registration.orderedHolderRegistrations.length !==
        input.preparation.orderedChildren.length
    ) {
      throw new Error('linked-device target registration identity differs from preparation');
    }
    if (
      input.credential.credentialIdB64u !==
        input.registration.webauthnRegistration.credentialIdB64u ||
      !input.credential.credentialPublicKeyB64u ||
      !Number.isSafeInteger(input.credential.counter) ||
      input.credential.counter < 0
    ) {
      throw new Error('verified linked-device credential does not match registration');
    }
    const preparationDigestB64u = await computeLinkedDeviceTargetPreparationDigestV1(
      input.preparation,
    );
    if (input.registration.targetPreparationDigestB64u !== preparationDigestB64u) {
      throw new Error('linked-device target registration preparation digest differs');
    }

    const resolutions: LinkedDeviceTargetEnrichedChildResolutionV1[] = [];
    const jobs: RotatableSigningLaneJobV1[] = [];
    for (
      let childIndex = 0;
      childIndex < input.preparation.orderedChildren.length;
      childIndex += 1
    ) {
      const preparationChild = input.preparation.orderedChildren[childIndex];
      const holderRegistration = input.registration.orderedHolderRegistrations[childIndex];
      if (!preparationChild || !holderRegistration) {
        throw new Error(`linked-device target registration child ${childIndex} is missing`);
      }
      assertHolderRegistrationMatchesPreparation(preparationChild, holderRegistration, childIndex);
      const sourceResolution = await this.resolveOwnerSourceChildV1({
        kind: 'commit',
        preparation: input.preparation,
        registration: input.registration,
        credential: input.credential,
        childIndex,
      });
      assertResolutionMatchesPreparation(sourceResolution, preparationChild, childIndex);
      const descriptor =
        await this.targetDeploymentDescriptorProvider.resolveTargetDeploymentDescriptorV1({
          request: buildLinkedDeviceTargetDeploymentDescriptorRequestV1({
            kind: 'linked_device_target_deployment_descriptor_request_v1',
            linkSessionId: input.preparation.linkSessionId,
            walletId: input.preparation.walletId,
            walletKeyId: preparationChild.walletKeyId,
            enrollmentId: input.preparation.enrollmentId,
            deviceId: input.preparation.deviceId,
            operationId: preparationChild.operationId,
            childIndex,
            keyFamily: preparationChild.keyFamily,
            targetLaneId: preparationChild.targetLaneId,
            targetLaneShareEpoch: preparationChild.targetLaneShareEpoch,
            targetMaterialActivationId: preparationChild.targetMaterialActivationId,
            targetHolderParticipantId: preparationChild.targetHolderParticipantId,
            targetPreparationDigestB64u: preparationDigestB64u,
            registrationDigestB64u,
            credentialIdB64u: parseRequired(
              parseWebAuthnCredentialIdB64u(input.credential.credentialIdB64u),
              'target descriptor credentialIdB64u',
            ),
          }),
          issuedAtMs: input.preparation.issuedAtMs,
          expiresAtMs: input.preparation.expiresAtMs,
        });
      assertDescriptorMatchesRegistration(
        descriptor,
        input,
        registrationDigestB64u,
        preparationChild,
        childIndex,
      );
      const resolution = enrichSourceResolution(sourceResolution, descriptor, childIndex);
      resolutions.push(resolution);
      jobs.push(
        buildTargetJob({
          preparation: input.preparation,
          preparationChild,
          holderParticipant: holderRegistration.holderParticipant,
          resolution,
        }),
      );
    }

    const firstResolution = resolutions[0];
    if (!firstResolution) throw new Error('linked-device target has no source resolution');
    for (const resolution of resolutions.slice(1)) {
      assertSameAuthorizationFacts(firstResolution.authorization, resolution.authorization);
    }
    const manifest = buildLaneEnrollmentManifestV1({
      enrollmentId: parseRequired(
        parseLaneEnrollmentId(String(input.preparation.enrollmentId)),
        'target manifest enrollmentId',
      ),
      walletId: input.preparation.walletId,
      authorization: {
        kind: 'linked_device_enrollment',
        authorizedOperationId: firstResolution.authorization.authorizedOperationId,
        linkedDeviceEnrollmentId: input.preparation.enrollmentId,
        linkedDevicePermissionDigestB64u:
          firstResolution.authorization.linkedDevicePermissionDigestB64u,
      },
      orderedChildren: requireNonEmpty(
        jobs.map(buildManifestChild),
        'linked-device target manifest children',
      ),
      createdAtMs: input.preparation.issuedAtMs,
      expiresAtMs: input.preparation.expiresAtMs,
    });
    const targetReady = parseLinkedDeviceTargetReadyR102InputV1({
      kind: 'linked_device_target_ready_r102_input_v1',
      linkSessionId: input.preparation.linkSessionId,
      walletId: input.preparation.walletId,
      enrollmentId: input.preparation.enrollmentId,
      deviceId: input.preparation.deviceId,
      manifest,
      children: requireNonEmpty(jobs, 'linked-device target jobs'),
    });
    return {
      keyManifestDigestB64u: parseDigestB64u(await computeLaneEnrollmentManifestDigestV1(manifest)),
      targetReady,
    };
  }
}

function assertPreparationInput(
  session: LinkedDeviceSessionRecordV1,
  approval: LinkedDeviceApprovalV1,
  requestedAtMs: number,
): void {
  if (
    session.state.state !== 'awaiting_target_passkey' ||
    session.linkSessionId !== approval.linkSessionId ||
    session.state.walletId !== approval.walletId ||
    session.state.enrollmentId !== approval.enrollmentId ||
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

function assertResolutionMatchesPreparation(
  resolution: LinkedDeviceOwnerSourceChildResolutionV1,
  child: LinkedDeviceTargetPreparationChildV1,
  childIndex: number,
): void {
  if (resolution.walletKeyId !== child.walletKeyId || resolution.keyFamily !== child.keyFamily) {
    throw new Error(`linked-device source resolution ${childIndex} differs from preparation`);
  }
}

function assertDescriptorMatchesRegistration(
  descriptor: LinkedDeviceTargetDeploymentDescriptorV1,
  input: {
    readonly preparation: LinkedDeviceTargetPreparationV1;
    readonly registration: LinkedDeviceTargetCredentialRegistrationV1;
    readonly credential: VerifiedLinkedDeviceWebAuthnCredentialV1;
    readonly requestedAtMs: number;
  },
  registrationDigestB64u: DigestB64u,
  preparationChild: LinkedDeviceTargetPreparationChildV1,
  childIndex: number,
): void {
  const request = descriptor.request;
  const registration = input.registration.orderedHolderRegistrations[childIndex];
  if (!registration)
    throw new Error(`linked-device target registration child ${childIndex} is missing`);
  if (
    descriptor.keyFamily !== preparationChild.keyFamily ||
    request.keyFamily !== preparationChild.keyFamily ||
    request.linkSessionId !== input.preparation.linkSessionId ||
    request.walletId !== input.preparation.walletId ||
    request.walletKeyId !== preparationChild.walletKeyId ||
    request.enrollmentId !== input.preparation.enrollmentId ||
    request.deviceId !== input.preparation.deviceId ||
    request.operationId !== preparationChild.operationId ||
    request.childIndex !== childIndex ||
    request.targetLaneId !== preparationChild.targetLaneId ||
    request.targetLaneShareEpoch !== preparationChild.targetLaneShareEpoch ||
    request.targetMaterialActivationId !== preparationChild.targetMaterialActivationId ||
    request.targetHolderParticipantId !== preparationChild.targetHolderParticipantId ||
    request.targetPreparationDigestB64u !== input.registration.targetPreparationDigestB64u ||
    request.registrationDigestB64u !== registrationDigestB64u ||
    request.credentialIdB64u !== input.credential.credentialIdB64u ||
    descriptor.targetHolderParticipantId !== preparationChild.targetHolderParticipantId ||
    registration.holderParticipant.participantId !== descriptor.targetHolderParticipantId ||
    descriptor.issuedAtMs !== input.preparation.issuedAtMs ||
    descriptor.expiresAtMs !== input.preparation.expiresAtMs ||
    input.requestedAtMs < descriptor.issuedAtMs ||
    input.requestedAtMs >= descriptor.expiresAtMs
  ) {
    throw new Error(
      `linked-device target deployment descriptor ${childIndex} differs from registration`,
    );
  }
}

function enrichSourceResolution(
  source: LinkedDeviceOwnerSourceChildResolutionV1,
  descriptor: LinkedDeviceTargetDeploymentDescriptorV1,
  childIndex: number,
): LinkedDeviceTargetEnrichedChildResolutionV1 {
  if (source.keyFamily !== descriptor.keyFamily) {
    throw new Error(
      `linked-device target deployment descriptor ${childIndex} has the wrong key family`,
    );
  }
  if (source.keyFamily === 'ed25519' && descriptor.keyFamily === 'ed25519') {
    return {
      ...source,
      keyFamily: 'ed25519',
      targetHolderParticipantId: descriptor.targetHolderParticipantId,
      targetSigningWorker: descriptor.targetSigningWorker,
      yaoSuiteId: descriptor.yaoSuiteId,
      circuitDigestB64u: descriptor.circuitDigestB64u,
    };
  }
  if (source.keyFamily !== 'ecdsa_secp256k1' || descriptor.keyFamily !== 'ecdsa_secp256k1') {
    throw new Error(
      `linked-device target deployment descriptor ${childIndex} has the wrong key family`,
    );
  }
  return {
    ...source,
    keyFamily: 'ecdsa_secp256k1',
    targetHolderParticipantId: descriptor.targetHolderParticipantId,
    targetSigningWorker: descriptor.targetSigningWorker,
    targetCapability: descriptor.targetCapability,
    reshareChannelBindingDigestB64u: descriptor.reshareChannelBindingDigestB64u,
  };
}

function assertHolderRegistrationMatchesPreparation(
  child: LinkedDeviceTargetPreparationChildV1,
  registration: LinkedDeviceTargetCredentialRegistrationV1['orderedHolderRegistrations'][number],
  childIndex: number,
): void {
  if (
    registration.operationId !== child.operationId ||
    registration.walletKeyId !== child.walletKeyId ||
    registration.keyFamily !== child.keyFamily ||
    registration.targetLaneId !== child.targetLaneId ||
    registration.targetLaneShareEpoch !== child.targetLaneShareEpoch ||
    registration.targetMaterialActivationId !== child.targetMaterialActivationId ||
    registration.holderParticipant.participantId !== child.targetHolderParticipantId
  ) {
    throw new Error(`linked-device holder registration ${childIndex} differs from preparation`);
  }
}

function assertSameAuthorizationFacts(
  expected: LinkedDeviceTargetAuthorizationFactsV1,
  actual: LinkedDeviceTargetAuthorizationFactsV1,
): void {
  if (
    expected.authorizedOperationId !== actual.authorizedOperationId ||
    expected.idempotencyKey !== actual.idempotencyKey ||
    expected.linkedDevicePermissionDigestB64u !== actual.linkedDevicePermissionDigestB64u
  ) {
    throw new Error('linked-device source resolutions disagree on authorization');
  }
}

function buildTargetJob(input: {
  readonly preparation: LinkedDeviceTargetPreparationV1;
  readonly preparationChild: LinkedDeviceTargetPreparationChildV1;
  readonly holderParticipant: LaneHolderParticipantRecordV1;
  readonly resolution: LinkedDeviceTargetEnrichedChildResolutionV1;
}): RotatableSigningLaneJobV1 {
  const enrollmentId = parseRequired(
    parseLaneEnrollmentId(String(input.preparation.enrollmentId)),
    'target job enrollmentId',
  );
  const common = {
    operationId: input.preparationChild.operationId,
    enrollmentId,
    idempotencyKey: input.resolution.authorization.idempotencyKey,
    walletId: input.preparation.walletId,
    walletKeyId: input.resolution.walletKeyId,
    source: input.resolution.source,
    targetHolder: {
      participantId: input.holderParticipant.participantId,
      participantBindingDigestB64u: input.holderParticipant.participantBindingDigestB64u,
      custodyBindingId: input.holderParticipant.custodyBindingId,
      custodyBindingDigestB64u: input.holderParticipant.custodyBindingDigestB64u,
      hpkePublicKeyB64u: input.holderParticipant.hpkePublicKeyB64u,
      hpkePublicKeyDigestB64u: input.holderParticipant.hpkePublicKeyDigestB64u,
    },
    targetSigningWorker: input.resolution.targetSigningWorker,
    targetMaterialActivationId: input.preparationChild.targetMaterialActivationId,
    protocolVersion: 'rotatable_signing_lane_protocol_v1' as const,
    expiresAtMs: input.preparation.expiresAtMs,
    target: {
      operation: 'create_lane' as const,
      laneId: input.preparationChild.targetLaneId,
      laneKind: 'linked_device' as const,
      laneShareEpoch: input.preparationChild.targetLaneShareEpoch,
      expectedTargetState: 'absent' as const,
    },
    authorization: {
      kind: 'linked_device_enrollment' as const,
      authorizedOperationId: input.resolution.authorization.authorizedOperationId,
      linkedDeviceEnrollmentId: input.preparation.enrollmentId,
      linkedDevicePermissionDigestB64u:
        input.resolution.authorization.linkedDevicePermissionDigestB64u,
    },
  };
  if (input.resolution.keyFamily === 'ed25519') {
    return buildRotatableSigningLaneJobV1({
      ...common,
      kind: 'ed25519_yao_lane_job_v1',
      keyFamily: 'ed25519',
      registeredPublicKeyB64u: input.resolution.registeredPublicKeyB64u,
      nearEd25519SigningKeyId: input.resolution.nearEd25519SigningKeyId,
      keyCreationSignerSlot: input.resolution.keyCreationSignerSlot,
      stableContextBindingB64u: input.resolution.stableContextBindingB64u,
      yaoSuiteId: input.resolution.yaoSuiteId,
      circuitDigestB64u: input.resolution.circuitDigestB64u,
      yaoRequestKind: 'lane_provisioning' as const,
    });
  }
  return buildRotatableSigningLaneJobV1({
    ...common,
    kind: 'ecdsa_additive_lane_job_v1',
    keyFamily: 'ecdsa_secp256k1',
    evmFamilySigningKeySlotId: input.resolution.evmFamilySigningKeySlotId,
    thresholdPublicKey33B64u: input.resolution.thresholdPublicKey33B64u,
    evmAddress: input.resolution.evmAddress,
    sourceCapability: input.resolution.sourceCapability,
    targetCapability: input.resolution.targetCapability,
    sourceHolderVerifyingShare33B64u: input.resolution.sourceHolderVerifyingShare33B64u,
    sourceServerVerifyingShare33B64u: input.resolution.sourceServerVerifyingShare33B64u,
    reshareChannelBindingDigestB64u: input.resolution.reshareChannelBindingDigestB64u,
    transcriptEncoding: 'ecdsa_additive_lane_transcript_v1' as const,
  });
}

function buildManifestChild(job: RotatableSigningLaneJobV1) {
  return {
    operationId: job.operationId,
    walletKeyId: job.walletKeyId,
    keyFamily: job.keyFamily,
    sourceLaneId: job.source.laneId,
    sourceLaneShareEpoch: job.source.laneShareEpoch,
    sourceRevocationEpoch: job.source.revocationEpoch,
    sourceMaterialActivation: job.source.materialActivation,
    targetLaneId: job.target.laneId,
    targetLaneShareEpoch: job.target.laneShareEpoch,
    targetMaterialActivationId: job.targetMaterialActivationId,
    holderParticipantBindingDigestB64u: job.targetHolder.participantBindingDigestB64u,
    signingWorkerParticipantBindingDigestB64u: job.targetSigningWorker.participantBindingDigestB64u,
  };
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
