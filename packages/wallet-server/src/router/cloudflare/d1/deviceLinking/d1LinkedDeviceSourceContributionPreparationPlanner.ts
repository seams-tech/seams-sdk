import type {
  LinkedDeviceApprovalV1,
  LinkedDeviceEcdsaSourceContributionPreparationV1,
  LinkedDeviceEd25519SourceContributionPreparationV1,
  LinkedDeviceOrdinaryMaterialSourceContributionPreparationTupleV1,
  LinkedDeviceTargetCredentialRegistrationV1,
  LinkedDeviceTargetPreparationV1,
  OrdinarySignerMaterialRecipientRequestV1,
  VerifiedTargetFactorV1,
} from '@shared/device-linking/contracts';
import {
  parseLinkedDeviceOrdinaryMaterialSourceContributionPreparationTupleV1,
} from '@shared/device-linking/sourceContribution';
import type {
  ExactAdministeredEcdsaSignerV1,
  ExactAdministeredEd25519SignerV1,
} from '@shared/device-linking/delegatedActivationPlan';
import { base64UrlDecode, base64UrlEncode } from '@shared/utils/base64';
import { parseDeviceId } from '@shared/authorization/capabilityKinds';
import {
  buildMpcMaterialActivationRef,
  parseMpcMaterialActivationId,
  type MpcMaterialActivationRef,
} from '@shared/utils/domainIds';
import { secureRandomBase64Url } from '@shared/utils/secureRandomId';
import {
  parseRouterAbEd25519YaoRegistrationActivationExecuteRequestV1,
  type RouterAbEd25519YaoActivationBindingV1,
  type RouterAbEd25519YaoDeriverRoleV1,
} from '@shared/utils/routerAbEd25519Yao';
import { routerAbMpcMaterialActivationRefToWire } from '@shared/utils/routerAbNormalSigningIdentity';
import {
  parseSecp256k1CompressedPublicKeyB64u,
} from '@shared/passkey-custody/primitives';
import type { LinkedDeviceSessionRecordV1 } from '../../../../core/deviceLinking/linkedDeviceSession';
import type {
  LinkedDeviceOwnerSourceChildResolutionV1,
  LinkedDeviceOwnerSourceChildResolverV1,
} from './d1LinkedDeviceTargetPlanner';
import type {
  LinkedDeviceSourceContributionPreparationPlannerV1,
  VerifiedLinkedDeviceTargetFactorEvidenceV1,
} from './d1LinkedDeviceTargetCredentialProvider';
import type { VerifiedLinkSourceReadV1 } from './d1LinkedDeviceVerifiedLinkBuilder';

export type D1LinkedDeviceSourceContributionPreparationPlannerOptionsV1 = {
  readonly resolveOwnerSourceChildV1: LinkedDeviceOwnerSourceChildResolverV1['resolveOwnerSourceChildV1'];
  /** The current SigningWorker X25519 recipient, encoded as canonical 32-byte base64url. */
  readonly signingWorkerRecipientPublicKeyB64u: string;
};

/**
 * Plans the exact public inputs consumed by Device 1 and the SigningWorker.
 * Activation identities are fresh, while every other activation field is
 * copied from the verified owner lane.
 */
export class D1LinkedDeviceSourceContributionPreparationPlannerV1
  implements LinkedDeviceSourceContributionPreparationPlannerV1
{
  private readonly resolveOwnerSourceChildV1: LinkedDeviceOwnerSourceChildResolverV1['resolveOwnerSourceChildV1'];
  private readonly signingWorkerRecipientPublicKeyB64u: string;

  constructor(input: D1LinkedDeviceSourceContributionPreparationPlannerOptionsV1) {
    this.resolveOwnerSourceChildV1 = input.resolveOwnerSourceChildV1;
    this.signingWorkerRecipientPublicKeyB64u = requireCanonicalBytes32(
      input.signingWorkerRecipientPublicKeyB64u,
      'signing worker recipient public key',
    );
  }

  async planSourceContributionPreparationV1(input: {
    readonly session: LinkedDeviceSessionRecordV1;
    readonly approval: LinkedDeviceApprovalV1;
    readonly preparation: LinkedDeviceTargetPreparationV1;
    readonly registration: LinkedDeviceTargetCredentialRegistrationV1;
    readonly evidence: VerifiedLinkedDeviceTargetFactorEvidenceV1;
    readonly targetFactor: VerifiedTargetFactorV1;
    readonly source: VerifiedLinkSourceReadV1;
    readonly requestedAtMs: number;
  }): Promise<LinkedDeviceOrdinaryMaterialSourceContributionPreparationTupleV1> {
    const preparations = [] as Array<
      | LinkedDeviceEd25519SourceContributionPreparationV1
      | LinkedDeviceEcdsaSourceContributionPreparationV1
    >;
    for (let index = 0; index < input.source.signerManifest.signers.length; index += 1) {
      const signer = input.source.signerManifest.signers[index];
      const sourceLaneHint = input.approval.orderedOwnerSourceLaneHints[index];
      const recipientRequest = input.registration.ordinarySignerMaterialRecipientRequests[index];
      if (!signer || !sourceLaneHint || !recipientRequest) {
        throw new Error(`linked-device source preparation ${index} is incomplete`);
      }
      assertSignerInputMatchesApproval(signer, sourceLaneHint, recipientRequest, index);
      const resolution = await this.resolveOwnerSourceChildV1({
        kind: 'preparation',
        session: input.session,
        approval: input.approval,
        sourceLaneHint,
        childIndex: index,
      });
      assertResolutionMatchesSigner(resolution, signer, sourceLaneHint, index);
      const targetActivation = freshTargetActivation(
        resolution.source.materialActivation,
        input,
        signer.walletKeyId,
        index,
      );
      if (signer.keyFamily === 'ed25519' && resolution.keyFamily === 'ed25519') {
        preparations.push(
          buildEd25519Preparation({
            input,
            source: input.source,
            signer,
            resolution,
            targetActivation,
            recipientRequest,
            signingWorkerRecipientPublicKeyB64u: this.signingWorkerRecipientPublicKeyB64u,
          }),
        );
        continue;
      }
      if (signer.keyFamily === 'ecdsa_secp256k1' && resolution.keyFamily === 'ecdsa_secp256k1') {
        preparations.push(
          buildEcdsaPreparation({
            input,
            signer,
            resolution,
            targetActivation,
            recipientRequest,
            signingWorkerRecipientPublicKeyB64u: this.signingWorkerRecipientPublicKeyB64u,
          }),
        );
        continue;
      }
      throw new Error(`linked-device source preparation ${index} has a mismatched key family`);
    }
    return parseLinkedDeviceOrdinaryMaterialSourceContributionPreparationTupleV1(preparations);
  }
}

export function createD1LinkedDeviceSourceContributionPreparationPlannerV1(
  input: D1LinkedDeviceSourceContributionPreparationPlannerOptionsV1,
): LinkedDeviceSourceContributionPreparationPlannerV1 {
  return new D1LinkedDeviceSourceContributionPreparationPlannerV1(input);
}

function buildEd25519Preparation(input: {
  readonly input: {
    readonly registration: LinkedDeviceTargetCredentialRegistrationV1;
    readonly targetFactor: VerifiedTargetFactorV1;
  };
  readonly source: VerifiedLinkSourceReadV1;
  readonly signer: ExactAdministeredEd25519SignerV1;
  readonly resolution: Extract<LinkedDeviceOwnerSourceChildResolutionV1, { readonly keyFamily: 'ed25519' }>;
  readonly targetActivation: MpcMaterialActivationRef;
  readonly recipientRequest: OrdinarySignerMaterialRecipientRequestV1;
  readonly signingWorkerRecipientPublicKeyB64u: string;
}): LinkedDeviceEd25519SourceContributionPreparationV1 {
  if (
    input.recipientRequest.keyFamily !== 'ed25519' ||
    input.recipientRequest.walletKeyId !== input.signer.walletKeyId
  ) {
    throw new Error('linked-device Ed25519 recipient request does not match the signer');
  }
  const targetClientRecipientPublicKeyB64u = input.recipientRequest.recipientPublicKeyB64u;
  const targetBinding = bindingWithMaterialActivation(
    input.resolution.sourceBinding,
    input.targetActivation,
  );
  const targetRequest = parseTargetRequest(targetBinding);
  const targetDeviceId = parseDeviceId(String(input.input.registration.deviceId));
  if (!targetDeviceId.ok) throw new Error(`target device id: ${targetDeviceId.error.message}`);
  if (input.resolution.source.sourceKind !== 'owner_registration') {
    throw new Error('linked-device Ed25519 source lane has no owner participant continuity');
  }
  return {
    kind: 'linked_device_ed25519_source_contribution_preparation_v1',
    linkSessionId: input.input.registration.linkSessionId,
    enrollmentId: input.input.registration.enrollmentId,
    sourceAuthorityId: input.source.authority.authorityId,
    walletKeyId: input.signer.walletKeyId,
    targetDeviceId: targetDeviceId.value,
    targetFactorVerificationDigestB64u: input.input.targetFactor.verificationDigestB64u,
    sourceBinding: input.resolution.sourceBinding,
    targetRequest,
    participantIds: input.resolution.source.ownerParticipantContinuity.participantIds,
    targetMaterialActivation: input.targetActivation,
    targetClientRecipientPublicKeyB64u,
    targetSigningWorkerRecipientPublicKeyB64u: input.signingWorkerRecipientPublicKeyB64u,
    sourceRegisteredPublicKeyB64u: input.signer.registeredPublicKeyB64u,
  };
}

function buildEcdsaPreparation(input: {
  readonly input: {
    readonly registration: LinkedDeviceTargetCredentialRegistrationV1;
    readonly targetFactor: VerifiedTargetFactorV1;
    readonly source: VerifiedLinkSourceReadV1;
  };
  readonly signer: ExactAdministeredEcdsaSignerV1;
  readonly resolution: Extract<LinkedDeviceOwnerSourceChildResolutionV1, { readonly keyFamily: 'ecdsa_secp256k1' }>;
  readonly targetActivation: MpcMaterialActivationRef;
  readonly recipientRequest: OrdinarySignerMaterialRecipientRequestV1;
  readonly signingWorkerRecipientPublicKeyB64u: string;
}): LinkedDeviceEcdsaSourceContributionPreparationV1 {
  if (
    input.recipientRequest.keyFamily !== 'ecdsa_secp256k1' ||
    input.recipientRequest.walletKeyId !== input.signer.walletKeyId
  ) {
    throw new Error('linked-device ECDSA recipient request does not match the signer');
  }
  const targetClientRecipientPublicKeyB64u = linkedDeviceX25519RecipientPublicKeyB64uV1(
    input.recipientRequest.clientEphemeralPublicKey,
  );
  const targetDeviceId = parseDeviceId(String(input.input.registration.deviceId));
  if (!targetDeviceId.ok) throw new Error(`target device id: ${targetDeviceId.error.message}`);
  return {
    linkSessionId: input.input.registration.linkSessionId,
    enrollmentId: input.input.registration.enrollmentId,
    sourceAuthorityId: input.input.source.authority.authorityId,
    source: {
      activation: input.resolution.source.materialActivation,
      clientPublicKey33B64u: parseSecp256k1CompressedPublicKeyB64u(
        input.resolution.sourceHolderVerifyingShare33B64u,
      ),
      relayerPublicKey33B64u: parseSecp256k1CompressedPublicKeyB64u(
        input.resolution.sourceServerVerifyingShare33B64u,
      ),
      thresholdPublicKey33B64u: parseSecp256k1CompressedPublicKeyB64u(
        input.resolution.thresholdPublicKey33B64u,
      ),
      thresholdEthereumAddress20B64u: evmAddressToBase64(input.resolution.evmAddress),
    },
    target: {
      activation: input.targetActivation,
      targetDeviceId: targetDeviceId.value,
      targetFactorVerificationDigestB64u: input.input.targetFactor.verificationDigestB64u,
      clientRecipientPublicKeyB64u: targetClientRecipientPublicKeyB64u,
      signingWorkerRecipientPublicKeyB64u: input.signingWorkerRecipientPublicKeyB64u,
    },
  };
}

function assertSignerInputMatchesApproval(
  signer: ExactAdministeredEd25519SignerV1 | ExactAdministeredEcdsaSignerV1,
  sourceLaneHint: LinkedDeviceApprovalV1['orderedOwnerSourceLaneHints'][number],
  recipientRequest: OrdinarySignerMaterialRecipientRequestV1,
  index: number,
): void {
  if (
    signer.keyFamily !== sourceLaneHint.keyFamily ||
    signer.walletKeyId !== sourceLaneHint.walletKey.walletKeyId ||
    signer.keyFamily !== recipientRequest.keyFamily ||
    signer.walletKeyId !== recipientRequest.walletKeyId
  ) {
    throw new Error(`linked-device source preparation ${index} differs from the signer manifest`);
  }
}

function assertResolutionMatchesSigner(
  resolution: LinkedDeviceOwnerSourceChildResolutionV1,
  signer: ExactAdministeredEd25519SignerV1 | ExactAdministeredEcdsaSignerV1,
  sourceLaneHint: LinkedDeviceApprovalV1['orderedOwnerSourceLaneHints'][number],
  index: number,
): void {
  if (
    resolution.walletKeyId !== signer.walletKeyId ||
    resolution.keyFamily !== signer.keyFamily ||
    resolution.source.laneId !== sourceLaneHint.lane.laneId ||
    resolution.source.laneShareEpoch !== sourceLaneHint.lane.laneShareEpoch ||
    resolution.source.revocationEpoch !== sourceLaneHint.lane.lifecycle.revocationEpoch ||
    resolution.source.participantBindingDigestB64u !== sourceLaneHint.lane.participantBindingDigestB64u
  ) {
    throw new Error(`linked-device source resolution ${index} differs from the approved lane`);
  }
}

function freshTargetActivation(
  source: MpcMaterialActivationRef,
  input: { readonly session: LinkedDeviceSessionRecordV1 },
  walletKeyId: string,
  index: number,
): MpcMaterialActivationRef {
  const parsed = parseMpcMaterialActivationId(
    `linked-device-target-material:${String(input.session.linkSessionId)}:${walletKeyId}:${index}:${secureRandomBase64Url(16, 'linked-device target material activation')}`,
  );
  if (!parsed.ok) throw new Error(`target material activation id: ${parsed.error.message}`);
  return buildMpcMaterialActivationRef({
    activationId: parsed.value,
    capability: source.capability,
    materialOwner: source.materialOwner,
    keyBinding: source.keyBinding,
    lifecycleBinding: source.lifecycleBinding,
    signingWorker: source.signingWorker,
  });
}

function bindingWithMaterialActivation(
  source: RouterAbEd25519YaoActivationBindingV1<'registration'>,
  materialActivation: MpcMaterialActivationRef,
): RouterAbEd25519YaoActivationBindingV1<'registration'> {
  return {
    lifecycle: {
      lifecycle_id: source.lifecycle.lifecycle_id,
      work_kind: source.lifecycle.work_kind,
      primitive_request_kind: source.lifecycle.primitive_request_kind,
      root_share_epoch: source.lifecycle.root_share_epoch,
      account_id: source.lifecycle.account_id,
      session_id: source.lifecycle.session_id,
      signer_set_id: source.lifecycle.signer_set_id,
      selected_server_id: source.lifecycle.selected_server_id,
    },
    operation: 'registration',
    session_id: source.session_id,
    stable_key_context_binding: source.stable_key_context_binding,
    material_activation: routerAbMpcMaterialActivationRefToWire(materialActivation),
  };
}

function parseTargetRequest(
  binding: RouterAbEd25519YaoActivationBindingV1<'registration'>,
): LinkedDeviceEd25519SourceContributionPreparationV1['targetRequest'] {
  const session = [...binding.session_id];
  const stableContextBinding = [...binding.stable_key_context_binding];
  const parsed = parseRouterAbEd25519YaoRegistrationActivationExecuteRequestV1({
    binding,
    deriver_a_input: encryptedInput('deriver_a', session, stableContextBinding),
    deriver_b_input: encryptedInput('deriver_b', session, stableContextBinding),
  });
  if (!parsed.ok) throw new Error(`linked-device target Ed25519 request: ${parsed.message}`);
  return parsed.value;
}

function encryptedInput(
  deriver: RouterAbEd25519YaoDeriverRoleV1,
  session: readonly number[],
  stableContextBinding: readonly number[],
): Record<string, unknown> {
  return {
    kind: 'activation',
    deriver,
    operation: 'registration',
    session,
    stable_context_binding: stableContextBinding,
    encapsulated_key: randomBytes32('linked-device target Ed25519 encapsulated key'),
    ciphertext: randomBytes32('linked-device target Ed25519 ciphertext'),
  };
}

function randomBytes32(label: string): readonly number[] {
  return [...base64UrlDecode(secureRandomBase64Url(32, label))];
}

function requireCanonicalBytes32(value: string, label: string): string {
  const bytes = base64UrlDecode(value);
  if (bytes.length !== 32 || base64UrlEncode(bytes) !== value) {
    throw new Error(`${label} must be canonical base64url for 32 bytes`);
  }
  return value;
}

export function linkedDeviceX25519RecipientPublicKeyB64uV1(value: string): string {
  if (!/^x25519:[0-9a-f]{64}$/.test(value)) {
    throw new Error('ECDSA client ephemeral public key is invalid');
  }
  const bytes = new Uint8Array(32);
  for (let index = 0; index < bytes.length; index += 1) {
    bytes[index] = Number.parseInt(value.slice(8 + index * 2, 10 + index * 2), 16);
  }
  return base64UrlEncode(bytes);
}

function evmAddressToBase64(value: string): string {
  if (!/^0x[0-9a-fA-F]{40}$/.test(value)) {
    throw new Error('source ECDSA Ethereum address is invalid');
  }
  const bytes = new Uint8Array(20);
  for (let index = 0; index < bytes.length; index += 1) {
    bytes[index] = Number.parseInt(value.slice(2 + index * 2, 4 + index * 2), 16);
  }
  return base64UrlEncode(bytes);
}
