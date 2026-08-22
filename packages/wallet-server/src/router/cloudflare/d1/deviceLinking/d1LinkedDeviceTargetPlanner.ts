import { hasDelegatedWalletPermissionV1 } from '@shared/authorization/delegatedAuthority';
import type {
  LinkedDeviceApprovalV1,
  LinkedDeviceOwnerSourceLaneV1,
  LinkedDevicePasskeyCreationOptionsV1,
  LinkedDeviceTargetPreparationV1,
  OrdinarySignerMaterialRecipientRequirementV1,
} from '@shared/device-linking/contracts';
import { buildLinkedDeviceTargetPreparationV1 } from '@shared/device-linking/parsers';
import { base64UrlEncode } from '@shared/utils/base64';
import type { DigestB64u } from '@shared/utils/canonicalPrimitives';
import { secureRandomBase64Url } from '@shared/utils/secureRandomId';
import {
  PASSKEY_PRF_FIRST_SALT_V1,
  PASSKEY_PRF_SECOND_SALT_V1,
} from '@shared/utils/signingSessionSeal';
import {
  parseWalletAuthMethodId,
  mpcMaterialActivationRefsEqual,
} from '@shared/utils/domainIds';
import type {
  ActiveLaneProtocolSourceV1,
  EcdsaSourceCapabilityBindingV1,
  EcdsaTargetCapabilityBindingV1,
  LaneTargetSigningWorkerV1,
} from '@shared/signing-lanes/rotation';
import type { LaneHolderParticipantId } from '@shared/signing-lanes/participants';
import type { EvmFamilySigningKeySlotId } from '@shared/signing-lanes/evmFamilySigningKeySlotId';
import type { KeyCreationSignerSlot } from '@shared/passkey-custody/primitives';
import type { Ed25519PublicKeyB64u } from '@shared/passkey-custody/primitives';
import type { RouterAbEd25519YaoActivationBindingV1 } from '@shared/utils/routerAbEd25519Yao';
import type {
  NearEd25519SigningKeyId,
  WalletAuthMethodRecordV2,
} from '@shared/utils/registrationIntent';
import type { WalletKeyId } from '@shared/signing-lanes/ids';
import type { LinkedDeviceSessionRecordV1 } from '../../../../core/deviceLinking/linkedDeviceSession';
import type {
  LinkedDeviceTargetPlannerV1,
} from './d1LinkedDeviceTargetCredentialProvider';

const DEFAULT_TARGET_PREPARATION_TTL_MS = 5 * 60 * 1_000;

type LinkedDeviceOwnerSourceChildResolutionBaseV1 = {
  readonly walletKeyId: WalletKeyId;
  readonly source: ActiveLaneProtocolSourceV1;
};

/** Facts authenticated from Device 1's owner lane projection. Target
 * participant and capability material is intentionally absent until Device 2
 * returns its verified factor and public recipient requests. */
type LinkedDeviceOwnerEd25519SourceChildResolutionV1 =
  LinkedDeviceOwnerSourceChildResolutionBaseV1 & {
    readonly keyFamily: 'ed25519';
    readonly applicationBindingDigestB64u: DigestB64u;
    readonly registeredPublicKeyB64u: Ed25519PublicKeyB64u;
    readonly nearEd25519SigningKeyId: NearEd25519SigningKeyId;
    readonly keyCreationSignerSlot: KeyCreationSignerSlot;
    readonly stableContextBindingB64u: string;
    readonly sourceBinding: RouterAbEd25519YaoActivationBindingV1<'registration'>;
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
    readonly applicationBindingDigestB64u: DigestB64u;
    readonly clientShareRetryCounter: number;
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
      readonly sourceLaneHint: LinkedDeviceOwnerSourceLaneV1;
      readonly childIndex: number;
    };

export type LinkedDeviceOwnerSourceChildResolverV1 = {
  resolveOwnerSourceChildV1(
    input: LinkedDeviceOwnerSourceChildResolutionRequestV1,
  ): Promise<LinkedDeviceTargetPreparationResolutionV1>;
};

export type D1LinkedDeviceTargetPlannerOptionsV1 = {
  readonly resolveOwnerSourceChildV1: LinkedDeviceOwnerSourceChildResolverV1['resolveOwnerSourceChildV1'];
  readonly preparationTtlMs?: number;
};

/**
 * Builds the one durable target preparation. Ordinary material activation and
 * reservation identities are derived only after Device 2 verifies its factor.
 */
export class D1LinkedDeviceTargetPlannerV1 implements LinkedDeviceTargetPlannerV1 {
  private readonly resolveOwnerSourceChildV1: LinkedDeviceOwnerSourceChildResolverV1['resolveOwnerSourceChildV1'];
  private readonly preparationTtlMs: number;

  constructor(input: D1LinkedDeviceTargetPlannerOptionsV1) {
    this.resolveOwnerSourceChildV1 = input.resolveOwnerSourceChildV1;
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
    readonly sourceAuthMethod: Extract<WalletAuthMethodRecordV2, { readonly status: 'active' }>;
  }): Promise<LinkedDeviceTargetPreparationV1> {
    assertPreparationInput(input.session, input.approval, input.requestedAtMs);
    // A preparation cannot outlive the approved link session.
    const expiresAtMs = Math.min(
      input.approval.expiresAtMs,
      input.requestedAtMs + this.preparationTtlMs,
    );
    if (expiresAtMs <= input.requestedAtMs) {
      throw new Error('linked-device target preparation has no remaining lifetime');
    }

    const ordinarySignerMaterialRecipientRequirements: OrdinarySignerMaterialRecipientRequirementV1[] = [];
    let ed25519ExportRoot: LinkedDeviceTargetPreparationV1['ed25519ExportRoot'] = null;
    for (
      let childIndex = 0;
      childIndex < input.approval.orderedOwnerSourceLaneHints.length;
      childIndex += 1
    ) {
      const sourceLaneHint = input.approval.orderedOwnerSourceLaneHints[childIndex];
      if (!sourceLaneHint) throw new Error(`linked-device approval child ${childIndex} is missing`);
      const resolution = await this.resolveOwnerSourceChildV1({
        kind: 'preparation',
        session: input.session,
        approval: input.approval,
        sourceLaneHint,
        childIndex,
      });
      assertResolutionMatchesSourceLaneHint(resolution, sourceLaneHint, childIndex);
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
      ordinarySignerMaterialRecipientRequirements.push({
        kind: 'ordinary_signer_material_recipient_requirement_v1',
        walletKeyId: sourceLaneHint.walletKey.walletKeyId,
        keyFamily: sourceLaneHint.keyFamily,
      });
    }

    const walletAuthMethodId = parseWalletAuthMethodId(
      `wallet-auth-method:${secureRandomBase64Url(32, 'linked-device target wallet auth method')}`,
    );
    if (!walletAuthMethodId.ok) {
      throw new Error(`linked-device target wallet auth method id: ${walletAuthMethodId.error.message}`);
    }

    if (input.approval.targetFactor.kind === 'passkey_prf') {
      return buildLinkedDeviceTargetPreparationV1({
        linkSessionId: input.approval.linkSessionId,
        walletId: input.approval.walletId,
        enrollmentId: input.approval.enrollmentId,
        deviceId: input.approval.deviceId,
        walletAuthMethodId: walletAuthMethodId.value,
        ed25519ExportRoot,
        targetFactor: input.approval.targetFactor,
        passkeyCreationOptions: buildPasskeyCreationOptionsV1({
          walletAuthMethodId: walletAuthMethodId.value,
          walletId: input.approval.walletId,
          sourceAuthMethod: input.sourceAuthMethod,
        }),
        ordinarySignerMaterialRecipientRequirements: requireNonEmpty(
          ordinarySignerMaterialRecipientRequirements,
          'linked-device ordinary signer material recipient requirements',
        ),
        issuedAtMs: input.requestedAtMs,
        expiresAtMs,
      });
    }

    return buildLinkedDeviceTargetPreparationV1({
      linkSessionId: input.approval.linkSessionId,
      walletId: input.approval.walletId,
      enrollmentId: input.approval.enrollmentId,
      deviceId: input.approval.deviceId,
      walletAuthMethodId: walletAuthMethodId.value,
      ed25519ExportRoot,
      targetFactor: input.approval.targetFactor,
      ordinarySignerMaterialRecipientRequirements: requireNonEmpty(
        ordinarySignerMaterialRecipientRequirements,
        'linked-device ordinary signer material recipient requirements',
      ),
      issuedAtMs: input.requestedAtMs,
      expiresAtMs,
    });
  }

}

function buildPasskeyCreationOptionsV1(input: {
  readonly walletAuthMethodId: Extract<WalletAuthMethodRecordV2, { readonly status: 'active' }>['walletAuthMethodId'];
  readonly walletId: Extract<WalletAuthMethodRecordV2, { readonly status: 'active' }>['walletId'];
  readonly sourceAuthMethod: Extract<WalletAuthMethodRecordV2, { readonly status: 'active' }>;
}): LinkedDevicePasskeyCreationOptionsV1 {
  if (input.sourceAuthMethod.kind !== 'passkey') {
    throw new Error('linked-device passkey preparation requires a passkey source auth method');
  }
  const challengeId = secureRandomBase64Url(16, 'linked-device target passkey challenge id');
  const challengeB64u = secureRandomBase64Url(32, 'linked-device target passkey challenge');
  return {
    kind: 'webauthn_add_auth_method_registration_v1',
    walletAuthMethodId: input.walletAuthMethodId,
    challengeId,
    challengeB64u,
    rpId: input.sourceAuthMethod.rpId,
    user: {
      idB64u: base64UrlEncode(new TextEncoder().encode(String(input.walletId))),
      name: String(input.walletId),
      displayName: String(input.walletId),
    },
    pubKeyCredParams: [
      { type: 'public-key', alg: -7 },
      { type: 'public-key', alg: -257 },
    ],
    authenticatorSelection: {
      residentKey: 'required',
      userVerification: 'preferred',
    },
    timeoutMs: 60_000,
    attestation: 'none',
    extensions: {
      prf: {
        eval: {
          firstB64u: base64UrlEncode(PASSKEY_PRF_FIRST_SALT_V1),
          secondB64u: base64UrlEncode(PASSKEY_PRF_SECOND_SALT_V1),
        },
      },
    },
    excludeCredentials: [
      {
        type: 'public-key',
        id: input.sourceAuthMethod.credentialIdB64u,
      },
    ],
  };
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

function assertResolutionMatchesSourceLaneHint(
  resolution: LinkedDeviceOwnerSourceChildResolutionV1,
  sourceLaneHint: LinkedDeviceOwnerSourceLaneV1,
  childIndex: number,
): void {
  if (
    resolution.walletKeyId !== sourceLaneHint.walletKey.walletKeyId ||
    resolution.keyFamily !== sourceLaneHint.keyFamily ||
    resolution.source.laneId !== sourceLaneHint.lane.laneId ||
    resolution.source.laneKind !== sourceLaneHint.lane.laneKind ||
    resolution.source.laneShareEpoch !== sourceLaneHint.lane.laneShareEpoch ||
    resolution.source.revocationEpoch !== sourceLaneHint.lane.lifecycle.revocationEpoch ||
    resolution.source.participantBindingDigestB64u !==
      sourceLaneHint.lane.participantBindingDigestB64u ||
    !mpcMaterialActivationRefsEqual(
      resolution.source.materialActivation,
      sourceLaneHint.materialActivation,
    )
  ) {
    throw new Error(`linked-device source resolution ${childIndex} differs from approval`);
  }
}

function requireNonEmpty<T>(values: readonly T[], label: string): readonly [T, ...T[]] {
  const [first, ...rest] = values;
  if (first === undefined) throw new Error(`${label} must not be empty`);
  return [first, ...rest];
}
