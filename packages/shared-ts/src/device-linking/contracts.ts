import type { DelegatedWalletAuthorityV1 } from '../authorization/delegatedAuthority';
import type {
  AuthorizationEvidenceSetId,
  AuthorizedOperationId,
  DeviceId,
  LinkedDeviceWalletSessionAuthorizationId,
  MpcWalletSigningQuotaId,
  TenantId,
  WalletSessionAuthorizationId,
  WalletSessionId,
} from '../authorization/capabilityKinds';
import type {
  LaneHolderParticipantId,
  SigningWorkerParticipantId,
} from '../signing-lanes/participants';
import type {
  LaneOperationId,
  LaneOperationIdempotencyKey,
  LaneShareEpoch,
  LinkedDeviceEnrollmentId,
  LinkedDeviceId,
  LinkDeviceSessionId,
  SigningLaneId,
  WalletKeyId,
} from '../signing-lanes/ids';
import type { SigningLaneKind } from '../signing-lanes/records';
import type { OwnerLaneParticipantContinuityV1 } from '../signing-lanes/ownerContinuity';
import type {
  MpcMaterialActivationRef,
  WalletAuthorityId,
  WalletAuthMethodId,
  WalletId,
  WebAuthnCredentialIdB64u,
} from '../utils/domainIds';
import type { WebAuthnAuthenticatorDeviceInfo } from '../utils/webauthnDeviceInfo';
import type { DigestB64u } from '../utils/canonicalPrimitives';
import type { Ed25519PublicKeyB64u } from '../passkey-custody/primitives';
import type { WalletAddAuthMethodRegistrationOptions } from '../utils/addAuthMethodRegistration';
import type {
  LaneHolderDeliveryReceiptV1,
  LaneHolderPackageWireV1,
  LaneProtocolCommitReceiptV1,
  LaneEnrollmentManifestV1,
  RotatableSigningLaneJobV1,
  ActiveLaneProtocolSourceV1,
} from '../signing-lanes/rotation';
import type { SigningLaneRecord, WalletKeyRecord } from '../signing-lanes/records';
import type {
  EcdsaCapabilityManifestId,
  EcdsaCapabilityManifestRevision,
} from '../utils/ecdsaCapabilityActivation';
import type { NearAccountId } from '../utils/near';
import type {
  ActiveWalletAuthorityV1,
  WalletAuthorityV1,
  WalletSignerActivationSetV1,
} from '../authorization/walletAuthority';
import type {
  CanonicalDelegatedWalletPermissionSetV1,
} from '../authorization/delegatedAuthority';
import type { ExactAdministeredSignerManifestV1 } from './delegatedActivationPlan';
import type {
  EmailOtpWalletAuthMethodDraftV1,
  PasskeyWalletAuthMethodDraftV1,
  WalletAuthMethodRecordV2,
} from '../utils/registrationIntent';
import type { RouterAbEd25519YaoActivationExecuteRequestV1 } from '../utils/routerAbEd25519Yao';
import type { RouterAbEcdsaRegistrationRequestV1 } from '../utils/routerAbEcdsaDerivation';

export type {
  CommittedAuthorityPackagesV1,
  CommittedEd25519SignerPackageV1,
  CommittedEcdsaSignerPackageV1,
  PendingWalletAuthMethodRecordV1,
  CommittedSignerPackageSetDigestInputV1,
  CommittedSignerPackageSetV1,
} from './committedSignerPackages';

/** Public key bytes carried by the link session, encoded as canonical base64url. */
export type LinkDevicePublicKeyB64u = string & {
  readonly __linkDevicePublicKeyB64uBrand: 'LinkDevicePublicKeyB64u';
};

export type LinkedDeviceTargetFactorV1 =
  | { readonly kind: 'passkey_prf' }
  | { readonly kind: 'email_otp' };

export type QrLinkedDeviceSessionPayloadV5 = {
  readonly version: 'v5';
  readonly purpose: 'linked_device_lane_creation';
  readonly linkSessionId: LinkDeviceSessionId;
  readonly linkPublicKeyB64u: LinkDevicePublicKeyB64u;
  readonly devicePublicKeyB64u: LinkDevicePublicKeyB64u;
  readonly requestedPermission: DelegatedWalletAuthorityV1;
  readonly targetFactor: LinkedDeviceTargetFactorV1;
  readonly issuedAtMs: number;
  readonly expiresAtMs: number;
};

type LinkedDeviceOwnerSourceLaneBaseV1<TWalletKey extends WalletKeyRecord> = {
  readonly kind: 'linked_device_owner_source_lane_v1';
  readonly walletKey: TWalletKey;
  readonly lane: Extract<
    SigningLaneRecord,
    { readonly laneKind: 'owner_passkey' | 'owner_email_otp' }
  >;
  readonly materialActivation: MpcMaterialActivationRef;
  readonly verifiedActivationReceiptDigestB64u: DigestB64u;
};

/** Public owner-lane identity authenticated by the wallet-host Wallet Session. */
export type LinkedDeviceOwnerSourceLaneV1 =
  | (LinkedDeviceOwnerSourceLaneBaseV1<
      Extract<WalletKeyRecord, { readonly keyFamily: 'ed25519' }>
    > & {
      readonly keyFamily: 'ed25519';
      readonly ecdsaSourceManifest?: never;
    })
  | (LinkedDeviceOwnerSourceLaneBaseV1<
      Extract<WalletKeyRecord, { readonly keyFamily: 'ecdsa_secp256k1' }>
    > & {
      readonly keyFamily: 'ecdsa_secp256k1';
      readonly ecdsaSourceManifest: {
        readonly manifestId: EcdsaCapabilityManifestId;
        readonly manifestRevision: EcdsaCapabilityManifestRevision;
      };
    });

/**
 * Authenticated Device 1 owner-authorization request. Source-lane hints carry
 * public wallet/lane identity and activation receipts only; Router re-resolves
 * every hint against its durable wallet projection.
 */
export type LinkedDeviceOwnerAuthorizationRequestV1 = {
  readonly payload: QrLinkedDeviceSessionPayloadV5;
  readonly requestedAtMs: number;
  readonly orderedOwnerSourceLaneHints: readonly [
    LinkedDeviceOwnerSourceLaneV1,
    ...LinkedDeviceOwnerSourceLaneV1[],
  ];
};

export type LinkedDeviceLocalPresenceAssertionV1 = {
  readonly kind: 'linked_device_local_presence_assertion_v1';
  readonly authorizedOperationId: AuthorizedOperationId;
  readonly deviceId: LinkedDeviceId;
  readonly enrollmentId: LinkedDeviceEnrollmentId;
  readonly credentialIdB64u: WebAuthnCredentialIdB64u;
  readonly intentDigestB64u: DigestB64u;
  readonly challengeDigestB64u: DigestB64u;
  readonly issuedAtMs: number;
  readonly expiresAtMs: number;
  readonly assertion: unknown;
};

/**
 * One exhaustive link-session state. The `never` fields intentionally keep
 * unclaimed branches from acquiring wallet or enrollment identity.
 */
export type LinkedDeviceSessionState =
  | {
      readonly state: 'displaying_qr';
      readonly linkSessionId: LinkDeviceSessionId;
      readonly expiresAtMs: number;
      readonly walletId?: never;
      readonly enrollmentId?: never;
    }
  | {
      readonly state: 'claimed_by_owner';
      readonly linkSessionId: LinkDeviceSessionId;
      readonly walletId: WalletId;
      readonly enrollmentId: LinkedDeviceEnrollmentId;
      readonly claimExpiresAtMs: number;
    }
  | {
      readonly state: 'awaiting_target_factor';
      readonly linkSessionId: LinkDeviceSessionId;
      readonly walletId: WalletId;
      readonly enrollmentId: LinkedDeviceEnrollmentId;
      readonly targetFactor: { readonly kind: 'passkey_prf' };
      readonly credentialDeadlineMs: number;
      readonly emailOtpChallenge?: never;
    }
  | {
      readonly state: 'awaiting_target_factor';
      readonly linkSessionId: LinkDeviceSessionId;
      readonly walletId: WalletId;
      readonly enrollmentId: LinkedDeviceEnrollmentId;
      readonly targetFactor: { readonly kind: 'email_otp' };
      readonly credentialDeadlineMs?: never;
      readonly emailOtpChallenge:
        | {
            readonly state: 'available';
            readonly maskedEmailHint: string;
          }
        | {
            readonly state: 'sent';
            readonly challengeId: string;
            readonly workerEphemeralPublicKey65B64u: string;
            readonly maskedEmailHint: string;
            readonly expiresAtMs: number;
            readonly resendAvailableAtMs: number;
          };
    }
  | {
      readonly state: 'provisioning';
      readonly linkSessionId: LinkDeviceSessionId;
      readonly walletId: WalletId;
      readonly enrollmentId: LinkedDeviceEnrollmentId;
      readonly keyManifestDigestB64u: DigestB64u;
    }
  | {
      readonly state: 'active';
      readonly linkSessionId: LinkDeviceSessionId;
      readonly walletId: WalletId;
      readonly enrollmentId: LinkedDeviceEnrollmentId;
      readonly activatedAtMs: number;
    }
  | {
      readonly state: 'expired_unclaimed';
      readonly linkSessionId: LinkDeviceSessionId;
      readonly expiredAtMs: number;
      readonly walletId?: never;
      readonly enrollmentId?: never;
    }
  | {
      readonly state: 'expired_claimed';
      readonly linkSessionId: LinkDeviceSessionId;
      readonly walletId: WalletId;
      readonly enrollmentId: LinkedDeviceEnrollmentId;
      readonly expiredAtMs: number;
    }
  | {
      readonly state: 'cancelled_unclaimed';
      readonly linkSessionId: LinkDeviceSessionId;
      readonly cancelledAtMs: number;
      readonly walletId?: never;
      readonly enrollmentId?: never;
    }
  | {
      readonly state: 'cancelled_claimed_precommit';
      readonly linkSessionId: LinkDeviceSessionId;
      readonly walletId: WalletId;
      readonly enrollmentId: LinkedDeviceEnrollmentId;
      readonly cancelledAtMs: number;
    }
  | {
      readonly state: 'committed_completion_required';
      readonly linkSessionId: LinkDeviceSessionId;
      readonly walletId: WalletId;
      readonly enrollmentId: LinkedDeviceEnrollmentId;
      readonly keyManifestDigestB64u: DigestB64u;
      readonly transcriptSetDigestB64u: DigestB64u;
    };

export type LinkedDeviceSessionUnclaimedState = Extract<
  LinkedDeviceSessionState,
  { readonly state: 'displaying_qr' | 'expired_unclaimed' | 'cancelled_unclaimed' }
>;

export type LinkedDeviceSessionClaimRequestV1 = {
  readonly kind: 'linked_device_session_claim_request_v1';
  readonly payload: QrLinkedDeviceSessionPayloadV5;
};

export type LinkedDeviceSessionClaimV1 = {
  readonly kind: 'linked_device_session_claim_v1';
  readonly linkSessionId: LinkDeviceSessionId;
  readonly walletId: WalletId;
  readonly enrollmentId: LinkedDeviceEnrollmentId;
  readonly deviceId: LinkedDeviceId;
  readonly devicePublicKeyB64u: LinkDevicePublicKeyB64u;
  readonly targetFactor: LinkedDeviceTargetFactorV1;
  readonly claimedAtMs: number;
  readonly claimExpiresAtMs: number;
};

/** Exactly one opaque Wallet Session or one fresh step-up authorization source. */
export type LinkedDeviceOwnerAuthorizationSourceV1 =
  | {
      readonly kind: 'wallet_session';
      readonly walletSessionId: WalletSessionId;
      readonly authorizationId: WalletSessionAuthorizationId;
      readonly stepUpEvidenceSetId?: never;
    }
  | {
      readonly kind: 'step_up';
      readonly evidenceSetId: AuthorizationEvidenceSetId;
      readonly walletSessionId?: never;
      readonly authorizationId?: never;
    };

type LinkedDeviceEnrollmentKeyBindingBaseV1 = {
  readonly walletKeyId: WalletKeyId;
  readonly keyFamily: 'ed25519' | 'ecdsa_secp256k1';
  readonly sourceLaneId: SigningLaneId;
  readonly sourceLaneKind: SigningLaneKind;
  readonly sourceKind: 'owner_registration' | 'provisioned_lane';
  readonly sourceLaneShareEpoch: LaneShareEpoch;
  readonly sourceRevocationEpoch: number;
  readonly targetLaneId: SigningLaneId;
  readonly targetLaneShareEpoch: LaneShareEpoch;
};

export type LinkedDeviceOwnerEnrollmentKeyBindingV1 = LinkedDeviceEnrollmentKeyBindingBaseV1 & {
  readonly sourceKind: 'owner_registration';
  readonly sourceLaneKind: 'owner_passkey' | 'owner_email_otp';
  readonly ownerParticipantContinuity: OwnerLaneParticipantContinuityV1;
  readonly sourceHolderParticipantId?: never;
  readonly sourceSigningWorkerParticipantId?: never;
};

export type LinkedDeviceProvisionedEnrollmentKeyBindingV1 =
  LinkedDeviceEnrollmentKeyBindingBaseV1 & {
    readonly sourceKind: 'provisioned_lane';
    readonly sourceLaneKind: Exclude<SigningLaneKind, 'owner_passkey' | 'owner_email_otp'>;
    readonly sourceHolderParticipantId: LaneHolderParticipantId;
    readonly sourceSigningWorkerParticipantId: SigningWorkerParticipantId;
    readonly ownerParticipantContinuity?: never;
  };

export type LinkedDeviceEnrollmentKeyBindingV1 =
  | LinkedDeviceOwnerEnrollmentKeyBindingV1
  | LinkedDeviceProvisionedEnrollmentKeyBindingV1;

export function linkedDeviceEnrollmentBindingMatchesSourceV1(
  binding: LinkedDeviceEnrollmentKeyBindingV1,
  source: ActiveLaneProtocolSourceV1,
): boolean {
  if (
    binding.sourceKind !== source.sourceKind ||
    binding.sourceLaneKind !== source.laneKind ||
    binding.sourceLaneId !== source.laneId ||
    binding.sourceLaneShareEpoch !== source.laneShareEpoch ||
    binding.sourceRevocationEpoch !== source.revocationEpoch
  ) {
    return false;
  }
  if (source.sourceKind === 'owner_registration') {
    if (binding.sourceKind !== 'owner_registration') return false;
    return (
      binding.ownerParticipantContinuity.signerId === source.ownerParticipantContinuity.signerId &&
      binding.ownerParticipantContinuity.signingWorkerId ===
        source.ownerParticipantContinuity.signingWorkerId &&
      binding.ownerParticipantContinuity.custodyKeyManifestDigestB64u ===
        source.ownerParticipantContinuity.custodyKeyManifestDigestB64u &&
      binding.ownerParticipantContinuity.sourceIdentityDigestB64u ===
        source.ownerParticipantContinuity.sourceIdentityDigestB64u &&
      binding.ownerParticipantContinuity.participantIds[0] ===
        source.ownerParticipantContinuity.participantIds[0] &&
      binding.ownerParticipantContinuity.participantIds[1] ===
        source.ownerParticipantContinuity.participantIds[1]
    );
  }
  if (binding.sourceKind !== 'provisioned_lane') return false;
  return (
    binding.sourceHolderParticipantId === source.holderParticipantId &&
    binding.sourceSigningWorkerParticipantId === source.signingWorkerParticipantId
  );
}

export type LinkedDeviceProtocolVersionV1 = {
  readonly keyFamily: 'ed25519' | 'ecdsa_secp256k1';
  readonly version: string;
};

type LinkedDeviceApprovalBaseV1 = {
  readonly kind: 'linked_device_approval_v1';
  readonly linkSessionId: LinkDeviceSessionId;
  readonly walletId: WalletId;
  readonly enrollmentId: LinkedDeviceEnrollmentId;
  readonly deviceId: LinkedDeviceId;
  readonly linkPublicKeyB64u: LinkDevicePublicKeyB64u;
  readonly devicePublicKeyB64u: LinkDevicePublicKeyB64u;
  readonly permission: DelegatedWalletAuthorityV1;
  readonly ownerAuthorization: LinkedDeviceOwnerAuthorizationSourceV1;
  /**
   * Refactor 103 Phase 8: the canonical owner add-auth-method ceremony this
   * enrollment will finalize.
   *
   * Device 2 has no owner authority and cannot start one. Device 1 does, and
   * approval is the one owner-authenticated step in the flow, so the ceremony
   * is started there and travels with the approval that authorizes it. An
   * approval is already immutable once recorded and replayed by digest, which
   * is exactly the lifecycle this binding needs: the same approval returns the
   * same ceremony, and a conflicting retry is refused.
   */
  readonly policyDigestB64u: DigestB64u;
  readonly operationId: LaneOperationId;
  readonly idempotencyKey: LaneOperationIdempotencyKey;
  readonly orderedKeyBindings: readonly [
    LinkedDeviceEnrollmentKeyBindingV1,
    ...LinkedDeviceEnrollmentKeyBindingV1[],
  ];
  readonly protocolVersions: readonly [
    LinkedDeviceProtocolVersionV1,
    ...LinkedDeviceProtocolVersionV1[],
  ];
  readonly approvedAtMs: number;
  readonly expiresAtMs: number;
};

export type LinkedDeviceApprovalV1 = LinkedDeviceApprovalBaseV1 &
  (
    | {
        readonly targetFactor: { readonly kind: 'passkey_prf' };
        readonly ownerEnrollment: Extract<
          LinkedDeviceOwnerEnrollmentCeremonyV1,
          { readonly kind: 'linked_device_passkey_owner_enrollment_v1' }
        >;
      }
    | {
        readonly targetFactor: { readonly kind: 'email_otp' };
        readonly ownerEnrollment: Extract<
          LinkedDeviceOwnerEnrollmentCeremonyV1,
          { readonly kind: 'linked_device_email_otp_owner_enrollment_v1' }
        >;
      }
  );

export type LinkedDeviceProvisioningCommandV1 = {
  readonly kind: 'linked_device_provisioning_command_v1';
  readonly linkSessionId: LinkDeviceSessionId;
  readonly enrollmentId: LinkedDeviceEnrollmentId;
  readonly deviceId: LinkedDeviceId;
  readonly targetFactor: LinkedDeviceTargetFactorV1;
};

/** Role-bound ciphertext delivery for one approved R102 child lane. */
export type LinkedDeviceProvisioningChildV1 = {
  readonly kind: 'linked_device_provisioning_child_v1';
  readonly job: RotatableSigningLaneJobV1;
  readonly protocolCommitReceipt: LaneProtocolCommitReceiptV1;
  readonly holderPackage: LaneHolderPackageWireV1;
  readonly expectedVersion: number;
};

export type LinkedDeviceProvisioningDeliveriesV1 = {
  readonly kind: 'linked_device_provisioning_deliveries_v1';
  readonly linkSessionId: LinkDeviceSessionId;
  readonly enrollmentId: LinkedDeviceEnrollmentId;
  readonly deviceId: LinkedDeviceId;
  readonly manifest: LaneEnrollmentManifestV1;
  readonly orderedChildren: readonly [
    LinkedDeviceProvisioningChildV1,
    ...LinkedDeviceProvisioningChildV1[],
  ];
};

/**
 * Exact owner-authenticated R102 source input. Jobs contain public protocol,
 * recipient, and participant records; private holder, PRF, and credential
 * material never crosses this DTO.
 */
export type LinkedDeviceTargetReadyR102InputV1 = {
  readonly kind: 'linked_device_target_ready_r102_input_v1';
  readonly linkSessionId: LinkDeviceSessionId;
  readonly walletId: WalletId;
  readonly enrollmentId: LinkedDeviceEnrollmentId;
  readonly deviceId: LinkedDeviceId;
  readonly manifest: LaneEnrollmentManifestV1;
  readonly children: readonly [RotatableSigningLaneJobV1, ...RotatableSigningLaneJobV1[]];
};

/** Owner-authenticated persistence submission for prepared R102 deliveries. */
export type LinkedDeviceProvisioningDeliveriesSubmissionV1 = {
  readonly kind: 'linked_device_provisioning_deliveries_submission_v1';
  readonly linkSessionId: LinkDeviceSessionId;
  readonly walletId: WalletId;
  readonly enrollmentId: LinkedDeviceEnrollmentId;
  readonly deviceId: LinkedDeviceId;
  readonly manifestDigestB64u: DigestB64u;
  readonly deliveries: LinkedDeviceProvisioningDeliveriesV1;
};

export type LinkedDeviceApprovalDeliveryV1 = {
  readonly kind: 'linked_device_approval_delivery_v1';
  readonly approval: LinkedDeviceApprovalV1;
};

/** Device2 returns only the holder receipts it produced for this enrollment. */
export type LinkedDeviceHolderDeliveryAcknowledgementV1 = {
  readonly kind: 'linked_device_holder_delivery_acknowledgement_v1';
  readonly linkSessionId: LinkDeviceSessionId;
  readonly enrollmentId: LinkedDeviceEnrollmentId;
  readonly deviceId: LinkedDeviceId;
  readonly orderedHolderDeliveryReceipts: readonly [
    LaneHolderDeliveryReceiptV1,
    ...LaneHolderDeliveryReceiptV1[],
  ];
  readonly acknowledgedAtMs: number;
};

export type LinkedDeviceEnrollmentTranscriptV1 = {
  readonly kind: 'linked_device_enrollment_transcript_v1';
  readonly linkSessionId: LinkDeviceSessionId;
  readonly walletId: WalletId;
  readonly enrollmentId: LinkedDeviceEnrollmentId;
  readonly deviceId: LinkedDeviceId;
  readonly linkPublicKeyB64u: LinkDevicePublicKeyB64u;
  readonly devicePublicKeyB64u: LinkDevicePublicKeyB64u;
  readonly permission: DelegatedWalletAuthorityV1;
  readonly targetFactor: LinkedDeviceTargetFactorV1;
  readonly ownerAuthorization: LinkedDeviceOwnerAuthorizationSourceV1;
  readonly policyDigestB64u: DigestB64u;
  readonly operationId: LaneOperationId;
  readonly idempotencyKey: LaneOperationIdempotencyKey;
  readonly orderedKeyBindings: readonly [
    LinkedDeviceEnrollmentKeyBindingV1,
    ...LinkedDeviceEnrollmentKeyBindingV1[],
  ];
  readonly protocolVersions: readonly [
    LinkedDeviceProtocolVersionV1,
    ...LinkedDeviceProtocolVersionV1[],
  ];
  readonly approvedAtMs: number;
  readonly expiresAtMs: number;
};

/** Public projection of one R102 child receipt; protocol receipt bodies stay private. */
export type LinkedDeviceEnrollmentChildReceiptV1 = {
  readonly kind: 'linked_device_enrollment_child_receipt_v1';
  readonly enrollmentId: LinkedDeviceEnrollmentId;
  readonly walletId: WalletId;
  readonly walletKeyId: WalletKeyId;
  readonly keyFamily: 'ed25519' | 'ecdsa_secp256k1';
  readonly targetLaneId: SigningLaneId;
  readonly targetLaneShareEpoch: LaneShareEpoch;
  readonly materialActivation: MpcMaterialActivationRef;
  readonly receiptDigestB64u: DigestB64u;
  readonly transcriptHashB64u: DigestB64u;
  readonly deliveredAtMs: number;
};

/** Aggregate projection references the exact R102 aggregate receipt by digest. */
export type LinkedDeviceEnrollmentReceiptV1 = {
  readonly kind: 'linked_device_enrollment_receipt_v1';
  readonly enrollmentId: LinkedDeviceEnrollmentId;
  readonly walletId: WalletId;
  readonly deviceId: LinkedDeviceId;
  readonly targetFactor: LinkedDeviceTargetFactorV1;
  readonly manifestDigestB64u: DigestB64u;
  readonly aggregateReceiptDigestB64u: DigestB64u;
  readonly orderedChildReceipts: readonly [
    LinkedDeviceEnrollmentChildReceiptV1,
    ...LinkedDeviceEnrollmentChildReceiptV1[],
  ];
  readonly activatedAtMs: number;
};

/** Public source facts needed to bind an Ed25519 export-root handoff. */
export type LinkedDeviceEd25519ExportRootPreparationV1 = {
  readonly kind: 'linked_device_ed25519_export_root_preparation_v1';
  readonly walletKeyId: WalletKeyId;
  readonly applicationBindingDigestB64u: DigestB64u;
  readonly registeredPublicKeyB64u: Ed25519PublicKeyB64u;
  readonly revocationEpoch: number;
};

/**
 * Refactor 103 Phase 8: the canonical owner add-auth-method ceremony this
 * enrollment will finalize.
 *
 * Device 2 has no owner authority, so it cannot start one. Device 1 does,
 * during approval, and its identity travels here so Device 2's single WebAuthn
 * creation is the ceremony's own registration — one prompt, one challenge, one
 * ceremony. Device 2 then finalizes it under link-session device
 * authentication rather than owner authentication.
 *
 * The registration options are the canonical `WalletAddAuthMethodRegistrationOptions`
 * the ceremony itself minted — the same declaration, not a copy of its shape.
 * They are the sole source of Device 2's WebAuthn registration parameters:
 * relying party, challenge, and user handle all come from here, so the
 * credential Device 2 creates cannot drift from the ceremony that must
 * finalize it.
 */
export type LinkedDeviceOwnerEnrollmentCeremonyV1 =
  | {
      readonly kind: 'linked_device_passkey_owner_enrollment_v1';
      readonly targetFactor: { readonly kind: 'passkey_prf' };
      readonly addAuthMethodCeremonyId: string;
      readonly registration: WalletAddAuthMethodRegistrationOptions;
      readonly baseWalletAuthMethodId?: never;
      readonly maskedEmailHint?: never;
      readonly expiresAtMs: number;
    }
  | {
      readonly kind: 'linked_device_email_otp_owner_enrollment_v1';
      readonly targetFactor: { readonly kind: 'email_otp' };
      readonly baseWalletAuthMethodId: WalletAuthMethodId;
      readonly maskedEmailHint: string;
      readonly addAuthMethodCeremonyId?: never;
      readonly registration?: never;
      readonly expiresAtMs: number;
    };
/**
 * The owner ceremony and server-allocated recipient requirements needed before
 * Device 2 creates its local recipient keypairs.
 *
 * `ownerEnrollment` is required, not optional: a preparation exists only once
 * Device 1 has started the ceremony during owner-authenticated approval, so a
 * preparation Device 2 cannot finalize is unrepresentable rather than merely
 * unexpected. "Ceremony not ready" is the absence of the whole record.
 *
 * The relying party, challenge, and user handle deliberately do not appear
 * here. They live in `ownerEnrollment.registration`, which is the ceremony's
 * own registration options — one source, so target passkey creation and its
 * later verification cannot disagree about what was signed.
 */
type LinkedDeviceTargetPreparationBaseV1 = {
  readonly kind: 'linked_device_target_preparation_v1';
  readonly linkSessionId: LinkDeviceSessionId;
  readonly walletId: WalletId;
  readonly enrollmentId: LinkedDeviceEnrollmentId;
  readonly deviceId: LinkedDeviceId;
  /** Allocated by the server before target-factor verification. */
  readonly walletAuthMethodId: WalletAuthMethodId;
  /** `null` is the explicit ECDSA-only/no-export-root branch. */
  readonly ed25519ExportRoot: LinkedDeviceEd25519ExportRootPreparationV1 | null;
  /** Public requirements from which the browser creates local recipients. */
  readonly ordinarySignerMaterialRecipientRequirements: readonly [
    OrdinarySignerMaterialRecipientRequirementV1,
    ...OrdinarySignerMaterialRecipientRequirementV1[],
  ];
  readonly issuedAtMs: number;
  readonly expiresAtMs: number;
};

export type LinkedDeviceTargetPreparationV1 = LinkedDeviceTargetPreparationBaseV1 &
  (
    | {
        readonly targetFactor: { readonly kind: 'passkey_prf' };
        readonly ownerEnrollment: Extract<
          LinkedDeviceOwnerEnrollmentCeremonyV1,
          { readonly kind: 'linked_device_passkey_owner_enrollment_v1' }
        >;
      }
    | {
        readonly targetFactor: { readonly kind: 'email_otp' };
        readonly ownerEnrollment: Extract<
          LinkedDeviceOwnerEnrollmentCeremonyV1,
          { readonly kind: 'linked_device_email_otp_owner_enrollment_v1' }
        >;
      }
  );

/** Verification-safe WebAuthn registration projection. PRF outputs stay on Device 2. */
export type LinkedDeviceWebAuthnRegistrationV1 = {
  readonly kind: 'linked_device_webauthn_registration_v1';
  readonly credentialIdB64u: WebAuthnCredentialIdB64u;
  readonly authenticatorAttachment: 'platform' | 'cross-platform' | null;
  readonly clientDataJsonB64u: string;
  readonly attestationObjectB64u: string;
  readonly transports: readonly (
    | 'ble'
    | 'cable'
    | 'hybrid'
    | 'internal'
    | 'nfc'
    | 'smart-card'
    | 'usb'
  )[];
};

/**
 * Server-derived ordinary material inputs returned after factor verification.
 * Activation identities are never accepted from a credential registration.
 */
export type OrdinarySignerMaterialReservationPreparationV1 =
  | {
      readonly kind: 'ordinary_ed25519_signer_material_reservation_preparation_v1';
      readonly activationRequest: RouterAbEd25519YaoActivationExecuteRequestV1<'registration'>;
    }
  | {
      readonly kind: 'ordinary_ecdsa_signer_material_reservation_preparation_v1';
      readonly registrationRequest: RouterAbEcdsaRegistrationRequestV1;
      readonly materialActivation: MpcMaterialActivationRef;
    };

/**
 * Public recipient requirements allocated by the server during target
 * preparation. The browser uses the family and wallet key identity to create
 * a local recipient keypair.
 */
export type OrdinarySignerMaterialRecipientRequirementV1 = {
  readonly kind: 'ordinary_signer_material_recipient_requirement_v1';
  readonly keyFamily: 'ed25519' | 'ecdsa_secp256k1';
  readonly walletKeyId: WalletKeyId;
};

/** Public recipient requests returned by the browser after local key creation. */
export type OrdinarySignerMaterialRecipientRequestV1 =
  | {
      readonly kind: 'ordinary_ed25519_signer_material_recipient_request_v1';
      readonly keyFamily: 'ed25519';
      readonly walletKeyId: WalletKeyId;
      readonly recipientPublicKeyB64u: string;
    }
  | {
      readonly kind: 'ordinary_ecdsa_signer_material_recipient_request_v1';
      readonly keyFamily: 'ecdsa_secp256k1';
      readonly walletKeyId: WalletKeyId;
      readonly clientEphemeralPublicKey: string;
    };

type LinkedDeviceTargetCredentialRegistrationBaseV1 = {
  readonly kind: 'linked_device_target_credential_registration_v1';
  readonly linkSessionId: LinkDeviceSessionId;
  readonly walletId: WalletId;
  readonly enrollmentId: LinkedDeviceEnrollmentId;
  readonly deviceId: LinkedDeviceId;
  readonly walletAuthMethodId: WalletAuthMethodId;
  readonly targetPreparationDigestB64u: DigestB64u;
  readonly ordinarySignerMaterialRecipientRequests: readonly [
    OrdinarySignerMaterialRecipientRequestV1,
    ...OrdinarySignerMaterialRecipientRequestV1[],
  ];
  readonly registeredAtMs: number;
};

export type LinkedDeviceEmailOtpVerificationGrantV1 = {
  readonly kind: 'linked_device_email_otp_verification_grant_v1';
  readonly grantId: string;
  readonly grantToken: string;
  readonly challengeId: string;
  readonly linkSessionId: LinkDeviceSessionId;
  readonly walletId: WalletId;
  readonly enrollmentId: LinkedDeviceEnrollmentId;
  readonly deviceId: LinkedDeviceId;
  readonly targetPreparationDigestB64u: DigestB64u;
  readonly baseWalletAuthMethodId: WalletAuthMethodId;
  readonly emailHashHex: string;
  readonly registrationAuthorityId: string;
  readonly providerUserId: string;
  readonly linkedOwnerAuthMethodId: WalletAuthMethodId;
  readonly authorityDigestB64u: DigestB64u;
  readonly issuedAtMs: number;
  readonly expiresAtMs: number;
};

export type LinkedDeviceEmailOtpFactorReleaseEnvelopeV1 = {
  readonly kind: 'email_otp_factor_release_v1';
  readonly challengeId: string;
  readonly enrollmentId: string;
  readonly enrollmentSealKeyVersion: string;
  readonly serverEphemeralPublicKey65B64u: string;
  readonly nonce12B64u: string;
  readonly ciphertextB64u: string;
};

export type LinkedDeviceEmailOtpChallengeStartRequestV1 = {
  readonly kind: 'linked_device_email_otp_challenge_start_request_v1';
  readonly linkSessionId: LinkDeviceSessionId;
  readonly workerEphemeralPublicKey65B64u: string;
};

export type LinkedDeviceEmailOtpChallengeResendRequestV1 = {
  readonly kind: 'linked_device_email_otp_challenge_resend_request_v1';
  readonly linkSessionId: LinkDeviceSessionId;
  readonly challengeId: string;
};

export type LinkedDeviceEmailOtpChallengeVerifyRequestV1 = {
  readonly kind: 'linked_device_email_otp_challenge_verify_request_v1';
  readonly linkSessionId: LinkDeviceSessionId;
  readonly challengeId: string;
  readonly otpCode: string;
};

export type LinkedDeviceEmailOtpChallengeResultV1 = {
  readonly kind: 'linked_device_email_otp_challenge_result_v1';
  readonly challengeId: string;
  readonly maskedEmailHint: string;
  readonly expiresAtMs: number;
  readonly resendAvailableAtMs: number;
};

export type LinkedDeviceEmailOtpVerificationResultV1 = {
  readonly kind: 'linked_device_email_otp_verification_result_v1';
  readonly verificationGrant: LinkedDeviceEmailOtpVerificationGrantV1;
  readonly factorRelease: LinkedDeviceEmailOtpFactorReleaseEnvelopeV1;
};

export type LinkedDeviceTargetCredentialRegistrationV1 =
  | (LinkedDeviceTargetCredentialRegistrationBaseV1 & {
      readonly targetFactor: { readonly kind: 'passkey_prf' };
      readonly webauthnRegistration: LinkedDeviceWebAuthnRegistrationV1;
      readonly emailOtpVerificationGrant?: never;
    })
  | (LinkedDeviceTargetCredentialRegistrationBaseV1 & {
      readonly targetFactor: { readonly kind: 'email_otp' };
      readonly emailOtpVerificationGrant: LinkedDeviceEmailOtpVerificationGrantV1;
      readonly webauthnRegistration?: never;
    });

export type LinkedDeviceReceiptAcknowledgementV1 = {
  readonly kind: 'linked_device_receipt_acknowledgement_v1';
  readonly linkSessionId: LinkDeviceSessionId;
  readonly enrollmentId: LinkedDeviceEnrollmentId;
  readonly deviceId: LinkedDeviceId;
  readonly receipt: LinkedDeviceEnrollmentReceiptV1;
  readonly acknowledgedAtMs: number;
};

export type LinkedDeviceSessionTransportRequestV1 =
  | LinkedDeviceSessionClaimRequestV1
  | LinkedDeviceApprovalV1
  | LinkedDeviceTargetCredentialRegistrationV1
  | LinkedDeviceReceiptAcknowledgementV1
  | {
      readonly kind: 'linked_device_session_cancel_unclaimed_request_v1';
      readonly linkSessionId: LinkDeviceSessionId;
      readonly reason: 'user_cancelled';
      readonly requestedAtMs: number;
    }
  | {
      readonly kind: 'linked_device_session_cancel_claimed_request_v1';
      readonly linkSessionId: LinkDeviceSessionId;
      readonly enrollmentId: LinkedDeviceEnrollmentId;
      readonly deviceId: LinkedDeviceId;
      readonly reason: 'user_cancelled' | 'expired' | 'revoked';
      readonly requestedAtMs: number;
    }
  | {
      readonly kind: 'linked_device_session_retry_committed_delivery_request_v1';
      readonly linkSessionId: LinkDeviceSessionId;
      readonly enrollmentId: LinkedDeviceEnrollmentId;
      readonly deviceId: LinkedDeviceId;
      readonly requestedAtMs: number;
    };

export type LinkedDeviceSessionTransportEventV1 = {
  readonly kind: 'linked_device_session_event_v1';
  readonly linkSessionId: LinkDeviceSessionId;
  readonly state: LinkedDeviceSessionState;
  readonly emittedAtMs: number;
};

/** Authenticated relay projection returned to the device that owns a session. */
export type LinkedDeviceSessionProjectionV1 = {
  readonly kind: 'linked_device_session_projection_v1';
  readonly linkSessionId: LinkDeviceSessionId;
  readonly qrPayload: QrLinkedDeviceSessionPayloadV5;
  readonly revision: number;
  readonly createdAtMs: number;
  readonly updatedAtMs: number;
} & (
  | {
      readonly state: LinkedDeviceSessionUnclaimedState;
      readonly deviceId?: never;
    }
  | {
      readonly state: Exclude<LinkedDeviceSessionState, LinkedDeviceSessionUnclaimedState>;
      readonly deviceId: LinkedDeviceId;
    }
);

type LinkedDevicePendingSessionStateV1 = Extract<
  LinkedDeviceSessionState,
  {
    readonly state: 'awaiting_target_factor' | 'provisioning' | 'committed_completion_required';
  }
>;

export type LinkedDeviceApprovalResultV1 =
  | {
      readonly outcome: 'pending';
      readonly state: LinkedDevicePendingSessionStateV1;
    }
  | {
      readonly outcome: 'active';
      readonly state: Extract<LinkedDeviceSessionState, { readonly state: 'active' }>;
      readonly manifestDigestB64u: DigestB64u;
      readonly receipt: LinkedDeviceEnrollmentReceiptV1;
    }
  | {
      readonly outcome: 'replayed';
      readonly replay:
        | {
            readonly state: 'pending';
            readonly session: LinkedDevicePendingSessionStateV1;
          }
        | {
            readonly state: 'active';
            readonly session: Extract<LinkedDeviceSessionState, { readonly state: 'active' }>;
            readonly manifestDigestB64u: DigestB64u;
            readonly receipt: LinkedDeviceEnrollmentReceiptV1;
          };
    };

/** Canonical owner credential metadata projected into linked-device management. */
export type LinkedOwnerCredentialMetadataV1 =
  | {
      readonly kind: 'passkey';
      readonly walletAuthMethodId: WalletAuthMethodId;
      readonly credentialIdB64u: WebAuthnCredentialIdB64u;
      readonly device: WebAuthnAuthenticatorDeviceInfo;
    }
  | {
      readonly kind: 'email_otp';
      readonly walletAuthMethodId: WalletAuthMethodId;
      readonly device?: never;
      readonly credentialIdB64u?: never;
    };

/** Public wallet-scoped projection for linked-device management. */
export type LinkedDeviceSummaryV1 = {
  readonly deviceId: LinkedDeviceId;
  readonly enrollmentId: LinkedDeviceEnrollmentId;
  readonly walletId: WalletId;
  readonly credential: LinkedOwnerCredentialMetadataV1;
  readonly permission: DelegatedWalletAuthorityV1;
  readonly keyManifestDigestB64u: DigestB64u;
  readonly coveredWalletKeys: readonly WalletKeyId[];
  readonly state: 'provisioning' | 'active' | 'suspended' | 'expired' | 'revoked';
  readonly createdAtMs: number;
  readonly lastActivityAtMs: number;
  readonly revocationEpoch: number;
};

export type LinkedDeviceListRequestV1 = {
  readonly kind: 'linked_device_list_request_v1';
  readonly walletId: WalletId;
  readonly limit: number;
  readonly cursor: string | null;
};

/**
 * An active owner credential with no linked-device enrollment: a device that
 * registered or recovered the wallet directly rather than joining through
 * linking. It has no deviceId or enrollmentId — removal goes through
 * auth-method revocation, not linked-device revocation.
 */
export type OwnerDeviceSummaryV1 = {
  readonly walletId: WalletId;
  readonly credential: LinkedOwnerCredentialMetadataV1;
  readonly createdAtMs: number;
  readonly lastActivityAtMs: number;
};

export type LinkedDeviceListResultV1 = {
  readonly devices: readonly LinkedDeviceSummaryV1[];
  /** Founding owner devices; served with the first page only (cursor === null). */
  readonly ownerDevices: readonly OwnerDeviceSummaryV1[];
  readonly nextCursor: string | null;
};

export type LinkedDeviceRevokeRequestV1 = {
  readonly kind: 'linked_device_revoke_request_v1';
  readonly walletId: WalletId;
  readonly deviceId: LinkedDeviceId;
  readonly requestedAtMs: number;
};

export type LinkedDeviceRevokeResultV1 =
  | {
      readonly kind: 'revoked' | 'replayed';
      readonly enrollmentId: LinkedDeviceEnrollmentId;
      readonly revocationEpoch: number;
      readonly aggregateReceiptDigestB64u: DigestB64u;
    }
  | {
      readonly kind: 'not_found' | 'conflict' | 'unauthorized';
    };

export type LinkedDeviceManagementRequestV1 =
  | LinkedDeviceListRequestV1
  | LinkedDeviceRevokeRequestV1;

type LinkedDeviceWalletSessionTokenBaseV1 = {
  readonly kind: 'linked_device_wallet_session_token_v1';
  readonly walletKeyId: WalletKeyId;
  readonly walletSessionJwt: string;
  /** Revocation epoch of this exact target lane. */
  readonly revocationEpoch: number;
};

export type LinkedDeviceWalletSessionEd25519TokenV1 = LinkedDeviceWalletSessionTokenBaseV1 & {
  readonly keyFamily: 'ed25519';
};

export type LinkedDeviceWalletSessionEcdsaTokenV1 = LinkedDeviceWalletSessionTokenBaseV1 & {
  readonly keyFamily: 'ecdsa_secp256k1';
};

export type LinkedDeviceWalletSessionTokenV1 =
  | LinkedDeviceWalletSessionEd25519TokenV1
  | LinkedDeviceWalletSessionEcdsaTokenV1;

/** Device2-only response from the authenticated post-activation boundary. */
type LinkedDeviceWalletSessionDeliveryBaseV1 = {
  readonly kind: 'linked_device_wallet_session_delivery_v1';
  readonly tenantId: TenantId;
  readonly walletId: WalletId;
  readonly enrollmentId: LinkedDeviceEnrollmentId;
  readonly deviceId: LinkedDeviceId;
  readonly authorizationId: LinkedDeviceWalletSessionAuthorizationId;
  readonly walletSessionId: WalletSessionId;
  readonly quotaId: MpcWalletSigningQuotaId;
  readonly keyManifestDigestB64u: DigestB64u;
  readonly permission: DelegatedWalletAuthorityV1;
  readonly revocationEpoch: number;
  readonly remainingUses: number;
  readonly issuedAtMs: number;
  readonly expiresAtMs: number;
};

export type LinkedDeviceWalletSessionDeliveryV1 =
  | (LinkedDeviceWalletSessionDeliveryBaseV1 & {
      readonly nearAccountId: NearAccountId;
      readonly orderedTokens:
        | readonly [LinkedDeviceWalletSessionEd25519TokenV1]
        | readonly [LinkedDeviceWalletSessionEd25519TokenV1, LinkedDeviceWalletSessionEcdsaTokenV1]
        | readonly [LinkedDeviceWalletSessionEcdsaTokenV1, LinkedDeviceWalletSessionEd25519TokenV1];
    })
  | (LinkedDeviceWalletSessionDeliveryBaseV1 & {
      readonly nearAccountId?: never;
      readonly orderedTokens: readonly [LinkedDeviceWalletSessionEcdsaTokenV1];
    });

export function assertNeverLinkedDeviceSessionState(value: never): never {
  throw new Error(`[LinkedDeviceSessionState] unsupported state: ${String(value)}`);
}

/**
 * What Device 2 sends to finalize its owner factor.
 *
 * Deliberately the same three fields the ordinary add-auth-method finalize
 * takes. Whether this is a linked-device enrollment is the server's to decide
 * from the authenticated link session, so it is absent here.
 */
export type LinkedDeviceOwnerFinalizeRequestV1 = {
  readonly kind: 'linked_device_owner_finalize_request_v1';
  readonly addAuthMethodCeremonyId: string;
  readonly webauthnRegistration: LinkedDeviceWebAuthnRegistrationV1;
};

/**
 * The wallet identity Device 2 needs to become an ordinary owner locally.
 *
 * Canonical unlock is fail-closed on three local records — a wallet profile, a
 * profile authenticator, and an active auth method — and it refuses to prompt
 * before it consults the server's credential allow-list. So the facts those
 * records need cannot be discovered by unlocking; they have to arrive with the
 * finalize that created the credential.
 *
 * Every field is server-verified against the wallet's Ed25519 public identity.
 * `signerSlot` names that logical wallet key. Device 2 receives an independent
 * exact capability for the same public key, produced by ordinary registration
 * under its own material activation rather than another account slot.
 *
 * Exactly what unlock reads and nothing more. Canonical unlock builds its
 * WebAuthn allow-list from the local authenticator records alone, keyed on the
 * wallet id, so it needs no account-signer projection and no public keys. The
 * fields ordinary signing dispatch will need arrive with that work rather than
 * riding here unused — a linked route that returned wallet state nobody reads
 * is a wallet-state reader, which this is not.
 */
export type LinkedDeviceLocalAccountProjectionV1 = {
  readonly kind: 'linked_device_local_account_projection_v1';
  readonly walletId: WalletId;
  readonly nearAccountId: string;
  /** The canonical Ed25519 key's creation slot. Never assume 1. */
  readonly signerSlot: number;
};

export type LinkPrecommitFailureV1 =
  | { readonly kind: 'invalid_input'; readonly reason: string }
  | { readonly kind: 'unauthorized_source'; readonly reason: string }
  | { readonly kind: 'revoked_source'; readonly reason: string }
  | { readonly kind: 'permission_attenuation_failed'; readonly reason: string }
  | { readonly kind: 'target_factor_failed'; readonly reason: string }
  | { readonly kind: 'expired_session'; readonly reason: string }
  | { readonly kind: 'cancelled_session'; readonly reason: string }
  | { readonly kind: 'claim_conflict'; readonly reason: string }
  | { readonly kind: 'package_preparation_failed'; readonly reason: string };

/** The only durable states retained by the linear link-session boundary. */
export type LinkSessionStateV1 =
  | {
      readonly state: 'displaying_qr';
      readonly deviceId?: never;
      readonly authorityId?: never;
      readonly packageSetDigestB64u?: never;
      readonly activatedAtMs?: never;
      readonly error?: never;
      readonly cancelledAtMs?: never;
      readonly expiredAtMs?: never;
    }
  | {
      readonly state: 'claimed';
      readonly deviceId: DeviceId;
      readonly authorityId?: never;
      readonly packageSetDigestB64u?: never;
      readonly activatedAtMs?: never;
      readonly error?: never;
      readonly cancelledAtMs?: never;
      readonly expiredAtMs?: never;
    }
  | {
      readonly state: 'awaiting_target_factor';
      readonly deviceId: DeviceId;
      readonly authorityId?: never;
      readonly packageSetDigestB64u?: never;
      readonly activatedAtMs?: never;
      readonly error?: never;
      readonly cancelledAtMs?: never;
      readonly expiredAtMs?: never;
    }
  | {
      readonly state: 'provisioning';
      readonly deviceId: DeviceId;
      readonly authorityId?: never;
      readonly packageSetDigestB64u?: never;
      readonly activatedAtMs?: never;
      readonly error?: never;
      readonly cancelledAtMs?: never;
      readonly expiredAtMs?: never;
    }
  | {
      readonly state: 'authority_pending_local_install';
      readonly deviceId: DeviceId;
      readonly authorityId: WalletAuthorityId;
      readonly packageSetDigestB64u: DigestB64u;
      readonly activatedAtMs?: never;
      readonly error?: never;
      readonly cancelledAtMs?: never;
      readonly expiredAtMs?: never;
    }
  | {
      readonly state: 'active';
      readonly deviceId: DeviceId;
      readonly authorityId: WalletAuthorityId;
      readonly activatedAtMs: number;
      readonly packageSetDigestB64u?: never;
      readonly error?: never;
      readonly cancelledAtMs?: never;
      readonly expiredAtMs?: never;
    }
  | {
      readonly state: 'failed_before_commit';
      readonly error: LinkPrecommitFailureV1;
      readonly deviceId?: never;
      readonly authorityId?: never;
      readonly packageSetDigestB64u?: never;
      readonly activatedAtMs?: never;
      readonly cancelledAtMs?: never;
      readonly expiredAtMs?: never;
    }
  | {
      readonly state: 'cancelled';
      readonly cancelledAtMs: number;
      readonly deviceId?: never;
      readonly authorityId?: never;
      readonly packageSetDigestB64u?: never;
      readonly activatedAtMs?: never;
      readonly error?: never;
      readonly expiredAtMs?: never;
    }
  | {
      readonly state: 'expired';
      readonly expiredAtMs: number;
      readonly deviceId?: never;
      readonly authorityId?: never;
      readonly packageSetDigestB64u?: never;
      readonly activatedAtMs?: never;
      readonly error?: never;
      readonly cancelledAtMs?: never;
    };

export type VerifiedSourceAuthorityV1 = {
  readonly authority: ActiveWalletAuthorityV1;
  readonly authMethodId: WalletAuthMethodId;
  readonly verifiedRevocationEpoch: number;
  readonly authorityDigestB64u: DigestB64u;
  readonly verifiedAtMs: number;
};

export type VerifiedTargetFactorV1 =
  | {
      readonly kind: 'verified_passkey_target_v1';
      readonly authMethod: PasskeyWalletAuthMethodDraftV1;
      readonly verificationDigestB64u: DigestB64u;
      readonly verifiedAtMs: number;
    }
  | {
      readonly kind: 'verified_email_otp_target_v1';
      readonly authMethod: EmailOtpWalletAuthMethodDraftV1;
      readonly verificationDigestB64u: DigestB64u;
      readonly verifiedAtMs: number;
    };

export type VerifiedLinkInputV1 = {
  readonly walletId: WalletId;
  readonly linkSessionId: LinkDeviceSessionId;
  readonly enrollmentId: LinkedDeviceEnrollmentId;
  readonly targetDeviceId: DeviceId;
  readonly sourceAuthority: VerifiedSourceAuthorityV1;
  readonly targetFactor: VerifiedTargetFactorV1;
  readonly permissions: CanonicalDelegatedWalletPermissionSetV1;
  readonly signerManifest: ExactAdministeredSignerManifestV1;
  readonly ordinarySignerMaterialRecipientRequests: readonly [
    OrdinarySignerMaterialRecipientRequestV1,
    ...OrdinarySignerMaterialRecipientRequestV1[],
  ];
};

/**
 * Browser-safe evidence returned after target-factor verification. Source
 * authority and grant internals stay inside the server installation port.
 */
export type LinkedDeviceTargetCredentialRegistrationResultV1 = {
  readonly kind: 'linked_device_target_credential_registration_result_v1';
  readonly outcome: 'applied' | 'replayed';
  readonly linkSessionId: LinkDeviceSessionId;
  readonly walletId: WalletId;
  readonly enrollmentId: LinkedDeviceEnrollmentId;
  readonly deviceId: LinkedDeviceId;
  readonly walletAuthMethodId: WalletAuthMethodId;
  readonly targetPreparationDigestB64u: DigestB64u;
  readonly targetFactor: VerifiedTargetFactorV1;
  readonly ordinarySignerMaterialPreparations: readonly [
    OrdinarySignerMaterialReservationPreparationV1,
    ...OrdinarySignerMaterialReservationPreparationV1[],
  ];
  readonly ordinarySignerMaterialRecipientRequests: readonly [
    OrdinarySignerMaterialRecipientRequestV1,
    ...OrdinarySignerMaterialRecipientRequestV1[],
  ];
  readonly keyManifestDigestB64u: DigestB64u;
};

/** The ordinary session issued by activation and persisted by the browser. */
export type WalletCapabilitySubjectV1 =
  | {
      readonly kind: 'sign';
      readonly keyFamily: 'ed25519' | 'ecdsa_secp256k1';
      readonly materialActivation: MpcMaterialActivationRef;
    }
  | {
      readonly kind: 'export_keys';
      readonly keyFamily: 'ed25519' | 'ecdsa_secp256k1';
      readonly materialActivation: MpcMaterialActivationRef;
    }
  | {
      readonly kind: 'link_devices' | 'revoke_devices';
      readonly keyFamily?: never;
      readonly materialActivation?: never;
    };

export type ActiveWalletSessionV1 = {
  readonly kind: 'active_wallet_session_v1';
  readonly walletId: WalletId;
  readonly authorityId: WalletAuthorityId;
  readonly authMethodId: WalletAuthMethodId;
  readonly authorizationId: WalletSessionAuthorizationId;
  readonly authorityDigestB64u: DigestB64u;
  readonly authorityRevocationEpoch: number;
  readonly capabilitySubjects: readonly [WalletCapabilitySubjectV1, ...WalletCapabilitySubjectV1[]];
  readonly issuedAtMs: number;
  readonly expiresAtMs: number;
};

export type LocalAuthorityInstallationReceiptV1 = {
  readonly kind: 'local_authority_installation_receipt_v1';
  readonly authorityId: WalletAuthorityId;
  readonly walletId: WalletId;
  readonly authMethodId: WalletAuthMethodId;
  readonly deviceId: DeviceId;
  readonly packageSetDigestB64u: DigestB64u;
  readonly installedActivationRefs: WalletSignerActivationSetV1;
  readonly installedRecordSetDigestB64u: DigestB64u;
  readonly targetFactorVerificationDigestB64u: DigestB64u;
  readonly installedAtMs: number;
};

export type RelinkRequiredReasonV1 =
  | { readonly kind: 'incomplete_migrated_enrollment' }
  | {
      readonly kind: 'missing_canonical_local_material';
      readonly activation: MpcMaterialActivationRef;
    };

export type LinkIntegrityFailureV1 =
  | {
      readonly kind: 'authority_id_mismatch';
      readonly expectedAuthorityId: WalletAuthorityId;
      readonly actualAuthorityId: WalletAuthorityId;
    }
  | {
      readonly kind: 'package_set_digest_mismatch';
      readonly expectedPackageSetDigestB64u: DigestB64u;
      readonly actualPackageSetDigestB64u: DigestB64u;
    }
  | {
      readonly kind: 'installation_receipt_mismatch';
      readonly field:
        | 'walletId'
        | 'authMethodId'
        | 'deviceId'
        | 'targetFactorVerificationDigestB64u'
        | 'installedActivationRefs';
    };

export type ActivationRetryReasonV1 =
  | { readonly kind: 'installation_receipt_not_found' }
  | { readonly kind: 'server_worker_activation_pending' }
  | { readonly kind: 'wallet_session_issuance_pending' };

export type ActivateInstalledAuthorityResultV1 =
  | {
      readonly kind: 'active';
      readonly authority: Extract<WalletAuthorityV1, { readonly state: 'active' }>;
      readonly authMethod: Extract<WalletAuthMethodRecordV2, { readonly status: 'active' }>;
      readonly walletSession: ActiveWalletSessionV1;
    }
  | {
      readonly kind: 'pending_local_install';
      readonly authorityId: WalletAuthorityId;
      readonly reason: ActivationRetryReasonV1;
    }
  | { readonly kind: 'integrity_error'; readonly reason: LinkIntegrityFailureV1 };

export type LinkedAuthorityActivationResultV1 =
  | { readonly kind: 'active'; readonly session: ActiveWalletSessionV1 }
  | {
      readonly kind: 'pending_local_install';
      readonly authorityId: WalletAuthorityId;
      readonly packageSetDigestB64u: DigestB64u;
    }
  | { readonly kind: 'failed_before_commit'; readonly reason: LinkPrecommitFailureV1 }
  | { readonly kind: 'relink_required'; readonly reason: RelinkRequiredReasonV1 }
  | { readonly kind: 'integrity_error'; readonly reason: LinkIntegrityFailureV1 };

/** Final wire acknowledgement after the active authority/session transaction. */
export type LocalAuthorityActivationFinalAckV1 = {
  readonly kind: 'local_authority_activation_final_ack_v1';
  readonly linkSessionId: LinkDeviceSessionId;
  readonly authorityId: WalletAuthorityId;
  readonly packageSetDigestB64u: DigestB64u;
  readonly authorizationId: WalletSessionAuthorizationId;
  readonly acknowledgedAtMs: number;
};

export function assertNeverLinkSessionStateV1(value: never): never {
  throw new Error(`[LinkSessionStateV1] unsupported state: ${String(value)}`);
}

/**
 * Authenticated Device 2 projection for the linear link lifecycle. The
 * temporary session id and QR payload stay at this boundary; lifecycle code
 * consumes the exact state union only.
 */
export type LinkSessionProjectionV1 = {
  readonly kind: 'linked_device_session_projection_v1';
  readonly linkSessionId: LinkDeviceSessionId;
  readonly qrPayload: QrLinkedDeviceSessionPayloadV5;
  readonly revision: number;
  readonly createdAtMs: number;
  readonly updatedAtMs: number;
  readonly state: LinkSessionStateV1;
};

export type LinkSessionTransportEventV1 = {
  readonly kind: 'linked_device_session_event_v1';
  readonly linkSessionId: LinkDeviceSessionId;
  readonly state: LinkSessionStateV1;
  readonly emittedAtMs: number;
};
