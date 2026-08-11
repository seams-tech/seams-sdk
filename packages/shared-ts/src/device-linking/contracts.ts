import type {
  AuthorizationEvidenceSetId,
  LinkedDeviceWalletSessionAuthorizationId,
  MpcWalletSigningQuotaId,
  TenantId,
  WalletSessionAuthorizationId,
  WalletSessionId,
} from '../authorization/capabilityKinds';
import type {
  LaneHolderParticipantRecordV1,
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
import type {
  MpcMaterialActivationId,
  MpcMaterialActivationRef,
  WalletId,
  WebAuthnCredentialIdB64u,
  WebAuthnRpId,
} from '../utils/domainIds';
import type { DigestB64u } from '../utils/canonicalPrimitives';
import type {
  LaneHolderDeliveryReceiptV1,
  LaneHolderPackageWireV1,
  LaneProtocolCommitReceiptV1,
  LaneEnrollmentManifestV1,
  RotatableSigningLaneJobV1,
} from '../signing-lanes/rotation';

/** Public key bytes carried by the link session, encoded as canonical base64url. */
export type LinkDevicePublicKeyB64u = string & {
  readonly __linkDevicePublicKeyB64uBrand: 'LinkDevicePublicKeyB64u';
};

/** The only permission branch available to the first linked-device release. */
export type QrLinkedDevicePermissionRequest = {
  readonly kind: 'owner_equivalent_signing';
  readonly administrationScope: 'signing_only';
  readonly localUserPresence: 'required';
};

export type QrLinkedDeviceSessionPayloadV4 = {
  readonly version: 'v4';
  readonly purpose: 'linked_device_lane_creation';
  readonly linkSessionId: LinkDeviceSessionId;
  readonly linkPublicKeyB64u: LinkDevicePublicKeyB64u;
  readonly devicePublicKeyB64u: LinkDevicePublicKeyB64u;
  readonly requestedPermission: QrLinkedDevicePermissionRequest;
  readonly issuedAtMs: number;
  readonly expiresAtMs: number;
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
      readonly state: 'awaiting_target_passkey';
      readonly linkSessionId: LinkDeviceSessionId;
      readonly walletId: WalletId;
      readonly enrollmentId: LinkedDeviceEnrollmentId;
      readonly credentialDeadlineMs: number;
    }
  | {
      readonly state: 'provisioning';
      readonly linkSessionId: LinkDeviceSessionId;
      readonly walletId: WalletId;
      readonly enrollmentId: LinkedDeviceEnrollmentId;
      readonly keyManifestDigestB64u: DigestB64u;
    }
  | {
      readonly state: 'awaiting_aggregate_receipt';
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
      readonly transcriptSetDigestB64u: DigestB64u;
    };

export type LinkedDeviceSessionUnclaimedState = Extract<
  LinkedDeviceSessionState,
  { readonly state: 'displaying_qr' | 'expired_unclaimed' | 'cancelled_unclaimed' }
>;

export type LinkedDeviceSessionClaimRequestV1 = {
  readonly kind: 'linked_device_session_claim_request_v1';
  readonly payload: QrLinkedDeviceSessionPayloadV4;
};

export type LinkedDeviceSessionClaimV1 = {
  readonly kind: 'linked_device_session_claim_v1';
  readonly linkSessionId: LinkDeviceSessionId;
  readonly walletId: WalletId;
  readonly enrollmentId: LinkedDeviceEnrollmentId;
  readonly deviceId: LinkedDeviceId;
  readonly devicePublicKeyB64u: LinkDevicePublicKeyB64u;
  readonly claimedAtMs: number;
  readonly claimExpiresAtMs: number;
};

/** Exactly one reusable owner-session or one fresh step-up authorization source. */
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

export type LinkedDeviceEnrollmentKeyBindingV1 = {
  readonly walletKeyId: WalletKeyId;
  readonly keyFamily: 'ed25519' | 'ecdsa_secp256k1';
  readonly sourceLaneId: SigningLaneId;
  readonly sourceLaneShareEpoch: LaneShareEpoch;
  readonly sourceRevocationEpoch: number;
  readonly sourceHolderParticipantId: LaneHolderParticipantId;
  readonly sourceSigningWorkerParticipantId: SigningWorkerParticipantId;
  readonly targetLaneId: SigningLaneId;
  readonly targetLaneShareEpoch: LaneShareEpoch;
};

export type LinkedDeviceProtocolVersionV1 = {
  readonly keyFamily: 'ed25519' | 'ecdsa_secp256k1';
  readonly version: string;
};

export type LinkedDeviceApprovalV1 = {
  readonly kind: 'linked_device_approval_v1';
  readonly linkSessionId: LinkDeviceSessionId;
  readonly walletId: WalletId;
  readonly enrollmentId: LinkedDeviceEnrollmentId;
  readonly deviceId: LinkedDeviceId;
  readonly linkPublicKeyB64u: LinkDevicePublicKeyB64u;
  readonly devicePublicKeyB64u: LinkDevicePublicKeyB64u;
  readonly permission: QrLinkedDevicePermissionRequest;
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

export type LinkedDeviceProvisioningCommandV1 = {
  readonly kind: 'linked_device_provisioning_command_v1';
  readonly linkSessionId: LinkDeviceSessionId;
  readonly enrollmentId: LinkedDeviceEnrollmentId;
  readonly deviceId: LinkedDeviceId;
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
  readonly permission: QrLinkedDevicePermissionRequest;
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
  readonly manifestDigestB64u: DigestB64u;
  readonly aggregateReceiptDigestB64u: DigestB64u;
  readonly orderedChildReceipts: readonly [
    LinkedDeviceEnrollmentChildReceiptV1,
    ...LinkedDeviceEnrollmentChildReceiptV1[],
  ];
  readonly activatedAtMs: number;
};

export type LinkedDeviceTargetPreparationChildV1 = {
  readonly kind: 'linked_device_target_preparation_child_v1';
  readonly operationId: LaneOperationId;
  readonly walletKeyId: WalletKeyId;
  readonly keyFamily: 'ed25519' | 'ecdsa_secp256k1';
  readonly targetLaneId: SigningLaneId;
  readonly targetLaneShareEpoch: LaneShareEpoch;
  readonly targetMaterialActivationId: MpcMaterialActivationId;
  readonly targetHolderParticipantId: LaneHolderParticipantId;
};

/** Server-owned challenge and exact R102 child identities required before Device 2 creates keys. */
export type LinkedDeviceTargetPreparationV1 = {
  readonly kind: 'linked_device_target_preparation_v1';
  readonly linkSessionId: LinkDeviceSessionId;
  readonly walletId: WalletId;
  readonly enrollmentId: LinkedDeviceEnrollmentId;
  readonly deviceId: LinkedDeviceId;
  readonly rpId: WebAuthnRpId;
  readonly userHandleB64u: string;
  readonly challengeB64u: DigestB64u;
  readonly orderedChildren: readonly [
    LinkedDeviceTargetPreparationChildV1,
    ...LinkedDeviceTargetPreparationChildV1[],
  ];
  readonly issuedAtMs: number;
  readonly expiresAtMs: number;
};

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

export type LinkedDeviceTargetHolderRegistrationV1 = {
  readonly kind: 'linked_device_target_holder_registration_v1';
  readonly operationId: LaneOperationId;
  readonly walletKeyId: WalletKeyId;
  readonly keyFamily: 'ed25519' | 'ecdsa_secp256k1';
  readonly targetLaneId: SigningLaneId;
  readonly targetLaneShareEpoch: LaneShareEpoch;
  readonly targetMaterialActivationId: MpcMaterialActivationId;
  readonly holderParticipant: LaneHolderParticipantRecordV1;
};

export type LinkedDeviceTargetCredentialRegistrationV1 = {
  readonly kind: 'linked_device_target_credential_registration_v1';
  readonly linkSessionId: LinkDeviceSessionId;
  readonly walletId: WalletId;
  readonly enrollmentId: LinkedDeviceEnrollmentId;
  readonly deviceId: LinkedDeviceId;
  readonly targetPreparationDigestB64u: DigestB64u;
  readonly webauthnRegistration: LinkedDeviceWebAuthnRegistrationV1;
  readonly orderedHolderRegistrations: readonly [
    LinkedDeviceTargetHolderRegistrationV1,
    ...LinkedDeviceTargetHolderRegistrationV1[],
  ];
  readonly registeredAtMs: number;
};

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
  readonly qrPayload: QrLinkedDeviceSessionPayloadV4;
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
    readonly state:
      | 'awaiting_target_passkey'
      | 'provisioning'
      | 'awaiting_aggregate_receipt'
      | 'committed_completion_required';
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

/** Public wallet-scoped projection for linked-device management. */
export type LinkedDeviceSummaryV1 = {
  readonly deviceId: LinkedDeviceId;
  readonly enrollmentId: LinkedDeviceEnrollmentId;
  readonly walletId: WalletId;
  readonly label: string;
  readonly platform: string;
  readonly permission: QrLinkedDevicePermissionRequest;
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
};

export type LinkedDeviceListResultV1 = {
  readonly devices: readonly LinkedDeviceSummaryV1[];
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

export type LinkedDeviceWalletSessionTokenV1 = {
  readonly kind: 'linked_device_wallet_session_token_v1';
  readonly walletKeyId: WalletKeyId;
  readonly keyFamily: 'ed25519' | 'ecdsa_secp256k1';
  readonly walletSessionJwt: string;
};

/** Device2-only response from the authenticated post-activation boundary. */
export type LinkedDeviceWalletSessionDeliveryV1 = {
  readonly kind: 'linked_device_wallet_session_delivery_v1';
  readonly tenantId: TenantId;
  readonly walletId: WalletId;
  readonly enrollmentId: LinkedDeviceEnrollmentId;
  readonly deviceId: LinkedDeviceId;
  readonly authorizationId: LinkedDeviceWalletSessionAuthorizationId;
  readonly walletSessionId: WalletSessionId;
  readonly quotaId: MpcWalletSigningQuotaId;
  readonly keyManifestDigestB64u: DigestB64u;
  readonly permission: QrLinkedDevicePermissionRequest;
  readonly revocationEpoch: number;
  readonly issuedAtMs: number;
  readonly expiresAtMs: number;
  readonly orderedTokens: readonly [
    LinkedDeviceWalletSessionTokenV1,
    ...LinkedDeviceWalletSessionTokenV1[],
  ];
};

export function assertNeverLinkedDeviceSessionState(value: never): never {
  throw new Error(`[LinkedDeviceSessionState] unsupported state: ${String(value)}`);
}
