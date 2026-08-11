import type {
  LinkedDeviceProvisioningChildV1,
  LinkedDeviceApprovalV1,
  LinkedDeviceApprovalResultV1,
  LinkedDeviceEnrollmentKeyBindingV1,
  LinkedDeviceEnrollmentReceiptV1,
  LinkedDeviceHolderDeliveryAcknowledgementV1,
  LinkedDeviceProvisioningCommandV1,
  LinkedDeviceProvisioningDeliveriesV1,
  LinkedDeviceProvisioningDeliveriesSubmissionV1,
  LinkedDeviceOwnerAuthorizationSourceV1,
  LinkedDeviceProtocolVersionV1,
  LinkedDeviceReceiptAcknowledgementV1,
  LinkedDeviceSessionClaimRequestV1,
  LinkedDeviceSessionClaimV1,
  LinkedDeviceSessionProjectionV1,
  LinkedDeviceSessionState,
  LinkedDeviceSessionTransportEventV1,
  LinkedDeviceSessionTransportRequestV1,
  LinkedDeviceTargetCredentialRegistrationV1,
  LinkedDeviceTargetHolderRegistrationV1,
  LinkedDeviceTargetPreparationV1,
  LinkedDeviceTargetReadyR102InputV1,
  LinkedDeviceWebAuthnRegistrationV1,
  LinkedDeviceWalletSessionDeliveryV1,
  LinkDevicePublicKeyB64u,
  QrLinkedDeviceSessionPayloadV4,
} from '@shared/device-linking';
import type {
  LaneProtocolCommitReceiptV1,
  RotatableSigningLaneJobV1,
  SealedLaneHolderMaterialV1,
} from '@shared/signing-lanes/rotation';
import type { DigestB64u } from '@shared/utils/canonicalPrimitives';
import type {
  LaneOperationId,
  LaneOperationIdempotencyKey,
  LinkedDeviceEnrollmentId,
  LinkedDeviceId,
  LinkDeviceSessionId,
} from '@shared/signing-lanes/ids';
import type { MpcMaterialActivationRef, WalletId } from '@shared/utils/domainIds';
import type { LinkedDeviceExecutionEvidenceRepositoryV1 } from '@/core/indexedDB/seamsWalletDB/linkedDeviceExecutionEvidenceStore';
import type { LaneSealedHolderRecordV1 } from '@/core/indexedDB/seamsWalletDB/laneHolderMaterialStore';

/** Authenticated owner request proof produced by the one owner auth source. */
export type LinkSessionAuthenticationV1 = {
  readonly kind: 'link_session_authenticated_request_v1';
  readonly source: LinkedDeviceOwnerAuthorizationSourceV1;
  readonly proofDigestB64u: DigestB64u;
};

export type LinkSessionSubscriptionV1 = {
  readonly close: () => void | Promise<void>;
};

export type LinkSessionSnapshotV1 = LinkedDeviceSessionProjectionV1;
export type { LinkedDeviceApprovalResultV1 };

/**
 * This adapter owns challenge exchange, canonical request bytes, and worker
 * signing. Domain flows see exact DTOs and an opaque worker handle only.
 */
export type DeviceLinkingAuthenticatedTransportPortV1 = {
  createUnclaimedSessionV1(input: {
    readonly payload: QrLinkedDeviceSessionPayloadV4;
    readonly state: Extract<LinkedDeviceSessionState, { readonly state: 'displaying_qr' }>;
  }): Promise<void>;
  getSessionV1(input: {
    readonly linkSessionId: LinkDeviceSessionId;
  }): Promise<LinkSessionSnapshotV1>;
  getApprovalV1(input: {
    readonly linkSessionId: LinkDeviceSessionId;
  }): Promise<LinkedDeviceApprovalV1>;
  getWalletSessionDeliveryV1(input: {
    readonly linkSessionId: LinkDeviceSessionId;
  }): Promise<LinkedDeviceWalletSessionDeliveryV1>;
  getTargetPreparationV1(input: {
    readonly linkSessionId: LinkDeviceSessionId;
  }): Promise<LinkedDeviceTargetPreparationV1>;
  requestProvisioningDeliveriesV1(input: {
    readonly command: LinkedDeviceProvisioningCommandV1;
  }): Promise<LinkedDeviceProvisioningDeliveriesV1>;
  acknowledgeHolderDeliveriesV1(input: {
    readonly acknowledgement: LinkedDeviceHolderDeliveryAcknowledgementV1;
  }): Promise<LinkedDeviceEnrollmentReceiptV1>;
  registerTargetCredentialV1(input: {
    readonly registration: LinkedDeviceTargetCredentialRegistrationV1;
  }): Promise<void>;
  acknowledgeReceiptV1(input: {
    readonly acknowledgement: LinkedDeviceReceiptAcknowledgementV1;
  }): Promise<void>;
  retryCommittedDeliveryV1(input: {
    readonly request: Extract<
      LinkedDeviceSessionTransportRequestV1,
      { readonly kind: 'linked_device_session_retry_committed_delivery_request_v1' }
    >;
  }): Promise<void>;
  cancelSessionV1(input: {
    readonly request:
      | Extract<
          LinkedDeviceSessionTransportRequestV1,
          { readonly kind: 'linked_device_session_cancel_unclaimed_request_v1' }
        >
      | Extract<
          LinkedDeviceSessionTransportRequestV1,
          { readonly kind: 'linked_device_session_cancel_claimed_request_v1' }
        >;
  }): Promise<void>;
  subscribeSessionV1(input: {
    readonly linkSessionId: LinkDeviceSessionId;
    readonly onEvent: (event: LinkedDeviceSessionTransportEventV1) => void;
  }): Promise<LinkSessionSubscriptionV1>;
};

export type LinkSessionOwnerTransportPortV1 = {
  claimSessionV1(input: {
    readonly request: LinkedDeviceSessionClaimRequestV1;
    readonly authentication: LinkSessionAuthenticationV1;
  }): Promise<LinkedDeviceSessionClaimV1>;
  recordOwnerApprovalV1(input: {
    readonly approval: LinkedDeviceApprovalV1;
    readonly authentication: LinkSessionAuthenticationV1;
  }): Promise<LinkedDeviceApprovalResultV1>;
  getApprovalV1(input: {
    readonly linkSessionId: LinkDeviceSessionId;
    readonly authentication: LinkSessionAuthenticationV1;
  }): Promise<LinkedDeviceApprovalResultV1>;
  getTargetReadyV1(input: {
    readonly linkSessionId: LinkDeviceSessionId;
    readonly authentication: LinkSessionAuthenticationV1;
  }): Promise<LinkedDeviceTargetReadyR102InputV1 | null>;
  submitPreparedProvisioningDeliveriesV1(input: {
    readonly submission: LinkedDeviceProvisioningDeliveriesSubmissionV1;
    readonly authentication: LinkSessionAuthenticationV1;
  }): Promise<LinkedDeviceProvisioningDeliveriesSubmissionV1>;
  subscribeApprovalV1(input: {
    readonly linkSessionId: LinkDeviceSessionId;
    readonly authentication: LinkSessionAuthenticationV1;
    readonly onResult: (result: LinkedDeviceApprovalResultV1) => void;
  }): Promise<LinkSessionSubscriptionV1>;
};

export type LinkSessionTransportPortV1 = LinkSessionOwnerTransportPortV1 & {
  createAuthenticatedSessionTransportV1(input: {
    readonly keyMaterial: DeviceLinkingKeyMaterialHandleV1;
    readonly devicePublicKeyB64u: LinkDevicePublicKeyB64u;
  }): DeviceLinkingAuthenticatedTransportPortV1;
};

/** A worker-owned handle. The browser receives no private key representation. */
export type DeviceLinkingKeyMaterialHandleV1 = {
  readonly kind: 'device_linking_key_material_handle_v1';
  /** Opaque worker-owned key slot; it carries no key bytes. */
  readonly handleId: string;
};

export type DeviceLinkingKeyMaterialBundleV1 = {
  readonly handle: DeviceLinkingKeyMaterialHandleV1;
  /** X25519/HPKE link public key; the private key remains in the worker. */
  readonly linkPublicKeyB64u: LinkDevicePublicKeyB64u;
  /** Ed25519 device identity public key; the private key remains in the worker. */
  readonly devicePublicKeyB64u: LinkDevicePublicKeyB64u;
};

export type DeviceLinkingHolderSigningMaterialHandleV1 = {
  readonly kind: 'device_linking_holder_signing_material_handle_v1';
  readonly handleId: string;
  readonly keyFamily: 'ed25519' | 'ecdsa_secp256k1';
};

export type DeviceLinkingHolderSigningMaterialPortV1 = {
  openPersistedHolderSigningMaterialV1(input: {
    readonly factorSecret: ArrayBuffer;
    readonly job: RotatableSigningLaneJobV1;
    readonly protocolCommitReceipt: LaneProtocolCommitReceiptV1;
    readonly materialActivation: MpcMaterialActivationRef;
    readonly holderRecord: LaneSealedHolderRecordV1;
  }): Promise<DeviceLinkingHolderSigningMaterialHandleV1>;
  discardHolderSigningMaterialV1(input: {
    readonly handle: DeviceLinkingHolderSigningMaterialHandleV1;
  }): Promise<void>;
};

export type DeviceLinkingKeyMaterialPortV1 = {
  createBootstrapKeyMaterialV1(): Promise<DeviceLinkingKeyMaterialBundleV1>;
  prepareTargetHolderRegistrationsV1(input: {
    readonly handle: DeviceLinkingKeyMaterialHandleV1;
    readonly preparation: LinkedDeviceTargetPreparationV1;
    readonly credentialIdB64u: LinkedDeviceWebAuthnRegistrationV1['credentialIdB64u'];
    readonly factorSecret: ArrayBuffer;
  }): Promise<{
    readonly orderedHolderRegistrations: readonly [
      LinkedDeviceTargetHolderRegistrationV1,
      ...LinkedDeviceTargetHolderRegistrationV1[],
    ];
  }>;
  openAndSealTargetHolderDeliveryV1(input: {
    readonly handle: DeviceLinkingKeyMaterialHandleV1;
    readonly delivery: LinkedDeviceProvisioningChildV1;
  }): Promise<SealedLaneHolderMaterialV1>;
  /** Discards the worker slot and releases all private key references. */
  discardKeyMaterialV1(input: { readonly handle: DeviceLinkingKeyMaterialHandleV1 }): Promise<void>;
  signDeviceSessionRequestV1(input: {
    readonly handle: DeviceLinkingKeyMaterialHandleV1;
    readonly linkSessionId: LinkDeviceSessionId;
    readonly method: 'GET' | 'POST';
    readonly canonicalPath: string;
    readonly bodyDigestB64u: DigestB64u;
    readonly devicePublicKeyDigestB64u: DigestB64u;
    readonly challengeB64u: string;
    readonly issuedAtMs: number;
    readonly expiresAtMs: number;
  }): Promise<{ readonly signatureB64u: string }>;
};

export type DeviceLinkingOwnerAuthorizationPortV1 = {
  authenticateOwnerForLinkingV1(input: {
    readonly payload: QrLinkedDeviceSessionPayloadV4;
    readonly requestedAtMs: number;
  }): Promise<{
    readonly authentication: LinkSessionAuthenticationV1;
    readonly walletId: WalletId;
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
    readonly expiresAtMs: number;
  }>;
};

export type DeviceLinkingTargetCredentialPortV1 = {
  createTargetCredentialV1(input: {
    readonly preparation: LinkedDeviceTargetPreparationV1;
    readonly keyMaterial: DeviceLinkingKeyMaterialHandleV1;
  }): Promise<{
    readonly webauthnRegistration: LinkedDeviceWebAuthnRegistrationV1;
    readonly orderedHolderRegistrations: readonly [
      LinkedDeviceTargetHolderRegistrationV1,
      ...LinkedDeviceTargetHolderRegistrationV1[],
    ];
  }>;
};

/** R102 source/recipient/delivery/activation handoff owned by the worker assembly. */
export type DeviceLinkingLaneProvisioningHandoffV1 = {
  readonly kind: 'linked_device_lane_provisioning_handoff_v1';
  readonly approval: LinkedDeviceApprovalV1;
  readonly deliveries: LinkedDeviceProvisioningDeliveriesV1;
  readonly keyMaterial: DeviceLinkingKeyMaterialHandleV1;
  readonly acknowledgeHolderDeliveriesV1: (
    acknowledgement: LinkedDeviceHolderDeliveryAcknowledgementV1,
  ) => Promise<LinkedDeviceEnrollmentReceiptV1>;
};

export type DeviceLinkingLaneProvisioningPortV1 = {
  prepareLinkedDeviceLanesV1(
    input: DeviceLinkingLaneProvisioningHandoffV1,
  ): Promise<LinkedDeviceEnrollmentReceiptV1>;
  resumeCommittedDeliveryV1(input: {
    readonly state: Extract<
      LinkedDeviceSessionState,
      { readonly state: 'committed_completion_required' }
    >;
    readonly refetchApprovalV1: () => Promise<LinkedDeviceApprovalV1>;
    readonly refetchProvisioningDeliveriesV1: () => Promise<LinkedDeviceProvisioningDeliveriesV1>;
    readonly acknowledgeHolderDeliveriesV1: (
      acknowledgement: LinkedDeviceHolderDeliveryAcknowledgementV1,
    ) => Promise<LinkedDeviceEnrollmentReceiptV1>;
  }): Promise<LinkedDeviceEnrollmentReceiptV1>;
};

export type DeviceLinkingWalletSessionStorePortV1 = {
  putExactActiveDeliveryV1(delivery: LinkedDeviceWalletSessionDeliveryV1): Promise<void>;
};

export type DeviceLinkingExecutionEvidenceStorePortV1 = Pick<
  LinkedDeviceExecutionEvidenceRepositoryV1,
  'putExactProvisionedEvidenceV1' | 'readForEnrollmentV1'
>;

export type Device2LinkingFlowPortsV1 = {
  readonly transport: LinkSessionTransportPortV1;
  readonly keyMaterial: DeviceLinkingKeyMaterialPortV1;
  readonly targetCredential: DeviceLinkingTargetCredentialPortV1;
  readonly laneProvisioning: DeviceLinkingLaneProvisioningPortV1;
  readonly walletSessions: DeviceLinkingWalletSessionStorePortV1;
  readonly executionEvidence: DeviceLinkingExecutionEvidenceStorePortV1;
};

export type Device1LinkingFlowPortsV1 = {
  readonly transport: LinkSessionOwnerTransportPortV1;
  readonly ownerAuthorization: DeviceLinkingOwnerAuthorizationPortV1;
  readonly sourcePreparation: Device1SourcePreparationPortV1;
};

export type Device1TargetReadySourceInputV1 = LinkedDeviceTargetReadyR102InputV1;

export type Device1SourcePreparationPortV1 = {
  prepareTargetReadyDeliveriesV1(
    input: Device1TargetReadySourceInputV1,
  ): Promise<LinkedDeviceProvisioningDeliveriesV1>;
};

export type DeviceLinkingFlowPortsV1 = Device2LinkingFlowPortsV1 & Device1LinkingFlowPortsV1;

export function createDeviceLinkingLaneProvisioningHandoffV1(input: {
  readonly approval: LinkedDeviceApprovalV1;
  readonly deliveries: LinkedDeviceProvisioningDeliveriesV1;
  readonly keyMaterial: DeviceLinkingKeyMaterialHandleV1;
  readonly acknowledgeHolderDeliveriesV1: (
    acknowledgement: LinkedDeviceHolderDeliveryAcknowledgementV1,
  ) => Promise<LinkedDeviceEnrollmentReceiptV1>;
}): DeviceLinkingLaneProvisioningHandoffV1 {
  return {
    kind: 'linked_device_lane_provisioning_handoff_v1',
    approval: input.approval,
    deliveries: input.deliveries,
    keyMaterial: input.keyMaterial,
    acknowledgeHolderDeliveriesV1: input.acknowledgeHolderDeliveriesV1,
  };
}
