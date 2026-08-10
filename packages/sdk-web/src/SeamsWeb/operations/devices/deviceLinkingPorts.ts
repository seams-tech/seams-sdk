import type {
  LinkedDeviceApprovalV1,
  LinkedDeviceEnrollmentKeyBindingV1,
  LinkedDeviceEnrollmentReceiptV1,
  LinkedDeviceOwnerAuthorizationSourceV1,
  LinkedDeviceProtocolVersionV1,
  LinkedDeviceReceiptAcknowledgementV1,
  LinkedDeviceSessionClaimRequestV1,
  LinkedDeviceSessionClaimV1,
  LinkedDeviceSessionState,
  LinkedDeviceSessionTransportEventV1,
  LinkedDeviceSessionTransportRequestV1,
  LinkedDeviceTargetCredentialRegistrationV1,
  LinkDevicePublicKeyB64u,
  QrLinkedDeviceSessionPayloadV4,
} from '@shared/device-linking';
import type { DigestB64u } from '@shared/utils/canonicalPrimitives';
import type {
  LaneOperationId,
  LaneOperationIdempotencyKey,
  LinkedDeviceEnrollmentId,
  LinkedDeviceId,
  LinkDeviceSessionId,
} from '@shared/signing-lanes/ids';
import type { WalletId, WebAuthnCredentialIdB64u } from '@shared/utils/domainIds';

/** Authenticated owner request proof produced by the one owner auth source. */
export type LinkSessionAuthenticationV1 = {
  readonly kind: 'link_session_authenticated_request_v1';
  readonly source: LinkedDeviceOwnerAuthorizationSourceV1;
  readonly proofDigestB64u: DigestB64u;
};

export type LinkSessionSubscriptionV1 = {
  readonly close: () => void | Promise<void>;
};

export type LinkSessionSnapshotV1 =
  | {
      readonly state: Extract<
        LinkedDeviceSessionState,
        { readonly state: 'displaying_qr' | 'expired_unclaimed' | 'cancelled_unclaimed' }
      >;
      readonly deviceId?: never;
    }
  | {
      readonly state: Exclude<
        LinkedDeviceSessionState,
        Extract<
          LinkedDeviceSessionState,
          { readonly state: 'displaying_qr' | 'expired_unclaimed' | 'cancelled_unclaimed' }
        >
      >;
      readonly deviceId: LinkedDeviceId;
    };

type LinkedDevicePendingSessionState = Extract<
  LinkedDeviceSessionState,
  {
    readonly state:
      | 'awaiting_target_passkey'
      | 'provisioning'
      | 'awaiting_aggregate_receipt'
      | 'committed_completion_required';
  }
>;

type LinkedDeviceApprovalReplayV1 =
  | {
      readonly state: 'pending';
      readonly session: LinkedDevicePendingSessionState;
    }
  | {
      readonly state: 'active';
      readonly session: Extract<LinkedDeviceSessionState, { readonly state: 'active' }>;
      readonly manifestDigestB64u: DigestB64u;
      readonly receipt: LinkedDeviceEnrollmentReceiptV1;
    };

export type LinkedDeviceApprovalResultV1 =
  | {
      readonly outcome: 'pending';
      readonly state: LinkedDevicePendingSessionState;
    }
  | {
      readonly outcome: 'active';
      readonly state: Extract<LinkedDeviceSessionState, { readonly state: 'active' }>;
      readonly manifestDigestB64u: DigestB64u;
      readonly receipt: LinkedDeviceEnrollmentReceiptV1;
    }
  | {
      readonly outcome: 'replayed';
      readonly replay: LinkedDeviceApprovalReplayV1;
    };

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
};

export type DeviceLinkingKeyMaterialPortV1 = {
  createBootstrapKeyMaterialV1(): Promise<{
    readonly handle: DeviceLinkingKeyMaterialHandleV1;
    readonly linkPublicKeyB64u: LinkDevicePublicKeyB64u;
    readonly devicePublicKeyB64u: LinkDevicePublicKeyB64u;
  }>;
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
    readonly walletId: WalletId;
    readonly enrollmentId: LinkedDeviceEnrollmentId;
    readonly deviceId: LinkedDeviceId;
    readonly keyMaterial: DeviceLinkingKeyMaterialHandleV1;
  }): Promise<{
    readonly credentialIdB64u: WebAuthnCredentialIdB64u;
  }>;
};

/** R102 source/recipient/delivery/activation handoff owned by the worker assembly. */
export type DeviceLinkingLaneProvisioningHandoffV1 = {
  readonly kind: 'linked_device_lane_provisioning_handoff_v1';
  readonly approval: LinkedDeviceApprovalV1;
  readonly keyMaterial: DeviceLinkingKeyMaterialHandleV1;
};

export type DeviceLinkingLaneProvisioningPortV1 = {
  installAuthorizedLaneHolderWorkerV1(input: {
    readonly walletId: WalletId;
    readonly enrollmentId: LinkedDeviceEnrollmentId;
    readonly deviceId: LinkedDeviceId;
    readonly credentialIdB64u: WebAuthnCredentialIdB64u;
  }): Promise<void>;
  prepareLinkedDeviceLanesV1(
    input: DeviceLinkingLaneProvisioningHandoffV1,
  ): Promise<LinkedDeviceEnrollmentReceiptV1>;
  resumeCommittedDeliveryV1(input: {
    readonly state: Extract<
      LinkedDeviceSessionState,
      { readonly state: 'committed_completion_required' }
    >;
    readonly keyMaterial: DeviceLinkingKeyMaterialHandleV1;
  }): Promise<LinkedDeviceEnrollmentReceiptV1 | void>;
};

export type Device2LinkingFlowPortsV1 = {
  readonly transport: LinkSessionTransportPortV1;
  readonly keyMaterial: DeviceLinkingKeyMaterialPortV1;
  readonly targetCredential: DeviceLinkingTargetCredentialPortV1;
  readonly laneProvisioning: DeviceLinkingLaneProvisioningPortV1;
};

export type Device1LinkingFlowPortsV1 = {
  readonly transport: LinkSessionOwnerTransportPortV1;
  readonly ownerAuthorization: DeviceLinkingOwnerAuthorizationPortV1;
};

export type DeviceLinkingFlowPortsV1 = Device2LinkingFlowPortsV1 & Device1LinkingFlowPortsV1;

export function createDeviceLinkingLaneProvisioningHandoffV1(input: {
  readonly approval: LinkedDeviceApprovalV1;
  readonly keyMaterial: DeviceLinkingKeyMaterialHandleV1;
}): DeviceLinkingLaneProvisioningHandoffV1 {
  return {
    kind: 'linked_device_lane_provisioning_handoff_v1',
    approval: input.approval,
    keyMaterial: input.keyMaterial,
  };
}
