import type { DeviceLinkingEd25519ExportRootPortV1 } from './deviceLinkingEd25519ExportRoot';
import type { UnlockedWalletEd25519ExportRootCapabilityV1 } from '@/core/signingEngine/workerManager/workerTypes';
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
  LinkSessionProjectionV1,
  LinkSessionStateV1,
  LinkSessionTransportEventV1,
  LinkedDeviceSessionTransportRequestV1,
  LinkedDeviceTargetCredentialRegistrationV1,
  LinkedDeviceTargetCredentialRegistrationResultV1,
  LinkedDeviceTargetPreparationV1,
  LinkedDeviceTargetReadyR102InputV1,
  LinkedDeviceWebAuthnRegistrationV1,
  LinkedDeviceWalletSessionDeliveryV1,
  LinkDevicePublicKeyB64u,
  QrLinkedDeviceSessionPayloadV5,
  LinkedDeviceOwnerFinalizeRequestV1,
  LinkedDeviceLocalAccountProjectionV1,
  LinkedDeviceEmailOtpChallengeStartRequestV1,
  LinkedDeviceEmailOtpChallengeResendRequestV1,
  LinkedDeviceEmailOtpChallengeVerifyRequestV1,
  LinkedDeviceEmailOtpChallengeResultV1,
  LinkedDeviceEmailOtpVerificationResultV1,
  LinkedDeviceEmailOtpFactorReleaseEnvelopeV1,
  LinkedDeviceOwnerEnrollmentCeremonyV1,
  ActivateInstalledAuthorityResultV1,
  CommittedAuthorityPackagesV1,
  LocalAuthorityActivationFinalAckV1,
  LocalAuthorityInstallationReceiptV1,
} from '@shared/device-linking';
import type { WalletAddAuthMethodFinalizeResponse } from '@/core/rpcClients/relayer/walletRegistration';
import type {
  LaneProtocolCommitReceiptV1,
  RotatableSigningLaneJobV1,
  SealedLaneHolderMaterialV1,
} from '@shared/signing-lanes/rotation';
import type {
  LinkedDeviceEd25519ExportRootPackageV1,
  LinkedDeviceEd25519ExportRootRecipientV1,
  LinkedDeviceEd25519ExportRootSubmissionV1,
} from '@shared/device-linking/ed25519ExportRoot';
import type { DigestB64u } from '@shared/utils/canonicalPrimitives';
import type {
  LaneOperationId,
  LaneOperationIdempotencyKey,
  LinkedDeviceId,
  LinkedDeviceEnrollmentId,
  LinkDeviceSessionId,
} from '@shared/signing-lanes/ids';
import type { MpcMaterialActivationRef, WalletId } from '@shared/utils/domainIds';
import type { LaneSealedHolderRecordV1 } from '@/core/indexedDB/seamsWalletDB/laneHolderMaterialStore';
import type {
  DeviceLinkingHolderSigningMaterialHandleV1,
  DeviceLinkingHolderSigningMaterialPortV1,
} from '@/core/signingEngine/session/lanes/linkedDevicePorts';
import type { DeviceLinkingOrdinaryMaterialWorkerPortV1 } from './deviceLinkingOrdinaryMaterialWorker';
import type {
  PasskeyCustodyEnvelopeRecord,
  WalletCustodyEnvelopeFactor,
} from '@shared/passkey-custody';
export type {
  DeviceLinkingAuthorityActivationFlowInputV1,
  DeviceLinkingAuthorityInstallationAssemblyOptionsV1,
  DeviceLinkingAuthorityInstallationPortV1,
  DeviceLinkingCommittedPackageSealingPortV1,
  DeviceLinkingSealedAuthorityRecordsV1,
} from './deviceLinkingAuthorityInstallation';
import type { DeviceLinkingAuthorityInstallationPortV1 } from './deviceLinkingAuthorityInstallation';

export type DeviceLinkingEmailOtpExportRootPreparationInputV1 =
  | {
      readonly kind: 'required';
      readonly transferBindingJson: string;
      readonly package: LinkedDeviceEd25519ExportRootPackageV1;
      readonly replacementEnvelopeBindingJson: string;
    }
  | {
      readonly kind: 'not_required';
      readonly transferBindingJson?: never;
      readonly package?: never;
      readonly replacementEnvelopeBindingJson?: never;
    };

export type {
  DeviceLinkingEd25519SigningShareV1,
  DeviceLinkingEcdsaExportArtifactV1,
  DeviceLinkingEcdsaExportPublicFactsV1,
  DeviceLinkingEcdsaExportRecipientV1,
  DeviceLinkingHolderSigningMaterialHandleV1,
  DeviceLinkingHolderSigningMaterialPortV1,
} from '@/core/signingEngine/session/lanes/linkedDevicePorts';

/** Authenticated owner request proof produced by the one owner auth source. */
export type LinkSessionAuthenticationV1 = {
  readonly kind: 'link_session_authenticated_request_v1';
  readonly source: LinkedDeviceOwnerAuthorizationSourceV1;
  readonly proofDigestB64u: DigestB64u;
};

export type LinkSessionSubscriptionV1 = {
  readonly close: () => void | Promise<void>;
};

export type LinkSessionSnapshotV1 = LinkSessionProjectionV1;
export type { LinkedDeviceApprovalResultV1 };

/** Strict R103E authority-package delivery and activation acknowledgement. */
export type DeviceLinkingAuthorityActivationTransportPortV1 = {
  receiveCommittedAuthorityPackagesV1(input: {
    readonly linkSessionId: LinkDeviceSessionId;
  }): Promise<CommittedAuthorityPackagesV1>;
  activateInstalledAuthorityV1(input: {
    readonly linkSessionId: LinkDeviceSessionId;
    readonly receipt: LocalAuthorityInstallationReceiptV1;
  }): Promise<ActivateInstalledAuthorityResultV1>;
  acknowledgeLocalAuthorityActivationV1(input: {
    readonly acknowledgement: LocalAuthorityActivationFinalAckV1;
  }): Promise<void>;
};

/**
 * This adapter owns challenge exchange, canonical request bytes, and worker
 * signing. Domain flows see exact DTOs and an opaque worker handle only.
 */
export type DeviceLinkingAuthenticatedTransportPortV1 = {
  createUnclaimedSessionV1(input: {
    readonly payload: QrLinkedDeviceSessionPayloadV5;
    readonly state: Extract<LinkSessionStateV1, { readonly state: 'displaying_qr' }>;
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
  startTargetEmailOtpChallengeV1(input: {
    readonly request: LinkedDeviceEmailOtpChallengeStartRequestV1;
  }): Promise<LinkedDeviceEmailOtpChallengeResultV1>;
  resendTargetEmailOtpChallengeV1(input: {
    readonly request: LinkedDeviceEmailOtpChallengeResendRequestV1;
  }): Promise<LinkedDeviceEmailOtpChallengeResultV1>;
  verifyTargetEmailOtpChallengeV1(input: {
    readonly request: LinkedDeviceEmailOtpChallengeVerifyRequestV1;
  }): Promise<LinkedDeviceEmailOtpVerificationResultV1>;
  requestProvisioningDeliveriesV1(input: {
    readonly command: LinkedDeviceProvisioningCommandV1;
  }): Promise<LinkedDeviceProvisioningDeliveriesV1>;
  acknowledgeHolderDeliveriesV1(input: {
    readonly acknowledgement: LinkedDeviceHolderDeliveryAcknowledgementV1;
  }): Promise<LinkedDeviceEnrollmentReceiptV1>;
  registerTargetCredentialV1(input: {
    readonly registration: LinkedDeviceTargetCredentialRegistrationV1;
  }): Promise<LinkedDeviceTargetCredentialRegistrationResultV1>;
  /**
   * Returns the local account identity alongside the finalize, because a device
   * that never registered here cannot unlock without it.
   */
  finalizeOwnerAuthMethodV1(input: {
    readonly linkSessionId: LinkDeviceSessionId;
    readonly request: LinkedDeviceOwnerFinalizeRequestV1;
  }): Promise<{
    readonly response: WalletAddAuthMethodFinalizeResponse;
    readonly localAccount: LinkedDeviceLocalAccountProjectionV1;
  }>;
  /**
   * Device 2 publishes where the Ed25519 Yao Client export root
   * should be sealed, then collects the sealed package once Device 1 has
   * produced it. `null` means Device 1 has not sealed yet — normal while the
   * owner is still approving, not an error.
   */
  registerEd25519ExportRootRecipientV1(input: {
    readonly recipient: LinkedDeviceEd25519ExportRootRecipientV1;
  }): Promise<void>;
  getEd25519ExportRootPackageV1(input: {
    readonly linkSessionId: LinkDeviceSessionId;
  }): Promise<LinkedDeviceEd25519ExportRootPackageV1 | null>;
  receiveCommittedAuthorityPackagesV1(input: {
    readonly linkSessionId: LinkDeviceSessionId;
  }): Promise<CommittedAuthorityPackagesV1>;
  activateInstalledAuthorityV1(input: {
    readonly linkSessionId: LinkDeviceSessionId;
    readonly receipt: LocalAuthorityInstallationReceiptV1;
  }): Promise<ActivateInstalledAuthorityResultV1>;
  acknowledgeLocalAuthorityActivationV1(input: {
    readonly acknowledgement: LocalAuthorityActivationFinalAckV1;
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
    readonly onEvent: (event: LinkSessionTransportEventV1) => void;
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
  /**
   * Device 1 reads where to seal, then returns the sealed package. `null` means Device 2 has not published a recipient key
   * yet — normal while the target device is still preparing.
   */
  getEd25519ExportRootRecipientV1(input: {
    readonly linkSessionId: LinkDeviceSessionId;
    readonly authentication: LinkSessionAuthenticationV1;
  }): Promise<LinkedDeviceEd25519ExportRootRecipientV1 | null>;
  submitEd25519ExportRootPackageV1(input: {
    readonly submission: LinkedDeviceEd25519ExportRootSubmissionV1;
    readonly authentication: LinkSessionAuthenticationV1;
  }): Promise<void>;
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
  /** Public P-256 recipient for an Email OTP factor release. */
  readonly emailOtpReleasePublicKey65B64u: string;
};

export type DeviceLinkingPersistedHolderSigningMaterialChildV1 = {
  readonly job: RotatableSigningLaneJobV1;
  readonly protocolCommitReceipt: LaneProtocolCommitReceiptV1;
  readonly materialActivation: MpcMaterialActivationRef;
  readonly holderRecord: LaneSealedHolderRecordV1;
};

export type DeviceLinkingEmailOtpHolderSigningMaterialBatchInputV1 = {
  /** The worker slot that retained the Email OTP factor during preparation. */
  readonly keyMaterial: DeviceLinkingKeyMaterialHandleV1;
  readonly walletId: WalletId;
  readonly linkSessionId: LinkDeviceSessionId;
  readonly enrollmentId: LinkedDeviceEnrollmentId;
  readonly deviceId: LinkedDeviceId;
  readonly targetPreparationDigestB64u: DigestB64u;
  readonly orderedChildren: readonly [
    DeviceLinkingPersistedHolderSigningMaterialChildV1,
    ...DeviceLinkingPersistedHolderSigningMaterialChildV1[],
  ];
};

export type DeviceLinkingEmailOtpHolderSigningMaterialBatchResultV1 = {
  readonly handles: readonly [
    DeviceLinkingHolderSigningMaterialHandleV1,
    ...DeviceLinkingHolderSigningMaterialHandleV1[],
  ];
  readonly warmSessionFactorSecret: ArrayBuffer;
};

export type DeviceLinkingEmailOtpFactorReleaseHolderSigningMaterialBatchInputV1 = {
  /** The fresh server envelope is decrypted only by this worker slot. */
  readonly keyMaterial: DeviceLinkingKeyMaterialHandleV1;
  readonly walletId: WalletId;
  readonly enrollmentId: LinkedDeviceEnrollmentId;
  readonly expectedChallengeId: string;
  readonly factorRelease: LinkedDeviceEmailOtpFactorReleaseEnvelopeV1;
  readonly orderedChildren: readonly [
    DeviceLinkingPersistedHolderSigningMaterialChildV1,
    ...DeviceLinkingPersistedHolderSigningMaterialChildV1[],
  ];
};

export type DeviceLinkingKeyMaterialPortV1 = {
  createBootstrapKeyMaterialV1(): Promise<DeviceLinkingKeyMaterialBundleV1>;

  openPersistedEmailOtpHolderSigningMaterialsV1(
    input: DeviceLinkingEmailOtpHolderSigningMaterialBatchInputV1,
  ): Promise<DeviceLinkingEmailOtpHolderSigningMaterialBatchResultV1>;
  openPersistedEmailOtpHolderSigningMaterialsFromFactorReleaseV1(
    input: DeviceLinkingEmailOtpFactorReleaseHolderSigningMaterialBatchInputV1,
  ): Promise<
    readonly [
      DeviceLinkingHolderSigningMaterialHandleV1,
      ...DeviceLinkingHolderSigningMaterialHandleV1[],
    ]
  >;
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

export type DeviceLinkingLiveKeyMaterialPortV1 = DeviceLinkingKeyMaterialPortV1 &
  DeviceLinkingHolderSigningMaterialPortV1 &
  DeviceLinkingOrdinaryMaterialWorkerPortV1;

export type EmailOtpExportRootEnvelopeRecordV1 = Omit<PasskeyCustodyEnvelopeRecord, 'factor'> & {
  readonly factor: Extract<WalletCustodyEnvelopeFactor, { readonly kind: 'email_otp' }>;
};

export type LinkedDeviceOwnerAuthorizationResultBaseV1 = {
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
};

export type LinkedDeviceOwnerAuthorizationResultV1 =
  | (LinkedDeviceOwnerAuthorizationResultBaseV1 & {
      readonly exportRootRequirement: 'required';
      readonly ed25519ExportRootCapability: UnlockedWalletEd25519ExportRootCapabilityV1;
    })
  | (LinkedDeviceOwnerAuthorizationResultBaseV1 & {
      readonly exportRootRequirement: 'not_required';
      readonly ed25519ExportRootCapability?: never;
    });

export type DeviceLinkingOwnerAuthorizationPortV1 = {
  /**
   * Starts the canonical owner add-auth-method ceremony that the linked device
   * will finalize.
   *
   * It belongs to Device 1's owner authority, not to the link session: Device 2
   * has no owner authority and cannot start one. Approval is the single
   * owner-authenticated step in the flow, so the ceremony is started here and
   * carried by the approval that authorizes it.
   *
   * It also returns the custody material that same prompt produced, held for
   * the seal that happens once Device 2 publishes a recipient.
   */
  startOwnerEnrollmentCeremonyV1(input: {
    readonly linkSessionId: LinkDeviceSessionId;
    readonly walletId: WalletId;
    readonly targetFactor: QrLinkedDeviceSessionPayloadV5['targetFactor'];
    readonly expiresAtMs: number;
    readonly requestedAtMs: number;
  }): Promise<{ readonly ceremony: LinkedDeviceOwnerEnrollmentCeremonyV1 }>;
  authenticateOwnerForLinkingV1(input: {
    readonly payload: QrLinkedDeviceSessionPayloadV5;
    readonly requestedAtMs: number;
  }): Promise<LinkedDeviceOwnerAuthorizationResultV1>;
};

export type DeviceLinkingTargetCredentialPortV1 = {
  createTargetCredentialV1(input: {
    readonly preparation: Extract<
      LinkedDeviceTargetPreparationV1,
      { readonly targetFactor: { readonly kind: 'passkey_prf' } }
    >;
    readonly keyMaterial: DeviceLinkingKeyMaterialHandleV1;
  }): Promise<{
    readonly webauthnRegistration: LinkedDeviceWebAuthnRegistrationV1;
    /** Ephemeral PRF output from the user-verified creation ceremony. */
    readonly factorSecret: Uint8Array;
  }>;
};

export type Device2LinkingFlowPortsV1 = {
  readonly transport: LinkSessionTransportPortV1;
  readonly keyMaterial: DeviceLinkingLiveKeyMaterialPortV1;
  readonly targetCredential: DeviceLinkingTargetCredentialPortV1;
  readonly authorityInstallation: DeviceLinkingAuthorityInstallationPortV1;
  readonly readExpectedLockGenerationV1: (walletId: WalletId) => Promise<number>;
  /** Device 2's recipient and factor-reseal half of the Ed25519 export-root handoff. */
  readonly ed25519ExportRoot: DeviceLinkingEd25519ExportRootPortV1;
};

export type Device1LinkingFlowPortsV1 = {
  readonly transport: LinkSessionOwnerTransportPortV1;
  readonly ownerAuthorization: DeviceLinkingOwnerAuthorizationPortV1;
  /** Device 1's encrypted Ed25519 export-root handoff. */
  readonly ed25519ExportRoot: DeviceLinkingEd25519ExportRootPortV1;
  readonly sourcePreparation: Device1SourcePreparationPortV1;
};

export type Device1TargetReadySourceInputV1 = LinkedDeviceTargetReadyR102InputV1;

export type Device1SourcePreparationPortV1 = {
  prepareTargetReadyDeliveriesV1(
    input: Device1TargetReadySourceInputV1,
  ): Promise<LinkedDeviceProvisioningDeliveriesV1>;
};

export type DeviceLinkingFlowPortsV1 = Device2LinkingFlowPortsV1 & Device1LinkingFlowPortsV1;
