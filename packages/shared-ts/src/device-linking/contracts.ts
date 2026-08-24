import type { DelegatedWalletAuthorityV1 } from '../authorization/delegatedAuthority';
import type {
  AuthorizationEvidenceSetId,
  DeviceId,
  WalletSessionAuthorizationId,
  WalletSessionId,
} from '../authorization/capabilityKinds';
import type {
  LinkedDeviceEnrollmentId,
  LinkedDeviceId,
  LinkDeviceSessionId,
  WalletKeyId,
} from '../signing-lanes/ids';
import type { WalletKeyRecord } from '../signing-lanes/records';
import type {
  MpcMaterialActivationRef,
  WalletAuthorityId,
  WalletAuthMethodId,
  WalletId,
  WebAuthnCredentialIdB64u,
} from '../utils/domainIds';
import type { WebAuthnAuthenticatorDeviceInfo } from '../utils/webauthnDeviceInfo';
import type { DigestB64u } from '../utils/canonicalPrimitives';
import type { WalletAddAuthMethodRegistrationOptions } from '../utils/addAuthMethodRegistration';
import type { Ed25519PublicKeyB64u } from '../passkey-custody/primitives';
import type { SigningLaneRecord } from '../signing-lanes/records';
import type {
  EcdsaCapabilityManifestId,
  EcdsaCapabilityManifestRevision,
} from '../utils/ecdsaCapabilityActivation';
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
import type {
  LinkedDeviceOrdinaryMaterialSourceContributionPreparationV1,
  LinkedDeviceOrdinaryMaterialSourceContributionPreparationTupleV1,
  LinkedDeviceOrdinaryMaterialSourceContributionTupleV1,
} from './sourceContribution';

export type {
  LinkedDeviceEcdsaSourceContributionBindingV1,
  LinkedDeviceEcdsaSourceContributionPackageV1,
  LinkedDeviceEcdsaSourceContributionPreparationV1,
  LinkedDeviceEcdsaSourceDerivationV1,
  LinkedDeviceEcdsaSourcePreservingActivationReceiptV1,
  LinkedDeviceEcdsaSourceContributionV1,
  LinkedDeviceEcdsaSourceSignerIdentityV1,
  LinkedDeviceEcdsaTargetRecipientPreparationV1,
  LinkedDeviceEd25519SourceContributionPreparationV1,
  LinkedDeviceEd25519SourceContributionV1,
  LinkedDeviceOrdinaryMaterialSourceContributionPreparationV1,
  LinkedDeviceOrdinaryMaterialSourceContributionPreparationTupleV1,
  LinkedDeviceOrdinaryMaterialSourceContributionTupleV1,
  LinkedDeviceOrdinaryMaterialSourceContributionV1,
} from './sourceContribution';

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
      readonly state: 'awaiting_source_contribution';
      readonly linkSessionId: LinkDeviceSessionId;
      readonly walletId: WalletId;
      readonly enrollmentId: LinkedDeviceEnrollmentId;
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
   * Source projections authenticated by the owner Wallet Session. The server
   * re-resolves each lane against the active authority before preparation.
   */
  readonly orderedOwnerSourceLaneHints: readonly [
    LinkedDeviceOwnerSourceLaneV1,
    ...LinkedDeviceOwnerSourceLaneV1[],
  ];
  readonly approvedAtMs: number;
  readonly expiresAtMs: number;
};

export type LinkedDeviceApprovalV1 =
  | (LinkedDeviceApprovalBaseV1 & {
      readonly targetFactor: LinkedDeviceTargetFactorV1;
      /** The first owner approval precedes Device 2 recipient preparation. */
      readonly sourceContribution?: never;
    })
  | (LinkedDeviceApprovalBaseV1 & {
      readonly targetFactor: LinkedDeviceTargetFactorV1;
      /** Final owner relay after Device 2 has registered recipient bindings. */
      readonly sourceContribution: LinkedDeviceOrdinaryMaterialSourceContributionTupleV1;
    });

export type LinkedDeviceApprovalDeliveryV1 = {
  readonly kind: 'linked_device_approval_delivery_v1';
  readonly approval: LinkedDeviceApprovalV1;
};

/** Public source facts needed to bind an Ed25519 export-root handoff. */
export type LinkedDeviceEd25519ExportRootPreparationV1 = {
  readonly kind: 'linked_device_ed25519_export_root_preparation_v1';
  readonly walletKeyId: WalletKeyId;
  readonly applicationBindingDigestB64u: DigestB64u;
  readonly registeredPublicKeyB64u: Ed25519PublicKeyB64u;
  readonly revocationEpoch: number;
};

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

/**
 * The server-owned passkey ceremony carried by a target preparation. The
 * auth-method identity is duplicated here intentionally: the parser binds it
 * to the preparation identity before this value can enter the domain.
 */
export type LinkedDevicePasskeyCreationOptionsV1 = WalletAddAuthMethodRegistrationOptions & {
  readonly walletAuthMethodId: WalletAuthMethodId;
};

export type LinkedDeviceTargetPreparationV1 =
  | (LinkedDeviceTargetPreparationBaseV1 & {
      readonly targetFactor: { readonly kind: 'passkey_prf' };
      readonly passkeyCreationOptions: LinkedDevicePasskeyCreationOptionsV1;
    })
  | (LinkedDeviceTargetPreparationBaseV1 & {
      readonly targetFactor: { readonly kind: 'email_otp' };
      readonly passkeyCreationOptions?: never;
    });

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
  LinkedDeviceOrdinaryMaterialSourceContributionPreparationV1;

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

export type LinkedDeviceSessionTransportRequestV1 =
  | LinkedDeviceSessionClaimRequestV1
  | LinkedDeviceApprovalV1
  | LinkedDeviceTargetCredentialRegistrationV1
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

export type LinkedDevicePendingSessionStateV1 = Extract<
  LinkSessionStateV1,
  {
    readonly state:
      | 'awaiting_target_factor'
      | 'awaiting_source_contribution'
      | 'provisioning'
      | 'authority_pending_local_install';
  }
>;

export type LinkedDeviceApprovalResultV1 =
  | {
      readonly outcome: 'pending';
      readonly state: LinkedDevicePendingSessionStateV1;
    }
  | {
      readonly outcome: 'replayed';
      readonly replay: {
        readonly state: 'pending';
        readonly session: LinkedDevicePendingSessionStateV1;
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
  /**
   * The authority this method belongs to.
   *
   * R109C puts both factor families on one founding authority and lists one
   * entry per active method, so a reader needs this to group the entries it was
   * given — to decide which family is still missing on THIS authority, and to
   * know which sibling would remain if one were removed. Grouping by wallet
   * instead would fold in every linked device's methods.
   */
  readonly walletAuthorityId: WalletAuthorityId;
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
  /** Exact persisted method selected from the authority inventory. */
  readonly walletAuthMethodId: WalletAuthMethodId;
  readonly requestedAtMs: number;
};

export type LinkedDeviceRevokeResultV1 =
  | {
      readonly kind: 'revoked';
      readonly walletAuthMethodId: WalletAuthMethodId;
      readonly authorityId: WalletAuthorityId;
      readonly revocationEpoch: number;
    }
  | {
      readonly kind: 'not_found' | 'conflict' | 'unauthorized';
    };

export type LinkedDeviceManagementRequestV1 =
  | LinkedDeviceListRequestV1
  | LinkedDeviceRevokeRequestV1;

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
      readonly state: 'awaiting_source_contribution';
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
  /** One encrypted/publicly-bound contribution per source signer family. */
  readonly sourceContribution: LinkedDeviceOrdinaryMaterialSourceContributionTupleV1;
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

/** The bearer used to authenticate ordinary operations for an active session. */
export type WalletSessionOperationCredentialV1 = {
  readonly kind: 'opaque_wallet_session_operation_credential_v1';
  readonly token: string;
  readonly walletSessionId: WalletSessionId;
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
      readonly operationCredential: WalletSessionOperationCredentialV1;
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
