import type {
  LinkedDeviceApprovalV1,
  LinkedDeviceRevokeResultV1,
  LinkedDeviceSummaryV1,
  LinkedDeviceOwnerAuthorizationSourceV1,
  LinkedDeviceOwnerSourceLaneV1,
  LinkedDeviceSessionTransportRequestV1,
  LinkedDeviceTargetCredentialRegistrationV1,
  LinkedDeviceTargetPreparationV1,
  LinkPrecommitFailureV1,
  LinkSessionStateV1,
  QrLinkedDeviceSessionPayloadV5,
  VerifiedLinkInputV1,
  VerifiedSourceAuthorityV1,
  VerifiedTargetFactorV1,
  OrdinarySignerMaterialRecipientRequestV1,
  LinkedDeviceOrdinaryMaterialSourceContributionTupleV1,
} from './contracts';
import type { SigningLaneRecord, WalletKeyRecord } from '../signing-lanes/records';
import type {
  EcdsaCapabilityManifestId,
  EcdsaCapabilityManifestRevision,
} from '../utils/ecdsaCapabilityActivation';
import type {
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
import type { DigestB64u } from '../utils/canonicalPrimitives';
import type {
  MpcMaterialActivationRef,
  WalletAuthorityId,
  WalletAuthMethodId,
  WalletId,
  WebAuthnCredentialIdB64u,
  WebAuthnRpId,
} from '../utils/domainIds';
import type { WebAuthnAuthenticatorDeviceInfo } from '../utils/webauthnDeviceInfo';
import type { ExactAdministeredSignerManifestV1 } from './delegatedActivationPlan';
import type { CanonicalDelegatedWalletPermissionSetV1 } from '../authorization/delegatedAuthority';
import type {
  ActiveWalletAuthorityV1,
  RevokedWalletAuthorityV1,
  WalletAuthorityV1,
  WalletEcdsaSignerActivationV1,
  WalletEd25519SignerActivationV1,
  WalletSignerActivationSetV1,
} from '../authorization/walletAuthority';
import type {
  EmailOtpWalletAuthMethodDraftV1,
  PasskeyWalletAuthMethodDraftV1,
} from '../utils/registrationIntent';

declare const linkSessionId: LinkDeviceSessionId;
declare const walletId: WalletId;
declare const enrollmentId: LinkedDeviceEnrollmentId;
declare const deviceId: LinkedDeviceId;
declare const walletKeyId: WalletKeyId;
declare const digest: DigestB64u;
declare const walletSessionId: WalletSessionId;
declare const authorizationId: WalletSessionAuthorizationId;
declare const credentialIdB64u: WebAuthnCredentialIdB64u;
declare const rpId: WebAuthnRpId;
declare const walletAuthMethodId: WalletAuthMethodId;
declare const authenticatorDevice: WebAuthnAuthenticatorDeviceInfo;
declare const ed25519WalletKey: Extract<WalletKeyRecord, { readonly keyFamily: 'ed25519' }>;
declare const ecdsaWalletKey: Extract<WalletKeyRecord, { readonly keyFamily: 'ecdsa_secp256k1' }>;
declare const ownerLane: Extract<
  SigningLaneRecord,
  { readonly laneKind: 'owner_passkey' | 'owner_email_otp' }
>;
declare const materialActivation: MpcMaterialActivationRef;
declare const manifestId: EcdsaCapabilityManifestId;
declare const manifestRevision: EcdsaCapabilityManifestRevision;
declare const targetDeviceId: DeviceId;
declare const walletAuthorityId: WalletAuthorityId;
declare const activeAuthority: ActiveWalletAuthorityV1;
declare const revokedAuthority: RevokedWalletAuthorityV1;
declare const ed25519Activation: WalletEd25519SignerActivationV1;
declare const ecdsaActivation: WalletEcdsaSignerActivationV1;
declare const permissionSet: CanonicalDelegatedWalletPermissionSetV1;
declare const signerManifest: ExactAdministeredSignerManifestV1;
declare const passkeyAuthMethod: PasskeyWalletAuthMethodDraftV1;
declare const emailOtpAuthMethod: EmailOtpWalletAuthMethodDraftV1;
declare const ordinarySignerMaterialRecipientRequests: readonly [
  OrdinarySignerMaterialRecipientRequestV1,
  ...OrdinarySignerMaterialRecipientRequestV1[],
];
declare const sourceContribution: LinkedDeviceOrdinaryMaterialSourceContributionTupleV1;

function acceptsWalletAuthorityId(value: WalletAuthorityId): void {
  void value;
}

acceptsWalletAuthorityId(walletAuthorityId);
// @ts-expect-error Wallet ids cannot be used as authority identities.
acceptsWalletAuthorityId(walletId);
// @ts-expect-error Auth-method ids cannot be used as authority identities.
acceptsWalletAuthorityId(walletAuthMethodId);

declare const payload: QrLinkedDeviceSessionPayloadV5;
declare const ownerAuthorization: LinkedDeviceOwnerAuthorizationSourceV1;

const ed25519OwnerSource: LinkedDeviceOwnerSourceLaneV1 = {
  kind: 'linked_device_owner_source_lane_v1',
  keyFamily: 'ed25519',
  walletKey: ed25519WalletKey,
  lane: ownerLane,
  materialActivation,
  verifiedActivationReceiptDigestB64u: digest,
};

const ecdsaOwnerSource: LinkedDeviceOwnerSourceLaneV1 = {
  kind: 'linked_device_owner_source_lane_v1',
  keyFamily: 'ecdsa_secp256k1',
  walletKey: ecdsaWalletKey,
  lane: ownerLane,
  materialActivation,
  verifiedActivationReceiptDigestB64u: digest,
  ecdsaSourceManifest: { manifestId, manifestRevision },
};

// @ts-expect-error Ed25519 source projections cannot carry ECDSA manifest identity.
const invalidEd25519OwnerSource: LinkedDeviceOwnerSourceLaneV1 = {
  ...ed25519OwnerSource,
  ecdsaSourceManifest: { manifestId, manifestRevision },
};

// @ts-expect-error ECDSA source projections require exact active manifest identity.
const invalidEcdsaOwnerSource: LinkedDeviceOwnerSourceLaneV1 = {
  kind: 'linked_device_owner_source_lane_v1',
  keyFamily: 'ecdsa_secp256k1',
  walletKey: ecdsaWalletKey,
  lane: ownerLane,
  materialActivation,
  verifiedActivationReceiptDigestB64u: digest,
};

// @ts-expect-error curve discriminator and wallet-key family must agree.
const invalidCrossCurveOwnerSource: LinkedDeviceOwnerSourceLaneV1 = {
  ...ed25519OwnerSource,
  walletKey: ecdsaWalletKey,
};

// Persisted permissions are delegated authorities with an opaque canonical set.
const invalidPermissionPayload: QrLinkedDeviceSessionPayloadV5 = {
  ...payload,
  requestedPermission: {
    // @ts-expect-error retired owner-equivalent permission branches are not supported
    kind: 'owner_equivalent_signing',
    permissions: payload.requestedPermission.permissions,
  },
};

const invalidPermissionPresence: QrLinkedDeviceSessionPayloadV5 = {
  ...payload,
  requestedPermission: {
    kind: 'delegated_wallet_authority_v1',
    // @ts-expect-error raw permission arrays must be parsed into the opaque canonical set
    permissions: ['sign'],
  },
};

const invalidOwnerAuthorization: LinkedDeviceOwnerAuthorizationSourceV1 = {
  kind: 'wallet_session',
  walletSessionId,
  authorizationId,
  // @ts-expect-error linked-device authorization cannot carry step-up evidence
  stepUpEvidenceSetId: digest,
};

const invalidStepUpOwnerAuthorization: LinkedDeviceOwnerAuthorizationSourceV1 = {
  // @ts-expect-error linked-device authorization requires an exact Wallet Session
  kind: 'step_up',
  evidenceSetId: digest,
};

const approval: LinkedDeviceApprovalV1 = {
  kind: 'linked_device_approval_v1',
  linkSessionId,
  walletId,
  enrollmentId,
  deviceId,
  linkPublicKeyB64u: payload.linkPublicKeyB64u,
  devicePublicKeyB64u: payload.devicePublicKeyB64u,
  permission: payload.requestedPermission,
  targetFactor: { kind: 'passkey_prf' },
  ownerAuthorization,
  orderedOwnerSourceLaneHints: [ed25519OwnerSource],
  approvedAtMs: 1,
  expiresAtMs: 2,
};

const summary: LinkedDeviceSummaryV1 = {
  deviceId,
  enrollmentId,
  walletId,
  credential: {
    kind: 'passkey',
    walletAuthMethodId,
    credentialIdB64u,
    device: authenticatorDevice,
  },
  permission: payload.requestedPermission,
  keyManifestDigestB64u: digest,
  coveredWalletKeys: [walletKeyId],
  state: 'provisioning',
  createdAtMs: 1,
  lastActivityAtMs: 2,
  revocationEpoch: 0,
};

const emailOtpSummary: LinkedDeviceSummaryV1 = {
  ...summary,
  credential: { kind: 'email_otp', walletAuthMethodId },
};

const invalidEmailOtpSummary: LinkedDeviceSummaryV1 = {
  ...emailOtpSummary,
  // @ts-expect-error Email OTP summaries cannot carry WebAuthn metadata.
  credential: { kind: 'email_otp', walletAuthMethodId, device: authenticatorDevice },
};
void invalidEmailOtpSummary;

const invalidPasskeySummary: LinkedDeviceSummaryV1 = {
  ...summary,
  // @ts-expect-error Passkey summaries require canonical authenticator metadata.
  credential: { kind: 'passkey', walletAuthMethodId, credentialIdB64u },
};
void invalidPasskeySummary;

const invalidSummaryState: LinkedDeviceSummaryV1 = {
  ...summary,
  // @ts-expect-error management projections have an exhaustive lifecycle
  state: 'pending',
};

// @ts-expect-error successful revocation results require enrollment receipt identity
const invalidRevokeResult: LinkedDeviceRevokeResultV1 = {
  kind: 'revoked',
};

// Approval always contains a non-empty ordered owner-source projection.
const invalidEmptyApprovalManifest: LinkedDeviceApprovalV1 = {
  ...approval,
  // @ts-expect-error empty source projections cannot activate an enrollment
  orderedOwnerSourceLaneHints: [],
};

const targetPreparation: LinkedDeviceTargetPreparationV1 = {
  kind: 'linked_device_target_preparation_v1',
  linkSessionId,
  walletId,
  enrollmentId,
  deviceId,
  walletAuthMethodId,
  ed25519ExportRoot: null,
  targetFactor: { kind: 'passkey_prf' },
  passkeyCreationOptions: {
    kind: 'webauthn_add_auth_method_registration_v1',
    walletAuthMethodId,
    challengeId: 'challenge-id',
    challengeB64u: 'challenge',
    rpId,
    user: { idB64u: 'user-handle', name: 'wallet', displayName: 'Wallet' },
    pubKeyCredParams: [
      { type: 'public-key', alg: -7 },
      { type: 'public-key', alg: -257 },
    ],
    authenticatorSelection: { residentKey: 'required', userVerification: 'preferred' },
    timeoutMs: 60_000,
    attestation: 'none',
    extensions: {
      prf: { eval: { firstB64u: 'first-salt', secondB64u: 'second-salt' } },
    },
    excludeCredentials: [],
  },
  ordinarySignerMaterialRecipientRequirements: [
    {
      kind: 'ordinary_signer_material_recipient_requirement_v1',
      walletKeyId,
      keyFamily: 'ed25519',
    },
  ],
  issuedAtMs: 1,
  expiresAtMs: 2,
};

const invalidEmptyTargetPreparation: LinkedDeviceTargetPreparationV1 = {
  ...targetPreparation,
  // @ts-expect-error a target preparation requires at least one recipient requirement
  ordinarySignerMaterialRecipientRequirements: [],
};

const credentialRegistration: LinkedDeviceTargetCredentialRegistrationV1 = {
  kind: 'linked_device_target_credential_registration_v1',
  linkSessionId,
  walletId,
  enrollmentId,
  deviceId,
  walletAuthMethodId,
  targetFactor: { kind: 'passkey_prf' },
  targetPreparationDigestB64u: digest,
  ordinarySignerMaterialRecipientRequests,
  webauthnRegistration: {
    kind: 'linked_device_webauthn_registration_v1',
    credentialIdB64u,
    authenticatorAttachment: 'platform',
    clientDataJsonB64u: 'AQ',
    attestationObjectB64u: 'Ag',
    transports: ['internal'],
  },
  registeredAtMs: 3,
};

const invalidPrivateRecipientRequest = {
  kind: 'ordinary_ed25519_signer_material_recipient_request_v1',
  keyFamily: 'ed25519',
  walletKeyId,
  // @ts-expect-error recipient private keys never cross the registration boundary
  recipientPrivateKey: 'private-key-must-stay-in-browser',
} satisfies OrdinarySignerMaterialRecipientRequestV1;
void invalidPrivateRecipientRequest;

const invalidIdOnlyCredentialRegistration: LinkedDeviceTargetCredentialRegistrationV1 = {
  kind: 'linked_device_target_credential_registration_v1',
  linkSessionId,
  walletId,
  enrollmentId,
  deviceId,
  // @ts-expect-error an ID cannot replace verified attestation and holder registrations
  credentialIdB64u: 'AQ',
  registeredAtMs: 3,
};

// Unclaimed cancellation cannot carry target identity; claimed cancellation requires it.
const invalidUnclaimedCancel: LinkedDeviceSessionTransportRequestV1 = {
  kind: 'linked_device_session_cancel_unclaimed_request_v1',
  linkSessionId,
  reason: 'user_cancelled',
  requestedAtMs: 1,
  // @ts-expect-error unclaimed cancellation has no device identity
  deviceId,
};

// @ts-expect-error claimed cancellation requires enrollment identity
const invalidClaimedCancel: LinkedDeviceSessionTransportRequestV1 = {
  kind: 'linked_device_session_cancel_claimed_request_v1',
  linkSessionId,
  deviceId,
  reason: 'user_cancelled',
  requestedAtMs: 1,
};

void invalidPermissionPayload;
void invalidPermissionPresence;
void invalidOwnerAuthorization;
void invalidEmptyApprovalManifest;
void invalidEmptyTargetPreparation;

// @ts-expect-error Email OTP preparation cannot carry passkey creation options.
const invalidEmailTargetPreparation: LinkedDeviceTargetPreparationV1 = {
  ...targetPreparation,
  targetFactor: { kind: 'email_otp' },
  passkeyCreationOptions: targetPreparation.passkeyCreationOptions,
};
void invalidEmailTargetPreparation;
void credentialRegistration;
void invalidIdOnlyCredentialRegistration;
void summary;
void invalidSummaryState;
void invalidRevokeResult;
void invalidUnclaimedCancel;
void invalidClaimedCancel;
void ed25519OwnerSource;
void ecdsaOwnerSource;
void invalidEd25519OwnerSource;
void invalidEcdsaOwnerSource;
void invalidCrossCurveOwnerSource;

const ed25519OnlyAuthorityActivations: Extract<
  WalletSignerActivationSetV1,
  { readonly keyFamilies: readonly ['ed25519'] }
> = {
  kind: 'wallet_signer_activation_set_v1',
  keyFamilies: ['ed25519'],
  ed25519: ed25519Activation,
};

const ecdsaOnlyAuthorityActivations: Extract<
  WalletSignerActivationSetV1,
  { readonly keyFamilies: readonly ['ecdsa_secp256k1'] }
> = {
  kind: 'wallet_signer_activation_set_v1',
  keyFamilies: ['ecdsa_secp256k1'],
  ecdsa: ecdsaActivation,
};

const bothAuthorityActivations: Extract<
  WalletSignerActivationSetV1,
  { readonly keyFamilies: readonly ['ed25519', 'ecdsa_secp256k1'] }
> = {
  kind: 'wallet_signer_activation_set_v1',
  keyFamilies: ['ed25519', 'ecdsa_secp256k1'],
  ed25519: ed25519Activation,
  ecdsa: ecdsaActivation,
};
void ed25519OnlyAuthorityActivations;
void ecdsaOnlyAuthorityActivations;
void bothAuthorityActivations;

const ed25519AuthorityWithEcdsa: Extract<
  WalletSignerActivationSetV1,
  { readonly keyFamilies: readonly ['ed25519'] }
> = {
  kind: 'wallet_signer_activation_set_v1',
  keyFamilies: ['ed25519'],
  ed25519: ed25519Activation,
  // @ts-expect-error Ed25519-only authorities cannot carry ECDSA activation material.
  ecdsa: ecdsaActivation,
};
void ed25519AuthorityWithEcdsa;

// @ts-expect-error A pending authority cannot retain an activation timestamp.
const pendingAuthorityWithActivation: Extract<
  WalletAuthorityV1,
  { readonly state: 'pending_local_install' }
> = {
  ...activeAuthority,
  state: 'pending_local_install',
  localInstallPackageSetDigestB64u: activeAuthority.authorityDigestB64u,
};
void pendingAuthorityWithActivation;

const activeAuthorityWithPendingPackage: ActiveWalletAuthorityV1 = {
  ...activeAuthority,
  // @ts-expect-error Active authorities cannot carry a local-install package digest.
  localInstallPackageSetDigestB64u: activeAuthority.authorityDigestB64u,
};
void activeAuthorityWithPendingPackage;

const revokedAuthorityWithPendingPackage: RevokedWalletAuthorityV1 = {
  ...revokedAuthority,
  // @ts-expect-error Revoked authorities cannot carry a local-install package digest.
  localInstallPackageSetDigestB64u: revokedAuthority.authorityDigestB64u,
};
void revokedAuthorityWithPendingPackage;

const validLinkSessionStates = [
  { state: 'displaying_qr' },
  { state: 'claimed', deviceId: targetDeviceId },
  { state: 'awaiting_target_factor', deviceId: targetDeviceId },
  { state: 'provisioning', deviceId: targetDeviceId },
  {
    state: 'authority_pending_local_install',
    deviceId: targetDeviceId,
    authorityId: walletAuthorityId,
    packageSetDigestB64u: digest,
  },
  {
    state: 'active',
    deviceId: targetDeviceId,
    authorityId: walletAuthorityId,
    activatedAtMs: 4,
  },
  {
    state: 'failed_before_commit',
    error: { kind: 'invalid_input', reason: 'invalid fixture' },
  },
  { state: 'cancelled', cancelledAtMs: 5 },
  { state: 'expired', expiredAtMs: 6 },
] satisfies readonly LinkSessionStateV1[];
void validLinkSessionStates;

const validFailure = {
  kind: 'claim_conflict',
  reason: 'already claimed',
} satisfies LinkPrecommitFailureV1;
void validFailure;

const verifiedSourceAuthority = {
  authority: activeAuthority,
  authMethodId: walletAuthMethodId,
  verifiedRevocationEpoch: 0,
  authorityDigestB64u: digest,
  verifiedAtMs: 7,
} satisfies VerifiedSourceAuthorityV1;

const verifiedPasskeyTarget = {
  kind: 'verified_passkey_target_v1',
  authMethod: passkeyAuthMethod,
  verificationDigestB64u: digest,
  verifiedAtMs: 8,
} satisfies VerifiedTargetFactorV1;

const verifiedEmailOtpTarget = {
  kind: 'verified_email_otp_target_v1',
  authMethod: emailOtpAuthMethod,
  verificationDigestB64u: digest,
  verifiedAtMs: 9,
} satisfies VerifiedTargetFactorV1;

const verifiedLinkInput = {
  walletId,
  linkSessionId,
  enrollmentId,
  targetDeviceId,
  sourceAuthority: verifiedSourceAuthority,
  targetFactor: verifiedPasskeyTarget,
  permissions: permissionSet,
  signerManifest,
  sourceContribution,
  ordinarySignerMaterialRecipientRequests,
} satisfies VerifiedLinkInputV1;
void verifiedLinkInput;
void verifiedEmailOtpTarget;

// @ts-expect-error claimed cannot carry an authority identity
const invalidClaimedAuthorityState: LinkSessionStateV1 = {
  state: 'claimed',
  deviceId: targetDeviceId,
  authorityId: walletAuthorityId,
};
void invalidClaimedAuthorityState;

// @ts-expect-error active requires its activation timestamp
const invalidActiveState: LinkSessionStateV1 = {
  state: 'active',
  deviceId: targetDeviceId,
  authorityId: walletAuthorityId,
};
void invalidActiveState;

// @ts-expect-error displaying_qr cannot carry a device identity
const invalidDisplayingDevice: LinkSessionStateV1 = {
  state: 'displaying_qr',
  deviceId: targetDeviceId,
};
void invalidDisplayingDevice;

// @ts-expect-error cancelled cannot carry an authority identity
const invalidCancelledAuthority: LinkSessionStateV1 = {
  state: 'cancelled',
  cancelledAtMs: 10,
  authorityId: walletAuthorityId,
};
void invalidCancelledAuthority;

const invalidTargetDeviceIdSwap: VerifiedLinkInputV1 = {
  ...verifiedLinkInput,
  // @ts-expect-error a wallet-authority id cannot replace the target device id
  targetDeviceId: walletAuthorityId,
};
void invalidTargetDeviceIdSwap;

// @ts-expect-error email target verification requires the email-OTP draft
const invalidTargetFactorSwap: VerifiedTargetFactorV1 = {
  kind: 'verified_email_otp_target_v1',
  authMethod: passkeyAuthMethod,
  verificationDigestB64u: digest,
  verifiedAtMs: 11,
};
void invalidTargetFactorSwap;

const activeLinkState = {
  state: 'active',
  deviceId: targetDeviceId,
  authorityId: walletAuthorityId,
  activatedAtMs: 12,
} satisfies Extract<LinkSessionStateV1, { readonly state: 'active' }>;

// @ts-expect-error a broad spread cannot turn active state into displaying_qr
const invalidBroadSpreadState: LinkSessionStateV1 = {
  ...activeLinkState,
  state: 'displaying_qr',
};
void invalidBroadSpreadState;
