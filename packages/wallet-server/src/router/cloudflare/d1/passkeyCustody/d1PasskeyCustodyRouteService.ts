import type {
  CloudflareD1PasskeyCustodyEnvelopeStore,
  PasskeyCustodyEnvelopeFactorLookupResult,
  PasskeyCustodyEnvelopeLocator,
  WalletCustodyFactorRef,
  WalletCredentialActivityProjection,
} from './d1PasskeyCustodyEnvelopeStore';
import { envelopeFactorRef } from './d1PasskeyCustodyEnvelopeStore';
import {
  handlePasskeyCustodyEnvelopeRetrieval,
  type PasskeyCustodyEnvelopeRetrievalRouteResponse,
} from '../../../domains/passkeyCustody/passkeyCustodyEnvelopeRetrievalRoute';
import type { PasskeyCustodyEnvelopeRetrievalRequest } from '../../../domains/passkeyCustody/passkeyCustodyEnvelopeRetrieval';
import type { WebAuthnAuthenticatorStore } from '../../../../core/WebAuthnAuthenticatorStore';
import type { CloudflareD1WebAuthnStore } from '../webauthn/d1WebAuthnStore';
import type { NormalizedLogger } from '../../../../core/logger';
import type {
  CloudflareD1WalletCustodyCommitStore,
  WalletRecoveryCodeLocatorRecord,
} from './d1WalletCustodyCommitStore';
import {
  prepareWalletRecoveryWithCodeV1,
  type WalletRecoveryPreparationResult,
} from '../../../domains/passkeyCustody/walletRecoveryAttempt';
import {
  parsePasskeyEnvelopeId,
  parseWalletAuthMethodId,
  parseWalletAuthorityId,
  parseWalletAuthorityBindingDigest,
  parseWalletId,
  parseWebAuthnCredentialIdB64u,
  parseWebAuthnRpId,
  parseWalletRecoveryOperationId,
  type WalletAuthMethodId,
  type WalletAuthorityBindingDigest,
  type WalletAuthorityId,
  type WalletId,
  type WalletRecoveryOperationId,
  type WebAuthnRpId,
} from '@shared/utils/domainIds';
import { parseDeviceId, type DeviceId } from '@shared/authorization/capabilityKinds';
import { isHostWithinRpId, originHostnameOrEmpty } from '../../../../core/authService/webauthnOidcHelpers';
import { parseDigestB64u, type DigestB64u } from '@shared/utils/canonicalPrimitives';
import { alphabetizeStringify, sha256BytesUtf8 } from '@shared/utils/digests';
import type { WalletAuthMethodRecordV2 } from '@shared/utils/registrationIntent';
import { secureRandomBase64Url } from '@shared/utils/secureRandomId';
import { base64UrlEncode } from '@shared/utils/encoders';
import {
  PASSKEY_PRF_FIRST_SALT_V1,
  PASSKEY_PRF_SECOND_SALT_V1,
} from '@shared/utils/signingSessionSeal';
import {
  finalizeRecoveredWalletCredentialV1,
  resolveCommittedRecoveryReplayV1,
  type WalletRecoveryFinalizationResult,
} from '../../../domains/passkeyCustody/walletRecoveryFinalization';
import type { PasskeyCustodyEnvelopeRecord } from '@shared/passkey-custody';
import {
  buildWebAuthnRecoveryContinuityAnchorRecord,
  type WebAuthnRecoveryRegistrationChallengeRecord,
  type WebAuthnRecoveryContinuityAnchorRecord,
} from '../webauthn/d1WebAuthnRecords';
import type {
  CloudflareD1WalletRecoveryGoogleEmailOtpService,
  WalletRecoveryGoogleEmailOtpFinalizationResult,
} from './d1WalletRecoveryGoogleEmailOtpService';
import {
  buildPreparedWalletRecoveryGoogleEmailOtpAttempt,
  walletRecoveryGoogleEmailOtpFinalizationInput,
  type WalletRecoveryGoogleEmailOtpFinalizationInput,
} from './d1WalletRecoveryGoogleEmailOtpRecords';
import type { EmailOtpEnrollmentMaterialBoundaryInput } from '../emailOtp/d1EmailOtpRecords';
import {
  rotateWalletRecoveryCodesV1,
  type WalletRecoveryRotationResult,
} from '../../../domains/passkeyCustody/walletRecoveryRotation';
import type {
  WalletRecoveryEnvelopeSetRecord,
  WalletRecoverySetRotationWireV1,
} from '@shared/wallet-recovery/walletRecoveryEnvelopeSet';
import { deriveRecoveryCodeLocatorV1FromBytes } from '@shared/wallet-recovery/recoveryCodeLocator';
import {
  buildWalletRecoveryBackupAcknowledgementV1,
  walletRecoveryBackupIsOutstanding,
} from '@shared/wallet-recovery/recoveryCodes';
import type { RecoveryCodeReservationId } from '@shared/wallet-recovery/recoveryCodeReservation';
import type {
  WalletRecoveryEcdsaPossessionChallengeV1,
  WalletRecoveryEcdsaPossessionProofV1,
} from '@shared/wallet-recovery/walletRecoveryEcdsaPossession';
import type { D1WalletStore } from '../../../../core/d1WalletStore';
import type { D1WalletAuthorityStore } from '../wallet/d1WalletAuthorityStore';
import type {
  ActiveWalletAuthorityV1,
  WalletAuthorityProvenanceV1,
} from '@shared/authorization/walletAuthority';
import type { WalletRecoveryTargetV1 } from '@shared/wallet-recovery/walletRecoveryTarget';
import {
  projectWalletUnlockKeyManifestV1,
  projectWalletRecoveryPreparationKeyManifestV1,
  resolveWalletRecoveryKeyManifestV1,
  verifyWalletRecoveryKeyActivationsV1,
  buildWalletRecoveryEcdsaPossessionChallengesV1,
  type PreparedEd25519RecoveryAdmissionV1,
  type WalletUnlockKeyManifestV1,
  type WalletRecoveryPreparationKeyManifestV1,
} from '../../../domains/passkeyCustody/walletRecoveryKeyManifest';

/**
 * The custody envelope layer's way into the router.
 *
 * Everything below this file — the store, the retrieval gate, the revocation
 * admission, the wire mapping — was written, tested, and unreachable: nothing
 * in the running server constructed a store, so cold unlock could not be
 * implemented end to end no matter how complete the pieces were. This is the
 * seam that makes them reachable.
 *
 * It is a *port*, like everything else in the service bag, not the store
 * itself. Routes get a method they can call; the store, the authenticator
 * store, and the logger stay behind it. A route holding a D1 store directly
 * would make every future custody route depend on the storage shape, and the
 * bag's whole point is that they do not.
 */

/**
 * What a browser may send. Deliberately *not*
 * `PasskeyCustodyEnvelopeRetrievalRequest`.
 *
 * That type carries `expectedChallenge`, `userId` and `rpId` — the values the
 * assertion is checked against. On a public route a caller that supplies both
 * the assertion and what it must match has proved nothing, so those three are
 * not accepted here: they come from the challenge record the server issued and
 * stores, named by an opaque id.
 */
export type PasskeyCustodyEnvelopeRetrievalWireRequest = {
  /** Wallet and verified passkey identify the envelope; the server resolves its opaque id. */
  readonly locator: {
    readonly walletId: PasskeyCustodyEnvelopeLocator['walletId'];
    readonly factor: Extract<WalletCustodyFactorRef, { readonly kind: 'passkey' }>;
  };
  /** Names the server-issued challenge; consumed once. */
  readonly challengeId: string;
  /**
   * The relying party's origin, taken from the request's `Origin` header.
   *
   * Frozen 2026-08-09 to the header with no body fallback. The sibling
   * WebAuthn service takes `expected_origin` from its caller because an app
   * server calls it; this route is browser-reachable, and there a value the
   * requester supplies is not evidence — it would let a caller name the
   * origin its own assertion is checked against.
   */
  readonly expectedOrigin: string;
  readonly webauthnAuthentication: PasskeyCustodyEnvelopeRetrievalRequest['webauthnAuthentication'];
};

/**
 * Refactor 109C: what became of a pre-109C envelope's ownership upgrade.
 *
 * `already_owned` is a success, not a near-miss. The upgrade runs on every
 * unlock until it lands, so the second unlock after a successful one finds the
 * work already done — reporting that as a conflict would turn the normal case
 * into an error the client has to special-case anyway.
 */
export type WalletCustodyEnvelopeOwnershipUpgradeResult =
  | { readonly kind: 'upgraded'; readonly envelopeRevision: number }
  | { readonly kind: 'already_owned' }
  | { readonly kind: 'not_found' }
  | { readonly kind: 'conflict'; readonly reason: string }
  | { readonly kind: 'refused'; readonly reason: string };

type WalletRecoveryRouteFinalizationResult =
  | {
      readonly kind: 'promoted';
      readonly storeVersion: string;
      readonly authority: ActiveWalletAuthorityV1;
      readonly authMethod: Extract<
        WalletAuthMethodRecordV2,
        { readonly kind: 'passkey'; readonly status: 'active' }
      >;
    }
  | Exclude<WalletRecoveryFinalizationResult, { readonly kind: 'promoted' }>;

export interface RouterApiPasskeyCustodyService {
  readVerifiedFactorCustody(request: {
    readonly walletId: WalletId;
    readonly factor: WalletCustodyFactorRef;
  }): Promise<
    | (Extract<PasskeyCustodyEnvelopeFactorLookupResult, { readonly kind: 'active' }> & {
        readonly keyManifest: WalletUnlockKeyManifestV1;
      })
    | Exclude<PasskeyCustodyEnvelopeFactorLookupResult, { readonly kind: 'active' }>
    | { readonly kind: 'manifest_unavailable'; readonly reason: string }
  >;
  /**
   * Fetch a wallet's custody envelope for a browser that has none locally.
   *
   * Returns the wire response rather than the domain result: the status a
   * failure earns is a decision, it is made once in the wire mapping, and a
   * second caller re-deciding it is how two clients come to disagree about
   * what "this credential no longer opens the wallet" means.
   */
  retrieveEnvelope(
    request: PasskeyCustodyEnvelopeRetrievalWireRequest,
  ): Promise<PasskeyCustodyEnvelopeRetrievalRouteResponse>;

  /**
   * Binds a pre-109C custody envelope to the auth method that just opened it.
   *
   * The ciphertext is the client's — the server never holds a factor secret and
   * cannot verify a reseal. What it can verify, and does, is that the submitted
   * envelope names the method the caller authenticated as, and that the row it
   * replaces is still the unbound one at the revision below it.
   */
  upgradeEnvelopeOwnership(request: {
    readonly walletId: WalletId;
    readonly walletAuthMethodId: WalletAuthMethodId;
    readonly envelope: PasskeyCustodyEnvelopeRecord;
  }): Promise<WalletCustodyEnvelopeOwnershipUpgradeResult>;

  listWalletCredentials(request: {
    readonly walletId: WalletId;
  }): Promise<readonly WalletCredentialActivityProjection[]>;

  renameWalletCredential(request: {
    readonly walletId: WalletId;
    readonly envelopeId: string;
    readonly label?: string;
  }): Promise<
    | { readonly kind: 'updated'; readonly projection: WalletCredentialActivityProjection }
    | { readonly kind: 'missing' }
    | { readonly kind: 'conflict' }
    | { readonly kind: 'invalid_label'; readonly reason: string }
    | { readonly kind: 'invalid_envelope_id' }
  >;

  /** Reserves one recovery code while the replacement Passkey is created. */
  prepareRecovery(request: {
    readonly target: WalletRecoveryTargetV1;
    readonly origin: string;
    readonly recoveryCodeBytes: Uint8Array;
    readonly reservationId: RecoveryCodeReservationId;
  }): Promise<WalletRecoveryRoutePreparationResult>;

  verifyGoogleRecovery(
    request: Parameters<CloudflareD1WalletRecoveryGoogleEmailOtpService['verifyGoogle']>[0],
  ): ReturnType<CloudflareD1WalletRecoveryGoogleEmailOtpService['verifyGoogle']>;

  verifyRecoveryEmailOtp(
    request: Parameters<CloudflareD1WalletRecoveryGoogleEmailOtpService['verifyOtp']>[0],
  ): ReturnType<CloudflareD1WalletRecoveryGoogleEmailOtpService['verifyOtp']>;

  releaseRecoveryEmailOtpFactor(
    request: Parameters<CloudflareD1WalletRecoveryGoogleEmailOtpService['releaseFactor']>[0],
  ): ReturnType<CloudflareD1WalletRecoveryGoogleEmailOtpService['releaseFactor']>;

  readPreparedEd25519RecoveryAdmission(request: {
    readonly challengeId: string;
    readonly nowMs: number;
  }): Promise<PreparedEd25519RecoveryAdmissionV1 | null>;

  /**
   * Installs the credential a recovery enrolled and retires the old ones.
   *
   * Called after activation, with an envelope the client sealed under the new
   * credential. The server cannot verify that sealing because it never has the
   * seed. It derives the exact wallet manifest and queries durable activation
   * receipts before this method can consume the reserved code.
   */
  finalizeRecovery(request: {
    readonly walletId: WalletId;
    readonly reservationId: RecoveryCodeReservationId;
    readonly recoveryOperationId: WalletRecoveryOperationId;
    readonly targetDeviceId: DeviceId;
    readonly targetAuthorityId: WalletAuthorityId;
    readonly targetWalletAuthMethodId: WalletAuthMethodId;
    readonly challengeId: string;
    readonly replacementId: string;
    readonly webauthnRegistration: unknown;
    readonly expectedOrigin: string;
    readonly replacementEnvelope: PasskeyCustodyEnvelopeRecord;
    readonly ecdsaMaterialPossessionProofs: readonly {
      readonly keySetId: string;
      readonly proof: WalletRecoveryEcdsaPossessionProofV1;
    }[];
  }): Promise<WalletRecoveryRouteFinalizationResult>;

  /**
   * Finalizes the Google/Email target from the server-retained OTP attempt.
   * The route never supplies recovery identity: the operation and reservation
   * select the verified attempt, while create material is the only enrollment
   * input a browser may add.
   */
  finalizeGoogleEmailOtpRecovery(
    request: WalletRecoveryGoogleEmailOtpRouteFinalizationRequest,
  ): Promise<WalletRecoveryGoogleEmailOtpFinalizationResult>;

  /**
   * Records that the owner confirmed saving their recovery codes.
   *
   * Cosmetic by design: nothing consults it to decide whether a recovery may
   * proceed. It exists so the product can stop asking, and it must never mean
   * more than that — a user who acknowledged without saving has no codes, and
   * one who never acknowledged still has working ones.
   */
  acknowledgeRecoveryBackup(request: {
    readonly walletId: string;
  }): Promise<{ kind: 'acknowledged'; issuedAtMs: number } | { kind: 'no_recovery_set' }>;

  /**
   * Replaces the wallet's recovery codes with a freshly wrapped set.
   *
   * The active factor opens the seed inside the custody worker and returns a
   * full replacement set. The server receives opaque wraps plus the freshly
   * sealed seed entry and CAS-replaces both the set and its backup ack.
   */
  rotateRecoveryCodes(request: {
    readonly walletId: string;
    readonly replacement: WalletRecoverySetRotationWireV1;
    readonly recoveryCodeLocators: readonly WalletRecoveryCodeLocatorRecord[];
    readonly expectedStoreVersion: string;
  }): Promise<WalletRecoveryRotationResult>;

  readRecoverySet(request: { readonly walletId: string }): Promise<
    | {
        readonly kind: 'ready';
        readonly record: WalletRecoveryEnvelopeSetRecord;
        readonly storeVersion: string;
      }
    | { readonly kind: 'no_recovery_set' }
  >;

  /**
   * How many codes remain and whether the owner has saved them.
   *
   * Counting is credential-gated. An unauthenticated caller learning how many
   * of ten codes are left gains an enumeration oracle; the wallet owner needs
   * the same count for the recovery settings screen.
   *
   * It returns counts, never identifiers: which codes remain is not something
   * even the owner's browser needs, and a list would be one leak away from
   * being useful to someone else.
   */
  readRecoveryStatus(request: { readonly walletId: string }): Promise<
    | {
        readonly kind: 'status';
        readonly activeCodeCount: number;
        readonly totalCodeCount: number;
        readonly issuedAtMs: number;
        readonly storeVersion: string;
        readonly backupOutstanding: boolean;
      }
    | { readonly kind: 'no_recovery_set' }
  >;
}

export type WalletRecoveryGoogleEmailOtpRouteFinalizationRequest = {
  readonly recoveryOperationId: WalletRecoveryOperationId;
  readonly reservationId: RecoveryCodeReservationId;
  readonly replacementEnvelope: PasskeyCustodyEnvelopeRecord;
  readonly ecdsaMaterialPossessionProofs: readonly {
    readonly keySetId: string;
    readonly proof: WalletRecoveryEcdsaPossessionProofV1;
  }[];
  /** Null is the existing-enrollment branch; the attempt supplies its IDs. */
  readonly emailOtpEnrollment: {
    readonly kind: 'create';
    readonly material: EmailOtpEnrollmentMaterialBoundaryInput;
  } | null;
};

/** How long a reservation may sit before another attempt may take the code. */
const RECOVERY_RESERVATION_TTL_MS = 5 * 60 * 1000;

type ActiveWalletAuthMethodRecordV2 = Extract<
  WalletAuthMethodRecordV2,
  { readonly status: 'active' }
>;

export type WalletRecoveryContinuityAnchor = {
  readonly kind: 'wallet_recovery_continuity_anchor_v1';
  readonly walletAuthMethodId: WalletAuthMethodId;
  readonly walletAuthorityId: WalletAuthorityId;
  readonly authorityDigestB64u: WalletAuthorityBindingDigest;
  readonly provenanceKind: WalletAuthorityProvenanceV1['kind'];
  readonly method: ActiveWalletAuthMethodRecordV2;
  readonly envelope: ActivePasskeyCustodyEnvelopeRecord;
};

type ActivePasskeyCustodyEnvelopeRecord = Omit<
  PasskeyCustodyEnvelopeRecord,
  'lifecycle'
> & {
  readonly lifecycle: Extract<PasskeyCustodyEnvelopeRecord['lifecycle'], { readonly state: 'active' }>;
};

export type WalletRecoveryAuthoritySelection = {
  readonly walletId: WalletId;
  readonly authorityId: WalletAuthorityId;
  readonly authorityDigestB64u: WalletAuthorityBindingDigest;
  readonly state: 'active';
  readonly provenanceKind: WalletAuthorityProvenanceV1['kind'];
};

/**
 * Finds the one existing custody path that can authenticate a recovery code.
 * The target's RP is deliberately absent: it describes the new credential,
 * while continuity belongs to an already enrolled method and its envelope.
 */
export function selectWalletRecoveryContinuityAnchor(input: {
  readonly walletId: WalletId;
  readonly targetFamily: 'passkey' | 'email_otp';
  readonly methods: readonly WalletAuthMethodRecordV2[];
  readonly envelopes: readonly PasskeyCustodyEnvelopeRecord[];
  readonly authorities: readonly WalletRecoveryAuthoritySelection[];
}): WalletRecoveryContinuityAnchor | undefined {
  const authoritiesById = new Map(
    input.authorities
      .filter(
        (authority) => authority.state === 'active' && authority.walletId === input.walletId,
      )
      .map((authority) => [String(authority.authorityId), authority]),
  );
  const candidates: WalletRecoveryContinuityAnchor[] = [];
  for (const method of input.methods) {
    if (method.status !== 'active' || method.walletId !== input.walletId) continue;
    const authority = authoritiesById.get(String(method.walletAuthorityId));
    if (!authority) continue;
    const activeEnvelopes = input.envelopes.filter(
      (envelope): envelope is ActivePasskeyCustodyEnvelopeRecord =>
        isActivePasskeyCustodyEnvelopeRecord(envelope) &&
        envelope.walletId === input.walletId &&
        envelope.binding.kind === 'wallet_custody_seed_v1' &&
        envelope.ownership.kind === 'method_bound' &&
        envelope.ownership.walletAuthMethodId === method.walletAuthMethodId &&
        envelopeFactorMatchesAuthMethod(envelope, method),
    );
    /* More than one live envelope for one method is an ambiguous custody
       state. Refuse to choose one by accident. */
    if (activeEnvelopes.length !== 1) continue;
    const [envelope] = activeEnvelopes;
    if (!envelope) continue;
    candidates.push({
      kind: 'wallet_recovery_continuity_anchor_v1',
      walletAuthMethodId: method.walletAuthMethodId,
      walletAuthorityId: method.walletAuthorityId,
      authorityDigestB64u: authority.authorityDigestB64u,
      provenanceKind: authority.provenanceKind,
      method,
      envelope,
    });
  }
  candidates.sort((left, right) => compareContinuityAnchors(left, right, input.targetFamily));
  return candidates[0];
}

function compareContinuityAnchors(
  left: WalletRecoveryContinuityAnchor,
  right: WalletRecoveryContinuityAnchor,
  targetFamily: 'passkey' | 'email_otp',
): number {
  const leftRegistration = left.provenanceKind === 'wallet_registration' ? 0 : 1;
  const rightRegistration = right.provenanceKind === 'wallet_registration' ? 0 : 1;
  if (leftRegistration !== rightRegistration) return leftRegistration - rightRegistration;
  const leftFamily = left.method.kind === targetFamily ? 0 : 1;
  const rightFamily = right.method.kind === targetFamily ? 0 : 1;
  if (leftFamily !== rightFamily) return leftFamily - rightFamily;
  if (left.method.createdAtMs !== right.method.createdAtMs) {
    return left.method.createdAtMs - right.method.createdAtMs;
  }
  const methodOrder = String(left.method.walletAuthMethodId).localeCompare(
    String(right.method.walletAuthMethodId),
  );
  if (methodOrder !== 0) return methodOrder;
  return String(left.envelope.envelopeId).localeCompare(String(right.envelope.envelopeId));
}

function envelopeFactorMatchesAuthMethod(
  envelope: PasskeyCustodyEnvelopeRecord,
  method: ActiveWalletAuthMethodRecordV2,
): boolean {
  if (method.kind === 'passkey') {
    return (
      envelope.factor.kind === 'passkey' &&
      envelope.factor.rpId === method.rpId &&
      envelope.factor.credentialIdB64u === method.credentialIdB64u
    );
  }
  return envelope.factor.kind === 'email_otp';
}

function isActivePasskeyCustodyEnvelopeRecord(
  envelope: PasskeyCustodyEnvelopeRecord,
): envelope is ActivePasskeyCustodyEnvelopeRecord {
  return envelope.lifecycle.state === 'active';
}

async function readWalletRecoveryAuthoritySelections(input: {
  readonly walletId: WalletId;
  readonly methods: readonly WalletAuthMethodRecordV2[];
  readonly walletAuthorityStore: Pick<D1WalletAuthorityStore, 'readById'>;
}): Promise<readonly WalletRecoveryAuthoritySelection[]> {
  const authorityIds = [
    ...new Set(
      input.methods
        .filter((method) => method.status === 'active' && method.walletId === input.walletId)
        .map((method) => method.walletAuthorityId),
    ),
  ];
  const authorities = await Promise.all(
    authorityIds.map((authorityId) => input.walletAuthorityStore.readById(authorityId)),
  );
  const selections: WalletRecoveryAuthoritySelection[] = [];
  for (const authority of authorities) {
    if (
      !authority ||
      authority.state !== 'active' ||
      authority.walletId !== input.walletId
    ) {
      continue;
    }
    const authorityDigestB64u = parseWalletAuthorityBindingDigest(
      String(authority.authorityDigestB64u),
    );
    if (!authorityDigestB64u.ok) continue;
    selections.push({
      walletId: authority.walletId,
      authorityId: authority.authorityId,
      authorityDigestB64u: authorityDigestB64u.value,
      state: 'active',
      provenanceKind: authority.provenance.kind,
    });
  }
  return selections;
}

export type WalletRecoveryRoutePreparationResult =
  | (Extract<WalletRecoveryPreparationResult, { readonly kind: 'prepared' }> & {
      readonly target: Extract<WalletRecoveryTargetV1, { readonly kind: 'passkey' }>;
      readonly recoveryOperationId: WalletRecoveryOperationId;
      readonly targetDeviceId: DeviceId;
      readonly targetAuthorityId: WalletAuthorityId;
      readonly targetWalletAuthMethodId: WalletAuthMethodId;
      readonly keyManifest: WalletRecoveryPreparationKeyManifestV1;
      readonly registration: WalletRecoveryRegistrationOptions;
    })
  | (Extract<WalletRecoveryPreparationResult, { readonly kind: 'prepared' }> & {
      readonly target: Extract<WalletRecoveryTargetV1, { readonly kind: 'google_email_otp' }>;
      readonly recoveryOperationId: WalletRecoveryOperationId;
      readonly targetDeviceId: DeviceId;
      readonly targetAuthorityId: WalletAuthorityId;
      readonly targetWalletAuthMethodId: WalletAuthMethodId;
      readonly keyManifest: WalletRecoveryPreparationKeyManifestV1;
      readonly registration?: never;
    })
  | Exclude<WalletRecoveryPreparationResult, { readonly kind: 'prepared' }>
  | { readonly kind: 'manifest_unavailable'; readonly reason: string }
  | { readonly kind: 'registration_unavailable'; readonly reason: string };

export type WalletRecoveryRegistrationOptions = {
  readonly kind: 'webauthn_recovery_registration_v1';
  readonly challengeId: string;
  readonly challengeB64u: string;
  readonly replacementId: string;
  readonly walletAuthMethodId: WalletAuthMethodId;
  readonly rpId: string;
  readonly user: {
    readonly idB64u: string;
    readonly name: string;
    readonly displayName: string;
  };
  readonly pubKeyCredParams: readonly [
    { readonly type: 'public-key'; readonly alg: -7 },
    { readonly type: 'public-key'; readonly alg: -257 },
  ];
  readonly authenticatorSelection: {
    readonly residentKey: 'required';
    readonly userVerification: 'preferred';
  };
  readonly timeoutMs: number;
  readonly attestation: 'none';
  readonly extensions: {
    readonly prf: {
      readonly eval: {
        readonly firstB64u: string;
        readonly secondB64u: string;
      };
    };
  };
  readonly excludeCredentials: readonly {
    readonly type: 'public-key';
    readonly id: string;
  }[];
};

type RecoveryTargetIdentity = {
  readonly recoveryOperationId: WalletRecoveryOperationId;
  readonly targetDeviceId: DeviceId;
  readonly targetAuthorityId: WalletAuthorityId;
  readonly targetWalletAuthMethodId: WalletAuthMethodId;
};

function allocateRecoveryTargetIdentity(): RecoveryTargetIdentity | null {
  const recoveryOperationId = parseWalletRecoveryOperationId(
    `wallet-recovery-operation:${secureRandomBase64Url(24, 'wallet recovery operation id')}`,
  );
  const targetDeviceId = parseDeviceId(
    `device:${secureRandomBase64Url(24, 'wallet recovery device id')}`,
  );
  const targetAuthorityId = parseWalletAuthorityId(
    `wallet-authority:${secureRandomBase64Url(24, 'wallet recovery authority id')}`,
  );
  const targetWalletAuthMethodId = parseWalletAuthMethodId(
    `wallet-auth-method:${secureRandomBase64Url(24, 'wallet recovery auth method id')}`,
  );
  if (
    !recoveryOperationId.ok ||
    !targetDeviceId.ok ||
    !targetAuthorityId.ok ||
    !targetWalletAuthMethodId.ok
  ) {
    return null;
  }
  return {
    recoveryOperationId: recoveryOperationId.value,
    targetDeviceId: targetDeviceId.value,
    targetAuthorityId: targetAuthorityId.value,
    targetWalletAuthMethodId: targetWalletAuthMethodId.value,
  };
}

function nowMsForAssembly(input: { readonly nowMs?: () => number }): number {
  return (input.nowMs ?? Date.now)();
}

function isOriginWithinRpId(origin: string, rpId: WebAuthnRpId): boolean {
  return isHostWithinRpId(originHostnameOrEmpty(origin), rpId);
}

async function walletRecoveryKeyManifestDigest(
  manifest: Parameters<typeof projectWalletRecoveryPreparationKeyManifestV1>[0],
): Promise<DigestB64u> {
  return parseDigestB64u(base64UrlEncode(await sha256BytesUtf8(alphabetizeStringify(manifest))));
}

async function unavailableWalletRecoveryGoogleVerify(
  _request: Parameters<CloudflareD1WalletRecoveryGoogleEmailOtpService['verifyGoogle']>[0],
) {
  return {
    ok: false as const,
    code: 'not_configured',
    message: 'Google Email OTP recovery is not configured',
  };
}

async function unavailableWalletRecoveryEmailOtpVerify(
  _request: Parameters<CloudflareD1WalletRecoveryGoogleEmailOtpService['verifyOtp']>[0],
) {
  return {
    ok: false as const,
    code: 'not_configured',
    message: 'Google Email OTP recovery is not configured',
  };
}

async function unavailableWalletRecoveryEmailOtpRelease(
  _request: Parameters<CloudflareD1WalletRecoveryGoogleEmailOtpService['releaseFactor']>[0],
) {
  return {
    ok: false as const,
    code: 'not_configured',
    message: 'Google Email OTP recovery is not configured',
  };
}

export function createD1PasskeyCustodyRouteService(assembly: {
  readonly orgId: string;
  readonly passkeyCustodyEnvelopes: CloudflareD1PasskeyCustodyEnvelopeStore;
  readonly walletCustodyCommits: CloudflareD1WalletCustodyCommitStore;
  readonly walletStore: D1WalletStore;
  readonly walletAuthorityStore: Pick<D1WalletAuthorityStore, 'readById'>;
  readonly webAuthnStore: CloudflareD1WebAuthnStore;
  readonly googleRecovery?: CloudflareD1WalletRecoveryGoogleEmailOtpService;
  readonly emailOtpRegistrationEnrollmentFinalizer?: Parameters<
    CloudflareD1WalletRecoveryGoogleEmailOtpService['finalizeRecovery']
  >[0]['dependencies']['enrollmentFinalizer'];
  readonly logger: NormalizedLogger;
  /** Injected so the reservation window is testable without waiting. */
  readonly nowMs?: () => number;
}): RouterApiPasskeyCustodyService {
  const authenticatorStore = authenticatorStoreView(assembly.webAuthnStore);
  const googleRecovery = assembly.googleRecovery;
  return {
    readVerifiedFactorCustody: async (request) => {
      const envelope = await assembly.passkeyCustodyEnvelopes.lookupEnvelopeForFactor(request);
      if (envelope.kind !== 'active') return envelope;
      try {
        const manifest = await resolveWalletRecoveryKeyManifestV1({
          registry: assembly.walletStore,
          walletId: request.walletId,
        });
        if (request.factor.kind === 'passkey') {
          await assembly.passkeyCustodyEnvelopes
            .recordWalletCredentialUse({
              walletId: request.walletId,
              envelopeId: envelope.envelope.envelopeId,
              usedAtMs: (assembly.nowMs ?? Date.now)(),
            })
            .catch(() => undefined);
        }
        return {
          ...envelope,
          keyManifest: projectWalletUnlockKeyManifestV1(manifest),
        };
      } catch (error: unknown) {
        return {
          kind: 'manifest_unavailable',
          reason:
            error instanceof Error ? error.message : 'wallet custody key manifest is unavailable',
        };
      }
    },
    listWalletCredentials: async (request) =>
      await assembly.passkeyCustodyEnvelopes.listWalletCredentialActivity(request.walletId),

    renameWalletCredential: async (request) => {
      const envelopeId = parsePasskeyEnvelopeId(request.envelopeId);
      if (!envelopeId.ok) return { kind: 'invalid_envelope_id' };
      const label = request.label === undefined ? undefined : String(request.label);
      return await assembly.passkeyCustodyEnvelopes.renameWalletCredential({
        walletId: request.walletId,
        envelopeId: envelopeId.value,
        ...(label === undefined ? {} : { label }),
        nowMs: (assembly.nowMs ?? Date.now)(),
      });
    },
    upgradeEnvelopeOwnership: async (request) => {
      const submitted = request.envelope;
      if (String(submitted.walletId) !== String(request.walletId)) {
        return { kind: 'refused', reason: 'the custody envelope belongs to a different wallet' };
      }
      /* The authorization, stated once: the envelope must name the method the
         caller proved. Everything below is a precondition on the row being
         replaced, not on who may replace it. */
      if (
        submitted.ownership.kind !== 'method_bound' ||
        String(submitted.ownership.walletAuthMethodId) !== String(request.walletAuthMethodId)
      ) {
        return {
          kind: 'refused',
          reason: 'an upgraded custody envelope must name the authenticated auth method',
        };
      }
      const submittedRevision = Number(submitted.envelopeRevision);
      const lookup = await assembly.passkeyCustodyEnvelopes.lookupEnvelope({
        walletId: request.walletId,
        factor: envelopeFactorRef(submitted),
        envelopeId: submitted.envelopeId,
      });
      if (lookup.kind === 'missing') return { kind: 'not_found' };
      if (lookup.kind !== 'active') {
        return { kind: 'refused', reason: `the custody envelope is ${lookup.kind}` };
      }
      const stored = lookup.envelope;
      if (stored.ownership.kind === 'method_bound') {
        /* Already bound. Same method means the upgrade landed on an earlier
           attempt; a different one means this caller never owned it. */
        return String(stored.ownership.walletAuthMethodId) === String(request.walletAuthMethodId)
          ? { kind: 'already_owned' }
          : {
              kind: 'refused',
              reason: 'the custody envelope is owned by a different auth method',
            };
      }
      if (Number(stored.envelopeRevision) !== submittedRevision - 1) {
        return {
          kind: 'conflict',
          reason: 'the custody envelope moved before the upgrade could be stored',
        };
      }
      const rewrapped = await assembly.passkeyCustodyEnvelopes.rewrapEnvelope(submitted, {
        envelopeId: stored.envelopeId,
        envelopeRevision: Number(stored.envelopeRevision),
        ownership: stored.ownership,
      });
      switch (rewrapped.kind) {
        case 'stored':
          return { kind: 'upgraded', envelopeRevision: rewrapped.envelopeRevision };
        case 'not_found':
          return { kind: 'not_found' };
        case 'ownership_conflict':
          return { kind: 'refused', reason: rewrapped.reason };
        case 'terminal_lifecycle':
          return { kind: 'refused', reason: 'the custody envelope is revoked' };
        case 'revision_conflict':
        case 'version_mismatch':
          return {
            kind: 'conflict',
            reason: 'the custody envelope moved before the upgrade could be stored',
          };
      }
    },
    retrieveEnvelope: async (request) => {
      const challengeId = String(request.challengeId || '').trim();
      const expectedOrigin = String(request.expectedOrigin || '').trim();
      if (!challengeId || !expectedOrigin) {
        return {
          status: 400,
          body: {
            ok: false,
            code: 'challenge_required',
            message: 'custody retrieval needs a server-issued challenge and an origin',
          },
        };
      }

      /* Consumed, not read: a challenge that could be replayed would let one
         captured assertion fetch the envelope repeatedly. */
      const challenge = await assembly.webAuthnStore.consumeLoginChallenge(challengeId);
      if (!challenge) {
        return {
          status: 401,
          body: {
            ok: false,
            code: 'challenge_unknown',
            message: 'the challenge is unknown, expired, or already used',
          },
        };
      }

      const projections = await assembly.passkeyCustodyEnvelopes.listWalletCredentialActivity(
        request.locator.walletId,
      );
      const requestedFactor = request.locator.factor;
      const matchingProjections = projections.filter((entry) => {
        const factor = entry.index.factor;
        return (
          factor.kind === 'passkey' &&
          requestedFactor.kind === 'passkey' &&
          String(factor.rpId) === String(requestedFactor.rpId) &&
          String(factor.credentialIdB64u) === String(requestedFactor.credentialIdB64u)
        );
      });
      const projection =
        matchingProjections.find((entry) => entry.index.lifecycle.state === 'active') ??
        matchingProjections[0];
      if (!projection || projection.index.factor.kind !== 'passkey') {
        return {
          status: 404,
          body: {
            ok: false,
            code: 'envelope_missing',
            message: 'no custody envelope for this wallet and credential',
          },
        };
      }
      const locator: PasskeyCustodyEnvelopeRetrievalRequest['locator'] = {
        walletId: request.locator.walletId,
        envelopeId: projection.index.envelopeId,
        factor: {
          kind: 'passkey',
          rpId: projection.index.factor.rpId,
          credentialIdB64u: projection.index.factor.credentialIdB64u,
        },
      };
      const response = await handlePasskeyCustodyEnvelopeRetrieval({
        request: {
          locator,
          /* From the issued challenge, never the request body. This is what
             makes the assertion evidence: the browser cannot choose the
             user, the relying party, or the bytes it signs over. */
          rpId: challenge.rpId as PasskeyCustodyEnvelopeRetrievalRequest['rpId'],
          userId: challenge.userId,
          expectedChallenge: challenge.challengeB64u,
          expectedOrigin,
          webauthnAuthentication: request.webauthnAuthentication,
        },
        envelopeStore: assembly.passkeyCustodyEnvelopes,
        authenticatorStore,
        logger: assembly.logger,
      });
      if (response.status === 200 && request.locator.factor.kind === 'passkey') {
        await assembly.passkeyCustodyEnvelopes
          .recordWalletCredentialUse({
            walletId: request.locator.walletId,
            envelopeId: locator.envelopeId,
            usedAtMs: (assembly.nowMs ?? Date.now)(),
          })
          .catch(() => undefined);
      }
      return response;
    },

    prepareRecovery: prepareRecoveryForRoute.bind(undefined, assembly),
    verifyGoogleRecovery: googleRecovery
      ? googleRecovery.verifyGoogle.bind(googleRecovery)
      : unavailableWalletRecoveryGoogleVerify,
    verifyRecoveryEmailOtp: googleRecovery
      ? googleRecovery.verifyOtp.bind(googleRecovery)
      : unavailableWalletRecoveryEmailOtpVerify,
    releaseRecoveryEmailOtpFactor: googleRecovery
      ? googleRecovery.releaseFactor.bind(googleRecovery)
      : unavailableWalletRecoveryEmailOtpRelease,
    readPreparedEd25519RecoveryAdmission: readPreparedEd25519RecoveryAdmission.bind(
      undefined,
      assembly,
    ),

    finalizeRecovery: finalizeRecoveryForRoute.bind(undefined, assembly),
    finalizeGoogleEmailOtpRecovery: finalizeGoogleEmailOtpRecoveryForRoute.bind(undefined, assembly),

    acknowledgeRecoveryBackup: async (request) => {
      const stored = await assembly.walletCustodyCommits.readRecoveryEnvelopeSet(
        requireWalletId(request.walletId),
      );
      /* The acknowledgement names the issuance it covers, so there has to be
         one. Acknowledging nothing would write a row that silences the prompt
         for codes that were never issued. */
      if (!stored) return { kind: 'no_recovery_set' };

      const issuedAtMs = Number(stored.record.issuedAtMs);
      await assembly.walletCustodyCommits.writeBackupAcknowledgement(
        buildWalletRecoveryBackupAcknowledgementV1({
          walletId: request.walletId,
          issuedAtMs,
          acknowledgedAtMs: (assembly.nowMs ?? Date.now)(),
        }),
      );
      return { kind: 'acknowledged', issuedAtMs };
    },

    readRecoveryStatus: async (request) => {
      const stored = await assembly.walletCustodyCommits.readRecoveryEnvelopeSet(
        requireWalletId(request.walletId),
      );
      if (!stored) return { kind: 'no_recovery_set' };

      const acknowledgement = await assembly.walletCustodyCommits.readBackupAcknowledgement(
        requireWalletId(request.walletId),
      );
      const issuedAtMs = Number(stored.record.issuedAtMs);
      return {
        kind: 'status',
        activeCodeCount: stored.record.manifestKekWraps.filter(
          (wrap) => wrap.lifecycle.state === 'active',
        ).length,
        /* Both counts, because "3 left" means something different out of ten
           than out of three, and a rotation changes which one the user is
           looking at. */
        totalCodeCount: stored.record.manifestKekWraps.length,
        issuedAtMs,
        storeVersion: stored.storeVersion,
        backupOutstanding: walletRecoveryBackupIsOutstanding({
          setIssuedAtMs: issuedAtMs,
          acknowledgement,
        }),
      };
    },

    rotateRecoveryCodes: (request) =>
      rotateWalletRecoveryCodesV1({
        store: assembly.walletCustodyCommits,
        walletId: requireWalletId(request.walletId),
        replacement: request.replacement,
        recoveryCodeLocators: request.recoveryCodeLocators,
        expectedStoreVersion: request.expectedStoreVersion,
        nowMs: (assembly.nowMs ?? Date.now)(),
      }),
    readRecoverySet: async (request) => {
      const stored = await assembly.walletCustodyCommits.readRecoveryEnvelopeSet(
        requireWalletId(request.walletId),
      );
      return stored
        ? { kind: 'ready', record: stored.record, storeVersion: stored.storeVersion }
        : { kind: 'no_recovery_set' };
    },
  };
}

async function readPreparedEd25519RecoveryAdmission(
  assembly: {
    readonly orgId: string;
    readonly walletCustodyCommits: CloudflareD1WalletCustodyCommitStore;
    readonly walletStore: D1WalletStore;
    readonly webAuthnStore: CloudflareD1WebAuthnStore;
    readonly googleRecovery?: CloudflareD1WalletRecoveryGoogleEmailOtpService;
  },
  request: {
    readonly challengeId: string;
    readonly nowMs: number;
  },
): Promise<PreparedEd25519RecoveryAdmissionV1 | null> {
  const challenge = await assembly.webAuthnStore.readRecoveryRegistrationChallenge(
    request.challengeId,
    request.nowMs,
  );
  if (challenge) {
    const storedRecoverySet = await assembly.walletCustodyCommits.readRecoveryEnvelopeSet(
      challenge.walletId,
    );
    const hasActiveReservation = storedRecoverySet?.record.manifestKekWraps.some(
      (wrap) =>
        wrap.lifecycle.state === 'reserved' &&
        wrap.lifecycle.reservationId === challenge.reservationId &&
        wrap.lifecycle.reservationExpiresAtMs > request.nowMs,
    );
    if (!hasActiveReservation) return null;
    const manifest = await resolveWalletRecoveryKeyManifestV1({
      registry: assembly.walletStore,
      walletId: challenge.walletId,
    });
    return {
      kind: 'prepared_ed25519_recovery_admission_v1',
      walletId: challenge.walletId,
      reservationId: challenge.reservationId,
      entries: manifest.entries.filter(
        (
          entry,
        ): entry is Extract<(typeof manifest.entries)[number], { readonly kind: 'near_ed25519' }> =>
          entry.kind === 'near_ed25519',
      ),
    };
  }

  const recoveryOperationId = parseWalletRecoveryOperationId(request.challengeId);
  if (!recoveryOperationId.ok || !assembly.googleRecovery) return null;
  const storedAttempt = await assembly.googleRecovery.readAttempt(recoveryOperationId.value);
  if (storedAttempt.kind !== 'present') return null;
  const attempt = storedAttempt.value;
  if (
    attempt.state !== 'otp_verified' ||
    attempt.orgId !== assembly.orgId ||
    attempt.recoveryOperationId !== recoveryOperationId.value ||
    attempt.expiresAtMs <= request.nowMs
  ) {
    return null;
  }
  const storedRecoverySet = await assembly.walletCustodyCommits.readRecoveryEnvelopeSet(
    attempt.walletId,
  );
  const hasActiveReservation = storedRecoverySet?.record.manifestKekWraps.some(
    (wrap) =>
      wrap.lifecycle.state === 'reserved' &&
      wrap.lifecycle.reservationId === attempt.reservationId &&
      wrap.lifecycle.reservationExpiresAtMs > request.nowMs,
  );
  if (!hasActiveReservation) return null;
  const manifest = await resolveWalletRecoveryKeyManifestV1({
    registry: assembly.walletStore,
    walletId: attempt.walletId,
  });
  return {
    kind: 'prepared_ed25519_recovery_admission_v1',
    walletId: attempt.walletId,
    reservationId: attempt.reservationId,
    entries: manifest.entries.filter(
      (
        entry,
      ): entry is Extract<(typeof manifest.entries)[number], { readonly kind: 'near_ed25519' }> =>
        entry.kind === 'near_ed25519',
    ),
  };
}

async function prepareRecoveryForRoute(
  assembly: {
    readonly orgId: string;
    readonly passkeyCustodyEnvelopes: CloudflareD1PasskeyCustodyEnvelopeStore;
    readonly walletCustodyCommits: CloudflareD1WalletCustodyCommitStore;
    readonly walletStore: D1WalletStore;
    readonly walletAuthorityStore: Pick<D1WalletAuthorityStore, 'readById'>;
    readonly webAuthnStore: CloudflareD1WebAuthnStore;
    readonly googleRecovery?: CloudflareD1WalletRecoveryGoogleEmailOtpService;
    readonly nowMs?: () => number;
  },
  request: {
    readonly target: WalletRecoveryTargetV1;
    readonly origin: string;
    readonly recoveryCodeBytes: Uint8Array;
    readonly reservationId: RecoveryCodeReservationId;
  },
): Promise<WalletRecoveryRoutePreparationResult> {
  const origin = request.origin.trim();
  if (!origin) return { kind: 'refused', reason: 'that recovery code cannot be used' };
  let passkeyRpId: WebAuthnRpId | null = null;
  if (request.target.kind === 'passkey') {
    const parsedRpId = parseWebAuthnRpId(request.target.rpId);
    if (!parsedRpId.ok || !isOriginWithinRpId(origin, parsedRpId.value)) {
      return { kind: 'refused', reason: 'that recovery code cannot be used' };
    }
    passkeyRpId = parsedRpId.value;
  }
  let locator: Awaited<ReturnType<typeof deriveRecoveryCodeLocatorV1FromBytes>>;
  try {
    locator = await deriveRecoveryCodeLocatorV1FromBytes(request.recoveryCodeBytes);
  } catch {
    return { kind: 'refused', reason: 'that recovery code cannot be used' };
  }
  const located = await assembly.walletCustodyCommits.readRecoveryCodeLocator(locator);
  if (!located) return { kind: 'refused', reason: 'that recovery code cannot be used' };
  const walletId = located.walletId;
  const methods = await assembly.walletCustodyCommits.listWalletAuthMethods(walletId);
  const envelopes = await assembly.passkeyCustodyEnvelopes.listWalletEnvelopes(walletId);
  const authorities = await readWalletRecoveryAuthoritySelections({
    walletId,
    methods,
    walletAuthorityStore: assembly.walletAuthorityStore,
  });
  const continuityAnchor = selectWalletRecoveryContinuityAnchor({
    walletId,
    targetFamily: request.target.kind === 'passkey' ? 'passkey' : 'email_otp',
    methods,
    envelopes,
    authorities,
  });
  if (!continuityAnchor) {
    return { kind: 'refused', reason: 'that recovery code cannot be used' };
  }
  const targetIdentity = allocateRecoveryTargetIdentity();
  if (!targetIdentity) {
    return {
      kind: 'registration_unavailable',
      reason: 'wallet recovery target identity allocation failed',
    };
  }
  const prepared = await prepareWalletRecoveryWithCodeV1({
    store: assembly.walletCustodyCommits,
    walletId,
    expectedRecoveryKeyId: located.recoveryKeyId,
    recoveryCodeBytes: request.recoveryCodeBytes,
    reservationId: request.reservationId,
    nowMs: (assembly.nowMs ?? Date.now)(),
    reservationTtlMs: RECOVERY_RESERVATION_TTL_MS,
  });
  if (prepared.kind !== 'prepared') return prepared;
  try {
    const manifest = await resolveWalletRecoveryKeyManifestV1({
      registry: assembly.walletStore,
      walletId,
    });
    const continuityAnchorRecord = buildWebAuthnRecoveryContinuityAnchorRecord(continuityAnchor);
    const keyManifestDigestB64u = await walletRecoveryKeyManifestDigest(manifest);
    const keyManifest = projectWalletRecoveryPreparationKeyManifestV1(
      manifest,
      await buildEcdsaPossessionChallenges({
        manifest,
        walletId,
        reservationId: request.reservationId,
        replacementId: String(targetIdentity.recoveryOperationId),
        sourceAuthorityDigestB64u: continuityAnchor.authorityDigestB64u,
        challengeB64u: String(targetIdentity.recoveryOperationId),
        expiresAtMs: prepared.reservationExpiresAtMs,
      }),
    );
    if (request.target.kind === 'google_email_otp') {
      if (!assembly.googleRecovery) {
        return {
          kind: 'registration_unavailable',
          reason: 'Google Email OTP recovery is not configured',
        };
      }
      const persisted = await assembly.googleRecovery.persistPrepared({
        attempt: buildPreparedWalletRecoveryGoogleEmailOtpAttempt({
          walletId,
          orgId: assembly.orgId,
          reservationId: request.reservationId,
          recoveryOperationId: targetIdentity.recoveryOperationId,
          targetDeviceId: targetIdentity.targetDeviceId,
          targetAuthorityId: targetIdentity.targetAuthorityId,
          targetWalletAuthMethodId: targetIdentity.targetWalletAuthMethodId,
          continuityAnchor: continuityAnchorRecord,
          recoverySetVersion: prepared.storeVersion,
          keyManifestDigestB64u,
          createdAtMs: nowMsForAssembly(assembly),
          expiresAtMs: prepared.reservationExpiresAtMs,
        }),
      });
      if (persisted.kind === 'conflict') return { kind: 'conflict' };
      return {
        ...prepared,
        target: request.target,
        recoveryOperationId: targetIdentity.recoveryOperationId,
        targetDeviceId: targetIdentity.targetDeviceId,
        targetAuthorityId: targetIdentity.targetAuthorityId,
        targetWalletAuthMethodId: targetIdentity.targetWalletAuthMethodId,
        keyManifest,
      };
    }
    if (!passkeyRpId) {
      return { kind: 'registration_unavailable', reason: 'Passkey recovery rpId is unavailable' };
    }
    const registration = await createWalletRecoveryRegistrationOptions({
      webAuthnStore: assembly.webAuthnStore,
      walletId,
      reservationId: request.reservationId,
      recoveryOperationId: targetIdentity.recoveryOperationId,
      targetDeviceId: targetIdentity.targetDeviceId,
      targetAuthorityId: targetIdentity.targetAuthorityId,
      targetWalletAuthMethodId: targetIdentity.targetWalletAuthMethodId,
      origin,
      rpId: passkeyRpId,
      continuityAnchor,
      expiresAtMs: prepared.reservationExpiresAtMs,
      nowMs: nowMsForAssembly(assembly),
    });
    if (registration.kind !== 'ready') {
      return { kind: 'registration_unavailable', reason: registration.reason };
    }
    const possessionChallenges = await buildEcdsaPossessionChallenges({
      manifest,
      walletId,
      reservationId: request.reservationId,
      replacementId: registration.options.replacementId,
      sourceAuthorityDigestB64u: continuityAnchor.authorityDigestB64u,
      challengeB64u: registration.options.challengeB64u,
      expiresAtMs: prepared.reservationExpiresAtMs,
    });
    return {
      ...prepared,
      target: request.target,
      recoveryOperationId: targetIdentity.recoveryOperationId,
      targetDeviceId: targetIdentity.targetDeviceId,
      targetAuthorityId: targetIdentity.targetAuthorityId,
      targetWalletAuthMethodId: targetIdentity.targetWalletAuthMethodId,
      keyManifest: projectWalletRecoveryPreparationKeyManifestV1(manifest, possessionChallenges),
      registration: registration.options,
    };
  } catch (error: unknown) {
    return {
      kind: 'manifest_unavailable',
      reason:
        error instanceof Error ? error.message : 'wallet recovery key manifest is unavailable',
    };
  }
}

export async function createWalletRecoveryRegistrationOptions(input: {
  readonly webAuthnStore: Pick<CloudflareD1WebAuthnStore, 'writeChallenge' | 'readBindingRows'>;
  readonly walletId: WalletId;
  readonly reservationId: RecoveryCodeReservationId;
  readonly recoveryOperationId: WalletRecoveryOperationId;
  readonly targetDeviceId: DeviceId;
  readonly targetAuthorityId: WalletAuthorityId;
  readonly targetWalletAuthMethodId: WalletAuthMethodId;
  readonly origin: string;
  readonly rpId: WebAuthnRpId;
  readonly continuityAnchor: WalletRecoveryContinuityAnchor;
  readonly expiresAtMs: number;
  readonly nowMs: number;
}): Promise<
  | { readonly kind: 'ready'; readonly options: WalletRecoveryRegistrationOptions }
  | { readonly kind: 'unavailable'; readonly reason: string }
> {
  const challengeId = secureRandomBase64Url(16, 'wallet recovery registration challenge id');
  const challengeB64u = secureRandomBase64Url(32, 'wallet recovery registration challenge');
  const replacementId = `wallet-recovery-replacement:${secureRandomBase64Url(
    18,
    'wallet recovery replacement id',
  )}`;
  const record: WebAuthnRecoveryRegistrationChallengeRecord = {
    version: 'webauthn_recovery_registration_challenge_v2',
    challengeId,
    walletId: input.walletId,
    reservationId: input.reservationId,
    recoveryOperationId: input.recoveryOperationId,
    targetDeviceId: input.targetDeviceId,
    targetAuthorityId: input.targetAuthorityId,
    targetWalletAuthMethodId: input.targetWalletAuthMethodId,
    origin: input.origin,
    rpId: input.rpId,
    replacementId,
    challengeB64u,
    continuityAnchor: buildWebAuthnRecoveryContinuityAnchorRecord(input.continuityAnchor),
    createdAtMs: input.nowMs,
    expiresAtMs: input.expiresAtMs,
  };
  await input.webAuthnStore.writeChallenge({
    challengeId,
    challengeKind: 'recovery_registration',
    record,
    createdAtMs: input.nowMs,
    expiresAtMs: input.expiresAtMs,
  });
  const bindings = await input.webAuthnStore.readBindingRows({
    userId: String(input.walletId),
    rpId: input.rpId,
  });
  const excludeCredentials = bindings
    .filter((binding) => String(binding.rpId) === String(input.rpId))
    .map((binding) => ({
      type: 'public-key' as const,
      id: String(binding.credentialIdB64u),
    }));
  return {
    kind: 'ready',
    options: {
      kind: 'webauthn_recovery_registration_v1',
      challengeId,
      challengeB64u,
      replacementId,
      walletAuthMethodId: input.targetWalletAuthMethodId,
      rpId: input.rpId,
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
      excludeCredentials,
    },
  };
}

async function finalizeRecoveryForRoute(
  assembly: {
    readonly passkeyCustodyEnvelopes: CloudflareD1PasskeyCustodyEnvelopeStore;
    readonly walletCustodyCommits: CloudflareD1WalletCustodyCommitStore;
    readonly walletStore: D1WalletStore;
    readonly walletAuthorityStore: Pick<D1WalletAuthorityStore, 'readById'>;
    readonly webAuthnStore: CloudflareD1WebAuthnStore;
    readonly nowMs?: () => number;
  },
  request: {
    readonly walletId: WalletId;
    readonly reservationId: RecoveryCodeReservationId;
    readonly recoveryOperationId: WalletRecoveryOperationId;
    readonly targetDeviceId: DeviceId;
    readonly targetAuthorityId: WalletAuthorityId;
    readonly targetWalletAuthMethodId: WalletAuthMethodId;
    readonly challengeId: string;
    readonly replacementId: string;
    readonly webauthnRegistration: unknown;
    readonly expectedOrigin: string;
    readonly replacementEnvelope: PasskeyCustodyEnvelopeRecord;
    readonly ecdsaMaterialPossessionProofs: readonly {
      readonly keySetId: string;
      readonly proof: WalletRecoveryEcdsaPossessionProofV1;
    }[];
  },
): Promise<WalletRecoveryRouteFinalizationResult> {
  const result = await finalizeRecoveredWalletCredentialV1({
    envelopeStore: assembly.passkeyCustodyEnvelopes,
    walletCustodyCommits: assembly.walletCustodyCommits,
    walletAuthorityStore: assembly.walletAuthorityStore,
    walletId: request.walletId,
    reservationId: request.reservationId,
    recoveryOperationId: request.recoveryOperationId,
    targetDeviceId: request.targetDeviceId,
    targetAuthorityId: request.targetAuthorityId,
    targetWalletAuthMethodId: request.targetWalletAuthMethodId,
    challengeId: request.challengeId,
    replacementId: request.replacementId,
    webauthnRegistration: request.webauthnRegistration,
    expectedOrigin: request.expectedOrigin,
    webAuthnStore: assembly.webAuthnStore,
    walletStore: assembly.walletStore,
    replacementEnvelope: request.replacementEnvelope,
    ecdsaMaterialPossessionProofs: request.ecdsaMaterialPossessionProofs,
    nowMs: (assembly.nowMs ?? Date.now)(),
  });
  if (result.kind !== 'promoted') return result;
  const [authority, authMethod] = await Promise.all([
    assembly.walletAuthorityStore.readById(result.walletAuthorityId),
    assembly.walletCustodyCommits.readWalletAuthMethodById(result.walletAuthMethodId),
  ]);
  if (
    !authority ||
    authority.state !== 'active' ||
    authority.walletId !== request.walletId ||
    !authMethod ||
    authMethod.kind !== 'passkey' ||
    authMethod.status !== 'active' ||
    authMethod.walletId !== request.walletId ||
    authMethod.walletAuthorityId !== authority.authorityId ||
    authMethod.credentialIdB64u !== result.credential.credentialIdB64u ||
    authMethod.credentialPublicKeyB64u !== result.credential.credentialPublicKeyB64u ||
    authMethod.counter !== result.credential.counter
  ) {
    throw new Error('recovery promotion authority projection is unavailable');
  }
  return {
    kind: 'promoted',
    storeVersion: result.storeVersion,
    authority,
    authMethod,
  };
}

async function finalizeGoogleEmailOtpRecoveryForRoute(
  assembly: {
    readonly orgId: string;
    readonly passkeyCustodyEnvelopes: CloudflareD1PasskeyCustodyEnvelopeStore;
    readonly walletCustodyCommits: CloudflareD1WalletCustodyCommitStore;
    readonly walletStore: D1WalletStore;
    readonly walletAuthorityStore: Pick<D1WalletAuthorityStore, 'readById'>;
    readonly googleRecovery?: CloudflareD1WalletRecoveryGoogleEmailOtpService;
    readonly emailOtpRegistrationEnrollmentFinalizer?: Parameters<
      CloudflareD1WalletRecoveryGoogleEmailOtpService['finalizeRecovery']
    >[0]['dependencies']['enrollmentFinalizer'];
  },
  request: WalletRecoveryGoogleEmailOtpRouteFinalizationRequest,
): Promise<WalletRecoveryGoogleEmailOtpFinalizationResult> {
  const googleRecovery = assembly.googleRecovery;
  const enrollmentFinalizer = assembly.emailOtpRegistrationEnrollmentFinalizer;
  if (!googleRecovery || !enrollmentFinalizer) {
    return { kind: 'refused', reason: 'Google Email OTP recovery is not configured' };
  }

  const stored = await googleRecovery.readAttempt(request.recoveryOperationId);
  if (stored.kind !== 'present' || stored.value.state !== 'otp_verified') {
    return { kind: 'refused', reason: 'the verified recovery operation is unavailable' };
  }
  const attempt = stored.value;
  if (String(attempt.reservationId) !== String(request.reservationId)) {
    return { kind: 'refused', reason: 'the recovery reservation does not match the operation' };
  }

  const recovery = walletRecoveryGoogleEmailOtpFinalizationInput(attempt);
  const emailOtpEnrollment = googleEmailOtpEnrollmentForRoute({
    recovery,
    emailOtpEnrollment: request.emailOtpEnrollment,
  });
  if (emailOtpEnrollment.kind !== 'ready') return emailOtpEnrollment;

  return await googleRecovery.finalizeRecovery({
    recovery,
    replacementEnvelope: request.replacementEnvelope,
    emailOtpEnrollment: emailOtpEnrollment.enrollment,
    ecdsaMaterialPossessionProofs: request.ecdsaMaterialPossessionProofs,
    dependencies: {
      envelopeStore: assembly.passkeyCustodyEnvelopes,
      walletCustodyCommits: assembly.walletCustodyCommits,
      walletAuthorityStore: assembly.walletAuthorityStore,
      walletStore: assembly.walletStore,
      enrollmentFinalizer,
    },
  });
}

type GoogleEmailOtpEnrollmentForRouteResult =
  | {
      readonly kind: 'ready';
      readonly enrollment: Parameters<
        CloudflareD1WalletRecoveryGoogleEmailOtpService['finalizeRecovery']
      >[0]['emailOtpEnrollment'];
    }
  | Extract<WalletRecoveryGoogleEmailOtpFinalizationResult, { readonly kind: 'enrollment_rejected' }>;

function googleEmailOtpEnrollmentForRoute(input: {
  readonly recovery: WalletRecoveryGoogleEmailOtpFinalizationInput;
  readonly emailOtpEnrollment: WalletRecoveryGoogleEmailOtpRouteFinalizationRequest['emailOtpEnrollment'];
}): GoogleEmailOtpEnrollmentForRouteResult {
  switch (input.recovery.targetEnrollment.kind) {
    case 'existing':
      if (input.emailOtpEnrollment !== null) {
        return {
          kind: 'enrollment_rejected',
          reason: 'existing recovery Email enrollment accepts no client material',
        };
      }
      return {
        kind: 'ready',
        enrollment: {
          kind: 'existing',
          enrollmentId: input.recovery.targetEnrollment.enrollmentId,
          enrollmentSealKeyVersion: input.recovery.targetEnrollment.enrollmentSealKeyVersion,
        },
      };
    case 'create':
      if (input.emailOtpEnrollment === null) {
        return {
          kind: 'enrollment_rejected',
          reason: 'new recovery Email enrollment material is required',
        };
      }
      return {
        kind: 'ready',
        enrollment: {
          kind: 'create',
          providerSubject: input.recovery.providerSubject,
          verifiedEmail: input.recovery.verifiedEmail,
          material: input.emailOtpEnrollment.material,
        },
      };
  }
}

async function buildEcdsaPossessionChallenges(input: {
  readonly manifest: Awaited<ReturnType<typeof resolveWalletRecoveryKeyManifestV1>>;
  readonly walletId: WalletId;
  readonly reservationId: RecoveryCodeReservationId;
  readonly replacementId: string;
  readonly sourceAuthorityDigestB64u: WalletAuthorityBindingDigest;
  readonly challengeB64u: string;
  readonly expiresAtMs: number;
}): Promise<ReadonlyMap<`evm_family_ecdsa:${string}`, WalletRecoveryEcdsaPossessionChallengeV1>> {
  return await buildWalletRecoveryEcdsaPossessionChallengesV1({
    manifest: input.manifest,
    walletId: input.walletId,
    reservationId: input.reservationId,
    replacementId: input.replacementId,
    sourceAuthorityDigestB64u: input.sourceAuthorityDigestB64u,
    challengeB64u: input.challengeB64u,
    expiresAtMs: input.expiresAtMs,
  });
}

function requireWalletId(value: unknown): WalletId {
  const parsed = parseWalletId(value);
  if (!parsed.ok) throw new Error('wallet ID is invalid');
  return parsed.value;
}

/**
 * The router's WebAuthn store, seen as the interface assertion verification
 * expects.
 *
 * The two shapes differ only in naming — both read and write the same
 * `WebAuthnAuthenticatorRecord` rows — so this adapts rather than duplicates.
 * Verifying against the router's own authenticators is the point: a separate
 * store would let a credential be active for registration and unknown to
 * custody, and the wallet would refuse a passkey the user just enrolled.
 */
function authenticatorStoreView(store: CloudflareD1WebAuthnStore): WebAuthnAuthenticatorStore {
  return {
    get: async (userId, credentialIdB64u) => {
      const record = await store.readAuthenticator({ userId, credentialIdB64u });
      if (!record) return null;
      /* The router row lacks the version tag the core record is discriminated
         by. Every other field, device metadata included, is identical in both. */
      return {
        version: 'webauthn_authenticator_v1',
        credentialIdB64u: record.credentialIdB64u,
        credentialPublicKeyB64u: record.credentialPublicKeyB64u,
        counter: record.counter,
        createdAtMs: record.createdAtMs,
        updatedAtMs: record.updatedAtMs,
        deviceInfo: record.deviceInfo,
      };
    },
    /* Narrowed to the counter on purpose. A successful assertion may advance
       the signature counter and nothing else; a general write here could
       replace a credential's public key on the strength of an assertion that
       key just verified, which is a credential swap with extra steps. It also
       cannot create a row, so custody retrieval can never enroll a factor. */
    put: (userId, record) =>
      store.updateAuthenticatorCounter({
        userId,
        credentialIdB64u: record.credentialIdB64u,
        newCounter: record.counter,
        updatedAtMs: record.updatedAtMs,
      }),
    del: async () => {
      /* Deliberately not implemented rather than a silent no-op. The D1 store
         has no delete, and a `del` that resolved without removing anything
         would report a revoked credential as gone while it still verified
         assertions. Retrieval never calls this; anything that does is a bug
         that should surface here rather than as phantom access later. */
      throw new Error(
        'the router WebAuthn store cannot delete authenticators; revoke the custody envelope instead',
      );
    },
  };
}
