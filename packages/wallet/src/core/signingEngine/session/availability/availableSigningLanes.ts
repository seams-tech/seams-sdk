import type { AccountId } from '@/core/types/accountIds';
import { toAccountId } from '@/core/types/accountIds';
import {
  nearEd25519SigningKeyIdFromString,
  type NearEd25519SigningKeyId,
} from '@shared/utils/registrationIntent';
import { parseSignerSlot } from '@shared/utils/signerSlot';
import type { SigningSessionSealedStoreRecord } from '../persistence/sealedSessionStore';
import type {
  EcdsaLaneCandidate,
  Ed25519LaneCandidate,
  LaneCandidateSource,
  LaneCandidateState,
} from '../identity/laneIdentity';
import {
  deriveEvmFamilyKeyFingerprintFromPublicFacts,
  toRpId,
  type EvmFamilyKeyFingerprint,
  type EvmFamilyEcdsaKeyIdentity,
  type PasskeyEcdsaAuthBinding,
  type ResolvedEvmFamilyEcdsaKey,
  type VerifiedEcdsaPublicFacts,
} from '../identity/evmFamilyEcdsaIdentity';
import {
  buildEmailOtpWalletAuthAuthority,
  buildPasskeyWalletAuthAuthority,
  walletAuthAuthorityRef,
  type WalletAuthAuthority,
} from '@shared/utils/walletAuthAuthority';
import {
  thresholdEcdsaChainTargetKey,
  toWalletId,
  type ThresholdEcdsaChainTarget,
  type WalletId,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import {
  signingLaneAuthBindingKey,
  signingLaneAuthMethod,
  type LinkedOwnerLaneIdentityV1,
  type OwnerLaneScope,
  type SigningLaneAuthBinding,
} from '../identity/signingLaneAuthBinding';
import {
  type FreshStepUpRequired,
  type StepUpExpiryState,
} from '../operationState/stepUpFreshness';
import {
  canonicalizeLaneFacts,
  serverIssuedGenerationFromNumber,
  type CanonicalFactSupersession,
  type CanonicalLaneInventoryAdapter,
  type CanonicalTieBreakOrder,
  type ServerIssuedGeneration,
} from './canonicalLaneInventory';
import {
  mpcMaterialActivationRefsEqual,
  type MpcMaterialActivationRef,
} from '@shared/utils/domainIds';
import type {
  ActiveEvmFamilyWalletSessionAuthorization,
  CanonicalEvmFamilyEcdsaSigningCapability,
} from '../material/ecdsaSigningCapability';
import {
  walletSessionThresholdSessionIdForCurve,
  walletSessionTokenForCurve,
  type ActiveWalletSessionAuthorizationProjection,
} from '@/core/indexedDB/seamsWalletDB/walletSessionAuthorizationStore';
import { SigningSessionIds } from '../operationState/types';
import type { Ed25519YaoPublicCapabilityLaneReferenceV1 } from '../../threshold/ed25519/yaoPublicCapabilityReferences';
import type {
  ActiveLinkedDeviceExecutionBundleV1,
  ActiveLinkedDeviceExecutionChildV1,
} from '../lanes/linkedDeviceExecutionBundle';
import type {
  DeviceLinkingHolderSigningMaterialHandleV1,
  DeviceLinkingHolderSigningMaterialPortV1,
} from '../lanes/linkedDevicePorts';
import type { LinkedDeviceWalletSessionTokenReadResultV1 } from '@/core/indexedDB/seamsWalletDB/linkedDeviceWalletSessionStore';
import type { EcdsaAdditiveLaneJobV1 } from '@shared/signing-lanes/rotation';
import type { LinkedDeviceEcdsaNormalSigningScopeV1 } from '@shared/signing-lanes/linkedEcdsaScope';
import type { DelegatedWalletAuthorityV1 } from '@shared/authorization/delegatedAuthority';

export type AvailableSigningLaneState =
  | 'ready'
  | 'restorable'
  | 'deferred'
  | 'expired'
  | 'exhausted';

export type AvailableSigningLanePolicyHint = {
  remainingUses?: number;
  expiresAtMs?: number;
};

export type MissingAvailableEcdsaSigningLane = {
  curve: 'ecdsa';
  chainTarget: ThresholdEcdsaChainTarget;
  state: 'missing';
  key?: never;
  publicFacts?: never;
  authMethod?: never;
  resolvedKey?: never;
  thresholdSessionId?: never;
  remainingUses?: never;
  expiresAtMs?: never;
  policyHint?: never;
  updatedAtMs?: never;
  source?: never;
  sourceChainTarget?: never;
  publicReauthAuthority?: never;
};

export type ResolvedPasskeyAvailableEcdsaKey = ResolvedEvmFamilyEcdsaKey<PasskeyEcdsaAuthBinding>;

type ConcreteAvailableEcdsaSigningLaneAuth =
  | {
      auth: Extract<SigningLaneAuthBinding, { kind: 'passkey' }>;
      resolvedKey: ResolvedPasskeyAvailableEcdsaKey;
      linkedOwner?: never;
    }
  | {
      auth: Extract<SigningLaneAuthBinding, { kind: 'email_otp' }>;
      resolvedKey?: never;
      linkedOwner?: LinkedOwnerLaneIdentityV1;
    };

type ConcreteAvailableEcdsaSigningLaneBase = {
  key: EvmFamilyEcdsaKeyIdentity;
  materialActivation: MpcMaterialActivationRef;
  publicFacts: VerifiedEcdsaPublicFacts;
  curve: 'ecdsa';
  chainTarget: ThresholdEcdsaChainTarget;
  state: Exclude<AvailableSigningLaneState, 'restorable'>;
  policyHint?: AvailableSigningLanePolicyHint;
  updatedAtMs?: number;
} & ConcreteAvailableEcdsaSigningLaneAuth;

export type ConcreteAvailableEcdsaSigningLane = ConcreteAvailableEcdsaSigningLaneBase & {
  source: 'canonical_capability';
  capability: CanonicalEvmFamilyEcdsaSigningCapability;
  sourceChainTarget?: never;
  publicReauthAuthority?: never;
  thresholdSessionId?: never;
} & (
    | {
        authorization: ActiveEvmFamilyWalletSessionAuthorization;
        remainingUses: number;
        expiresAtMs: number;
      }
    | {
        authorization?: never;
        state: 'deferred';
        remainingUses?: never;
        expiresAtMs?: never;
      }
  );

/**
 * An activated linked lane is a distinct ECDSA identity. It has no owner
 * derivation root, key handle, or canonical capability; those fields stay
 * forbidden so selection cannot silently fall back to the owner lane.
 */
export type ActiveExecutionBundleEcdsaSigningLane = {
  source: 'active_execution_bundle';
  curve: 'ecdsa';
  chainTarget: ThresholdEcdsaChainTarget;
  state: 'ready';
  auth: SigningLaneAuthBinding;
  linkedOwner: LinkedOwnerLaneIdentityV1;
  authorizationState: 'authorized';
  authorization: ActiveWalletSessionAuthorizationProjection;
  remainingUses: number;
  expiresAtMs: number;
  updatedAtMs: number;
  job: EcdsaAdditiveLaneJobV1;
  materialActivation: MpcMaterialActivationRef;
  laneIdentity: LinkedDeviceEcdsaNormalSigningScopeV1;
  holderHandle: Extract<
    DeviceLinkingHolderSigningMaterialHandleV1,
    { readonly keyFamily: 'ecdsa_secp256k1' }
  >;
  holderMaterial: DeviceLinkingHolderSigningMaterialPortV1;
  walletSession: Extract<LinkedDeviceWalletSessionTokenReadResultV1, { readonly kind: 'found' }>;
  execution: Extract<
    ActiveLinkedDeviceExecutionChildV1,
    { readonly kind: 'active_linked_device_ecdsa_execution_v1' }
  >;
  key?: never;
  publicFacts?: never;
  capability?: never;
  resolvedKey?: never;
  sourceChainTarget?: never;
  publicReauthAuthority?: never;
  thresholdSessionId?: never;
  policyHint?: never;
};

export type ActiveExecutionBundleEcdsaExportContext = {
  bundle: ActiveLinkedDeviceExecutionBundleV1;
  execution: Extract<
    ActiveLinkedDeviceExecutionChildV1,
    { readonly kind: 'active_linked_device_ecdsa_execution_v1' }
  >;
  job: EcdsaAdditiveLaneJobV1;
  materialActivation: MpcMaterialActivationRef;
  laneIdentity: LinkedDeviceEcdsaNormalSigningScopeV1;
  holderHandle: Extract<
    DeviceLinkingHolderSigningMaterialHandleV1,
    { readonly keyFamily: 'ecdsa_secp256k1' }
  >;
  holderMaterial: DeviceLinkingHolderSigningMaterialPortV1;
  walletSession: Extract<LinkedDeviceWalletSessionTokenReadResultV1, { readonly kind: 'found' }>;
  chainTarget: ThresholdEcdsaChainTarget;
  auth: SigningLaneAuthBinding;
  linkedOwner: LinkedOwnerLaneIdentityV1;
};

export type AvailableEcdsaSigningLane =
  | MissingAvailableEcdsaSigningLane
  | ConcreteAvailableEcdsaSigningLane
  | ActiveExecutionBundleEcdsaSigningLane;

function materialActivationKey(activation: MpcMaterialActivationRef): string {
  return [
    activation.activationId,
    activation.capability,
    activation.materialOwner,
    activation.keyBinding,
    activation.lifecycleBinding,
    activation.signingWorker,
  ]
    .map((part) => encodeURIComponent(String(part)))
    .join(':');
}

export type EcdsaLaneRecordFactSource = 'canonical_capability';

export type EcdsaLaneGroupKey = {
  walletId: string;
  authKey: string;
  materialActivationKey: string;
  ecdsaThresholdKeyId: string;
  signingRootId: string;
  signingRootVersion: string;
};

export type EcdsaLaneRecordFact = {
  source: EcdsaLaneRecordFactSource;
  groupKey: EcdsaLaneGroupKey;
  chainTargetKey: string;
  lane: ConcreteAvailableEcdsaSigningLane;
};

export type EcdsaLaneGroup = {
  key: EcdsaLaneGroupKey;
  facts: readonly EcdsaLaneRecordFact[];
};

export type EcdsaLaneConflict = {
  groupKey: EcdsaLaneGroupKey;
  field:
    | 'ecdsaThresholdKeyId'
    | 'thresholdOwnerAddress'
    | 'keyHandle'
    | 'publicKeyB64u'
    | 'participantIds';
  values: readonly string[];
};

export type EcdsaCanonicalLaneSelection =
  | {
      kind: 'selected';
      selectedFact: EcdsaLaneRecordFact;
      supersededFacts: readonly EcdsaLaneRecordFact[];
    }
  | { kind: 'no_current_lane'; unusableFacts: readonly EcdsaLaneRecordFact[] }
  | { kind: 'conflicting_key_material'; conflicts: readonly EcdsaLaneConflict[] }
  | {
      kind: 'ambiguous_material';
      candidates: readonly EcdsaLaneGroupKey[];
      candidateFacts: readonly EcdsaLaneRecordFact[];
    };

export function availableEcdsaSigningLaneAuthMethod(
  lane: Pick<ConcreteAvailableEcdsaSigningLane, 'auth'>,
): WalletAuthAuthority['factor']['kind'] {
  return signingLaneAuthMethod(lane.auth);
}

export type MissingAvailableEd25519SigningLane = {
  curve: 'ed25519';
  chain: 'near';
  state: 'missing';
  walletId?: never;
  nearAccountId?: never;
  nearEd25519SigningKeyId?: never;
  signerSlot?: never;
  authMethod?: never;
  thresholdSessionId?: never;
  remainingUses?: never;
  expiresAtMs?: never;
  policyHint?: never;
  updatedAtMs?: never;
  source?: never;
};

type ConcreteAvailableEd25519SigningLaneBase = {
  auth: SigningLaneAuthBinding;
  curve: 'ed25519';
  chain: 'near';
  materialActivation: MpcMaterialActivationRef;
  walletId: WalletId;
  nearAccountId: AccountId;
  nearEd25519SigningKeyId: NearEd25519SigningKeyId;
  signerSlot: number;
  thresholdSessionId: string;
  remainingUses?: number;
  expiresAtMs?: number;
  policyHint?: AvailableSigningLanePolicyHint;
  updatedAtMs?: number;
  source?: 'durable_sealed_record' | 'public_capability_reference' | 'active_execution_bundle';
  delegatedAuthority?: DelegatedWalletAuthorityV1;
  /** Present only for an enrollment-scoped linked owner Email OTP lane. */
  linkedOwner?: LinkedOwnerLaneIdentityV1;
};

function activeLinkedDeviceEd25519Execution(
  bundle: ActiveLinkedDeviceExecutionBundleV1,
): Extract<
  ActiveLinkedDeviceExecutionBundleV1['orderedExecutions'][number],
  { kind: 'active_linked_device_ed25519_execution_v1' }
> | null {
  const executions = bundle.orderedExecutions.filter(
    (
      execution,
    ): execution is Extract<
      ActiveLinkedDeviceExecutionBundleV1['orderedExecutions'][number],
      { kind: 'active_linked_device_ed25519_execution_v1' }
    > => execution.kind === 'active_linked_device_ed25519_execution_v1',
  );
  return executions.length === 1 ? executions[0]! : null;
}

async function activeExecutionBundleToEd25519Lane(
  bundle: ActiveLinkedDeviceExecutionBundleV1,
  activeAuthorization: ActiveWalletSessionAuthorizationProjection | null,
): Promise<ConcreteAvailableEd25519SigningLane | null> {
  const execution = activeLinkedDeviceEd25519Execution(bundle);
  const thresholdSessionId = activeAuthorization
    ? walletSessionThresholdSessionIdForCurve(activeAuthorization, 'ed25519')
    : null;
  const walletSessionToken = activeAuthorization
    ? walletSessionTokenForCurve(activeAuthorization, 'ed25519')
    : null;
  const signerSlot = execution
    ? parseSignerSlot(execution.walletKey.keyCreationSignerSlot, { min: 1 })
    : null;
  if (
    !execution ||
    !bundle.nearAccountId ||
    !activeAuthorization ||
    !thresholdSessionId ||
    !walletSessionToken ||
    signerSlot === null ||
    String(activeAuthorization.walletId) !== String(bundle.walletId) ||
    String(activeAuthorization.walletSessionId) !== String(bundle.walletSessionId)
  ) {
    return null;
  }

  const registration = bundle.targetCredentialRegistration;
  let auth: SigningLaneAuthBinding;
  let authority: WalletAuthAuthority;
  switch (registration.targetFactor.kind) {
    case 'passkey_prf': {
      const preparation = bundle.targetPreparation;
      if (
        preparation.targetFactor.kind !== 'passkey_prf' ||
        preparation.ownerEnrollment.registration === undefined ||
        registration.webauthnRegistration === undefined
      ) {
        return null;
      }
      auth = {
        kind: 'passkey',
        rpId: toRpId(preparation.ownerEnrollment.registration.rpId),
        credentialIdB64u: registration.webauthnRegistration.credentialIdB64u,
      };
      authority = buildPasskeyWalletAuthAuthority({
        walletId: bundle.walletId,
        rpId: auth.rpId,
        credentialIdB64u: auth.credentialIdB64u,
      });
      break;
    }
    case 'email_otp': {
      const grant = registration.emailOtpVerificationGrant;
      if (!grant) return null;
      auth = {
        kind: 'email_otp',
        providerSubjectId: grant.providerUserId,
      };
      authority = buildEmailOtpWalletAuthAuthority({
        walletId: bundle.walletId,
        provider: 'google',
        providerUserId: grant.providerUserId,
        emailHashHex: grant.emailHashHex,
      });
      break;
    }
  }
  const authorityRef = await walletAuthAuthorityRef({ authority });
  if (
    authorityRef.walletAuthMethodId !== activeAuthorization.authority.walletAuthMethodId ||
    authorityRef.authorityDigest !== activeAuthorization.authority.authorityDigest
  ) {
    return null;
  }
  return {
    auth,
    curve: 'ed25519',
    chain: 'near',
    materialActivation: execution.materialActivation,
    walletId: toWalletId(bundle.walletId),
    nearAccountId: toAccountId(bundle.nearAccountId),
    nearEd25519SigningKeyId: nearEd25519SigningKeyIdFromString(
      execution.walletKey.nearEd25519SigningKeyId,
    ),
    signerSlot,
    thresholdSessionId,
    remainingUses: bundle.remainingUses,
    expiresAtMs: bundle.expiresAtMs,
    updatedAtMs: bundle.activatedAtMs,
    source: 'active_execution_bundle',
    delegatedAuthority: bundle.permission,
    state: 'ready',
    authorizationState: 'authorized',
    authorization: activeAuthorization,
  };
}

export type ConcreteAvailableEd25519SigningLane = ConcreteAvailableEd25519SigningLaneBase &
  (
    | {
        authorizationState: 'authorized';
        authorization: ActiveWalletSessionAuthorizationProjection;
        state: Exclude<AvailableSigningLaneState, 'deferred'>;
      }
    | {
        authorizationState: 'authorization_required';
        authorization?: never;
        state: 'deferred';
      }
  );

export type AvailableEd25519SigningLane =
  | MissingAvailableEd25519SigningLane
  | ConcreteAvailableEd25519SigningLane;

export function availableEd25519SigningLaneAuthMethod(
  lane: Pick<ConcreteAvailableEd25519SigningLane, 'auth'>,
): 'email_otp' | 'passkey' {
  return signingLaneAuthMethod(lane.auth);
}

function durableEd25519AuthBinding(
  record: Extract<SigningSessionSealedStoreRecord, { curve: 'ed25519' }>,
): SigningLaneAuthBinding | null {
  const restore = record.ed25519Restore;
  if (record.authMethod === 'passkey') {
    if (!restore.credentialIdB64u) return null;
    try {
      return {
        kind: 'passkey',
        rpId: toRpId(restore.rpId),
        credentialIdB64u: restore.credentialIdB64u,
      };
    } catch {
      return null;
    }
  }
  if (!restore.providerSubjectId) return null;
  return {
    kind: 'email_otp',
    providerSubjectId: restore.providerSubjectId,
  };
}

function activeExecutionBundleToEcdsaLane(
  context: ActiveExecutionBundleEcdsaExportContext,
  activeAuthorization: ActiveWalletSessionAuthorizationProjection | null,
): ActiveExecutionBundleEcdsaSigningLane | null {
  const { bundle, execution, job, laneIdentity } = context;
  const thresholdSession = job.targetCapability.orderedThresholdSessions.find(
    (target) =>
      thresholdEcdsaChainTargetKey(target.chainTarget) ===
      thresholdEcdsaChainTargetKey(context.chainTarget),
  );
  const laneTargetSession = laneIdentity.targetCapability.orderedThresholdSessions.find(
    (target) =>
      thresholdEcdsaChainTargetKey(target.chainTarget) ===
      thresholdEcdsaChainTargetKey(context.chainTarget),
  );
  const walletSessionToken = activeAuthorization
    ? walletSessionTokenForCurve(activeAuthorization, 'ecdsa')
    : null;
  let rejectionReason: string | null = null;
  if (!activeAuthorization) rejectionReason = 'active_authorization_missing';
  else if (!walletSessionToken) rejectionReason = 'ecdsa_wallet_session_token_missing';
  else if (!thresholdSession) rejectionReason = 'job_threshold_target_missing';
  else if (!laneTargetSession) rejectionReason = 'lane_threshold_target_missing';
  else if (execution.keyFamily !== 'ecdsa_secp256k1') rejectionReason = 'execution_family_mismatch';
  else if (context.holderHandle.keyFamily !== 'ecdsa_secp256k1') {
    rejectionReason = 'holder_family_mismatch';
  } else if (String(activeAuthorization.walletId) !== String(bundle.walletId)) {
    rejectionReason = 'authorization_wallet_mismatch';
  } else if (String(activeAuthorization.walletSessionId) !== String(bundle.walletSessionId)) {
    rejectionReason = 'authorization_session_mismatch';
  } else if (activeAuthorization.authMethod !== context.auth.kind) {
    rejectionReason = 'authorization_method_mismatch';
  } else if (String(laneIdentity.walletId) !== String(bundle.walletId)) {
    rejectionReason = 'lane_wallet_mismatch';
  } else if (String(laneIdentity.walletKeyId) !== String(execution.walletKey.walletKeyId)) {
    rejectionReason = 'lane_wallet_key_mismatch';
  } else if (String(laneIdentity.enrollmentId) !== String(bundle.enrollmentId)) {
    rejectionReason = 'lane_enrollment_mismatch';
  } else if (String(laneIdentity.operationId) !== String(job.operationId)) {
    rejectionReason = 'lane_operation_mismatch';
  } else if (String(laneIdentity.laneId) !== String(job.target.laneId)) {
    rejectionReason = 'lane_id_mismatch';
  } else if (String(laneIdentity.laneShareEpoch) !== String(job.target.laneShareEpoch)) {
    rejectionReason = 'lane_share_epoch_mismatch';
  } else if (
    !mpcMaterialActivationRefsEqual(laneIdentity.materialActivation, context.materialActivation)
  ) {
    rejectionReason = 'lane_material_activation_mismatch';
  } else if (
    !mpcMaterialActivationRefsEqual(execution.materialActivation, context.materialActivation)
  ) {
    rejectionReason = 'execution_material_activation_mismatch';
  } else if (
    String(laneIdentity.targetMaterialActivationId) !== String(job.targetMaterialActivationId)
  ) {
    rejectionReason = 'target_material_activation_mismatch';
  } else if (
    String(laneIdentity.evmAddress).toLowerCase() !==
    String(execution.walletKey.evmAddress).toLowerCase()
  ) {
    rejectionReason = 'evm_address_mismatch';
  } else if (
    String(laneIdentity.thresholdPublicKey33B64u) !==
    String(execution.walletKey.thresholdPublicKey33B64u)
  ) {
    rejectionReason = 'threshold_public_key_mismatch';
  } else if (
    String(laneIdentity.publicIdentityDigestB64u) !== String(execution.publicIdentityDigestB64u)
  ) {
    rejectionReason = 'public_identity_digest_mismatch';
  } else if (
    String(laneTargetSession?.thresholdSessionId) !== String(thresholdSession?.thresholdSessionId)
  ) {
    rejectionReason = 'threshold_session_mismatch';
  } else if (
    String(laneTargetSession?.participantBindingDigestB64u) !==
    String(thresholdSession?.participantBindingDigestB64u)
  ) {
    rejectionReason = 'participant_binding_digest_mismatch';
  } else if (context.linkedOwner.enrollmentId !== bundle.enrollmentId) {
    rejectionReason = 'owner_enrollment_mismatch';
  } else if (context.linkedOwner.deviceId !== bundle.deviceId) {
    rejectionReason = 'owner_device_mismatch';
  } else if (
    context.linkedOwner.walletAuthMethodId !== activeAuthorization.authority.walletAuthMethodId
  ) {
    rejectionReason = 'owner_auth_method_id_mismatch';
  } else if (
    String(context.linkedOwner.authorityDigest) !==
    String(activeAuthorization.authority.authorityDigest)
  ) {
    rejectionReason = 'owner_authority_digest_mismatch';
  }
  if (rejectionReason) {
    if (isAvailableSigningLaneDiagnosticsEnabled()) {
      console.warn('[SigningLanes][active-ecdsa][rejected]', {
        reason: rejectionReason,
        walletId: String(bundle.walletId),
        enrollmentId: String(bundle.enrollmentId),
        targetKey: thresholdEcdsaChainTargetKey(context.chainTarget),
      });
    }
    return null;
  }
  if (!activeAuthorization) return null;
  return {
    source: 'active_execution_bundle',
    curve: 'ecdsa',
    chainTarget: context.chainTarget,
    state: 'ready',
    auth: context.auth,
    linkedOwner: context.linkedOwner,
    authorizationState: 'authorized',
    authorization: activeAuthorization,
    remainingUses: bundle.remainingUses,
    expiresAtMs: bundle.expiresAtMs,
    updatedAtMs: bundle.activatedAtMs,
    job,
    materialActivation: context.materialActivation,
    laneIdentity,
    holderHandle: context.holderHandle,
    holderMaterial: context.holderMaterial,
    walletSession: context.walletSession,
    execution,
  };
}

function activeAuthorizationMatchesEd25519Lane(input: {
  readonly authorization: ActiveWalletSessionAuthorizationProjection;
  readonly auth: SigningLaneAuthBinding;
  readonly walletId: string;
  readonly thresholdSessionId: string;
}): boolean {
  if (
    String(input.authorization.walletId) !== input.walletId ||
    input.authorization.authMethod !== input.auth.kind ||
    input.authorization.walletSessionId.length === 0 ||
    input.authorization.quotaId.length === 0 ||
    String(walletSessionThresholdSessionIdForCurve(input.authorization, 'ed25519')) !==
      input.thresholdSessionId
  ) {
    return false;
  }
  if (input.auth.kind === 'email_otp') return true;
  try {
    const authority = buildPasskeyWalletAuthAuthority({
      walletId: input.walletId,
      rpId: input.auth.rpId,
      credentialIdB64u: input.auth.credentialIdB64u,
    });
    return input.authorization.authority.walletAuthMethodId === authority.bindingId;
  } catch {
    return false;
  }
}

function recordToEd25519Lane(
  record: SigningSessionSealedStoreRecord,
  activeAuthorization: ActiveWalletSessionAuthorizationProjection | null,
): ConcreteAvailableEd25519SigningLane | null {
  if (record.curve !== 'ed25519') return null;
  const thresholdSessionId = String(record.thresholdSessionIds.ed25519 || '').trim();
  const walletId = String(record.walletId || '').trim();
  const restore = record.ed25519Restore;
  const signerSlot = parseSignerSlot(restore.signerSlot);
  const auth = durableEd25519AuthBinding(record);
  if (!thresholdSessionId || !walletId || signerSlot === null || !auth) {
    return null;
  }
  const expiresAtMs = Math.floor(Number(record.expiresAtMs) || 0);
  const remainingUses = Math.max(0, Math.floor(Number(record.remainingUses) || 0));
  const state: AvailableSigningLaneState =
    expiresAtMs > 0 && expiresAtMs <= Date.now()
      ? 'expired'
      : remainingUses === 0
        ? 'exhausted'
        : 'restorable';
  const walletSessionToken = activeAuthorization
    ? walletSessionTokenForCurve(activeAuthorization, 'ed25519')
    : null;
  const authorization =
    activeAuthorization &&
    walletSessionToken &&
    activeAuthorizationMatchesEd25519Lane({
      authorization: activeAuthorization,
      auth,
      walletId,
      thresholdSessionId,
    })
      ? activeAuthorization
      : null;
  try {
    const base = {
      auth,
      curve: 'ed25519',
      chain: 'near',
      materialActivation: restore.materialActivation,
      walletId: toWalletId(walletId),
      nearAccountId: toAccountId(restore.nearAccountId),
      nearEd25519SigningKeyId: nearEd25519SigningKeyIdFromString(restore.nearEd25519SigningKeyId),
      signerSlot,
      source: 'durable_sealed_record',
      thresholdSessionId,
      remainingUses,
      ...(expiresAtMs > 0 ? { expiresAtMs } : {}),
      updatedAtMs: Math.floor(Number(record.updatedAtMs) || 0),
      ...(durablePolicyHint(record) ? { policyHint: durablePolicyHint(record) } : {}),
    } as const;
    return authorization
      ? {
          ...base,
          state,
          authorizationState: 'authorized',
          authorization,
        }
      : {
          ...base,
          state: 'deferred',
          authorizationState: 'authorization_required',
        };
  } catch {
    return null;
  }
}

function isEmailOtpPublicCapabilityLaneReference(
  reference: Ed25519YaoPublicCapabilityLaneReferenceV1,
): reference is Extract<
  Ed25519YaoPublicCapabilityLaneReferenceV1,
  { auth: { kind: 'email_otp' } }
> {
  return reference.auth.kind === 'email_otp';
}

function publicCapabilityReferenceToEd25519Lane(
  reference: Ed25519YaoPublicCapabilityLaneReferenceV1,
  activeAuthorization: ActiveWalletSessionAuthorizationProjection | null,
): ConcreteAvailableEd25519SigningLane | null {
  const walletId = String(reference.walletId || '').trim();
  const nearAccountId = String(reference.nearAccountId || '').trim();
  const thresholdSessionId = String(reference.thresholdSessionId || '').trim();
  if (!walletId || !nearAccountId || !thresholdSessionId) return null;
  const walletSessionToken = activeAuthorization
    ? walletSessionTokenForCurve(activeAuthorization, 'ed25519')
    : null;
  const authorization =
    activeAuthorization &&
    walletSessionToken &&
    activeAuthorizationMatchesEd25519Lane({
      authorization: activeAuthorization,
      auth: reference.auth,
      walletId,
      thresholdSessionId,
    })
      ? activeAuthorization
      : null;
  try {
    const base = {
      auth: reference.auth,
      curve: 'ed25519' as const,
      chain: 'near' as const,
      materialActivation: reference.materialActivation,
      walletId: toWalletId(walletId),
      nearAccountId: toAccountId(nearAccountId),
      nearEd25519SigningKeyId: reference.nearEd25519SigningKeyId,
      signerSlot: reference.signerSlot,
      thresholdSessionId,
      source: 'public_capability_reference' as const,
    };
    if (!authorization) {
      return { ...base, state: 'deferred', authorizationState: 'authorization_required' };
    }
    const authorizationExpiresAtMs = Math.floor(Number(authorization.expiresAtMs) || 0);
    const emailOtpReference = isEmailOtpPublicCapabilityLaneReference(reference) ? reference : null;
    const expiresAtMs = emailOtpReference
      ? Math.min(emailOtpReference.expiresAtMs, authorizationExpiresAtMs)
      : authorizationExpiresAtMs;
    const state: AvailableSigningLaneState =
      expiresAtMs > 0 && expiresAtMs <= Date.now() ? 'expired' : 'ready';
    return {
      ...base,
      state,
      authorizationState: 'authorized',
      authorization,
      ...(emailOtpReference ? { remainingUses: emailOtpReference.remainingUses } : {}),
      ...(expiresAtMs > 0 ? { expiresAtMs } : {}),
    };
  } catch {
    return null;
  }
}

export type InvalidAvailableSigningLaneDiagnostic =
  | {
      curve: 'ed25519';
      source: 'canonical_lane_inventory';
      reason:
        | 'missing_router_ab_state'
        | 'missing_threshold_session_id'
        | 'ambiguous_material'
        | 'conflicting_key_material';
      authMethod?: 'email_otp' | 'passkey';
      thresholdSessionId?: string;
      message?: string;
    }
  | {
      curve: 'ecdsa';
      source: 'runtime_session_record' | 'canonical_lane_inventory';
      reason:
        | 'missing_router_ab_state'
        | 'missing_threshold_session_id'
        | 'unsupported_ecdsa_chain_target'
        | 'invalid_runtime_public_facts'
        | 'conflicting_key_material'
        | 'ambiguous_material';
      authMethod?: 'email_otp' | 'passkey';
      thresholdSessionId?: string;
      targetKey?: string;
      message?: string;
      groupKey?: EcdsaLaneGroupKey;
      conflicts?: readonly EcdsaLaneConflict[];
    };

export type AvailableSigningLaneDiagnostics = {
  invalidLanes: InvalidAvailableSigningLaneDiagnostic[];
};

export type AvailableSigningLanes = {
  walletId: WalletId;
  generation: number;
  ecdsa: {
    targets: ThresholdEcdsaChainTarget[];
    lanesByTarget: Record<string, AvailableEcdsaSigningLane>;
    candidatesByTarget: Record<string, AvailableEcdsaSigningLane[]>;
  };
  lanes: {
    ed25519: {
      near: AvailableEd25519SigningLane;
    };
  };
  candidates: {
    ed25519: {
      near: AvailableEd25519SigningLane[];
    };
  };
  diagnostics?: AvailableSigningLaneDiagnostics;
};

export type ConcreteAvailableSigningLane =
  | ConcreteAvailableEcdsaSigningLane
  | ConcreteAvailableEd25519SigningLane;

export type ReadAvailableSigningLanesInput = {
  walletId: WalletId | string;
  subjectId?: never;
  ecdsaChainTargets: readonly ThresholdEcdsaChainTarget[];
  authMethod?: 'email_otp' | 'passkey';
  /**
   * R103C: when present, candidates are filtered to this exact owner before
   * canonicalization. Sibling owner lanes and lanes on other signer slots
   * never reach selection. Omitted only for persistence maintenance,
   * normalization, and diagnostics reads.
   */
  ownerScope?: OwnerLaneScope;
  nowMs?: number;
};

export type ReadAvailableSigningLanesForSigningInput =
  | {
      walletId: WalletId | string;
      subjectId?: never;
      curve: 'ed25519';
      authMethod?: 'email_otp' | 'passkey';
      ownerScope: OwnerLaneScope;
    }
  | {
      walletId: WalletId;
      subjectId?: never;
      curve: 'ecdsa';
      ecdsaChainTargets: readonly ThresholdEcdsaChainTarget[];
      authMethod?: 'email_otp' | 'passkey';
      ownerScope: OwnerLaneScope;
    };

export type ReadAvailableSigningLanesPorts = {
  listSealedRecordsForWallet: (args: {
    walletId: string;
    filter: {
      authMethod?: 'email_otp' | 'passkey';
      curve: 'ed25519';
    };
  }) => Promise<SigningSessionSealedStoreRecord[]>;
  listPublicCapabilityReferences?: () => Promise<
    readonly Ed25519YaoPublicCapabilityLaneReferenceV1[]
  >;
  isPublicCapabilityActive?: (reference: Ed25519YaoPublicCapabilityLaneReferenceV1) => boolean;
  readActiveWalletSessionAuthorization?: (
    walletId: WalletId,
  ) => Promise<ActiveWalletSessionAuthorizationProjection | null>;
  readActiveExecutionBundleForWallet?: (args: {
    walletId: WalletId;
    nowMs: number;
  }) => Promise<ActiveLinkedDeviceExecutionBundleV1 | null>;
  readActiveEcdsaExportContextForWallet?: (args: {
    walletId: WalletId;
    chainTarget: ThresholdEcdsaChainTarget;
    nowMs: number;
  }) => Promise<ActiveExecutionBundleEcdsaExportContext | null>;
  listCanonicalEcdsaLanesForWallet?: (args: {
    walletId: string;
  }) => Promise<ConcreteAvailableEcdsaSigningLane[]>;
};

export function isConcreteAvailableSigningLane(
  lane: AvailableEcdsaSigningLane | AvailableEd25519SigningLane,
): lane is ConcreteAvailableSigningLane {
  if (lane.state === 'missing') return false;
  if (lane.curve !== 'ecdsa') {
    const thresholdSessionId = String(lane.thresholdSessionId || '').trim();
    if (lane.thresholdSessionId !== thresholdSessionId) return false;
    if (!thresholdSessionId) return false;
    if (lane.authorizationState === 'authorization_required') {
      return lane.state === 'deferred';
    }
    if (!lane.authorization.walletSessionId || !lane.authorization.quotaId) return false;
    return lane.auth.kind === 'email_otp' || lane.auth.kind === 'passkey';
  }
  if (lane.source === 'active_execution_bundle') return false;
  if (lane.auth.kind !== 'email_otp' && lane.auth.kind !== 'passkey') return false;
  const hasEcdsaFields = Boolean(
    lane.key &&
    String(lane.key.walletId || '').trim() &&
    String(lane.key.ecdsaThresholdKeyId || '').trim() &&
    String(lane.key.signingRootId || '').trim() &&
    String(lane.key.signingRootVersion || '').trim() &&
    Array.isArray(lane.key.participantIds) &&
    lane.key.participantIds.length > 0 &&
    String(lane.key.thresholdOwnerAddress || '').trim() &&
    Boolean(
      'publicFacts' in lane &&
      lane.publicFacts &&
      lane.publicFacts.keyHandle &&
      String(lane.publicFacts.publicKeyB64u || '').trim() &&
      Array.isArray(lane.publicFacts.participantIds) &&
      lane.publicFacts.participantIds.length > 0 &&
      String(lane.publicFacts.thresholdOwnerAddress || '').trim(),
    ),
  );
  if (!hasEcdsaFields) return false;
  if (signingLaneAuthMethod(lane.auth) === 'passkey') {
    return (
      lane.resolvedKey?.kind === 'resolved_evm_family_ecdsa_key' &&
      lane.resolvedKey.authBinding.kind === 'passkey_ecdsa_auth_binding' &&
      String(lane.resolvedKey.walletId) === String(lane.key.walletId) &&
      lane.resolvedKey.publicFacts === lane.publicFacts
    );
  }
  return !('resolvedKey' in lane);
}

function laneCandidateStateFromAvailableLaneState(
  state: AvailableSigningLaneState | 'missing',
): LaneCandidateState | null {
  return state === 'missing' ? null : state;
}

function laneCandidateSourceFromAvailableLaneSource(
  source: ConcreteAvailableSigningLane['source'],
): LaneCandidateSource {
  return source || 'unknown';
}

function nullablePositiveInteger(value: unknown): number | null {
  const normalized = Math.floor(Number(value));
  return Number.isFinite(normalized) && normalized > 0 ? normalized : null;
}

function nullableNonNegativeInteger(value: unknown): number | null {
  const normalized = Math.max(0, Math.floor(Number(value)));
  return Number.isFinite(normalized) ? normalized : null;
}

export function ed25519LaneCandidateFromAvailableLane(args: {
  lane: AvailableEd25519SigningLane;
}): Ed25519LaneCandidate | null {
  if (!isConcreteAvailableSigningLane(args.lane) || args.lane.curve !== 'ed25519') {
    return null;
  }
  const state = laneCandidateStateFromAvailableLaneState(args.lane.state);
  if (!state) return null;
  const base = {
    kind: 'lane_candidate',
    walletId: args.lane.walletId,
    nearAccountId: args.lane.nearAccountId,
    nearEd25519SigningKeyId: args.lane.nearEd25519SigningKeyId,
    signerSlot: args.lane.signerSlot,
    materialActivation: args.lane.materialActivation,
    auth: args.lane.auth,
    curve: 'ed25519',
    chain: 'near',
    thresholdSessionId: args.lane.thresholdSessionId,
    state,
    remainingUses: nullableNonNegativeInteger(args.lane.remainingUses),
    expiresAtMs: nullablePositiveInteger(args.lane.expiresAtMs),
    updatedAtMs: nullablePositiveInteger(args.lane.updatedAtMs),
    source: laneCandidateSourceFromAvailableLaneSource(args.lane.source),
  } as const;
  if (args.lane.authorizationState === 'authorization_required') {
    return {
      ...base,
      authorizationState: 'authorization_required',
      state: 'deferred',
    };
  }
  return {
    ...base,
    authorizationState: 'authorized',
    authorization: args.lane.authorization,
  };
}

export function ecdsaLaneCandidateFromAvailableLane(args: {
  walletId: WalletId | string;
  lane: AvailableEcdsaSigningLane;
}): EcdsaLaneCandidate | null {
  if (!isConcreteAvailableSigningLane(args.lane) || args.lane.curve !== 'ecdsa') {
    return null;
  }
  if (args.lane.source !== 'canonical_capability') return null;
  const state = laneCandidateStateFromAvailableLaneState(args.lane.state);
  if (!state) return null;
  const authMethod = signingLaneAuthMethod(args.lane.auth);
  const base = {
    kind: 'lane_candidate',
    walletId: toWalletId(args.walletId),
    auth: args.lane.auth,
    authMethod,
    curve: 'ecdsa',
    chain: args.lane.chainTarget.kind,
    key: args.lane.key,
    materialActivation: args.lane.materialActivation,
    ...(authMethod === 'passkey' ? { resolvedKey: args.lane.resolvedKey } : {}),
    keyHandle: args.lane.publicFacts.keyHandle,
    chainTarget: args.lane.chainTarget,
  } as const;
  if (!args.lane.authorization) {
    return {
      ...base,
      source: 'canonical_capability',
      authorizationState: 'authorization_required',
      state: 'deferred',
    };
  }
  return {
    ...base,
    source: 'canonical_capability',
    authorizationState: 'authorized',
    authorization: args.lane.authorization,
    state,
  };
}

type EcdsaAvailableLaneIdentityBase = Pick<
  ConcreteAvailableEcdsaSigningLane,
  'curve' | 'chainTarget' | 'key' | 'materialActivation' | 'publicFacts' | 'authorization'
>;

export type EcdsaAvailableLaneIdentityInput = EcdsaAvailableLaneIdentityBase &
  ConcreteAvailableEcdsaSigningLaneAuth;

export function ecdsaAvailableLaneIdentityKey(
  lane: EcdsaAvailableLaneIdentityInput | MissingAvailableEcdsaSigningLane | null | undefined,
): string | null {
  if (!lane || lane.curve !== 'ecdsa') return null;
  if (!lane.chainTarget) return null;
  if (!('key' in lane) || !lane.key) return null;
  if (!('auth' in lane) || !lane.auth) return null;
  const authMethod = signingLaneAuthMethod(lane.auth);
  try {
    const authKey = signingLaneAuthBindingKey(lane.auth);
    return [
      authMethod,
      'ecdsa',
      thresholdEcdsaChainTargetKey(lane.chainTarget),
      authKey,
      deriveAvailableEcdsaLaneFingerprint(lane),
      materialActivationKey(lane.materialActivation),
    ].join(':');
  } catch {
    return null;
  }
}

function deriveAvailableEcdsaLaneFingerprint(args: {
  key: EvmFamilyEcdsaKeyIdentity;
  publicFacts: VerifiedEcdsaPublicFacts;
}): EvmFamilyKeyFingerprint {
  return deriveEvmFamilyKeyFingerprintFromPublicFacts({
    walletId: args.key.walletId,
    publicFacts: args.publicFacts,
  });
}

type Ed25519AvailableLaneIdentityInput = {
  auth?: SigningLaneAuthBinding;
  curve: 'ed25519';
  chain: 'near';
  materialActivation?: MpcMaterialActivationRef;
  walletId?: unknown;
  nearAccountId?: unknown;
  nearEd25519SigningKeyId?: unknown;
  signerSlot?: unknown;
  thresholdSessionId?: unknown;
  state?: AvailableSigningLaneState | 'missing';
};

export function ed25519AvailableLaneIdentityKey(
  lane: Ed25519AvailableLaneIdentityInput | null | undefined,
): string | null {
  if (!lane || lane.curve !== 'ed25519' || lane.chain !== 'near') return null;
  if (lane.state === 'missing') return null;
  if (!lane.auth) return null;
  const authMethod = signingLaneAuthMethod(lane.auth);
  const walletId = String(lane.walletId || '').trim();
  const nearAccountId = String(lane.nearAccountId || '').trim();
  const nearEd25519SigningKeyId = String(lane.nearEd25519SigningKeyId || '').trim();
  const signerSlot = String(lane.signerSlot || '').trim();
  const thresholdSessionId = String(lane.thresholdSessionId || '').trim();
  const activationKey = lane.materialActivation
    ? materialActivationKey(lane.materialActivation)
    : '';
  if (
    !authMethod ||
    !walletId ||
    !nearAccountId ||
    !nearEd25519SigningKeyId ||
    !signerSlot ||
    !thresholdSessionId ||
    !activationKey
  ) {
    return null;
  }
  return [
    walletId,
    nearAccountId,
    nearEd25519SigningKeyId,
    signerSlot,
    authMethod,
    'ed25519',
    'near',
    thresholdSessionId,
    activationKey,
  ].join(':');
}

function emptyEcdsaLane(args: {
  chainTarget: ThresholdEcdsaChainTarget;
}): MissingAvailableEcdsaSigningLane {
  return {
    curve: 'ecdsa',
    chainTarget: args.chainTarget,
    state: 'missing',
  };
}

export function ecdsaAvailableLaneForTarget(
  availableLanes: AvailableSigningLanes,
  chainTarget: ThresholdEcdsaChainTarget,
): AvailableEcdsaSigningLane {
  const targetKey = thresholdEcdsaChainTargetKey(chainTarget);
  return availableLanes.ecdsa.lanesByTarget[targetKey] || emptyEcdsaLane({ chainTarget });
}

export function ecdsaAvailableLaneTargets(
  availableLanes: AvailableSigningLanes,
): ThresholdEcdsaChainTarget[] {
  return availableLanes.ecdsa.targets;
}

export function ecdsaAvailableLaneCandidatesForTarget(
  availableLanes: AvailableSigningLanes,
  chainTarget: ThresholdEcdsaChainTarget,
): AvailableEcdsaSigningLane[] {
  const targetKey = thresholdEcdsaChainTargetKey(chainTarget);
  return availableLanes.ecdsa.candidatesByTarget[targetKey] || [];
}

function emptyEd25519Lane(): AvailableEd25519SigningLane {
  return {
    curve: 'ed25519',
    chain: 'near',
    state: 'missing',
  };
}

function durablePolicyHint(record: {
  remainingUses: number;
  expiresAtMs: number;
}): AvailableSigningLanePolicyHint | undefined {
  const remainingUses = Math.floor(Number(record.remainingUses));
  const expiresAtMs = Math.floor(Number(record.expiresAtMs));
  const hint: AvailableSigningLanePolicyHint = {};
  if (Number.isFinite(remainingUses) && remainingUses >= 0) {
    hint.remainingUses = remainingUses;
  }
  if (Number.isFinite(expiresAtMs) && expiresAtMs > 0) {
    hint.expiresAtMs = expiresAtMs;
  }
  return Object.keys(hint).length ? hint : undefined;
}

function availableLaneUpdatedAtMs(
  lane: AvailableEcdsaSigningLane | AvailableEd25519SigningLane,
): number {
  return Math.floor(Number('updatedAtMs' in lane ? lane.updatedAtMs : 0) || 0);
}

function laneCandidateUpdatedAtMs(candidate: EcdsaLaneCandidate | Ed25519LaneCandidate): number {
  return candidate.curve === 'ecdsa' ? 0 : Math.floor(Number(candidate.updatedAtMs) || 0);
}

function laneCandidateExpiry(
  candidate: EcdsaLaneCandidate | Ed25519LaneCandidate,
): StepUpExpiryState {
  if (candidate.curve === 'ecdsa' && candidate.authorizationState !== 'authorized') {
    return { kind: 'unavailable', reason: 'restored_record_has_no_expiry' };
  }
  const expiresAtMs =
    candidate.curve === 'ecdsa'
      ? candidate.authorization.status.expiresAtMs
      : nullablePositiveInteger(candidate.expiresAtMs);
  return expiresAtMs
    ? { kind: 'known', expiresAtMs }
    : { kind: 'unavailable', reason: 'restored_record_has_no_expiry' };
}

function laneCandidateStepUpReason(
  candidate: EcdsaLaneCandidate | Ed25519LaneCandidate,
): FreshStepUpRequired['reason'] {
  switch (candidate.state) {
    case 'expired':
      return 'threshold_session_expired';
    case 'exhausted':
      return 'threshold_session_exhausted';
    case 'ready':
    case 'restorable':
    case 'deferred':
      throw new Error('[SigningEngine] lane candidate does not require fresh auth');
  }
}

function availableLaneServerIssuedGeneration(
  lane: ConcreteAvailableEcdsaSigningLane | ConcreteAvailableEd25519SigningLane,
): ServerIssuedGeneration | null {
  return serverIssuedGenerationFromNumber(lane.expiresAtMs ?? lane.policyHint?.expiresAtMs);
}

function availableLaneStatePriority(
  lane: AvailableEcdsaSigningLane | AvailableEd25519SigningLane,
): number {
  switch (lane.state) {
    case 'ready':
      return 5;
    case 'restorable':
      return 4;
    case 'deferred':
      return 3;
    case 'expired':
    case 'exhausted':
      return 2;
    case 'missing':
      return 1;
  }
}

function availableLaneSourcePriority(
  lane: AvailableEcdsaSigningLane | AvailableEd25519SigningLane,
): number {
  if (!isConcreteAvailableSigningLane(lane)) return 0;
  if (lane.curve === 'ecdsa') return 0;
  if (lane.source === 'active_execution_bundle') return 2;
  return lane.source === 'durable_sealed_record' ? 1 : 0;
}

function compareAvailableLanePriority(
  left: AvailableEcdsaSigningLane | AvailableEd25519SigningLane,
  right: AvailableEcdsaSigningLane | AvailableEd25519SigningLane,
): number {
  const stateDelta = availableLaneStatePriority(left) - availableLaneStatePriority(right);
  if (stateDelta) return stateDelta;
  const sourceDelta = availableLaneSourcePriority(left) - availableLaneSourcePriority(right);
  if (sourceDelta) return sourceDelta;
  return availableLaneUpdatedAtMs(left) - availableLaneUpdatedAtMs(right);
}

function compareEd25519AvailableLanePriority(
  left: AvailableEd25519SigningLane,
  right: AvailableEd25519SigningLane,
): number {
  return compareAvailableLanePriority(left, right);
}

function compareEd25519DuplicateLanePriority(
  left: AvailableEd25519SigningLane,
  right: AvailableEd25519SigningLane,
): number {
  const stateDelta = availableLaneStatePriority(left) - availableLaneStatePriority(right);
  if (stateDelta) return stateDelta;
  const sourceDelta = availableLaneSourcePriority(left) - availableLaneSourcePriority(right);
  if (sourceDelta) return sourceDelta;
  return availableLaneUpdatedAtMs(left) - availableLaneUpdatedAtMs(right);
}

type Ed25519LaneGroupKey = {
  walletId: string;
  authKey: string;
  nearAccountId: string;
  nearEd25519SigningKeyId: string;
  signerSlot: string;
  materialActivationKey: string;
};

type Ed25519LaneRecordFact = {
  groupKey: Ed25519LaneGroupKey;
  lane: ConcreteAvailableEd25519SigningLane;
};

function ed25519LaneGroupKey(
  lane: ConcreteAvailableEd25519SigningLane,
): Ed25519LaneGroupKey | null {
  const authKey = signingLaneAuthBindingKey(lane.auth);
  const walletId = String(lane.walletId || '').trim();
  const nearAccountId = String(lane.nearAccountId || '').trim();
  const nearEd25519SigningKeyId = String(lane.nearEd25519SigningKeyId || '').trim();
  const signerSlot = String(lane.signerSlot || '').trim();
  const materialActivationKeyValue = materialActivationKey(lane.materialActivation);
  if (
    !authKey ||
    !walletId ||
    !nearAccountId ||
    !nearEd25519SigningKeyId ||
    !signerSlot ||
    !materialActivationKeyValue
  ) {
    return null;
  }
  return {
    walletId,
    authKey,
    nearAccountId,
    nearEd25519SigningKeyId,
    signerSlot,
    materialActivationKey: materialActivationKeyValue,
  };
}

function ed25519LaneGroupKeyString(key: Ed25519LaneGroupKey): string {
  return [
    key.walletId,
    key.authKey,
    key.nearAccountId,
    key.nearEd25519SigningKeyId,
    key.signerSlot,
    key.materialActivationKey,
  ]
    .map((part) => encodeURIComponent(part))
    .join('|');
}

function ed25519LaneRecordFact(lane: AvailableEd25519SigningLane): Ed25519LaneRecordFact | null {
  if (!isConcreteAvailableSigningLane(lane) || lane.curve !== 'ed25519') return null;
  const groupKey = ed25519LaneGroupKey(lane);
  if (!groupKey) return null;
  return { groupKey, lane };
}

function compareEd25519AvailableLanePriorityDescending(
  left: AvailableEd25519SigningLane,
  right: AvailableEd25519SigningLane,
): number {
  return compareEd25519AvailableLanePriority(right, left);
}

function canonicalTieBreakFromNumber(left: number, right: number): CanonicalTieBreakOrder {
  if (left > right) return 1;
  if (right > left) return -1;
  return 0;
}

function canonicalTieBreakFromString(left: string, right: string): CanonicalTieBreakOrder {
  const comparison = left.localeCompare(right);
  if (comparison > 0) return 1;
  if (comparison < 0) return -1;
  return 0;
}

function firstCanonicalTieBreakResult(
  results: readonly CanonicalTieBreakOrder[],
): CanonicalTieBreakOrder {
  for (const result of results) {
    if (result !== 0) return result;
  }
  return 0;
}

type Ed25519LaneConflict = never;

function ed25519LaneGroupConflicts(
  _facts: readonly Ed25519LaneRecordFact[],
): readonly Ed25519LaneConflict[] {
  return [];
}

function isEd25519CanonicalFactOperationUsable(_fact: Ed25519LaneRecordFact): boolean {
  return true;
}

function ed25519CanonicalFactGeneration(
  fact: Ed25519LaneRecordFact,
): ServerIssuedGeneration | null {
  return availableLaneServerIssuedGeneration(fact.lane);
}

function ed25519CanonicalFactExactness(): 'exact_target' {
  return 'exact_target';
}

function ed25519CanonicalTieBreak(
  left: Ed25519LaneRecordFact,
  right: Ed25519LaneRecordFact,
): CanonicalTieBreakOrder {
  return firstCanonicalTieBreakResult([
    canonicalTieBreakFromNumber(
      availableLaneStatePriority(left.lane),
      availableLaneStatePriority(right.lane),
    ),
    canonicalTieBreakFromNumber(
      availableLaneSourcePriority(left.lane),
      availableLaneSourcePriority(right.lane),
    ),
    canonicalTieBreakFromString(
      ed25519CanonicalStableTieBreakKey(left.lane),
      ed25519CanonicalStableTieBreakKey(right.lane),
    ),
  ]);
}

function ed25519CanonicalStableTieBreakKey(lane: ConcreteAvailableEd25519SigningLane): string {
  return [
    lane.thresholdSessionId,
    lane.authorizationState === 'authorized' ? lane.authorization.walletSessionId : '',
    lane.authorizationState === 'authorized' ? lane.authorization.quotaId : '',
    lane.source || 'durable_sealed_record',
  ]
    .map((part) => String(part))
    .join('|');
}

const ed25519CanonicalSupersession: CanonicalFactSupersession<Ed25519LaneRecordFact> = {
  isOperationUsable: isEd25519CanonicalFactOperationUsable,
  generation: ed25519CanonicalFactGeneration,
  exactness: ed25519CanonicalFactExactness,
  tieBreak: ed25519CanonicalTieBreak,
};

const ed25519CanonicalLaneInventoryAdapter: CanonicalLaneInventoryAdapter<
  Ed25519LaneRecordFact,
  Ed25519LaneGroupKey,
  Ed25519LaneConflict
> = {
  groupKey: ed25519RecordFactGroupKey,
  groupKeyString: ed25519LaneGroupKeyString,
  groupConflicts: ed25519LaneGroupConflicts,
  supersession: ed25519CanonicalSupersession,
};

function ed25519RecordFactGroupKey(fact: Ed25519LaneRecordFact): Ed25519LaneGroupKey {
  return fact.groupKey;
}

function ed25519FactsByGroup(
  facts: readonly Ed25519LaneRecordFact[],
): Map<string, Ed25519LaneRecordFact[]> {
  const groups = new Map<string, Ed25519LaneRecordFact[]>();
  for (const fact of facts) {
    const groupKey = ed25519LaneGroupKeyString(fact.groupKey);
    groups.set(groupKey, [...(groups.get(groupKey) || []), fact]);
  }
  return groups;
}

function canonicalizeEd25519FactGroup(
  facts: readonly Ed25519LaneRecordFact[],
  invalidLanes: InvalidAvailableSigningLaneDiagnostic[],
): AvailableEd25519SigningLane[] {
  const selection = canonicalizeLaneFacts(facts, ed25519CanonicalLaneInventoryAdapter);
  switch (selection.kind) {
    case 'selected':
      return [selection.selectedFact.lane];
    case 'no_current_lane':
      return [];
    case 'conflicting_key_material':
      invalidLanes.push({
        curve: 'ed25519',
        source: 'canonical_lane_inventory',
        reason: 'conflicting_key_material',
        message: 'Ed25519 canonical lane inventory has conflicting material facts',
      });
      return [];
    case 'ambiguous_material':
      invalidLanes.push({
        curve: 'ed25519',
        source: 'canonical_lane_inventory',
        reason: 'ambiguous_material',
        message: 'Ed25519 canonical lane inventory has incomparable usable records',
      });
      return [];
    default: {
      const exhaustive: never = selection;
      return exhaustive;
    }
  }
}

function canonicalizeEd25519AvailableLanes(
  candidates: readonly AvailableEd25519SigningLane[],
  invalidLanes: InvalidAvailableSigningLaneDiagnostic[],
): AvailableEd25519SigningLane[] {
  const facts = candidates
    .map(ed25519LaneRecordFact)
    .filter((fact): fact is Ed25519LaneRecordFact => fact !== null);
  const canonicalLanes: AvailableEd25519SigningLane[] = [];
  for (const factGroup of ed25519FactsByGroup(facts).values()) {
    canonicalLanes.push(...canonicalizeEd25519FactGroup(factGroup, invalidLanes));
  }
  return canonicalLanes.sort(compareEd25519AvailableLanePriorityDescending);
}

function ed25519CompanionIdentityKey(lane: AvailableEd25519SigningLane): string | null {
  if (!isConcreteAvailableSigningLane(lane) || lane.curve !== 'ed25519') return null;
  const thresholdSessionId = String(lane.thresholdSessionId || '').trim();
  if (lane.authorizationState !== 'authorized' || !thresholdSessionId) return null;
  return `${lane.authorization.walletSessionId}:${lane.authorization.quotaId}:${thresholdSessionId}`;
}

function emailOtpPreferredEd25519PrimaryLane(args: {
  primaryLane: AvailableEd25519SigningLane;
  candidates: AvailableEd25519SigningLane[];
}): AvailableEd25519SigningLane {
  if (
    !isConcreteAvailableSigningLane(args.primaryLane) ||
    args.primaryLane.curve !== 'ed25519' ||
    availableEd25519SigningLaneAuthMethod(args.primaryLane) !== 'passkey'
  ) {
    return args.primaryLane;
  }
  const primaryKey = ed25519CompanionIdentityKey(args.primaryLane);
  if (!primaryKey) return args.primaryLane;
  const emailOtpLane = args.candidates.find(
    (candidate) =>
      isConcreteAvailableSigningLane(candidate) &&
      candidate.curve === 'ed25519' &&
      availableEd25519SigningLaneAuthMethod(candidate) === 'email_otp' &&
      ed25519CompanionIdentityKey(candidate) === primaryKey,
  );
  return emailOtpLane || args.primaryLane;
}

function isAvailableSigningLaneDiagnosticsEnabled(): boolean {
  try {
    const storage = (globalThis as { localStorage?: Storage }).localStorage;
    return storage?.getItem('seams:debug:signing-session') === '1';
  } catch {
    return false;
  }
}

function summarizeEcdsaLaneForDiagnostics(
  lane: AvailableEcdsaSigningLane | null | undefined,
): Record<string, unknown> {
  if (!lane) return { present: false };
  if (!isConcreteAvailableSigningLane(lane)) {
    if (lane.source === 'active_execution_bundle') {
      return {
        present: true,
        authMethod: signingLaneAuthMethod(lane.auth),
        curve: lane.curve,
        chainTarget: lane.chainTarget,
        targetKey: thresholdEcdsaChainTargetKey(lane.chainTarget),
        state: lane.state,
        source: lane.source,
        walletId: lane.laneIdentity.walletId,
        laneId: lane.laneIdentity.laneId,
        laneShareEpoch: lane.laneIdentity.laneShareEpoch,
        materialActivationId: lane.materialActivation.activationId,
        publicIdentityDigestB64u: lane.laneIdentity.publicIdentityDigestB64u,
        remainingUses: lane.remainingUses,
        expiresAtMs: lane.expiresAtMs,
        updatedAtMs: lane.updatedAtMs,
      };
    }
    return {
      present: true,
      curve: lane.curve,
      chainTarget: lane.chainTarget,
      state: lane.state,
    };
  }
  return {
    present: true,
    authMethod: signingLaneAuthMethod(lane.auth),
    curve: lane.curve,
    keyHandle: lane.publicFacts.keyHandle,
    walletId: lane.key.walletId,
    chainTarget: lane.chainTarget,
    targetKey: thresholdEcdsaChainTargetKey(lane.chainTarget),
    state: lane.state,
    source: lane.source,
    evmFamilyKeyFingerprint: deriveAvailableEcdsaLaneFingerprint(lane),
    ecdsaThresholdKeyId: lane.key.ecdsaThresholdKeyId,
    participantIds: lane.publicFacts.participantIds,
    thresholdOwnerAddress: lane.publicFacts.thresholdOwnerAddress,
    remainingUses: lane.remainingUses,
    expiresAtMs: lane.expiresAtMs,
    updatedAtMs: lane.updatedAtMs,
  };
}

function ecdsaLaneRecordFactSource(
  _lane: ConcreteAvailableEcdsaSigningLane,
): EcdsaLaneRecordFactSource {
  return 'canonical_capability';
}

function ecdsaLaneGroupKey(lane: ConcreteAvailableEcdsaSigningLane): EcdsaLaneGroupKey | null {
  const authKey = signingLaneAuthBindingKey(lane.auth);
  return {
    walletId: String(lane.key.walletId),
    authKey,
    materialActivationKey: materialActivationKey(lane.materialActivation),
    ecdsaThresholdKeyId: String(lane.key.ecdsaThresholdKeyId),
    signingRootId: String(lane.key.signingRootId),
    signingRootVersion: String(lane.key.signingRootVersion || 'default'),
  };
}

function ecdsaLaneGroupKeyString(key: EcdsaLaneGroupKey): string {
  return [
    key.walletId,
    key.authKey,
    key.materialActivationKey,
    key.ecdsaThresholdKeyId,
    key.signingRootId,
    key.signingRootVersion,
  ]
    .map((part) => encodeURIComponent(part))
    .join('|');
}

function ecdsaLaneRecordFact(lane: ConcreteAvailableEcdsaSigningLane): EcdsaLaneRecordFact | null {
  const groupKey = ecdsaLaneGroupKey(lane);
  if (!groupKey) return null;
  return {
    source: ecdsaLaneRecordFactSource(lane),
    groupKey,
    chainTargetKey: thresholdEcdsaChainTargetKey(lane.chainTarget),
    lane,
  };
}

function ecdsaLaneFamilyGroupKeyString(lane: ConcreteAvailableEcdsaSigningLane): string | null {
  const authKey = signingLaneAuthBindingKey(lane.auth);
  return [
    String(lane.key.walletId),
    authKey,
    materialActivationKey(lane.materialActivation),
    String(lane.key.signingRootId),
    String(lane.key.signingRootVersion || 'default'),
  ]
    .map((part) => encodeURIComponent(part))
    .join('|');
}

function ecdsaCanonicalPublicFactValues(
  facts: readonly EcdsaLaneRecordFact[],
  read: (lane: ConcreteAvailableEcdsaSigningLane) => string,
): string[] {
  return [...new Set(facts.map((fact) => read(fact.lane)).filter(Boolean))].sort();
}

function ecdsaLaneGroupConflicts(group: EcdsaLaneGroup): EcdsaLaneConflict[] {
  const fields = [
    {
      field: 'ecdsaThresholdKeyId' as const,
      values: ecdsaCanonicalPublicFactValues(group.facts, (lane) =>
        String(lane.key.ecdsaThresholdKeyId || ''),
      ),
    },
    {
      field: 'thresholdOwnerAddress' as const,
      values: ecdsaCanonicalPublicFactValues(group.facts, (lane) =>
        String(lane.publicFacts.thresholdOwnerAddress || '').toLowerCase(),
      ),
    },
    {
      field: 'keyHandle' as const,
      values: ecdsaCanonicalPublicFactValues(group.facts, (lane) =>
        String(lane.publicFacts.keyHandle || ''),
      ),
    },
    {
      field: 'publicKeyB64u' as const,
      values: ecdsaCanonicalPublicFactValues(group.facts, (lane) =>
        String(lane.publicFacts.publicKeyB64u || ''),
      ),
    },
    {
      field: 'participantIds' as const,
      values: ecdsaCanonicalPublicFactValues(group.facts, (lane) =>
        lane.publicFacts.participantIds.map((participantId) => Number(participantId)).join(','),
      ),
    },
  ];
  return fields
    .filter((entry) => entry.values.length > 1)
    .map((entry) => ({
      groupKey: group.key,
      field: entry.field,
      values: entry.values,
    }));
}

function ecdsaFamilyGroupConflicts(
  facts: readonly EcdsaLaneRecordFact[],
): Map<string, EcdsaLaneConflict[]> {
  const factsByFamilyGroup = new Map<string, EcdsaLaneRecordFact[]>();
  for (const fact of facts) {
    const familyGroupKey = ecdsaLaneFamilyGroupKeyString(fact.lane);
    if (!familyGroupKey) continue;
    factsByFamilyGroup.set(familyGroupKey, [
      ...(factsByFamilyGroup.get(familyGroupKey) || []),
      fact,
    ]);
  }
  const conflictsByFamilyGroup = new Map<string, EcdsaLaneConflict[]>();
  for (const [familyGroupKey, groupFacts] of factsByFamilyGroup) {
    const firstFact = groupFacts[0];
    if (!firstFact) continue;
    const conflicts = ecdsaLaneGroupConflicts({
      key: firstFact.groupKey,
      facts: groupFacts,
    });
    if (conflicts.length) {
      conflictsByFamilyGroup.set(familyGroupKey, conflicts);
    }
  }
  return conflictsByFamilyGroup;
}

function ecdsaFactFamilyConflicts(args: {
  fact: EcdsaLaneRecordFact;
  conflictsByFamilyGroup: Map<string, EcdsaLaneConflict[]>;
}): readonly EcdsaLaneConflict[] {
  const familyGroupKey = ecdsaLaneFamilyGroupKeyString(args.fact.lane);
  if (!familyGroupKey) return [];
  return args.conflictsByFamilyGroup.get(familyGroupKey) || [];
}

function ecdsaRecordFactsForCandidates(
  candidates: readonly AvailableEcdsaSigningLane[],
): EcdsaLaneRecordFact[] {
  return candidates
    .filter(
      (candidate): candidate is ConcreteAvailableEcdsaSigningLane =>
        isConcreteAvailableSigningLane(candidate) && candidate.curve === 'ecdsa',
    )
    .map(ecdsaLaneRecordFact)
    .filter((fact): fact is EcdsaLaneRecordFact => fact !== null);
}

function ecdsaCanonicalSourcePriority(_lane: ConcreteAvailableEcdsaSigningLane): number {
  return 1;
}

function ecdsaCanonicalFactGroupKey(fact: EcdsaLaneRecordFact): EcdsaLaneGroupKey {
  return fact.groupKey;
}

function ecdsaCanonicalGroupConflicts(
  facts: readonly EcdsaLaneRecordFact[],
): readonly EcdsaLaneConflict[] {
  const firstFact = facts[0];
  if (!firstFact) return [];
  return ecdsaLaneGroupConflicts({ key: firstFact.groupKey, facts });
}

function isEcdsaCanonicalFactOperationUsable(fact: EcdsaLaneRecordFact): boolean {
  return (
    fact.lane.state !== 'deferred' ||
    (fact.lane.source === 'canonical_capability' && !fact.lane.authorization)
  );
}

function ecdsaCanonicalFactGeneration(fact: EcdsaLaneRecordFact): ServerIssuedGeneration | null {
  return availableLaneServerIssuedGeneration(fact.lane);
}

function ecdsaCanonicalFactExactness(_fact: EcdsaLaneRecordFact): 'exact_target' {
  return 'exact_target';
}

function ecdsaCanonicalStableTieBreakKey(lane: ConcreteAvailableEcdsaSigningLane): string {
  return [
    materialActivationKey(lane.materialActivation),
    lane.source,
    thresholdEcdsaChainTargetKey(lane.chainTarget),
  ]
    .map((part) => String(part))
    .join('|');
}

function ecdsaCanonicalTieBreak(
  left: EcdsaLaneRecordFact,
  right: EcdsaLaneRecordFact,
): CanonicalTieBreakOrder {
  return firstCanonicalTieBreakResult([
    canonicalTieBreakFromNumber(
      availableLaneStatePriority(left.lane),
      availableLaneStatePriority(right.lane),
    ),
    canonicalTieBreakFromNumber(
      ecdsaCanonicalSourcePriority(left.lane),
      ecdsaCanonicalSourcePriority(right.lane),
    ),
    canonicalTieBreakFromString(
      ecdsaCanonicalStableTieBreakKey(left.lane),
      ecdsaCanonicalStableTieBreakKey(right.lane),
    ),
  ]);
}

const ecdsaCanonicalSupersession: CanonicalFactSupersession<EcdsaLaneRecordFact> = {
  isOperationUsable: isEcdsaCanonicalFactOperationUsable,
  generation: ecdsaCanonicalFactGeneration,
  exactness: ecdsaCanonicalFactExactness,
  tieBreak: ecdsaCanonicalTieBreak,
};

const ecdsaCanonicalLaneInventoryAdapter: CanonicalLaneInventoryAdapter<
  EcdsaLaneRecordFact,
  EcdsaLaneGroupKey,
  EcdsaLaneConflict
> = {
  groupKey: ecdsaCanonicalFactGroupKey,
  groupKeyString: ecdsaLaneGroupKeyString,
  groupConflicts: ecdsaCanonicalGroupConflicts,
  supersession: ecdsaCanonicalSupersession,
};

function ecdsaGroupKeysForFacts(facts: readonly EcdsaLaneRecordFact[]): EcdsaLaneGroupKey[] {
  const groupKeysByEncodedKey = new Map<string, EcdsaLaneGroupKey>();
  for (const fact of facts) {
    groupKeysByEncodedKey.set(ecdsaLaneGroupKeyString(fact.groupKey), fact.groupKey);
  }
  return [...groupKeysByEncodedKey.values()];
}

function canonicalEcdsaLaneSelectionForFacts(
  facts: readonly EcdsaLaneRecordFact[],
): EcdsaCanonicalLaneSelection {
  const selection = canonicalizeLaneFacts(facts, ecdsaCanonicalLaneInventoryAdapter);
  switch (selection.kind) {
    case 'selected':
      return {
        kind: 'selected',
        selectedFact: selection.selectedFact,
        supersededFacts: selection.supersededFacts,
      };
    case 'no_current_lane':
      return {
        kind: 'no_current_lane',
        unusableFacts: selection.unusableFacts,
      };
    case 'conflicting_key_material':
      return { kind: 'conflicting_key_material', conflicts: selection.conflicts };
    case 'ambiguous_material':
      return {
        kind: 'ambiguous_material',
        candidates: ecdsaGroupKeysForFacts(selection.candidates),
        candidateFacts: selection.candidates,
      };
    default: {
      const exhaustive: never = selection;
      return exhaustive;
    }
  }
}

function canonicalizeEcdsaAvailableLanes(args: {
  targets: readonly ThresholdEcdsaChainTarget[];
  candidatesByTarget: Record<string, AvailableEcdsaSigningLane[]>;
  invalidLanes: InvalidAvailableSigningLaneDiagnostic[];
}): {
  lanesByTarget: Record<string, AvailableEcdsaSigningLane>;
  candidatesByTarget: Record<string, AvailableEcdsaSigningLane[]>;
} {
  const canonicalCandidatesByTarget: Record<string, AvailableEcdsaSigningLane[]> = {};
  const canonicalLanesByTarget: Record<string, AvailableEcdsaSigningLane> = {};
  const allConcreteFacts = Object.values(args.candidatesByTarget).flatMap(
    ecdsaRecordFactsForCandidates,
  );
  const conflictsByFamilyGroup = ecdsaFamilyGroupConflicts(allConcreteFacts);
  for (const chainTarget of args.targets) {
    const targetKey = thresholdEcdsaChainTargetKey(chainTarget);
    const concreteFacts = ecdsaRecordFactsForCandidates(args.candidatesByTarget[targetKey] || []);
    const targetConflicts = concreteFacts.flatMap((fact) =>
      ecdsaFactFamilyConflicts({ fact, conflictsByFamilyGroup }),
    );
    if (targetConflicts.length) {
      args.invalidLanes.push({
        curve: 'ecdsa',
        source: 'canonical_lane_inventory',
        reason: 'conflicting_key_material',
        targetKey,
        groupKey: targetConflicts[0]?.groupKey,
        conflicts: targetConflicts,
      });
      canonicalCandidatesByTarget[targetKey] = [];
      canonicalLanesByTarget[targetKey] = emptyEcdsaLane({ chainTarget });
      continue;
    }
    const selection = canonicalEcdsaLaneSelectionForFacts(concreteFacts);
    switch (selection.kind) {
      case 'selected':
        canonicalCandidatesByTarget[targetKey] = [selection.selectedFact.lane];
        canonicalLanesByTarget[targetKey] = selection.selectedFact.lane;
        break;
      case 'no_current_lane':
        canonicalCandidatesByTarget[targetKey] = [];
        canonicalLanesByTarget[targetKey] = emptyEcdsaLane({ chainTarget });
        break;
      case 'conflicting_key_material':
        args.invalidLanes.push({
          curve: 'ecdsa',
          source: 'canonical_lane_inventory',
          reason: 'conflicting_key_material',
          targetKey,
          groupKey: selection.conflicts[0]?.groupKey,
          conflicts: selection.conflicts,
        });
        canonicalCandidatesByTarget[targetKey] = [];
        canonicalLanesByTarget[targetKey] = emptyEcdsaLane({ chainTarget });
        break;
      case 'ambiguous_material':
        args.invalidLanes.push({
          curve: 'ecdsa',
          source: 'canonical_lane_inventory',
          reason: 'ambiguous_material',
          targetKey,
        });
        canonicalCandidatesByTarget[targetKey] = [];
        canonicalLanesByTarget[targetKey] = emptyEcdsaLane({ chainTarget });
        break;
    }
  }
  return {
    lanesByTarget: canonicalLanesByTarget,
    candidatesByTarget: canonicalCandidatesByTarget,
  };
}

function collapseExactDuplicateAvailableLanes<
  TLane extends AvailableEcdsaSigningLane | AvailableEd25519SigningLane,
>(
  lanes: TLane[],
  laneIdentityKey: (lane: TLane) => string | null,
  comparePriority: (left: TLane, right: TLane) => number = compareAvailableLanePriority,
): TLane[] {
  const keyedGroups = new Map<string, TLane[]>();
  const unkeyed: TLane[] = [];
  for (const lane of lanes) {
    const key = laneIdentityKey(lane);
    if (!key) {
      unkeyed.push(lane);
      continue;
    }
    keyedGroups.set(key, [...(keyedGroups.get(key) || []), lane]);
  }
  const normalized = [...keyedGroups.values()].map(
    (group) => [...group].sort((left, right) => comparePriority(right, left))[0]!,
  );
  return [...normalized, ...unkeyed];
}

function suppressPublicEd25519CandidatesWithDurablePolicy(
  candidates: readonly AvailableEd25519SigningLane[],
): AvailableEd25519SigningLane[] {
  const durableGroupKeys = new Set(
    candidates
      .filter(
        (lane): lane is ConcreteAvailableEd25519SigningLane =>
          isConcreteAvailableSigningLane(lane) &&
          lane.curve === 'ed25519' &&
          lane.source === 'durable_sealed_record' &&
          (lane.state === 'ready' || lane.state === 'restorable'),
      )
      .map(ed25519LaneGroupKey)
      .filter((key): key is Ed25519LaneGroupKey => key !== null)
      .map(ed25519LaneGroupKeyString),
  );
  if (!durableGroupKeys.size) return [...candidates];
  return candidates.filter((lane) => {
    if (
      !isConcreteAvailableSigningLane(lane) ||
      lane.curve !== 'ed25519' ||
      lane.source !== 'public_capability_reference'
    ) {
      return true;
    }
    const groupKey = ed25519LaneGroupKey(lane);
    return !groupKey || !durableGroupKeys.has(ed25519LaneGroupKeyString(groupKey));
  });
}

/**
 * R103C owner-scope matching. Ed25519 lanes bind an owner's credential AND
 * signer slot; ECDSA lanes bind the credential alone. State stays untouched:
 * the scope decides whose lane it is, never whether it is usable.
 */
export function ed25519LaneMatchesOwnerScope(
  lane: AvailableEd25519SigningLane,
  scope: OwnerLaneScope,
): boolean {
  if (lane.state === 'missing') return false;
  if (signingLaneAuthBindingKey(lane.auth) !== signingLaneAuthBindingKey(scope.auth)) return false;
  if (scope.linkedOwner) {
    const linkedOwner = lane.linkedOwner;
    return (
      linkedOwner !== undefined &&
      linkedOwner.enrollmentId === scope.linkedOwner.enrollmentId &&
      linkedOwner.deviceId === scope.linkedOwner.deviceId &&
      linkedOwner.walletAuthMethodId === scope.linkedOwner.walletAuthMethodId &&
      linkedOwner.authorityDigest === scope.linkedOwner.authorityDigest
    );
  }
  return scope.auth.kind === 'email_otp' || lane.signerSlot === scope.signerSlot;
}

export function ecdsaLaneMatchesOwnerScope(
  lane: AvailableEcdsaSigningLane,
  scope: OwnerLaneScope,
): boolean {
  if (lane.state === 'missing') return false;
  if (signingLaneAuthBindingKey(lane.auth) !== signingLaneAuthBindingKey(scope.auth)) {
    return false;
  }
  if (!scope.linkedOwner) return true;
  const linkedOwner = lane.linkedOwner;
  return (
    linkedOwner !== undefined &&
    linkedOwner.enrollmentId === scope.linkedOwner.enrollmentId &&
    linkedOwner.deviceId === scope.linkedOwner.deviceId &&
    linkedOwner.walletAuthMethodId === scope.linkedOwner.walletAuthMethodId &&
    linkedOwner.authorityDigest === scope.linkedOwner.authorityDigest
  );
}

export async function readAvailableSigningLanes(
  input: ReadAvailableSigningLanesInput,
  ports: ReadAvailableSigningLanesPorts,
): Promise<AvailableSigningLanes> {
  const walletId = toWalletId(input.walletId);
  const ecdsaTargetsByKey = new Map<string, ThresholdEcdsaChainTarget>();
  for (const chainTarget of input.ecdsaChainTargets) {
    ecdsaTargetsByKey.set(thresholdEcdsaChainTargetKey(chainTarget), chainTarget);
  }
  const ecdsaChainTargets = [...ecdsaTargetsByKey.values()];
  const ed25519Records = await ports.listSealedRecordsForWallet({
    walletId,
    filter: {
      ...(input.authMethod ? { authMethod: input.authMethod } : {}),
      curve: 'ed25519',
    },
  });
  const publicCapabilityReferences = ports.listPublicCapabilityReferences
    ? await ports.listPublicCapabilityReferences()
    : [];
  const activeAuthorization = ports.readActiveWalletSessionAuthorization
    ? await ports.readActiveWalletSessionAuthorization(walletId)
    : null;
  const activeExecutionBundle = ports.readActiveExecutionBundleForWallet
    ? await ports.readActiveExecutionBundleForWallet({
        walletId,
        nowMs: input.nowMs ?? Date.now(),
      })
    : null;
  const ecdsaTargets = [...ecdsaChainTargets];
  const ecdsaLanesByTarget: Record<string, AvailableEcdsaSigningLane> = {};
  const ecdsaCandidatesByTarget: Record<string, AvailableEcdsaSigningLane[]> = {};
  const ecdsaLaneUpdatedAtMsByTarget: Record<string, number> = {};
  for (const chainTarget of ecdsaTargets) {
    const targetKey = thresholdEcdsaChainTargetKey(chainTarget);
    ecdsaLanesByTarget[targetKey] = emptyEcdsaLane({ chainTarget });
    ecdsaCandidatesByTarget[targetKey] = [];
    ecdsaLaneUpdatedAtMsByTarget[targetKey] = 0;
  }
  const ed25519Candidates: AvailableEd25519SigningLane[] = [];
  let generation = 0;
  const collectDiagnostics = isAvailableSigningLaneDiagnosticsEnabled();
  const runtimeEcdsaDiscovery: Record<string, unknown>[] = [];
  const invalidLanes: InvalidAvailableSigningLaneDiagnostic[] = [];

  for (const record of ed25519Records) {
    const lane = recordToEd25519Lane(record, activeAuthorization);
    if (!lane) continue;
    ed25519Candidates.push(lane);
    const updatedAtMs = availableLaneUpdatedAtMs(lane);
    generation = Math.max(generation, updatedAtMs);
  }
  for (const reference of publicCapabilityReferences) {
    if (String(reference.walletId) !== String(walletId)) continue;
    if (!ports.isPublicCapabilityActive?.(reference)) continue;
    const lane = publicCapabilityReferenceToEd25519Lane(reference, activeAuthorization);
    if (!lane) continue;
    if (input.authMethod && signingLaneAuthMethod(lane.auth) !== input.authMethod) continue;
    ed25519Candidates.push(lane);
  }
  if (activeExecutionBundle) {
    const lane = await activeExecutionBundleToEd25519Lane(
      activeExecutionBundle,
      activeAuthorization,
    );
    if (lane && (!input.authMethod || signingLaneAuthMethod(lane.auth) === input.authMethod)) {
      ed25519Candidates.push(lane);
      generation = Math.max(generation, availableLaneUpdatedAtMs(lane));
    }
  }
  for (const chainTarget of ecdsaTargets) {
    if (!ports.readActiveEcdsaExportContextForWallet) continue;
    const activeEcdsaExportContext = await ports.readActiveEcdsaExportContextForWallet({
      walletId,
      chainTarget,
      nowMs: input.nowMs ?? Date.now(),
    });
    if (!activeEcdsaExportContext) continue;
    const lane = activeExecutionBundleToEcdsaLane(activeEcdsaExportContext, activeAuthorization);
    const targetKey = lane ? thresholdEcdsaChainTargetKey(lane.chainTarget) : null;
    if (
      lane &&
      targetKey !== null &&
      ecdsaTargetsByKey.has(targetKey) &&
      (!input.authMethod || signingLaneAuthMethod(lane.auth) === input.authMethod)
    ) {
      ecdsaCandidatesByTarget[targetKey] ||= [];
      ecdsaCandidatesByTarget[targetKey].push(lane);
      generation = Math.max(generation, availableLaneUpdatedAtMs(lane));
      runtimeEcdsaDiscovery.push({
        result: 'accepted',
        targetKey,
        lane: summarizeEcdsaLaneForDiagnostics(lane),
      });
    }
  }
  const canonicalEcdsaLanes =
    ecdsaChainTargets.length > 0 && ports.listCanonicalEcdsaLanesForWallet
      ? await ports.listCanonicalEcdsaLanesForWallet({ walletId })
      : [];
  for (const lane of canonicalEcdsaLanes) {
    const authMethod = signingLaneAuthMethod(lane.auth);
    if (input.authMethod && authMethod !== input.authMethod) continue;
    if (String(lane.key.walletId) !== String(walletId)) continue;
    const targetKey = thresholdEcdsaChainTargetKey(lane.chainTarget);
    if (!ecdsaTargetsByKey.has(targetKey)) continue;
    ecdsaCandidatesByTarget[targetKey] ||= [];
    ecdsaCandidatesByTarget[targetKey].push(lane);
    const updatedAtMs = availableLaneUpdatedAtMs(lane);
    generation = Math.max(generation, updatedAtMs);
    runtimeEcdsaDiscovery.push({
      result: 'accepted',
      targetKey,
      lane: summarizeEcdsaLaneForDiagnostics(lane),
    });
  }

  // R103C: filter to the exact owner BEFORE canonicalization. A sibling
  // owner's lanes must not participate in duplicate collapse, priority
  // ordering, or canonical fact grouping for this owner's operation.
  const ownerScope = input.ownerScope;
  const ownerScopedEd25519Candidates = ownerScope
    ? ed25519Candidates.filter((lane) => ed25519LaneMatchesOwnerScope(lane, ownerScope))
    : ed25519Candidates;
  if (ownerScope) {
    for (const targetKey of Object.keys(ecdsaCandidatesByTarget)) {
      ecdsaCandidatesByTarget[targetKey] = (ecdsaCandidatesByTarget[targetKey] || []).filter(
        (lane) => ecdsaLaneMatchesOwnerScope(lane, ownerScope),
      );
    }
  }

  const policyBoundEd25519Candidates = suppressPublicEd25519CandidatesWithDurablePolicy(
    ownerScopedEd25519Candidates,
  );
  const normalizedEd25519Candidates = collapseExactDuplicateAvailableLanes(
    policyBoundEd25519Candidates,
    ed25519AvailableLaneIdentityKey,
    compareEd25519DuplicateLanePriority,
  ).sort(compareEd25519AvailableLanePriorityDescending);
  const activeEd25519Candidates = canonicalizeEd25519AvailableLanes(
    normalizedEd25519Candidates,
    invalidLanes,
  );
  const primaryEd25519Lane = activeEd25519Candidates[0] || emptyEd25519Lane();
  const preferredEd25519Lane = emailOtpPreferredEd25519PrimaryLane({
    primaryLane: primaryEd25519Lane,
    candidates: activeEd25519Candidates,
  });
  const canonicalEcdsaSources = canonicalizeEcdsaAvailableLanes({
    targets: ecdsaTargets,
    candidatesByTarget: ecdsaCandidatesByTarget,
    invalidLanes,
  });
  const canonicalEcdsaAvailableLanes = canonicalizeEcdsaAvailableLanes({
    targets: ecdsaTargets,
    candidatesByTarget: canonicalEcdsaSources.candidatesByTarget,
    invalidLanes,
  });
  const ecdsaCandidatesWithActiveExecutionBundle: Record<string, AvailableEcdsaSigningLane[]> = {};
  const ecdsaLanesWithActiveExecutionBundle: Record<string, AvailableEcdsaSigningLane> = {};
  for (const chainTarget of ecdsaTargets) {
    const targetKey = thresholdEcdsaChainTargetKey(chainTarget);
    const activeCandidates = (ecdsaCandidatesByTarget[targetKey] || []).filter(
      (candidate): candidate is ActiveExecutionBundleEcdsaSigningLane =>
        candidate.source === 'active_execution_bundle',
    );
    const canonicalCandidates = canonicalEcdsaAvailableLanes.candidatesByTarget[targetKey] || [];
    ecdsaCandidatesWithActiveExecutionBundle[targetKey] = [
      ...activeCandidates,
      ...canonicalCandidates,
    ];
    ecdsaLanesWithActiveExecutionBundle[targetKey] =
      activeCandidates[0] ||
      canonicalEcdsaAvailableLanes.lanesByTarget[targetKey] ||
      emptyEcdsaLane({ chainTarget });
  }

  const availableLanes: AvailableSigningLanes = {
    walletId,
    generation,
    ecdsa: {
      targets: ecdsaTargets,
      lanesByTarget: ecdsaLanesWithActiveExecutionBundle,
      candidatesByTarget: ecdsaCandidatesWithActiveExecutionBundle,
    },
    lanes: {
      ed25519: {
        near: preferredEd25519Lane,
      },
    },
    candidates: {
      ed25519: {
        near: activeEd25519Candidates,
      },
    },
    diagnostics: {
      invalidLanes,
    },
  };
  const missingEcdsaTargets = ecdsaTargets
    .map((target) => {
      const targetKey = thresholdEcdsaChainTargetKey(target);
      const candidates = availableLanes.ecdsa.candidatesByTarget[targetKey] || [];
      const selectedLane = availableLanes.ecdsa.lanesByTarget[targetKey];
      const selectedLaneState = selectedLane?.state || 'missing';
      if (candidates.length > 0 && selectedLaneState !== 'missing') return null;
      return {
        chainTarget: target,
        targetKey,
        candidateCount: candidates.length,
        selectedLane: summarizeEcdsaLaneForDiagnostics(selectedLane),
      };
    })
    .filter((entry): entry is NonNullable<typeof entry> => Boolean(entry));
  const laneDiagnosticPayload = {
    walletId,
    authMethod: input.authMethod || 'any',
    requestedTargets: ecdsaTargets.map((target) => ({
      chainTarget: target,
      targetKey: thresholdEcdsaChainTargetKey(target),
    })),
    sealedRecordCount: 0,
    runtimeRecordCount: canonicalEcdsaLanes.length,
    durableDiscovery: [],
    runtimeDiscovery: runtimeEcdsaDiscovery,
    resultSelectedLanesByTarget: Object.fromEntries(
      Object.entries(availableLanes.ecdsa.lanesByTarget).map(([targetKey, lane]) => [
        targetKey,
        summarizeEcdsaLaneForDiagnostics(lane),
      ]),
    ),
    resultCandidatesByTarget: Object.fromEntries(
      Object.entries(availableLanes.ecdsa.candidatesByTarget).map(([targetKey, lanes]) => [
        targetKey,
        lanes.map((lane) => summarizeEcdsaLaneForDiagnostics(lane)),
      ]),
    ),
  };
  if (collectDiagnostics && missingEcdsaTargets.length > 0) {
    try {
      console.warn(
        '[SigningLanes][available][ecdsa][missing-candidates]',
        JSON.stringify({
          ...laneDiagnosticPayload,
          missingEcdsaTargets,
        }),
      );
    } catch {}
  }
  if (collectDiagnostics) {
    try {
      console.info('[SigningLanes][available][ecdsa]', JSON.stringify(laneDiagnosticPayload));
    } catch {}
  }
  return availableLanes;
}
