import type { NearResolvedEd25519SigningSessionState } from '@/core/signingEngine/interfaces/near';
import type { Ed25519YaoPublicCapabilityLaneReferenceV1 } from '@/core/signingEngine/threshold/ed25519/yaoPublicCapabilityReferences';
import { IndexedDBManager } from '@/core/indexedDB';
import {
  openEd25519YaoRecoverySourceV1,
  sealEd25519YaoRecoverySourceV1,
  type Ed25519YaoRecoverySourceIdentityV1,
} from '@/core/signingEngine/session/passkey/ed25519YaoRecoverySource';
import {
  buildPreparedNearEd25519YaoRecoveryJournalV1,
  finalizeCancelledPromotedNearEd25519YaoRecoveryV1,
  finalizePromotionCommittedNearEd25519YaoRecoveryV1,
  persistPreparedNearEd25519YaoRecoveryJournalV1,
  persistPromotionCommittedNearEd25519YaoRecoveryV1,
  readNearEd25519YaoRecoveryJournalV1,
  requestCancelNearEd25519YaoRecoveryV1,
  type NearEd25519YaoRecoveryCommitJournalV1,
} from '@/core/signingEngine/session/passkey/ed25519YaoRecoveryJournal';
import {
  buildPromotedPasskeyEd25519YaoLocalMaterialRecordV1,
  rehydratePasskeyEd25519YaoLocalMaterialRecordV1,
  type PasskeyEd25519YaoLocalMaterialTargetV1,
} from '@/core/signingEngine/session/passkey/ed25519YaoLocalMaterial';
import { buildPasskeyRouterAbEd25519WalletSessionState } from '@/core/signingEngine/session/warmCapabilities/routerAbEd25519WalletSessionState';
import {
  buildRouterAbEd25519SigningWalletSession,
  parseRouterAbEd25519WalletSessionIdentityClaims,
} from '@/core/signingEngine/session/routerAbSigningWalletSession';
import { toWalletId } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import { toRpId } from '@/core/signingEngine/session/identity/evmFamilyEcdsaIdentity';
import {
  RouterAbEd25519YaoClientV1,
  RouterAbEd25519YaoHttpActivationTransportV1,
  createRouterAbEd25519YaoActivationEntropyV1,
  readRouterAbEd25519YaoRecoveryStatusV1,
  zeroizeRouterAbEd25519YaoActivationEntropyV1,
  type RouterAbEd25519YaoActiveClientV1,
  type RouterAbEd25519YaoRecoveryTransportV1,
  type RouterAbEd25519YaoRecoveryResultV1,
} from '@/core/signingEngine/threshold/ed25519/yaoClient';
import { toAccountId, type AccountId } from '@/core/types/accountIds';
import { base58Encode } from '@shared/utils/base58';
import {
  normalizeRuntimePolicyScope,
  signingRootScopeFromRuntimePolicyScope,
} from '@shared/threshold/signingRootScope';
import { walletIdFromString, type WalletId } from '@shared/utils/registrationIntent';
import { nearEd25519SigningKeyIdFromString } from '@shared/utils/registrationIntent';
import {
  buildMpcMaterialActivationRef,
  mpcMaterialActivationRefsEqual,
  parseMpcMaterialActivationId,
  parseMpcLifecycleBindingRef,
  parseThresholdEd25519SessionId,
  type MpcMaterialActivationRef,
  type ThresholdEd25519SessionId,
} from '@shared/utils/domainIds';
import {
  parseRouterAbEd25519YaoRecoveryAdmissionRequestV1,
  parseRouterAbEd25519YaoRegistrationActivationAdmissionReceiptV1,
  parseRouterAbEd25519YaoRegistrationAdmissionRequestV1,
  type RouterAbEd25519YaoActivationAdmissionReceiptV1,
  type RouterAbEd25519YaoRecoveryAdmissionRequestV1,
  type RouterAbEd25519YaoRegistrationAdmissionRequestV1,
} from '@shared/utils/routerAbEd25519Yao';
import {
  parsePasskeyCustodyEnvelopeRecord,
  type PasskeyCustodyEnvelopeRecord,
} from '@shared/passkey-custody';
import { secureRandomId } from '@shared/utils/secureRandomId';
import { parseRouterAbEd25519NormalSigningState } from '@shared/utils/signingSessionSeal';
import { isPlainObject } from '@shared/utils/validation';
import {
  routerAbMpcMaterialActivationRefFromWire,
  routerAbMpcMaterialActivationRefToWire,
} from '@shared/utils/routerAbNormalSigningIdentity';
import { parseMpcMaterialOwnerRef, type MpcMaterialOwnerRef } from '@shared/utils/domainIds';
import {
  parseWalletAuthAuthorityRef,
  type WalletAuthAuthorityRef,
} from '@shared/utils/walletAuthAuthority';
import {
  parseMpcWalletSigningQuotaId,
  parseWalletSessionId,
  type MpcWalletSigningQuotaId,
  type WalletSessionId,
} from '@shared/authorization/capabilityKinds';

export type ParsedYaoRecoverySessionV1 = {
  readonly walletSessionJwt: string;
  readonly thresholdSessionId: string;
  readonly walletSessionId: WalletSessionId;
  readonly quotaId: MpcWalletSigningQuotaId;
  readonly expiresAtMs: number;
  readonly remainingUses: number;
  readonly runtimePolicyScope: ReturnType<typeof normalizeRuntimePolicyScope>;
  readonly participantIds: readonly [number, number];
  readonly routerAbNormalSigning: NonNullable<
    ReturnType<typeof parseRouterAbEd25519NormalSigningState>
  >;
};

export type ParsedYaoRecoveryCapabilityV1 = {
  readonly materialActivation: MpcMaterialActivationRef;
  readonly activeCapabilityBinding: readonly number[];
  readonly registeredPublicKey: readonly number[];
  readonly nearAccountId: AccountId;
  readonly applicationBinding: {
    readonly wallet_id: string;
    readonly near_ed25519_signing_key_id: string;
    readonly signing_root_id: string;
    readonly key_creation_signer_slot: number;
  };
  readonly participantIds: readonly [number, number];
  readonly runtimePolicyScope: ReturnType<typeof normalizeRuntimePolicyScope>;
  readonly lifecycle: {
    readonly lifecycleId: string;
    readonly rootShareEpoch: string;
    readonly accountId: string;
    readonly thresholdSessionId: ThresholdEd25519SessionId;
    readonly signerSetId: string;
    readonly signingWorkerId: string;
  };
  readonly stateEpoch: number;
  readonly registrationContinuity:
    | {
        readonly kind: 'registration';
        readonly admissionRequest: RouterAbEd25519YaoRegistrationAdmissionRequestV1;
        readonly admissionReceipt: RouterAbEd25519YaoActivationAdmissionReceiptV1<'registration'>;
        readonly activationTranscript: readonly number[];
      }
    | { readonly kind: 'recovery' };
};

export type ParsedPasskeyEd25519YaoRecoveryDescriptorV1 = {
  readonly authority: WalletAuthAuthorityRef;
  readonly walletId: WalletId;
  readonly nearAccountId: AccountId;
  readonly nearEd25519SigningKeyId: string;
  readonly signerSlot: number;
  readonly operationalPublicKey: string;
  readonly relayerKeyId: string;
  readonly credentialIdB64u: string;
  readonly session: ParsedYaoRecoverySessionV1;
  readonly capability: ParsedYaoRecoveryCapabilityV1;
};

function requireThresholdEd25519SessionId(
  value: unknown,
  label: string,
): ThresholdEd25519SessionId {
  const parsed = parseThresholdEd25519SessionId(value);
  if (!parsed.ok) {
    throw new Error(`${label} is invalid`);
  }
  return parsed.value;
}

export type ParsedPasskeyEd25519YaoSyncResponseV1 = ParsedPasskeyEd25519YaoRecoveryDescriptorV1 & {
  readonly credentialPublicKeyB64u: string;
  readonly walletCustody: {
    readonly envelope: PasskeyCustodyEnvelopeRecord;
    readonly storeVersion: string;
  };
};

export type PasskeyEd25519YaoRecoveryResultV1<
  TParsed extends ParsedPasskeyEd25519YaoRecoveryDescriptorV1 =
    ParsedPasskeyEd25519YaoSyncResponseV1,
> = {
  readonly activeClient: RouterAbEd25519YaoActiveClientV1;
  readonly walletSessionState: NearResolvedEd25519SigningSessionState;
  readonly parsed: TParsed;
};

export function passkeyEd25519YaoLaneReferenceFromRecovery(args: {
  walletSessionState: NearResolvedEd25519SigningSessionState;
  materialActivation: MpcMaterialActivationRef;
}): Ed25519YaoPublicCapabilityLaneReferenceV1 {
  const lane = args.walletSessionState.signingLane;
  if (lane.auth.kind !== 'passkey') {
    throw new Error('[SigningEngine][near] Passkey recovery returned another auth lane');
  }
  const signer = lane.identity.signer;
  return {
    walletId: signer.account.wallet.walletId,
    nearAccountId: signer.account.nearAccountId,
    thresholdSessionId: args.walletSessionState.thresholdSessionId,
    runtimePolicyScope: args.walletSessionState.runtimePolicyScope,
    materialActivation: args.materialActivation,
    auth: {
      kind: 'passkey',
      rpId: lane.auth.rpId,
      credentialIdB64u: lane.auth.credentialIdB64u,
    },
    nearEd25519SigningKeyId: signer.nearEd25519SigningKeyId,
    signerSlot: signer.signerSlot,
  };
}

function requireString(value: unknown, label: string): string {
  const parsed = typeof value === 'string' ? value.trim() : '';
  if (!parsed) throw new Error(`${label} is required`);
  return parsed;
}

function requirePositiveInteger(value: unknown, label: string): number {
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < 1) {
    throw new Error(`${label} must be a positive integer`);
  }
  return value;
}

function requireBytes32(value: unknown, label: string): readonly number[] {
  if (!Array.isArray(value) || value.length !== 32) {
    throw new Error(`${label} must contain exactly 32 bytes`);
  }
  const bytes: number[] = [];
  for (const byte of value) {
    if (typeof byte !== 'number' || !Number.isInteger(byte) || byte < 0 || byte > 255) {
      throw new Error(`${label} must contain exactly 32 bytes`);
    }
    bytes.push(byte);
  }
  return Object.freeze(bytes);
}

function requireBytes(value: unknown, label: string): readonly number[] {
  if (!Array.isArray(value) || value.length === 0) {
    throw new Error(`${label} must contain bytes`);
  }
  return value.map((byte) => {
    if (typeof byte !== 'number' || !Number.isInteger(byte) || byte < 0 || byte > 255) {
      throw new Error(`${label} must contain bytes`);
    }
    return byte;
  });
}

function parseRegistrationContinuity(
  value: unknown,
): ParsedYaoRecoveryCapabilityV1['registrationContinuity'] {
  const record = requireRecord(value, 'capability.registrationContinuity');
  if (record.kind === 'recovery') return { kind: 'recovery' };
  if (record.kind !== 'registration') {
    throw new Error('capability.registrationContinuity kind is invalid');
  }
  const admissionRequest = parseRouterAbEd25519YaoRegistrationAdmissionRequestV1(
    record.admissionRequest,
  );
  const admissionReceipt = parseRouterAbEd25519YaoRegistrationActivationAdmissionReceiptV1(
    record.admissionReceipt,
  );
  if (!admissionRequest.ok) {
    throw new Error(
      `capability registration continuity transcript is invalid: ${admissionRequest.message}`,
    );
  }
  if (!admissionReceipt.ok) {
    throw new Error(
      `capability registration continuity transcript is invalid: ${admissionReceipt.message}`,
    );
  }
  return {
    kind: 'registration',
    admissionRequest: admissionRequest.value,
    admissionReceipt: admissionReceipt.value,
    activationTranscript: requireBytes(
      record.activationTranscript,
      'capability.registrationContinuity.activationTranscript',
    ),
  };
}

function requireParticipantIds(value: unknown): readonly [number, number] {
  if (
    !Array.isArray(value) ||
    value.length !== 2 ||
    !Number.isSafeInteger(value[0]) ||
    !Number.isSafeInteger(value[1]) ||
    value[0] < 1 ||
    value[1] < 1 ||
    value[0] === value[1]
  ) {
    throw new Error('participantIds must contain two distinct positive integers');
  }
  return [Number(value[0]), Number(value[1])];
}

function requireRecord(value: unknown, label: string): Record<string, unknown> {
  if (!isPlainObject(value)) throw new Error(`${label} must be an object`);
  return value;
}

function parseRecoverySession(
  raw: Record<string, unknown>,
  participantIds: readonly [number, number],
  identity: {
    readonly walletId: string;
    readonly nearAccountId: string;
    readonly nearEd25519SigningKeyId: string;
  },
): ParsedYaoRecoverySessionV1 {
  if (raw.sessionKind !== 'jwt') throw new Error('Yao recovery session must use JWT');
  if (
    requireString(raw.walletId, 'session.walletId') !== identity.walletId ||
    requireString(raw.nearAccountId, 'session.nearAccountId') !== identity.nearAccountId ||
    requireString(raw.nearEd25519SigningKeyId, 'session.nearEd25519SigningKeyId') !==
      identity.nearEd25519SigningKeyId
  ) {
    throw new Error('Yao recovery session identity does not match the verified passkey');
  }
  const runtimePolicyRecord = requireRecord(raw.runtimePolicyScope, 'session.runtimePolicyScope');
  const runtimePolicyScope = normalizeRuntimePolicyScope(runtimePolicyRecord);
  const routerAbNormalSigning = parseRouterAbEd25519NormalSigningState(raw.routerAbNormalSigning);
  if (!routerAbNormalSigning) throw new Error('Yao recovery session signing state is invalid');
  const walletSessionId = parseWalletSessionId(raw.walletSessionId);
  const quotaId = parseMpcWalletSigningQuotaId(raw.quotaId);
  if (!walletSessionId.ok || !quotaId.ok) {
    throw new Error('Yao recovery Wallet Session identity is invalid');
  }
  return {
    walletSessionJwt: requireString(raw.walletSessionJwt, 'session.walletSessionJwt'),
    thresholdSessionId: requireString(raw.thresholdSessionId, 'session.thresholdSessionId'),
    walletSessionId: walletSessionId.value,
    quotaId: quotaId.value,
    expiresAtMs: requirePositiveInteger(raw.expiresAtMs, 'session.expiresAtMs'),
    remainingUses: requirePositiveInteger(raw.remainingUses, 'session.remainingUses'),
    runtimePolicyScope,
    participantIds,
    routerAbNormalSigning,
  };
}

export function parseEd25519YaoRecoveryCapabilityV1(raw: unknown): ParsedYaoRecoveryCapabilityV1 {
  const record = requireRecord(raw, 'capability');
  if (record.kind !== 'router_ab_ed25519_yao_active_capability_v1') {
    throw new Error('Yao recovery capability kind is invalid');
  }
  const application = requireRecord(record.applicationBinding, 'capability.applicationBinding');
  const lifecycle = requireRecord(record.lifecycle, 'capability.lifecycle');
  let materialActivation: MpcMaterialActivationRef;
  try {
    materialActivation = routerAbMpcMaterialActivationRefFromWire(record.materialActivation);
  } catch (error) {
    throw new Error(
      `capability.materialActivation is invalid: ${error instanceof Error ? error.message : String(error)}`,
    );
  }
  return {
    materialActivation,
    activeCapabilityBinding: requireBytes32(
      record.activeCapabilityBinding,
      'capability.activeCapabilityBinding',
    ),
    registeredPublicKey: requireBytes32(
      record.registeredPublicKey,
      'capability.registeredPublicKey',
    ),
    nearAccountId: toAccountId(requireString(record.nearAccountId, 'capability.nearAccountId')),
    applicationBinding: {
      wallet_id: requireString(application.wallet_id, 'applicationBinding.wallet_id'),
      near_ed25519_signing_key_id: requireString(
        application.near_ed25519_signing_key_id,
        'applicationBinding.near_ed25519_signing_key_id',
      ),
      signing_root_id: requireString(
        application.signing_root_id,
        'applicationBinding.signing_root_id',
      ),
      key_creation_signer_slot: requirePositiveInteger(
        application.key_creation_signer_slot,
        'applicationBinding.key_creation_signer_slot',
      ),
    },
    participantIds: requireParticipantIds(record.participantIds),
    runtimePolicyScope: normalizeRuntimePolicyScope(
      requireRecord(record.runtimePolicyScope, 'capability.runtimePolicyScope'),
    ),
    lifecycle: {
      lifecycleId: requireString(lifecycle.lifecycleId, 'lifecycle.lifecycleId'),
      rootShareEpoch: requireString(lifecycle.rootShareEpoch, 'lifecycle.rootShareEpoch'),
      accountId: requireString(lifecycle.accountId, 'lifecycle.accountId'),
      thresholdSessionId: requireThresholdEd25519SessionId(
        requireString(lifecycle.thresholdSessionId, 'lifecycle.thresholdSessionId'),
        'lifecycle.thresholdSessionId',
      ),
      signerSetId: requireString(lifecycle.signerSetId, 'lifecycle.signerSetId'),
      signingWorkerId: requireString(lifecycle.signingWorkerId, 'lifecycle.signingWorkerId'),
    },
    stateEpoch: requirePositiveInteger(record.stateEpoch, 'capability.stateEpoch'),
    registrationContinuity: parseRegistrationContinuity(record.registrationContinuity),
  };
}

function sameRuntimePolicyScope(
  left: ReturnType<typeof normalizeRuntimePolicyScope>,
  right: ReturnType<typeof normalizeRuntimePolicyScope>,
): boolean {
  return (
    left.orgId === right.orgId &&
    left.projectId === right.projectId &&
    left.envId === right.envId &&
    left.signingRootVersion === right.signingRootVersion
  );
}

function assertEd25519YaoRecoveryDescriptorStableIdentity(
  parsed: ParsedPasskeyEd25519YaoRecoveryDescriptorV1,
): void {
  const capability = parsed.capability;
  const session = parsed.session;
  const signingRoot = signingRootScopeFromRuntimePolicyScope(session.runtimePolicyScope);
  if (
    !signingRoot ||
    capability.applicationBinding.wallet_id !== String(parsed.walletId) ||
    capability.applicationBinding.near_ed25519_signing_key_id !== parsed.nearEd25519SigningKeyId ||
    capability.applicationBinding.key_creation_signer_slot !== parsed.signerSlot ||
    capability.nearAccountId !== parsed.nearAccountId ||
    capability.lifecycle.accountId !== String(parsed.walletId) ||
    capability.lifecycle.signingWorkerId !== parsed.relayerKeyId ||
    session.routerAbNormalSigning?.signingWorkerId !== parsed.relayerKeyId ||
    session.participantIds[0] !== capability.participantIds[0] ||
    session.participantIds[1] !== capability.participantIds[1] ||
    !sameRuntimePolicyScope(session.runtimePolicyScope, capability.runtimePolicyScope) ||
    session.runtimePolicyScope.signingRootVersion !== capability.lifecycle.rootShareEpoch ||
    capability.applicationBinding.signing_root_id !== signingRoot.signingRootId ||
    parsed.operationalPublicKey !==
      `ed25519:${base58Encode(Uint8Array.from(capability.registeredPublicKey))}`
  ) {
    throw new Error('Yao recovery response does not preserve the registered wallet identity');
  }
}

export function assertEd25519YaoRecoveryDescriptorContinuity(
  parsed: ParsedPasskeyEd25519YaoRecoveryDescriptorV1,
): void {
  assertEd25519YaoRecoveryDescriptorStableIdentity(parsed);
  if (parsed.capability.lifecycle.thresholdSessionId !== parsed.session.thresholdSessionId) {
    throw new Error('Yao recovery response does not preserve the threshold material lifecycle');
  }
}

export function assertEd25519YaoWarmRecoveryDescriptorStableMaterialContinuity(
  parsed: ParsedPasskeyEd25519YaoRecoveryDescriptorV1,
  expectedMaterialActivation: MpcMaterialActivationRef,
): void {
  assertEd25519YaoRecoveryDescriptorStableIdentity(parsed);
  if (
    !mpcMaterialActivationRefsEqual(
      parsed.capability.materialActivation,
      expectedMaterialActivation,
    )
  ) {
    throw new Error('Yao warm recovery response does not preserve exact material activation');
  }
}

export function parsePasskeyEd25519YaoSyncResponseV1(
  raw: unknown,
): ParsedPasskeyEd25519YaoSyncResponseV1 {
  const response = requireRecord(raw, 'sync-account response');
  if (response.ok !== true || response.verified !== true) {
    throw new Error('sync-account response is not verified');
  }
  const walletId = walletIdFromString(requireString(response.walletId, 'walletId'));
  const nearAccountId = toAccountId(requireString(response.nearAccountId, 'nearAccountId'));
  const nearEd25519SigningKeyId = requireString(
    response.nearEd25519SigningKeyId,
    'nearEd25519SigningKeyId',
  );
  const threshold = requireRecord(response.thresholdEd25519, 'thresholdEd25519');
  const participantIds = requireParticipantIds(threshold.participantIds);
  const recovery = requireRecord(response.ed25519YaoRecovery, 'ed25519YaoRecovery');
  if (recovery.kind !== 'router_ab_ed25519_yao_sync_recovery_v1') {
    throw new Error('sync-account recovery kind is invalid');
  }
  const authority = parseWalletAuthAuthorityRef(recovery.authorityRef);
  if (!authority || String(authority.walletId) !== String(walletId)) {
    throw new Error('sync-account recovery authority is invalid');
  }
  const custody = requireRecord(response.walletCustody, 'walletCustody');
  if (custody.kind !== 'wallet_custody_sync_bootstrap_v1') {
    throw new Error('walletCustody kind is invalid');
  }
  const parsed: ParsedPasskeyEd25519YaoSyncResponseV1 = {
    authority,
    walletId,
    nearAccountId,
    nearEd25519SigningKeyId,
    signerSlot: requirePositiveInteger(response.signerSlot, 'signerSlot'),
    operationalPublicKey: requireString(response.publicKey, 'publicKey'),
    relayerKeyId: requireString(threshold.relayerKeyId, 'thresholdEd25519.relayerKeyId'),
    credentialIdB64u: requireString(response.credentialIdB64u, 'credentialIdB64u'),
    credentialPublicKeyB64u: requireString(
      response.credentialPublicKeyB64u,
      'credentialPublicKeyB64u',
    ),
    session: parseRecoverySession(
      requireRecord(threshold.session, 'thresholdEd25519.session'),
      participantIds,
      {
        walletId: String(walletId),
        nearAccountId: String(nearAccountId),
        nearEd25519SigningKeyId,
      },
    ),
    capability: parseEd25519YaoRecoveryCapabilityV1(recovery.capability),
    walletCustody: {
      envelope: parsePasskeyCustodyEnvelopeRecord(custody.envelope),
      storeVersion: requireString(custody.storeVersion, 'walletCustody.storeVersion'),
    },
  };
  assertEd25519YaoRecoveryDescriptorContinuity(parsed);
  return parsed;
}

function recoveryAdmissionRequest(
  parsed: ParsedPasskeyEd25519YaoRecoveryDescriptorV1,
): RouterAbEd25519YaoRecoveryAdmissionRequestV1 {
  const replacementCapabilityBinding = new Uint8Array(32);
  globalThis.crypto.getRandomValues(replacementCapabilityBinding);
  const lifecycleId = secureRandomId('ed25519-yao-recovery', 32, 'Ed25519 Yao recovery IDs');
  const replacementActivationId = parseMpcMaterialActivationId(
    secureRandomId(
      'ed25519-yao-recovery-material-activation',
      32,
      'Ed25519 Yao recovery material activation IDs',
    ),
  );
  const replacementLifecycleBinding = parseMpcLifecycleBindingRef(
    `${lifecycleId}:material-activation`,
  );
  if (!replacementActivationId.ok || !replacementLifecycleBinding.ok) {
    throw new Error('Ed25519 Yao recovery material activation identity is invalid');
  }
  const replacementMaterialActivation = buildMpcMaterialActivationRef({
    activationId: replacementActivationId.value,
    capability: parsed.capability.materialActivation.capability,
    materialOwner: parsed.capability.materialActivation.materialOwner,
    keyBinding: parsed.capability.materialActivation.keyBinding,
    lifecycleBinding: replacementLifecycleBinding.value,
    signingWorker: parsed.capability.materialActivation.signingWorker,
  });
  try {
    const request = parseRouterAbEd25519YaoRecoveryAdmissionRequestV1({
      scope: {
        lifecycle_id: lifecycleId,
        root_share_epoch: parsed.capability.lifecycle.rootShareEpoch,
        account_id: parsed.capability.lifecycle.accountId,
        threshold_session_id: parsed.session.thresholdSessionId,
        signer_set_id: parsed.capability.lifecycle.signerSetId,
        signing_worker_id: parsed.capability.lifecycle.signingWorkerId,
        material_activation: routerAbMpcMaterialActivationRefToWire(replacementMaterialActivation),
      },
      active_material_activation: routerAbMpcMaterialActivationRefToWire(
        parsed.capability.materialActivation,
      ),
      application_binding: parsed.capability.applicationBinding,
      participant_ids: parsed.capability.participantIds,
      active_capability_binding: parsed.capability.activeCapabilityBinding,
      replacement_capability_binding: [...replacementCapabilityBinding],
      registered_public_key: parsed.capability.registeredPublicKey,
    });
    if (!request.ok) throw new Error(request.message);
    return request.value;
  } finally {
    replacementCapabilityBinding.fill(0);
  }
}

export function buildRecoveredWalletSessionState(input: {
  readonly parsed: ParsedPasskeyEd25519YaoRecoveryDescriptorV1;
  readonly relayerUrl: string;
  readonly rpId: string;
}): NearResolvedEd25519SigningSessionState {
  const parsed = input.parsed;
  const session = parsed.session;
  const claims = parseRouterAbEd25519WalletSessionIdentityClaims(session.walletSessionJwt);
  if (!claims) throw new Error('recovered Yao Wallet Session claims are invalid');
  const signingRoot = signingRootScopeFromRuntimePolicyScope(session.runtimePolicyScope);
  const signingWalletSession = buildRouterAbEd25519SigningWalletSession({
    walletId: String(parsed.walletId),
    nearAccountId: String(parsed.nearAccountId),
    nearEd25519SigningKeyId: parsed.nearEd25519SigningKeyId,
    walletSessionId: claims.walletSessionId,
    quotaId: claims.quotaId,
    thresholdSessionId: session.thresholdSessionId,
    remainingUses: session.remainingUses,
    expiresAtMs: session.expiresAtMs,
    runtimePolicyScope: session.runtimePolicyScope,
    signingRootId: signingRoot.signingRootId,
    signingRootVersion: String(signingRoot.signingRootVersion || ''),
    routerAbNormalSigning: session.routerAbNormalSigning,
    walletSessionJwt: session.walletSessionJwt,
    nowMs: Math.min(Date.now(), session.expiresAtMs - 1),
  });
  if (!signingWalletSession.ok) {
    throw new Error(`recovered Yao Wallet Session is unusable: ${signingWalletSession.reason}`);
  }
  return buildPasskeyRouterAbEd25519WalletSessionState({
    walletId: toWalletId(parsed.walletId),
    nearAccountId: parsed.nearAccountId,
    nearEd25519SigningKeyId: nearEd25519SigningKeyIdFromString(parsed.nearEd25519SigningKeyId),
    signerSlot: parsed.signerSlot,
    rpId: toRpId(input.rpId),
    credentialIdB64u: parsed.credentialIdB64u,
    relayerUrl: input.relayerUrl,
    authority: parsed.authority,
    signingWalletSession: signingWalletSession.value,
  });
}

function publishRecoveredWalletSession(input: {
  readonly parsed: ParsedPasskeyEd25519YaoRecoveryDescriptorV1;
  readonly relayerUrl: string;
  readonly rpId: string;
}): NearResolvedEd25519SigningSessionState {
  const state = buildRecoveredWalletSessionState(input);
  return state;
}

function requireMaterialOwner(walletId: WalletId): MpcMaterialOwnerRef {
  const parsed = parseMpcMaterialOwnerRef(walletId);
  if (!parsed.ok) throw new Error(parsed.error.message);
  return parsed.value;
}

function recoverySourceIdentity(
  parsed: ParsedPasskeyEd25519YaoRecoveryDescriptorV1,
): Ed25519YaoRecoverySourceIdentityV1 {
  return {
    walletId: String(parsed.walletId),
    nearAccountId: parsed.nearAccountId,
    nearEd25519SigningKeyId: parsed.nearEd25519SigningKeyId,
    signerSlot: parsed.signerSlot,
    operationalPublicKey: parsed.operationalPublicKey,
    authority: parsed.authority,
    materialOwner: requireMaterialOwner(parsed.walletId),
  };
}

function recoveryTransport(input: {
  parsed: ParsedPasskeyEd25519YaoRecoveryDescriptorV1;
  relayerUrl: string;
  fetch: typeof fetch;
}): RouterAbEd25519YaoRecoveryTransportV1 {
  return new RouterAbEd25519YaoHttpActivationTransportV1({
    routerOrigin: new URL(input.relayerUrl).origin,
    authorization: `Bearer ${input.parsed.session.walletSessionJwt}`,
    fetch: input.fetch,
  });
}

function assertRecoveryJournalIdentity(
  parsed: ParsedPasskeyEd25519YaoRecoveryDescriptorV1,
  journal: NearEd25519YaoRecoveryCommitJournalV1,
): void {
  if (
    String(journal.authority.walletId) !== String(parsed.authority.walletId) ||
    String(journal.authority.authorityDigest) !== String(parsed.authority.authorityDigest) ||
    String(journal.materialOwner) !== String(parsed.walletId)
  ) {
    throw new Error('Near recovery journal does not match the current authority');
  }
}

function recoveryLocalMaterialTarget(input: {
  parsed: ParsedPasskeyEd25519YaoRecoveryDescriptorV1;
  source: Extract<NearEd25519YaoRecoveryCommitJournalV1, { kind: 'prepared' }>['source'];
}): PasskeyEd25519YaoLocalMaterialTargetV1 {
  return {
    profileId: input.source.profileId,
    chainIdKey: input.source.chainIdKey,
    accountAddress: String(input.parsed.nearAccountId).trim().toLowerCase(),
  };
}

function validateRecoveredActiveClient(input: {
  parsed: ParsedPasskeyEd25519YaoRecoveryDescriptorV1;
  activeClient: RouterAbEd25519YaoActiveClientV1;
}): void {
  const metadata = input.activeClient.metadata();
  if (
    metadata.stateEpoch !== BigInt(input.parsed.capability.stateEpoch) + 1n ||
    `ed25519:${base58Encode(metadata.registeredPublicKey)}` !== input.parsed.operationalPublicKey
  ) {
    throw new Error('recovered Yao Client does not preserve the registered public key');
  }
}

async function commitRecoveredCapability<
  TParsed extends ParsedPasskeyEd25519YaoRecoveryDescriptorV1,
>(input: {
  parsed: TParsed;
  prepared: Extract<NearEd25519YaoRecoveryCommitJournalV1, { kind: 'prepared' }>;
  result: RouterAbEd25519YaoRecoveryResultV1;
  ownedPasskeyPrfFirst: Uint8Array;
  relayerUrl: string;
  rpId: string;
}): Promise<PasskeyEd25519YaoRecoveryResultV1<TParsed>> {
  if (!input.result.ok) throw new Error(input.result.message);
  const activeClient = input.result.activeClient;
  try {
    validateRecoveredActiveClient({ parsed: input.parsed, activeClient });
    const current = await readNearEd25519YaoRecoveryJournalV1({
      store: IndexedDBManager,
      walletId: String(input.parsed.walletId),
      signerSlot: input.parsed.signerSlot,
    });
    if (
      !current ||
      current.kind !== 'prepared' ||
      current.recoveryId !== input.prepared.recoveryId
    ) {
      throw new Error('Near recovery journal changed before local promotion');
    }
    assertRecoveryJournalIdentity(input.parsed, current);
    const walletSessionState = buildRecoveredWalletSessionState({
      parsed: input.parsed,
      relayerUrl: input.relayerUrl,
      rpId: input.rpId,
    });
    const replacement = buildPromotedPasskeyEd25519YaoLocalMaterialRecordV1({
      target: recoveryLocalMaterialTarget({
        parsed: input.parsed,
        source: current.source,
      }),
      activeClient,
      walletSessionState,
      rpId: input.rpId,
      credentialIdB64u: input.parsed.credentialIdB64u,
      ownedPasskeyPrfFirst: input.ownedPasskeyPrfFirst,
      promotionReceipt: input.result.activation,
    });
    if (current.disposition === 'cancel_requested') {
      await finalizeCancelledPromotedNearEd25519YaoRecoveryV1({
        store: IndexedDBManager,
        walletId: String(input.parsed.walletId),
        signerSlot: input.parsed.signerSlot,
        journal: current,
        promotionReceipt: input.result.activation,
        replacement,
      });
      throw new Error('Near recovery was cancelled');
    }
    const committed = await persistPromotionCommittedNearEd25519YaoRecoveryV1({
      store: IndexedDBManager,
      walletId: String(input.parsed.walletId),
      signerSlot: input.parsed.signerSlot,
      prepared: current,
      promotionReceipt: input.result.activation,
      replacement,
    });
    await finalizePromotionCommittedNearEd25519YaoRecoveryV1({
      store: IndexedDBManager,
      walletId: String(input.parsed.walletId),
      signerSlot: input.parsed.signerSlot,
      journal: committed,
    });
    const publishedWalletSessionState = publishRecoveredWalletSession({
      parsed: input.parsed,
      relayerUrl: input.relayerUrl,
      rpId: input.rpId,
    });
    return {
      activeClient,
      walletSessionState: publishedWalletSessionState,
      parsed: input.parsed,
    };
  } catch (error) {
    activeClient.dispose();
    throw error;
  }
}

export async function recoverPasskeyEd25519YaoCapabilityV1(input: {
  readonly syncResponse: unknown;
  readonly ownedPasskeyPrfFirst: Uint8Array;
  readonly relayerUrl: string;
  readonly rpId: string;
  readonly fetch: typeof fetch;
}): Promise<PasskeyEd25519YaoRecoveryResultV1> {
  try {
    const parsed = parsePasskeyEd25519YaoSyncResponseV1(input.syncResponse);
    return await recoverParsedPasskeyEd25519YaoCapabilityV1({
      parsed,
      ownedPasskeyPrfFirst: input.ownedPasskeyPrfFirst,
      relayerUrl: input.relayerUrl,
      rpId: input.rpId,
      fetch: input.fetch,
    });
  } finally {
    input.ownedPasskeyPrfFirst.fill(0);
  }
}

export async function recoverParsedPasskeyEd25519YaoCapabilityV1<
  TParsed extends ParsedPasskeyEd25519YaoRecoveryDescriptorV1,
>(input: {
  readonly parsed: TParsed;
  readonly ownedPasskeyPrfFirst: Uint8Array;
  readonly relayerUrl: string;
  readonly rpId: string;
  readonly fetch: typeof fetch;
}): Promise<PasskeyEd25519YaoRecoveryResultV1<TParsed>> {
  try {
    const parsed = input.parsed;
    assertEd25519YaoRecoveryDescriptorContinuity(parsed);
    const existing = await readNearEd25519YaoRecoveryJournalV1({
      store: IndexedDBManager,
      walletId: String(parsed.walletId),
      signerSlot: parsed.signerSlot,
    });
    if (existing) {
      assertRecoveryJournalIdentity(parsed, existing);
      if (existing.kind === 'promotion_committed') {
        const walletSessionState = buildRecoveredWalletSessionState({
          parsed,
          relayerUrl: input.relayerUrl,
          rpId: input.rpId,
        });
        await finalizePromotionCommittedNearEd25519YaoRecoveryV1({
          store: IndexedDBManager,
          walletId: String(parsed.walletId),
          signerSlot: parsed.signerSlot,
          journal: existing,
        });
        const replacement = existing.finalization.replacement;
        const rehydrated = await rehydratePasskeyEd25519YaoLocalMaterialRecordV1({
          stored: replacement,
          target: {
            profileId: replacement.profileId,
            chainIdKey: replacement.chainIdKey,
            accountAddress: replacement.accountAddress,
          },
          walletSessionState,
          rpId: input.rpId,
          credentialIdB64u: parsed.credentialIdB64u,
          ownedPasskeyPrfFirst: input.ownedPasskeyPrfFirst,
        });
        try {
          validateRecoveredActiveClient({
            parsed,
            activeClient: rehydrated.activeClient,
          });
          const publishedWalletSessionState = publishRecoveredWalletSession({
            parsed,
            relayerUrl: input.relayerUrl,
            rpId: input.rpId,
          });
          return {
            activeClient: rehydrated.activeClient,
            walletSessionState: publishedWalletSessionState,
            parsed,
          };
        } catch (error) {
          rehydrated.activeClient.dispose();
          throw error;
        }
      }
      const request = existing.correlation.admissionRequest;
      const transport = recoveryTransport(input);
      const status = await readRouterAbEd25519YaoRecoveryStatusV1({ request, transport });
      if (!status.ok) throw new Error(status.message);
      if (existing.disposition === 'cancel_requested' && status.status.stage !== 'promoted') {
        throw new Error('Near recovery was cancelled');
      }
      const client = await RouterAbEd25519YaoClientV1.initializeBundled();
      const entropy = await openEd25519YaoRecoverySourceV1({
        store: IndexedDBManager,
        identity: recoverySourceIdentity(parsed),
        request,
        ownedPasskeyPrfFirst: input.ownedPasskeyPrfFirst,
      });
      const factorSecret = input.ownedPasskeyPrfFirst.slice();
      const result =
        status.status.stage === 'missing'
          ? await client.recoverPrepared({
              request,
              factor: { kind: 'passkey_prf_first', ownedSecret32: factorSecret },
              entropy,
              transport,
            })
          : await client.resumePreparedRecovery({
              request,
              factor: { kind: 'passkey_prf_first', ownedSecret32: factorSecret },
              entropy,
              transport,
            });
      const recovered = await commitRecoveredCapability({
        parsed,
        prepared: existing,
        result,
        ownedPasskeyPrfFirst: input.ownedPasskeyPrfFirst,
        relayerUrl: input.relayerUrl,
        rpId: input.rpId,
      });
      return recovered;
    }
    const request = recoveryAdmissionRequest(parsed);
    const client = await RouterAbEd25519YaoClientV1.initializeBundled();
    const entropy = createRouterAbEd25519YaoActivationEntropyV1();
    let source: Awaited<ReturnType<typeof sealEd25519YaoRecoverySourceV1>>;
    try {
      source = await sealEd25519YaoRecoverySourceV1({
        store: IndexedDBManager,
        identity: recoverySourceIdentity(parsed),
        request,
        ownedPasskeyPrfFirst: input.ownedPasskeyPrfFirst,
        entropy,
      });
    } catch (error) {
      zeroizeRouterAbEd25519YaoActivationEntropyV1(entropy);
      throw error;
    }
    const prepared = buildPreparedNearEd25519YaoRecoveryJournalV1({
      authority: parsed.authority,
      materialOwner: requireMaterialOwner(parsed.walletId),
      source,
      request,
    });
    try {
      await persistPreparedNearEd25519YaoRecoveryJournalV1({
        store: IndexedDBManager,
        walletId: String(parsed.walletId),
        signerSlot: parsed.signerSlot,
        journal: prepared,
      });
    } catch (error) {
      zeroizeRouterAbEd25519YaoActivationEntropyV1(entropy);
      throw error;
    }
    const factorSecret = input.ownedPasskeyPrfFirst.slice();
    const result = await client.recoverPrepared({
      request,
      factor: { kind: 'passkey_prf_first', ownedSecret32: factorSecret },
      entropy,
      transport: recoveryTransport(input),
    });
    const recovered = await commitRecoveredCapability({
      parsed,
      prepared,
      result,
      ownedPasskeyPrfFirst: input.ownedPasskeyPrfFirst,
      relayerUrl: input.relayerUrl,
      rpId: input.rpId,
    });
    return recovered;
  } finally {
    input.ownedPasskeyPrfFirst.fill(0);
  }
}

export async function resumeParsedPasskeyEd25519YaoCapabilityV1<
  TParsed extends ParsedPasskeyEd25519YaoRecoveryDescriptorV1,
>(input: {
  readonly parsed: TParsed;
  readonly request: RouterAbEd25519YaoRecoveryAdmissionRequestV1;
  readonly ownedPasskeyPrfFirst: Uint8Array;
  readonly relayerUrl: string;
  readonly rpId: string;
  readonly fetch: typeof fetch;
}): Promise<PasskeyEd25519YaoRecoveryResultV1<TParsed>> {
  try {
    assertEd25519YaoRecoveryDescriptorContinuity(input.parsed);
    const journal = await readNearEd25519YaoRecoveryJournalV1({
      store: IndexedDBManager,
      walletId: String(input.parsed.walletId),
      signerSlot: input.parsed.signerSlot,
    });
    if (
      !journal ||
      journal.kind !== 'prepared' ||
      journal.recoveryId !== input.request.scope.lifecycle_id
    ) {
      throw new Error('Prepared Near recovery journal is unavailable');
    }
    return await recoverParsedPasskeyEd25519YaoCapabilityV1({
      parsed: input.parsed,
      ownedPasskeyPrfFirst: input.ownedPasskeyPrfFirst,
      relayerUrl: input.relayerUrl,
      rpId: input.rpId,
      fetch: input.fetch,
    });
  } finally {
    input.ownedPasskeyPrfFirst.fill(0);
  }
}

export async function cancelPasskeyEd25519YaoRecoveryV1(input: {
  walletId: string;
  signerSlot: number;
}): Promise<boolean> {
  return requestCancelNearEd25519YaoRecoveryV1({
    store: IndexedDBManager,
    walletId: input.walletId,
    signerSlot: input.signerSlot,
  });
}
