import type { NearResolvedEd25519SigningSessionState } from '@/core/signingEngine/interfaces/near';
import type { Ed25519YaoPublicCapabilityLaneReferenceV1 } from '@/core/signingEngine/threshold/ed25519/yaoPublicCapabilityReferences';
import { buildPasskeyRouterAbEd25519WalletSessionState } from '@/core/signingEngine/session/warmCapabilities/routerAbEd25519WalletSessionState';
import {
  buildRouterAbEd25519SigningWalletSession,
  parseRouterAbEd25519WalletSessionIdentityClaims,
} from '@/core/signingEngine/session/routerAbSigningWalletSession';
import { toWalletId } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import { toRpId } from '@/core/signingEngine/session/identity/evmFamilyEcdsaIdentity';
import type { RouterAbEd25519YaoActiveClientV1 } from '@/core/signingEngine/threshold/ed25519/yaoClient';
import { toAccountId, type AccountId } from '@/core/types/accountIds';
import {
  normalizeRuntimePolicyScope,
  signingRootScopeFromRuntimePolicyScope,
} from '@shared/threshold/signingRootScope';
import { walletIdFromString, type WalletId } from '@shared/utils/registrationIntent';
import { base58Encode } from '@shared/utils/base58';
import { nearEd25519SigningKeyIdFromString } from '@shared/utils/registrationIntent';
import {
  mpcMaterialActivationRefsEqual,
  parseThresholdEd25519SessionId,
  type MpcMaterialActivationRef,
  type ThresholdEd25519SessionId,
} from '@shared/utils/domainIds';
import {
  parseRouterAbEd25519YaoRegistrationActivationAdmissionReceiptV1,
  parseRouterAbEd25519YaoRegistrationAdmissionRequestV1,
  type RouterAbEd25519YaoActivationAdmissionReceiptV1,
  type RouterAbEd25519YaoRegistrationAdmissionRequestV1,
} from '@shared/utils/routerAbEd25519Yao';
import {
  parsePasskeyCustodyEnvelopeRecord,
  type PasskeyCustodyEnvelopeRecord,
} from '@shared/passkey-custody';
import { parseRouterAbEd25519NormalSigningState } from '@shared/utils/signingSessionSeal';
import { isPlainObject } from '@shared/utils/validation';
import { routerAbMpcMaterialActivationRefFromWire } from '@shared/utils/routerAbNormalSigningIdentity';
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
