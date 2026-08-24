import type { NearResolvedEd25519SigningSessionState } from '@/core/signingEngine/interfaces/near';
import type { Ed25519YaoPublicCapabilityLaneReferenceV1 } from '@/core/signingEngine/threshold/ed25519/yaoPublicCapabilityReferences';
import { buildPasskeyRouterAbEd25519WalletSessionState } from '@/core/signingEngine/session/warmCapabilities/routerAbEd25519WalletSessionState';
import { buildRouterAbEd25519SigningWalletSession } from '@/core/signingEngine/session/routerAbSigningWalletSession';
import { toWalletId } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import { toRpId } from '@/core/signingEngine/session/identity/evmFamilyEcdsaIdentity';
import type { RouterAbEd25519YaoActiveClientV1 } from '@/core/signingEngine/threshold/ed25519/yaoClient';
import { toAccountId, type AccountId } from '@/core/types/accountIds';
import {
  normalizeRuntimePolicyScope,
  signingRootScopeFromRuntimePolicyScope,
} from '@shared/threshold/signingRootScope';
import {
  parseWalletAuthMethodRecordV2,
  walletIdFromString,
  type WalletAuthMethodRecordV2,
  type WalletId,
} from '@shared/utils/registrationIntent';
import { base58Encode } from '@shared/utils/base58';
import { nearEd25519SigningKeyIdFromString } from '@shared/utils/registrationIntent';
import {
  mpcMaterialActivationRefsEqual,
  parseWalletAuthMethodId,
  parseWalletAuthorityId,
  parseThresholdEd25519SessionId,
  type MpcMaterialActivationRef,
  type ThresholdEd25519SessionId,
  type WalletAuthMethodId,
  type WalletAuthorityId,
} from '@shared/utils/domainIds';
import {
  parsePasskeyCustodyEnvelopeRecord,
  type PasskeyCustodyEnvelopeRecord,
} from '@shared/passkey-custody';
import { parseRouterAbEd25519NormalSigningState } from '@shared/utils/signingSessionSeal';
import { isPlainObject } from '@shared/utils/validation';
import {
  parseWalletAuthAuthorityRef,
  type WalletAuthAuthorityRef,
} from '@shared/utils/walletAuthAuthority';
import {
  parseMpcWalletSigningQuotaId,
  parseWalletSessionAuthorizationId,
  parseWalletSessionId,
  type MpcWalletSigningQuotaId,
  type WalletSessionId,
} from '@shared/authorization/capabilityKinds';
import {
  parseEd25519YaoRecoveryCapabilityV1,
  type ParsedYaoRecoveryCapabilityV1,
  type ParsedYaoRecoverySessionV1,
} from '@/core/signingEngine/session/passkey/ed25519YaoRecoveryCapability';
import {
  parseWalletAuthorityV1,
  type ActiveWalletAuthorityV1,
} from '@shared/authorization/walletAuthority';
export type { ParsedYaoRecoveryCapabilityV1 } from '@/core/signingEngine/session/passkey/ed25519YaoRecoveryCapability';
export { parseEd25519YaoRecoveryCapabilityV1 } from '@/core/signingEngine/session/passkey/ed25519YaoRecoveryCapability';

export type { ParsedYaoRecoverySessionV1 } from '@/core/signingEngine/session/passkey/ed25519YaoRecoveryCapability';

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
  readonly walletAuthMethodId: WalletAuthMethodId;
  readonly walletAuthorityId: WalletAuthorityId;
  readonly foundingAuthority: ActiveWalletAuthorityV1;
  readonly foundingAuthMethod: Extract<
    WalletAuthMethodRecordV2,
    { readonly kind: 'passkey'; readonly status: 'active' }
  >;
  readonly keyVersion: string;
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
  if (raw.sessionKind !== 'opaque') throw new Error('Yao recovery session must use opaque token');
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
  const authorizationId = parseWalletSessionAuthorizationId(raw.authorizationId);
  const quotaId = parseMpcWalletSigningQuotaId(raw.quotaId);
  if (!walletSessionId.ok || !authorizationId.ok || !quotaId.ok) {
    throw new Error('Yao recovery Wallet Session identity is invalid');
  }
  return {
    sessionKind: 'opaque',
    walletSessionToken: requireString(raw.walletSessionToken, 'session.walletSessionToken'),
    thresholdSessionId: requireString(raw.thresholdSessionId, 'session.thresholdSessionId'),
    authorizationId: authorizationId.value,
    walletSessionId: walletSessionId.value,
    quotaId: quotaId.value,
    expiresAtMs: requirePositiveInteger(raw.expiresAtMs, 'session.expiresAtMs'),
    remainingUses: requirePositiveInteger(raw.remainingUses, 'session.remainingUses'),
    runtimePolicyScope,
    participantIds,
    routerAbNormalSigning,
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
  const walletAuthMethodId = parseWalletAuthMethodId(response.walletAuthMethodId);
  const walletAuthorityId = parseWalletAuthorityId(response.walletAuthorityId);
  const foundingAuthority = parseWalletAuthorityV1(response.foundingAuthority);
  const foundingAuthMethod = parseWalletAuthMethodRecordV2(response.foundingAuthMethod);
  if (
    !walletAuthMethodId.ok ||
    !walletAuthorityId.ok ||
    walletAuthMethodId.value !== authority.walletAuthMethodId ||
    !foundingAuthority.ok ||
    foundingAuthority.value.state !== 'active' ||
    foundingAuthority.value.provenance.kind !== 'wallet_registration' ||
    foundingAuthority.value.walletId !== walletId ||
    foundingAuthority.value.authorityId !== walletAuthorityId.value ||
    !foundingAuthMethod ||
    foundingAuthMethod.kind !== 'passkey' ||
    foundingAuthMethod.status !== 'active' ||
    foundingAuthMethod.walletId !== walletId ||
    foundingAuthMethod.walletAuthorityId !== walletAuthorityId.value ||
    foundingAuthMethod.walletAuthMethodId !== walletAuthMethodId.value
  ) {
    throw new Error('sync-account exact auth-method identity is invalid');
  }
  const custody = requireRecord(response.walletCustody, 'walletCustody');
  if (custody.kind !== 'wallet_custody_sync_bootstrap_v1') {
    throw new Error('walletCustody kind is invalid');
  }
  const parsed: ParsedPasskeyEd25519YaoSyncResponseV1 = {
    authority,
    walletAuthMethodId: walletAuthMethodId.value,
    walletAuthorityId: walletAuthorityId.value,
    foundingAuthority: foundingAuthority.value,
    foundingAuthMethod,
    walletId,
    nearAccountId,
    nearEd25519SigningKeyId,
    signerSlot: requirePositiveInteger(response.signerSlot, 'signerSlot'),
    operationalPublicKey: requireString(response.publicKey, 'publicKey'),
    relayerKeyId: requireString(threshold.relayerKeyId, 'thresholdEd25519.relayerKeyId'),
    keyVersion: requireString(threshold.keyVersion, 'thresholdEd25519.keyVersion'),
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
  readonly thresholdSessionId: ThresholdEd25519SessionId;
}): NearResolvedEd25519SigningSessionState {
  const parsed = input.parsed;
  const session = parsed.session;
  const signingRoot = signingRootScopeFromRuntimePolicyScope(session.runtimePolicyScope);
  const signingWalletSession = buildRouterAbEd25519SigningWalletSession({
    walletId: String(parsed.walletId),
    nearAccountId: String(parsed.nearAccountId),
    nearEd25519SigningKeyId: parsed.nearEd25519SigningKeyId,
    walletSessionId: session.walletSessionId,
    authorizationId: session.authorizationId,
    quotaId: session.quotaId,
    thresholdSessionId: input.thresholdSessionId,
    remainingUses: session.remainingUses,
    expiresAtMs: session.expiresAtMs,
    runtimePolicyScope: session.runtimePolicyScope,
    signingRootId: signingRoot.signingRootId,
    signingRootVersion: String(signingRoot.signingRootVersion || ''),
    routerAbNormalSigning: session.routerAbNormalSigning,
    walletSessionToken: session.walletSessionToken,
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
