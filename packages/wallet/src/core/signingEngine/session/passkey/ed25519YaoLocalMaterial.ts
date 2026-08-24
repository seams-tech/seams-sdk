import { buildNearAccountRefs } from '@/core/accountData/near/accountRefs';
import { buildEnvelopeAAD, KEY_PAYLOAD_ENC_VERSION } from '@/core/indexedDB/keyMaterialEnvelope';
import type { KeyMaterialRecord } from '@/core/indexedDB/keyMaterial.types';
import {
  resolveAccountKeyMaterialTarget,
  type AccountKeyMaterialDeps,
} from '@/core/indexedDB/accountKeyMaterial';
import type {
  NearEd25519YaoOperationMaterial,
  NearResolvedEd25519SigningSessionState,
} from '@/core/signingEngine/interfaces/near';
import {
  normalizeThresholdRuntimePolicyScope,
  type ThresholdRuntimePolicyScope,
} from '@/core/signingEngine/threshold/sessionPolicy';
import {
  requireRouterAbEd25519NormalSigningState,
  type RouterAbEd25519NormalSigningState,
} from '@/core/signingEngine/threshold/ed25519/routerAbNormalSigningState';
import {
  ROUTER_AB_ED25519_YAO_ACTIVE_CLIENT_KIND_V1,
  RouterAbEd25519YaoClientV1,
  type RouterAbEd25519YaoActiveClientMetadataV1,
  type RouterAbEd25519YaoActiveClientV1,
  type RouterAbEd25519YaoSealableActiveClientV1,
} from '@/core/signingEngine/threshold/ed25519/yaoClient';
import { base58Encode } from '@shared/utils/base58';
import { base64UrlDecode, base64UrlEncode } from '@shared/utils/base64';
import { routerAbMpcMaterialActivationRefToWire } from '@shared/utils/routerAbNormalSigningIdentity';
import {
  mpcMaterialActivationRefsEqual,
  parseMpcMaterialActivationRef,
  parseThresholdEd25519SessionId,
  type MpcMaterialActivationRef,
  type ThresholdEd25519SessionId,
} from '@shared/utils/domainIds';
import {
  nearEd25519YaoMaterialActivationFromMetadata,
  nearEd25519YaoRuntimeRef,
  resolveNearEd25519YaoCapabilityHydrationV1,
  type NearEd25519YaoPublicLocatorObservationV1,
  type NearEd25519YaoRuntimeObservationV1,
  type NearEd25519YaoUnlockSourceObservationV1,
} from '../material/nearEd25519YaoMaterialActivation';
import type { RouterAbEd25519YaoRecoveryActivationReceiptV1 } from '@shared/utils/routerAbEd25519Yao';
import {
  parsePasskeyWalletAuthAuthority,
  walletAuthAuthorityRef,
  type WalletAuthAuthorityRef,
} from '@shared/utils/walletAuthAuthority';
import { buildRestorableMpcMaterialRefInternal } from '../material/restorableMpcMaterialRef.internal';
import type { MpcCapabilityHydrationPlan } from '../material/mpcCapabilityHydration';

export const ED25519_YAO_LOCAL_MATERIAL_KEY_KIND =
  'router_ab_ed25519_yao_active_client_v1' as const;
const ED25519_YAO_LOCAL_MATERIAL_SCHEMA_VERSION = 3;
const ED25519_YAO_LOCAL_MATERIAL_ALGORITHM = 'chacha20poly1305-hkdf-sha256-prf-first-v1';
const ED25519_YAO_LOCAL_MATERIAL_NONCE_BYTES = 12;
const MAX_U64 = (1n << 64n) - 1n;

type Ed25519YaoLocalMaterialStorePort = AccountKeyMaterialDeps['clientDB'] &
  AccountKeyMaterialDeps['keyMaterialStore'] & {
    deleteKeyMaterial(
      profileId: string,
      signerSlot: number,
      chainIdKey: string,
      keyKind: typeof ED25519_YAO_LOCAL_MATERIAL_KEY_KIND,
    ): Promise<void>;
  };

export type Ed25519YaoLocalMaterialIdentity = {
  walletId: string;
  nearAccountId: string;
  nearEd25519SigningKeyId: string;
  thresholdSessionId: string;
  signerSlot: number;
  rpId: string;
  credentialIdB64u: string;
  signingRootId: string;
  signingRootVersion: string;
  signingWorkerId: string;
};

export type Ed25519YaoLocalMaterialBindingV1 = {
  kind: typeof ED25519_YAO_LOCAL_MATERIAL_KEY_KIND;
  walletId: string;
  nearAccountId: string;
  nearEd25519SigningKeyId: string;
  signerSlot: number;
  rpId: string;
  credentialIdB64u: string;
  lifecycleId: string;
  thresholdSessionId: ThresholdEd25519SessionId;
  materialActivation: MpcMaterialActivationRef;
  signingRootId: string;
  signingRootVersion: string;
  signerSetId: string;
  signingWorkerId: string;
  participantIds: readonly [number, number];
  registeredPublicKeyB64u: string;
  signingWorkerVerifyingShareB64u: string;
  stateEpoch: string;
  activationTranscriptB64u: string;
  activationCapabilityBindingB64u: string;
};

export type PasskeyEd25519YaoStableServerScopeV1 = {
  relayerKeyId: string;
  participantIds: readonly [number, number];
  runtimePolicyScope: ThresholdRuntimePolicyScope;
  routerAbNormalSigning: RouterAbEd25519NormalSigningState;
};

export type PasskeyEd25519YaoLocalMaterialLocatorV1 = {
  kind: 'passkey_ed25519_yao_local_material_locator_v1';
  authority: WalletAuthAuthorityRef;
  materialActivation: MpcMaterialActivationRef;
  sealedMaterial: ReturnType<typeof buildRestorableMpcMaterialRefInternal>;
  stableServerScope: PasskeyEd25519YaoStableServerScopeV1;
  thresholdSessionId?: never;
};

export type ReadPasskeyEd25519YaoLocalMaterialLocatorInputV1 = {
  store: Ed25519YaoLocalMaterialStorePort;
  walletId: string;
  nearAccountId: string;
  nearEd25519SigningKeyId: string;
  signerSlot: number;
  rpId: string;
  credentialIdB64u: string;
  authority: WalletAuthAuthorityRef;
};

export type ReadPasskeyEd25519YaoLocalMaterialLocatorResultV1 =
  | {
      kind: 'available';
      locator: PasskeyEd25519YaoLocalMaterialLocatorV1;
    }
  | {
      kind: 'unavailable';
      locator?: never;
    };

export type PersistPasskeyEd25519YaoLocalMaterialInputV1 = {
  store: Ed25519YaoLocalMaterialStorePort;
  activeClient: RouterAbEd25519YaoSealableActiveClientV1;
  walletSessionState: NearResolvedEd25519SigningSessionState;
  rpId: string;
  credentialIdB64u: string;
  passkeyPrfFirstB64u: string;
};

export type PersistPasskeyEd25519YaoSignerMaterialInputV1 = {
  store: Ed25519YaoLocalMaterialStorePort;
  activeClient: RouterAbEd25519YaoSealableActiveClientV1;
  identity: Ed25519YaoLocalMaterialIdentity;
  stableServerScope: PasskeyEd25519YaoStableServerScopeV1;
  passkeyPrfFirstB64u: string;
};

export type PasskeyEd25519YaoLocalMaterialTargetV1 = {
  profileId: string;
  chainIdKey: string;
  accountAddress: string;
};

export type BuildPromotedPasskeyEd25519YaoLocalMaterialRecordInputV1 = {
  target: PasskeyEd25519YaoLocalMaterialTargetV1;
  activeClient: RouterAbEd25519YaoSealableActiveClientV1;
  walletSessionState: NearResolvedEd25519SigningSessionState;
  rpId: string;
  credentialIdB64u: string;
  ownedPasskeyPrfFirst: Uint8Array;
  promotionReceipt: RouterAbEd25519YaoRecoveryActivationReceiptV1;
};

export type RehydratePasskeyEd25519YaoLocalMaterialInputV1 = {
  store: Ed25519YaoLocalMaterialStorePort;
  walletSessionState: NearResolvedEd25519SigningSessionState;
  rpId: string;
  credentialIdB64u: string;
  passkeyPrfFirstB64u: string;
};

export type RehydratePasskeyEd25519YaoLocalMaterialRecordInputV1 = {
  stored: KeyMaterialRecord;
  target: PasskeyEd25519YaoLocalMaterialTargetV1;
  walletSessionState: NearResolvedEd25519SigningSessionState;
  rpId: string;
  credentialIdB64u: string;
  ownedPasskeyPrfFirst: Uint8Array;
};

export type DeletePasskeyEd25519YaoLocalMaterialInputV1 = {
  store: Ed25519YaoLocalMaterialStorePort;
  walletSessionState: NearResolvedEd25519SigningSessionState;
  rpId: string;
  credentialIdB64u: string;
};

export type RehydratePasskeyEd25519YaoLocalMaterialResultV1 =
  | {
      kind: 'rehydrated';
      activeClient: RouterAbEd25519YaoActiveClientV1;
    }
  | {
      kind: 'unavailable';
      activeClient?: never;
    };

export type HydratePasskeyEd25519YaoLocalMaterialResultV1 =
  | {
      kind: 'live';
      plan: Extract<MpcCapabilityHydrationPlan, { kind: 'use_live_runtime' }>;
      material: NearEd25519YaoOperationMaterial;
      activeClient?: never;
    }
  | {
      kind: 'rehydrated';
      plan: Extract<MpcCapabilityHydrationPlan, { kind: 'rehydrate_material_activation' }>;
      activeClient: RouterAbEd25519YaoActiveClientV1;
      capability?: never;
    }
  | {
      kind: 'blocked';
      plan: Extract<MpcCapabilityHydrationPlan, { kind: 'blocked' }>;
      capability?: never;
      activeClient?: never;
    };

export type PreparePasskeyEd25519YaoLocalMaterialRehydrationResultV1 =
  | {
      kind: 'prepared';
      plan: Extract<MpcCapabilityHydrationPlan, { kind: 'rehydrate_material_activation' }>;
    }
  | {
      kind: 'blocked';
      plan: Extract<MpcCapabilityHydrationPlan, { kind: 'blocked' }>;
    };

export type PasskeyEd25519YaoUnlockSourceV1 =
  | {
      kind: 'available';
      passkeyPrfFirstB64u: string;
    }
  | {
      kind: 'unavailable';
      passkeyPrfFirstB64u?: never;
    };

export type PasskeyEd25519YaoPublicLocatorObservationV1 =
  | Omit<Extract<NearEd25519YaoPublicLocatorObservationV1, { kind: 'available' }>, 'authority'>
  | Exclude<NearEd25519YaoPublicLocatorObservationV1, { kind: 'available' }>;

function asRecord(value: unknown): Record<string, unknown> | null {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return null;
  return value as Record<string, unknown>;
}

function requireNonEmpty(value: unknown, label: string): string {
  const parsed = String(value ?? '').trim();
  if (!parsed) throw new Error(`${label} is required for local Ed25519 material`);
  return parsed;
}

function requirePositiveSafeInteger(value: unknown, label: string): number {
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed < 1) {
    throw new Error(`${label} must be a positive safe integer`);
  }
  return parsed;
}

function requireThresholdSessionId(value: unknown, label: string): ThresholdEd25519SessionId {
  const parsed = parseThresholdEd25519SessionId(value);
  if (!parsed.ok) throw new Error(`${label}: ${parsed.error.message}`);
  return parsed.value;
}

function requireBytes32B64u(value: unknown, label: string): string {
  const parsed = requireNonEmpty(value, label);
  if (base64UrlDecode(parsed).length !== 32) {
    throw new Error(`${label} must encode 32 bytes`);
  }
  return parsed;
}

function requireParticipantIds(value: unknown): readonly [number, number] {
  if (!Array.isArray(value) || value.length !== 2) {
    throw new Error('participantIds must contain exactly two entries');
  }
  const participantIds = [
    requirePositiveSafeInteger(value[0], 'participantIds[0]'),
    requirePositiveSafeInteger(value[1], 'participantIds[1]'),
  ] as const;
  if (
    participantIds[0] > 65_535 ||
    participantIds[1] > 65_535 ||
    participantIds[0] === participantIds[1]
  ) {
    throw new Error('participantIds must contain two distinct u16 identifiers');
  }
  return participantIds;
}

function requireU64String(value: unknown, label: string): string {
  const parsed = requireNonEmpty(value, label);
  if (!/^(0|[1-9][0-9]*)$/.test(parsed)) {
    throw new Error(`${label} must be a canonical u64`);
  }
  const bigint = BigInt(parsed);
  if (bigint > MAX_U64) {
    throw new Error(`${label} must be a canonical u64`);
  }
  return parsed;
}

function walletSessionIdentity(
  walletSessionState: NearResolvedEd25519SigningSessionState,
  rpId: string,
  credentialIdB64u: string,
): Ed25519YaoLocalMaterialIdentity {
  const signer = walletSessionState.signingLane.identity.signer;
  return {
    walletId: requireNonEmpty(signer.account.wallet.walletId, 'walletId'),
    nearAccountId: requireNonEmpty(signer.account.nearAccountId, 'nearAccountId'),
    nearEd25519SigningKeyId: requireNonEmpty(
      signer.nearEd25519SigningKeyId,
      'nearEd25519SigningKeyId',
    ),
    thresholdSessionId: requireThresholdSessionId(
      walletSessionState.signingLane.identity.thresholdSessionId,
      'thresholdSessionId',
    ),
    signerSlot: requirePositiveSafeInteger(signer.signerSlot, 'signerSlot'),
    rpId: requireNonEmpty(rpId, 'rpId'),
    credentialIdB64u: requireNonEmpty(credentialIdB64u, 'credentialIdB64u'),
    signingRootId: requireNonEmpty(walletSessionState.signingRootId, 'signingRootId'),
    signingRootVersion: requireNonEmpty(
      walletSessionState.signingRootVersion,
      'signingRootVersion',
    ),
    signingWorkerId: requireNonEmpty(
      walletSessionState.routerAbNormalSigning.signingWorkerId,
      'signingWorkerId',
    ),
  };
}

function stableServerScopeFromActiveClient(
  activeClient: RouterAbEd25519YaoActiveClientV1,
  walletSessionState: NearResolvedEd25519SigningSessionState,
): PasskeyEd25519YaoStableServerScopeV1 {
  const metadata = activeClient.metadata();
  return {
    relayerKeyId: walletSessionState.routerAbNormalSigning.signingWorkerId,
    participantIds: [metadata.participantIds[0], metadata.participantIds[1]],
    runtimePolicyScope: walletSessionState.runtimePolicyScope,
    routerAbNormalSigning: walletSessionState.routerAbNormalSigning,
  };
}

function bindingFromActiveClient(args: {
  identity: Ed25519YaoLocalMaterialIdentity;
  metadata: RouterAbEd25519YaoActiveClientMetadataV1;
}): Ed25519YaoLocalMaterialBindingV1 {
  const metadata = args.metadata;
  if (
    metadata.scope.account_id !== args.identity.walletId ||
    metadata.applicationBinding.wallet_id !== args.identity.walletId ||
    metadata.applicationBinding.near_ed25519_signing_key_id !==
      args.identity.nearEd25519SigningKeyId ||
    metadata.scope.threshold_session_id !== args.identity.thresholdSessionId ||
    metadata.applicationBinding.key_creation_signer_slot !== args.identity.signerSlot ||
    metadata.applicationBinding.signing_root_id !== args.identity.signingRootId ||
    metadata.scope.root_share_epoch !== args.identity.signingRootVersion ||
    metadata.scope.signing_worker_id !== args.identity.signingWorkerId
  ) {
    throw new Error('Active Ed25519 Client metadata does not match the wallet signing lane');
  }
  return {
    kind: ED25519_YAO_LOCAL_MATERIAL_KEY_KIND,
    walletId: args.identity.walletId,
    nearAccountId: args.identity.nearAccountId,
    nearEd25519SigningKeyId: args.identity.nearEd25519SigningKeyId,
    signerSlot: args.identity.signerSlot,
    rpId: args.identity.rpId,
    credentialIdB64u: args.identity.credentialIdB64u,
    lifecycleId: requireNonEmpty(metadata.scope.lifecycle_id, 'lifecycleId'),
    thresholdSessionId: requireThresholdSessionId(
      metadata.scope.threshold_session_id,
      'thresholdSessionId',
    ),
    materialActivation: nearEd25519YaoMaterialActivationFromMetadata(metadata),
    signingRootId: args.identity.signingRootId,
    signingRootVersion: args.identity.signingRootVersion,
    signerSetId: requireNonEmpty(metadata.scope.signer_set_id, 'signerSetId'),
    signingWorkerId: args.identity.signingWorkerId,
    participantIds: [metadata.participantIds[0], metadata.participantIds[1]],
    registeredPublicKeyB64u: base64UrlEncode(metadata.registeredPublicKey),
    signingWorkerVerifyingShareB64u: base64UrlEncode(metadata.signingWorkerVerifyingShare),
    stateEpoch: metadata.stateEpoch.toString(10),
    activationTranscriptB64u: base64UrlEncode(metadata.transcript),
    activationCapabilityBindingB64u: base64UrlEncode(
      Uint8Array.from(metadata.activeCapabilityBinding),
    ),
  };
}

function bindingBytes(binding: Ed25519YaoLocalMaterialBindingV1): Uint8Array {
  return new TextEncoder().encode(
    JSON.stringify([
      binding.kind,
      binding.walletId,
      binding.nearAccountId,
      binding.nearEd25519SigningKeyId,
      binding.signerSlot,
      binding.rpId,
      binding.credentialIdB64u,
      binding.lifecycleId,
      binding.thresholdSessionId,
      binding.materialActivation.kind,
      binding.materialActivation.activationId,
      binding.materialActivation.capability,
      binding.materialActivation.materialOwner,
      binding.materialActivation.keyBinding,
      binding.materialActivation.lifecycleBinding,
      binding.materialActivation.signingWorker,
      binding.signingRootId,
      binding.signingRootVersion,
      binding.signerSetId,
      binding.signingWorkerId,
      binding.participantIds[0],
      binding.participantIds[1],
      binding.registeredPublicKeyB64u,
      binding.signingWorkerVerifyingShareB64u,
      binding.stateEpoch,
      binding.activationTranscriptB64u,
      binding.activationCapabilityBindingB64u,
    ]),
  );
}

function assertBindingIdentity(
  binding: Ed25519YaoLocalMaterialBindingV1,
  identity: Ed25519YaoLocalMaterialIdentity,
): void {
  if (
    binding.walletId !== identity.walletId ||
    binding.nearAccountId !== identity.nearAccountId ||
    binding.nearEd25519SigningKeyId !== identity.nearEd25519SigningKeyId ||
    binding.signerSlot !== identity.signerSlot ||
    binding.rpId !== identity.rpId ||
    binding.credentialIdB64u !== identity.credentialIdB64u ||
    binding.signingRootId !== identity.signingRootId ||
    binding.signingRootVersion !== identity.signingRootVersion ||
    binding.signingWorkerId !== identity.signingWorkerId
  ) {
    throw new Error('Stored Ed25519 Client material does not match the wallet signing lane');
  }
}

export function parsePasskeyEd25519YaoLocalMaterialBindingV1(
  value: unknown,
): Ed25519YaoLocalMaterialBindingV1 {
  const record = asRecord(value);
  if (!record || record.kind !== ED25519_YAO_LOCAL_MATERIAL_KEY_KIND) {
    throw new Error('Stored Ed25519 Client material binding is invalid');
  }
  const materialActivation = parseMpcMaterialActivationRef(record.materialActivation);
  if (!materialActivation.ok) {
    throw new Error(materialActivation.error.message);
  }
  const binding: Ed25519YaoLocalMaterialBindingV1 = {
    kind: ED25519_YAO_LOCAL_MATERIAL_KEY_KIND,
    walletId: requireNonEmpty(record.walletId, 'binding.walletId'),
    nearAccountId: requireNonEmpty(record.nearAccountId, 'binding.nearAccountId'),
    nearEd25519SigningKeyId: requireNonEmpty(
      record.nearEd25519SigningKeyId,
      'binding.nearEd25519SigningKeyId',
    ),
    signerSlot: requirePositiveSafeInteger(record.signerSlot, 'binding.signerSlot'),
    rpId: requireNonEmpty(record.rpId, 'binding.rpId'),
    credentialIdB64u: requireNonEmpty(record.credentialIdB64u, 'binding.credentialIdB64u'),
    lifecycleId: requireNonEmpty(record.lifecycleId, 'binding.lifecycleId'),
    thresholdSessionId: requireThresholdSessionId(
      record.thresholdSessionId,
      'binding.thresholdSessionId',
    ),
    materialActivation: materialActivation.value,
    signingRootId: requireNonEmpty(record.signingRootId, 'binding.signingRootId'),
    signingRootVersion: requireNonEmpty(record.signingRootVersion, 'binding.signingRootVersion'),
    signerSetId: requireNonEmpty(record.signerSetId, 'binding.signerSetId'),
    signingWorkerId: requireNonEmpty(record.signingWorkerId, 'binding.signingWorkerId'),
    participantIds: requireParticipantIds(record.participantIds),
    registeredPublicKeyB64u: requireBytes32B64u(
      record.registeredPublicKeyB64u,
      'binding.registeredPublicKeyB64u',
    ),
    signingWorkerVerifyingShareB64u: requireBytes32B64u(
      record.signingWorkerVerifyingShareB64u,
      'binding.signingWorkerVerifyingShareB64u',
    ),
    stateEpoch: requireU64String(record.stateEpoch, 'binding.stateEpoch'),
    activationTranscriptB64u: requireBytes32B64u(
      record.activationTranscriptB64u,
      'binding.activationTranscriptB64u',
    ),
    activationCapabilityBindingB64u: requireBytes32B64u(
      record.activationCapabilityBindingB64u,
      'binding.activationCapabilityBindingB64u',
    ),
  };
  if (
    binding.materialActivation.materialOwner !== binding.walletId ||
    binding.materialActivation.signingWorker !== binding.signingWorkerId
  ) {
    throw new Error('Stored Ed25519 Client material activation does not match its binding');
  }
  return binding;
}

function parseStoredBinding(
  value: unknown,
  identity: Ed25519YaoLocalMaterialIdentity,
): Ed25519YaoLocalMaterialBindingV1 {
  const binding = parsePasskeyEd25519YaoLocalMaterialBindingV1(value);
  assertBindingIdentity(binding, identity);
  return binding;
}

function parseStableServerScope(value: unknown): PasskeyEd25519YaoStableServerScopeV1 {
  const record = asRecord(value);
  if (!record) {
    throw new Error('Stored Ed25519 Client stable server scope is invalid');
  }
  const runtimePolicyScope = normalizeThresholdRuntimePolicyScope(record.runtimePolicyScope);
  if (!runtimePolicyScope) {
    throw new Error('Stored Ed25519 Client server runtime policy scope is invalid');
  }
  return {
    relayerKeyId: requireNonEmpty(record.relayerKeyId, 'stableServerScope.relayerKeyId'),
    participantIds: requireParticipantIds(record.participantIds),
    runtimePolicyScope,
    routerAbNormalSigning: requireRouterAbEd25519NormalSigningState(record.routerAbNormalSigning),
  };
}

async function parseStoredLocalMaterialLocator(args: {
  stored: KeyMaterialRecord;
  target: PasskeyEd25519YaoLocalMaterialTargetV1;
  authority: WalletAuthAuthorityRef;
}): Promise<PasskeyEd25519YaoLocalMaterialLocatorV1> {
  const value = args.stored.payload;
  const record = asRecord(value);
  if (!record) {
    throw new Error('Stored Ed25519 Client local material locator is invalid');
  }
  const binding = parsePasskeyEd25519YaoLocalMaterialBindingV1(record.binding);
  const expectedPublicKey = `ed25519:${base58Encode(base64UrlDecode(binding.registeredPublicKeyB64u))}`;
  const envelope = args.stored.payloadEnvelope;
  if (
    args.stored.profileId !== args.target.profileId ||
    args.stored.chainIdKey !== args.target.chainIdKey ||
    args.stored.accountAddress !== args.target.accountAddress ||
    args.stored.keyKind !== ED25519_YAO_LOCAL_MATERIAL_KEY_KIND ||
    args.stored.schemaVersion !== ED25519_YAO_LOCAL_MATERIAL_SCHEMA_VERSION ||
    args.stored.publicKey !== expectedPublicKey ||
    args.stored.signerId !== binding.nearEd25519SigningKeyId ||
    envelope?.encVersion !== KEY_PAYLOAD_ENC_VERSION ||
    envelope.alg !== ED25519_YAO_LOCAL_MATERIAL_ALGORITHM
  ) {
    throw new Error('Stored Ed25519 Client local material record is invalid');
  }
  const parsedAuthority = parsePasskeyWalletAuthAuthority({
    walletId: binding.walletId,
    factor: {
      kind: 'passkey',
      credentialIdB64u: binding.credentialIdB64u,
    },
    verifier: {
      kind: 'webauthn',
      rpId: binding.rpId,
    },
    bindingId: args.authority.walletAuthMethodId,
  });
  if (!parsedAuthority) {
    throw new Error('Stored Ed25519 Client local material authority is invalid');
  }
  const authority = await walletAuthAuthorityRef({
    authority: parsedAuthority,
  });
  if (authority.authorityDigest !== args.authority.authorityDigest) {
    throw new Error('Stored Ed25519 Client local material authority changed');
  }
  return {
    kind: 'passkey_ed25519_yao_local_material_locator_v1',
    authority,
    materialActivation: binding.materialActivation,
    sealedMaterial: buildRestorableMpcMaterialRefInternal(
      JSON.stringify([
        args.stored.profileId,
        args.stored.signerSlot,
        args.stored.chainIdKey,
        args.stored.keyKind,
        binding.materialActivation.activationId,
      ]),
    ),
    stableServerScope: parseStableServerScope(record.stableServerScope),
  };
}

function assertStoredIdentitySubset(args: {
  stored: KeyMaterialRecord;
  target: {
    profileId: string;
    chainIdKey: string;
    accountAddress: string;
  };
  input: ReadPasskeyEd25519YaoLocalMaterialLocatorInputV1;
}): void {
  const binding = asRecord(args.stored.payload?.binding);
  if (
    args.stored.profileId !== args.target.profileId ||
    args.stored.chainIdKey !== args.target.chainIdKey ||
    args.stored.accountAddress !== args.target.accountAddress ||
    args.stored.signerSlot !== args.input.signerSlot ||
    args.stored.signerId !== args.input.nearEd25519SigningKeyId ||
    args.stored.keyKind !== ED25519_YAO_LOCAL_MATERIAL_KEY_KIND ||
    binding?.kind !== ED25519_YAO_LOCAL_MATERIAL_KEY_KIND ||
    binding.walletId !== args.input.walletId ||
    binding.nearAccountId !== args.input.nearAccountId ||
    binding.nearEd25519SigningKeyId !== args.input.nearEd25519SigningKeyId ||
    binding.signerSlot !== args.input.signerSlot ||
    binding.rpId !== args.input.rpId ||
    binding.credentialIdB64u !== args.input.credentialIdB64u
  ) {
    throw new Error('Stored Ed25519 Client material locator does not match local custody');
  }
}

export function metadataFromPasskeyEd25519YaoLocalMaterialBindingV1(
  binding: Ed25519YaoLocalMaterialBindingV1,
  thresholdSessionId: string,
): RouterAbEd25519YaoActiveClientMetadataV1 {
  const resolvedThresholdSessionId = requireNonEmpty(thresholdSessionId, 'thresholdSessionId');
  return {
    kind: ROUTER_AB_ED25519_YAO_ACTIVE_CLIENT_KIND_V1,
    scope: {
      lifecycle_id: binding.lifecycleId,
      root_share_epoch: binding.signingRootVersion,
      account_id: binding.walletId,
      threshold_session_id: resolvedThresholdSessionId,
      signer_set_id: binding.signerSetId,
      signing_worker_id: binding.signingWorkerId,
      material_activation: routerAbMpcMaterialActivationRefToWire(binding.materialActivation),
    },
    applicationBinding: {
      wallet_id: binding.walletId,
      near_ed25519_signing_key_id: binding.nearEd25519SigningKeyId,
      signing_root_id: binding.signingRootId,
      key_creation_signer_slot: binding.signerSlot,
    },
    participantIds: binding.participantIds,
    registeredPublicKey: base64UrlDecode(binding.registeredPublicKeyB64u),
    signingWorkerVerifyingShare: base64UrlDecode(binding.signingWorkerVerifyingShareB64u),
    stateEpoch: BigInt(binding.stateEpoch),
    transcript: base64UrlDecode(binding.activationTranscriptB64u),
    activeCapabilityBinding: Array.from(base64UrlDecode(binding.activationCapabilityBindingB64u)),
    materialActivation: binding.materialActivation,
  };
}

function randomNonce(): Uint8Array {
  const nonce = new Uint8Array(ED25519_YAO_LOCAL_MATERIAL_NONCE_BYTES);
  globalThis.crypto.getRandomValues(nonce);
  return nonce;
}

function buildPasskeyEd25519YaoLocalMaterialRecordV1(input: {
  target: PasskeyEd25519YaoLocalMaterialTargetV1;
  activeClient: RouterAbEd25519YaoSealableActiveClientV1;
  identity: Ed25519YaoLocalMaterialIdentity;
  stableServerScope: PasskeyEd25519YaoStableServerScopeV1;
  ownedPasskeyPrfFirst: Uint8Array;
  lifecycle:
    | { kind: 'registration_or_rehydration'; promotionReceipt?: never }
    | {
        kind: 'recovery_promotion';
        promotionReceipt: RouterAbEd25519YaoRecoveryActivationReceiptV1;
      };
}): KeyMaterialRecord {
  const identity = input.identity;
  const metadata = input.activeClient.metadata();
  const binding = bindingFromActiveClient({ identity, metadata });
  const nonce = randomNonce();
  const sealed = input.activeClient.sealLocalMaterial({
    ownedPasskeyPrfFirst: input.ownedPasskeyPrfFirst,
    binding: bindingBytes(binding),
    nonce,
  });
  const payload: Record<string, unknown> = {
    binding,
    stableServerScope: input.stableServerScope,
  };
  switch (input.lifecycle.kind) {
    case 'registration_or_rehydration':
      break;
    case 'recovery_promotion':
      payload.lifecycleReceipt = input.lifecycle.promotionReceipt;
      break;
    default:
      input.lifecycle satisfies never;
  }
  return {
    profileId: input.target.profileId,
    signerSlot: identity.signerSlot,
    chainIdKey: input.target.chainIdKey,
    accountAddress: input.target.accountAddress,
    keyKind: ED25519_YAO_LOCAL_MATERIAL_KEY_KIND,
    algorithm: 'ed25519',
    publicKey: `ed25519:${base58Encode(metadata.registeredPublicKey)}`,
    signerId: identity.nearEd25519SigningKeyId,
    payload,
    payloadEnvelope: {
      encVersion: KEY_PAYLOAD_ENC_VERSION,
      alg: ED25519_YAO_LOCAL_MATERIAL_ALGORITHM,
      nonce: base64UrlEncode(sealed.nonce),
      ciphertext: base64UrlEncode(sealed.ciphertext),
      aad: buildEnvelopeAAD({
        profileId: input.target.profileId,
        signerSlot: identity.signerSlot,
        chainIdKey: input.target.chainIdKey,
        accountAddress: input.target.accountAddress,
        keyKind: ED25519_YAO_LOCAL_MATERIAL_KEY_KIND,
        schemaVersion: ED25519_YAO_LOCAL_MATERIAL_SCHEMA_VERSION,
        signerId: identity.nearEd25519SigningKeyId,
      }),
    },
    timestamp: Date.now(),
    schemaVersion: ED25519_YAO_LOCAL_MATERIAL_SCHEMA_VERSION,
  };
}

export function buildPromotedPasskeyEd25519YaoLocalMaterialRecordV1(
  input: BuildPromotedPasskeyEd25519YaoLocalMaterialRecordInputV1,
): KeyMaterialRecord {
  const identity = walletSessionIdentity(
    input.walletSessionState,
    input.rpId,
    input.credentialIdB64u,
  );
  return buildPasskeyEd25519YaoLocalMaterialRecordV1({
    target: input.target,
    activeClient: input.activeClient,
    identity,
    stableServerScope: stableServerScopeFromActiveClient(
      input.activeClient,
      input.walletSessionState,
    ),
    ownedPasskeyPrfFirst: input.ownedPasskeyPrfFirst,
    lifecycle: {
      kind: 'recovery_promotion',
      promotionReceipt: input.promotionReceipt,
    },
  });
}

export async function persistPasskeyEd25519YaoLocalMaterialV1(
  input: PersistPasskeyEd25519YaoLocalMaterialInputV1,
): Promise<void> {
  const identity = walletSessionIdentity(
    input.walletSessionState,
    input.rpId,
    input.credentialIdB64u,
  );
  const target = await resolveAccountKeyMaterialTarget(input.store, {
    accountRefs: buildNearAccountRefs(identity.nearAccountId),
  });
  if (!target) {
    throw new Error('Local Ed25519 material requires a persisted wallet profile');
  }
  const record = buildPasskeyEd25519YaoLocalMaterialRecordV1({
    target,
    activeClient: input.activeClient,
    identity,
    stableServerScope: stableServerScopeFromActiveClient(
      input.activeClient,
      input.walletSessionState,
    ),
    ownedPasskeyPrfFirst: base64UrlDecode(input.passkeyPrfFirstB64u),
    lifecycle: { kind: 'registration_or_rehydration' },
  });
  await input.store.storeKeyMaterial(record);
}

export async function persistPasskeyEd25519YaoSignerMaterialV1(
  input: PersistPasskeyEd25519YaoSignerMaterialInputV1,
): Promise<void> {
  const target = await resolveAccountKeyMaterialTarget(input.store, {
    accountRefs: buildNearAccountRefs(input.identity.nearAccountId),
  });
  if (!target) {
    throw new Error('Local Ed25519 material requires a persisted wallet profile');
  }
  const record = buildPasskeyEd25519YaoLocalMaterialRecordV1({
    target,
    activeClient: input.activeClient,
    identity: input.identity,
    stableServerScope: input.stableServerScope,
    ownedPasskeyPrfFirst: base64UrlDecode(input.passkeyPrfFirstB64u),
    lifecycle: { kind: 'registration_or_rehydration' },
  });
  await input.store.storeKeyMaterial(record);
}

export async function deletePasskeyEd25519YaoSignerMaterialV1(input: {
  store: Ed25519YaoLocalMaterialStorePort;
  nearAccountId: string;
  signerSlot: number;
}): Promise<void> {
  const target = await resolveAccountKeyMaterialTarget(input.store, {
    accountRefs: buildNearAccountRefs(input.nearAccountId),
  });
  if (!target) return;
  await input.store.deleteKeyMaterial(
    target.profileId,
    requirePositiveSafeInteger(input.signerSlot, 'signerSlot'),
    target.chainIdKey,
    ED25519_YAO_LOCAL_MATERIAL_KEY_KIND,
  );
}

export async function readPasskeyEd25519YaoLocalMaterialLocatorV1(
  input: ReadPasskeyEd25519YaoLocalMaterialLocatorInputV1,
): Promise<ReadPasskeyEd25519YaoLocalMaterialLocatorResultV1> {
  const nearAccountId = requireNonEmpty(input.nearAccountId, 'nearAccountId');
  const target = await resolveAccountKeyMaterialTarget(input.store, {
    accountRefs: buildNearAccountRefs(nearAccountId),
  });
  if (!target) return { kind: 'unavailable' };
  const stored = await input.store.getKeyMaterial(
    target.profileId,
    requirePositiveSafeInteger(input.signerSlot, 'signerSlot'),
    target.chainIdKey,
    ED25519_YAO_LOCAL_MATERIAL_KEY_KIND,
  );
  if (!stored) return { kind: 'unavailable' };
  assertStoredIdentitySubset({ stored, target, input });
  return {
    kind: 'available',
    locator: await parseStoredLocalMaterialLocator({ stored, target, authority: input.authority }),
  };
}

function publicLocatorMatchesWalletSession(args: {
  publicLocator: Extract<PasskeyEd25519YaoPublicLocatorObservationV1, { kind: 'available' }>;
  walletSessionState: NearResolvedEd25519SigningSessionState;
}): boolean {
  const signer = args.walletSessionState.signingLane.identity.signer;
  return (
    args.publicLocator.walletId === String(signer.account.wallet.walletId) &&
    args.publicLocator.nearAccountId === String(signer.account.nearAccountId) &&
    args.publicLocator.signerSlot === signer.signerSlot
  );
}

async function expectedPasskeyAuthority(args: {
  walletSessionState: NearResolvedEd25519SigningSessionState;
  rpId: string;
  credentialIdB64u: string;
  authority: WalletAuthAuthorityRef;
}): Promise<WalletAuthAuthorityRef> {
  const authority = parsePasskeyWalletAuthAuthority({
    walletId: args.walletSessionState.signingLane.identity.signer.account.wallet.walletId,
    factor: {
      kind: 'passkey',
      credentialIdB64u: args.credentialIdB64u,
    },
    verifier: {
      kind: 'webauthn',
      rpId: args.rpId,
    },
    bindingId: args.authority.walletAuthMethodId,
  });
  if (!authority) throw new Error('Passkey Ed25519 authority is invalid');
  const authorityRef = await walletAuthAuthorityRef({ authority });
  if (authorityRef.authorityDigest !== args.authority.authorityDigest) {
    throw new Error('Passkey Ed25519 authority does not match the Wallet Session');
  }
  return authorityRef;
}

function liveRuntimeObservation(
  material: NearEd25519YaoOperationMaterial | null,
): NearEd25519YaoRuntimeObservationV1 {
  if (!material) return { kind: 'absent' };
  if (material.activeClient.status().kind !== 'active') return { kind: 'absent' };
  const materialActivation = nearEd25519YaoMaterialActivationFromMetadata(
    material.activeClient.metadata(),
  );
  return {
    kind: 'live',
    runtime: nearEd25519YaoRuntimeRef(materialActivation),
    materialActivation,
  };
}

function hydrationBlocked(
  plan: Extract<MpcCapabilityHydrationPlan, { kind: 'blocked' }>,
): HydratePasskeyEd25519YaoLocalMaterialResultV1 {
  return { kind: 'blocked', plan };
}

export async function preparePasskeyEd25519YaoLocalMaterialRehydrationV1(input: {
  store: Ed25519YaoLocalMaterialStorePort;
  walletSessionState: NearResolvedEd25519SigningSessionState;
  rpId: string;
  credentialIdB64u: string;
  authority: WalletAuthAuthorityRef;
  publicLocator: PasskeyEd25519YaoPublicLocatorObservationV1;
}): Promise<PreparePasskeyEd25519YaoLocalMaterialRehydrationResultV1> {
  const expectedAuthority = await expectedPasskeyAuthority(input);
  const publicLocator: NearEd25519YaoPublicLocatorObservationV1 =
    input.publicLocator.kind === 'available' &&
    !publicLocatorMatchesWalletSession({
      publicLocator: input.publicLocator,
      walletSessionState: input.walletSessionState,
    })
      ? { kind: 'conflict' }
      : input.publicLocator.kind === 'available'
        ? { ...input.publicLocator, authority: expectedAuthority }
        : input.publicLocator;
  let localMaterial: ReadPasskeyEd25519YaoLocalMaterialLocatorResultV1;
  try {
    localMaterial = await readPasskeyEd25519YaoLocalMaterialLocatorV1({
      store: input.store,
      walletId: String(
        input.walletSessionState.signingLane.identity.signer.account.wallet.walletId,
      ),
      nearAccountId: String(
        input.walletSessionState.signingLane.identity.signer.account.nearAccountId,
      ),
      nearEd25519SigningKeyId: String(
        input.walletSessionState.signingLane.identity.signer.nearEd25519SigningKeyId,
      ),
      signerSlot: input.walletSessionState.signingLane.identity.signer.signerSlot,
      rpId: input.rpId,
      credentialIdB64u: input.credentialIdB64u,
      authority: expectedAuthority,
    });
  } catch {
    const plan = resolveNearEd25519YaoCapabilityHydrationV1({
      publicLocator,
      sealed: { kind: 'corrupt' },
      runtime: { kind: 'absent' },
      unlockSource: { kind: 'unavailable' },
    });
    if (plan.kind !== 'blocked') {
      throw new Error('Corrupt Near Ed25519 material resolved to an executable hydration plan');
    }
    return {
      kind: 'blocked',
      plan,
    };
  }
  const plan = resolveNearEd25519YaoCapabilityHydrationV1({
    publicLocator,
    sealed:
      localMaterial.kind === 'available'
        ? {
            kind: 'available',
            authority: localMaterial.locator.authority,
            materialActivation: localMaterial.locator.materialActivation,
            sealedMaterial: localMaterial.locator.sealedMaterial,
          }
        : { kind: 'missing' },
    runtime: { kind: 'absent' },
    unlockSource: { kind: 'available', authority: expectedAuthority },
  });
  switch (plan.kind) {
    case 'rehydrate_material_activation':
      return { kind: 'prepared', plan };
    case 'blocked':
      return { kind: 'blocked', plan };
    case 'use_live_runtime':
    case 'reauthorize_public_anchor':
      throw new Error('Sealed Near Ed25519 preparation resolved an invalid hydration plan');
    default:
      plan satisfies never;
      throw new Error('Unsupported sealed Near Ed25519 preparation plan');
  }
}

export async function hydratePasskeyEd25519YaoLocalMaterialV1(input: {
  store: Ed25519YaoLocalMaterialStorePort;
  walletSessionState: NearResolvedEd25519SigningSessionState;
  rpId: string;
  credentialIdB64u: string;
  authority: WalletAuthAuthorityRef;
  publicLocator: PasskeyEd25519YaoPublicLocatorObservationV1;
  unlockSource: PasskeyEd25519YaoUnlockSourceV1;
  liveMaterial: NearEd25519YaoOperationMaterial | null;
}): Promise<HydratePasskeyEd25519YaoLocalMaterialResultV1> {
  const expectedAuthority = await expectedPasskeyAuthority(input);
  const publicLocator: NearEd25519YaoPublicLocatorObservationV1 =
    input.publicLocator.kind === 'available' &&
    !publicLocatorMatchesWalletSession({
      publicLocator: input.publicLocator,
      walletSessionState: input.walletSessionState,
    })
      ? { kind: 'conflict' }
      : input.publicLocator.kind === 'available'
        ? { ...input.publicLocator, authority: expectedAuthority }
        : input.publicLocator;
  let localMaterial: ReadPasskeyEd25519YaoLocalMaterialLocatorResultV1;
  try {
    localMaterial = await readPasskeyEd25519YaoLocalMaterialLocatorV1({
      store: input.store,
      walletId: String(
        input.walletSessionState.signingLane.identity.signer.account.wallet.walletId,
      ),
      nearAccountId: String(
        input.walletSessionState.signingLane.identity.signer.account.nearAccountId,
      ),
      nearEd25519SigningKeyId: String(
        input.walletSessionState.signingLane.identity.signer.nearEd25519SigningKeyId,
      ),
      signerSlot: input.walletSessionState.signingLane.identity.signer.signerSlot,
      rpId: input.rpId,
      credentialIdB64u: input.credentialIdB64u,
      authority: expectedAuthority,
    });
  } catch {
    const plan = resolveNearEd25519YaoCapabilityHydrationV1({
      publicLocator,
      sealed: { kind: 'corrupt' },
      runtime: liveRuntimeObservation(input.liveMaterial),
      unlockSource: { kind: 'unavailable' },
    });
    if (plan.kind !== 'blocked') {
      throw new Error('Corrupt Near Ed25519 material resolved to an executable hydration plan');
    }
    return hydrationBlocked(plan);
  }
  const unlockSource: NearEd25519YaoUnlockSourceObservationV1 =
    input.unlockSource.kind === 'available'
      ? { kind: 'available', authority: expectedAuthority }
      : { kind: 'unavailable' };
  const plan = resolveNearEd25519YaoCapabilityHydrationV1({
    publicLocator,
    sealed:
      localMaterial.kind === 'available'
        ? {
            kind: 'available',
            authority: localMaterial.locator.authority,
            materialActivation: localMaterial.locator.materialActivation,
            sealedMaterial: localMaterial.locator.sealedMaterial,
          }
        : { kind: 'missing' },
    runtime: liveRuntimeObservation(input.liveMaterial),
    unlockSource,
  });
  switch (plan.kind) {
    case 'use_live_runtime': {
      const material = input.liveMaterial;
      if (
        !material ||
        material.activeClient.status().kind !== 'active' ||
        !mpcMaterialActivationRefsEqual(
          plan.materialActivation,
          nearEd25519YaoMaterialActivationFromMetadata(material.activeClient.metadata()),
        )
      ) {
        throw new Error('Near Ed25519 live hydration plan lost its exact runtime');
      }
      return { kind: 'live', plan, material };
    }
    case 'rehydrate_material_activation': {
      if (input.unlockSource.kind !== 'available') {
        throw new Error('Near Ed25519 rehydration plan lost its unlock source');
      }
      const rehydrated = await rehydratePasskeyEd25519YaoLocalMaterialV1({
        store: input.store,
        walletSessionState: input.walletSessionState,
        rpId: input.rpId,
        credentialIdB64u: input.credentialIdB64u,
        passkeyPrfFirstB64u: input.unlockSource.passkeyPrfFirstB64u,
      });
      if (rehydrated.kind !== 'rehydrated') {
        throw new Error('Near Ed25519 rehydration plan lost its sealed material');
      }
      const rehydratedActivation = nearEd25519YaoMaterialActivationFromMetadata(
        rehydrated.activeClient.metadata(),
      );
      if (!mpcMaterialActivationRefsEqual(plan.materialActivation, rehydratedActivation)) {
        rehydrated.activeClient.dispose();
        throw new Error('Near Ed25519 rehydration changed the material activation');
      }
      return { kind: 'rehydrated', plan, activeClient: rehydrated.activeClient };
    }
    case 'blocked':
      return hydrationBlocked(plan);
    case 'reauthorize_public_anchor':
      throw new Error('Near Ed25519 material retirement requires explicit reauthorization');
    default:
      plan satisfies never;
      throw new Error('Unsupported Near Ed25519 hydration plan');
  }
}

export async function deletePasskeyEd25519YaoLocalMaterialV1(
  input: DeletePasskeyEd25519YaoLocalMaterialInputV1,
): Promise<void> {
  const identity = walletSessionIdentity(
    input.walletSessionState,
    input.rpId,
    input.credentialIdB64u,
  );
  const target = await resolveAccountKeyMaterialTarget(input.store, {
    accountRefs: buildNearAccountRefs(identity.nearAccountId),
  });
  if (!target) return;
  await input.store.deleteKeyMaterial(
    target.profileId,
    identity.signerSlot,
    target.chainIdKey,
    ED25519_YAO_LOCAL_MATERIAL_KEY_KIND,
  );
}

export async function rehydratePasskeyEd25519YaoLocalMaterialV1(
  input: RehydratePasskeyEd25519YaoLocalMaterialInputV1,
): Promise<RehydratePasskeyEd25519YaoLocalMaterialResultV1> {
  const identity = walletSessionIdentity(
    input.walletSessionState,
    input.rpId,
    input.credentialIdB64u,
  );
  const target = await resolveAccountKeyMaterialTarget(input.store, {
    accountRefs: buildNearAccountRefs(identity.nearAccountId),
  });
  if (!target) return { kind: 'unavailable' };
  const stored = await input.store.getKeyMaterial(
    target.profileId,
    identity.signerSlot,
    target.chainIdKey,
    ED25519_YAO_LOCAL_MATERIAL_KEY_KIND,
  );
  if (!stored) return { kind: 'unavailable' };
  return rehydratePasskeyEd25519YaoLocalMaterialRecordV1({
    stored,
    target,
    walletSessionState: input.walletSessionState,
    rpId: input.rpId,
    credentialIdB64u: input.credentialIdB64u,
    ownedPasskeyPrfFirst: base64UrlDecode(input.passkeyPrfFirstB64u),
  });
}

export async function rehydratePasskeyEd25519YaoLocalMaterialRecordV1(
  input: RehydratePasskeyEd25519YaoLocalMaterialRecordInputV1,
): Promise<Extract<RehydratePasskeyEd25519YaoLocalMaterialResultV1, { kind: 'rehydrated' }>> {
  const identity = walletSessionIdentity(
    input.walletSessionState,
    input.rpId,
    input.credentialIdB64u,
  );
  const stored = input.stored;
  const target = input.target;
  const envelope = stored.payloadEnvelope;
  if (
    stored.profileId !== target.profileId ||
    stored.accountAddress !== target.accountAddress ||
    stored.signerId !== identity.nearEd25519SigningKeyId ||
    stored.keyKind !== ED25519_YAO_LOCAL_MATERIAL_KEY_KIND ||
    stored.schemaVersion !== ED25519_YAO_LOCAL_MATERIAL_SCHEMA_VERSION ||
    envelope?.encVersion !== KEY_PAYLOAD_ENC_VERSION ||
    envelope.alg !== ED25519_YAO_LOCAL_MATERIAL_ALGORITHM
  ) {
    throw new Error('Stored Ed25519 Client material record is invalid');
  }
  const binding = parseStoredBinding(stored.payload?.binding, identity);
  const metadata = metadataFromPasskeyEd25519YaoLocalMaterialBindingV1(
    binding,
    identity.thresholdSessionId,
  );
  const expectedPublicKey = `ed25519:${base58Encode(metadata.registeredPublicKey)}`;
  if (stored.publicKey !== expectedPublicKey) {
    throw new Error('Stored Ed25519 Client public key does not match its sealed binding');
  }
  const client = await RouterAbEd25519YaoClientV1.initializeBundled();
  const activeClient = client.importLocalMaterial({
    ownedPasskeyPrfFirst: input.ownedPasskeyPrfFirst,
    binding: bindingBytes(binding),
    sealed: {
      kind: 'router_ab_ed25519_yao_sealed_local_material_v1',
      nonce: base64UrlDecode(envelope.nonce),
      ciphertext: base64UrlDecode(envelope.ciphertext),
    },
    metadata,
  });
  return { kind: 'rehydrated', activeClient };
}
