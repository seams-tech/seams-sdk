import { buildNearAccountRefs } from '@/core/accountData/near/accountRefs';
import { buildEnvelopeAAD, KEY_PAYLOAD_ENC_VERSION } from '@/core/indexedDB/keyMaterialEnvelope';
import type { KeyMaterialRecord } from '@/core/indexedDB/keyMaterial.types';
import {
  resolveAccountKeyMaterialTarget,
  type AccountKeyMaterialDeps,
} from '@/core/indexedDB/accountKeyMaterial';
import type { NearResolvedEd25519SigningSessionState } from '@/core/signingEngine/interfaces/near';
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

export const ED25519_YAO_LOCAL_MATERIAL_KEY_KIND =
  'router_ab_ed25519_yao_active_client_v1' as const;
const ED25519_YAO_LOCAL_MATERIAL_SCHEMA_VERSION = 1;
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

type Ed25519YaoLocalMaterialIdentity = {
  walletId: string;
  nearAccountId: string;
  nearEd25519SigningKeyId: string;
  signerSlot: number;
  rpId: string;
  credentialIdB64u: string;
  signingRootId: string;
  signingRootVersion: string;
  signingWorkerId: string;
};

type Ed25519YaoLocalMaterialBindingV1 = {
  kind: typeof ED25519_YAO_LOCAL_MATERIAL_KEY_KIND;
  walletId: string;
  nearAccountId: string;
  nearEd25519SigningKeyId: string;
  signerSlot: number;
  rpId: string;
  credentialIdB64u: string;
  lifecycleId: string;
  activeStateSessionId: string;
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
  stableServerScope: PasskeyEd25519YaoStableServerScopeV1;
  thresholdSessionId?: never;
  signingGrantId?: never;
};

export type ReadPasskeyEd25519YaoLocalMaterialLocatorInputV1 = {
  store: Ed25519YaoLocalMaterialStorePort;
  walletId: string;
  nearAccountId: string;
  nearEd25519SigningKeyId: string;
  signerSlot: number;
  rpId: string;
  credentialIdB64u: string;
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

export type RehydratePasskeyEd25519YaoLocalMaterialInputV1 = {
  store: Ed25519YaoLocalMaterialStorePort;
  walletSessionState: NearResolvedEd25519SigningSessionState;
  rpId: string;
  credentialIdB64u: string;
  passkeyPrfFirstB64u: string;
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
    activeStateSessionId: requireNonEmpty(metadata.scope.wallet_session_id, 'activeStateSessionId'),
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
      binding.activeStateSessionId,
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

function parseStoredBinding(
  value: unknown,
  identity: Ed25519YaoLocalMaterialIdentity,
): Ed25519YaoLocalMaterialBindingV1 {
  const record = asRecord(value);
  if (!record || record.kind !== ED25519_YAO_LOCAL_MATERIAL_KEY_KIND) {
    throw new Error('Stored Ed25519 Client material binding is invalid');
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
    activeStateSessionId: requireNonEmpty(
      record.activeStateSessionId,
      'binding.activeStateSessionId',
    ),
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

function parseStoredLocalMaterialLocator(value: unknown): PasskeyEd25519YaoLocalMaterialLocatorV1 {
  const record = asRecord(value);
  if (!record) {
    throw new Error('Stored Ed25519 Client local material locator is invalid');
  }
  return {
    kind: 'passkey_ed25519_yao_local_material_locator_v1',
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

function metadataFromBinding(
  binding: Ed25519YaoLocalMaterialBindingV1,
): RouterAbEd25519YaoActiveClientMetadataV1 {
  return {
    kind: ROUTER_AB_ED25519_YAO_ACTIVE_CLIENT_KIND_V1,
    scope: {
      lifecycle_id: binding.lifecycleId,
      root_share_epoch: binding.signingRootVersion,
      account_id: binding.walletId,
      wallet_session_id: binding.activeStateSessionId,
      signer_set_id: binding.signerSetId,
      signing_worker_id: binding.signingWorkerId,
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
  };
}

function randomNonce(): Uint8Array {
  const nonce = new Uint8Array(ED25519_YAO_LOCAL_MATERIAL_NONCE_BYTES);
  globalThis.crypto.getRandomValues(nonce);
  return nonce;
}

export async function persistPasskeyEd25519YaoLocalMaterialV1(
  input: PersistPasskeyEd25519YaoLocalMaterialInputV1,
): Promise<void> {
  const identity = walletSessionIdentity(
    input.walletSessionState,
    input.rpId,
    input.credentialIdB64u,
  );
  const metadata = input.activeClient.metadata();
  const binding = bindingFromActiveClient({ identity, metadata });
  const nonce = randomNonce();
  const sealed = input.activeClient.sealLocalMaterial({
    ownedPasskeyPrfFirst: base64UrlDecode(input.passkeyPrfFirstB64u),
    binding: bindingBytes(binding),
    nonce,
  });
  const target = await resolveAccountKeyMaterialTarget(input.store, {
    accountRefs: buildNearAccountRefs(identity.nearAccountId),
  });
  if (!target) {
    throw new Error('Local Ed25519 material requires a persisted wallet profile');
  }
  const record: KeyMaterialRecord = {
    profileId: target.profileId,
    signerSlot: identity.signerSlot,
    chainIdKey: target.chainIdKey,
    accountAddress: target.accountAddress,
    keyKind: ED25519_YAO_LOCAL_MATERIAL_KEY_KIND,
    algorithm: 'ed25519',
    publicKey: `ed25519:${base58Encode(metadata.registeredPublicKey)}`,
    signerId: identity.nearEd25519SigningKeyId,
    payload: {
      binding,
      stableServerScope: {
        relayerKeyId: binding.signingWorkerId,
        participantIds: binding.participantIds,
        runtimePolicyScope: input.walletSessionState.runtimePolicyScope,
        routerAbNormalSigning: input.walletSessionState.routerAbNormalSigning,
      },
    },
    payloadEnvelope: {
      encVersion: KEY_PAYLOAD_ENC_VERSION,
      alg: ED25519_YAO_LOCAL_MATERIAL_ALGORITHM,
      nonce: base64UrlEncode(sealed.nonce),
      ciphertext: base64UrlEncode(sealed.ciphertext),
      aad: buildEnvelopeAAD({
        profileId: target.profileId,
        signerSlot: identity.signerSlot,
        chainIdKey: target.chainIdKey,
        accountAddress: target.accountAddress,
        keyKind: ED25519_YAO_LOCAL_MATERIAL_KEY_KIND,
        schemaVersion: ED25519_YAO_LOCAL_MATERIAL_SCHEMA_VERSION,
        signerId: identity.nearEd25519SigningKeyId,
      }),
    },
    timestamp: Date.now(),
    schemaVersion: ED25519_YAO_LOCAL_MATERIAL_SCHEMA_VERSION,
  };
  await input.store.storeKeyMaterial(record);
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
    locator: parseStoredLocalMaterialLocator(stored.payload),
  };
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
  const metadata = metadataFromBinding(binding);
  const expectedPublicKey = `ed25519:${base58Encode(metadata.registeredPublicKey)}`;
  if (stored.publicKey !== expectedPublicKey) {
    throw new Error('Stored Ed25519 Client public key does not match its sealed binding');
  }
  const client = await RouterAbEd25519YaoClientV1.initializeBundled();
  const activeClient = client.importLocalMaterial({
    ownedPasskeyPrfFirst: base64UrlDecode(input.passkeyPrfFirstB64u),
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
