import type { ThresholdEd25519PresignCommitmentsWire } from '@/core/types/signer-worker';
import type { RuntimePolicyScope } from '@shared/threshold/signingRootScope';
import type {
  Ed25519ClientPresignEntry,
  Ed25519ClientPresignId,
  Ed25519ClientPresignNonceHandle,
  Ed25519ClientPresignPoolState,
  Ed25519PresignOperationIdentity,
  Ed25519PresignScopeKey,
  Ed25519ReadyClientPresignEntry,
  Ed25519ServerPresignId,
} from './presignPool';
import { DEFAULT_ED25519_PRESIGN_POOL_POLICY } from './presignPool';
import type {
  SigningOperationFingerprint,
  SigningOperationId,
} from '../../session/operationState/types';

declare const clientPresignId: Ed25519ClientPresignId;
declare const nonceHandle: Ed25519ClientPresignNonceHandle;
declare const presignId: Ed25519ServerPresignId;
declare const scopeKey: Ed25519PresignScopeKey;
declare const operationId: SigningOperationId;
declare const operationFingerprint: SigningOperationFingerprint;

const commitments: ThresholdEd25519PresignCommitmentsWire = {
  hiding: 'hiding-commitment',
  binding: 'binding-commitment',
};

const runtimePolicyScope: RuntimePolicyScope = {
  orgId: 'org',
  projectId: 'project',
  envId: 'env',
  signingRootVersion: 'root-v1',
};

const routerAbPoolEntry = {
  kind: 'router_ab_ed25519_presign_pool_entry_v2',
  scope: {
    request_id: 'router-ab-presign-pool-refill-1',
    account_id: 'account.near',
    session_id: 'threshold-session-1',
    signing_worker_id: 'server-a',
  },
  generation: 1,
  poolEntryBindingDigest: { bytes: Array.from({ length: 32 }, () => 1) },
} as const;

const offeredEntry: Ed25519ClientPresignEntry = {
  state: 'offered',
  clientPresignId,
  nonceHandle,
  clientVerifyingShareB64u: 'client-verifying-share',
  clientCommitments: commitments,
  createdAtMs: 1,
};
void offeredEntry;

// @ts-expect-error offered entries cannot carry a server presign id.
const invalidOfferedWithServerId: Ed25519ClientPresignEntry = {
  state: 'offered',
  clientPresignId,
  nonceHandle,
  clientVerifyingShareB64u: 'client-verifying-share',
  clientCommitments: commitments,
  createdAtMs: 1,
  presignId,
};
void invalidOfferedWithServerId;

const readyEntry: Ed25519ReadyClientPresignEntry = {
  state: 'ready',
  source: 'router_ab_ed25519_presign_pool_v2',
  presignId,
  clientPresignId,
  nonceHandle,
  clientVerifyingShareB64u: 'client-verifying-share',
  clientCommitments: commitments,
  relayerCommitments: commitments,
  relayerVerifyingShareB64u: 'relayer-verifying-share',
  nearNetworkId: 'testnet',
  signerPublicKey: 'ed25519-public-key',
  participantIds: [1, 2],
  runtimePolicyScope,
  expiresAtMs: 120_000,
  routerAbPoolEntry,
};
void readyEntry;

const invalidLegacyReadyEntry: Ed25519ReadyClientPresignEntry = {
  state: 'ready',
  // @ts-expect-error legacy relayer presign-pool entries are no longer valid.
  source: 'threshold_ed25519_relayer_presign_v1',
  presignId,
  clientPresignId,
  nonceHandle,
  clientVerifyingShareB64u: 'client-verifying-share',
  clientCommitments: commitments,
  relayerCommitments: commitments,
  relayerVerifyingShareB64u: 'relayer-verifying-share',
  nearNetworkId: 'testnet',
  signerPublicKey: 'ed25519-public-key',
  participantIds: [1, 2],
  runtimePolicyScope,
  expiresAtMs: 120_000,
  routerAbPoolEntry,
};
void invalidLegacyReadyEntry;

// @ts-expect-error ready entries require the normalized runtime policy scope.
const invalidReadyWithoutRuntimeScope: Ed25519ClientPresignEntry = {
  state: 'ready',
  source: 'router_ab_ed25519_presign_pool_v2',
  presignId,
  clientPresignId,
  nonceHandle,
  clientVerifyingShareB64u: 'client-verifying-share',
  clientCommitments: commitments,
  relayerCommitments: commitments,
  relayerVerifyingShareB64u: 'relayer-verifying-share',
  nearNetworkId: 'testnet',
  signerPublicKey: 'ed25519-public-key',
  participantIds: [1, 2],
  expiresAtMs: 120_000,
  routerAbPoolEntry,
};
void invalidReadyWithoutRuntimeScope;

// @ts-expect-error ready entries require Router A/B pool metadata.
const invalidReadyWithoutRouterAbMetadata: Ed25519ReadyClientPresignEntry = {
  state: 'ready',
  source: 'router_ab_ed25519_presign_pool_v2',
  presignId,
  clientPresignId,
  nonceHandle,
  clientVerifyingShareB64u: 'client-verifying-share',
  clientCommitments: commitments,
  relayerCommitments: commitments,
  relayerVerifyingShareB64u: 'relayer-verifying-share',
  nearNetworkId: 'testnet',
  signerPublicKey: 'ed25519-public-key',
  participantIds: [1, 2],
  runtimePolicyScope,
  expiresAtMs: 120_000,
};
void invalidReadyWithoutRouterAbMetadata;

const burnedEntry: Ed25519ClientPresignEntry = {
  state: 'burned',
  presignId,
  clientPresignId,
  reason: 'send_attempted',
  burnedAtMs: 2,
};
void burnedEntry;

// @ts-expect-error burned entries cannot retain worker nonce handles.
const invalidBurnedWithNonceHandle: Ed25519ClientPresignEntry = {
  state: 'burned',
  presignId,
  clientPresignId,
  reason: 'used',
  burnedAtMs: 2,
  nonceHandle,
};
void invalidBurnedWithNonceHandle;

const readyPool: Ed25519ClientPresignPoolState = {
  state: 'ready',
  scopeKey,
  generation: 1,
  targetDepth: DEFAULT_ED25519_PRESIGN_POOL_POLICY.targetDepth,
  lowWatermark: DEFAULT_ED25519_PRESIGN_POOL_POLICY.lowWatermark,
  entries: [offeredEntry, readyEntry, burnedEntry],
  refill: { state: 'idle' },
};
void readyPool;

// @ts-expect-error disabled pools cannot retain presign entries.
const invalidDisabledWithEntries: Ed25519ClientPresignPoolState = {
  state: 'disabled',
  reason: 'no_threshold_session',
  entries: [readyEntry],
};
void invalidDisabledWithEntries;

const operationIdentity: Ed25519PresignOperationIdentity = {
  kind: 'router_ab_ed25519_presign_operation_identity_v1',
  operationId,
  operationFingerprint,
  purpose: 'near_transaction',
};
void operationIdentity;

// @ts-expect-error presign operation identity requires the existing branded fingerprint.
const invalidOperationWithoutFingerprint: Ed25519PresignOperationIdentity = {
  kind: 'router_ab_ed25519_presign_operation_identity_v1',
  operationId,
  purpose: 'near_transaction',
};
void invalidOperationWithoutFingerprint;

export {};
