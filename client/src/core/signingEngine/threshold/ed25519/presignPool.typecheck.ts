import type {
  PrepareThresholdEd25519PresignPoolPayload,
  ThresholdEd25519PresignCommitmentsWire,
} from '@/core/types/signer-worker';
import type { RuntimePolicyScope } from '@shared/threshold/signingRootScope';
import type { NearSignerWorkerPresignPoolOperationMap } from '../../workerManager/workerTypes';
import type {
  Ed25519ClientPresignEntry,
  Ed25519ClientPresignId,
  Ed25519ClientPresignNonceHandle,
  Ed25519ClientPresignPoolState,
  Ed25519PresignOperationIdentity,
  Ed25519PresignSigningPathSelection,
  Ed25519PresignScopeKey,
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

const readyEntry: Ed25519ClientPresignEntry = {
  state: 'ready',
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
void readyEntry;

// @ts-expect-error ready entries require the normalized runtime policy scope.
const invalidReadyWithoutRuntimeScope: Ed25519ClientPresignEntry = {
  state: 'ready',
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
};
void invalidReadyWithoutRuntimeScope;

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
  targetDepth: 2,
  lowWatermark: 1,
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
  kind: 'threshold_ed25519_presign_operation_identity_v1',
  operationId,
  operationFingerprint,
  purpose: 'near_transaction',
};
void operationIdentity;

const oneRttSelection: Ed25519PresignSigningPathSelection = {
  kind: 'pool_hit_one_rtt',
  operation: operationIdentity,
  reservation: {
    state: 'reserved_for_finalize',
    entry: readyEntry,
    operation: operationIdentity,
    reservedAtMs: 3,
  },
};
void oneRttSelection;

const invalidOneRttSelectionWithRefill: Ed25519PresignSigningPathSelection = {
  kind: 'pool_hit_one_rtt',
  operation: operationIdentity,
  reservation: {
    state: 'reserved_for_finalize',
    entry: readyEntry,
    operation: operationIdentity,
    reservedAtMs: 3,
  },
  refill: {
    scheduled: true,
    // @ts-expect-error one-RTT selections cannot include fallback refill state.
    reason: 'scheduled',
    depth: 0,
    targetDepth: 2,
    generation: 1,
  },
};
void invalidOneRttSelectionWithRefill;

const twoRttSelection: Ed25519PresignSigningPathSelection = {
  kind: 'pool_miss_two_rtt',
  operation: operationIdentity,
  miss: {
    ok: false,
    code: 'pool_empty',
    message: 'threshold-ed25519 pool is empty',
  },
  refill: {
    scheduled: true,
    reason: 'scheduled',
    depth: 0,
    targetDepth: 2,
    generation: 1,
  },
};
void twoRttSelection;

const invalidTwoRttSelectionWithReservation: Ed25519PresignSigningPathSelection = {
  kind: 'pool_miss_two_rtt',
  operation: operationIdentity,
  miss: {
    ok: false,
    code: 'pool_empty',
    message: 'threshold-ed25519 pool is empty',
  },
  refill: {
    scheduled: true,
    reason: 'scheduled',
    depth: 0,
    targetDepth: 2,
    generation: 1,
  },
  reservation: {
    // @ts-expect-error two-RTT fallback selections cannot reserve a presign.
    state: 'reserved_for_finalize',
    entry: readyEntry,
    operation: operationIdentity,
    reservedAtMs: 3,
  },
};
void invalidTwoRttSelectionWithReservation;

// @ts-expect-error presign operation identity requires the existing branded fingerprint.
const invalidOperationWithoutFingerprint: Ed25519PresignOperationIdentity = {
  kind: 'threshold_ed25519_presign_operation_identity_v1',
  operationId,
  purpose: 'near_transaction',
};
void invalidOperationWithoutFingerprint;

const preparePayload: PrepareThresholdEd25519PresignPoolPayload = {
  kind: 'prepare_threshold_ed25519_presign_pool_v1',
  sessionKind: 'jwt',
  thresholdSessionAuthToken: 'threshold-session-token',
  relayUrl: 'https://relay.example',
  thresholdSessionId: 'threshold-session-id',
  walletSigningSessionId: 'wallet-signing-session-id',
  relayerKeyId: 'relayer-key',
  nearAccountId: 'alice.testnet',
  nearNetworkId: 'testnet',
  signerPublicKey: 'ed25519-public-key',
  participantIds: [1, 2],
  runtimePolicyScope,
  policy: DEFAULT_ED25519_PRESIGN_POOL_POLICY,
  requestTag: 'background_presign_pool_refill',
  generation: 1,
  clientPresigns: [
    {
      clientPresignId: 'client-presign-1',
      nonceHandle: 'nonce-handle-1',
      clientVerifyingShareB64u: 'client-verifying-share',
      clientCommitments: commitments,
    },
  ],
};
void preparePayload;

// @ts-expect-error cookie presign refill auth cannot carry a bearer token.
const invalidCookiePayloadWithBearer: PrepareThresholdEd25519PresignPoolPayload = {
  kind: 'prepare_threshold_ed25519_presign_pool_v1',
  sessionKind: 'cookie',
  useThresholdSessionCookie: true,
  thresholdSessionAuthToken: 'threshold-session-token',
  relayUrl: 'https://relay.example',
  thresholdSessionId: 'threshold-session-id',
  walletSigningSessionId: 'wallet-signing-session-id',
  relayerKeyId: 'relayer-key',
  nearAccountId: 'alice.testnet',
  nearNetworkId: 'testnet',
  signerPublicKey: 'ed25519-public-key',
  participantIds: [1, 2],
  runtimePolicyScope,
  policy: DEFAULT_ED25519_PRESIGN_POOL_POLICY,
  requestTag: 'background_presign_pool_refill',
  generation: 1,
  clientPresigns: [],
};
void invalidCookiePayloadWithBearer;

const invalidPayloadWithRawNonce: PrepareThresholdEd25519PresignPoolPayload = {
  ...preparePayload,
  clientPresigns: [
    {
      clientPresignId: 'client-presign-2',
      nonceHandle: 'nonce-handle-2',
      clientVerifyingShareB64u: 'client-verifying-share',
      clientCommitments: commitments,
      // @ts-expect-error worker presign offers cannot expose nonce secret material.
      nonceSecretB64u: 'raw-secret',
    },
  ],
};
void invalidPayloadWithRawNonce;

const prepareOperation = {
  payload: preparePayload,
  result: {
    ok: true,
    kind: 'prepare_threshold_ed25519_presign_pool_result_v1',
    generation: 1,
    accepted: [
      {
        presignId: 'presign-1',
        clientPresignId: 'client-presign-1',
        relayerCommitments: commitments,
        relayerVerifyingShareB64u: 'relayer-verifying-share',
        expiresAtMs: 120_000,
      },
    ],
    rejectedClientPresignIds: [],
    expiresAtMs: 120_000,
  },
} satisfies NearSignerWorkerPresignPoolOperationMap['prepareThresholdEd25519PresignPool'];
void prepareOperation;

const invalidPrepareFailureWithAccepted = {
  payload: preparePayload,
  // @ts-expect-error failed prepare results cannot carry accepted presign pairs.
  result: {
    ok: false,
    kind: 'prepare_threshold_ed25519_presign_pool_result_v1',
    code: 'worker_error',
    message: 'failed',
    generation: 1,
    accepted: [],
  },
} satisfies NearSignerWorkerPresignPoolOperationMap['prepareThresholdEd25519PresignPool'];
void invalidPrepareFailureWithAccepted;

export {};
