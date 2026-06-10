import type {
  ThresholdEd25519FinalizeAndDispatchResponse,
  ThresholdEd25519FinalizeSignatureOnlyRequest,
  ThresholdEd25519PresignRefillRequest,
} from '../types';
import type { ThresholdEd25519NearAction } from '@shared/threshold/ed25519OperationFingerprint';

const validRefill: ThresholdEd25519PresignRefillRequest = {
  kind: 'threshold_ed25519_presign_refill_v1',
  relayerKeyId: 'relayer-key',
  nearAccountId: 'alice.testnet',
  nearNetworkId: 'testnet',
  expectedSignerPublicKey: 'ed25519-public-key',
  participantIds: [1, 2],
  clientPresigns: [
    {
      clientPresignId: 'client-presign-1',
      clientVerifyingShareB64u: 'client-verifying-share',
      clientCommitments: { hiding: 'hiding', binding: 'binding' },
    },
  ],
  requestTag: 'background_presign_pool_refill',
};

void validRefill;

const validFinalize: ThresholdEd25519FinalizeSignatureOnlyRequest = {
  kind: 'threshold_ed25519_finalize_signature_only_v1',
  operation: {
    kind: 'threshold_ed25519_signing_operation_v1',
    operationId: 'operation-1',
    operationFingerprint: 'fingerprint-1',
    purpose: 'nep413_message',
  },
  requestIntegrityHash: 'sha256:request-integrity',
  presignId: 'presign-1',
  relayerKeyId: 'relayer-key',
  nearAccountId: 'alice.testnet',
  nearNetworkId: 'testnet',
  expectedSignerPublicKey: 'ed25519-public-key',
  intent: {
    kind: 'nep413_message_v1',
    message: 'hello',
    recipient: 'recipient.testnet',
    nonce: 'nonce',
  },
  clientSignatureShareB64u: 'client-share',
};

void validFinalize;

// @ts-expect-error presign refill requires non-optional participant ids.
const invalidRefillMissingParticipantIds: ThresholdEd25519PresignRefillRequest = {
  kind: 'threshold_ed25519_presign_refill_v1',
  relayerKeyId: 'relayer-key',
  nearAccountId: 'alice.testnet',
  nearNetworkId: 'testnet',
  expectedSignerPublicKey: 'ed25519-public-key',
  clientPresigns: [],
  requestTag: 'background_presign_pool_refill',
};

void invalidRefillMissingParticipantIds;

const invalidFinalizeMissingFingerprint: ThresholdEd25519FinalizeSignatureOnlyRequest = {
  kind: 'threshold_ed25519_finalize_signature_only_v1',
  // @ts-expect-error operation fingerprints are required in the presign path.
  operation: {
    kind: 'threshold_ed25519_signing_operation_v1',
    operationId: 'operation-1',
    purpose: 'nep413_message',
  },
  requestIntegrityHash: 'sha256:request-integrity',
  presignId: 'presign-1',
  relayerKeyId: 'relayer-key',
  nearAccountId: 'alice.testnet',
  nearNetworkId: 'testnet',
  expectedSignerPublicKey: 'ed25519-public-key',
  intent: {
    kind: 'nep413_message_v1',
    message: 'hello',
    recipient: 'recipient.testnet',
    nonce: 'nonce',
  },
  clientSignatureShareB64u: 'client-share',
};

void invalidFinalizeMissingFingerprint;

const invalidWithoutOperationRejection: ThresholdEd25519FinalizeAndDispatchResponse = {
  ok: false,
  kind: 'threshold_ed25519_finalize_rejected_without_operation_v1',
  code: 'invalid_body',
  message: 'invalid',
  budgetState: 'not_consumed',
  // @ts-expect-error rejected responses without an operation cannot report a consumed presign.
  presignConsumed: true,
  dispatchState: 'not_attempted',
};

void invalidWithoutOperationRejection;

// @ts-expect-error successful signature-only results must include remaining budget projection.
const invalidSignatureSuccess: ThresholdEd25519FinalizeAndDispatchResponse = {
  ok: true,
  kind: 'threshold_ed25519_signature_only_result_v1',
  operationId: 'operation-1',
  budgetState: 'consumed',
  signatureB64u: 'signature',
  signerPublicKey: 'ed25519-public-key',
};

void invalidSignatureSuccess;

const validUseGlobalContractByAccount: ThresholdEd25519NearAction = {
  action_type: 'UseGlobalContract',
  account_id: 'global-contract-owner.testnet',
};

void validUseGlobalContractByAccount;

const validUseGlobalContractByHash: ThresholdEd25519NearAction = {
  action_type: 'UseGlobalContract',
  code_hash: '11111111111111111111111111111111',
};

void validUseGlobalContractByHash;

const invalidUseGlobalContractWithBothSelectors: ThresholdEd25519NearAction = {
  action_type: 'UseGlobalContract',
  account_id: 'global-contract-owner.testnet',
  // @ts-expect-error UseGlobalContract requires exactly one selector.
  code_hash: '11111111111111111111111111111111',
};

void invalidUseGlobalContractWithBothSelectors;

// @ts-expect-error UseGlobalContract requires exactly one selector.
const invalidUseGlobalContractWithoutSelector: ThresholdEd25519NearAction = {
  action_type: 'UseGlobalContract',
};

void invalidUseGlobalContractWithoutSelector;

const validSignedDelegateAction: ThresholdEd25519NearAction = {
  action_type: 'SignedDelegate',
  delegate_action: {
    senderId: 'alice.testnet',
    receiverId: 'receiver.testnet',
    actions: [{ action_type: 'Transfer', deposit: '1' }],
    nonce: '1',
    maxBlockHeight: '2',
    publicKey: { keyType: 0, keyData: new Array(32).fill(1) },
  },
  signature: { keyType: 0, signatureData: new Array(64).fill(2) },
};

void validSignedDelegateAction;

const invalidSignedDelegateActionMissingSignature: ThresholdEd25519NearAction = {
  action_type: 'SignedDelegate',
  delegate_action: {
    senderId: 'alice.testnet',
    receiverId: 'receiver.testnet',
    actions: [{ action_type: 'Transfer', deposit: '1' }],
    nonce: '1',
    maxBlockHeight: '2',
    publicKey: { keyType: 0, keyData: new Array(32).fill(1) },
  },
  // @ts-expect-error SignedDelegate requires a typed signature.
  signature: undefined,
};

void invalidSignedDelegateActionMissingSignature;
