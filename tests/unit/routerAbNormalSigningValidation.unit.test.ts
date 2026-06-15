import { expect, test } from '@playwright/test';
import type {
  RouterAbNormalSigningPrepareRequestV2Wire,
  RouterAbNormalSigningPrepareResponseV1Wire,
  RouterAbNormalSigningResponseV1Wire,
  RouterAbPublicDigest32Wire,
} from '@/core/rpcClients/relayer/routerAbNormalSigning';
import {
  requireRouterAbNormalSigningPrepareMatchesRequest,
  requireRouterAbNormalSigningResponseMatchesRequest,
} from '@/core/rpcClients/relayer/routerAbNormalSigningValidation';

const digest32: RouterAbPublicDigest32Wire = {
  bytes: Array.from({ length: 32 }, (_, index) => index),
};

const request: RouterAbNormalSigningPrepareRequestV2Wire = {
  scope: {
    request_id: 'router-ab-normal-signing/request-1',
    account_id: 'alice.testnet',
    session_id: 'wallet-session-1',
    signing_worker_id: 'signing-worker-a',
  },
  expires_at_ms: 1_900_000_000_000,
  intent: {
    kind: 'near_transaction_v1',
    operation_id: 'operation-1',
    operation_fingerprint: 'fingerprint-1',
    near_account_id: 'alice.testnet',
    near_network_id: 'testnet',
    transactions: [
      {
        receiver_id: 'contract.testnet',
        action_fingerprint: 'action-fingerprint-1',
      },
    ],
    unsigned_transaction_borsh_b64u: 'unsigned-transaction-borsh',
  },
  signing_payload: {
    kind: 'near_unsigned_transaction_borsh_v1',
    unsigned_transaction_borsh_b64u: 'unsigned-transaction-borsh',
    expected_signing_digest_b64u: 'signing-digest',
  },
};

function prepareResponse(signingWorkerId: string): RouterAbNormalSigningPrepareResponseV1Wire {
  return {
    scope: request.scope,
    signing_payload_digest: digest32,
    round1_binding_digest: digest32,
    signing_worker: {
      server_id: signingWorkerId,
      key_epoch: 'epoch-1',
      recipient_encryption_key: 'recipient-key',
    },
    server_round1_handle: 'round-1-handle',
    server_commitments: {
      hiding: 'server-hiding',
      binding: 'server-binding',
    },
    server_verifying_share_b64u: 'server-verifying-share',
    signature_scheme: 'ed25519_v1',
    prepared_at_ms: 1_800_000_000_000,
    expires_at_ms: request.expires_at_ms,
  };
}

function signingResponse(signingWorkerId: string): RouterAbNormalSigningResponseV1Wire {
  return {
    scope: request.scope,
    signing_payload_digest: digest32,
    signing_worker: {
      server_id: signingWorkerId,
      key_epoch: 'epoch-1',
      recipient_encryption_key: 'recipient-key',
    },
    signature_scheme: 'ed25519_v1',
    signature: {
      bytes: Array.from({ length: 64 }, (_, index) => index),
    },
    signed_at_ms: 1_800_000_000_000,
  };
}

test.describe('Router A/B normal-signing response validation', () => {
  test('accepts prepare and finalize responses from the scoped SigningWorker', () => {
    expect(() =>
      requireRouterAbNormalSigningPrepareMatchesRequest({
        request,
        signingPayloadDigest: digest32,
        response: prepareResponse('signing-worker-a'),
      }),
    ).not.toThrow();
    expect(() =>
      requireRouterAbNormalSigningResponseMatchesRequest({
        request,
        signingPayloadDigest: digest32,
        response: signingResponse('signing-worker-a'),
      }),
    ).not.toThrow();
  });

  test('rejects mismatched SigningWorker ids in prepare and finalize responses', () => {
    expect(() =>
      requireRouterAbNormalSigningPrepareMatchesRequest({
        request,
        signingPayloadDigest: digest32,
        response: prepareResponse('signing-worker-b'),
      }),
    ).toThrow('Router A/B normal-signing prepare response SigningWorker mismatch');

    expect(() =>
      requireRouterAbNormalSigningResponseMatchesRequest({
        request,
        signingPayloadDigest: digest32,
        response: signingResponse('signing-worker-b'),
      }),
    ).toThrow('Router A/B normal-signing response SigningWorker mismatch');
  });
});
