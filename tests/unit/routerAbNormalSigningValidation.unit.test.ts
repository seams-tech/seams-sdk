import { expect, test } from '@playwright/test';
import type {
  RouterAbEd25519PresignPoolAcceptedEntryV2Wire,
  RouterAbEd25519PresignPoolPrepareResponseV2Wire,
  RouterAbNormalSigningPrepareRequestV2Wire,
  RouterAbNormalSigningPrepareResponseV1Wire,
  RouterAbNormalSigningResponseV1Wire,
  RouterAbPublicDigest32Wire,
} from '@/core/rpcClients/relayer/routerAbNormalSigning';
import {
  buildRouterAbEd25519PresignPoolPrepareRequestV2,
  prepareRouterAbNormalSigningPresignPoolV2,
} from '@/core/rpcClients/relayer/routerAbNormalSigning';
import {
  isSigningSessionBudgetAdmissionBlockedError,
  SIGNING_SESSION_BUDGET_EXHAUSTED_ERROR,
  SIGNING_SESSION_BUDGET_IN_FLIGHT_ERROR,
} from '@/core/signingEngine/session/budget/budget';
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
    budget_reservation_id: 'ed25519-sign-budget-reservation-1',
    budget_operation_id: 'operation-1',
    budget_status: {
      committed_remaining_uses: 3,
      reserved_uses: 1,
      available_uses: 2,
    },
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

const presignPoolRequest = buildRouterAbEd25519PresignPoolPrepareRequestV2({
  scope: request.scope,
  expiresAtMs: 1_900_000_000_000,
  generation: 7,
  clientOffers: [
    {
      clientPresignId: 'client-presign-1',
      clientNonceHandle: 'client-nonce-1',
      clientCommitments: {
        hiding: 'client-hiding-1',
        binding: 'client-binding-1',
      },
      clientVerifyingShareB64u: 'client-verifying-share-1',
    },
    {
      clientPresignId: 'client-presign-2',
      clientNonceHandle: 'client-nonce-2',
      clientCommitments: {
        hiding: 'client-hiding-2',
        binding: 'client-binding-2',
      },
      clientVerifyingShareB64u: 'client-verifying-share-2',
    },
  ],
});

function presignPoolAcceptedEntry(args: {
  clientPresignId?: string;
  generation?: number;
} = {}): RouterAbEd25519PresignPoolAcceptedEntryV2Wire {
  const clientPresignId = args.clientPresignId || 'client-presign-1';
  return {
    client_presign_id: clientPresignId,
    generation: args.generation ?? presignPoolRequest.generation,
    pool_entry_binding_digest: digest32,
    signing_worker: {
      server_id: request.scope.signing_worker_id,
      key_epoch: 'epoch-1',
      recipient_encryption_key: 'recipient-key',
    },
    server_round1_handle: `server-round-1/${clientPresignId}`,
    server_commitments: {
      hiding: `server-hiding/${clientPresignId}`,
      binding: `server-binding/${clientPresignId}`,
    },
    server_verifying_share_b64u: 'server-verifying-share',
    signature_scheme: 'ed25519_v1',
    prepared_at_ms: 1_800_000_000_000,
    expires_at_ms: presignPoolRequest.expires_at_ms,
  };
}

function presignPoolResponse(
  overrides: Partial<RouterAbEd25519PresignPoolPrepareResponseV2Wire> = {},
): RouterAbEd25519PresignPoolPrepareResponseV2Wire {
  return {
    scope: presignPoolRequest.scope,
    generation: presignPoolRequest.generation,
    accepted: [presignPoolAcceptedEntry()],
    rejected_client_presign_ids: ['client-presign-2'],
    ...overrides,
  };
}

async function preparePresignPoolWithResponse(
  response: RouterAbEd25519PresignPoolPrepareResponseV2Wire,
): Promise<{
  calls: Array<{ url: string; init: RequestInit }>;
  parsed: RouterAbEd25519PresignPoolPrepareResponseV2Wire;
}> {
  const calls: Array<{ url: string; init: RequestInit }> = [];
  const originalFetch = globalThis.fetch;
  globalThis.fetch = (async (url: RequestInfo | URL, init?: RequestInit) => {
    calls.push({ url: String(url), init: init || {} });
    return new Response(JSON.stringify(response), {
      status: 200,
      headers: { 'content-type': 'application/json' },
    });
  }) as typeof fetch;
  try {
    const parsed = await prepareRouterAbNormalSigningPresignPoolV2({
      relayServerUrl: 'https://router.example/base/',
      credential: { kind: 'jwt', walletSessionJwt: 'wallet-session-jwt' },
      request: presignPoolRequest,
    });
    return { calls, parsed };
  } finally {
    globalThis.fetch = originalFetch;
  }
}

async function preparePresignPoolWithHttpError(args: {
  status: number;
  body: unknown;
}): Promise<unknown> {
  const originalFetch = globalThis.fetch;
  globalThis.fetch = (async () =>
    new Response(JSON.stringify(args.body), {
      status: args.status,
      headers: { 'content-type': 'application/json' },
    })) as typeof fetch;
  try {
    await prepareRouterAbNormalSigningPresignPoolV2({
      relayServerUrl: 'https://router.example/base/',
      credential: { kind: 'jwt', walletSessionJwt: 'wallet-session-jwt' },
      request: presignPoolRequest,
    });
    return null;
  } catch (error) {
    return error;
  } finally {
    globalThis.fetch = originalFetch;
  }
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

  test('binds presign-pool prepare responses to the original request', async () => {
    const response = presignPoolResponse();
    const { calls, parsed } = await preparePresignPoolWithResponse(response);

    expect(parsed).toEqual(response);
    expect(calls.map((call) => call.url)).toEqual([
      'https://router.example/base/v2/router-ab/ed25519/sign/presign-pool/prepare',
    ]);
    expect(calls[0].init.credentials).toBe('omit');
    expect(calls[0].init.headers).toEqual({
      'Content-Type': 'application/json',
      Authorization: 'Bearer wallet-session-jwt',
    });
    expect(JSON.parse(String(calls[0].init.body))).toEqual(presignPoolRequest);
  });

  test('maps server budget failures to signing-session budget domain errors', async () => {
    const exhausted = await preparePresignPoolWithHttpError({
      status: 409,
      body: {
        ok: false,
        code: 'wallet_budget_exhausted',
        message: 'Wallet Session signature budget is exhausted',
      },
    });
    const inFlight = await preparePresignPoolWithHttpError({
      status: 409,
      body: {
        ok: false,
        code: 'wallet_budget_in_flight',
        message: 'Wallet Session signature budget is reserved by another request',
      },
    });

    expect(exhausted).toBeInstanceOf(Error);
    expect(inFlight).toBeInstanceOf(Error);
    expect(String((exhausted as Error).message)).toContain(SIGNING_SESSION_BUDGET_EXHAUSTED_ERROR);
    expect(String((inFlight as Error).message)).toContain(SIGNING_SESSION_BUDGET_IN_FLIGHT_ERROR);
    expect(isSigningSessionBudgetAdmissionBlockedError(exhausted)).toBe(true);
    expect(isSigningSessionBudgetAdmissionBlockedError(inFlight)).toBe(true);
  });

  test('rejects presign-pool responses for another scope or generation', async () => {
    await expect(
      preparePresignPoolWithResponse(
        presignPoolResponse({
          scope: {
            ...presignPoolRequest.scope,
            request_id: 'router-ab-normal-signing/request-2',
          },
        }),
      ),
    ).rejects.toThrow('Router A/B presign-pool response scope does not match request');

    await expect(
      preparePresignPoolWithResponse(
        presignPoolResponse({
          generation: presignPoolRequest.generation + 1,
        }),
      ),
    ).rejects.toThrow('Router A/B presign-pool response generation does not match request');

    await expect(
      preparePresignPoolWithResponse(
        presignPoolResponse({
          accepted: [presignPoolAcceptedEntry({ generation: presignPoolRequest.generation + 1 })],
        }),
      ),
    ).rejects.toThrow('accepted[0].generation does not match request');
  });

  test('rejects presign-pool responses for unknown or overlapping client offers', async () => {
    await expect(
      preparePresignPoolWithResponse(
        presignPoolResponse({
          accepted: [presignPoolAcceptedEntry({ clientPresignId: 'client-presign-unknown' })],
          rejected_client_presign_ids: ['client-presign-2'],
        }),
      ),
    ).rejects.toThrow('accepted[0].client_presign_id is not in request.client_offers');

    await expect(
      preparePresignPoolWithResponse(
        presignPoolResponse({
          rejected_client_presign_ids: ['client-presign-1'],
        }),
      ),
    ).rejects.toThrow('rejected_client_presign_ids[0] was already accepted');
  });

  test('rejects presign-pool responses with duplicate accepted or rejected IDs', async () => {
    await expect(
      preparePresignPoolWithResponse(
        presignPoolResponse({
          accepted: [
            presignPoolAcceptedEntry({ clientPresignId: 'client-presign-1' }),
            presignPoolAcceptedEntry({ clientPresignId: 'client-presign-1' }),
          ],
          rejected_client_presign_ids: ['client-presign-2'],
        }),
      ),
    ).rejects.toThrow('accepted[1].client_presign_id is duplicated');

    await expect(
      preparePresignPoolWithResponse(
        presignPoolResponse({
          accepted: [],
          rejected_client_presign_ids: ['client-presign-1', 'client-presign-1'],
        }),
      ),
    ).rejects.toThrow('rejected_client_presign_ids[1] is duplicated');
  });
});
