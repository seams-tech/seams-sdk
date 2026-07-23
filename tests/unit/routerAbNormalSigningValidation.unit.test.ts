import { expect, test } from '@playwright/test';
import type {
  RouterAbNormalSigningPrepareRequestV2Wire,
  RouterAbNormalSigningPrepareResponseV1Wire,
  RouterAbNormalSigningResponseV1Wire,
  RouterAbPublicDigest32Wire,
} from '@/core/rpcClients/relayer/routerAbNormalSigning';
import { prepareRouterAbNormalSigningV2 } from '@/core/rpcClients/relayer/routerAbNormalSigning';
import {
  isSigningSessionBudgetAdmissionBlockedError,
  SIGNING_SESSION_BUDGET_EXHAUSTED_ERROR,
  SIGNING_SESSION_BUDGET_IN_FLIGHT_ERROR,
} from '@/core/signingEngine/session/budget/budget';
import {
  classifySigningGrantAdmissionFailure,
  SigningGrantAdmissionError,
} from '@/core/signingEngine/session/budget/admission';
import {
  requireRouterAbNormalSigningPrepareMatchesRequest,
  requireRouterAbNormalSigningResponseMatchesRequest,
} from '@/core/rpcClients/relayer/routerAbNormalSigningValidation';

type HttpErrorFixture = {
  status: number;
  body: unknown;
};

let httpErrorFixture: HttpErrorFixture | null = null;

function byteRange(length: number): number[] {
  const bytes: number[] = [];
  for (let index = 0; index < length; index += 1) bytes.push(index);
  return bytes;
}

async function fixtureErrorFetch(): Promise<Response> {
  if (!httpErrorFixture) throw new Error('HTTP error fixture is missing');
  return new Response(JSON.stringify(httpErrorFixture.body), {
    status: httpErrorFixture.status,
    headers: { 'content-type': 'application/json' },
  });
}

const digest32: RouterAbPublicDigest32Wire = {
  bytes: byteRange(32),
};

const request: RouterAbNormalSigningPrepareRequestV2Wire = {
  scope: {
    request_id: 'router-ab-normal-signing/request-1',
    account_id: 'alice.testnet',
    session_id: 'wallet-session-1',
    active_state_session_id: 'activation-session-1',
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
    signature: { bytes: byteRange(64) },
    signed_at_ms: 1_800_000_000_000,
  };
}

async function prepareWithHttpError(fixture: HttpErrorFixture): Promise<unknown> {
  const originalFetch = globalThis.fetch;
  httpErrorFixture = fixture;
  globalThis.fetch = fixtureErrorFetch;
  try {
    await prepareRouterAbNormalSigningV2({
      relayServerUrl: 'https://router.example/base/',
      credential: { kind: 'jwt', walletSessionJwt: 'wallet-session-jwt' },
      request,
    });
    return null;
  } catch (error) {
    return error;
  } finally {
    httpErrorFixture = null;
    globalThis.fetch = originalFetch;
  }
}

function acceptScopedPrepareResponse(): void {
  requireRouterAbNormalSigningPrepareMatchesRequest({
    request,
    signingPayloadDigest: digest32,
    response: prepareResponse('signing-worker-a'),
  });
}

function acceptScopedSigningResponse(): void {
  requireRouterAbNormalSigningResponseMatchesRequest({
    request,
    signingPayloadDigest: digest32,
    response: signingResponse('signing-worker-a'),
  });
}

function rejectMismatchedPrepareResponse(): void {
  requireRouterAbNormalSigningPrepareMatchesRequest({
    request,
    signingPayloadDigest: digest32,
    response: prepareResponse('signing-worker-b'),
  });
}

function rejectMismatchedSigningResponse(): void {
  requireRouterAbNormalSigningResponseMatchesRequest({
    request,
    signingPayloadDigest: digest32,
    response: signingResponse('signing-worker-b'),
  });
}

function acceptsScopedSigningWorker(): void {
  expect(acceptScopedPrepareResponse).not.toThrow();
  expect(acceptScopedSigningResponse).not.toThrow();
}

function rejectsMismatchedSigningWorker(): void {
  expect(rejectMismatchedPrepareResponse).toThrow(
    'Router A/B normal-signing prepare response SigningWorker mismatch',
  );
  expect(rejectMismatchedSigningResponse).toThrow(
    'Router A/B normal-signing response SigningWorker mismatch',
  );
}

async function mapsBudgetFailures(): Promise<void> {
  const exhausted = await prepareWithHttpError({
    status: 409,
    body: {
      ok: false,
      code: 'wallet_budget_exhausted',
      message: 'Wallet Session signature budget is exhausted',
    },
  });
  const inFlight = await prepareWithHttpError({
    status: 409,
    body: {
      ok: false,
      code: 'wallet_budget_in_flight',
      message: 'Wallet Session signature budget is reserved by another request',
    },
  });

  expect(exhausted).toBeInstanceOf(SigningGrantAdmissionError);
  expect(inFlight).toBeInstanceOf(SigningGrantAdmissionError);
  expect(String((exhausted as Error).message)).toContain(SIGNING_SESSION_BUDGET_EXHAUSTED_ERROR);
  expect(String((inFlight as Error).message)).toContain(SIGNING_SESSION_BUDGET_IN_FLIGHT_ERROR);
  expect(classifySigningGrantAdmissionFailure(exhausted)?.kind).toBe('exhausted');
  expect(classifySigningGrantAdmissionFailure(inFlight)?.kind).toBe('in_flight');
  expect(isSigningSessionBudgetAdmissionBlockedError(exhausted)).toBe(true);
  expect(isSigningSessionBudgetAdmissionBlockedError(inFlight)).toBe(true);
}

test(
  'accepts prepare and finalize responses from the scoped SigningWorker',
  acceptsScopedSigningWorker,
);
test(
  'rejects mismatched SigningWorker ids in prepare and finalize responses',
  rejectsMismatchedSigningWorker,
);
test('maps server budget failures to signing-session budget domain errors', mapsBudgetFailures);
