import { expect, test } from '@playwright/test';
import type {
  RouterAbNormalSigningPrepareRequestV2Wire,
  RouterAbNormalSigningPrepareResponseV1Wire,
  RouterAbNormalSigningResponseV1Wire,
  RouterAbPublicDigest32Wire,
} from '@/core/rpcClients/relayer/routerAbNormalSigning';
import {
  buildRouterAbEd25519NormalSigningFinalizeRequestV2,
  prepareRouterAbNormalSigningV2,
} from '@/core/rpcClients/relayer/routerAbNormalSigning';
import {
  isWalletSessionQuotaAdmissionError,
  WALLET_SESSION_QUOTA_EXHAUSTED_ERROR,
  WALLET_SESSION_QUOTA_IN_FLIGHT_ERROR,
} from '@/core/signingEngine/session/operationState/authorizationAdmission';
import {
  classifyWalletSessionQuotaAdmissionFailure,
  WalletSessionQuotaAdmissionError,
} from '@/core/signingEngine/session/operationState/authorizationAdmission';
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
    authorization: {
      kind: 'reusable_wallet_session',
      wallet_session_id: 'wallet-session-1',
    },
    material_activation: {
      kind: 'mpc_material_activation_ref',
      activation_id: 'activation-session-1',
      capability: 'capability-1',
      material_owner: 'alice.testnet',
      key_binding: 'key-binding-1',
      lifecycle_binding: 'lifecycle-1',
      signing_worker: 'signing-worker-a',
    },
    signing_worker_id: 'signing-worker-a',
  },
  expires_at_ms: 1_900_000_000_000,
  display_digest: digest32,
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
    authorized_operation: {
      kind: 'reusable_wallet_session_authorized_operation_v1',
      authorized_operation_id: 'authorized-operation-1',
      operation_id: 'operation-1',
      capability_kind: 'near_ed25519_mpc_signing',
      operation_kind: 'near.sign_transaction',
      lane_digest_b64u: 'BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc',
      intent_digest_b64u: 'BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc',
      display_digest_b64u: 'BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc',
      operation_fingerprint_digest: 'BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc',
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
      credential: {
        kind: 'wallet_session_opaque',
        walletSessionToken: 'wallet-session-token',
      },
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

async function prepareWithHttpResponse(body: unknown): Promise<unknown> {
  return prepareRequestWithHttpResponse(request, body);
}

async function prepareRequestWithHttpResponse(
  requestInput: RouterAbNormalSigningPrepareRequestV2Wire,
  body: unknown,
): Promise<unknown> {
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async () =>
    new Response(JSON.stringify(body), {
      status: 200,
      headers: { 'content-type': 'application/json' },
    });
  try {
    return await prepareRouterAbNormalSigningV2({
      relayServerUrl: 'https://router.example/base/',
      credential: {
        kind: 'wallet_session_opaque',
        walletSessionToken: 'wallet-session-token',
      },
      request: requestInput,
    });
  } finally {
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

  expect(exhausted).toBeInstanceOf(WalletSessionQuotaAdmissionError);
  expect(inFlight).toBeInstanceOf(WalletSessionQuotaAdmissionError);
  expect(String((exhausted as Error).message)).toContain(WALLET_SESSION_QUOTA_EXHAUSTED_ERROR);
  expect(String((inFlight as Error).message)).toContain(WALLET_SESSION_QUOTA_IN_FLIGHT_ERROR);
  expect(classifyWalletSessionQuotaAdmissionFailure(exhausted)?.kind).toBe('exhausted');
  expect(classifyWalletSessionQuotaAdmissionFailure(inFlight)?.kind).toBe('in_flight');
  expect(isWalletSessionQuotaAdmissionError(exhausted)).toBe(true);
  expect(isWalletSessionQuotaAdmissionError(inFlight)).toBe(true);
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

test('parses the reusable Wallet Session authorized-operation receipt', async () => {
  const response = prepareResponse('signing-worker-a');
  await expect(prepareWithHttpResponse(response)).resolves.toEqual(response);

  const { operation_fingerprint_digest: _operationFingerprintDigest, ...truncatedClaim } =
    response.authorized_operation;
  await expect(
    prepareWithHttpResponse({ ...response, authorized_operation: truncatedClaim }),
  ).rejects.toThrow('authorized_operation has invalid fields');
});

test('parses and echoes the verified step-up authorized operation receipt', async () => {
  const stepUpRequest: RouterAbNormalSigningPrepareRequestV2Wire = {
    ...request,
    scope: {
      ...request.scope,
      authorization: { kind: 'operation_step_up' },
    },
  };
  const stepUpClaim = {
    kind: 'verified_step_up_authorized_operation_v1' as const,
    authorization_session_id: 'authorization-session-1',
    evidence_set_digest: 'BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc',
    authorized_operation_id: 'authorized-operation-2',
    operation_id: 'operation-1',
    capability_kind: 'near_ed25519_mpc_signing' as const,
    operation_kind: 'near.sign_transaction' as const,
    lane_digest_b64u: 'BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc',
    intent_digest_b64u: 'BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc',
    display_digest_b64u: 'BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc',
    operation_fingerprint_digest: 'BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc',
  };
  const response: RouterAbNormalSigningPrepareResponseV1Wire = {
    ...prepareResponse('signing-worker-a'),
    scope: stepUpRequest.scope,
    authorized_operation: stepUpClaim,
  };
  await expect(prepareRequestWithHttpResponse(stepUpRequest, response)).resolves.toEqual(response);

  const finalize = buildRouterAbEd25519NormalSigningFinalizeRequestV2({
    scope: stepUpRequest.scope,
    expiresAtMs: stepUpRequest.expires_at_ms,
    prepareResponse: response,
    admissionMaterial: {
      intentDigest: digest32,
      signingPayloadDigest: digest32,
      admittedSigningDigest: digest32,
    },
    clientCommitments: { hiding: 'client-hiding', binding: 'client-binding' },
    clientVerifyingShareB64u: 'client-verifying-share',
    clientSignatureShareB64u: 'client-signature-share',
  });
  expect(finalize.authorized_operation).toEqual(stepUpClaim);

  const { authorized_operation_id: _authorizedOperationId, ...truncatedClaim } = stepUpClaim;
  await expect(
    prepareRequestWithHttpResponse(stepUpRequest, {
      ...response,
      authorized_operation: truncatedClaim,
    }),
  ).rejects.toThrow('authorized_operation has invalid fields');
});
