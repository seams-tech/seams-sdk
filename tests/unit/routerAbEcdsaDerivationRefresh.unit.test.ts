import { expect, test } from '@playwright/test';
import {
  parseRouterAbEcdsaDerivationActivationRefreshCommitRequestV1,
  parseRouterAbEcdsaDerivationActivationRefreshRequestV1,
  parseRouterAbEcdsaDerivationActivationRefreshResponseV1,
  type RouterAbEcdsaDerivationActivationRefreshCommitRequestV1,
  type RouterAbEcdsaDerivationActivationRefreshRequestV1,
} from '@shared/utils/routerAbEcdsaDerivation';
import { parseCorrelationId } from '@shared/utils/canonicalPrimitives';
import { parseEcdsaServerGeneration } from '@shared/utils/ecdsaCapabilityActivation';
import {
  createRouterAbEcdsaStrictPostRegistrationPort,
  type RouterAbEcdsaCeremonyTokenIssuer,
} from '../../packages/sdk-server-ts/src/router/routerAbEcdsaStrictRegistration';
import {
  HttpRouterAbEcdsaDerivationRefreshPort,
  handleRouterAbEcdsaDerivationRefreshRoute,
  type RouterAbEcdsaDerivationRefreshPort,
  type RouterAbEcdsaDerivationRefreshPortInput,
} from '../../packages/sdk-server-ts/src/router/routerAbEcdsaDerivationRefreshPort';

let capturedFetchUrl = '';
let capturedFetchInit: RequestInit | undefined;

async function captureRefreshFetch(
  input: RequestInfo | URL,
  init?: RequestInit,
): Promise<Response> {
  capturedFetchUrl = String(input);
  capturedFetchInit = init;
  return Response.json({ ok: true, receipt: 'opaque' }, { status: 201 });
}

function b64u(byte: number, length: number): string {
  return Buffer.from(new Uint8Array(length).fill(byte)).toString('base64url');
}

function digest(byte: number): { bytes: number[] } {
  return { bytes: Array.from(new Uint8Array(32).fill(byte)) };
}

function refreshRequest(): RouterAbEcdsaDerivationActivationRefreshRequestV1 {
  return {
    context: { application_binding_digest_b64u: b64u(1, 32) },
    lifecycle: {
      lifecycle_id: 'lifecycle-refresh-1',
      work_kind: 'server_share_refresh',
      primitive_request_kind: 'refresh',
      root_share_epoch: 'activation-2',
      account_id: 'wallet-1',
      session_id: 'session-1',
      signer_set_id: 'signer-set-1',
      selected_server_id: 'signing-worker-1',
    },
    public_identity: {
      context_binding_b64u: b64u(2, 32),
      derivation_client_share_public_key33_b64u: b64u(3, 33),
      server_public_key33_b64u: b64u(2, 33),
      threshold_public_key33_b64u: b64u(3, 33),
      ethereum_address20_b64u: b64u(6, 20),
      client_share_retry_counter: 0,
      server_share_retry_counter: 1,
    },
    signer_set: {
      signer_set_id: 'signer-set-1',
      policy: 'all_2',
      signer_a: { role: 'signer_a', signer_id: 'deriver-a', key_epoch: 'a-epoch-1' },
      signer_b: { role: 'signer_b', signer_id: 'deriver-b', key_epoch: 'b-epoch-1' },
      selected_server: {
        server_id: 'signing-worker-1',
        key_epoch: 'worker-epoch-1',
        recipient_encryption_key: `x25519:${'ab'.repeat(32)}`,
      },
    },
    router_id: 'router-1',
    client_id: 'client-1',
    signing_worker_ephemeral_public_key: `x25519:${'cd'.repeat(32)}`,
    refresh_authorization_digest_b64u: b64u(7, 32),
    refresh_nonce: 'refresh-nonce-1',
    previous_activation_epoch: 'activation-1',
    next_activation_epoch: 'activation-2',
    expires_at_ms: 1_900_000_000_000,
    deriver_a_refresh_envelope: {
      recipient_role: 'signer_a',
      header_digest: digest(8),
      aad_digest: digest(9),
      ciphertext: { bytes: [1, 2, 3] },
    },
    deriver_b_refresh_envelope: {
      recipient_role: 'signer_b',
      header_digest: digest(10),
      aad_digest: digest(11),
      ciphertext: { bytes: [4, 5, 6] },
    },
  };
}

function refreshCommitRequest(): RouterAbEcdsaDerivationActivationRefreshCommitRequestV1 {
  return {
    activation_correlation_id: parseCorrelationId('activation-correlation-1'),
    expected_server_generation: parseEcdsaServerGeneration('server-generation-1'),
    refresh_request: refreshRequest(),
  };
}

class CapturingRefreshPort implements RouterAbEcdsaDerivationRefreshPort {
  input: RouterAbEcdsaDerivationRefreshPortInput | null = null;

  async refresh(input: RouterAbEcdsaDerivationRefreshPortInput): Promise<Response> {
    this.input = input;
    return Response.json({ ok: true, owner: 'strict-rust' }, { status: 202 });
  }
}

class FixtureCeremonyTokenIssuer implements RouterAbEcdsaCeremonyTokenIssuer {
  async issue(): Promise<string> {
    return 'fixture-token';
  }

  publicJwks(): { readonly keys: readonly JsonWebKey[] } {
    return { keys: [] };
  }
}

class StoppedRefreshRouter {
  async fetch(): Promise<Response> {
    return Response.json(
      {
        result: 'stopped',
        replay: { request_id: 'request-1', reserved: true },
        lifecycle: { lifecycle_id: 'lifecycle-refresh-1', stored: true },
        decision: { kind: 'defer', reason: 'signer_queue_saturated' },
      },
      { status: 200 },
    );
  }
}

test('refresh parser accepts the exact strict Rust request shape', () => {
  expect(parseRouterAbEcdsaDerivationActivationRefreshRequestV1(refreshRequest())).toEqual(
    refreshRequest(),
  );
});

test('refresh commit parser requires journal correlation and server generation', () => {
  expect(
    parseRouterAbEcdsaDerivationActivationRefreshCommitRequestV1(refreshCommitRequest()),
  ).toEqual(refreshCommitRequest());
  const missingCorrelation = {
    expected_server_generation: refreshCommitRequest().expected_server_generation,
    refresh_request: refreshRequest(),
  };
  expect(() =>
    parseRouterAbEcdsaDerivationActivationRefreshCommitRequestV1(missingCorrelation),
  ).toThrow('correlation id must be a non-empty canonical string');
});

test('refresh parser rejects unknown fields and cross-epoch lifecycle drift', () => {
  const unknownField = { ...refreshRequest(), compatibility_refresh: true };
  expect(() => parseRouterAbEcdsaDerivationActivationRefreshRequestV1(unknownField)).toThrow(
    'compatibility_refresh is not a supported field',
  );

  const sameEpoch = refreshRequest();
  sameEpoch.next_activation_epoch = sameEpoch.previous_activation_epoch;
  sameEpoch.lifecycle.root_share_epoch = sameEpoch.previous_activation_epoch;
  expect(() => parseRouterAbEcdsaDerivationActivationRefreshRequestV1(sameEpoch)).toThrow(
    'refresh must advance activation epoch',
  );

  const rootEpochDrift = refreshRequest();
  rootEpochDrift.lifecycle.root_share_epoch = 'activation-3';
  expect(() => parseRouterAbEcdsaDerivationActivationRefreshRequestV1(rootEpochDrift)).toThrow(
    'root_share_epoch must equal next_activation_epoch',
  );
});

test('refresh parser rejects wrong lifecycle and recipient roles', () => {
  const wrongWorkKind: Record<string, unknown> = refreshRequest();
  wrongWorkKind.lifecycle = {
    ...refreshRequest().lifecycle,
    work_kind: 'registration_prepare',
  };
  expect(() => parseRouterAbEcdsaDerivationActivationRefreshRequestV1(wrongWorkKind)).toThrow(
    'work_kind must be server_share_refresh',
  );

  const swappedEnvelope: Record<string, unknown> = refreshRequest();
  swappedEnvelope.deriver_a_refresh_envelope = {
    ...refreshRequest().deriver_a_refresh_envelope,
    recipient_role: 'signer_b',
  };
  expect(() => parseRouterAbEcdsaDerivationActivationRefreshRequestV1(swappedEnvelope)).toThrow(
    'recipient_role must be signer_a',
  );
});

test('refresh route forwards one parsed request and opaque strict-owner response', async () => {
  const port = new CapturingRefreshPort();
  const response = await handleRouterAbEcdsaDerivationRefreshRoute({
    body: refreshCommitRequest(),
    authorizationHeader: 'Bearer refresh-wallet-session',
    port,
  });

  expect(response.status).toBe(202);
  expect(await response.json()).toEqual({ ok: true, owner: 'strict-rust' });
  expect(port.input).toEqual({
    request: refreshCommitRequest(),
    authorization: { kind: 'bearer', token: 'refresh-wallet-session' },
  });
});

test('HTTP refresh port targets the strict Rust route and preserves opaque response', async () => {
  capturedFetchUrl = '';
  capturedFetchInit = undefined;
  const port = new HttpRouterAbEcdsaDerivationRefreshPort({
    strictRouterBaseUrl: 'https://strict-router.example/',
    fetch: captureRefreshFetch,
  });
  const response = await port.refresh({
    request: refreshCommitRequest(),
    authorization: { kind: 'bearer', token: 'refresh-wallet-session' },
  });

  expect(capturedFetchUrl).toBe('https://strict-router.example/router-ab/ecdsa-derivation/refresh');
  expect(capturedFetchInit?.method).toBe('POST');
  expect(capturedFetchInit?.headers).toEqual({
    authorization: 'Bearer refresh-wallet-session',
    'content-type': 'application/json',
  });
  expect(JSON.parse(String(capturedFetchInit?.body))).toEqual(refreshCommitRequest());
  expect(response.status).toBe(201);
  expect(await response.json()).toEqual({ ok: true, receipt: 'opaque' });
});

test('refresh route rejects missing port, authorization, and malformed body before dispatch', async () => {
  const noPort = await handleRouterAbEcdsaDerivationRefreshRoute({
    body: refreshCommitRequest(),
    authorizationHeader: 'Bearer refresh-wallet-session',
    port: null,
  });
  expect(noPort.status).toBe(503);

  const port = new CapturingRefreshPort();
  const noAuthorization = await handleRouterAbEcdsaDerivationRefreshRoute({
    body: refreshCommitRequest(),
    authorizationHeader: null,
    port,
  });
  expect(noAuthorization.status).toBe(401);

  const malformed = await handleRouterAbEcdsaDerivationRefreshRoute({
    body: {
      ...refreshCommitRequest(),
      refresh_request: { ...refreshRequest(), expires_at_ms: 0 },
    },
    authorizationHeader: 'Bearer refresh-wallet-session',
    port,
  });
  expect(malformed.status).toBe(400);
  expect(port.input).toBeNull();
});

test('refresh response parser preserves forwarded, committed replay, and stopped HTTP bodies', () => {
  const activationReceipt = {
    activation_correlation_id: 'activation-correlation-1',
    activation_request_digest: digest(12),
    server_generation: 'server-generation-2',
    ecdsa_activation: {
      context: refreshRequest().context,
      public_identity: refreshRequest().public_identity,
      signing_worker: refreshRequest().signer_set.selected_server,
      activation_epoch: refreshRequest().next_activation_epoch,
      activation_digest_b64u: b64u(13, 32),
      activated_at_ms: 1_800_000_000_000,
    },
    lifecycle_id: refreshRequest().lifecycle.lifecycle_id,
    transcript_digest: digest(14),
  };
  expect(
    parseRouterAbEcdsaDerivationActivationRefreshResponseV1({
      result: 'activation_committed',
      signing_worker_activation: activationReceipt,
    }),
  ).toMatchObject({
    result: 'activation_committed',
    signing_worker_activation: {
      activation_correlation_id: 'activation-correlation-1',
      server_generation: 'server-generation-2',
    },
  });
  expect(
    parseRouterAbEcdsaDerivationActivationRefreshResponseV1({
      result: 'stopped',
      replay: { request_id: 'request-1', reserved: true },
      lifecycle: { lifecycle_id: 'lifecycle-refresh-1', stored: true },
      decision: { kind: 'defer', reason: 'signer_queue_saturated' },
    }),
  ).toEqual({
    result: 'stopped',
    replay: { request_id: 'request-1', reserved: true },
    lifecycle: { lifecycle_id: 'lifecycle-refresh-1', stored: true },
    decision: { kind: 'defer', reason: 'signer_queue_saturated' },
  });
});

test('strict refresh treats a stopped HTTP 200 as a typed terminal result', async () => {
  const request = refreshCommitRequest();
  const port = createRouterAbEcdsaStrictPostRegistrationPort({
    router: new StoppedRefreshRouter(),
    tokenIssuer: new FixtureCeremonyTokenIssuer(),
    tokenScope: {
      orgId: 'org-1',
      projectId: 'project-1',
      environment: 'test',
    },
    topology: {
      routerId: request.refresh_request.router_id,
      signerSet: request.refresh_request.signer_set,
      deriverRecipientKeys: {
        deriver_a: {
          role: 'signer_a',
          key_epoch: 'a-epoch-1',
          public_key: `x25519:${'01'.repeat(32)}`,
        },
        deriver_b: {
          role: 'signer_b',
          key_epoch: 'b-epoch-1',
          public_key: `x25519:${'02'.repeat(32)}`,
        },
      },
    },
  });
  const result = await port.refresh({
    request,
    authority: {
      subjectId: request.refresh_request.client_id,
      sessionId: request.refresh_request.lifecycle.session_id,
      accountId: request.refresh_request.lifecycle.account_id,
      expiresAtMs: request.refresh_request.expires_at_ms,
    },
  });
  expect(result).toEqual({
    ok: true,
    value: {
      result: 'stopped',
      replay: { request_id: 'request-1', reserved: true },
      lifecycle: { lifecycle_id: 'lifecycle-refresh-1', stored: true },
      decision: { kind: 'defer', reason: 'signer_queue_saturated' },
    },
  });
});
