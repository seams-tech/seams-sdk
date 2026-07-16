import { expect, test } from '@playwright/test';
import {
  parseRouterAbEcdsaDerivationActivationRefreshRequestV1,
  type RouterAbEcdsaDerivationActivationRefreshRequestV1,
} from '@shared/utils/routerAbEcdsaDerivation';
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
      server_public_key33_b64u: b64u(4, 33),
      threshold_public_key33_b64u: b64u(5, 33),
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
        recipient_encryption_key: 'x25519:worker-public-key',
      },
    },
    router_id: 'router-1',
    client_id: 'client-1',
    signing_worker_ephemeral_public_key: 'x25519:ephemeral-public-key',
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

class CapturingRefreshPort implements RouterAbEcdsaDerivationRefreshPort {
  input: RouterAbEcdsaDerivationRefreshPortInput | null = null;

  async refresh(input: RouterAbEcdsaDerivationRefreshPortInput): Promise<Response> {
    this.input = input;
    return Response.json({ ok: true, owner: 'strict-rust' }, { status: 202 });
  }
}

test('refresh parser accepts the exact strict Rust request shape', () => {
  expect(parseRouterAbEcdsaDerivationActivationRefreshRequestV1(refreshRequest())).toEqual(
    refreshRequest(),
  );
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
    body: refreshRequest(),
    authorizationHeader: 'Bearer refresh-wallet-session',
    port,
  });

  expect(response.status).toBe(202);
  expect(await response.json()).toEqual({ ok: true, owner: 'strict-rust' });
  expect(port.input).toEqual({
    request: refreshRequest(),
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
    request: refreshRequest(),
    authorization: { kind: 'bearer', token: 'refresh-wallet-session' },
  });

  expect(capturedFetchUrl).toBe('https://strict-router.example/router-ab/ecdsa-derivation/refresh');
  expect(capturedFetchInit?.method).toBe('POST');
  expect(capturedFetchInit?.headers).toEqual({
    authorization: 'Bearer refresh-wallet-session',
    'content-type': 'application/json',
  });
  expect(JSON.parse(String(capturedFetchInit?.body))).toEqual(refreshRequest());
  expect(response.status).toBe(201);
  expect(await response.json()).toEqual({ ok: true, receipt: 'opaque' });
});

test('refresh route rejects missing port, authorization, and malformed body before dispatch', async () => {
  const noPort = await handleRouterAbEcdsaDerivationRefreshRoute({
    body: refreshRequest(),
    authorizationHeader: 'Bearer refresh-wallet-session',
    port: null,
  });
  expect(noPort.status).toBe(503);

  const port = new CapturingRefreshPort();
  const noAuthorization = await handleRouterAbEcdsaDerivationRefreshRoute({
    body: refreshRequest(),
    authorizationHeader: null,
    port,
  });
  expect(noAuthorization.status).toBe(401);

  const malformed = await handleRouterAbEcdsaDerivationRefreshRoute({
    body: { ...refreshRequest(), expires_at_ms: 0 },
    authorizationHeader: 'Bearer refresh-wallet-session',
    port,
  });
  expect(malformed.status).toBe(400);
  expect(port.input).toBeNull();
});
