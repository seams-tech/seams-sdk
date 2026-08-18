import { expect, test } from '@playwright/test';
import { proxyNormalSigningRequestToMpcRouter } from '../../packages/wallet-server/src/router/transport/fetch/routes/normalSigningRouterProxy';
import {
  buildEd25519ReplayResponse,
  decideEd25519NormalSigningExecution,
  decideEd25519OperationStepUpExecution,
  isRouterAbEd25519OperationInProgressResponse,
  requireCompletedEd25519OperationResponse,
} from '../../packages/wallet-server/src/router/transport/fetch/routes/thresholdEd25519';
import { decideRouterAbEcdsaOperationStepUpExecution } from '../../packages/wallet-server/src/router/transport/fetch/routes/thresholdEcdsa';
import {
  buildCompletedAuthorizedOperationFixture,
  buildReusableAuthorizationCoreFixture,
  buildStepUpAuthorizationCoreFixture,
} from './helpers/authorizationCore.fixtures';
import {
  routerAbEcdsaOperationInProgressResult,
  routerAbEcdsaReplayHttpResponse,
  routerAbEcdsaReplayResult,
} from '../../packages/wallet-server/src/router/domains/signingOperations/routerAbPrivateSigningWorker';

test('normal-signing proxy preserves authorization and source-binding headers', async () => {
  let forwarded: Request | null = null;
  const request = new Request('https://gateway.example/router-ab/ecdsa-derivation/sign/prepare', {
    method: 'POST',
    headers: {
      authorization: 'Bearer wallet-session-jwt',
      'content-type': 'application/json',
      origin: 'https://sign.example',
      'cf-connecting-ip': '203.0.113.17',
      'cf-ray': 'ray-id-NRT',
      'x-seams-trace-id': 'trace-correlation-1',
      'x-router-ab-internal-service-auth': 'forged-client-secret',
    },
    body: JSON.stringify({ request_id: 'request-1' }),
  });

  const response = await proxyNormalSigningRequestToMpcRouter({
    request,
    proxy: {
      internalServiceAuthSecret: 'router-internal-secret',
      async fetch(input) {
        forwarded = input;
        return new Response(JSON.stringify({ ok: true }), {
          status: 200,
          headers: {
            'content-type': 'application/json',
            'server-timing': 'router;dur=12',
          },
        });
      },
    },
  });

  expect(forwarded).not.toBeNull();
  if (!forwarded) throw new Error('expected MPC Router request');
  expect(forwarded.url).toBe(request.url);
  expect(forwarded.method).toBe('POST');
  expect(forwarded.headers.get('authorization')).toBe('Bearer wallet-session-jwt');
  expect(forwarded.headers.get('origin')).toBe('https://sign.example');
  expect(forwarded.headers.get('cf-connecting-ip')).toBe('203.0.113.17');
  expect(forwarded.headers.get('cf-ray')).toBe('ray-id-NRT');
  expect(forwarded.headers.get('x-seams-trace-id')).toBe('trace-correlation-1');
  expect(forwarded.headers.get('x-router-ab-internal-service-auth')).toBe('router-internal-secret');
  expect(await forwarded.json()).toEqual({ request_id: 'request-1' });
  expect(response.status).toBe(200);
  expect(response.headers.get('server-timing')).toBe('router;dur=12');
  await expect(response.json()).resolves.toEqual({ ok: true });
});

test('normal-signing proxy fails closed when MPC Router transport is absent', async () => {
  const response = await proxyNormalSigningRequestToMpcRouter({
    request: new Request('https://gateway.example/router-ab/ed25519/sign', {
      method: 'POST',
      body: '{}',
    }),
    proxy: null,
  });

  expect(response.status).toBe(501);
  await expect(response.json()).resolves.toMatchObject({
    ok: false,
    code: 'not_configured',
  });
});

test('Ed25519 SigningWorker in-progress conflict remains non-terminal at the Gateway', () => {
  expect(
    isRouterAbEd25519OperationInProgressResponse({
      status: 409,
      bodyText: 'ReplayedLocalRequest: SigningWorker normal-signing effect is already in progress',
    }),
  ).toBe(true);
  expect(
    isRouterAbEd25519OperationInProgressResponse({
      status: 409,
      bodyText: 'ConflictingPair: SigningWorker request conflicts with existing work',
    }),
  ).toBe(false);
});

test('Ed25519 completion captures the upstream response text and content type exactly', async () => {
  const upstream = new Response('{"ok":false}\n', {
    status: 502,
    headers: { 'content-type': 'application/problem+json' },
  });

  expect(
    buildEd25519ReplayResponse({
      response: upstream,
      bodyText: await upstream.clone().text(),
    }),
  ).toEqual({
    status: 502,
    contentType: 'application/problem+json',
    bodyText: '{"ok":false}\n',
  });
});

test('Ed25519 in-progress prepare admission returns 409 without an execution decision', async () => {
  const fixture = await buildReusableAuthorizationCoreFixture();
  const decision = decideEd25519NormalSigningExecution({
    phase: 'prepare',
    admissionKind: 'operation_in_progress',
    operation: fixture.authorizedOperation,
  });

  expect(decision.kind).toBe('operation_in_progress');
  if (decision.kind !== 'operation_in_progress') throw new Error('expected in-progress decision');
  expect(decision.response.status).toBe(409);
  await expect(decision.response.json()).resolves.toMatchObject({
    ok: false,
    code: 'operation_in_progress',
  });
});

test('Ed25519 operation step-up reuses its preclaimed operation through prepare', async () => {
  const stepUp = await buildStepUpAuthorizationCoreFixture();

  const prepare = decideEd25519OperationStepUpExecution({
    admissionKind: 'operation_in_progress',
    operation: stepUp.authorizedOperation,
  });
  expect(prepare.kind).toBe('execute');
  if (prepare.kind !== 'execute') throw new Error('expected preclaimed prepare to execute');
  expect(prepare.operation).toBe(stepUp.authorizedOperation);

  const completed = await buildCompletedAuthorizedOperationFixture(stepUp);
  const replay = decideEd25519OperationStepUpExecution({
    admissionKind: 'replayed',
    operation: completed,
  });
  expect(replay.kind).toBe('replay');
  if (replay.kind !== 'replay') throw new Error('expected completed step-up to replay');
  expect(replay.response.status).toBe(200);
  await expect(replay.response.text()).resolves.toBe('{"ok":true}');
});

test('Ed25519 completion readback is required and preserves the recorded response', async () => {
  const fixture = await buildReusableAuthorizationCoreFixture();
  expect(() => requireCompletedEd25519OperationResponse(fixture.authorizedOperation)).toThrow(
    'Ed25519 operation completion readback is not completed',
  );

  const operation = await buildCompletedAuthorizedOperationFixture(fixture);
  const replay = requireCompletedEd25519OperationResponse(operation);
  expect(replay.status).toBe(200);
  expect(replay.headers.get('content-type')).toBe('application/json');
  await expect(replay.text()).resolves.toBe('{"ok":true}');

  const decision = decideEd25519NormalSigningExecution({
    phase: 'prepare',
    admissionKind: 'replayed',
    operation,
  });
  expect(decision.kind).toBe('replayed');
});

test('normal-signing proxy forwards the trusted body selected by the gateway', async () => {
  let forwardedBody: unknown = null;
  const request = new Request('https://gateway.example/router-ab/ed25519/sign', {
    method: 'POST',
    headers: { authorization: 'Bearer wallet-session-jwt' },
    body: JSON.stringify({ authorized_operation: { kind: 'untrusted' } }),
  });
  const response = await proxyNormalSigningRequestToMpcRouter({
    request,
    body: {
      authorized_operation: {
        kind: 'reusable_wallet_session_authorized_operation_v1',
        authorized_operation_id: 'authorized-operation-1',
      },
    },
    proxy: {
      internalServiceAuthSecret: 'router-internal-secret',
      async fetch(input) {
        forwardedBody = await input.json();
        return Response.json({ ok: true });
      },
    },
  });

  expect(response.status).toBe(200);
  expect(forwardedBody).toEqual({
    authorized_operation: {
      kind: 'reusable_wallet_session_authorized_operation_v1',
      authorized_operation_id: 'authorized-operation-1',
    },
  });
});

test('ECDSA in-progress admission returns a typed conflict before execution', async () => {
  const result = routerAbEcdsaOperationInProgressResult();

  expect(result).toEqual({
    status: 409,
    body: {
      ok: false,
      code: 'operation_in_progress',
      message: 'ECDSA signing operation is already in progress',
    },
  });
});

test('ECDSA operation step-up reuses its preclaimed operation through finalize', async () => {
  const stepUp = await buildStepUpAuthorizationCoreFixture();

  const prepare = decideRouterAbEcdsaOperationStepUpExecution({
    phase: 'prepare',
    admissionKind: 'operation_in_progress',
    operation: stepUp.authorizedOperation,
  });
  expect(prepare.kind).toBe('execute');
  if (prepare.kind !== 'execute') throw new Error('expected preclaimed prepare to execute');
  expect(prepare.operation).toBe(stepUp.authorizedOperation);

  const finalize = decideRouterAbEcdsaOperationStepUpExecution({
    phase: 'finalize',
    admissionKind: 'operation_in_progress',
    operation: prepare.operation,
  });
  expect(finalize.kind).toBe('execute');
  if (finalize.kind !== 'execute') throw new Error('expected preclaimed finalize to execute');
  expect(finalize.operation).toBe(stepUp.authorizedOperation);

  const reusable = await buildReusableAuthorizationCoreFixture();
  const completed = await buildCompletedAuthorizedOperationFixture(reusable);
  expect(
    decideRouterAbEcdsaOperationStepUpExecution({
      phase: 'finalize',
      admissionKind: 'replayed',
      operation: completed,
    }).kind,
  ).toBe('replay');
});

test('ECDSA completed admission replays the recorded response without proxying', async () => {
  const fixture = await buildReusableAuthorizationCoreFixture();
  const operation = await buildCompletedAuthorizedOperationFixture(fixture);
  const replay = routerAbEcdsaReplayHttpResponse(operation);

  expect(replay).not.toBeNull();
  if (!replay) throw new Error('expected a replay response');
  expect(replay.status).toBe(200);
  expect(replay.headers.get('content-type')).toBe('application/json');
  await expect(replay.text()).resolves.toBe('{"ok":true}');
  expect(routerAbEcdsaReplayResult(operation)).toEqual({
    status: 200,
    body: { ok: true },
  });
});
