import { expect, test } from '@playwright/test';
import {
  createInMemoryRouterAbNormalSigningAdmissionStore,
  createRouterAbNormalSigningAdmissionAdapter,
  type RouterAbNormalSigningAdmissionInput,
} from '@server/router/express-adaptor';

const BASE_EXPIRES_AT_MS = 10_000;

type Ed25519AdmissionInput = Extract<RouterAbNormalSigningAdmissionInput, { curve: 'ed25519' }>;
type EcdsaHssAdmissionInput = Extract<RouterAbNormalSigningAdmissionInput, { curve: 'ecdsa-hss' }>;

function ed25519AdmissionInput(
  overrides: Partial<Ed25519AdmissionInput> = {},
): Ed25519AdmissionInput {
  return {
    curve: 'ed25519',
    phase: 'prepare',
    walletId: 'alice.testnet',
    rpId: 'example.localhost',
    thresholdSessionId: 'threshold-session-1',
    signingGrantId: 'signing-grant-1',
    requestId: 'request-1',
    expiresAtMs: BASE_EXPIRES_AT_MS,
    signingWorkerId: 'signing-worker-a',
    runtimePolicyScope: {
      orgId: 'org',
      projectId: 'project',
      envId: 'dev',
      signingRootVersion: 'root-v1',
    },
    ...overrides,
  };
}

function ecdsaHssAdmissionInput(
  overrides: Partial<EcdsaHssAdmissionInput> = {},
): EcdsaHssAdmissionInput {
  return {
    curve: 'ecdsa-hss',
    phase: 'prepare',
    walletId: 'alice.testnet',
    rpId: 'example.localhost',
    thresholdSessionId: 'ecdsa-session-1',
    signingGrantId: 'signing-grant-1',
    requestId: 'ecdsa-request-1',
    expiresAtMs: BASE_EXPIRES_AT_MS,
    signingWorkerId: 'signing-worker-a',
    keyHandle: 'ecdsa-key-handle-1',
    runtimePolicyScope: {
      orgId: 'org',
      projectId: 'project',
      envId: 'dev',
      signingRootVersion: 'root-v1',
    },
    ...overrides,
  };
}

test.describe('Router A/B normal-signing admission store', () => {
  test('accepts the first request and treats the same request id as existing work', async () => {
    let nowMs = 1_000;
    const store = createInMemoryRouterAbNormalSigningAdmissionStore({ now: () => nowMs });
    const adapter = createRouterAbNormalSigningAdmissionAdapter(store, { now: () => nowMs });
    const input = ed25519AdmissionInput();

    await expect(adapter.evaluate(input)).resolves.toEqual({ ok: true });
    await expect(adapter.evaluate(input)).resolves.toEqual({ ok: true });
  });

  test('accepts distinct active request ids for the same signing scope', async () => {
    let nowMs = 1_000;
    const store = createInMemoryRouterAbNormalSigningAdmissionStore({ now: () => nowMs });
    const adapter = createRouterAbNormalSigningAdmissionAdapter(store, { now: () => nowMs });
    const input = ed25519AdmissionInput();
    const ecdsaInput = ecdsaHssAdmissionInput();

    await expect(adapter.evaluate(input)).resolves.toEqual({ ok: true });
    await expect(
      adapter.evaluate(ed25519AdmissionInput({ requestId: 'request-2' })),
    ).resolves.toEqual({ ok: true });
    await expect(adapter.evaluate(ecdsaInput)).resolves.toEqual({ ok: true });
    await expect(
      adapter.evaluate(ecdsaHssAdmissionInput({ requestId: 'ecdsa-request-2' })),
    ).resolves.toEqual({ ok: true });
  });

  test('expires quota reservations before accepting later work', async () => {
    let nowMs = 1_000;
    const store = createInMemoryRouterAbNormalSigningAdmissionStore({ now: () => nowMs });
    const adapter = createRouterAbNormalSigningAdmissionAdapter(store, { now: () => nowMs });

    await expect(
      adapter.evaluate(ed25519AdmissionInput({ requestId: 'request-1', expiresAtMs: 2_000 })),
    ).resolves.toEqual({ ok: true });

    nowMs = 3_000;

    await expect(
      adapter.evaluate(ed25519AdmissionInput({ requestId: 'request-2', expiresAtMs: 4_000 })),
    ).resolves.toEqual({ ok: true });
  });

  test('expires exact lifecycle reservations before the signing request expiry', async () => {
    let nowMs = 1_000;
    const store = createInMemoryRouterAbNormalSigningAdmissionStore({ now: () => nowMs });
    const input = ecdsaHssAdmissionInput({ expiresAtMs: 60_000 });

    await expect(store.reserveQuota(input)).resolves.toEqual({
      kind: 'accepted',
      requestId: input.requestId,
    });
    await expect(store.reserveQuota(input)).resolves.toEqual({
      kind: 'reuse_existing',
      requestId: input.requestId,
      existingLifecycleId:
        'ecdsa-hss:prepare:alice.testnet:example.localhost:ecdsa-session-1:signing-grant-1:ecdsa-request-1:signing-worker-a:ecdsa-key-handle-1',
    });

    nowMs = 6_001;

    await expect(store.reserveQuota(input)).resolves.toEqual({
      kind: 'accepted',
      requestId: input.requestId,
    });
  });

  test('keeps Ed25519 and ECDSA-HSS quota scopes separate', async () => {
    let nowMs = 1_000;
    const store = createInMemoryRouterAbNormalSigningAdmissionStore({ now: () => nowMs });
    const adapter = createRouterAbNormalSigningAdmissionAdapter(store, { now: () => nowMs });

    await expect(adapter.evaluate(ed25519AdmissionInput())).resolves.toEqual({ ok: true });
    await expect(adapter.evaluate(ecdsaHssAdmissionInput())).resolves.toEqual({ ok: true });
  });

  test('maps project policy rejection before quota reservation', async () => {
    let nowMs = 1_000;
    const store = createInMemoryRouterAbNormalSigningAdmissionStore({ now: () => nowMs });
    const adapter = createRouterAbNormalSigningAdmissionAdapter(store, { now: () => nowMs });
    const input = ed25519AdmissionInput();
    store.setProjectPolicy(input.runtimePolicyScope, {
      kind: 'rejected',
      retryAfterMs: 5_000,
    });

    await expect(adapter.evaluate(input)).resolves.toEqual({
      ok: false,
      status: 403,
      code: 'project_policy_rejected',
      message: 'Router A/B normal-signing project policy rejected the request',
    });

    store.clearProjectPolicy(input.runtimePolicyScope);
    await expect(adapter.evaluate(input)).resolves.toEqual({ ok: true });
  });

  test('maps abuse rate-limit and rejection decisions before quota reservation', async () => {
    let nowMs = 1_000;
    const store = createInMemoryRouterAbNormalSigningAdmissionStore({ now: () => nowMs });
    const adapter = createRouterAbNormalSigningAdmissionAdapter(store, { now: () => nowMs });
    const input = ed25519AdmissionInput();

    store.setAbuseDecision(input, { kind: 'rate_limited', retryAfterMs: 5_000 });
    await expect(adapter.evaluate(input)).resolves.toEqual({
      ok: false,
      status: 429,
      code: 'rate_limited',
      message: 'Router A/B normal-signing request is rate limited',
    });

    store.setAbuseDecision(input, { kind: 'rejected', retryAfterMs: 5_000 });
    await expect(adapter.evaluate(input)).resolves.toEqual({
      ok: false,
      status: 403,
      code: 'abuse_rejected',
      message: 'Router A/B normal-signing abuse policy rejected the request',
    });

    store.clearAbuseDecision(input);
    await expect(adapter.evaluate(input)).resolves.toEqual({ ok: true });
  });

  test('rejects expired requests before store decisions run', async () => {
    let nowMs = 5_000;
    const store = createInMemoryRouterAbNormalSigningAdmissionStore({ now: () => nowMs });
    const adapter = createRouterAbNormalSigningAdmissionAdapter(store, { now: () => nowMs });

    await expect(adapter.evaluate(ed25519AdmissionInput({ expiresAtMs: nowMs }))).resolves.toEqual({
      ok: false,
      status: 408,
      code: 'invalid_body',
      message: 'Router A/B normal-signing request is expired',
    });

    await expect(
      adapter.evaluate(ed25519AdmissionInput({ requestId: 'request-2', expiresAtMs: 6_000 })),
    ).resolves.toEqual({ ok: true });
  });
});
