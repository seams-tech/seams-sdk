import { expect, test } from '@playwright/test';
import {
  createInMemoryRouterAbNormalSigningAdmissionStore,
  createRouterAbNormalSigningAdmissionAdapter,
  type RouterAbNormalSigningAdmissionInput,
} from '@server/router/express-adaptor';
import { createCloudflareD1RouterAbNormalSigningAdmissionStore } from '../../packages/wallet-server/src/router/cloudflare/d1/signingAdmission/d1RouterAbNormalSigningAdmissionStore';
import {
  applyD1MigrationFiles,
  cleanupTemporaryD1Database,
  createTemporaryD1Database,
  listD1MigrationFiles,
} from '../helpers/sqliteD1';
import { parseMpcMaterialActivationId } from '../../packages/shared-ts/src/utils/domainIds';

const BASE_EXPIRES_AT_MS = 10_000;

type Ed25519AdmissionInput = Extract<RouterAbNormalSigningAdmissionInput, { curve: 'ed25519' }>;
type EcdsaAdmissionInput = Extract<RouterAbNormalSigningAdmissionInput, { curve: 'ecdsa' }>;

function materialActivationId(value: string) {
  const parsed = parseMpcMaterialActivationId(value);
  if (!parsed.ok) throw new Error(parsed.error.message);
  return parsed.value;
}

function ed25519AdmissionInput(
  overrides: Partial<Ed25519AdmissionInput> = {},
): Ed25519AdmissionInput {
  return {
    curve: 'ed25519',
    phase: 'prepare',
    walletId: 'alice.testnet',
    authorityScope: {
      kind: 'passkey_rp',
      rpId: 'example.localhost',
    },
    thresholdSessionId: 'threshold-session-1',
    walletSessionId: 'wallet-session-1',
    quotaId: 'wallet-session-quota-1',
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

function ecdsaAdmissionInput(overrides: Partial<EcdsaAdmissionInput> = {}): EcdsaAdmissionInput {
  return {
    curve: 'ecdsa',
    phase: 'prepare',
    walletId: 'alice.testnet',
    materialActivationId: materialActivationId('ecdsa-material-activation-1'),
    authorizationIdentity: {
      kind: 'reusable_wallet_session',
      walletSessionId: 'ecdsa-session-1',
    },
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
  test('private D1 store persists project and abuse policy decisions', async () => {
    const { database, tempDir } = createTemporaryD1Database();
    try {
      await applyD1MigrationFiles(database, listD1MigrationFiles('d1-signer'));
      const nowMs = 1_000;
      const store = createCloudflareD1RouterAbNormalSigningAdmissionStore({
        database,
        storageNamespace: 'test-namespace',
        now: () => nowMs,
      });
      const adapter = createRouterAbNormalSigningAdmissionAdapter(store, { now: () => nowMs });
      const input = ed25519AdmissionInput();

      await store.setProjectPolicy(input.runtimePolicyScope, {
        kind: 'rejected',
        retryAfterMs: 5_000,
      });
      await expect(adapter.evaluatePolicy(input)).resolves.toEqual({
        ok: false,
        status: 403,
        code: 'project_policy_rejected',
        message: 'Router A/B normal-signing project policy rejected the request',
      });

      await store.clearProjectPolicy(input.runtimePolicyScope);
      await store.setAbuseDecision(input, { kind: 'rate_limited', retryAfterMs: 5_000 });
      await expect(adapter.evaluatePolicy(input)).resolves.toEqual({
        ok: false,
        status: 429,
        code: 'rate_limited',
        message: 'Router A/B normal-signing request is rate limited',
      });

      await store.clearAbuseDecision(input);
      await expect(adapter.evaluatePolicy(input)).resolves.toEqual({ ok: true });
    } finally {
      cleanupTemporaryD1Database(tempDir);
    }
  });

  test('accepts repeated admission after policy evaluation', async () => {
    const nowMs = 1_000;
    const store = createInMemoryRouterAbNormalSigningAdmissionStore();
    const adapter = createRouterAbNormalSigningAdmissionAdapter(store, { now: () => nowMs });
    const input = ed25519AdmissionInput();

    await expect(adapter.evaluatePolicy(input)).resolves.toEqual({ ok: true });
    await expect(adapter.evaluatePolicy(input)).resolves.toEqual({ ok: true });
  });

  test('accepts distinct active request ids for the same signing scope', async () => {
    const nowMs = 1_000;
    const store = createInMemoryRouterAbNormalSigningAdmissionStore();
    const adapter = createRouterAbNormalSigningAdmissionAdapter(store, { now: () => nowMs });
    const input = ed25519AdmissionInput();

    await expect(adapter.evaluatePolicy(input)).resolves.toEqual({ ok: true });
    await expect(
      adapter.evaluatePolicy(ed25519AdmissionInput({ requestId: 'request-2' })),
    ).resolves.toEqual({ ok: true });
  });

  test('rejects expired input and accepts later live work', async () => {
    let nowMs = 1_000;
    const store = createInMemoryRouterAbNormalSigningAdmissionStore();
    const adapter = createRouterAbNormalSigningAdmissionAdapter(store, { now: () => nowMs });

    await expect(
      adapter.evaluatePolicy(ed25519AdmissionInput({ requestId: 'request-1', expiresAtMs: 2_000 })),
    ).resolves.toEqual({ ok: true });

    nowMs = 3_000;

    await expect(
      adapter.evaluatePolicy(ed25519AdmissionInput({ requestId: 'request-2', expiresAtMs: 4_000 })),
    ).resolves.toEqual({ ok: true });
  });

  test('evaluates ECDSA policy through the same admission store', async () => {
    const nowMs = 1_000;
    const store = {
      async evaluateProjectPolicy() {
        return { kind: 'allowed' as const };
      },
      async evaluateAbuse() {
        return { kind: 'allowed' as const };
      },
    };
    const adapter = createRouterAbNormalSigningAdmissionAdapter(store, { now: () => nowMs });

    await expect(adapter.evaluatePolicy(ecdsaAdmissionInput())).resolves.toEqual({ ok: true });
  });

  test('maps project policy rejection', async () => {
    const nowMs = 1_000;
    const store = createInMemoryRouterAbNormalSigningAdmissionStore();
    const adapter = createRouterAbNormalSigningAdmissionAdapter(store, { now: () => nowMs });
    const input = ed25519AdmissionInput();
    store.setProjectPolicy(input.runtimePolicyScope, {
      kind: 'rejected',
      retryAfterMs: 5_000,
    });

    await expect(adapter.evaluatePolicy(input)).resolves.toEqual({
      ok: false,
      status: 403,
      code: 'project_policy_rejected',
      message: 'Router A/B normal-signing project policy rejected the request',
    });

    store.clearProjectPolicy(input.runtimePolicyScope);
    await expect(adapter.evaluatePolicy(input)).resolves.toEqual({ ok: true });
  });

  test('maps abuse rate-limit and rejection decisions', async () => {
    const nowMs = 1_000;
    const store = createInMemoryRouterAbNormalSigningAdmissionStore();
    const adapter = createRouterAbNormalSigningAdmissionAdapter(store, { now: () => nowMs });
    const input = ed25519AdmissionInput();

    store.setAbuseDecision(input, { kind: 'rate_limited', retryAfterMs: 5_000 });
    await expect(adapter.evaluatePolicy(input)).resolves.toEqual({
      ok: false,
      status: 429,
      code: 'rate_limited',
      message: 'Router A/B normal-signing request is rate limited',
    });

    store.setAbuseDecision(input, { kind: 'rejected', retryAfterMs: 5_000 });
    await expect(adapter.evaluatePolicy(input)).resolves.toEqual({
      ok: false,
      status: 403,
      code: 'abuse_rejected',
      message: 'Router A/B normal-signing abuse policy rejected the request',
    });

    store.clearAbuseDecision(input);
    await expect(adapter.evaluatePolicy(input)).resolves.toEqual({ ok: true });
  });

  test('rejects expired requests before store decisions run', async () => {
    const nowMs = 5_000;
    const store = createInMemoryRouterAbNormalSigningAdmissionStore();
    const adapter = createRouterAbNormalSigningAdmissionAdapter(store, { now: () => nowMs });

    await expect(
      adapter.evaluatePolicy(ed25519AdmissionInput({ expiresAtMs: nowMs })),
    ).resolves.toEqual({
      ok: false,
      status: 408,
      code: 'invalid_body',
      message: 'Router A/B normal-signing request is expired',
    });

    await expect(
      adapter.evaluatePolicy(ed25519AdmissionInput({ requestId: 'request-2', expiresAtMs: 6_000 })),
    ).resolves.toEqual({ ok: true });
  });
});
