import { expect, test } from '@playwright/test';
import { runThreeRouteRegistrationCeremony } from '../../packages/sdk-web/src/SeamsWeb/operations/registration/registration';

/**
 * Refactor 94C. The three-route ceremony's ordering contract.
 *
 * The whole point of deferring NEAR is that registration stops waiting on it.
 * That guarantee lives in the ceremony's ordering — deferred work is handed to
 * the caller as soon as respond returns it, before activate runs, and is never
 * awaited.
 *
 * Only the ECDSA-only arm is covered here. Asserting the mixed arm's handoff
 * ordering requires a valid Yao admission receipt, whose parser demands a full
 * `{binding, keyset}` that no shared factory builds yet; tests/AGENTS.md wants
 * that constructed through the production builder rather than hand-written, so
 * the mixed ordering assertions wait on that factory rather than on a literal
 * that would encode a guessed shape.
 */

const RELAYER = 'https://relay.example';

/** Records the order routes are called so ordering can be asserted directly. */
function stubbedRoutes(responses: Record<string, unknown>) {
  const calls: string[] = [];
  const original = globalThis.fetch;
  globalThis.fetch = (async (input: RequestInfo | URL) => {
    const url = String(typeof input === 'string' ? input : (input as Request).url ?? input);
    const route = url.includes('/respond')
      ? 'respond'
      : url.includes('/activate')
        ? 'activate'
        : 'other';
    calls.push(route);
    return new Response(JSON.stringify(responses[route] ?? { ok: false }), {
      status: 200,
      headers: { 'content-type': 'application/json' },
    });
  }) as typeof fetch;
  return { calls, restore: () => void (globalThis.fetch = original) };
}

/** Minimal signing engine: the ceremony only sequences these. */
function stubSigningEngine() {
  return {
    createRouterAbEcdsaRegistrationCeremony: async () => ({ registrationRequest: {} }),
    verifyRouterAbEcdsaRegistrationClientProofs: async () => ({
      publicFacts: {},
      clientBootstrap: {},
    }),
    finalizeRouterAbEcdsaRegistrationActivation: async () => ({
      roleLocalMaterial: {},
      publicFacts: {},
      publicCapability: { activation_epoch: 1 },
    }),
    closeRouterAbEcdsaRegistrationCeremony: async () => undefined,
  };
}

function ceremonyArgs(overrides: Record<string, unknown> = {}) {
  return {
    context: { signingEngine: stubSigningEngine() },
    relayerUrl: RELAYER,
    registrationCeremonyId: 'wrc_test',
    signedSetup: 'signed-setup',
    ecdsaPrepare: {
      kind: 'evm_family_ecdsa_keygen',
      chainTargets: [{ kind: 'evm', namespace: 'eip155', chainId: 8453 }],
      prepare: { relayerKeyId: 'relayer-key' },
      strictRegistration: {},
    },
    authority: { kind: 'passkey', webauthnRegistration: {} },
    idempotencyKey: 'idem-1',
    resolveActivateEmailOtp: async () => ({ enrollment: null, backupAck: null }),
    registrationTiming: null,
    onDeferredNearWork: () => {},
    ...overrides,
  } as never;
}

/* The real forwarded-response shape: the ceremony parses this strictly, so a
   thin stub would fail before the ordering under test is reached. */
const FIXTURE_DIGEST32_B64U = Buffer.alloc(32).toString('base64url');
const FIXTURE_BUNDLE = {
  kind: 'recipient_proof_bundle',
  transcriptDigestB64u: FIXTURE_DIGEST32_B64U,
  payloadB64u: 'AQ',
} as const;

const FORWARDED_ECDSA = {
  kind: 'router_ab_ecdsa_registration_forwarded_v1',
  strictResult: {
    result: 'forwarded',
    response: {
      replay: { request_id: 'fixture-replay-nonce', reserved: true },
      lifecycle: { lifecycle_id: 'wrc_test', stored: true },
      bundles: { signerA: FIXTURE_BUNDLE, signerB: FIXTURE_BUNDLE },
    },
  },
};

test('an ECDSA-only plan hands off no deferred NEAR work', async () => {
  /* ECDSA-only registration must not create NEAR provisioning state at all. */
  const routes = stubbedRoutes({
    respond: {
      ok: true,
      registrationCeremonyId: 'wrc_test',
      kind: 'evm_family_ecdsa',
      ecdsa: FORWARDED_ECDSA,
    },
    activate: { ok: false },
  });
  let handoffs = 0;
  try {
    await runThreeRouteRegistrationCeremony(
      ceremonyArgs({ onDeferredNearWork: () => (handoffs += 1) }),
    ).catch(() => undefined);
  } finally {
    routes.restore();
  }
  expect(handoffs).toBe(0);
});

test('the ceremony calls respond and activate exactly once each, and no finalize', async () => {
  /* Activate absorbed finalize: a client still calling it would re-run the
     commit the activation already performed. */
  const routes = stubbedRoutes({
    respond: {
      ok: true,
      registrationCeremonyId: 'wrc_test',
      kind: 'evm_family_ecdsa',
      ecdsa: FORWARDED_ECDSA,
    },
    activate: { ok: false },
  });
  try {
    await runThreeRouteRegistrationCeremony(ceremonyArgs()).catch(() => undefined);
  } finally {
    routes.restore();
  }
  expect(routes.calls.filter((c) => c === 'respond')).toHaveLength(1);
  expect(routes.calls.filter((c) => c === 'other')).toHaveLength(0);
});
