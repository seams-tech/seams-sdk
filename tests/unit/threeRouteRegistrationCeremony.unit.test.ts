import { expect, test } from '@playwright/test';
import { runEcdsaEnabledThreeRouteRegistrationCeremony } from '../../packages/sdk-web/src/SeamsWeb/operations/registration/registration';
import { buildFixtureRespondEd25519DeferredWork } from '../helpers/ed25519YaoAdmissionFixtures';
import { initialEcdsaCapabilityActivationFixture } from './helpers/initialEcdsaCapabilityActivation.fixtures';

/**
 * Refactor 94C. The three-route ceremony's ordering contract.
 *
 * The whole point of deferring NEAR is that registration stops waiting on it.
 * That guarantee lives in the ceremony's ordering — deferred work is handed to
 * the caller as soon as respond returns it, before activate runs, and is never
 * awaited.
 *
 * The mixed arm's admission records come from the shared factory, which builds
 * them through the production parsers — hand-written literals were rejected
 * three times over for shapes that had drifted.
 */

const RELAYER = 'https://relay.example';

/** Records the order routes are called so ordering can be asserted directly. */
function stubbedRoutes(responses: Record<string, unknown>) {
  const calls: string[] = [];
  const original = globalThis.fetch;
  globalThis.fetch = (async (input: RequestInfo | URL) => {
    const url = String(typeof input === 'string' ? input : ((input as Request).url ?? input));
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
function stubSigningEngine(
  activation: Awaited<ReturnType<typeof initialEcdsaCapabilityActivationFixture>>,
) {
  return {
    createRouterAbEcdsaRegistrationCeremony: async () => ({
      registrationRequest: {},
      registrationRequestDigestB64u: FIXTURE_DIGEST32_B64U,
    }),
    verifyRouterAbEcdsaRegistrationClientProofs: async () => ({
      publicFacts: activation.clientActivation,
      clientBootstrap: {},
    }),
    persistInitialCanonicalEcdsaActivation: async () => ({
      ok: true,
      journalId: activation.input.journalId,
    }),
    finalizeRouterAbEcdsaRegistrationActivation: async () => ({
      roleLocalMaterial: {},
      publicFacts: {},
      publicCapability: { activation_epoch: 1 },
    }),
    closeRouterAbEcdsaRegistrationCeremony: async () => undefined,
  };
}

async function ceremonyArgs(overrides: Record<string, unknown> = {}) {
  const activation = await initialEcdsaCapabilityActivationFixture();
  return {
    context: { signingEngine: stubSigningEngine(activation) },
    relayerUrl: RELAYER,
    registrationCeremonyId: 'wrc_test',
    signedSetup: 'signed-setup',
    signerPlan: 'near_ed25519_and_evm_family_ecdsa',
    ecdsaPrepare: {
      kind: 'evm_family_ecdsa_keygen',
      chainTargets: [{ kind: 'evm', namespace: 'eip155', chainId: 8453 }],
      prepare: {
        evmFamilySigningKeySlotId: activation.input.evmFamilySigningKeySlotId,
        ecdsaThresholdKeyId: activation.input.ecdsaThresholdKeyId,
        signingRootId: activation.input.signingRootId,
        signingRootVersion: activation.input.signingRootVersion,
        relayerKeyId: activation.input.relayerKeyId,
        participantIds: activation.input.participantIds,
      },
      strictRegistration: {},
    },
    materialAuthority: activation.input.authority,
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
      bundles: { signerA: FIXTURE_BUNDLE, signerB: FIXTURE_BUNDLE },
    },
  },
};

const MIXED_RESPOND = {
  ok: true,
  registrationCeremonyId: 'wrc_test',
  kind: 'near_ed25519_and_evm_family_ecdsa',
  ecdsa: FORWARDED_ECDSA,
  ed25519: buildFixtureRespondEd25519DeferredWork({ lifecycleId: 'wrc_test' }),
};

test('a mixed plan hands off deferred NEAR work before activate is called', async () => {
  /* If the handoff happened after activate, Yao would be serialized behind the
     rest of registration — the exact coupling this refactor removes. */
  const routes = stubbedRoutes({ respond: MIXED_RESPOND, activate: { ok: false } });
  const callsAtHandoff: string[] = [];
  try {
    await runEcdsaEnabledThreeRouteRegistrationCeremony(
      await ceremonyArgs({
        onDeferredNearWork: () => callsAtHandoff.push(...routes.calls),
      }),
    ).catch(() => undefined);
  } finally {
    routes.restore();
  }
  /* Respond had returned; activate had not yet been called. */
  expect(callsAtHandoff).toEqual(['respond']);
  expect(routes.calls).toContain('activate');
});

test('the ceremony never awaits the deferred NEAR work it hands off', async () => {
  /* The callback receives a handle, not a promise the ceremony waits on: work
     that never completes must not stop activate from being called. */
  const routes = stubbedRoutes({ respond: MIXED_RESPOND, activate: { ok: false } });
  try {
    await runEcdsaEnabledThreeRouteRegistrationCeremony(
      await ceremonyArgs({
        onDeferredNearWork: () => {
          void new Promise<void>(() => {});
        },
      }),
    ).catch(() => undefined);
  } finally {
    routes.restore();
  }
  expect(routes.calls).toContain('activate');
});

test('a mixed plan carries the deferred work through to the caller', async () => {
  /* The handed-off work is what starts Yao, so it must arrive intact and
     marked deferred — never as something already in progress. */
  const routes = stubbedRoutes({ respond: MIXED_RESPOND, activate: { ok: false } });
  let handed: unknown = null;
  try {
    await runEcdsaEnabledThreeRouteRegistrationCeremony(
      await ceremonyArgs({ onDeferredNearWork: (work: unknown) => (handed = work) }),
    ).catch(() => undefined);
  } finally {
    routes.restore();
  }
  expect(handed).toMatchObject({ status: 'deferred' });
});

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
    await runEcdsaEnabledThreeRouteRegistrationCeremony(
      await ceremonyArgs({ onDeferredNearWork: () => (handoffs += 1) }),
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
    await runEcdsaEnabledThreeRouteRegistrationCeremony(await ceremonyArgs()).catch(
      () => undefined,
    );
  } finally {
    routes.restore();
  }
  expect(routes.calls.filter((c) => c === 'respond')).toHaveLength(1);
  expect(routes.calls.filter((c) => c === 'other')).toHaveLength(0);
});

test('the ceremony consumes the collected authority and never asks for another', async () => {
  /* Exactly one passkey prompt: the proof is collected once against setup's
     challenge and passed in. If a later change moved collection inside the
     ceremony — to re-prompt on a retry, say — the user would see a second
     Touch ID, so any authority-collecting hook reached from here fails. */
  const routes = stubbedRoutes({ respond: MIXED_RESPOND, activate: { ok: false } });
  const args = await ceremonyArgs();
  const engine = args.context.signingEngine as Record<string, unknown>;
  let authorityRequests = 0;
  for (const hook of [
    'collectPasskeyRegistrationAuthority',
    'createPasskeyCredential',
    'signRegistrationChallenge',
  ]) {
    engine[hook] = async () => {
      authorityRequests += 1;
      return {};
    };
  }
  try {
    await runEcdsaEnabledThreeRouteRegistrationCeremony(
      { ...args, context: { signingEngine: engine } } as never,
    ).catch(() => undefined);
  } finally {
    routes.restore();
  }
  expect(authorityRequests).toBe(0);
  /* And the one proof it was given rode exactly one respond call. */
  expect(routes.calls.filter((c) => c === 'respond')).toHaveLength(1);
});
