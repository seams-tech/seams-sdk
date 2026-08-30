import { expect, test } from '@playwright/test';
import { runEcdsaEnabledThreeRouteRegistrationCeremony } from '../../packages/wallet/src/SeamsWeb/operations/registration/registration';
import { buildPendingRegistrationCommit } from '../../packages/wallet/src/SeamsWeb/operations/registration/registrationTerminalCommit';
import {
  parsePendingWalletRegistrationCommitStorageRow,
  toPendingWalletRegistrationCommitStorageRow,
  type PendingWalletRegistrationCommitV1,
} from '../../packages/wallet/src/core/indexedDB/pendingWalletRegistrationCommit';
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

type ThreeRouteCeremonyArgs = Parameters<typeof runEcdsaEnabledThreeRouteRegistrationCeremony>[0];
type PendingCommitInput = Parameters<ThreeRouteCeremonyArgs['persistPendingCommit']>[0];

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
      bootstrapOwner: 'wallet_custody',
      applicationBindingDigestB64u: activation.clientActivation.contextBinding32B64u,
      registrationRequestDigestB64u: activation.clientActivation.registrationRequestDigestB64u,
      proofTranscriptDigestB64u: activation.clientActivation.proofTranscriptDigestB64u,
    }),
    establishWalletCustodyEvmFamilyKeySet: async (args: {
      confirmRecoveryCodesBackedUp: (codes: readonly string[]) => Promise<void>;
      runRelayerRound: (bootstrap: unknown) => Promise<string>;
    }) => {
      await args.confirmRecoveryCodesBackedUp(
        Array.from({ length: 10 }, (_, index) => `code-${index}`),
      );
      return await args.runRelayerRound({
        contextBinding32B64u: activation.clientActivation.contextBinding32B64u,
        clientSharePublicKey33B64u:
          activation.clientActivation.derivationClientSharePublicKey33B64u,
        clientShareRetryCounter: activation.clientActivation.clientShareRetryCounter,
        preActivationCommitPayload: {
          walletId: 'alice.testnet',
          keySet: 'evm_family_ecdsa_v1',
          keyManifestDigestB64u: FIXTURE_DIGEST32_B64U,
          // serde-wasm-bindgen emits undefined-valued properties for every
          // optional Rust field; the pending-commit boundary must canonicalize
          // those away before its strict parser runs.
          establishedCustody: undefined,
          recoveryReplacementEnvelope: undefined,
          registeredPublicKeyB64u: undefined,
          ed25519LocalMaterialB64u: undefined,
          ed25519LocalMaterialNonceB64u: undefined,
          ed25519ApplicationBindingDigestB64u: undefined,
          clientRootPublicKey33B64u: undefined,
          ecdsaReadyStateBlobB64u: undefined,
          ecdsaPublicFacts: undefined,
        },
      });
    },
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
    authority: {
      kind: 'passkey',
      webauthnRegistration: {},
      walletCustodyFactorJson: '{}',
      walletCustodyFactorSecret: new ArrayBuffer(32),
    },
    idempotencyKey: 'idem-1',
    resolveActivateEmailOtp: async () => ({ enrollment: null, walletCustodyFactorJson: null }),
    registrationTiming: null,
    confirmRecoveryCodesBackedUp: async () => undefined,
    persistPendingCommit: async () => undefined,
    startDeferredNearCustody: async () => ({}),
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

test('a mixed plan starts the NEAR custody join before activate is called', async () => {
  const routes = stubbedRoutes({ respond: MIXED_RESPOND, activate: { ok: false } });
  const callsAtStart: string[] = [];
  let pendingCommitPersistedBeforeActivate = false;
  let persistedPending: PendingWalletRegistrationCommitV1 | null = null;
  try {
    await runEcdsaEnabledThreeRouteRegistrationCeremony(
      await ceremonyArgs({
        persistPendingCommit: async (input: PendingCommitInput) => {
          expect(routes.calls).toEqual(['respond']);
          const pending = buildPendingRegistrationCommit({
            operation: 'registration_activate',
            registrationCeremonyId: 'wrc_test',
            idempotencyKey: 'idem-1',
            walletId: String(input.localMaterial.custodyCommit.walletId),
            walletAuthMethodId: 'wallet-auth-method:pending',
            signedSetup: 'signed-setup',
            auth: {
              kind: 'passkey',
              rpId: 'wallet.example.test',
              credentialIdB64u: 'new-passkey-credential',
              transports: ['internal'],
            },
            localMaterial: input.localMaterial,
            createdAtMs: 1,
            updatedAtMs: 1,
          });
          const storageRow = toPendingWalletRegistrationCommitStorageRow(pending);
          persistedPending =
            parsePendingWalletRegistrationCommitStorageRow(storageRow)?.record ?? null;
          pendingCommitPersistedBeforeActivate = true;
        },
        startDeferredNearCustody: () => {
          callsAtStart.push(...routes.calls);
          return Promise.resolve({});
        },
      }),
    ).catch(() => undefined);
  } finally {
    routes.restore();
  }
  expect(callsAtStart).toEqual(['respond']);
  expect(pendingCommitPersistedBeforeActivate).toBe(true);
  expect(persistedPending?.localMaterial).toEqual({
    keyFamilies: ['ecdsa_secp256k1'],
    custodyCommit: {
      walletId: 'alice.testnet',
      keySet: 'evm_family_ecdsa_v1',
      keyManifestDigestB64u: FIXTURE_DIGEST32_B64U,
    },
    ecdsa: { activationJournalId: 'initial-ecdsa-registration-ceremony' },
  });
  expect(routes.calls).toContain('activate');
});

test('the ceremony never awaits the deferred NEAR custody join', async () => {
  const routes = stubbedRoutes({ respond: MIXED_RESPOND, activate: { ok: false } });
  try {
    await runEcdsaEnabledThreeRouteRegistrationCeremony(
      await ceremonyArgs({
        startDeferredNearCustody: () => new Promise(() => {}),
      }),
    ).catch(() => undefined);
  } finally {
    routes.restore();
  }
  expect(routes.calls).toContain('activate');
});

test('a mixed plan starts NEAR with its deferred admission and established envelope', async () => {
  const routes = stubbedRoutes({ respond: MIXED_RESPOND, activate: { ok: false } });
  let started: unknown = null;
  try {
    await runEcdsaEnabledThreeRouteRegistrationCeremony(
      await ceremonyArgs({
        startDeferredNearCustody: (input: unknown) => {
          started = input;
          return Promise.resolve({});
        },
      }),
    ).catch(() => undefined);
  } finally {
    routes.restore();
  }
  expect(started).toMatchObject({
    deferredNear: { status: 'deferred' },
    establishedEvmCustodyCommit: { keySet: 'evm_family_ecdsa_v1' },
  });
});

test('an ECDSA-only plan starts no deferred NEAR custody work', async () => {
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
      await ceremonyArgs({
        startDeferredNearCustody: () => {
          handoffs += 1;
          return Promise.resolve({});
        },
      }),
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
    await runEcdsaEnabledThreeRouteRegistrationCeremony({
      ...args,
      context: { signingEngine: engine },
    } as never).catch(() => undefined);
  } finally {
    routes.restore();
  }
  expect(authorityRequests).toBe(0);
  /* And the one proof it was given rode exactly one respond call. */
  expect(routes.calls.filter((c) => c === 'respond')).toHaveLength(1);
});
