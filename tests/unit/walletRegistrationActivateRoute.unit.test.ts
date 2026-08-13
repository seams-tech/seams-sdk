import { expect, test } from '@playwright/test';
import { base64UrlEncode } from '../../packages/shared-ts/src/utils/encoders';
import { secp256k1PrivateKey32ToPublicKey33 } from '../../packages/sdk-server-ts/src/core/ThresholdService/evmCryptoWasm';
import { createCloudflareD1RouterApiAuthService } from '../../packages/sdk-server-ts/src/router/cloudflare/d1/auth/d1RouterApiAuthService';
import { parseWebAuthnRpId } from '../../packages/shared-ts/src/utils/domainIds';
import { implicitNearAccountProvisioning } from '../../packages/shared-ts/src/utils/registrationIntent';
import { cleanupTemporaryD1Database, createTemporaryD1Database } from '../helpers/sqliteD1';
import {
  buildFixtureRouterAbEcdsaStrictRegistrationRequest,
  createRouterAbSigningRuntimesForUnitTests,
  fixtureRouterAbEcdsaActivationFacts,
  SuccessfulFixtureRouterAbEcdsaStrictRegistrationPort,
} from '../helpers/routerAbSigningRuntimeTestUtils';
import { createActivatedFinalizeYaoRuntimeFixture } from './helpers/d1WalletRegistrationFinalizeConvergence.fixtures';
import { CloudflareD1WalletCustodyCommitStore } from '../../packages/sdk-server-ts/src/router/cloudflare/d1/passkeyCustody/d1WalletCustodyCommitStore';
import { buildWalletCustodyCommitPayloadFixture } from './helpers/passkeyCustodyEnvelope.fixtures';
import {
  applySignerMigrations,
  createWebAuthnRegistrationCredential,
  RecordingDurableObjectNamespace,
  requireParsedDomainId,
} from './helpers/cloudflareD1RouterApiAuthService.fixtures';

/**
 * Refactor 94C. `/wallets/register/activate` folds activation and
 * finalization into one irreversible step behind a single Gateway operation
 * row.
 *
 * Previously three records guarded this one commit: the activation branch CAS,
 * finalize's side-effect journal, and finalize's separate replay cache. The
 * operation row is now the only one — its claim is the activation claim and
 * its completion record holds the exact terminal bytes. These tests pin the
 * properties that made the other two records seem necessary: identical retry
 * returns stored bytes without repeating custody, and a conflicting retry
 * fails before any custody effect.
 */

const SCOPE = {
  namespace: 'registration-activate',
  orgId: 'org-activate',
  projectId: 'project-activate',
  envId: 'env-activate',
};

let fakeSignerInstances = 0;

function fakeGatewaySigner() {
  const issued = new Map<string, Record<string, unknown>>();
  const instance = (fakeSignerInstances += 1);
  let counter = 0;
  return {
    signJwt: async (sub: string, extra?: Record<string, unknown>) => {
      counter += 1;
      const header = base64UrlEncode(
        new TextEncoder().encode(JSON.stringify({ alg: 'none', typ: 'JWT' })),
      );
      const payload = base64UrlEncode(
        new TextEncoder().encode(
          JSON.stringify({
            sub,
            exp: Math.floor(Date.now() / 1000) + 900,
            ...(extra || {}),
          }),
        ),
      );
      const token = `${header}.${payload}.test-signature-${instance}-${counter}`;
      issued.set(token, { sub, ...(extra || {}) });
      return token;
    },
    verifyJwt: async (token: string) => {
      const payload = issued.get(token);
      return payload ? ({ valid: true, payload } as const) : ({ valid: false } as const);
    },
  };
}

/** Counts custody-affecting Router calls so a replay that skips them is visible. */
class CountingStrictRegistrationPort extends SuccessfulFixtureRouterAbEcdsaStrictRegistrationPort {
  registerCalls = 0;
  activateCalls = 0;
  override async register(
    ...args: Parameters<SuccessfulFixtureRouterAbEcdsaStrictRegistrationPort['register']>
  ): ReturnType<SuccessfulFixtureRouterAbEcdsaStrictRegistrationPort['register']> {
    this.registerCalls += 1;
    return await super.register(...args);
  }
  override async activate(
    ...args: Parameters<SuccessfulFixtureRouterAbEcdsaStrictRegistrationPort['activate']>
  ): ReturnType<SuccessfulFixtureRouterAbEcdsaStrictRegistrationPort['activate']> {
    this.activateCalls += 1;
    return await super.activate(...args);
  }
}

/** Drives a ceremony through setup and respond, ready to activate. */
async function respondedCeremony(database: unknown, strictRegistration: unknown) {
  const routerAbSigningRuntimes = createRouterAbSigningRuntimesForUnitTests({
    config: { ROUTER_AB_NORMAL_SIGNING_WORKER_ID: 'signing-worker-activate' },
  });
  const thresholdStore = new RecordingDurableObjectNamespace();
  const service = createCloudflareD1RouterApiAuthService({
    database: database as never,
    ...SCOPE,
    routerAbSigningRuntimes: routerAbSigningRuntimes.runtimes,
    ecdsaStrictRegistration: strictRegistration,
    thresholdStore: {
      kind: 'cloudflare-do',
      namespace: thresholdStore,
      THRESHOLD_PREFIX: 'registration-activate-test',
      ROUTER_AB_NORMAL_SIGNING_WORKER_ID: 'signing-worker-activate',
    },
  } as never);
  const signer = fakeGatewaySigner();
  const rpId = requireParsedDomainId(parseWebAuthnRpId('example.com'));
  const setup = await service.walletRegistration.setupWalletRegistration({
    request: {
      signerSelection: {
        kind: 'signer_set',
        signers: [
          {
            kind: 'evm_family_ecdsa',
            participantIds: [1, 2],
            chainTargets: [{ kind: 'evm', namespace: 'eip155', chainId: 8453 }],
          },
        ],
      },
      authMethod: { kind: 'passkey', rpId },
    },
    orgId: SCOPE.orgId,
    expectedOrigin: 'https://app.example.com',
    signer,
    signingRootId: `${SCOPE.projectId}:${SCOPE.envId}`,
    signingRootVersion: 'root-activate-v1',
  } as never);
  if (!setup.ok) throw new Error(`setup: ${setup.code}: ${setup.message}`);

  const responded = await service.walletRegistration.respondWalletRegistration({
    registrationCeremonyId: setup.registrationCeremonyId,
    signedSetup: setup.signedSetup,
    authority: {
      kind: 'passkey',
      webauthnRegistration: await createWebAuthnRegistrationCredential({
        rpId,
        challengeB64u: setup.registrationIntentDigestB64u,
        origin: 'https://app.example.com',
      }),
    },
    ecdsa: {
      kind: 'router_ab_ecdsa_registration_v1',
      strictRegistration: buildFixtureRouterAbEcdsaStrictRegistrationRequest(
        setup.ecdsa.strictRegistration,
      ),
    },
    verifier: signer,
    minter: signer,
  } as never);
  if (!responded.ok) throw new Error(`respond: ${responded.code}: ${responded.message}`);

  const activateRequest = {
    registrationCeremonyId: setup.registrationCeremonyId,
    signedSetup: setup.signedSetup,
    idempotencyKey: 'activate-key-1',
    planKind: 'evm_family_ecdsa',
    session: signer,
    ecdsa: {
      activationCorrelationId: setup.registrationCeremonyId,
      activationRequestDigestB64u: base64UrlEncode(new Uint8Array(32)),
      clientActivation: fixtureRouterAbEcdsaActivationFacts(),
    },
    verifier: signer,
    minter: signer,
  };
  return { service, signer, setup, activateRequest, thresholdStore };
}

test('a conflicting activate retry is refused before any custody effect', async () => {
  const { database, tempDir } = createTemporaryD1Database();
  try {
    await applySignerMigrations(database);
    const strictRegistration = new CountingStrictRegistrationPort();
    const { service, activateRequest } = await respondedCeremony(database, strictRegistration);

    const first = await service.walletRegistration.activateWalletRegistration(
      activateRequest as never,
    );
    /* The conflict case is only meaningful against a landed first activation. */
    if (!first.ok) throw new Error(`first activate: ${first.code}: ${first.message}`);
    const activateCallsAfterFirst = strictRegistration.activateCalls;

    /* Same idempotency key, different request bytes. The operation row must
       refuse this on fingerprint before invoking custody again — that is the
       whole point of binding the key to the digest. */
    const conflicting = await service.walletRegistration.activateWalletRegistration({
      ...activateRequest,
      /* Same key, different request bytes. */
      ecdsa: {
        clientActivation: {
          ...(activateRequest.ecdsa.clientActivation as Record<string, unknown>),
          clientShareRetryCounter: 7,
        },
      },
    } as never);

    expect(conflicting).toMatchObject({ ok: false, code: 'idempotency_conflict' });
    expect(strictRegistration.activateCalls).toBe(activateCallsAfterFirst);
  } finally {
    cleanupTemporaryD1Database(tempDir);
  }
});

test('an identical activate retry returns the stored terminal bytes without repeating custody', async () => {
  const { database, tempDir } = createTemporaryD1Database();
  try {
    await applySignerMigrations(database);
    const strictRegistration = new CountingStrictRegistrationPort();
    const { service, activateRequest, thresholdStore } = await respondedCeremony(
      database,
      strictRegistration,
    );

    const first = await service.walletRegistration.activateWalletRegistration(
      activateRequest as never,
    );
    if (!first.ok) throw new Error(`first activate: ${first.code}: ${first.message}`);
    expect(first.appSessionJwt).toEqual(expect.any(String));
    const custodyCallsAfterFirst = strictRegistration.activateCalls;

    const replayed = await service.walletRegistration.activateWalletRegistration(
      activateRequest as never,
    );

    /* The replay is the stored completion record itself, not a
       reconstruction: same wallet, same keys, same authority. Compared by
       value rather than by serialized string — the record round-trips through
       the store's JSON encoding, so property order is the encoder's business
       and pinning it here would assert an implementation detail. */
    expect(replayed).toEqual(first);
    expect(replayed.ok && replayed.appSessionJwt).toBe(first.appSessionJwt);
    /* And no repeated custody effect. */
    expect(strictRegistration.activateCalls).toBe(custodyCallsAfterFirst);
    /* Both legs merged: the commit half's wallet keys plus the activation
       half's receipt and bootstrap. Returning only the commit half would
       leave the client unable to bring the wallet online. */
    expect(first.ecdsa.walletKeys.length).toBeGreaterThan(0);
    expect(first.ecdsa.activation).toBeTruthy();
    expect(first.ecdsa.bootstrap).toBeTruthy();
    expect(replayed.ok && replayed.ecdsa.activation).toBeTruthy();
    expect(thresholdStore.objectNames).toEqual([]);
    expect(replayed.ok && replayed.ecdsa.bootstrap).toBeTruthy();
  } finally {
    cleanupTemporaryD1Database(tempDir);
  }
});

test('activate refuses a ceremony whose authority proof is not yet verified', async () => {
  const { database, tempDir } = createTemporaryD1Database();
  try {
    await applySignerMigrations(database);
    const strictRegistration = new CountingStrictRegistrationPort();
    const routerAbSigningRuntimes = createRouterAbSigningRuntimesForUnitTests({
      config: { ROUTER_AB_NORMAL_SIGNING_WORKER_ID: 'signing-worker-activate' },
    });
    const service = createCloudflareD1RouterApiAuthService({
      database: database as never,
      ...SCOPE,
      routerAbSigningRuntimes: routerAbSigningRuntimes.runtimes,
      ecdsaStrictRegistration: strictRegistration,
      thresholdStore: {
        kind: 'cloudflare-do',
        namespace: new RecordingDurableObjectNamespace(),
        THRESHOLD_PREFIX: 'registration-activate-unverified',
        ROUTER_AB_NORMAL_SIGNING_WORKER_ID: 'signing-worker-activate',
      },
    } as never);
    const signer = fakeGatewaySigner();
    const rpId = requireParsedDomainId(parseWebAuthnRpId('example.com'));
    /* Setup only — respond never runs, so the ceremony is awaiting_proof. */
    const setup = await service.walletRegistration.setupWalletRegistration({
      request: {
        signerSelection: {
          kind: 'signer_set',
          signers: [
            {
              kind: 'evm_family_ecdsa',
              participantIds: [1, 2],
              chainTargets: [{ kind: 'evm', namespace: 'eip155', chainId: 8453 }],
            },
          ],
        },
        authMethod: { kind: 'passkey', rpId },
      },
      orgId: SCOPE.orgId,
      expectedOrigin: 'https://app.example.com',
      signer,
      signingRootId: `${SCOPE.projectId}:${SCOPE.envId}`,
      signingRootVersion: 'root-activate-v1',
    } as never);
    if (!setup.ok) throw new Error(`${setup.code}: ${setup.message}`);

    const activated = await service.walletRegistration.activateWalletRegistration({
      registrationCeremonyId: setup.registrationCeremonyId,
      signedSetup: setup.signedSetup,
      idempotencyKey: 'activate-unverified',
      ecdsa: { clientActivation: fixtureRouterAbEcdsaActivationFacts() },
      verifier: signer,
      minter: signer,
    } as never);

    expect(activated).toMatchObject({
      ok: false,
      code: 'invalid_state',
      message: 'registration ceremony has not verified its authority proof',
    });
    /* Refused before custody. */
    expect(strictRegistration.activateCalls).toBe(0);
  } finally {
    cleanupTemporaryD1Database(tempDir);
  }
});

test('activate refuses a signedSetup that does not belong to the ceremony', async () => {
  const { database, tempDir } = createTemporaryD1Database();
  try {
    await applySignerMigrations(database);
    const strictRegistration = new CountingStrictRegistrationPort();
    const first = await respondedCeremony(database, strictRegistration);
    const other = await respondedCeremony(database, strictRegistration);
    const custodyCallsBefore = strictRegistration.activateCalls;

    const crossed = await first.service.walletRegistration.activateWalletRegistration({
      ...first.activateRequest,
      signedSetup: other.setup.signedSetup,
    } as never);

    expect(crossed).toMatchObject({ ok: false, code: 'invalid_grant' });
    expect(strictRegistration.activateCalls).toBe(custodyCallsBefore);
  } finally {
    cleanupTemporaryD1Database(tempDir);
  }
});

/**
 * Refactor 94C. Ed25519-only registration on the three-route system.
 *
 * Its defining property is that it stays asynchronous: Yao is the wallet's
 * only signer, and that is deliberately not a reason to block. The wallet is
 * created in `near_pending` with no signer at all, and becomes signable when
 * the deferred computation completes.
 */

/** The commit validates a real curve point, not merely 33 bytes. */
async function compressedSecp256k1PubkeyB64u(): Promise<string> {
  const privateKey32 = new Uint8Array(32);
  privateKey32[31] = 7;
  return base64UrlEncode(await secp256k1PrivateKey32ToPublicKey33(privateKey32));
}

const ED_SCOPE = {
  namespace: 'registration-ed25519',
  orgId: 'org-ed25519',
  projectId: 'project-ed25519',
  envId: 'env-ed25519',
};

const ED25519_ONLY_PLAN = {
  kind: 'signer_set' as const,
  signers: [
    {
      kind: 'near_ed25519' as const,
      accountProvisioning: implicitNearAccountProvisioning(),
      signerSlot: 1,
      participantIds: [1, 2],
      derivationVersion: 1,
    },
  ],
};

async function ed25519OnlyCeremony(database: unknown) {
  const routerAbSigningRuntimes = createRouterAbSigningRuntimesForUnitTests({
    config: { ROUTER_AB_NORMAL_SIGNING_WORKER_ID: 'signing-worker-ed25519' },
  });
  const service = createCloudflareD1RouterApiAuthService({
    database: database as never,
    ...ED_SCOPE,
    routerAbSigningRuntimes: routerAbSigningRuntimes.runtimes,
    ecdsaStrictRegistration: new CountingStrictRegistrationPort(),
    thresholdStore: {
      kind: 'cloudflare-do',
      namespace: new RecordingDurableObjectNamespace(),
      THRESHOLD_PREFIX: 'registration-ed25519-test',
      ROUTER_AB_NORMAL_SIGNING_WORKER_ID: 'signing-worker-ed25519',
    },
  } as never);
  const signer = fakeGatewaySigner();
  const rpId = requireParsedDomainId(parseWebAuthnRpId('example.com'));
  const setup = await service.walletRegistration.setupWalletRegistration({
    request: { signerSelection: ED25519_ONLY_PLAN, authMethod: { kind: 'passkey', rpId } },
    orgId: ED_SCOPE.orgId,
    expectedOrigin: 'https://app.example.com',
    signer,
    signingRootId: `${ED_SCOPE.projectId}:${ED_SCOPE.envId}`,
    signingRootVersion: 'root-ed25519-v1',
  } as never);
  return { service, signer, setup, rpId };
}

test('Ed25519-only setup skips ECDSA preparation entirely', async () => {
  const { database, tempDir } = createTemporaryD1Database();
  try {
    await applySignerMigrations(database);
    const { setup } = await ed25519OnlyCeremony(database);
    if (!setup.ok) throw new Error(`${setup.code}: ${setup.message}`);

    expect(setup.kind).toBe('near_ed25519');
    /* Not an empty preparation — no preparation at all. */
    expect('ecdsa' in setup).toBe(false);
    /* The challenge still exists: setup's job is the ceremony and the proof
       challenge, which this plan needs exactly as much as any other. */
    expect(setup.registrationIntentDigestB64u).toBeTruthy();
  } finally {
    cleanupTemporaryD1Database(tempDir);
  }
});

/**
 * A Yao runtime that admits whatever ceremony arrives.
 *
 * The convergence fixture mints against its own fixed ids, so it can only
 * satisfy its own ceremony. The receipt binding mirrors the admission request
 * scope, so building the fixture lazily from the first incoming request lets
 * one runtime serve a freshly generated ceremony — which is what makes a real
 * Ed25519-only path testable rather than only its error branches.
 */
function derivingYaoRuntime(capture?: {
  registrationBearerToken: string | null;
  /** The session the deferred leg must present to claim the Yao result. */
  activationSessionId?: readonly number[] | null;
}) {
  let delegate: Awaited<ReturnType<typeof createActivatedFinalizeYaoRuntimeFixture>> | null = null;
  const runtime = {
    kind: 'router_ab_ed25519_yao_product_registration_runtime_v1' as const,
    signingWorkerId: 'signing-worker-ed25519',
    async bindAndAdmitVerifiedRegistration(input: {
      admissionRequest: never;
      registrationIntentGrant: unknown;
    }) {
      if (capture) capture.registrationBearerToken = String(input.registrationIntentGrant);
      /* The fixture admits and executes during construction, so its receipt
         is already the admitted one — re-admitting would collide with itself. */
      delegate = await createActivatedFinalizeYaoRuntimeFixture({
        admissionRequest: input.admissionRequest,
      });
      if (capture) capture.activationSessionId = delegate.activationResult.binding.session_id;
      return { ok: true as const, value: delegate.admissionReceipt };
    },
    async consumeActivated(request: never) {
      if (!delegate) throw new Error('consumeActivated before admission');
      return await delegate.runtime.consumeActivated(request);
    },
  };
  return new Proxy(runtime, {
    get(target, prop, receiver) {
      if (prop in target) return Reflect.get(target, prop, receiver);
      /* Everything else (capability install/resolve, session minting) is the
         delegate's once it exists. */
      const current = delegate?.runtime as Record<string | symbol, unknown> | undefined;
      const value = current?.[prop];
      return typeof value === 'function' ? value.bind(current) : value;
    },
  });
}

test('Ed25519-only registers end to end: pending wallet now, signer when Yao resolves', async () => {
  const { database, tempDir } = createTemporaryD1Database();
  try {
    await applySignerMigrations(database);
    const routerAbSigningRuntimes = createRouterAbSigningRuntimesForUnitTests({
      config: { ROUTER_AB_NORMAL_SIGNING_WORKER_ID: 'signing-worker-ed25519' },
    });
    const signer = fakeGatewaySigner();
    const yaoCredential = { registrationBearerToken: null as string | null };
    const service = createCloudflareD1RouterApiAuthService({
      database: database as never,
      ...ED_SCOPE,
      routerAbSigningRuntimes: routerAbSigningRuntimes.runtimes,
      ed25519YaoProductRegistration: derivingYaoRuntime(yaoCredential),
      ecdsaStrictRegistration: new CountingStrictRegistrationPort(),
      thresholdStore: {
        kind: 'cloudflare-do',
        namespace: new RecordingDurableObjectNamespace(),
        THRESHOLD_PREFIX: 'registration-ed25519-e2e',
        ROUTER_AB_NORMAL_SIGNING_WORKER_ID: 'signing-worker-ed25519',
      },
    } as never);
    const rpId = requireParsedDomainId(parseWebAuthnRpId('example.com'));

    const setup = await service.walletRegistration.setupWalletRegistration({
      request: { signerSelection: ED25519_ONLY_PLAN, authMethod: { kind: 'passkey', rpId } },
      orgId: ED_SCOPE.orgId,
      expectedOrigin: 'https://app.example.com',
      signer,
      signingRootId: `${ED_SCOPE.projectId}:${ED_SCOPE.envId}`,
      signingRootVersion: 'root-ed25519-v1',
    } as never);
    if (!setup.ok) throw new Error(`setup: ${setup.code}: ${setup.message}`);
    expect(setup.kind).toBe('near_ed25519');
    expect('ecdsa' in setup).toBe(false);

    const responded = await service.walletRegistration.respondWalletRegistration({
      registrationCeremonyId: setup.registrationCeremonyId,
      signedSetup: setup.signedSetup,
      planKind: 'near_ed25519',
      authority: {
        kind: 'passkey',
        webauthnRegistration: await createWebAuthnRegistrationCredential({
          rpId,
          challengeB64u: setup.registrationIntentDigestB64u,
          origin: 'https://app.example.com',
        }),
      },
      verifier: signer,
      minter: signer,
    } as never);
    if (!responded.ok) throw new Error(`respond: ${responded.code}: ${responded.message}`);
    /* Execute uses signedSetup as its Bearer credential, so admission must be
       bound to those exact bytes rather than the ceremony id it replaced. */
    expect(yaoCredential.registrationBearerToken).toBe(setup.signedSetup);
    /* Deferred, not blocking — the client starts Yao and moves on. */
    expect(responded.ed25519).toMatchObject({ status: 'deferred' });
    expect('ecdsa' in responded).toBe(false);

    const activateRequest = {
      registrationCeremonyId: setup.registrationCeremonyId,
      signedSetup: setup.signedSetup,
      idempotencyKey: 'ed25519-e2e-activate',
      planKind: 'near_ed25519',
      session: signer,
      verifier: signer,
      minter: signer,
    };
    /* Yao has not resolved. Activate must still return a wallet. */
    const activated = await service.walletRegistration.activateWalletRegistration(
      activateRequest as never,
    );
    if (!activated.ok) throw new Error(`activate: ${activated.code}: ${activated.message}`);
    expect(activated.nearProvisioning).toEqual({ status: 'near_pending' });
    expect('ecdsa' in activated).toBe(false);
    expect('resolvedAccount' in activated).toBe(false);

    /* Exact replay returns the same pending terminal. */
    const replayed = await service.walletRegistration.activateWalletRegistration(
      activateRequest as never,
    );
    expect(replayed).toEqual(activated);
  } finally {
    cleanupTemporaryD1Database(tempDir);
  }
});

test('Email OTP + Ed25519-only: enrollment persists with the pending wallet, before any signer', async () => {
  const { database, tempDir } = createTemporaryD1Database();
  try {
    await applySignerMigrations(database);
    const routerAbSigningRuntimes = createRouterAbSigningRuntimesForUnitTests({
      config: { ROUTER_AB_NORMAL_SIGNING_WORKER_ID: 'signing-worker-ed25519' },
    });
    const signer = fakeGatewaySigner();
    const service = createCloudflareD1RouterApiAuthService({
      database: database as never,
      ...ED_SCOPE,
      routerAbSigningRuntimes: routerAbSigningRuntimes.runtimes,
      ed25519YaoProductRegistration: derivingYaoRuntime(),
      ecdsaStrictRegistration: new CountingStrictRegistrationPort(),
      thresholdStore: {
        kind: 'cloudflare-do',
        namespace: new RecordingDurableObjectNamespace(),
        THRESHOLD_PREFIX: 'registration-ed25519-otp',
        ROUTER_AB_NORMAL_SIGNING_WORKER_ID: 'signing-worker-ed25519',
      },
      emailOtpDeliveryMode: 'dev_d1_outbox',
    } as never);

    const unlockPublicKeyB64u = await compressedSecp256k1PubkeyB64u();
    const email = 'ed25519-otp@example.test';
    const providerSubject = 'google:ed25519-otp-user';
    const appSessionVersion = 'app-session-v1';

    const setup = await service.walletRegistration.setupWalletRegistration({
      request: {
        signerSelection: ED25519_ONLY_PLAN,
        authMethod: {
          kind: 'email_otp',
          proofKind: 'otp_challenge',
          email,
          otpCode: 'intent-otp-placeholder',
          appSessionJwt: 'intent-session-placeholder',
        },
      },
      orgId: ED_SCOPE.orgId,
      expectedOrigin: 'https://app.example.com',
      signer,
      signingRootId: `${ED_SCOPE.projectId}:${ED_SCOPE.envId}`,
      signingRootVersion: 'root-ed25519-v1',
    } as never);
    if (!setup.ok) throw new Error(`setup: ${setup.code}: ${setup.message}`);
    expect(setup.kind).toBe('near_ed25519');

    /* The challenge binds the digest setup issued, exactly as the passkey
       flow binds it into the WebAuthn create. */
    const challenge = await service.emailOtp.createEmailOtpEnrollmentChallenge({
      userId: providerSubject,
      walletId: setup.walletId,
      orgId: ED_SCOPE.orgId,
      email,
      otpChannel: 'email_otp',
      sessionHash: setup.registrationIntentDigestB64u,
      appSessionVersion,
    });
    if (!challenge.ok) throw new Error(`challenge: ${challenge.message}`);
    const outbox = await service.emailOtp.readEmailOtpOutboxEntry({
      challengeId: challenge.challenge.challengeId,
      userId: providerSubject,
      walletId: setup.walletId,
    });
    if (!outbox.ok) throw new Error(`outbox: ${outbox.message}`);

    const responded = await service.walletRegistration.respondWalletRegistration({
      registrationCeremonyId: setup.registrationCeremonyId,
      signedSetup: setup.signedSetup,
      planKind: 'near_ed25519',
      authority: {
        kind: 'email_otp',
        emailOtpRegistrationProof: {
          version: 'email_otp_registration_proof_v1',
          proofKind: 'otp_challenge',
          providerSubject,
          email,
          challengeId: challenge.challenge.challengeId,
          otpCode: outbox.otpCode,
          otpChannel: 'email_otp',
          registrationIntentDigestB64u: setup.registrationIntentDigestB64u,
          appSessionVersion,
        },
      },
      verifier: signer,
      minter: signer,
    } as never);
    if (!responded.ok) throw new Error(`respond: ${responded.code}: ${responded.message}`);
    expect(responded.ed25519).toMatchObject({ status: 'deferred' });

    const activateRequest = {
      registrationCeremonyId: setup.registrationCeremonyId,
      signedSetup: setup.signedSetup,
      idempotencyKey: 'ed25519-otp-activate',
      planKind: 'near_ed25519',
      emailOtpEnrollment: {
        enrollmentSealKeyVersion: 'seal-v1',
        clientUnlockPublicKeyB64u: unlockPublicKeyB64u,
        unlockKeyVersion: 'unlock-v1',
      },
      session: signer,
      verifier: signer,
      minter: signer,
    };

    /* Yao is unresolved. The wallet must still be created, with its
       recovery-critical enrollment committed in the same transaction. */
    const activated = await service.walletRegistration.activateWalletRegistration(
      activateRequest as never,
    );
    if (!activated.ok) throw new Error(`activate: ${activated.code}: ${activated.message}`);
    expect(activated.nearProvisioning).toEqual({ status: 'near_pending' });
    expect('ecdsa' in activated).toBe(false);
    expect('resolvedAccount' in activated).toBe(false);

    /* Enrollment landed even though no signer exists yet. */
    const enrollmentRows = (await database
      .prepare(`SELECT COUNT(*) AS count FROM email_otp_wallet_enrollments WHERE wallet_id = ?1`)
      .bind(setup.walletId)
      .first()) as { count?: number } | null;
    expect(Number(enrollmentRows?.count || 0)).toBeGreaterThan(0);

    const signerRows = (await database
      .prepare(`SELECT COUNT(*) AS count FROM wallet_signers WHERE wallet_id = ?1`)
      .bind(setup.walletId)
      .first()) as { count?: number } | null;
    expect(Number(signerRows?.count || 0)).toBe(0);

    /* Exact pending replay. */
    const replayed = await service.walletRegistration.activateWalletRegistration(
      activateRequest as never,
    );
    expect(replayed).toEqual(activated);
  } finally {
    cleanupTemporaryD1Database(tempDir);
  }
});

/**
 * Refactor 100. The wallet custody commit rides the registration leg rather
 * than a route of its own: what may establish custody for a wallet is exactly
 * what may create that wallet, and a separate endpoint would be a second,
 * weaker way in.
 *
 * These pin where that commit actually happens, which is the thing easiest to
 * get wrong — an Ed25519-only wallet has no key set at activate, so wiring the
 * commit there alone would silently never fire for it.
 */

test('an activate carrying a custody payload commits it under the registered wallet', async () => {
  const { database, tempDir } = createTemporaryD1Database();
  try {
    await applySignerMigrations(database);
    const { service, setup, activateRequest } = await respondedCeremony(
      database,
      new CountingStrictRegistrationPort(),
    );

    const activated = await service.walletRegistration.activateWalletRegistration({
      ...activateRequest,
      walletCustodyCommit: buildWalletCustodyCommitPayloadFixture({ walletId: setup.walletId }),
    } as never);
    if (!activated.ok) throw new Error(`activate: ${activated.code}: ${activated.message}`);

    expect(activated.walletCustody).toEqual({ status: 'committed' });

    /* The response is not the evidence — the stored recovery set is. A wallet
       whose codes never landed is a wallet nobody can recover. */
    const custodyStore = new CloudflareD1WalletCustodyCommitStore({
      database: database as never,
      scope: SCOPE,
    });
    const recoverySet = await custodyStore.readRecoveryEnvelopeSet(setup.walletId as never);
    expect(recoverySet?.record.manifestKekWraps).toHaveLength(10);
  } finally {
    cleanupTemporaryD1Database(tempDir);
  }
});

test('a custody payload naming another wallet is refused without failing activation', async () => {
  const { database, tempDir } = createTemporaryD1Database();
  try {
    await applySignerMigrations(database);
    const { service, setup, activateRequest } = await respondedCeremony(
      database,
      new CountingStrictRegistrationPort(),
    );

    const activated = await service.walletRegistration.activateWalletRegistration({
      ...activateRequest,
      walletCustodyCommit: buildWalletCustodyCommitPayloadFixture({ walletId: 'mallory.testnet' }),
    } as never);

    /* Activation never fails because of custody: the wallet is already
       committed when the payload is admitted, and the seed exists only in the
       client's worker, so an error response would leave the client with a
       registered wallet and no instruction it can read. */
    if (!activated.ok) throw new Error(`activate: ${activated.code}: ${activated.message}`);
    expect(activated.walletCustody?.status).toBe('rejected');

    const custodyStore = new CloudflareD1WalletCustodyCommitStore({
      database: database as never,
      scope: SCOPE,
    });
    expect(await custodyStore.readRecoveryEnvelopeSet(setup.walletId as never)).toBeNull();
    expect(await custodyStore.readRecoveryEnvelopeSet('mallory.testnet' as never)).toBeNull();
  } finally {
    cleanupTemporaryD1Database(tempDir);
  }
});

test('an Ed25519-only wallet establishes custody on the deferred NEAR leg, not at activate', async () => {
  const { database, tempDir } = createTemporaryD1Database();
  try {
    await applySignerMigrations(database);
    const routerAbSigningRuntimes = createRouterAbSigningRuntimesForUnitTests({
      config: { ROUTER_AB_NORMAL_SIGNING_WORKER_ID: 'signing-worker-ed25519' },
    });
    const signer = fakeGatewaySigner();
    const yaoCapture = {
      registrationBearerToken: null as string | null,
      activationSessionId: null as readonly number[] | null,
    };
    const service = createCloudflareD1RouterApiAuthService({
      database: database as never,
      ...ED_SCOPE,
      routerAbSigningRuntimes: routerAbSigningRuntimes.runtimes,
      ed25519YaoProductRegistration: derivingYaoRuntime(yaoCapture),
      ecdsaStrictRegistration: new CountingStrictRegistrationPort(),
      thresholdStore: {
        kind: 'cloudflare-do',
        namespace: new RecordingDurableObjectNamespace(),
        THRESHOLD_PREFIX: 'registration-ed25519-custody',
        ROUTER_AB_NORMAL_SIGNING_WORKER_ID: 'signing-worker-ed25519',
      },
    } as never);
    const rpId = requireParsedDomainId(parseWebAuthnRpId('example.com'));

    const setup = await service.walletRegistration.setupWalletRegistration({
      request: { signerSelection: ED25519_ONLY_PLAN, authMethod: { kind: 'passkey', rpId } },
      orgId: ED_SCOPE.orgId,
      expectedOrigin: 'https://app.example.com',
      signer,
      signingRootId: `${ED_SCOPE.projectId}:${ED_SCOPE.envId}`,
      signingRootVersion: 'root-ed25519-v1',
    } as never);
    if (!setup.ok) throw new Error(`setup: ${setup.code}: ${setup.message}`);

    const responded = await service.walletRegistration.respondWalletRegistration({
      registrationCeremonyId: setup.registrationCeremonyId,
      signedSetup: setup.signedSetup,
      planKind: 'near_ed25519',
      authority: {
        kind: 'passkey',
        webauthnRegistration: await createWebAuthnRegistrationCredential({
          rpId,
          challengeB64u: setup.registrationIntentDigestB64u,
          origin: 'https://app.example.com',
        }),
      },
      verifier: signer,
      minter: signer,
    } as never);
    if (!responded.ok) throw new Error(`respond: ${responded.code}: ${responded.message}`);

    /* Activate returns `near_pending`: the Yao computation has not resolved, so
       this wallet has no key set to seal custody against yet. */
    const activated = await service.walletRegistration.activateWalletRegistration({
      registrationCeremonyId: setup.registrationCeremonyId,
      signedSetup: setup.signedSetup,
      idempotencyKey: 'ed25519-custody-activate',
      planKind: 'near_ed25519',
      session: signer,
      verifier: signer,
      minter: signer,
    } as never);
    if (!activated.ok) throw new Error(`activate: ${activated.code}: ${activated.message}`);
    expect(activated.nearProvisioning).toEqual({ status: 'near_pending' });
    expect(activated.walletCustody).toBeUndefined();

    const custodyStore = new CloudflareD1WalletCustodyCommitStore({
      database: database as never,
      scope: ED_SCOPE,
    });
    expect(await custodyStore.readRecoveryEnvelopeSet(setup.walletId as never)).toBeNull();

    /* The deferred leg. This is the first point at which an Ed25519-only
       wallet has a key set at all, so it is where its custody is established —
       a commit wired only into activate would never fire for this wallet. */
    const provisioned = await service.walletRegistration.completeWalletRegistrationNearProvisioning(
      {
        registrationCeremonyId: setup.registrationCeremonyId,
        signedSetup: setup.signedSetup,
        idempotencyKey: 'ed25519-custody-provisioning',
        ed25519: {
          activationReference: {
            lifecycle_id: setup.registrationCeremonyId,
            session_id: yaoCapture.activationSessionId,
          },
        },
        walletCustodyCommit: buildWalletCustodyCommitPayloadFixture({
          walletId: setup.walletId,
          keySet: 'near_ed25519_v1',
        }),
        verifier: signer,
        session: signer,
      } as never,
    );
    if (!provisioned.ok) {
      throw new Error(`near provisioning: ${provisioned.code}: ${provisioned.message}`);
    }

    expect(provisioned.walletCustody).toEqual({ status: 'committed' });
    const recoverySet = await custodyStore.readRecoveryEnvelopeSet(setup.walletId as never);
    expect(recoverySet?.record.manifestKekWraps).toHaveLength(10);
  } finally {
    cleanupTemporaryD1Database(tempDir);
  }
});
