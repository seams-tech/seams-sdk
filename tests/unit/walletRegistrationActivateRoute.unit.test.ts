import { expect, test } from '@playwright/test';
import { createCloudflareD1RouterApiAuthService } from '../../packages/sdk-server-ts/src/router/cloudflare/d1RouterApiAuthService';
import { parseWebAuthnRpId } from '../../packages/shared-ts/src/utils/domainIds';
import { cleanupTemporaryD1Database, createTemporaryD1Database } from '../helpers/sqliteD1';
import {
  buildFixtureRouterAbEcdsaStrictRegistrationRequest,
  createRouterAbSigningRuntimesForUnitTests,
  fixtureRouterAbEcdsaActivationFacts,
  SuccessfulFixtureRouterAbEcdsaStrictRegistrationPort,
} from '../helpers/routerAbSigningRuntimeTestUtils';
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
      const token = `activate-jwt-${instance}-${counter}`;
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
  const service = createCloudflareD1RouterApiAuthService({
    database: database as never,
    ...SCOPE,
    routerAbSigningRuntimes: routerAbSigningRuntimes.runtimes,
    ecdsaStrictRegistration: strictRegistration,
    thresholdStore: {
      kind: 'cloudflare-do',
      namespace: new RecordingDurableObjectNamespace(),
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
    ecdsa: { clientActivation: fixtureRouterAbEcdsaActivationFacts() },
    verifier: signer,
    minter: signer,
  };
  return { service, signer, setup, activateRequest };
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
    const { service, activateRequest } = await respondedCeremony(database, strictRegistration);

    const first = await service.walletRegistration.activateWalletRegistration(
      activateRequest as never,
    );
    if (!first.ok) throw new Error(`first activate: ${first.code}: ${first.message}`);
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
    /* And no repeated custody effect. */
    expect(strictRegistration.activateCalls).toBe(custodyCallsAfterFirst);
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
