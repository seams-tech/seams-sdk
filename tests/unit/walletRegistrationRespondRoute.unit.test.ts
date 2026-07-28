import { expect, test } from '@playwright/test';
import { createCloudflareD1RouterApiAuthService } from '../../packages/sdk-server-ts/src/router/cloudflare/d1RouterApiAuthService';
import { CloudflareD1RegistrationCeremonyIntentStore } from '../../packages/sdk-server-ts/src/router/cloudflare/d1RegistrationCeremonyStore';
import { parseWebAuthnRpId } from '../../packages/shared-ts/src/utils/domainIds';
import { cleanupTemporaryD1Database, createTemporaryD1Database } from '../helpers/sqliteD1';
import {
  buildFixtureRouterAbEcdsaStrictRegistrationRequest,
  createRouterAbSigningRuntimesForUnitTests,
  SuccessfulFixtureRouterAbEcdsaStrictRegistrationPort,
} from '../helpers/routerAbSigningRuntimeTestUtils';
import {
  applySignerMigrations,
  createWebAuthnRegistrationCredential,
  RecordingDurableObjectNamespace,
  requireParsedDomainId,
} from './helpers/cloudflareD1RouterApiAuthService.fixtures';

/**
 * Refactor 94C. `/wallets/register/respond` is the authenticated leg: it
 * verifies `signedSetup` and the proof, establishes the verified authority,
 * and commits the Router result — in one read and one write.
 *
 * The load-bearing question this file answers is whether a Gateway respond
 * journal is needed. The old leg claimed the branch in D1 *before* calling the
 * Router purely so a duplicate respond could be reconciled. That is only
 * necessary if an identical retry can produce a different result. These tests
 * show it cannot: the role layer is deterministic for an exact retry, and the
 * stored terminal branch answers a replay without a second Router call.
 */

const SCOPE = {
  namespace: 'registration-respond',
  orgId: 'org-respond',
  projectId: 'project-respond',
  envId: 'env-respond',
};

/* Each signer stands for a distinct deployment key, so its tokens must not
   collide with another instance's — otherwise a cross-ceremony test would
   verify against the wrong signer and silently pass. */
let fakeSignerInstances = 0;

function fakeGatewaySigner() {
  const issued = new Map<string, Record<string, unknown>>();
  const minted: Array<Record<string, unknown>> = [];
  const instance = (fakeSignerInstances += 1);
  let counter = 0;
  return {
    mintedPolicyJwts: () => minted.filter((c) => c.kind === 'router_policy_v1'),
    signJwt: async (sub: string, extra?: Record<string, unknown>) => {
      counter += 1;
      const token = `gateway-jwt-${instance}-${counter}`;
      const claims = { sub, ...(extra || {}) };
      issued.set(token, claims);
      minted.push(claims);
      return token;
    },
    verifyJwt: async (token: string) => {
      const payload = issued.get(token);
      return payload ? ({ valid: true, payload } as const) : ({ valid: false } as const);
    },
  };
}

/** Counts Router register calls so a replay that skips the Router is visible. */
class CountingStrictRegistrationPort extends SuccessfulFixtureRouterAbEcdsaStrictRegistrationPort {
  registerCalls = 0;
  override async register(input: never): Promise<never> {
    this.registerCalls += 1;
    return (await super.register(input as never)) as never;
  }
}

async function setupCeremony(
  database: unknown,
  strictRegistration: unknown,
  sharedSigner?: ReturnType<typeof fakeGatewaySigner>,
) {
  const routerAbSigningRuntimes = createRouterAbSigningRuntimesForUnitTests({
    config: { ROUTER_AB_NORMAL_SIGNING_WORKER_ID: 'signing-worker-respond' },
  });
  const service = createCloudflareD1RouterApiAuthService({
    database: database as never,
    ...SCOPE,
    routerAbSigningRuntimes: routerAbSigningRuntimes.runtimes,
    ecdsaStrictRegistration: strictRegistration,
    thresholdStore: {
      kind: 'cloudflare-do',
      namespace: new RecordingDurableObjectNamespace(),
      THRESHOLD_PREFIX: 'registration-respond-test',
      ROUTER_AB_NORMAL_SIGNING_WORKER_ID: 'signing-worker-respond',
    },
  } as never);
  const signer = sharedSigner ?? fakeGatewaySigner();
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
    signingRootVersion: 'root-respond-v1',
  } as never);
  if (!setup.ok) throw new Error(`${setup.code}: ${setup.message}`);

  const authority = {
    kind: 'passkey' as const,
    webauthnRegistration: await createWebAuthnRegistrationCredential({
      rpId,
      /* Setup issued this challenge; create signs exactly it. */
      challengeB64u: setup.registrationIntentDigestB64u,
      origin: 'https://app.example.com',
    }),
  };
  const respondRequest = {
    registrationCeremonyId: setup.registrationCeremonyId,
    signedSetup: setup.signedSetup,
    authority,
    ecdsa: {
      kind: 'router_ab_ecdsa_registration_v1' as const,
      strictRegistration: buildFixtureRouterAbEcdsaStrictRegistrationRequest(
        setup.ecdsa.strictRegistration,
      ),
    },
    verifier: signer,
    minter: signer,
  };
  return { service, signer, setup, respondRequest };
}

test('an identical respond retry is deterministic without a Gateway claim record', async () => {
  const { database, tempDir } = createTemporaryD1Database();
  try {
    await applySignerMigrations(database);
    const strictRegistration = new CountingStrictRegistrationPort();
    const { service, respondRequest } = await setupCeremony(database, strictRegistration);

    const first = await service.walletRegistration.respondWalletRegistration(
      respondRequest as never,
    );
    if (!first.ok) throw new Error(`${first.code}: ${first.message}`);
    expect(strictRegistration.registerCalls).toBe(1);

    const second = await service.walletRegistration.respondWalletRegistration(
      respondRequest as never,
    );
    if (!second.ok) throw new Error(`${second.code}: ${second.message}`);

    /* The stored terminal branch answers the replay, so the Router is not
       called again — which is exactly what a pre-call Gateway claim record
       would have bought, without the extra write on the success path. */
    expect(strictRegistration.registerCalls).toBe(1);
    expect(second.ecdsa).toEqual(first.ecdsa);
    expect(second.kind).toBe(first.kind);
  } finally {
    cleanupTemporaryD1Database(tempDir);
  }
});

test('respond establishes the verified authority in the same write as the result', async () => {
  const { database, tempDir } = createTemporaryD1Database();
  try {
    await applySignerMigrations(database);
    const strictRegistration = new CountingStrictRegistrationPort();
    const { service, respondRequest, setup } = await setupCeremony(database, strictRegistration);

    const store = new CloudflareD1RegistrationCeremonyIntentStore({
      kind: 'partitioned_d1',
      database: database as never,
      scope: SCOPE,
      keyPrefix: 'gateway-registration:',
    });
    const before = await store.getCeremony(setup.registrationCeremonyId);
    expect(before?.authorityState.kind).toBe('awaiting_proof');

    const responded = await service.walletRegistration.respondWalletRegistration(
      respondRequest as never,
    );
    if (!responded.ok) throw new Error(`${responded.code}: ${responded.message}`);

    const after = await store.getCeremony(setup.registrationCeremonyId);
    /* Verified authority and the branch result land together: a ceremony can
       never be verified without its result, nor hold a result without a
       verified authority. */
    expect(after?.authorityState.kind).toBe('verified');
    if (after?.authorityState.kind !== 'verified') throw new Error('expected verified authority');
    expect(after.authorityState.authority.walletId).toBe(setup.walletId);
    if (after.signerState.kind !== 'signer_set_registration') {
      throw new Error('expected signer-set state');
    }
    expect(after.signerState.branches.some((b) => b.kind === 'evm_family_ecdsa_pending_activation'))
      .toBe(true);
  } finally {
    cleanupTemporaryD1Database(tempDir);
  }
});

test('respond refuses a signedSetup minted for a different ceremony', async () => {
  const { database, tempDir } = createTemporaryD1Database();
  try {
    await applySignerMigrations(database);
    const strictRegistration = new CountingStrictRegistrationPort();
    /* One Gateway deployment key, two ceremonies — so the crossed payload
       verifies cryptographically and must still be refused. Signature
       validity is not authorization for this request. */
    const signer = fakeGatewaySigner();
    const first = await setupCeremony(database, strictRegistration, signer);
    const second = await setupCeremony(database, strictRegistration, signer);

    const crossed = await first.service.walletRegistration.respondWalletRegistration({
      ...first.respondRequest,
      signedSetup: second.setup.signedSetup,
    } as never);
    expect(crossed).toMatchObject({
      ok: false,
      message: 'signedSetup belongs to a different registration ceremony',
    });
    /* Refused before any Router work. */
    expect(strictRegistration.registerCalls).toBe(0);
  } finally {
    cleanupTemporaryD1Database(tempDir);
  }
});

test('respond mints an internal Router policy JWT bound to the respond digest', async () => {
  const { database, tempDir } = createTemporaryD1Database();
  try {
    await applySignerMigrations(database);
    const strictRegistration = new CountingStrictRegistrationPort();
    const { service, signer, respondRequest } = await setupCeremony(database, strictRegistration);

    expect(signer.mintedPolicyJwts()).toHaveLength(0);
    const responded = await service.walletRegistration.respondWalletRegistration(
      respondRequest as never,
    );
    if (!responded.ok) throw new Error(`${responded.code}: ${responded.message}`);

    const policy = signer.mintedPolicyJwts();
    expect(policy).toHaveLength(1);
    expect(policy[0]).toMatchObject({ operation: 'wallet_registration_respond' });
    expect(String(policy[0]?.requestDigestB64u || '')).toBeTruthy();
    /* Policy never crosses the public wire; the response carries no token. */
    expect(JSON.stringify(responded)).not.toContain('router_policy_v1');
  } finally {
    cleanupTemporaryD1Database(tempDir);
  }
});
