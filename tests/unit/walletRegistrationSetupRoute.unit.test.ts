import { expect, test } from '@playwright/test';
import { createCloudflareD1RouterApiAuthService } from '../../packages/wallet-server/src/router/cloudflare/d1/auth/d1RouterApiAuthService';
import { CloudflareD1RegistrationCeremonyIntentStore } from '../../packages/wallet-server/src/router/cloudflare/d1/registration/d1RegistrationCeremonyStore';
import {
  computeWalletRegistrationSetupDigestB64u,
  parseWalletRegistrationSetupClaims,
  verifySignedWalletRegistrationSetup,
} from '../../packages/wallet-server/src/router/domains/walletRegistration/walletRegistrationSetupPayload';
import { parseWebAuthnRpId } from '../../packages/shared-ts/src/utils/domainIds';
import { implicitNearAccountProvisioning } from '../../packages/shared-ts/src/utils/registrationIntent';
import { cleanupTemporaryD1Database, createTemporaryD1Database } from '../helpers/sqliteD1';
import {
  createRouterAbSigningRuntimesForUnitTests,
  SuccessfulFixtureRouterAbEcdsaStrictRegistrationPort,
} from '../helpers/routerAbSigningRuntimeTestUtils';
import {
  applySignerMigrations,
  RecordingDurableObjectNamespace,
  requireParsedDomainId,
} from './helpers/cloudflareD1RouterApiAuthService.fixtures';

/**
 * Refactor 94C. `/wallets/register/setup` creates the registration ceremony
 * with one request and one D1 write.
 *
 * The properties worth pinning are the ones the collapse is supposed to buy:
 * exactly one ceremony row written, the ceremony stored awaiting its proof
 * (setup issues the challenge, so no proof can exist yet), and a signedSetup
 * that only authorizes the ceremony and parameters it was minted for.
 */

const SCOPE = {
  namespace: 'registration-setup',
  orgId: 'org-setup',
  projectId: 'project-setup',
  envId: 'env-setup',
};

/** Mirrors the Gateway session signer the route supplies. */
function fakeSetupSigner() {
  const issued = new Map<string, Record<string, unknown>>();
  let counter = 0;
  return {
    issuedCount: () => counter,
    signJwt: async (sub: string, extra?: Record<string, unknown>) => {
      counter += 1;
      const token = `setup-jwt-${counter}`;
      issued.set(token, { sub, ...(extra || {}) });
      return token;
    },
    verifyJwt: async (token: string) => {
      const payload = issued.get(token);
      return payload ? ({ valid: true, payload } as const) : ({ valid: false } as const);
    },
  };
}

async function countCeremonyRows(database: {
  prepare: (sql: string) => { bind: (...a: unknown[]) => { first: () => Promise<unknown> } };
}): Promise<number> {
  const row = (await database
    .prepare(
      `SELECT COUNT(*) AS count
         FROM registration_ceremony_records
        WHERE namespace = ?1 AND org_id = ?2 AND project_id = ?3 AND env_id = ?4
          AND record_scope = 'ceremony'`,
    )
    .bind(SCOPE.namespace, SCOPE.orgId, SCOPE.projectId, SCOPE.envId)
    .first()) as { count?: number } | null;
  return Number(row?.count || 0);
}

async function countAllRegistrationRows(database: {
  prepare: (sql: string) => { bind: (...a: unknown[]) => { first: () => Promise<unknown> } };
}): Promise<number> {
  const row = (await database
    .prepare(
      `SELECT COUNT(*) AS count
         FROM registration_ceremony_records
        WHERE namespace = ?1 AND org_id = ?2 AND project_id = ?3 AND env_id = ?4`,
    )
    .bind(SCOPE.namespace, SCOPE.orgId, SCOPE.projectId, SCOPE.envId)
    .first()) as { count?: number } | null;
  return Number(row?.count || 0);
}

function setupService(database: unknown) {
  const routerAbSigningRuntimes = createRouterAbSigningRuntimesForUnitTests({
    config: { ROUTER_AB_NORMAL_SIGNING_WORKER_ID: 'signing-worker-setup' },
  });
  return createCloudflareD1RouterApiAuthService({
    database: database as never,
    ...SCOPE,
    routerAbSigningRuntimes: routerAbSigningRuntimes.runtimes,
    ecdsaStrictRegistration: new SuccessfulFixtureRouterAbEcdsaStrictRegistrationPort(),
    thresholdStore: {
      kind: 'cloudflare-do',
      namespace: new RecordingDurableObjectNamespace(),
      THRESHOLD_PREFIX: 'registration-setup-test',
      ROUTER_AB_NORMAL_SIGNING_WORKER_ID: 'signing-worker-setup',
    },
  } as never);
}

const ECDSA_SIGNER = {
  kind: 'evm_family_ecdsa' as const,
  participantIds: [1, 2] as const,
  chainTargets: [{ kind: 'evm' as const, namespace: 'eip155' as const, chainId: 8453 }],
};

function setupInput(signer: ReturnType<typeof fakeSetupSigner>, rpId: unknown) {
  return {
    request: {
      signerSelection: { kind: 'signer_set' as const, signers: [ECDSA_SIGNER] },
      authMethod: { kind: 'passkey' as const, rpId },
    },
    orgId: SCOPE.orgId,
    expectedOrigin: 'https://app.example.com',
    signer,
    signingRootId: `${SCOPE.projectId}:${SCOPE.envId}`,
    signingRootVersion: 'root-setup-v1',
  } as never;
}

test('setup writes exactly one ceremony row and returns a usable ECDSA preparation', async () => {
  const { database, tempDir } = createTemporaryD1Database();
  try {
    await applySignerMigrations(database);
    const service = setupService(database);
    const signer = fakeSetupSigner();
    const rpId = requireParsedDomainId(parseWebAuthnRpId('example.com'));

    expect(await countAllRegistrationRows(database as never)).toBe(0);
    const result = await service.walletRegistration.setupWalletRegistration(
      setupInput(signer, rpId),
    );
    if (!result.ok) throw new Error(`${result.code}: ${result.message}`);

    /* The collapse's whole point: one write, and it is the ceremony. No grant
       record, no wallet reservation, no start journal. */
    expect(await countCeremonyRows(database as never)).toBe(1);
    expect(await countAllRegistrationRows(database as never)).toBe(1);

    expect(result.ecdsa.kind).toBe('evm_family_ecdsa_keygen');
    expect(result.walletId).toBeTruthy();
    /* Setup issues the challenge the client's WebAuthn create must sign. */
    expect(result.registrationIntentDigestB64u).toBeTruthy();
    expect(result.intent.walletId).toBe(result.walletId);

    const store = new CloudflareD1RegistrationCeremonyIntentStore({
      kind: 'partitioned_d1',
      database: database as never,
      scope: SCOPE,
      keyPrefix: 'gateway-registration:',
    });
    const ceremony = await store.getCeremony(result.registrationCeremonyId);
    if (!ceremony) throw new Error('Expected the setup ceremony to be stored');
    expect(result.walletAuthMethodId).toBe(ceremony.foundingWalletAuthMethodId);
    expect(String(ceremony.foundingWalletAuthorityId)).toMatch(/^wallet-authority:/);
    expect(String(ceremony.foundingDeviceId)).toMatch(/^device:/);
    expect(String(ceremony.foundingWalletAuthMethodId)).toMatch(/^wallet-auth-method:/);
    /* No proof can exist yet — setup runs before the authenticator prompt. */
    expect(ceremony.authorityState).toEqual({
      kind: 'awaiting_proof',
      authMethod: { kind: 'passkey', rpId },
    });
  } finally {
    cleanupTemporaryD1Database(tempDir);
  }
});

test('two setups are independent ceremonies rather than a replayed one', async () => {
  const { database, tempDir } = createTemporaryD1Database();
  try {
    await applySignerMigrations(database);
    const service = setupService(database);
    const signer = fakeSetupSigner();
    const rpId = requireParsedDomainId(parseWebAuthnRpId('example.com'));

    const first = await service.walletRegistration.setupWalletRegistration(
      setupInput(signer, rpId),
    );
    const second = await service.walletRegistration.setupWalletRegistration(
      setupInput(signer, rpId),
    );
    if (!first.ok || !second.ok) throw new Error('Expected both setups to succeed');

    const store = new CloudflareD1RegistrationCeremonyIntentStore({
      kind: 'partitioned_d1',
      database: database as never,
      scope: SCOPE,
      keyPrefix: 'gateway-registration:',
    });
    const firstCeremony = await store.getCeremony(first.registrationCeremonyId);
    const secondCeremony = await store.getCeremony(second.registrationCeremonyId);
    if (!firstCeremony || !secondCeremony) throw new Error('Expected both ceremonies to persist');
    expect(firstCeremony.foundingWalletAuthorityId).not.toBe(
      secondCeremony.foundingWalletAuthorityId,
    );
    expect(firstCeremony.foundingDeviceId).not.toBe(secondCeremony.foundingDeviceId);
    expect(firstCeremony.foundingWalletAuthMethodId).not.toBe(
      secondCeremony.foundingWalletAuthMethodId,
    );

    /* Setup has no earlier leg to reconcile against, so it does not replay:
       each call is a distinct ceremony with a distinct wallet and payload.
       Idempotency belongs to activate, which owns the irreversible commit. */
    expect(second.registrationCeremonyId).not.toBe(first.registrationCeremonyId);
    expect(second.walletId).not.toBe(first.walletId);
    expect(second.signedSetup).not.toBe(first.signedSetup);
    expect(await countCeremonyRows(database as never)).toBe(2);
  } finally {
    cleanupTemporaryD1Database(tempDir);
  }
});

test('signedSetup authorizes only the ceremony and parameters it was minted for', async () => {
  const { database, tempDir } = createTemporaryD1Database();
  try {
    await applySignerMigrations(database);
    const service = setupService(database);
    const signer = fakeSetupSigner();
    const rpId = requireParsedDomainId(parseWebAuthnRpId('example.com'));

    const first = await service.walletRegistration.setupWalletRegistration(
      setupInput(signer, rpId),
    );
    const second = await service.walletRegistration.setupWalletRegistration(
      setupInput(signer, rpId),
    );
    if (!first.ok || !second.ok) throw new Error('Expected both setups to succeed');

    const store = new CloudflareD1RegistrationCeremonyIntentStore({
      kind: 'partitioned_d1',
      database: database as never,
      scope: SCOPE,
      keyPrefix: 'gateway-registration:',
    });
    const ceremony = await store.getCeremony(first.registrationCeremonyId);
    if (!ceremony) throw new Error('Expected the first setup ceremony');
    const setupDigestB64u = await computeWalletRegistrationSetupDigestB64u({
      registrationCeremonyId: ceremony.registrationCeremonyId,
      intent: ceremony.intent,
      intentDigestB64u: ceremony.digestB64u,
      orgId: ceremony.orgId,
      signingRootId: String(ceremony.signingRootId),
      signingRootVersion: String(ceremony.signingRootVersion),
      expectedOrigin: 'https://app.example.com',
    });
    const nowMs = Date.now();

    await expect(
      verifySignedWalletRegistrationSetup(signer, first.signedSetup, {
        registrationCeremonyId: first.registrationCeremonyId,
        setupDigestB64u,
        nowMs,
      }),
    ).resolves.toMatchObject({ ok: true });

    /* A payload that verifies cryptographically still must not drive a
       different ceremony — signature validity is not authorization. */
    await expect(
      verifySignedWalletRegistrationSetup(signer, second.signedSetup, {
        registrationCeremonyId: first.registrationCeremonyId,
        setupDigestB64u,
        nowMs,
      }),
    ).resolves.toMatchObject({
      ok: false,
      message: 'signedSetup belongs to a different registration ceremony',
    });

    /* Nor the same ceremony with mutated parameters. */
    await expect(
      verifySignedWalletRegistrationSetup(signer, first.signedSetup, {
        registrationCeremonyId: first.registrationCeremonyId,
        setupDigestB64u: `${setupDigestB64u}-tampered`,
        nowMs,
      }),
    ).resolves.toMatchObject({
      ok: false,
      message: 'signedSetup does not match this registration setup',
    });

    /* And an expired one is refused even though it is otherwise exact. */
    const verified = await signer.verifyJwt(String(first.signedSetup));
    const claims = parseWalletRegistrationSetupClaims(verified.valid ? verified.payload : null);
    if (!claims) throw new Error('Expected parseable setup claims');
    await expect(
      verifySignedWalletRegistrationSetup(signer, first.signedSetup, {
        registrationCeremonyId: first.registrationCeremonyId,
        setupDigestB64u,
        nowMs: claims.expiresAtMs + 1,
      }),
    ).resolves.toMatchObject({ ok: false, message: 'signedSetup has expired' });
  } finally {
    cleanupTemporaryD1Database(tempDir);
  }
});

test('setup prepares ECDSA only for a mixed plan, for either auth method', async () => {
  const { database, tempDir } = createTemporaryD1Database();
  try {
    await applySignerMigrations(database);
    const service = setupService(database);
    const signer = fakeSetupSigner();

    /* Yao admission binds the Ed25519 authority scope, which is only sound
       once the proof is verified — so setup never prepares it, for either
       auth method. Email OTP is the case that could not have been special
       cased safely; making both defer keeps one setup protocol. */
    const mixedPlan = (authMethod: unknown) => ({
      request: {
        signerSelection: {
          kind: 'signer_set',
          signers: [
            {
              kind: 'near_ed25519',
              accountProvisioning: implicitNearAccountProvisioning(),
              signerSlot: 1,
              participantIds: [1, 2],
              derivationVersion: 1,
            },
            ECDSA_SIGNER,
          ],
        },
        authMethod,
      },
      orgId: SCOPE.orgId,
      expectedOrigin: 'https://app.example.com',
      signer,
      signingRootId: `${SCOPE.projectId}:${SCOPE.envId}`,
      signingRootVersion: 'root-setup-v1',
    });

    const rpId = requireParsedDomainId(parseWebAuthnRpId('example.com'));
    for (const authMethod of [
      { kind: 'passkey', rpId },
      {
        kind: 'email_otp',
        proofKind: 'otp_challenge',
        email: 'setup@example.test',
        providerSubject: 'provider-subject:setup',
        otpCode: '000000',
      },
    ]) {
      const result = await service.walletRegistration.setupWalletRegistration(
        mixedPlan(authMethod) as never,
      );
      if (!result.ok) throw new Error(`${result.code}: ${result.message}`);
      /* No Ed25519 arm on the setup response at all — not an empty one. */
      expect('ed25519' in result).toBe(false);
      expect(result.ecdsa.kind).toBe('evm_family_ecdsa_keygen');
    }
  } finally {
    cleanupTemporaryD1Database(tempDir);
  }
});

test('the setup route definition accepts a publishable key and nothing else', async () => {
  const { createRouterApiRouteDefinitions } =
    await import('../../packages/wallet-server/src/router/framework/routeDefinitions');
  const routes = createRouterApiRouteDefinitions({});
  const setup = routes.find((route) => route.id === 'wallet_registration_setup');
  if (!setup) throw new Error('Expected the setup route definition');
  expect(setup.path).toBe('/wallets/register/setup');
  if (setup.auth.plane !== 'api_credentials') {
    throw new Error('Expected the setup route on the api_credentials plane');
  }
  expect(setup.auth.credentials).toEqual(['publishable_key']);
  expect(setup.auth.environmentBinding).toBe('required');
  expect(setup.auth.originBinding).toBe('required');
});

test('add-signer intent accepts a publishable key and nothing else', async () => {
  const { createRouterApiRouteDefinitions } =
    await import('../../packages/wallet-server/src/router/framework/routeDefinitions');
  const routes = createRouterApiRouteDefinitions({});
  const addSigner = routes.find((route) => route.id === 'wallet_add_signer_intent');
  if (!addSigner) throw new Error('Expected the add-signer intent route definition');
  if (addSigner.auth.plane !== 'api_credentials') {
    throw new Error('Expected add-signer intent on the api_credentials plane');
  }
  /* Only the admission credential moved; the ceremony and its journals are
     deliberately unchanged. */
  expect(addSigner.auth.credentials).toEqual(['publishable_key']);
  expect(addSigner.auth.environmentBinding).toBe('required');
  expect(addSigner.auth.originBinding).toBe('required');
});
