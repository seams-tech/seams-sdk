import { expect, test } from '@playwright/test';
import { createCloudflareD1RouterApiAuthService } from '../../packages/sdk-server-ts/src/router/cloudflare/d1RouterApiAuthService';
import { CloudflareD1RegistrationCeremonyIntentStore } from '../../packages/sdk-server-ts/src/router/cloudflare/d1RegistrationCeremonyStore';
import {
  computeWalletRegistrationSetupDigestB64u,
  parseWalletRegistrationSetupClaims,
  verifySignedWalletRegistrationSetup,
} from '../../packages/sdk-server-ts/src/router/walletRegistrationSetupPayload';
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
 * Refactor 94C. `/wallets/register/setup` replaces the bootstrap grant, the
 * intent, and start with one request and one D1 write.
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
      const claims = issued.get(token);
      return claims
        ? ({ ok: true, claims } as const)
        : ({ ok: false, code: 'invalid_token', message: 'unknown token' } as const);
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
    const claims = parseWalletRegistrationSetupClaims(
      (await signer.verifyJwt(String(first.signedSetup))).ok
        ? ((await signer.verifyJwt(String(first.signedSetup))) as { claims: unknown }).claims
        : null,
    );
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

test('setup defers Ed25519 admission when the authority scope needs the proof', async () => {
  const { database, tempDir } = createTemporaryD1Database();
  try {
    await applySignerMigrations(database);
    const service = setupService(database);
    const signer = fakeSetupSigner();

    /* Email OTP's Ed25519 scope carries a providerUserId that only the
       verified proof establishes. Admitting here would bind key material to
       an unauthenticated claim, so setup must defer instead. */
    const result = await service.walletRegistration.setupWalletRegistration({
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
        authMethod: {
          kind: 'email_otp',
          proofKind: 'otp_challenge',
          email: 'setup@example.test',
          otpCode: '000000',
          appSessionJwt: 'app-session',
        },
      },
      orgId: SCOPE.orgId,
      expectedOrigin: 'https://app.example.com',
      signer,
      signingRootId: `${SCOPE.projectId}:${SCOPE.envId}`,
      signingRootVersion: 'root-setup-v1',
    } as never);
    if (!result.ok) throw new Error(`${result.code}: ${result.message}`);
    expect(result.ed25519).toEqual({
      status: 'deferred_to_respond',
      reason: 'authority_scope_requires_proof',
    });
  } finally {
    cleanupTemporaryD1Database(tempDir);
  }
});
