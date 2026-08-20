import { expect, test } from '@playwright/test';
import { createCloudflareD1RouterApiAuthService } from '../../packages/wallet-server/src/router/cloudflare/d1/auth/d1RouterApiAuthService';
import { normalizeLogger } from '../../packages/wallet-server/src/core/logger';
import { parseWalletId, parseWebAuthnRpId } from '../../packages/shared-ts/src/utils/domainIds';
import { cleanupTemporaryD1Database, createTemporaryD1Database } from '../helpers/sqliteD1';
import {
  requireParsedDomainId,
  createWebAuthnAssertionFixture,
  createWebAuthnAssertion,
  applySignerMigrations,
  insertIdentity,
  insertWebAuthn,
  readWebAuthnChallengeRow,
  readWebAuthnAuthenticatorRow,
  insertNearPublicKey,
} from './helpers/cloudflareD1RouterApiAuthService.fixtures';
import { UnusedSessionAdapter } from './helpers/routerAbEd25519YaoRegistrationBridge.fixtures';
import {
  CloudflareD1WebAuthnAuthService,
  type D1WebAuthnWalletManifestSource,
} from '../../packages/wallet-server/src/router/cloudflare/d1/webauthn/d1WebAuthnAuthService';
import { CloudflareD1WebAuthnStore } from '../../packages/wallet-server/src/router/cloudflare/d1/webauthn/d1WebAuthnStore';
import { D1WalletAuthMethodStore } from '../../packages/wallet-server/src/core/d1WalletAuthMethodStore';
import type { WalletAuthMethodRecord } from '../../packages/wallet-server/src/core/WalletStore';

const SYNC_KEY_MANIFEST_DIGEST_B64U = Buffer.alloc(32, 21).toString('base64url');
const SYNC_SIGNER_SLOT = 4;

function passkeyAuthMethodRecord(input: {
  readonly walletId: string;
  readonly credentialIdB64u: string;
  readonly credentialPublicKeyB64u: string;
  readonly status: 'active' | 'revoked';
  readonly updatedAtMs: number;
}): Extract<WalletAuthMethodRecord, { readonly kind: 'passkey' }> {
  return {
    version: 'wallet_auth_method_v1',
    kind: 'passkey',
    status: input.status,
    walletId: requireParsedDomainId(parseWalletId(input.walletId)),
    rpId: requireParsedDomainId(parseWebAuthnRpId('example.com')),
    credentialIdB64u: input.credentialIdB64u,
    credentialPublicKeyB64u: input.credentialPublicKeyB64u,
    counter: 0,
    createdAtMs: 100,
    updatedAtMs: input.updatedAtMs,
  };
}

class RecordingWalletManifestSource implements D1WebAuthnWalletManifestSource {
  readonly requests: Parameters<
    D1WebAuthnWalletManifestSource['getEd25519KeyManifestBySlot']
  >[0][] = [];

  async getEd25519KeyManifestBySlot(
    input: Parameters<D1WebAuthnWalletManifestSource['getEd25519KeyManifestBySlot']>[0],
  ): Promise<{ readonly custodyKeyManifestDigestB64u: string }> {
    this.requests.push(input);
    return { custodyKeyManifestDigestB64u: SYNC_KEY_MANIFEST_DIGEST_B64U };
  }
}

test('Cloudflare D1 WebAuthn login options require and return registered credentials', async () => {
  const { database, tempDir } = createTemporaryD1Database();
  try {
    await applySignerMigrations(database);
    const scope = {
      namespace: 'seams-local-test',
      orgId: 'org-a',
      projectId: 'project-a',
      envId: 'env-a',
      userId: 'wallet-a',
    };
    const service = createCloudflareD1RouterApiAuthService({
      database,
      namespace: scope.namespace,
      orgId: scope.orgId,
      projectId: scope.projectId,
      envId: scope.envId,
      relayerAccount: 'relay.local',
      googleOidcClientId: 'google-client',
      accountIdDerivationSecret: 'test-account-id-derivation-secret',
    });
    const walletAuthMethodStore = new D1WalletAuthMethodStore({
      database,
      namespace: scope.namespace,
      orgId: scope.orgId,
      projectId: scope.projectId,
      envId: scope.envId,
      ensureSchema: false,
    });

    await expect(
      service.webAuthn.createWebAuthnLoginOptions({
        userId: scope.userId,
        rpId: 'example.com',
      }),
    ).resolves.toMatchObject({
      ok: false,
      code: 'unknown_credential',
    });

    await insertWebAuthn({ database, ...scope, credentialIdB64u: 'credential-a' });
    await walletAuthMethodStore.put(
      passkeyAuthMethodRecord({
        walletId: scope.userId,
        credentialIdB64u: 'credential-a',
        credentialPublicKeyB64u: 'credential-public-key-a',
        status: 'active',
        updatedAtMs: 100,
      }),
    );
    await expect(
      service.webAuthn.createWebAuthnLoginOptions({
        userId: scope.userId,
        rpId: 'example.com',
      }),
    ).resolves.toMatchObject({
      ok: true,
      credentialIds: ['credential-a'],
    });
    await walletAuthMethodStore.put(
      passkeyAuthMethodRecord({
        walletId: scope.userId,
        credentialIdB64u: 'credential-a',
        credentialPublicKeyB64u: 'credential-public-key-a',
        status: 'revoked',
        updatedAtMs: 200,
      }),
    );
    await expect(
      service.webAuthn.createWebAuthnLoginOptions({
        userId: scope.userId,
        rpId: 'example.com',
      }),
    ).resolves.toMatchObject({ ok: false, code: 'unknown_credential' });
  } finally {
    cleanupTemporaryD1Database(tempDir);
  }
});

test('Cloudflare D1 Router API auth service reads signer metadata with tenant scope', async () => {
  const { database, tempDir } = createTemporaryD1Database();
  try {
    await applySignerMigrations(database);
    const scope = {
      namespace: 'seams-local-test',
      orgId: 'org-a',
      projectId: 'project-a',
      envId: 'env-a',
      userId: 'wallet-a',
    };
    const manifestSource = new RecordingWalletManifestSource();
    const walletAuthMethodStore = new D1WalletAuthMethodStore({
      database,
      namespace: scope.namespace,
      orgId: scope.orgId,
      projectId: scope.projectId,
      envId: scope.envId,
      ensureSchema: false,
    });
    const syncWebAuthnService = new CloudflareD1WebAuthnAuthService({
      webAuthnStore: new CloudflareD1WebAuthnStore({
        database,
        namespace: scope.namespace,
        orgId: scope.orgId,
        projectId: scope.projectId,
        envId: scope.envId,
      }),
      walletManifestSource: manifestSource,
      walletAuthMethodStore,
    });
    const service = createCloudflareD1RouterApiAuthService({
      database,
      namespace: scope.namespace,
      orgId: scope.orgId,
      projectId: scope.projectId,
      envId: scope.envId,
      relayerAccount: 'relay.local',
      relayerPublicKey: 'relay-public-key',
      googleOidcClientId: 'google-client',
      githubOAuth: {
        clientId: 'github-client',
        clientSecret: 'github-secret',
        callbackUrl: 'https://example.localhost/dashboard/login',
      },
      accountIdDerivationSecret: 'test-account-id-derivation-secret',
    });
    await insertIdentity({ database, ...scope, subject: 'google:alice' });
    await insertIdentity({ database, ...scope, orgId: 'org-b', subject: 'google:bob' });
    await insertIdentity({
      database,
      ...scope,
      userId: 'linked.testnet',
      subject: 'wallet:oidc:linked',
    });
    await insertWebAuthn({ database, ...scope });
    await walletAuthMethodStore.put(
      passkeyAuthMethodRecord({
        walletId: scope.userId,
        credentialIdB64u: 'credential-a',
        credentialPublicKeyB64u: 'credential-public-key-a',
        status: 'active',
        updatedAtMs: 100,
      }),
    );
    await insertNearPublicKey({ database, ...scope });

    await expect(service.identity.listIdentities({ userId: scope.userId })).resolves.toEqual({
      ok: true,
      subjects: ['google:alice'],
    });
    await expect(
      service.identity.linkIdentity({ userId: 'wallet-b', subject: 'google:alice' }),
    ).resolves.toMatchObject({ ok: false, code: 'already_linked' });
    await expect(
      service.identity.linkIdentity({ userId: scope.userId, subject: 'google:carol' }),
    ).resolves.toEqual({ ok: true });
    await expect(service.identity.listIdentities({ userId: scope.userId })).resolves.toEqual({
      ok: true,
      subjects: ['google:alice', 'google:carol'],
    });
    await expect(
      service.identity.unlinkIdentity({ userId: scope.userId, subject: 'google:alice' }),
    ).resolves.toEqual({ ok: true });
    await expect(service.identity.listIdentities({ userId: scope.userId })).resolves.toEqual({
      ok: true,
      subjects: ['google:carol'],
    });
    await expect(
      service.identity.unlinkIdentity({ userId: scope.userId, subject: 'google:carol' }),
    ).resolves.toMatchObject({ ok: false, code: 'cannot_unlink_last_identity' });
    await insertIdentity({
      database,
      ...scope,
      userId: 'wallet-solo',
      subject: 'google:solo',
    });
    await expect(
      service.identity.linkIdentity({
        userId: scope.userId,
        subject: 'google:solo',
        allowMoveIfSoleIdentity: true,
      }),
    ).resolves.toEqual({ ok: true, movedFromUserId: 'wallet-solo' });
    await expect(service.identity.listIdentities({ userId: 'wallet-solo' })).resolves.toEqual({
      ok: true,
      subjects: [],
    });
    await insertIdentity({
      database,
      ...scope,
      userId: 'wallet-many',
      subject: 'google:many-a',
    });
    await insertIdentity({
      database,
      ...scope,
      userId: 'wallet-many',
      subject: 'google:many-b',
    });
    await expect(
      service.identity.linkIdentity({
        userId: scope.userId,
        subject: 'google:many-a',
        allowMoveIfSoleIdentity: true,
      }),
    ).resolves.toMatchObject({ ok: false, code: 'already_linked' });
    await expect(
      service.identity.resolveOidcWalletId({
        providerSubject: 'oidc:linked',
        runtimePolicyScope: {
          orgId: scope.orgId,
          projectId: scope.projectId,
          envId: scope.envId,
          signingRootVersion: 'v1',
        },
      }),
    ).resolves.toBe('linked.testnet');
    const derivedOidcWalletId = await service.identity.resolveOidcWalletId({
      providerSubject: 'oidc:new-user',
      email: 'new-user@example.test',
      runtimePolicyScope: {
        orgId: scope.orgId,
        projectId: scope.projectId,
        envId: scope.envId,
        signingRootVersion: 'v1',
      },
    });
    expect(derivedOidcWalletId).toMatch(/^[a-z]+-[a-z]+-[a-z0-9]{10}\.relay\.local$/);
    await expect(
      service.webAuthn.listWebAuthnAuthenticatorsForUser({
        userId: scope.userId,
        rpId: 'example.com',
      }),
    ).resolves.toMatchObject({
      ok: true,
      authenticators: [
        {
          credentialIdB64u: 'credential-a',
          signerSlot: 2,
          publicKey: 'ed25519:public',
          createdAtMs: 200,
          updatedAtMs: 300,
          /* Inserted without device capture, so the D1 boundary synthesizes the
             fallback rather than dropping the contract's required field. */
          device: {
            label: 'Unknown device',
            browser: 'other',
            os: 'other',
            synced: false,
            transports: [],
          },
        },
      ],
    });
    const webAuthnFixture = await createWebAuthnAssertionFixture();
    await insertWebAuthn({
      database,
      ...scope,
      credentialIdB64u: webAuthnFixture.credentialIdB64u,
      credentialPublicKeyB64u: webAuthnFixture.credentialPublicKeyB64u,
      signerSlot: SYNC_SIGNER_SLOT,
    });
    await walletAuthMethodStore.put(
      passkeyAuthMethodRecord({
        walletId: scope.userId,
        credentialIdB64u: webAuthnFixture.credentialIdB64u,
        credentialPublicKeyB64u: webAuthnFixture.credentialPublicKeyB64u,
        status: 'active',
        updatedAtMs: 100,
      }),
    );
    const loginOptions = await service.webAuthn.createWebAuthnLoginOptions({
      userId: scope.userId,
      rpId: 'example.com',
      ttlMs: 60_000,
    });
    expect(loginOptions.ok).toBe(true);
    if (!loginOptions.ok) throw new Error(loginOptions.message);
    const loginChallengeId = String(loginOptions.challengeId || '');
    expect(loginChallengeId).not.toBe('');
    expect(loginOptions.challengeB64u).toEqual(expect.any(String));
    expect(loginOptions.credentialIds).toEqual(['credential-a', webAuthnFixture.credentialIdB64u]);
    expect(loginOptions.expiresAtMs).toBeGreaterThan(Date.now());
    const loginChallengeRow = await readWebAuthnChallengeRow({
      database,
      ...scope,
      challengeId: loginChallengeId,
    });
    expect(loginChallengeRow?.challenge_kind).toBe('login');
    expect(loginChallengeRow?.created_at_ms).toEqual(expect.any(Number));
    expect(loginChallengeRow?.expires_at_ms).toBe(loginOptions.expiresAtMs);
    const rawLoginChallengeRecord = loginChallengeRow?.record_json;
    if (typeof rawLoginChallengeRecord !== 'string') {
      throw new Error('Expected WebAuthn login challenge record_json');
    }
    const loginChallengeRecord: unknown = JSON.parse(rawLoginChallengeRecord);
    expect(loginChallengeRecord).toMatchObject({
      version: 'webauthn_login_challenge_v1',
      challengeId: loginChallengeId,
      userId: scope.userId,
      rpId: 'example.com',
      challengeB64u: loginOptions.challengeB64u,
      expiresAtMs: loginOptions.expiresAtMs,
    });
    const loginAssertion = await createWebAuthnAssertion({
      fixture: webAuthnFixture,
      rpId: 'example.com',
      origin: 'https://example.com',
      challengeB64u: String(loginOptions.challengeB64u || ''),
      counter: 1,
    });
    await expect(
      service.webAuthn.verifyWebAuthnLogin({
        challengeId: loginChallengeId,
        webauthn_authentication: loginAssertion,
        expected_origin: 'https://example.com',
      }),
    ).resolves.toMatchObject({
      ok: true,
      verified: true,
      userId: scope.userId,
      rpId: 'example.com',
    });
    await expect(
      readWebAuthnAuthenticatorRow({
        database,
        ...scope,
        userId: scope.userId,
        credentialIdB64u: webAuthnFixture.credentialIdB64u,
      }),
    ).resolves.toMatchObject({ counter: 1 });
    const revokedLoginOptions = await service.webAuthn.createWebAuthnLoginOptions({
      userId: scope.userId,
      rpId: 'example.com',
      ttlMs: 60_000,
    });
    expect(revokedLoginOptions.ok).toBe(true);
    if (!revokedLoginOptions.ok) throw new Error(revokedLoginOptions.message);
    const revokedAssertion = await createWebAuthnAssertion({
      fixture: webAuthnFixture,
      rpId: 'example.com',
      origin: 'https://example.com',
      challengeB64u: String(revokedLoginOptions.challengeB64u || ''),
      counter: 2,
    });
    await walletAuthMethodStore.put(
      passkeyAuthMethodRecord({
        walletId: scope.userId,
        credentialIdB64u: webAuthnFixture.credentialIdB64u,
        credentialPublicKeyB64u: webAuthnFixture.credentialPublicKeyB64u,
        status: 'revoked',
        updatedAtMs: 200,
      }),
    );
    await expect(
      service.webAuthn.verifyWebAuthnLogin({
        challengeId: String(revokedLoginOptions.challengeId || ''),
        webauthn_authentication: revokedAssertion,
        expected_origin: 'https://example.com',
      }),
    ).resolves.toMatchObject({
      ok: false,
      verified: false,
      code: 'unknown_credential',
    });
    await expect(
      service.webAuthn.createWebAuthnLoginOptions({ userId: 'bad user', rpId: 'example.com' }),
    ).resolves.toMatchObject({
      ok: false,
      code: 'invalid_body',
      message: 'Invalid userId',
    });
    await expect(
      service.webAuthn.createWebAuthnLoginOptions({
        userId: 'wallet-without-passkey',
        rpId: 'example.com',
      }),
    ).resolves.toMatchObject({
      ok: false,
      code: 'unknown_credential',
      message: 'Wallet has no registered passkey credential',
    });
    const syncOptions = await syncWebAuthnService.createWebAuthnSyncAccountOptions({
      rp_id: 'example.com',
      account_id: scope.userId,
      ttl_ms: 60_000,
    });
    expect(syncOptions.ok).toBe(true);
    if (!syncOptions.ok) throw new Error(syncOptions.message);
    const syncChallengeId = String(syncOptions.challengeId || '');
    expect(syncChallengeId).not.toBe('');
    expect(syncOptions.challengeB64u).toEqual(expect.any(String));
    expect(syncOptions.credentialIds).toEqual(['credential-a']);
    expect(syncOptions.walletBinding).toEqual({
      walletId: scope.userId,
      nearAccountId: 'near.testnet',
      nearEd25519SigningKeyId: 'ed25519:key',
      rpId: 'example.com',
      credentialIdB64u: 'credential-a',
      signerSlot: 2,
    });
    const syncChallengeRow = await readWebAuthnChallengeRow({
      database,
      ...scope,
      challengeId: syncChallengeId,
    });
    expect(syncChallengeRow?.challenge_kind).toBe('sync');
    expect(syncChallengeRow?.expires_at_ms).toBe(syncOptions.expiresAtMs);
    const rawSyncChallengeRecord = syncChallengeRow?.record_json;
    if (typeof rawSyncChallengeRecord !== 'string') {
      throw new Error('Expected WebAuthn sync challenge record_json');
    }
    const syncChallengeRecord: unknown = JSON.parse(rawSyncChallengeRecord);
    expect(syncChallengeRecord).toMatchObject({
      version: 'webauthn_sync_challenge_v1',
      challengeId: syncChallengeId,
      rpId: 'example.com',
      expectedUserId: scope.userId,
      challengeB64u: syncOptions.challengeB64u,
      expiresAtMs: syncOptions.expiresAtMs,
    });
    const syncAssertion = await createWebAuthnAssertion({
      fixture: webAuthnFixture,
      rpId: 'example.com',
      origin: 'https://example.com',
      challengeB64u: String(syncOptions.challengeB64u || ''),
      counter: 2,
    });
    await expect(
      syncWebAuthnService.verifyWebAuthnSyncAccount({
        challengeId: syncChallengeId,
        webauthn_authentication: syncAssertion,
        expected_origin: 'https://example.com',
      }),
    ).resolves.toMatchObject({
      ok: false,
      verified: false,
      code: 'unknown_credential',
    });
    expect(manifestSource.requests).toEqual([]);
    await expect(
      readWebAuthnAuthenticatorRow({
        database,
        ...scope,
        userId: scope.userId,
        credentialIdB64u: webAuthnFixture.credentialIdB64u,
      }),
    ).resolves.toMatchObject({ counter: 1 });
    await expect(
      syncWebAuthnService.createWebAuthnSyncAccountOptions({
        account_id: scope.userId,
      }),
    ).resolves.toMatchObject({
      ok: false,
      code: 'invalid_body',
      message: 'Missing rp_id',
    });
    await expect(
      service.nearFunding.listNearPublicKeysForUser({ userId: scope.userId }),
    ).resolves.toEqual({
      ok: true,
      keys: [
        {
          publicKey: 'ed25519:near-public',
          kind: 'threshold',
          signerSlot: 1,
          createdAtMs: 400,
          updatedAtMs: 500,
          authBinding: {
            kind: 'passkey',
            rpId: 'example.com',
            credentialIdB64u: 'credential-a',
          },
        },
      ],
    });
    expect(service.router.getConfiguredRelayerAccount()).toBe('relay.local');
    await expect(service.router.getRelayerAccount()).resolves.toEqual({
      accountId: 'relay.local',
      publicKey: 'relay-public-key',
    });
    expect(service.identity.getGoogleOidcPublicConfig()).toEqual({
      configured: true,
      clientId: 'google-client',
    });
    expect(service.identity.getGithubOAuthPublicConfig()).toEqual({
      configured: true,
      clientId: 'github-client',
      callbackUrl: 'https://example.localhost/dashboard/login',
    });
  } finally {
    cleanupTemporaryD1Database(tempDir);
  }
});

test('Cloudflare D1 Router API auth service has no Gateway-owned signing runtime by default', async () => {
  const { database, tempDir } = createTemporaryD1Database();
  try {
    const withoutThreshold = createCloudflareD1RouterApiAuthService({
      database,
      namespace: 'seams-local-test',
      orgId: 'org-a',
      projectId: 'project-a',
      envId: 'env-a',
      relayerAccount: 'relay.local',
      relayerPublicKey: 'relay-public-key',
    });
    expect(withoutThreshold.thresholdRuntime.getRouterAbEcdsaPresignRuntime()).toBeNull();
  } finally {
    cleanupTemporaryD1Database(tempDir);
  }
});

test('Cloudflare D1 R103 composition exposes linked admission and local presence ports', async () => {
  const { database, tempDir } = createTemporaryD1Database();
  try {
    const rpId = requireParsedDomainId(parseWebAuthnRpId('example.test'));
    const service = createCloudflareD1RouterApiAuthService({
      database,
      namespace: 'seams-local-test',
      orgId: 'org-a',
      projectId: 'project-a',
      envId: 'env-a',
      linkedDevice: {
        execution: {
          nowV1: () => 5_000,
          rpId,
          expectedOrigin: 'https://example.test',
          logger: normalizeLogger(),
        },
      },
    });

    expect(service.linkedDeviceExecution).toBeDefined();
    expect(service.linkedDeviceLocalPresence).toBeDefined();
    expect(service.deviceLinking).toBeUndefined();
    expect(service.deviceManagement).toBeUndefined();
    expect(service.deviceLinkingGateway).toBeUndefined();
  } finally {
    cleanupTemporaryD1Database(tempDir);
  }
});

test('Cloudflare D1 R103 composition owns lane activation and aggregate revocation wiring', async () => {
  const { database, tempDir } = createTemporaryD1Database();
  try {
    const rpId = requireParsedDomainId(parseWebAuthnRpId('example.test'));
    const inertLaneBinding = {
      fetch: async () => new Response(null, { status: 503 }),
    };
    const inertEd25519YaoKeyset = {
      deriver_a_input_public_key: new Array<number>(32).fill(0),
      deriver_b_input_public_key: new Array<number>(32).fill(0),
      signing_worker_recipient_public_key: new Array<number>(32).fill(0),
    };
    const service = createCloudflareD1RouterApiAuthService({
      database,
      namespace: 'seams-local-test',
      orgId: 'org-a',
      projectId: 'project-a',
      envId: 'env-a',
      linkedDevice: {
        execution: {
          nowV1: () => 5_000,
          rpId,
          expectedOrigin: 'https://example.test',
          logger: normalizeLogger(),
        },
        session: {
          session: new UnusedSessionAdapter(),
          laneRuntime: {
            router: inertLaneBinding,
            signingWorker: inertLaneBinding,
            internalServiceAuth: 'test-internal-service-auth',
            ed25519YaoKeyset: inertEd25519YaoKeyset,
          },
          operatorRecovery: {
            operatorSecret: 'operator-recovery-test-secret',
          },
        },
        management: {},
      },
    });

    expect(service.deviceLinking).toBeDefined();
    expect(service.deviceManagement).toBeDefined();
    expect(service.deviceLinkingOwnerAuthorization).toBeDefined();
    expect(service.deviceLinkingLaneGateway).toBeDefined();
  } finally {
    cleanupTemporaryD1Database(tempDir);
  }
});
