import { expect, test } from '@playwright/test';
import { createCloudflareD1RouterApiAuthService } from '../../packages/wallet-server/src/router/cloudflare/d1/auth/d1RouterApiAuthService';
import { createCloudflareRouter } from '../../packages/wallet-server/src/router/cloudflare/runtime/createCloudflareRouter';
import { cleanupTemporaryD1Database, createTemporaryD1Database } from '../helpers/sqliteD1';
import { callCf } from '../relayer/helpers';
import {
  applySignerMigrations,
  generateGoogleOidcTestKey,
  installGoogleJwksFetchMock,
  makeSignedGoogleIdToken,
  restoreGoogleJwksFetchMock,
} from './helpers/cloudflareD1RouterApiAuthService.fixtures';

test('Cloudflare D1 Router API auth service verifies Google OIDC tokens and links identity', async () => {
  const { database, tempDir } = createTemporaryD1Database();
  const key = await generateGoogleOidcTestKey('google-kid-success');
  const originalFetch = installGoogleJwksFetchMock(key.publicJwk);
  try {
    await applySignerMigrations(database);
    const service = createCloudflareD1RouterApiAuthService({
      database,
      namespace: 'seams-local-test',
      orgId: 'org-a',
      projectId: 'project-a',
      envId: 'env-a',
      relayerAccount: 'relay.local',
      googleOidcClientId: 'google-client',
      accountIdDerivationSecret: 'test-account-id-derivation-secret',
    });
    const nowSec = Math.floor(Date.now() / 1_000);
    const idToken = await makeSignedGoogleIdToken({
      privateKey: key.privateKey,
      kid: key.kid,
      payload: {
        iss: 'https://accounts.google.com',
        aud: 'google-client',
        sub: 'subject-123',
        email: 'Alice@Example.Test',
        email_verified: true,
        name: 'Alice Example',
        given_name: 'Alice',
        family_name: 'Example',
        hd: 'example.test',
        iat: nowSec,
        exp: nowSec + 300,
      },
    });

    await expect(service.identity.verifyGoogleLogin({ idToken })).resolves.toMatchObject({
      ok: true,
      verified: true,
      userId: 'google:subject-123',
      providerSubject: 'google:subject-123',
      sub: 'subject-123',
      email: 'Alice@Example.Test',
      emailVerified: true,
      hostedDomain: 'example.test',
    });
    await expect(
      service.identity.listIdentities({ userId: 'google:subject-123' }),
    ).resolves.toEqual({
      ok: true,
      subjects: ['google:subject-123'],
    });

    const router = createCloudflareRouter(service, {
      publishableKeyAuth: {
        authenticate: async () => ({
          ok: true,
          principal: {
            apiKeyId: 'publishable-key-a',
            orgId: 'org-a',
            projectId: 'project-a',
            envId: 'env-a',
            environmentId: 'project-env-a',
            scopes: ['wallets:create'],
          },
        }),
      },
      orgProjectEnv: {
        listEnvironments: async () => [
          {
            id: 'project-env-a',
            projectId: 'project-a',
            key: 'env-a',
            signingRootVersion: 'default',
            status: 'active',
          },
        ],
      },
    });
    const resolution = await callCf(router, {
      method: 'POST',
      path: '/auth/google/verify',
      origin: 'https://app.example.test',
      headers: { authorization: 'Bearer publishable-key' },
      body: {
        id_token: idToken,
        account_mode: 'register',
        project_environment_id: 'project-env-a',
      },
    });
    expect(resolution.status).toBe(200);
    expect(resolution.json).toMatchObject({
      ok: true,
      mode: 'register_started',
      providerSubject: 'google:subject-123',
      email: 'alice@example.test',
    });

    const loginWithoutEnrollment = await callCf(router, {
      method: 'POST',
      path: '/auth/google/verify',
      origin: 'https://app.example.test',
      headers: { authorization: 'Bearer publishable-key' },
      body: {
        id_token: idToken,
        account_mode: 'login',
        project_environment_id: 'project-env-a',
      },
    });
    expect(loginWithoutEnrollment.status).toBe(200);
    expect(loginWithoutEnrollment.json).toMatchObject({
      ok: true,
      mode: 'register_started',
      walletId: resolution.json.walletId,
      providerSubject: 'google:subject-123',
      email: 'alice@example.test',
    });

    const parts = idToken.split('.');
    const tampered = `${parts[0]}.${parts[1]}x.${parts[2]}`;
    await expect(service.identity.verifyGoogleLogin({ idToken: tampered })).resolves.toMatchObject({
      ok: false,
      verified: false,
    });
  } finally {
    restoreGoogleJwksFetchMock(originalFetch);
    cleanupTemporaryD1Database(tempDir);
  }
});
