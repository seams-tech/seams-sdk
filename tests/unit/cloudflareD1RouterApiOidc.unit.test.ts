import { expect, test } from '@playwright/test';
import { createCloudflareD1RouterApiAuthService } from '../../packages/sdk-server-ts/src/router/cloudflare/d1RouterApiAuthService';
import {
  cleanupTemporaryD1Database,
  createTemporaryD1Database,
} from '../helpers/sqliteD1';
import {
  applySignerMigrations,
  generateGoogleOidcTestKey,
  insertIdentity,
  installGoogleJwksFetchMock,
  installOidcJwksFetchMock,
  jsonBase64Url,
  makeSignedGoogleIdToken,
  restoreGoogleJwksFetchMock,
  restoreOidcJwksFetchMock,
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
    const nowSec = Math.floor(Date.now() / 1000);
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

    const verified = await service.identity.verifyGoogleLogin({ idToken });
    expect(verified).toMatchObject({
      ok: true,
      verified: true,
      userId: 'google:subject-123',
      providerSubject: 'google:subject-123',
      sub: 'subject-123',
      email: 'Alice@Example.Test',
      emailVerified: true,
      hostedDomain: 'example.test',
    });
    await expect(service.identity.listIdentities({ userId: 'google:subject-123' })).resolves.toEqual({
      ok: true,
      subjects: ['google:subject-123'],
    });

    const parts = idToken.split('.');
    const tamperedPayloadB64u = jsonBase64Url({
      iss: 'https://accounts.google.com',
      aud: 'google-client',
      sub: 'subject-999',
      iat: nowSec,
      exp: nowSec + 300,
    });
    const tampered = `${parts[0]}.${tamperedPayloadB64u}.${parts[2]}`;
    await expect(service.identity.verifyGoogleLogin({ idToken: tampered })).resolves.toMatchObject({
      ok: false,
      verified: false,
      code: 'invalid_signature',
    });
  } finally {
    restoreGoogleJwksFetchMock(originalFetch);
    cleanupTemporaryD1Database(tempDir);
  }
});

test('Cloudflare D1 Router API auth service verifies generic OIDC exchange tokens', async () => {
  const { database, tempDir } = createTemporaryD1Database();
  const key = await generateGoogleOidcTestKey('oidc-kid-success');
  const jwksUrl = 'https://issuer.example.com/.well-known/jwks.json';
  const originalFetch = installOidcJwksFetchMock({
    jwksUrl,
    publicJwk: key.publicJwk,
  });
  try {
    await applySignerMigrations(database);
    const scope = {
      namespace: 'seams-local-test',
      orgId: 'org-a',
      projectId: 'project-a',
      envId: 'env-a',
    };
    const providerSubject = 'oidc:https://issuer.example.com:subject-123';
    await insertIdentity({
      database,
      namespace: scope.namespace,
      orgId: scope.orgId,
      projectId: scope.projectId,
      envId: scope.envId,
      userId: 'linked-oidc-wallet.testnet',
      subject: providerSubject,
    });
    const service = createCloudflareD1RouterApiAuthService({
      database,
      namespace: scope.namespace,
      orgId: scope.orgId,
      projectId: scope.projectId,
      envId: scope.envId,
      relayerAccount: 'relay.local',
      accountIdDerivationSecret: 'test-account-id-derivation-secret',
      oidcExchange: {
        clockSkewSec: 0,
        issuers: [
          {
            issuer: 'https://issuer.example.com/',
            audiences: ['wallet-app'],
            jwksUrl,
          },
        ],
      },
    });
    const nowSec = Math.floor(Date.now() / 1000);
    const token = await makeSignedGoogleIdToken({
      privateKey: key.privateKey,
      kid: key.kid,
      payload: {
        iss: 'https://issuer.example.com',
        aud: 'wallet-app',
        sub: 'subject-123',
        email: 'oidc-user@example.test',
        name: 'OIDC User',
        given_name: 'OIDC',
        family_name: 'User',
        iat: nowSec,
        exp: nowSec + 300,
      },
    });

    await expect(service.identity.verifyOidcJwtExchange({ token })).resolves.toMatchObject({
      ok: true,
      verified: true,
      userId: 'linked-oidc-wallet.testnet',
      providerSubject,
      iss: 'https://issuer.example.com',
      aud: ['wallet-app'],
      sub: 'subject-123',
      email: 'oidc-user@example.test',
      name: 'OIDC User',
      given_name: 'OIDC',
      family_name: 'User',
    });
    await expect(service.identity.listIdentities({ userId: 'linked-oidc-wallet.testnet' })).resolves.toEqual(
      {
        ok: true,
        subjects: [providerSubject],
      },
    );

    const parts = token.split('.');
    const tamperedPayloadB64u = jsonBase64Url({
      iss: 'https://issuer.example.com',
      aud: 'wallet-app',
      sub: 'subject-999',
      iat: nowSec,
      exp: nowSec + 300,
    });
    const tampered = `${parts[0]}.${tamperedPayloadB64u}.${parts[2]}`;
    await expect(service.identity.verifyOidcJwtExchange({ token: tampered })).resolves.toMatchObject({
      ok: false,
      verified: false,
      code: 'invalid_signature',
    });
  } finally {
    restoreOidcJwksFetchMock(originalFetch);
    cleanupTemporaryD1Database(tempDir);
  }
});
