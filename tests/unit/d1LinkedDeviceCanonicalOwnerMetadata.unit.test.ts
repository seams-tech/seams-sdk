import { expect, test } from '@playwright/test';
import { deriveWebAuthnAuthenticatorDeviceInfo } from '../../packages/shared-ts/src/utils/webauthnDeviceInfo';
import { D1LinkedDeviceCanonicalOwnerAuthMetadataSourceV1 } from '../../packages/sdk-server-ts/src/router/cloudflare/d1/deviceLinking/d1LinkedDeviceManagementStore';
import {
  D1LinkedDeviceOwnerAuthBindingStoreV1,
  assertOwnerAuthBindingBatchApplied,
} from '../../packages/sdk-server-ts/src/router/cloudflare/d1/deviceLinking/d1LinkedDeviceOwnerAuthBindingStore';
import type { D1LinkedDeviceSessionScopeV1 } from '../../packages/sdk-server-ts/src/router/cloudflare/d1/deviceLinking/d1LinkedDeviceSessionStore';
import type { D1ResultLike } from '../../packages/sdk-server-ts/src/storage/tenantRoute';
import {
  applyD1MigrationFiles,
  cleanupTemporaryD1Database,
  createTemporaryD1Database,
  listD1MigrationFiles,
} from '../helpers/sqliteD1';
import {
  insertWalletAuthMethod,
  insertWebAuthn,
} from './helpers/cloudflareD1RouterApiAuthService.fixtures';
import {
  buildLinkedOwnerEmailOtpBindingFixtureV1,
  buildLinkedOwnerPasskeyBindingFixtureV1,
} from './helpers/linkedOwnerAuthBinding.fixtures';

const scope: D1LinkedDeviceSessionScopeV1 = {
  namespace: 'signer',
  orgId: 'org_metadata_projection',
  projectId: 'project_metadata_projection',
  envId: 'env_metadata_projection',
};

test('projects one linked enrollment through its exact canonical passkey binding', async () => {
  const temporary = createTemporaryD1Database();
  try {
    await applyD1MigrationFiles(temporary.database, listD1MigrationFiles('d1-signer'));
    const binding = buildLinkedOwnerPasskeyBindingFixtureV1();
    if (binding.factor.kind !== 'passkey') throw new Error('expected passkey binding');
    await insertWalletAuthMethod({
      database: temporary.database,
      ...scope,
      record: {
        version: 'wallet_auth_method_v1',
        kind: 'passkey',
        status: 'active',
        walletId: String(binding.walletId),
        rpId: String(binding.factor.rpId),
        credentialIdB64u: String(binding.factor.credentialIdB64u),
        credentialPublicKeyB64u: 'credential-public-key',
        counter: 0,
        createdAtMs: binding.createdAtMs,
        updatedAtMs: binding.updatedAtMs,
      },
    });
    const device = deriveWebAuthnAuthenticatorDeviceInfo({
      userAgent:
        'Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 Version/18.0 Mobile/15E148 Safari/604.1',
      aaguid: 'fbfc3007-154e-4ecc-8c0b-6e020557d7bd',
      backedUp: true,
      transports: ['internal'],
    });
    await insertWebAuthn({
      database: temporary.database,
      ...scope,
      userId: String(binding.walletId),
      rpId: String(binding.factor.rpId),
      credentialIdB64u: String(binding.factor.credentialIdB64u),
      credentialPublicKeyB64u: 'credential-public-key',
      deviceInfo: device,
    });
    const bindingStore = new D1LinkedDeviceOwnerAuthBindingStoreV1({
      database: temporary.database,
      scope,
    });
    assertOwnerAuthBindingBatchApplied(
      await temporary.database.batch<D1ResultLike>([bindingStore.buildInsertV1(binding).statement]),
      1,
    );

    const metadata = await new D1LinkedDeviceCanonicalOwnerAuthMetadataSourceV1({
      database: temporary.database,
      scope,
      tenantId: binding.tenantId,
    }).readLinkedDeviceMetadataV1({
      walletId: binding.walletId,
      enrollmentId: binding.enrollmentId,
      deviceId: binding.deviceId,
    });

    expect(metadata).toEqual({
      kind: 'passkey',
      walletAuthMethodId: binding.walletAuthMethodId,
      credentialIdB64u: binding.factor.credentialIdB64u,
      device,
    });
  } finally {
    cleanupTemporaryD1Database(temporary.tempDir);
  }
});

test('projects an Email OTP owner binding without WebAuthn metadata', async () => {
  const temporary = createTemporaryD1Database();
  try {
    await applyD1MigrationFiles(temporary.database, listD1MigrationFiles('d1-signer'));
    const binding = buildLinkedOwnerEmailOtpBindingFixtureV1();
    if (binding.factor.kind !== 'email_otp') throw new Error('expected Email OTP binding');
    await insertWalletAuthMethod({
      database: temporary.database,
      ...scope,
      record: {
        version: 'wallet_auth_method_v1',
        kind: 'email_otp',
        status: 'active',
        walletId: String(binding.walletId),
        emailHashHex: binding.factor.emailHashHex,
        registrationAuthorityId: binding.factor.registrationAuthorityId,
        createdAtMs: binding.createdAtMs,
        updatedAtMs: binding.updatedAtMs,
      },
    });
    const bindingStore = new D1LinkedDeviceOwnerAuthBindingStoreV1({
      database: temporary.database,
      scope,
    });
    assertOwnerAuthBindingBatchApplied(
      await temporary.database.batch<D1ResultLike>([bindingStore.buildInsertV1(binding).statement]),
      1,
    );

    const metadata = await new D1LinkedDeviceCanonicalOwnerAuthMetadataSourceV1({
      database: temporary.database,
      scope,
      tenantId: binding.tenantId,
    }).readLinkedDeviceMetadataV1({
      walletId: binding.walletId,
      enrollmentId: binding.enrollmentId,
      deviceId: binding.deviceId,
    });

    expect(metadata).toEqual({
      kind: 'email_otp',
      walletAuthMethodId: binding.walletAuthMethodId,
    });
  } finally {
    cleanupTemporaryD1Database(temporary.tempDir);
  }
});
