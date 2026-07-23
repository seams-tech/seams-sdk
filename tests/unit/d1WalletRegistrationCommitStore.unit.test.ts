import { expect, test } from '@playwright/test';
import { D1WalletStore } from '../../packages/sdk-server-ts/src/core/d1WalletStore';
import type {
  WalletEd25519SignerRecord,
  WalletEcdsaSignerRecord,
  WalletRecord,
} from '../../packages/sdk-server-ts/src/core/WalletStore';
import { CloudflareD1WalletRegistrationCommitStore } from '../../packages/sdk-server-ts/src/router/cloudflare/d1WalletRegistrationCommitStore';
import { CloudflareD1WebAuthnStore } from '../../packages/sdk-server-ts/src/router/cloudflare/d1WebAuthnStore';
import type { D1DatabaseLike } from '../../packages/sdk-server-ts/src/storage/tenantRoute';
import { parseWebAuthnRpId } from '../../packages/shared-ts/src/utils/domainIds';
import {
  walletIdFromString,
  type RegistrationAuthority,
  type WalletId,
} from '../../packages/shared-ts/src/utils/registrationIntent';
import { unknownWebAuthnAuthenticatorDeviceInfo } from '../../packages/shared-ts/src/utils/webauthnDeviceInfo';
import { cleanupTemporaryD1Database, createTemporaryD1Database } from '../helpers/sqliteD1';
import { buildEd25519YaoCapabilityFixture } from '../helpers/ed25519YaoCapabilityFixtures';
import { applySignerMigrations } from './helpers/cloudflareD1RouterApiAuthService.fixtures';
import { createWalletEcdsaSignerRecord } from './helpers/walletRegistrationSigner.fixtures';

const TEST_SCOPE = {
  namespace: 'registration-commit-test',
  orgId: 'org-a',
  projectId: 'project-a',
  envId: 'env-a',
} as const;

function testRpId() {
  const parsed = parseWebAuthnRpId('example.com');
  if (!parsed.ok) throw new Error(parsed.error.message);
  return parsed.value;
}

function testWalletRecord(walletId: WalletId, now: number): WalletRecord {
  return {
    version: 'wallet_v1',
    walletId,
    createdAtMs: now,
    updatedAtMs: now,
  };
}

function testEd25519Signer(walletId: WalletId, now: number): WalletEd25519SignerRecord {
  const nearAccountId = '0000000000000000000000000000000000000000000000000000000000000001';
  const runtimePolicyScope = {
    orgId: 'org-a',
    projectId: 'project-a',
    envId: 'env-a',
    signingRootVersion: 'root-v1',
  } as const;
  const activeYao = buildEd25519YaoCapabilityFixture({
    walletId,
    nearAccountId,
    nearEd25519SigningKeyId: 'near-ed25519-key-1',
    thresholdSessionId: 'threshold-session-1',
    signerSlot: 1,
    signingWorkerId: 'yao-signing-worker-a',
    participantIds: [1, 2],
    runtimePolicyScope,
    seed: 61,
  });
  return {
    version: 'wallet_signer_ed25519_v1',
    walletId,
    signerId: `ed25519:${nearAccountId}:1`,
    nearAccountId,
    nearEd25519SigningKeyId: 'near-ed25519-key-1',
    thresholdSessionId: 'threshold-session-1',
    signerSlot: 1,
    publicKey: activeYao.publicKey,
    signingWorkerId: 'yao-signing-worker-a',
    keyVersion: 'yao-key-v1',
    recoveryExportCapable: true,
    participantIds: [1, 2],
    signingRootId: 'project-a:env-a',
    signingRootVersion: 'root-v1',
    runtimePolicyScope,
    activeYaoCapability: activeYao.capability,
    createdAtMs: now,
    updatedAtMs: now,
  };
}

function testEcdsaSigner(walletId: WalletId, now: number): WalletEcdsaSignerRecord {
  return createWalletEcdsaSignerRecord({ walletId, now });
}

function testPasskeyAuthority(walletId: WalletId): RegistrationAuthority {
  return {
    kind: 'passkey',
    walletId,
    rpId: testRpId(),
    credentialIdB64u: 'credential-a',
    credentialPublicKeyB64u: 'credential-public-key-a',
    counter: 0,
    device: unknownWebAuthnAuthenticatorDeviceInfo(),
    registrationIntentDigestB64u: 'registration-intent-digest-a',
  };
}

async function countRows(database: D1DatabaseLike, table: string): Promise<number> {
  const row = await database.prepare(`SELECT COUNT(*) AS count FROM ${table}`).first<{
    readonly count?: unknown;
  }>();
  return Number(row?.count || 0);
}

test('D1 registration commit stores a mixed Ed25519 and ECDSA wallet atomically', async () => {
  const { database, tempDir } = createTemporaryD1Database();
  try {
    await applySignerMigrations(database);
    const walletId = walletIdFromString('amber-atlas-abcdef');
    const now = 1_900_000_000_000;
    const store = new CloudflareD1WalletRegistrationCommitStore({
      database,
      ...TEST_SCOPE,
    });

    await store.commit({
      wallet: testWalletRecord(walletId, now),
      walletSigners: [testEd25519Signer(walletId, now), testEcdsaSigner(walletId, now)],
      authority: testPasskeyAuthority(walletId),
      now,
    });

    await expect(countRows(database, 'wallets')).resolves.toBe(1);
    await expect(countRows(database, 'wallet_signers')).resolves.toBe(2);
    await expect(countRows(database, 'wallet_auth_methods')).resolves.toBe(1);
    const walletStore = new D1WalletStore({
      database,
      ...TEST_SCOPE,
      ensureSchema: false,
    });
    await expect(walletStore.listEd25519Signers()).resolves.toMatchObject([
      {
        walletId,
        activeYaoCapability: {
          version: 'wallet_ed25519_yao_registration_capability_v1',
          nearAccountId:
            '0000000000000000000000000000000000000000000000000000000000000001',
        },
      },
    ]);
    await expect(countRows(database, 'webauthn_authenticators')).resolves.toBe(1);
    await expect(countRows(database, 'webauthn_credential_bindings')).resolves.toBe(1);

    const webAuthnStore = new CloudflareD1WebAuthnStore({
      database,
      ...TEST_SCOPE,
    });
    await expect(
      webAuthnStore.readAuthenticator({
        userId: walletId,
        credentialIdB64u: 'credential-a',
      }),
    ).resolves.toMatchObject({
      credentialIdB64u: 'credential-a',
      credentialPublicKeyB64u: 'credential-public-key-a',
      counter: 0,
    });

    const bindingRow = await database
      .prepare('SELECT record_json FROM webauthn_credential_bindings LIMIT 1')
      .first<{ readonly record_json?: unknown }>();
    expect(JSON.parse(String(bindingRow?.record_json))).toMatchObject({
      version: 'webauthn_credential_binding_v1',
      rpId: 'example.com',
      credentialIdB64u: 'credential-a',
      userId: walletId,
      nearEd25519SigningKeyId: 'near-ed25519-key-1',
      signerSlot: 1,
      relayerKeyId: 'yao-signing-worker-a',
      participantIds: [1, 2],
    });
  } finally {
    cleanupTemporaryD1Database(tempDir);
  }
});

test('D1 registration commit rolls back every mixed-wallet record when one signer fails', async () => {
  const { database, tempDir } = createTemporaryD1Database();
  try {
    await applySignerMigrations(database);
    const walletId = walletIdFromString('brisk-bloom-abcdef');
    const now = 1_900_000_000_000;
    // Deliberately corrupt valid factory output: updatedAtMs earlier than
    // createdAtMs violates the wallet_signers CHECK (updated_at_ms >= created_at_ms).
    const invalidEcdsaSigner = {
      ...createWalletEcdsaSignerRecord({ walletId, now }),
      updatedAtMs: now - 1,
    };
    const store = new CloudflareD1WalletRegistrationCommitStore({
      database,
      ...TEST_SCOPE,
    });

    await expect(
      store.commit({
        wallet: testWalletRecord(walletId, now),
        walletSigners: [testEd25519Signer(walletId, now), invalidEcdsaSigner],
        authority: testPasskeyAuthority(walletId),
        now,
      }),
    ).rejects.toThrow(/CHECK constraint failed/);

    await expect(countRows(database, 'wallets')).resolves.toBe(0);
    await expect(countRows(database, 'wallet_signers')).resolves.toBe(0);
    await expect(countRows(database, 'wallet_auth_methods')).resolves.toBe(0);
    await expect(countRows(database, 'webauthn_authenticators')).resolves.toBe(0);
    await expect(countRows(database, 'webauthn_credential_bindings')).resolves.toBe(0);
  } finally {
    cleanupTemporaryD1Database(tempDir);
  }
});
