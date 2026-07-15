import { expect, test } from '@playwright/test';
import { createThresholdEd25519SessionStore } from '../../packages/sdk-server-ts/src/core/ThresholdService/stores/SessionStore';
import {
  parseEd25519WalletSessionRecord,
  parseThresholdEd25519MpcSessionRecord,
} from '../../packages/sdk-server-ts/src/core/ThresholdService/validation';
import type { ThresholdEd25519MpcSessionRecord } from '../../packages/sdk-server-ts/src/core/ThresholdService/stores/SessionStore';
import type { NormalizedLogger } from '../../packages/sdk-server-ts/src/core/logger';
import { parseWebAuthnRpId } from '@shared/utils/domainIds';

const noopLogger: NormalizedLogger = {
  debug: () => {},
  info: () => {},
  warn: () => {},
  error: () => {},
};

function authorityScope() {
  const rpId = parseWebAuthnRpId('example.localhost');
  if (!rpId.ok) throw new Error('invalid rpId fixture');
  return { kind: 'passkey_rp' as const, rpId: rpId.value };
}

function createStore() {
  return createThresholdEd25519SessionStore({
    config: { kind: 'in-memory' },
    logger: noopLogger,
    isNode: true,
  });
}

function createMpcSessionRecord(): ThresholdEd25519MpcSessionRecord {
  return {
    expiresAtMs: Date.now() + 60_000,
    ecdsaThresholdKeyId: 'ecdsa-threshold-key',
    keyHandle: 'wallet-key-handle',
    relayerKeyId: 'relayer-key',
    purpose: 'threshold-ecdsa-sign',
    intentDigestB64u: 'intent-digest',
    signingDigestB64u: 'signing-digest',
    userId: 'wallet-user',
    authorityScope: authorityScope(),
    clientVerifyingShareB64u: 'client-verifying-share',
    participantIds: [1, 2],
    signingRootId: 'project-presign:test',
    signingRootVersion: 'root-v1',
    walletKeyVersion: 'v1',
    derivationVersion: 1,
  };
}

function delay(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

test.describe('threshold Ed25519 MPC session store', () => {
  test('rejects stale root rpId on persisted Ed25519 session records', () => {
    const authority = authorityScope();
    expect(parseThresholdEd25519MpcSessionRecord({ ...createMpcSessionRecord(), rpId: 'legacy-rp' }))
      .toBeNull();
    expect(
      parseEd25519WalletSessionRecord({
        expiresAtMs: Date.now() + 60_000,
        relayerKeyId: 'relayer-key',
        userId: 'wallet-user',
        walletId: 'wallet-user',
        nearAccountId: 'alice.testnet',
        nearEd25519SigningKeyId: 'ed25519:wallet-user:1',
        authorityScope: authority,
        rpId: 'legacy-rp',
        participantIds: [1, 2],
      }),
    ).toBeNull();
  });

  test('versioned MPC session claim preserves stale versions and consumes once', async () => {
    const store = createStore();
    const record = createMpcSessionRecord();

    await store.putMpcSession('mpc-versioned-1', record, 60_000);

    const read = await store.readMpcSession('mpc-versioned-1');
    expect(read?.record.signingDigestB64u).toBe(record.signingDigestB64u);
    expect(typeof read?.version).toBe('string');

    await expect(
      store.claimMpcSession('mpc-versioned-1', `${read?.version}:stale`),
    ).resolves.toEqual({ ok: false, code: 'version_mismatch' });
    await expect(store.readMpcSession('mpc-versioned-1')).resolves.toMatchObject({
      record: { signingDigestB64u: record.signingDigestB64u },
    });

    if (!read) throw new Error('expected versioned MPC read');
    const claimed = await store.claimMpcSession('mpc-versioned-1', read.version);
    expect(claimed).toMatchObject({ ok: true });
    if (!claimed.ok) throw new Error(`expected MPC claim, got ${claimed.code}`);
    expect(claimed.record.signingDigestB64u).toBe(record.signingDigestB64u);

    await expect(store.claimMpcSession('mpc-versioned-1', read.version)).resolves.toEqual({
      ok: false,
      code: 'not_found',
    });
  });

  test('versioned MPC session read and claim expire by store ttl', async () => {
    const store = createStore();
    const record = createMpcSessionRecord();

    await store.putMpcSession('mpc-versioned-expired', record, 1);
    await delay(10);

    await expect(store.readMpcSession('mpc-versioned-expired')).resolves.toBeNull();
    await expect(store.claimMpcSession('mpc-versioned-expired', 'any-version')).resolves.toEqual({
      ok: false,
      code: 'not_found',
    });
  });
});
