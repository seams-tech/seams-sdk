import { expect, test } from '@playwright/test';
import { createThresholdEd25519SessionStore } from '../../packages/sdk-server-ts/src/core/ThresholdService/stores/SessionStore';
import type {
  ThresholdEd25519MpcSessionRecord,
  RouterAbEd25519PresignExpectedScope,
  RouterAbEd25519PresignRecord,
} from '../../packages/sdk-server-ts/src/core/ThresholdService/stores/SessionStore';
import type { NormalizedLogger } from '../../packages/sdk-server-ts/src/core/logger';

const noopLogger: NormalizedLogger = {
  debug: () => {},
  info: () => {},
  warn: () => {},
  error: () => {},
};

const runtimePolicyScope = {
  orgId: 'org-presign',
  projectId: 'project-presign',
  envId: 'test',
  signingRootVersion: 'root-v1',
};

function createStore() {
  return createThresholdEd25519SessionStore({
    config: { kind: 'in-memory' },
    logger: noopLogger,
    isNode: true,
  });
}

function createPresignRecord(): RouterAbEd25519PresignRecord {
  return {
    kind: 'router_ab_ed25519_presign_record_v2',
    expiresAtMs: Date.now() + 60_000,
    thresholdSessionId: 'threshold-session',
    signingGrantId: 'signing-grant',
    relayerKeyId: 'relayer-key',
    nearAccountId: 'alice.testnet',
    nearNetworkId: 'testnet',
    signerPublicKey: 'ed25519-public-key',
    rpcPolicyId: 'ed25519-presign-finalize',
    rpId: 'example.localhost',
    runtimePolicyScope,
    protocolVersion: 'ed25519_frost_2p_presign_v1',
    participantIds: [1, 2],
    groupPublicKey: 'group-public-key',
    clientVerifyingShareB64u: 'client-verifying-share',
    clientCommitments: { hiding: 'client-hiding', binding: 'client-binding' },
    relayerCommitments: { hiding: 'relayer-hiding', binding: 'relayer-binding' },
    relayerVerifyingShareB64u: 'relayer-verifying-share',
    relayerNoncesB64u: 'relayer-nonces',
  };
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
    rpId: 'example.localhost',
    clientVerifyingShareB64u: 'client-verifying-share',
    participantIds: [1, 2],
    signingRootId: 'project-presign:test',
    signingRootVersion: 'root-v1',
    walletKeyVersion: 'v1',
    derivationVersion: 1,
  };
}

function createPresignRecordForWalletSession(
  signingGrantId: string,
): RouterAbEd25519PresignRecord {
  return { ...createPresignRecord(), signingGrantId };
}

function expectedScopeForRecord(
  record: RouterAbEd25519PresignRecord,
): RouterAbEd25519PresignExpectedScope {
  return {
    thresholdSessionId: record.thresholdSessionId,
    signingGrantId: record.signingGrantId,
    relayerKeyId: record.relayerKeyId,
    nearAccountId: record.nearAccountId,
    nearNetworkId: record.nearNetworkId,
    signerPublicKey: record.signerPublicKey,
    rpcPolicyId: record.rpcPolicyId,
    rpId: record.rpId,
    runtimePolicyScope: record.runtimePolicyScope,
    participantIds: record.participantIds,
    groupPublicKey: record.groupPublicKey,
  };
}

test.describe('threshold Ed25519 presign session store', () => {
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
    await new Promise((resolve) => setTimeout(resolve, 10));

    await expect(store.readMpcSession('mpc-versioned-expired')).resolves.toBeNull();
    await expect(store.claimMpcSession('mpc-versioned-expired', 'any-version')).resolves.toEqual({
      ok: false,
      code: 'not_found',
    });
  });

  test('atomically consumes a matching presign once', async () => {
    const store = createStore();
    const record = createPresignRecord();
    const expectedScope = expectedScopeForRecord(record);

    await store.putPresign('presign-1', record, 60_000);

    const taken = await store.takePresignForFinalize('presign-1', expectedScope);
    expect(taken).toMatchObject({ ok: true });
    if (!taken.ok) throw new Error(`expected presign consume, got ${taken.code}`);
    expect(taken.record.thresholdSessionId).toBe(record.thresholdSessionId);

    await expect(store.takePresignForFinalize('presign-1', expectedScope)).resolves.toEqual({
      ok: false,
      code: 'not_found',
    });
  });

  test('preserves the record when finalize scope does not match', async () => {
    const store = createStore();
    const record = createPresignRecord();
    const expectedScope = expectedScopeForRecord(record);

    await store.putPresign('presign-2', record, 60_000);

    await expect(
      store.takePresignForFinalize('presign-2', {
        ...expectedScope,
        signerPublicKey: 'other-ed25519-public-key',
      }),
    ).resolves.toEqual({ ok: false, code: 'scope_mismatch' });

    const taken = await store.takePresignForFinalize('presign-2', expectedScope);
    expect(taken).toMatchObject({ ok: true });
  });

  test('expires unused presigns by store ttl', async () => {
    const store = createStore();
    const record = createPresignRecord();

    await store.putPresign('presign-3', record, 1);
    await new Promise((resolve) => setTimeout(resolve, 10));

    await expect(
      store.takePresignForFinalize('presign-3', expectedScopeForRecord(record)),
    ).resolves.toEqual({ ok: false, code: 'expired' });
  });

  test('enforces per-signing-grant outstanding presign capacity', async () => {
    const store = createStore();
    const record = createPresignRecord();

    await expect(
      store.putPresignWithCapacity('presign-4a', record, 60_000, {
        signingGrantMax: 1,
        globalMax: 10,
      }),
    ).resolves.toEqual({ ok: true });

    await expect(
      store.putPresignWithCapacity('presign-4b', record, 60_000, {
        signingGrantMax: 1,
        globalMax: 10,
      }),
    ).resolves.toEqual({ ok: false, code: 'capacity_exceeded' });

    await store.takePresignForFinalize('presign-4a', expectedScopeForRecord(record));

    await expect(
      store.putPresignWithCapacity('presign-4c', record, 60_000, {
        signingGrantMax: 1,
        globalMax: 10,
      }),
    ).resolves.toEqual({ ok: true });
  });

  test('enforces global outstanding presign capacity across wallet sessions', async () => {
    const store = createStore();
    const first = createPresignRecordForWalletSession('signing-grant-a');
    const second = createPresignRecordForWalletSession('signing-grant-b');

    await expect(
      store.putPresignWithCapacity('presign-5a', first, 60_000, {
        signingGrantMax: 2,
        globalMax: 1,
      }),
    ).resolves.toEqual({ ok: true });

    await expect(
      store.putPresignWithCapacity('presign-5b', second, 60_000, {
        signingGrantMax: 2,
        globalMax: 1,
      }),
    ).resolves.toEqual({ ok: false, code: 'capacity_exceeded' });
  });

  test('prunes expired presigns before capacity checks', async () => {
    const store = createStore();
    const record = createPresignRecord();

    await expect(
      store.putPresignWithCapacity('presign-6a', record, 1, {
        signingGrantMax: 1,
        globalMax: 1,
      }),
    ).resolves.toEqual({ ok: true });
    await new Promise((resolve) => setTimeout(resolve, 10));

    await expect(
      store.putPresignWithCapacity('presign-6b', record, 60_000, {
        signingGrantMax: 1,
        globalMax: 1,
      }),
    ).resolves.toEqual({ ok: true });
  });

  test('reports outstanding capacity before refill creates nonce material', async () => {
    const store = createStore();
    const record = createPresignRecord();

    await expect(
      store.checkPresignCapacity(record.signingGrantId, {
        signingGrantMax: 1,
        globalMax: 1,
      }),
    ).resolves.toEqual({ ok: true });

    await store.putPresignWithCapacity('presign-preflight-full', record, 60_000, {
      signingGrantMax: 1,
      globalMax: 1,
    });

    await expect(
      store.checkPresignCapacity(record.signingGrantId, {
        signingGrantMax: 1,
        globalMax: 1,
      }),
    ).resolves.toEqual({ ok: false, code: 'capacity_exceeded' });

    await store.takePresignForFinalize('presign-preflight-full', expectedScopeForRecord(record));

    await expect(
      store.checkPresignCapacity(record.signingGrantId, {
        signingGrantMax: 1,
        globalMax: 1,
      }),
    ).resolves.toEqual({ ok: true });
  });

  test('keeps presign refill rate counters separate from presign pruning', async () => {
    const store = createStore();
    const record = createPresignRecord();
    const bucket = {
      kind: 'wallet_signing_session' as const,
      key: record.signingGrantId,
    };
    const policy = { windowMs: 60_000, maxCost: 2 };

    await expect(store.consumePresignRefillRateLimit(bucket, policy, 1)).resolves.toEqual({
      ok: true,
    });
    await expect(
      store.checkPresignCapacity(record.signingGrantId, {
        signingGrantMax: 1,
        globalMax: 1,
      }),
    ).resolves.toEqual({ ok: true });
    await expect(store.consumePresignRefillRateLimit(bucket, policy, 2)).resolves.toEqual({
      ok: false,
      code: 'rate_limited',
    });
  });

  test('allows only one concurrent finalize consume for a presign', async () => {
    const store = createStore();
    const record = createPresignRecord();
    const expectedScope = expectedScopeForRecord(record);

    await store.putPresignWithCapacity('presign-7', record, 60_000, {
      signingGrantMax: 2,
      globalMax: 2,
    });

    const results = await Promise.all([
      store.takePresignForFinalize('presign-7', expectedScope),
      store.takePresignForFinalize('presign-7', expectedScope),
    ]);

    expect(results.filter((result) => result.ok)).toHaveLength(1);
    expect(results.filter((result) => !result.ok)).toEqual([{ ok: false, code: 'not_found' }]);
  });
});
