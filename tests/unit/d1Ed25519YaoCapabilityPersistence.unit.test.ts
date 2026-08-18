import { expect, test } from '@playwright/test';
import { D1WalletStore } from '../../packages/wallet-server/src/core/d1WalletStore';
import type {
  D1DatabaseLike,
  D1PreparedStatementLike,
} from '../../packages/wallet-server/src/storage/tenantRoute';
import {
  CloudflareD1RouterAbEd25519YaoCapabilityPersistence,
  ROUTER_AB_ED25519_YAO_CAPABILITY_REPLACEMENT_TABLE_V1,
} from '../../packages/wallet-server/src/router/cloudflare/d1/ed25519Yao/d1Ed25519YaoCapabilityPersistence';
import {
  buildYaoEd25519WalletSignerRecord,
  ed25519NearPublicKeyFromBytes,
} from '../../packages/wallet-server/src/router/cloudflare/d1/ed25519Yao/d1Ed25519YaoWalletSigner';
import { walletIdFromString } from '../../packages/shared-ts/src/utils/registrationIntent';
import { cleanupTemporaryD1Database, createTemporaryD1Database } from '../helpers/sqliteD1';
import { applySignerMigrations } from './helpers/cloudflareD1RouterApiAuthService.fixtures';
import { buildRouterAbEd25519YaoCapabilityReplacementFixture } from './helpers/routerAbEd25519YaoRecoveryRequestScoped.fixtures';

const TEST_SCOPE = {
  namespace: 'yao-capability-replacement-test',
  orgId: 'org-recovery',
  projectId: 'project-recovery',
  envId: 'test',
} as const;

type BatchFailureMode = 'none' | 'before_commit' | 'after_commit';

class OneShotBatchFailureDatabase implements D1DatabaseLike {
  private failed = false;

  constructor(
    private readonly delegate: D1DatabaseLike,
    private readonly mode: BatchFailureMode,
  ) {}

  prepare(query: string): D1PreparedStatementLike {
    return this.delegate.prepare(query);
  }

  async batch<T = unknown>(statements: readonly D1PreparedStatementLike[]): Promise<readonly T[]> {
    if (!this.failed && this.mode === 'before_commit') {
      this.failed = true;
      throw new Error('scripted D1 request loss before commit');
    }
    const result = await this.delegate.batch<T>(statements);
    if (!this.failed && this.mode === 'after_commit') {
      this.failed = true;
      throw new Error('scripted D1 response loss after commit');
    }
    return result;
  }

  async exec(query: string): Promise<unknown> {
    return await this.delegate.exec(query);
  }
}

test.describe('D1 Ed25519 Yao capability replacement receipts', () => {
  test('atomically replaces once, redelivers exact retries, and rejects operation conflicts', async () => {
    const temporary = createTemporaryD1Database();
    try {
      const fixture = buildRouterAbEd25519YaoCapabilityReplacementFixture();
      const walletStore = await seedWalletSigner(temporary.database);
      const persistence = createPersistence(temporary.database, walletStore);
      const operation = replacementOperation('activation-fingerprint-1');

      await expect(
        persistence.replaceActiveCapability({
          operation,
          previous: fixture.previous,
          next: fixture.next,
        }),
      ).resolves.toEqual({ ok: true, disposition: 'applied' });
      await expect(
        persistence.replaceActiveCapability({
          operation,
          previous: fixture.previous,
          next: fixture.next,
        }),
      ).resolves.toEqual({ ok: true, disposition: 'exact_retry' });

      const conflicting = await persistence.replaceActiveCapability({
        operation: replacementOperation('different-activation'),
        previous: fixture.previous,
        next: fixture.next,
      });
      expect(conflicting).toMatchObject({
        ok: false,
        disposition: 'rejected',
        code: 'operation_conflict',
      });
      await expect(receiptCount(temporary.database)).resolves.toBe(1);
      await expect(activeCapabilityVersion(walletStore)).resolves.toBe(
        'wallet_ed25519_yao_recovery_capability_v1',
      );
    } finally {
      cleanupTemporaryD1Database(temporary.tempDir);
    }
  });

  test('reconciles committed response loss and reports uncommitted request loss as uncertain', async () => {
    const committed = createTemporaryD1Database();
    try {
      const fixture = buildRouterAbEd25519YaoCapabilityReplacementFixture();
      const walletStore = await seedWalletSigner(committed.database);
      const persistence = createPersistence(
        new OneShotBatchFailureDatabase(committed.database, 'after_commit'),
        walletStore,
      );
      await expect(
        persistence.replaceActiveCapability({
          operation: replacementOperation('after-commit'),
          previous: fixture.previous,
          next: fixture.next,
        }),
      ).resolves.toEqual({ ok: true, disposition: 'exact_retry' });
      await expect(receiptCount(committed.database)).resolves.toBe(1);
    } finally {
      cleanupTemporaryD1Database(committed.tempDir);
    }

    const uncommitted = createTemporaryD1Database();
    try {
      const fixture = buildRouterAbEd25519YaoCapabilityReplacementFixture();
      const walletStore = await seedWalletSigner(uncommitted.database);
      const persistence = createPersistence(
        new OneShotBatchFailureDatabase(uncommitted.database, 'before_commit'),
        walletStore,
      );
      const operation = replacementOperation('before-commit');
      await expect(
        persistence.replaceActiveCapability({
          operation,
          previous: fixture.previous,
          next: fixture.next,
        }),
      ).resolves.toMatchObject({
        ok: false,
        disposition: 'uncertain',
        code: 'capability_persistence_uncertain',
      });
      await expect(receiptCount(uncommitted.database)).resolves.toBe(0);
      await expect(
        persistence.replaceActiveCapability({
          operation,
          previous: fixture.previous,
          next: fixture.next,
        }),
      ).resolves.toEqual({ ok: true, disposition: 'applied' });
      await expect(receiptCount(uncommitted.database)).resolves.toBe(1);
    } finally {
      cleanupTemporaryD1Database(uncommitted.tempDir);
    }
  });
});

async function seedWalletSigner(database: D1DatabaseLike): Promise<D1WalletStore> {
  await applySignerMigrations(database);
  const fixture = buildRouterAbEd25519YaoCapabilityReplacementFixture();
  const walletId = walletIdFromString(fixture.walletId);
  const walletStore = new D1WalletStore({
    database,
    ...TEST_SCOPE,
    ensureSchema: false,
  });
  await walletStore.putSigner(
    buildYaoEd25519WalletSignerRecord({
      walletId,
      nearAccountId: fixture.nearAccountId,
      nearEd25519SigningKeyId: fixture.nearSigningKeyId,
      thresholdSessionId: fixture.previous.admissionRequest.scope.threshold_session_id,
      signerSlot: fixture.previous.admissionRequest.application_binding.key_creation_signer_slot,
      publicKey: ed25519NearPublicKeyFromBytes(
        fixture.previous.activationResult.public_receipt.registered_public_key,
      ),
      signingWorkerId: fixture.signingWorkerId,
      keyVersion: 'router-ab-ed25519-yao-v1',
      participantIds: fixture.previous.admissionRequest.participant_ids,
      signingRootId: fixture.previous.admissionRequest.application_binding.signing_root_id,
      signingRootVersion: fixture.previous.admissionRequest.scope.root_share_epoch,
      runtimePolicyScope: fixture.previous.runtimePolicyScope,
      activeYaoCapability: fixture.previous,
      now: 1_900_000_000_000,
    }),
  );
  return walletStore;
}

function createPersistence(
  database: D1DatabaseLike,
  walletStore: D1WalletStore,
): CloudflareD1RouterAbEd25519YaoCapabilityPersistence {
  return new CloudflareD1RouterAbEd25519YaoCapabilityPersistence({
    database,
    scope: TEST_SCOPE,
    walletStore,
    ensureSchema: false,
    now: () => 1_900_000_001_000,
  });
}

function replacementOperation(operationFingerprint: string) {
  return {
    kind: 'router_ab_ed25519_yao_capability_replacement_operation_v1' as const,
    operationId: 'recovery-request-scoped-1',
    operationFingerprint,
  };
}

async function receiptCount(database: D1DatabaseLike): Promise<number> {
  const row = await database
    .prepare(
      `SELECT COUNT(*) AS count
         FROM ${ROUTER_AB_ED25519_YAO_CAPABILITY_REPLACEMENT_TABLE_V1}`,
    )
    .first<{ readonly count?: unknown }>();
  return Number(row?.count ?? 0);
}

async function activeCapabilityVersion(walletStore: D1WalletStore): Promise<string | null> {
  const fixture = buildRouterAbEd25519YaoCapabilityReplacementFixture();
  const signer = await walletStore.getEd25519SignerBySlot({
    walletId: walletIdFromString(fixture.walletId),
    signerSlot: 1,
  });
  return signer?.activeYaoCapability.version ?? null;
}
