import { expect, test } from '@playwright/test';
import { parseWalletRecoveryEnvelopeSetRecord } from '@shared/wallet-recovery';
import { CloudflareD1PasskeyCustodyEnvelopeStore } from '../../packages/wallet-server/src/router/cloudflare/d1/passkeyCustody/d1PasskeyCustodyEnvelopeStore';
import { CloudflareD1WalletCustodyCommitStore } from '../../packages/wallet-server/src/router/cloudflare/d1/passkeyCustody/d1WalletCustodyCommitStore';
import type { D1DatabaseLike } from '../../packages/wallet-server/src/storage/tenantRoute';
import type {
  PasskeyEnvelopeId,
  WalletId,
  WebAuthnCredentialIdB64u,
  WebAuthnRpId,
} from '../../packages/shared-ts/src/utils/domainIds';
import { cleanupTemporaryD1Database, createTemporaryD1Database } from '../helpers/sqliteD1';
import { buildWalletRecoveryBackupAcknowledgementV1 } from '../../packages/shared-ts/src/wallet-recovery/backupAcknowledgement';
import { applySignerMigrations } from './helpers/cloudflareD1RouterApiAuthService.fixtures';
import {
  CREDENTIAL_ID_B64U,
  DIGEST_B64U,
  ENVELOPE_ID,
  OTHER_WALLET_ID,
  RP_ID,
  WALLET_ID,
  passkeyCustodyEnvelope,
  rawEmailOtpFactor,
  rawWalletCustodySeedBinding,
  rawWalletRecoveryEnvelopeSet,
} from './helpers/passkeyCustodyEnvelope.fixtures';

/**
 * The registration commit writes a custody envelope and a recovery envelope set
 * together. These own the property that makes that worth a dedicated store: the
 * pair is all-or-nothing, so a wallet is never left working without the
 * recovery codes its owner believes they hold.
 */

const TEST_SCOPE = {
  namespace: 'wallet-custody-commit-test',
  orgId: 'org-a',
  projectId: 'project-a',
  envId: 'env-a',
} as const;

const LOCATOR = {
  walletId: WALLET_ID as WalletId,
  factor: {
    kind: 'passkey',
    rpId: RP_ID as WebAuthnRpId,
    credentialIdB64u: CREDENTIAL_ID_B64U as WebAuthnCredentialIdB64u,
  },
  envelopeId: ENVELOPE_ID as PasskeyEnvelopeId,
} as const;

function recoverySet(overrides: Record<string, unknown> = {}) {
  return parseWalletRecoveryEnvelopeSetRecord(rawWalletRecoveryEnvelopeSet(overrides), {
    expectedWalletId: String(overrides.walletId ?? WALLET_ID) as WalletId,
  });
}

function registrationCommit(input: {
  readonly envelope: ReturnType<typeof passkeyCustodyEnvelope>;
  readonly recoverySet: ReturnType<typeof recoverySet>;
}) {
  return {
    ...input,
    recoveryBackupAcknowledgement: buildWalletRecoveryBackupAcknowledgementV1({
      walletId: String(input.recoverySet.walletId),
      issuedAtMs: input.recoverySet.issuedAtMs,
      acknowledgedAtMs: input.recoverySet.issuedAtMs + 1,
    }),
  };
}

async function withStores(
  run: (stores: {
    commit: CloudflareD1WalletCustodyCommitStore;
    envelopes: CloudflareD1PasskeyCustodyEnvelopeStore;
    database: D1DatabaseLike;
  }) => Promise<void>,
): Promise<void> {
  const { database, tempDir } = createTemporaryD1Database();
  try {
    await applySignerMigrations(database);
    await run({
      commit: new CloudflareD1WalletCustodyCommitStore({ database, scope: TEST_SCOPE }),
      envelopes: new CloudflareD1PasskeyCustodyEnvelopeStore({ database, scope: TEST_SCOPE }),
      database,
    });
  } finally {
    cleanupTemporaryD1Database(tempDir);
  }
}

test('a registration commit stores the envelope and the recovery set together', async () => {
  await withStores(async ({ commit, envelopes }) => {
    const result = await commit.commitRegistration(
      registrationCommit({
        envelope: passkeyCustodyEnvelope(),
        recoverySet: recoverySet(),
      }),
    );
    expect(result.kind).toBe('committed');

    // The envelope is addressed by the same key the retrieval store uses, so a
    // committed envelope is one an authenticated lookup can actually find.
    const lookup = await envelopes.lookupEnvelope(LOCATOR);
    expect(lookup.kind).toBe('active');

    const stored = await commit.readRecoveryEnvelopeSet(WALLET_ID as WalletId);
    expect(stored?.record.manifestKekWraps.length).toBe(10);
    expect(stored?.record.entries[0]?.custodySecretKind).toBe('wallet_custody_seed_v1');
  });
});

test('a wallet that already has custody is never overwritten', async () => {
  await withStores(async ({ commit }) => {
    expect(
      (
        await commit.commitRegistration(
          registrationCommit({
            envelope: passkeyCustodyEnvelope(),
            recoverySet: recoverySet(),
          }),
        )
      ).kind,
    ).toBe('committed');

    // A second ceremony for the same wallet would strand every key the first
    // seed controls, so both keys refuse to be replaced.
    const again = await commit.commitRegistration(
      registrationCommit({
        envelope: passkeyCustodyEnvelope(),
        recoverySet: recoverySet(),
      }),
    );
    expect(again.kind).toBe('already_exists');
  });
});

test('a commit whose recovery set already exists writes no envelope', async () => {
  await withStores(async ({ commit, envelopes }) => {
    // First wallet registers with a passkey factor.
    await commit.commitRegistration(
      registrationCommit({
        envelope: passkeyCustodyEnvelope(),
        recoverySet: recoverySet(),
      }),
    );

    // A second ceremony for the same wallet under a *different* factor: its
    // envelope key is free, but the wallet-scoped recovery-set key is taken.
    const otherFactorEnvelope = passkeyCustodyEnvelope({
      envelopeId: 'passkey-envelope-2',
      factor: rawEmailOtpFactor(),
    });
    const conflicted = await commit.commitRegistration(
      registrationCommit({
        envelope: otherFactorEnvelope,
        recoverySet: recoverySet(),
      }),
    );
    expect(conflicted.kind).toBe('custody_already_established');

    // The batch rolled back: no envelope was written for the second factor.
    const orphan = await envelopes.lookupEnvelope({
      walletId: WALLET_ID as WalletId,
      factor: {
        kind: 'email_otp',
        enrollmentId: 'enrollment-1',
        enrollmentSealKeyVersion: 'seal-v1',
      },
      envelopeId: 'passkey-envelope-2' as PasskeyEnvelopeId,
    });
    expect(orphan.kind).toBe('missing');
  });
});

test('a mismatched pair is refused before anything is written', async () => {
  await withStores(async ({ commit, envelopes }) => {
    const otherWalletSet = await commit.commitRegistration(
      registrationCommit({
        envelope: passkeyCustodyEnvelope(),
        recoverySet: recoverySet({ walletId: OTHER_WALLET_ID }),
      }),
    );
    expect(otherWalletSet.kind).toBe('inconsistent');

    expect((await envelopes.lookupEnvelope(LOCATOR)).kind).toBe('missing');
    expect(await commit.readRecoveryEnvelopeSet(WALLET_ID as WalletId)).toBeNull();
  });
});

test('a recovery set is readable only under the wallet it names', async () => {
  await withStores(async ({ commit }) => {
    await commit.commitRegistration(
      registrationCommit({
        envelope: passkeyCustodyEnvelope(),
        recoverySet: recoverySet(),
      }),
    );
    expect(await commit.readRecoveryEnvelopeSet(WALLET_ID as WalletId)).not.toBeNull();
    expect(await commit.readRecoveryEnvelopeSet(OTHER_WALLET_ID as WalletId)).toBeNull();
  });
});

test('a backup acknowledgement round-trips through the custody record store', async () => {
  await withStores(async ({ commit }) => {
    const acknowledgement = buildWalletRecoveryBackupAcknowledgementV1({
      walletId: WALLET_ID,
      issuedAtMs: 1_000,
      acknowledgedAtMs: 2_000,
    });

    expect(await commit.writeBackupAcknowledgement(acknowledgement)).toEqual({ kind: 'stored' });
    expect(await commit.readBackupAcknowledgement(WALLET_ID as WalletId)).toEqual(acknowledgement);
  });
});

test('two wallets keep separate custody', async () => {
  await withStores(async ({ commit }) => {
    await commit.commitRegistration(
      registrationCommit({
        envelope: passkeyCustodyEnvelope(),
        recoverySet: recoverySet(),
      }),
    );
    const second = await commit.commitRegistration(
      registrationCommit({
        envelope: passkeyCustodyEnvelope({ walletId: OTHER_WALLET_ID }),
        recoverySet: recoverySet({ walletId: OTHER_WALLET_ID }),
      }),
    );
    expect(second.kind).toBe('committed');

    const first = await commit.readRecoveryEnvelopeSet(WALLET_ID as WalletId);
    const other = await commit.readRecoveryEnvelopeSet(OTHER_WALLET_ID as WalletId);
    expect(String(first?.record.walletId)).toBe(WALLET_ID);
    expect(String(other?.record.walletId)).toBe(OTHER_WALLET_ID);
  });
});
