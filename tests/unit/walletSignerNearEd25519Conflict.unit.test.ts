import { expect, test } from '@playwright/test';
import { deleteConflictingNearEd25519SignerRows } from '@/core/indexedDB/seamsWalletDB/repositories';
import { SEAMS_WALLET_INDEXES } from '@/core/indexedDB/schemaNames';

/**
 * The unique indexes on the wallet signer store key on the NEAR signing key id
 * and the signer slot, but the row's own primary key is derived from the chain,
 * account, and signer id. Those can disagree — a wallet key re-projected under a
 * different signer id is a new row naming the same NEAR key — and IndexedDB
 * rejects the write rather than replacing the row. That surfaces as a login that
 * cannot open the wallet, so the earlier mirror has to be superseded first.
 */
type FakeRow = {
  readonly wallet_signer_id: string;
  readonly wallet_id: string;
  readonly kind: string;
  readonly near_ed25519_signing_key_id?: string;
  readonly near_signer_slot?: number;
};

function fakeSignerStore(rows: readonly FakeRow[]) {
  const deleted: string[] = [];
  return {
    deleted,
    store: {
      index(name: string) {
        if (name !== SEAMS_WALLET_INDEXES.walletId) {
          throw new Error(`unexpected index read: ${name}`);
        }
        return {
          getAll: async (walletId: string) => rows.filter((row) => row.wallet_id === walletId),
        };
      },
      delete: async (rowId: string) => {
        deleted.push(rowId);
      },
    },
  };
}

const NEAR_KIND = 'near_ed25519';

test('supersedes the earlier row that collides on the NEAR signing key id', async () => {
  const fake = fakeSignerStore([
    {
      wallet_signer_id: 'signer:device-1',
      wallet_id: 'wallet-1',
      kind: NEAR_KIND,
      near_ed25519_signing_key_id: 'ed25519:shared',
      near_signer_slot: 1,
    },
  ]);
  await deleteConflictingNearEd25519SignerRows({
    store: fake.store,
    nextRow: {
      wallet_signer_id: 'signer:device-2',
      wallet_id: 'wallet-1',
      kind: NEAR_KIND,
      near_ed25519_signing_key_id: 'ed25519:shared',
      near_signer_slot: 1,
      status: 'active',
      updated_at: 1,
      record: {},
    } as never,
  });
  expect(fake.deleted).toEqual(['signer:device-1']);
});

test('keeps two genuinely distinct signers for the same wallet', async () => {
  const fake = fakeSignerStore([
    {
      wallet_signer_id: 'signer:slot-1',
      wallet_id: 'wallet-1',
      kind: NEAR_KIND,
      near_ed25519_signing_key_id: 'ed25519:one',
      near_signer_slot: 1,
    },
  ]);
  await deleteConflictingNearEd25519SignerRows({
    store: fake.store,
    nextRow: {
      wallet_signer_id: 'signer:slot-4',
      wallet_id: 'wallet-1',
      kind: NEAR_KIND,
      near_ed25519_signing_key_id: 'ed25519:four',
      near_signer_slot: 4,
      status: 'active',
      updated_at: 1,
      record: {},
    } as never,
  });
  // Neither unique mirror collides, so nothing is superseded.
  expect(fake.deleted).toEqual([]);
});

test('leaves other wallets and revoked writes alone', async () => {
  const rows: readonly FakeRow[] = [
    {
      wallet_signer_id: 'signer:other-wallet',
      wallet_id: 'wallet-2',
      kind: NEAR_KIND,
      near_ed25519_signing_key_id: 'ed25519:shared',
      near_signer_slot: 1,
    },
  ];
  const crossWallet = fakeSignerStore(rows);
  await deleteConflictingNearEd25519SignerRows({
    store: crossWallet.store,
    nextRow: {
      wallet_signer_id: 'signer:device-2',
      wallet_id: 'wallet-1',
      kind: NEAR_KIND,
      near_ed25519_signing_key_id: 'ed25519:shared',
      near_signer_slot: 1,
      status: 'active',
      updated_at: 1,
      record: {},
    } as never,
  });
  expect(crossWallet.deleted).toEqual([]);

  // A revocation is not a new projection and must not delete the live mirror.
  const revoked = fakeSignerStore([{ ...rows[0], wallet_id: 'wallet-1' }]);
  await deleteConflictingNearEd25519SignerRows({
    store: revoked.store,
    nextRow: {
      wallet_signer_id: 'signer:device-2',
      wallet_id: 'wallet-1',
      kind: NEAR_KIND,
      near_ed25519_signing_key_id: 'ed25519:shared',
      near_signer_slot: 1,
      status: 'revoked',
      updated_at: 1,
      record: {},
    } as never,
  });
  expect(revoked.deleted).toEqual([]);
});
