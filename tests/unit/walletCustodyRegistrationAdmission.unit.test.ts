import { expect, test } from '@playwright/test';
import { CloudflareD1WalletCustodyCommitStore } from '../../packages/wallet-server/src/router/cloudflare/d1/passkeyCustody/d1WalletCustodyCommitStore';
import { admitWalletCustodyRegistrationCommit } from '../../packages/wallet-server/src/router/domains/passkeyCustody/walletCustodyRegistrationAdmission';
import type { WalletCustodyCeremonyCommitPayload } from '../../packages/wallet-server/src/router/domains/passkeyCustody/walletCustodyRegistrationCommit';
import type { WalletId } from '../../packages/shared-ts/src/utils/domainIds';
import { cleanupTemporaryD1Database, createTemporaryD1Database } from '../helpers/sqliteD1';
import { applySignerMigrations } from './helpers/cloudflareD1RouterApiAuthService.fixtures';
import {
  ALT_DIGEST_B64U,
  CIPHERTEXT_B64U,
  CIPHERTEXT_DIGEST_B64U,
  DIGEST_B64U,
  ENVELOPE_ID,
  NONCE_12_B64U,
  OTHER_WALLET_ID,
  WALLET_ID,
  rawPasskeyFactor,
  rawWalletCustodySeedBinding,
} from './helpers/passkeyCustodyEnvelope.fixtures';

/**
 * The gate between a verified registration and the custody store.
 *
 * The custody commit has no route of its own — it rides the registration's
 * activate leg — so this module is what makes "may create this wallet" and
 * "may establish custody for this wallet" the same authority. These own the two
 * checks that make that safe, and the joining case that must write nothing.
 */

const TEST_SCOPE = {
  namespace: 'wallet-custody-admission-test',
  orgId: 'org-a',
  projectId: 'project-a',
  envId: 'env-a',
} as const;

const NOW_MS = 1_700_000_000_000;

function envelopeBindingJson(walletId: string = WALLET_ID): string {
  return JSON.stringify({
    walletId,
    envelopeId: ENVELOPE_ID,
    factor: rawPasskeyFactor(),
    envelopeRevision: 1,
    binding: rawWalletCustodySeedBinding(),
  });
}

function recoveryWrap(index: number) {
  return {
    recoveryKeyId: `wallet-rkid-v1-${DIGEST_B64U.slice(0, 42)}${'ABCDEFGHIJ'[index]}`,
    nonceB64u: NONCE_12_B64U,
    ciphertextB64u: CIPHERTEXT_B64U,
    aadHashB64u: ALT_DIGEST_B64U,
  };
}

function recoveryCodeLocators() {
  return Array.from({ length: 10 }, (_, index) => ({
    locatorB64u: `${String.fromCharCode(65 + index)}${DIGEST_B64U.slice(1)}`,
    recoveryKeyId: `wallet-rkid-v1-${DIGEST_B64U.slice(0, 42)}${'ABCDEFGHIJ'[index]}`,
  }));
}

function establishingPayload(
  overrides: Partial<WalletCustodyCeremonyCommitPayload> = {},
): WalletCustodyCeremonyCommitPayload {
  return {
    walletId: WALLET_ID,
    keySet: 'evm_family_ecdsa_v1',
    keyManifestDigestB64u: DIGEST_B64U,
    recoveryBackupAcknowledged: true,
    establishedCustody: {
      envelopeId: ENVELOPE_ID,
      envelopeBindingJson: envelopeBindingJson(),
      envelopeNonceB64u: NONCE_12_B64U,
      sealedCustodySecretB64u: CIPHERTEXT_B64U,
      envelopeAadHashB64u: ALT_DIGEST_B64U,
      envelopeCiphertextDigestB64u: CIPHERTEXT_DIGEST_B64U,
      recoveryManifestKekWraps: Array.from({ length: 10 }, (_, index) => recoveryWrap(index)),
      recoveryCodeLocators: recoveryCodeLocators(),
      recoveryEntryNonceB64u: NONCE_12_B64U,
      recoveryEntryCiphertextB64u: CIPHERTEXT_B64U,
      recoveryEntryAadHashB64u: DIGEST_B64U,
    },
    clientRootPublicKey33B64u: DIGEST_B64U,
    ecdsaReadyStateBlobB64u: CIPHERTEXT_B64U,
    ...overrides,
  };
}

function joiningPayload(): WalletCustodyCeremonyCommitPayload {
  return {
    walletId: WALLET_ID,
    keySet: 'near_ed25519_v1',
    keyManifestDigestB64u: ALT_DIGEST_B64U,
    registeredPublicKeyB64u: DIGEST_B64U,
  };
}

async function withStore(
  run: (store: CloudflareD1WalletCustodyCommitStore) => Promise<void>,
): Promise<void> {
  const { database, tempDir } = createTemporaryD1Database();
  try {
    await applySignerMigrations(database);
    await run(new CloudflareD1WalletCustodyCommitStore({ database, scope: TEST_SCOPE }));
  } finally {
    cleanupTemporaryD1Database(tempDir);
  }
}

test('a payload naming the registered wallet commits under the verified factor', async () => {
  await withStore(async (store) => {
    const outcome = await admitWalletCustodyRegistrationCommit({
      payload: establishingPayload(),
      verifiedWalletId: WALLET_ID as WalletId,
      verifiedFactor: rawPasskeyFactor() as never,
      nowMs: NOW_MS,
      store,
    });

    expect(outcome.kind).toBe('committed');
  });
});

test('a payload naming another wallet is refused, and writes nothing', async () => {
  await withStore(async (store) => {
    // The registration is for OTHER_WALLET_ID; the payload claims WALLET_ID.
    // Without this check a caller with a valid registration of their own could
    // commit an envelope under someone else's wallet.
    const outcome = await admitWalletCustodyRegistrationCommit({
      payload: establishingPayload(),
      verifiedWalletId: OTHER_WALLET_ID as WalletId,
      verifiedFactor: rawPasskeyFactor() as never,
      nowMs: NOW_MS,
      store,
    });

    expect(outcome.kind).toBe('rejected');
    expect(outcome.kind === 'rejected' && outcome.reason).toContain('does not name the registered');

    // Nothing was written, so the real wallet can still establish custody.
    const after = await admitWalletCustodyRegistrationCommit({
      payload: establishingPayload(),
      verifiedWalletId: WALLET_ID as WalletId,
      verifiedFactor: rawPasskeyFactor() as never,
      nowMs: NOW_MS,
      store,
    });
    expect(after.kind).toBe('committed');
  });
});

test('a payload with no wallet id is refused', async () => {
  await withStore(async (store) => {
    const outcome = await admitWalletCustodyRegistrationCommit({
      payload: establishingPayload({ walletId: '   ' }),
      verifiedWalletId: WALLET_ID as WalletId,
      verifiedFactor: rawPasskeyFactor() as never,
      nowMs: NOW_MS,
      store,
    });
    expect(outcome.kind).toBe('rejected');
  });
});

test('a payload with no manifest digest is refused', async () => {
  await withStore(async (store) => {
    const outcome = await admitWalletCustodyRegistrationCommit({
      payload: establishingPayload({ keyManifestDigestB64u: '' }),
      verifiedWalletId: WALLET_ID as WalletId,
      verifiedFactor: rawPasskeyFactor() as never,
      nowMs: NOW_MS,
      store,
    });
    expect(outcome.kind).toBe('rejected');
  });
});

test('a joining run is admitted and writes no custody records', async () => {
  await withStore(async (store) => {
    const outcome = await admitWalletCustodyRegistrationCommit({
      payload: joiningPayload(),
      verifiedWalletId: WALLET_ID as WalletId,
      verifiedFactor: rawPasskeyFactor() as never,
      nowMs: NOW_MS,
      store,
    });

    // Distinct from a rejection: nothing to write is a success, and the caller
    // needs the digest to put on this key set's registration state.
    expect(outcome.kind).toBe('no_custody_records');
    expect(outcome.kind === 'no_custody_records' && outcome.keyManifestDigestB64u).toBe(
      ALT_DIGEST_B64U,
    );

    // Having written nothing, the wallet can still establish custody after.
    const established = await admitWalletCustodyRegistrationCommit({
      payload: establishingPayload(),
      verifiedWalletId: WALLET_ID as WalletId,
      verifiedFactor: rawPasskeyFactor() as never,
      nowMs: NOW_MS,
      store,
    });
    expect(established.kind).toBe('committed');
  });
});

test('a second establishing run for one wallet is told custody already exists', async () => {
  await withStore(async (store) => {
    const first = await admitWalletCustodyRegistrationCommit({
      payload: establishingPayload(),
      verifiedWalletId: WALLET_ID as WalletId,
      verifiedFactor: rawPasskeyFactor() as never,
      nowMs: NOW_MS,
      store,
    });
    expect(first.kind).toBe('committed');

    const second = await admitWalletCustodyRegistrationCommit({
      payload: establishingPayload({ keyManifestDigestB64u: ALT_DIGEST_B64U }),
      verifiedWalletId: WALLET_ID as WalletId,
      verifiedFactor: rawPasskeyFactor() as never,
      nowMs: NOW_MS,
      store,
    });

    // The client must discard its run's seed and re-enter as a join rather than
    // treat this as a plain duplicate.
    expect(['already_exists', 'custody_already_established']).toContain(second.kind);
  });
});
