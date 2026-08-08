import { expect, test } from '@playwright/test';
import { CloudflareD1WalletCustodyCommitStore } from '../../packages/sdk-server-ts/src/router/cloudflare/d1/passkeyCustody/d1WalletCustodyCommitStore';
import { CloudflareD1PasskeyCustodyEnvelopeStore } from '../../packages/sdk-server-ts/src/router/cloudflare/d1/passkeyCustody/d1PasskeyCustodyEnvelopeStore';
import {
  buildWalletCustodyRegistrationRecords,
  commitWalletCustodyRegistration,
  type WalletCustodyCeremonyCommitPayload,
} from '../../packages/sdk-server-ts/src/router/domains/passkeyCustody/walletCustodyRegistrationCommit';
import type { WalletId } from '../../packages/shared-ts/src/utils/domainIds';
import { cleanupTemporaryD1Database, createTemporaryD1Database } from '../helpers/sqliteD1';
import { applySignerMigrations } from './helpers/cloudflareD1RouterApiAuthService.fixtures';
import {
  ALT_DIGEST_B64U,
  CIPHERTEXT_B64U,
  CIPHERTEXT_DIGEST_B64U,
  CREDENTIAL_ID_B64U,
  DIGEST_B64U,
  ENVELOPE_ID,
  NONCE_12_B64U,
  OTHER_WALLET_ID,
  RP_ID,
  WALLET_ID,
  rawPasskeyFactor,
  rawWalletCustodySeedBinding,
} from './helpers/passkeyCustodyEnvelope.fixtures';

/**
 * The seam between the ceremony's commit payload and the records the store
 * writes. These own what the adapter must refuse: a payload it cannot parse
 * must become a rejection with nothing written, never a stored record a later
 * reader chokes on.
 */

const TEST_SCOPE = {
  namespace: 'wallet-custody-commit-adapter-test',
  orgId: 'org-a',
  projectId: 'project-a',
  envId: 'env-a',
} as const;

const NOW_MS = 1_700_000_000_000;

function envelopeBindingJson(overrides: Record<string, unknown> = {}): string {
  return JSON.stringify({
    walletId: WALLET_ID,
    envelopeId: ENVELOPE_ID,
    factor: rawPasskeyFactor(),
    envelopeRevision: 1,
    binding: rawWalletCustodySeedBinding(),
    ...overrides,
  });
}

function recoveryWrap(index: number) {
  return {
    // 43 base64url chars after the prefix, distinct per code: the parser
    // enforces that shape, so appending an index would not be a valid id.
    recoveryKeyId: `wallet-rkid-v1-${DIGEST_B64U.slice(0, 42)}${'ABCDEFGHIJ'[index]}`,
    nonceB64u: NONCE_12_B64U,
    ciphertextB64u: CIPHERTEXT_B64U,
    aadHashB64u: ALT_DIGEST_B64U,
  };
}

function establishedCustody(overrides: Record<string, unknown> = {}) {
  return {
    envelopeId: ENVELOPE_ID,
    envelopeBindingJson: envelopeBindingJson(),
    envelopeNonceB64u: NONCE_12_B64U,
    sealedCustodySecretB64u: CIPHERTEXT_B64U,
    envelopeAadHashB64u: ALT_DIGEST_B64U,
    envelopeCiphertextDigestB64u: CIPHERTEXT_DIGEST_B64U,
    recoveryManifestKekWraps: Array.from({ length: 10 }, (_, index) => recoveryWrap(index)),
    recoveryEntryNonceB64u: NONCE_12_B64U,
    recoveryEntryCiphertextB64u: CIPHERTEXT_B64U,
    recoveryEntryAadHashB64u: DIGEST_B64U,
    ...overrides,
  };
}

function payload(
  overrides: Partial<WalletCustodyCeremonyCommitPayload> = {},
): WalletCustodyCeremonyCommitPayload {
  return {
    walletId: WALLET_ID,
    keySet: 'evm_family_ecdsa_v1',
    keyManifestDigestB64u: DIGEST_B64U,
    establishedCustody: establishedCustody(),
    clientRootPublicKey33B64u: DIGEST_B64U,
    ecdsaReadyStateBlobB64u: CIPHERTEXT_B64U,
    ...overrides,
  };
}

async function withStore(
  run: (
    store: CloudflareD1WalletCustodyCommitStore,
    database: Parameters<typeof applySignerMigrations>[0],
  ) => Promise<void>,
): Promise<void> {
  const { database, tempDir } = createTemporaryD1Database();
  try {
    await applySignerMigrations(database);
    await run(new CloudflareD1WalletCustodyCommitStore({ database, scope: TEST_SCOPE }), database);
  } finally {
    cleanupTemporaryD1Database(tempDir);
  }
}

test('a ceremony payload becomes one envelope and one ten-code recovery set', () => {
  const records = buildWalletCustodyRegistrationRecords({
    payload: payload(),
    factor: rawPasskeyFactor(),
    nowMs: NOW_MS,
  });

  expect(records.envelope.envelopeRevision).toBe(1);
  expect(records.envelope.lifecycle.state).toBe('active');
  expect(records.envelope.binding.kind).toBe('wallet_custody_seed_v1');
  expect(records.recoverySet.manifestKekWraps.length).toBe(10);
  expect(records.recoverySet.entries.length).toBe(1);
  expect(records.recoverySet.entries[0]?.custodySecretKind).toBe('wallet_custody_seed_v1');
  // Neither record names a key manifest. Key sets carry their own digest on
  // their own registration state; a manifest here would couple the seed to one
  // key set and re-open the deleted-manifest hole the decoupling closed.
  expect('keyManifestDigestB64u' in records.recoverySet).toBe(false);
  expect('keyManifestDigestB64u' in records.envelope.binding).toBe(false);
});

test('the binding is carried through, not reassembled', () => {
  // The AAD was computed over the ceremony's binding. If this server rebuilt it
  // from loose fields, a single differing field would produce an envelope that
  // cannot open — so the parsed binding must equal what the payload carried.
  const records = buildWalletCustodyRegistrationRecords({
    payload: payload(),
    factor: rawPasskeyFactor(),
    nowMs: NOW_MS,
  });
  const carried = JSON.parse(envelopeBindingJson()).binding as Record<string, unknown>;
  expect(records.envelope.binding).toEqual(carried);
});

test('a payload that contradicts its own binding is refused', () => {
  const cases: Array<[string, WalletCustodyCeremonyCommitPayload]> = [
    [
      'binding names another wallet',
      payload({
        establishedCustody: establishedCustody({
          envelopeBindingJson: envelopeBindingJson({ walletId: OTHER_WALLET_ID }),
        }),
      }),
    ],
    [
      'binding names another wallet, again',
      payload({
        establishedCustody: establishedCustody({
          envelopeBindingJson: envelopeBindingJson({ walletId: OTHER_WALLET_ID }),
        }),
      }),
    ],
  ];
  for (const [label, bad] of cases) {
    expect(
      () =>
        buildWalletCustodyRegistrationRecords({
          payload: bad,
          factor: rawPasskeyFactor(),
          nowMs: NOW_MS,
        }),
      label,
    ).toThrow();
  }
});

test('a recovery set that is not exactly ten distinct codes is refused', () => {
  const nine = payload({
    establishedCustody: establishedCustody({
      recoveryManifestKekWraps: Array.from({ length: 9 }, (_, index) => recoveryWrap(index)),
    }),
  });
  expect(() =>
    buildWalletCustodyRegistrationRecords({
      payload: nine,
      factor: rawPasskeyFactor(),
      nowMs: NOW_MS,
    }),
  ).toThrow();

  // Duplicate ids would silently reduce a ten-code set: a code is found by id.
  const duplicated = payload({
    establishedCustody: establishedCustody({
      recoveryManifestKekWraps: Array.from({ length: 10 }, () => recoveryWrap(0)),
    }),
  });
  expect(() =>
    buildWalletCustodyRegistrationRecords({
      payload: duplicated,
      factor: rawPasskeyFactor(),
      nowMs: NOW_MS,
    }),
  ).toThrow();
});

test('malformed ciphertext and nonces are refused at the boundary', () => {
  for (const bad of [
    payload({ establishedCustody: establishedCustody({ envelopeNonceB64u: 'AQID' }) }), // not 12 bytes
    payload({ establishedCustody: establishedCustody({ envelopeAadHashB64u: 'AQID' }) }), // not a 32-byte digest
    payload({
      establishedCustody: establishedCustody({ sealedCustodySecretB64u: 'not base64url!!' }),
    }),
  ]) {
    expect(() =>
      buildWalletCustodyRegistrationRecords({
        payload: bad,
        factor: rawPasskeyFactor(),
        nowMs: NOW_MS,
      }),
    ).toThrow();
  }
});

test('an unparseable payload is a rejection, and writes nothing', async () => {
  await withStore(async (store) => {
    const rejected = await commitWalletCustodyRegistration({
      payload: payload({ establishedCustody: establishedCustody({ envelopeBindingJson: '{' }) }),
      factor: rawPasskeyFactor(),
      nowMs: NOW_MS,
      store,
    });
    expect(rejected.kind).toBe('rejected');
    expect(await store.readRecoveryEnvelopeSet(WALLET_ID as WalletId)).toBeNull();
  });
});

test('a valid payload commits, and a repeat is reported rather than overwriting', async () => {
  await withStore(async (store) => {
    const committed = await commitWalletCustodyRegistration({
      payload: payload(),
      factor: rawPasskeyFactor(),
      nowMs: NOW_MS,
      store,
    });
    expect(committed.kind).toBe('committed');

    const stored = await store.readRecoveryEnvelopeSet(WALLET_ID as WalletId);
    expect(stored?.record.manifestKekWraps.length).toBe(10);
    expect(stored?.record.manifestKekWraps[0]?.lifecycle.state).toBe('active');

    // The same ceremony's commit replayed — the envelope itself is the
    // duplicate, so this is a repeat, not a lost race.
    const repeat = await commitWalletCustodyRegistration({
      payload: payload(),
      factor: rawPasskeyFactor(),
      nowMs: NOW_MS + 1,
      store,
    });
    expect(repeat.kind).toBe('already_exists');
  });
});

/**
 * The establish race. Registration runs one custody ceremony per key set, and
 * under Refactor 94C's deferred-NEAR contract the EVM and NEAR runs can be in
 * flight at once. If both believe they are the wallet's first key set, both
 * seal a seed and both try to establish. Exactly one may win: the loser's seed
 * must be discarded, its run re-entered as a join of the winner's envelope, and
 * the wallet must end with one envelope, one recovery set, two manifests.
 *
 * `custody_already_established` is what tells the loser that re-entry is the
 * correct move. `already_exists` must stay distinct: it means *this* commit was
 * already applied, for which re-entering as a join would be wrong — the caller
 * is done.
 */

/** A second establishing ceremony for the same wallet: fresh envelope, fresh codes. */
function racingNearPayload(): WalletCustodyCeremonyCommitPayload {
  return payload({
    keySet: 'near_ed25519_v1',
    keyManifestDigestB64u: ALT_DIGEST_B64U,
    registeredPublicKeyB64u: DIGEST_B64U,
    clientRootPublicKey33B64u: undefined,
    ecdsaReadyStateBlobB64u: undefined,
    establishedCustody: establishedCustody({
      envelopeId: RACING_ENVELOPE_ID,
      envelopeBindingJson: envelopeBindingJson({ envelopeId: RACING_ENVELOPE_ID }),
      recoveryManifestKekWraps: Array.from({ length: 10 }, (_, index) =>
        racingRecoveryWrap(index),
      ),
    }),
  });
}

const RACING_ENVELOPE_ID = 'passkey-envelope-2';

function racingRecoveryWrap(index: number) {
  return {
    ...recoveryWrap(index),
    recoveryKeyId: `wallet-rkid-v1-${DIGEST_B64U.slice(0, 42)}${'KLMNOPQRST'[index]}`,
  };
}

function passkeyEnvelopeLocator(envelopeId: string) {
  return {
    walletId: WALLET_ID as WalletId,
    factor: {
      kind: 'passkey',
      rpId: RP_ID,
      credentialIdB64u: CREDENTIAL_ID_B64U,
    },
    envelopeId,
  } as Parameters<CloudflareD1PasskeyCustodyEnvelopeStore['lookupEnvelope']>[0];
}

test('a second establishing ceremony is told custody exists, and writes nothing', async () => {
  await withStore(async (store, database) => {
    const first = await commitWalletCustodyRegistration({
      payload: payload(),
      factor: rawPasskeyFactor(),
      nowMs: NOW_MS,
      store,
    });
    expect(first.kind).toBe('committed');

    // A different ceremony: its envelope id is fresh, so nothing about *its*
    // records exists yet — only the wallet's custody does.
    const second = await commitWalletCustodyRegistration({
      payload: racingNearPayload(),
      factor: rawPasskeyFactor(),
      nowMs: NOW_MS + 1,
      store,
    });
    expect(second).toEqual({
      kind: 'custody_already_established',
      walletId: WALLET_ID,
    });

    // The loser wrote nothing: the winner's recovery set is untouched and the
    // loser's envelope was never stored.
    const stored = await store.readRecoveryEnvelopeSet(WALLET_ID as WalletId);
    expect(stored?.record.manifestKekWraps[0]?.recoveryKeyId).toBe(
      recoveryWrap(0).recoveryKeyId,
    );
    const envelopes = new CloudflareD1PasskeyCustodyEnvelopeStore({
      database,
      scope: TEST_SCOPE,
    });
    expect((await envelopes.lookupEnvelope(passkeyEnvelopeLocator(RACING_ENVELOPE_ID))).kind).toBe(
      'missing',
    );
    expect((await envelopes.lookupEnvelope(passkeyEnvelopeLocator(ENVELOPE_ID))).kind).toBe(
      'active',
    );
  });
});

test('concurrent establishing ceremonies end with one custody and one loser told to join', async () => {
  await withStore(async (store) => {
    const [evm, near] = await Promise.all([
      commitWalletCustodyRegistration({
        payload: payload(),
        factor: rawPasskeyFactor(),
        nowMs: NOW_MS,
        store,
      }),
      commitWalletCustodyRegistration({
        payload: racingNearPayload(),
        factor: rawPasskeyFactor(),
        nowMs: NOW_MS,
        store,
      }),
    ]);

    // Exactly one winner, and the loser is told custody exists — not that its
    // own commit already happened, which would end its retry instead of
    // re-entering it as a join.
    const kinds = [evm.kind, near.kind].sort();
    expect(kinds).toEqual(['committed', 'custody_already_established']);

    // One recovery set, and it is the winner's.
    const stored = await store.readRecoveryEnvelopeSet(WALLET_ID as WalletId);
    const winnerWrapId =
      evm.kind === 'committed' ? recoveryWrap(0).recoveryKeyId : racingRecoveryWrap(0).recoveryKeyId;
    expect(stored?.record.manifestKekWraps[0]?.recoveryKeyId).toBe(winnerWrapId);
  });
});
