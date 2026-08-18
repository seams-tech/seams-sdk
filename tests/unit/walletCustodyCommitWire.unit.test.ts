import { expect, test } from '@playwright/test';
import {
  parseWalletCustodyRegistrationOutcome,
  walletCustodyCeremonyCommitPayloadFromWire,
} from '../../packages/shared-ts/src/passkey-custody';
import { commitRegistrationCustody } from '../../packages/wallet-server/src/router/domains/passkeyCustody/registrationCustodyOutcome';
import { CloudflareD1WalletCustodyCommitStore } from '../../packages/wallet-server/src/router/cloudflare/d1/passkeyCustody/d1WalletCustodyCommitStore';
import { buildPasskeyWalletAuthAuthority } from '../../packages/shared-ts/src/utils/walletAuthAuthority';
import type { WalletId } from '../../packages/shared-ts/src/utils/domainIds';
import { cleanupTemporaryD1Database, createTemporaryD1Database } from '../helpers/sqliteD1';
import { applySignerMigrations } from './helpers/cloudflareD1RouterApiAuthService.fixtures';
import {
  buildWalletCustodyCommitPayloadFixture,
  CIPHERTEXT_B64U,
  CREDENTIAL_ID_B64U,
  DIGEST_B64U,
  NONCE_12_B64U,
  RP_ID,
  WALLET_ID,
} from './helpers/passkeyCustodyEnvelope.fixtures';

/**
 * The custody commit's two wire crossings: the ceremony payload coming in, and
 * the outcome going back.
 *
 * The load-bearing asymmetry is that the request half never throws and the
 * response half always does. Inbound, a malformed payload has to reach the
 * admission gate so it comes back as a reported `rejected` — the registration
 * is already committed by then, and rejecting at the boundary would fail a
 * call whose wallet survives, telling the client nothing about its seed.
 * Outbound, an unrecognised status is version skew the client must not guess
 * its way past.
 */

const NOW_MS = 1_700_000_000_000;

function passkeyAuthority() {
  return buildPasskeyWalletAuthAuthority({
    walletId: WALLET_ID,
    rpId: RP_ID,
    credentialIdB64u: CREDENTIAL_ID_B64U,
  });
}

async function withStore(
  run: (store: CloudflareD1WalletCustodyCommitStore) => Promise<void>,
): Promise<void> {
  const { database, tempDir } = createTemporaryD1Database();
  try {
    await applySignerMigrations(database);
    await run(
      new CloudflareD1WalletCustodyCommitStore({
        database,
        scope: {
          namespace: 'custody-commit-wire-test',
          orgId: 'org-a',
          projectId: 'project-a',
          envId: 'env-a',
        },
      }),
    );
  } finally {
    cleanupTemporaryD1Database(tempDir);
  }
}

test('an absent field is the only thing that reads as no custody run', () => {
  expect(walletCustodyCeremonyCommitPayloadFromWire(undefined)).toBeUndefined();
  expect(walletCustodyCeremonyCommitPayloadFromWire(null)).toBeUndefined();
});

test('garbage in the field is a payload, never an absence', () => {
  /* The distinction this pins: `undefined` means the client ran no ceremony,
     so registration is complete. Anything else means it ran one, and the
     client must be told what became of it. Collapsing the two would let a
     wallet with an unrecoverable seed report as fully registered. */
  for (const garbage of ['not-an-object', 42, [], true, {}]) {
    const parsed = walletCustodyCeremonyCommitPayloadFromWire(garbage);
    expect(parsed).not.toBeUndefined();
    expect(parsed?.walletId).toBe('');
  }
});

test('a well-formed payload crosses, minus the client-only material', () => {
  const payload = buildWalletCustodyCommitPayloadFixture({ walletId: WALLET_ID });
  const parsed = walletCustodyCeremonyCommitPayloadFromWire(
    JSON.parse(JSON.stringify(payload)) as unknown,
  );
  // Everything the commit needs crosses; the ready-state blob does not.
  const { ecdsaReadyStateBlobB64u: _clientOnly, ...wire } = payload;
  expect(parsed).toEqual(wire);
});

test('non-string scalars are emptied rather than coerced to their text', () => {
  /* `String(42)` would produce a wallet id of "42", which the gate would then
     compare against the registered wallet as though the client had named one. */
  const parsed = walletCustodyCeremonyCommitPayloadFromWire({
    walletId: 42,
    keySet: { evil: true },
    keyManifestDigestB64u: null,
  });
  expect(parsed).toMatchObject({ walletId: '', keySet: '', keyManifestDigestB64u: '' });
});

test('client signing material never crosses to the server, for either key set', async () => {
  /* Both records are the ceremony's output to its own client. The ECDSA blob
     is the sharper case: it is not self-encrypted —
     extract_client_signing_share32_from_ready_state_blob yields the client's
     signing share from its bytes with no key — so letting it cross would hand
     one share of a 2-of-2 key to the holder of the other share. The inbound
     coercion drops all three fields even when a client sends them. */
  const near = walletCustodyCeremonyCommitPayloadFromWire({
    ...buildWalletCustodyCommitPayloadFixture({ walletId: WALLET_ID, keySet: 'near_ed25519_v1' }),
    ed25519LocalMaterialB64u: CIPHERTEXT_B64U,
    ed25519LocalMaterialNonceB64u: NONCE_12_B64U,
  });
  expect(near).not.toBeUndefined();
  expect(Object.keys(near ?? {})).not.toContain('ed25519LocalMaterialB64u');
  expect(Object.keys(near ?? {})).not.toContain('ed25519LocalMaterialNonceB64u');
  // The rest of the payload still crosses.
  expect(near?.walletId).toBe(WALLET_ID);
  expect(near?.keySet).toBe('near_ed25519_v1');

  const evm = walletCustodyCeremonyCommitPayloadFromWire(
    buildWalletCustodyCommitPayloadFixture({ walletId: WALLET_ID }),
  );
  expect(Object.keys(evm ?? {})).not.toContain('ecdsaReadyStateBlobB64u');
  expect(evm?.keySet).toBe('evm_family_ecdsa_v1');
});

test('a garbage payload reaches the gate and is reported, not silently dropped', async () => {
  await withStore(async (store) => {
    const outcome = await commitRegistrationCustody({
      payload: walletCustodyCeremonyCommitPayloadFromWire('garbage'),
      verifiedWalletId: WALLET_ID as WalletId,
      verifiedAuthority: passkeyAuthority(),
      nowMs: NOW_MS,
      store,
    });
    expect(outcome.status).toBe('rejected');
  });
});

test('a store failure is reported, because the wallet is already committed', async () => {
  /* Activation never fails because of custody. By the time this runs the
     registration is durable, and the seed lives only in the client's worker —
     so a D1 failure has to come back as an outcome the client can retry from,
     not as an exception that unwinds a wallet that already exists. */
  const exploding = {
    commitRegistration: async () => {
      throw new Error('D1 unavailable');
    },
  } as unknown as CloudflareD1WalletCustodyCommitStore;

  const outcome = await commitRegistrationCustody({
    payload: buildWalletCustodyCommitPayloadFixture({ walletId: WALLET_ID }),
    verifiedWalletId: WALLET_ID as WalletId,
    verifiedAuthority: passkeyAuthority(),
    nowMs: NOW_MS,
    store: exploding,
  });

  expect(outcome.status).toBe('rejected');
  expect(outcome.status === 'rejected' && outcome.reason).toContain('D1 unavailable');
});

test('every outcome status survives the response boundary', () => {
  const label = 'test';
  for (const outcome of [
    { status: 'not_requested' },
    { status: 'committed' },
    { status: 'custody_already_established' },
    { status: 'joined', keyManifestDigestB64u: DIGEST_B64U },
    { status: 'rejected', reason: 'because' },
  ]) {
    expect(parseWalletCustodyRegistrationOutcome(outcome, label)).toEqual(outcome);
  }
});

test('an unrecognised outcome is refused rather than guessed', () => {
  const label = 'test';
  for (const bad of [
    undefined,
    null,
    'committed',
    { status: 'invented_status' },
    // A joined outcome without its digest, and a rejection without its reason,
    // are both outcomes a client cannot act on.
    { status: 'joined' },
    { status: 'rejected' },
  ]) {
    expect(() => parseWalletCustodyRegistrationOutcome(bad, label)).toThrow();
  }
});
