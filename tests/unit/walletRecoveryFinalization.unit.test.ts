import { expect, test } from '@playwright/test';
import { finalizeRecoveredWalletCredentialV1 } from '../../packages/sdk-server-ts/src/router/domains/passkeyCustody/walletRecoveryFinalization';

/**
 * Promoting the credential a recovery enrolled.
 *
 * The ordering is the property worth a test. Create-then-retire and
 * retire-then-create both pass a naive "the new credential works" check; only
 * the second can leave a wallet with no active envelope if the create fails,
 * and by then the user has already spent a recovery code. So the tests below
 * observe the *sequence*, not just the outcome.
 */

const WALLET_ID = 'alice.testnet';
const B64U_32 = 'A'.repeat(43);
const RESERVATION_ID = 'reservation-1' as never;

function envelope(envelopeId: string, state: 'active' | 'retired' = 'active') {
  return {
    kind: 'wallet_custody_envelope_v2',
    envelopeId,
    walletId: WALLET_ID,
    binding: { kind: 'wallet_custody_seed_v1' },
    factor: { kind: 'passkey', rpId: 'example.localhost', credentialIdB64u: envelopeId },
    envelopeVersion: 'v2',
    envelopeRevision: 1,
    nonceB64u: 'B'.repeat(16),
    sealedCustodySecretB64u: 'C'.repeat(64),
    ciphertextDigestB64u: B64U_32,
    aadHashB64u: B64U_32,
    lifecycle: state === 'active' ? { state: 'active', activatedAtMs: 1 } : { state: 'retired' },
    createdAtMs: 1,
    updatedAtMs: 1,
  } as never;
}

function storeStub(options: {
  readonly existing: unknown[];
  readonly trace: string[];
  readonly createFails?: boolean;
  readonly retireFails?: boolean;
}) {
  return {
    envelopeStore: {
      listWalletEnvelopes: async () => {
        options.trace.push('list');
        return options.existing;
      },
      retireEnvelope: async (args: { locator: { envelopeId: string } }) => {
        options.trace.push(`retire:${args.locator.envelopeId}`);
        return options.retireFails
          ? { kind: 'version_mismatch' }
          : { kind: 'stored', storeVersion: '3' };
      },
    },
    walletCustodyCommits: {
      readRecoveryEnvelopeSet: async () => ({
        storeVersion: '4',
        record: {
          kind: 'wallet_recovery_envelope_set_v1',
          walletId: WALLET_ID,
          manifestKekWraps: [
            {
              recoveryKeyId: `wallet-rkid-v1-${'A'.repeat(43)}`,
              nonceB64u: 'B'.repeat(16),
              wrappedManifestKekB64u: 'C'.repeat(64),
              aadHashB64u: B64U_32,
              lifecycle: {
                state: 'reserved',
                issuedAtMs: 1,
                reservationId: RESERVATION_ID,
                reservedAtMs: 2,
                reservationExpiresAtMs: 10_000,
              },
            },
          ],
          entries: [],
          issuedAtMs: 1,
          updatedAtMs: 2,
        },
      }),
      commitRecoveryPromotion: async () => {
        options.trace.push('commit');
        return options.createFails
          ? { kind: 'inconsistent', reason: 'replacement envelope rejected' }
          : { kind: 'committed', envelopeStoreVersion: '2' };
      },
    },
  };
}

const VERIFIED = [{ keySet: 'near_ed25519_v1', kind: 'verified' as const }];

test('the new envelope is created before any old one is retired', async () => {
  const trace: string[] = [];
  const stores = storeStub({ existing: [envelope('old-1')], trace });
  const result = await finalizeRecoveredWalletCredentialV1({
    envelopeStore: stores.envelopeStore as never,
    walletCustodyCommits: stores.walletCustodyCommits as never,
    walletId: WALLET_ID,
    reservationId: RESERVATION_ID,
    replacementEnvelope: envelope('new-1'),
    requiredKeySets: ['near_ed25519_v1'],
    outcomes: VERIFIED,
    nowMs: 5_000,
  });

  expect(result.kind).toBe('promoted');
  // The order, not just the outcome: retiring first would open a window with
  // no active envelope, and a failed create would make it permanent.
  expect(trace).toEqual(['list', 'commit', 'retire:old-1']);
});

test('a failed create retires nothing', async () => {
  const trace: string[] = [];
  const stores = storeStub({ existing: [envelope('old-1')], trace, createFails: true });
  const result = await finalizeRecoveredWalletCredentialV1({
    envelopeStore: stores.envelopeStore as never,
    walletCustodyCommits: stores.walletCustodyCommits as never,
    walletId: WALLET_ID,
    reservationId: RESERVATION_ID,
    replacementEnvelope: envelope('new-1'),
    requiredKeySets: ['near_ed25519_v1'],
    outcomes: VERIFIED,
    nowMs: 5_000,
  });

  expect(result.kind).toBe('envelope_rejected');
  // The wallet is untouched: still openable by the credential being replaced,
  // which is the safe direction to fail in.
  expect(trace).toEqual(['list', 'commit']);
});

test('an unverified key set refuses before touching the store', async () => {
  const trace: string[] = [];
  const stores = storeStub({ existing: [envelope('old-1')], trace });
  const result = await finalizeRecoveredWalletCredentialV1({
    envelopeStore: stores.envelopeStore as never,
    walletCustodyCommits: stores.walletCustodyCommits as never,
    walletId: WALLET_ID,
    reservationId: RESERVATION_ID,
    replacementEnvelope: envelope('new-1'),
    requiredKeySets: ['near_ed25519_v1', 'evm_family_ecdsa_v1'],
    outcomes: VERIFIED,
    nowMs: 5_000,
  });

  expect(result.kind).toBe('refused');
  expect(trace).toEqual([]);
});

test('an envelope naming another wallet is rejected', async () => {
  const trace: string[] = [];
  const stores = storeStub({ existing: [], trace });
  const result = await finalizeRecoveredWalletCredentialV1({
    envelopeStore: stores.envelopeStore as never,
    walletCustodyCommits: stores.walletCustodyCommits as never,
    walletId: 'someone-else.testnet',
    reservationId: RESERVATION_ID,
    replacementEnvelope: envelope('new-1'),
    requiredKeySets: ['near_ed25519_v1'],
    outcomes: VERIFIED,
    nowMs: 5_000,
  });

  expect(result.kind).toBe('envelope_rejected');
  expect(trace).toEqual([]);
});

test('a failed retire is reported without failing the recovery', async () => {
  const trace: string[] = [];
  const stores = storeStub({ existing: [envelope('old-1')], trace, retireFails: true });
  const result = await finalizeRecoveredWalletCredentialV1({
    envelopeStore: stores.envelopeStore as never,
    walletCustodyCommits: stores.walletCustodyCommits as never,
    walletId: WALLET_ID,
    reservationId: RESERVATION_ID,
    replacementEnvelope: envelope('new-1'),
    requiredKeySets: ['near_ed25519_v1'],
    outcomes: VERIFIED,
    nowMs: 5_000,
  });

  // The wallet is recovered and the new credential opens it. An old one still
  // working is cleanup, not a failed recovery.
  expect(result.kind).toBe('promoted');
  if (result.kind !== 'promoted') return;
  expect(result.retireFailures).toEqual(['old-1']);
  expect(result.retiredEnvelopeIds).toEqual([]);
});
