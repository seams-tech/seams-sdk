import { expect, test } from '@playwright/test';
import { promoteRecoveredWalletCredentialV1 } from '../../packages/sdk-server-ts/src/router/domains/passkeyCustody/walletRecoveryPromotion';

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
    listWalletEnvelopes: async () => {
      options.trace.push('list');
      return options.existing;
    },
    createEnvelope: async () => {
      options.trace.push('create');
      return options.createFails
        ? { kind: 'revision_conflict', expectedRevision: 1 }
        : { kind: 'stored', storeVersion: '2', envelopeRevision: 1 };
    },
    retireEnvelope: async (args: { locator: { envelopeId: string } }) => {
      options.trace.push(`retire:${args.locator.envelopeId}`);
      return options.retireFails
        ? { kind: 'version_mismatch' }
        : { kind: 'stored', storeVersion: '3' };
    },
  } as never;
}

const VERIFIED = [{ keySet: 'near_ed25519_v1', kind: 'verified' as const }];

test('the new envelope is created before any old one is retired', async () => {
  const trace: string[] = [];
  const result = await promoteRecoveredWalletCredentialV1({
    envelopeStore: storeStub({ existing: [envelope('old-1')], trace }),
    walletId: WALLET_ID,
    replacementEnvelope: envelope('new-1'),
    requiredKeySets: ['near_ed25519_v1'],
    outcomes: VERIFIED,
    nowMs: 5_000,
  });

  expect(result.kind).toBe('promoted');
  // The order, not just the outcome: retiring first would open a window with
  // no active envelope, and a failed create would make it permanent.
  expect(trace).toEqual(['list', 'create', 'retire:old-1']);
});

test('a failed create retires nothing', async () => {
  const trace: string[] = [];
  const result = await promoteRecoveredWalletCredentialV1({
    envelopeStore: storeStub({ existing: [envelope('old-1')], trace, createFails: true }),
    walletId: WALLET_ID,
    replacementEnvelope: envelope('new-1'),
    requiredKeySets: ['near_ed25519_v1'],
    outcomes: VERIFIED,
    nowMs: 5_000,
  });

  expect(result.kind).toBe('envelope_rejected');
  // The wallet is untouched: still openable by the credential being replaced,
  // which is the safe direction to fail in.
  expect(trace).toEqual(['list', 'create']);
});

test('an unverified key set refuses before touching the store', async () => {
  const trace: string[] = [];
  const result = await promoteRecoveredWalletCredentialV1({
    envelopeStore: storeStub({ existing: [envelope('old-1')], trace }),
    walletId: WALLET_ID,
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
  const result = await promoteRecoveredWalletCredentialV1({
    envelopeStore: storeStub({ existing: [], trace }),
    walletId: 'someone-else.testnet',
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
  const result = await promoteRecoveredWalletCredentialV1({
    envelopeStore: storeStub({ existing: [envelope('old-1')], trace, retireFails: true }),
    walletId: WALLET_ID,
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
