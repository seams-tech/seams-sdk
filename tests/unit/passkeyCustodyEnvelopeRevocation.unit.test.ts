import { expect, test } from '@playwright/test';
import { admitEnvelopeRevocation } from '../../packages/wallet-server/src/router/domains/passkeyCustody/envelopeRevocationAdmission';
import { CloudflareD1PasskeyCustodyEnvelopeStore } from '../../packages/wallet-server/src/router/cloudflare/d1/passkeyCustody/d1PasskeyCustodyEnvelopeStore';
import { cleanupTemporaryD1Database, createTemporaryD1Database } from '../helpers/sqliteD1';
import { applySignerMigrations } from './helpers/cloudflareD1RouterApiAuthService.fixtures';
import {
  passkeyCustodyEnvelope,
  rawPasskeyFactor,
  WALLET_ID,
} from './helpers/passkeyCustodyEnvelope.fixtures';
import type { WalletId } from '../../packages/shared-ts/src/utils/domainIds';

/**
 * Revoking a custody envelope.
 *
 * The rule needs the wallet's whole set, not a lookup: revoking the last
 * active envelope leaves a seed no factor can open, and it would appear to
 * succeed. Removing a synced passkey is the case this permits — another active
 * envelope still protects the same secret.
 */

const TEST_SCOPE = {
  namespace: 'envelope-revocation-test',
  orgId: 'org-a',
  projectId: 'project-a',
  envId: 'env-a',
} as const;

function envelope(envelopeId: string, state: 'active' | 'revoked' = 'active') {
  return passkeyCustodyEnvelope({
    envelopeId,
    // A distinct credential per envelope: two passkeys on one wallet.
    factor: rawPasskeyFactor({ credentialIdB64u: `Y3JlZGVudGlhbC0${envelopeId.slice(-1)}` }),
    lifecycle:
      state === 'active'
        ? { state: 'active', activatedAtMs: 1_000 }
        : { state: 'revoked', activatedAtMs: 1_000, revokedAtMs: 2_000 },
  });
}

test('the last active envelope cannot be revoked', () => {
  const admission = admitEnvelopeRevocation({
    envelopes: [envelope('passkey-envelope-1')],
    envelopeId: 'passkey-envelope-1',
  });

  expect(admission.kind).toBe('refused');
  expect(admission.kind === 'refused' && admission.reason).toContain('no factor that can open');
});

test('one of two active envelopes may be revoked', () => {
  // Removing a synced passkey: the same secret stays reachable through the
  // other envelope, so the lane stays open.
  const admission = admitEnvelopeRevocation({
    envelopes: [envelope('passkey-envelope-1'), envelope('passkey-envelope-2')],
    envelopeId: 'passkey-envelope-1',
  });
  expect(admission.kind).toBe('admitted');
});

test('a revoked envelope does not count toward what remains', () => {
  /* Two rows, one already revoked — so this is still the last *active* one and
     revoking it would strand the seed. Counting rows rather than active rows
     is the mistake this pins. */
  const admission = admitEnvelopeRevocation({
    envelopes: [envelope('passkey-envelope-1'), envelope('passkey-envelope-2', 'revoked')],
    envelopeId: 'passkey-envelope-1',
  });
  expect(admission.kind).toBe('refused');
});

test('an unknown or already-revoked envelope is refused', () => {
  const envelopes = [envelope('passkey-envelope-1'), envelope('passkey-envelope-2', 'revoked')];

  expect(admitEnvelopeRevocation({ envelopes, envelopeId: 'passkey-envelope-9' }).kind).toBe(
    'refused',
  );
  const repeat = admitEnvelopeRevocation({ envelopes, envelopeId: 'passkey-envelope-2' });
  expect(repeat.kind === 'refused' && repeat.reason).toContain('already revoked');
});

test('listing returns a wallet own envelopes and no others', async () => {
  const { database, tempDir } = createTemporaryD1Database();
  try {
    await applySignerMigrations(database);
    const store = new CloudflareD1PasskeyCustodyEnvelopeStore({ database, scope: TEST_SCOPE });

    await store.createEnvelope(envelope('passkey-envelope-1'));
    await store.createEnvelope(envelope('passkey-envelope-2'));
    await store.createEnvelope(
      passkeyCustodyEnvelope({
        walletId: 'mallory.testnet',
        envelopeId: 'passkey-envelope-3',
      }),
    );

    const listed = await store.listWalletEnvelopes(WALLET_ID as WalletId);
    expect(listed.map((record) => String(record.envelopeId)).sort()).toEqual([
      'passkey-envelope-1',
      'passkey-envelope-2',
    ]);
    // The scan is bounded by the wallet's own key prefix.
    for (const record of listed) expect(String(record.walletId)).toBe(WALLET_ID);
  } finally {
    cleanupTemporaryD1Database(tempDir);
  }
});
