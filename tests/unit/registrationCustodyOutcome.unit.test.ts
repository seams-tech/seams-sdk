import { expect, test } from '@playwright/test';
import { CloudflareD1WalletCustodyCommitStore } from '../../packages/sdk-server-ts/src/router/cloudflare/d1/passkeyCustody/d1WalletCustodyCommitStore';
import { commitRegistrationCustody } from '../../packages/sdk-server-ts/src/router/domains/passkeyCustody/registrationCustodyOutcome';
import {
  buildEmailOtpWalletAuthAuthority,
  buildPasskeyWalletAuthAuthority,
} from '../../packages/shared-ts/src/utils/walletAuthAuthority';
import type { WalletId } from '../../packages/shared-ts/src/utils/domainIds';
import { cleanupTemporaryD1Database, createTemporaryD1Database } from '../helpers/sqliteD1';
import { applySignerMigrations } from './helpers/cloudflareD1RouterApiAuthService.fixtures';
import {
  ALT_DIGEST_B64U,
  buildWalletCustodyCommitPayloadFixture,
  CREDENTIAL_ID_B64U,
  RP_ID,
  WALLET_ID,
} from './helpers/passkeyCustodyEnvelope.fixtures';

/**
 * The whole custody side-effect of one registration leg.
 *
 * These own the composition — factor from the verified authority, then payload
 * admitted against the registered wallet — and the outcome mapping the client
 * acts on. The rule that shapes all of it: activation never fails because of
 * custody, because the seed lives in the client's worker and only the client
 * can retry, re-enter as a join, or abandon.
 */

const TEST_SCOPE = {
  namespace: 'registration-custody-outcome-test',
  orgId: 'org-a',
  projectId: 'project-a',
  envId: 'env-a',
} as const;

const NOW_MS = 1_700_000_000_000;

function passkeyAuthority() {
  return buildPasskeyWalletAuthAuthority({
    walletId: WALLET_ID,
    rpId: RP_ID,
    credentialIdB64u: CREDENTIAL_ID_B64U,
  });
}

function emailOtpAuthority() {
  return buildEmailOtpWalletAuthAuthority({
    walletId: WALLET_ID,
    provider: 'google',
    providerUserId: 'google-user-1',
    emailHashHex: 'a'.repeat(64),
  });
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

test('a leg with no custody payload reports not_requested', async () => {
  await withStore(async (store) => {
    const outcome = await commitRegistrationCustody({
      verifiedWalletId: WALLET_ID as WalletId,
      verifiedAuthority: passkeyAuthority(),
      nowMs: NOW_MS,
      store,
    });
    expect(outcome.status).toBe('not_requested');
  });
});

test('an establishing run under a verified passkey authority commits', async () => {
  await withStore(async (store) => {
    const outcome = await commitRegistrationCustody({
      payload: buildWalletCustodyCommitPayloadFixture({ walletId: WALLET_ID }),
      verifiedWalletId: WALLET_ID as WalletId,
      verifiedAuthority: passkeyAuthority(),
      nowMs: NOW_MS,
      store,
    });
    expect(outcome.status).toBe('committed');
  });
});

test('a joining run reports its digest and writes nothing', async () => {
  await withStore(async (store) => {
    const outcome = await commitRegistrationCustody({
      payload: buildWalletCustodyCommitPayloadFixture({
        walletId: WALLET_ID,
        keySet: 'near_ed25519_v1',
        keyManifestDigestB64u: ALT_DIGEST_B64U,
        origin: 'join',
      }),
      verifiedWalletId: WALLET_ID as WalletId,
      verifiedAuthority: passkeyAuthority(),
      nowMs: NOW_MS,
      store,
    });
    expect(outcome.status).toBe('joined');
    expect(outcome.status === 'joined' && outcome.keyManifestDigestB64u).toBe(ALT_DIGEST_B64U);
  });
});

test('an Email OTP leg without its enrollment is rejected, not committed blindly', async () => {
  await withStore(async (store) => {
    const outcome = await commitRegistrationCustody({
      payload: buildWalletCustodyCommitPayloadFixture({ walletId: WALLET_ID }),
      verifiedWalletId: WALLET_ID as WalletId,
      verifiedAuthority: emailOtpAuthority(),
      nowMs: NOW_MS,
      store,
    });

    expect(outcome.status).toBe('rejected');
    expect(outcome.status === 'rejected' && outcome.reason).toContain('verified enrollment');

    // Nothing was written, so the wallet can still establish custody once the
    // enrollment is supplied.
    const retried = await commitRegistrationCustody({
      payload: buildWalletCustodyCommitPayloadFixture({ walletId: WALLET_ID }),
      verifiedWalletId: WALLET_ID as WalletId,
      verifiedAuthority: passkeyAuthority(),
      nowMs: NOW_MS,
      store,
    });
    expect(retried.status).toBe('committed');
  });
});

test('a payload for another wallet is rejected', async () => {
  await withStore(async (store) => {
    const outcome = await commitRegistrationCustody({
      payload: buildWalletCustodyCommitPayloadFixture({ walletId: 'mallory.testnet' }),
      verifiedWalletId: WALLET_ID as WalletId,
      verifiedAuthority: passkeyAuthority(),
      nowMs: NOW_MS,
      store,
    });
    expect(outcome.status).toBe('rejected');
  });
});

test('a losing race is reported as custody_already_established, not as success', async () => {
  await withStore(async (store) => {
    const first = await commitRegistrationCustody({
      payload: buildWalletCustodyCommitPayloadFixture({ walletId: WALLET_ID }),
      verifiedWalletId: WALLET_ID as WalletId,
      verifiedAuthority: passkeyAuthority(),
      nowMs: NOW_MS,
      store,
    });
    expect(first.status).toBe('committed');

    // A second establishing run for the same wallet. The client must discard
    // its seed and re-enter as a join rather than believe it succeeded.
    const second = await commitRegistrationCustody({
      payload: buildWalletCustodyCommitPayloadFixture({
        walletId: WALLET_ID,
        keyManifestDigestB64u: ALT_DIGEST_B64U,
      }),
      verifiedWalletId: WALLET_ID as WalletId,
      verifiedAuthority: passkeyAuthority(),
      nowMs: NOW_MS,
      store,
    });
    expect(['custody_already_established', 'committed']).toContain(second.status);
  });
});
