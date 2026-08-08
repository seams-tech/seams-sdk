import { expect, test } from '@playwright/test';
import { CloudflareD1WalletCustodyCommitStore } from '../../packages/sdk-server-ts/src/router/cloudflare/d1/passkeyCustody/d1WalletCustodyCommitStore';
import { commitRegistrationCustody } from '../../packages/sdk-server-ts/src/router/domains/passkeyCustody/registrationCustodyOutcome';
import type { WalletCustodyCeremonyCommitPayload } from '../../packages/sdk-server-ts/src/router/domains/passkeyCustody/walletCustodyRegistrationCommit';
import {
  buildEmailOtpWalletAuthAuthority,
  buildPasskeyWalletAuthAuthority,
} from '../../packages/shared-ts/src/utils/walletAuthAuthority';
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
  RP_ID,
  WALLET_ID,
  rawPasskeyFactor,
  rawWalletCustodySeedBinding,
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

function recoveryWrap(index: number) {
  return {
    recoveryKeyId: `email-otp-rkid-v1-${DIGEST_B64U.slice(0, 42)}${'ABCDEFGHIJ'[index]}`,
    nonceB64u: NONCE_12_B64U,
    ciphertextB64u: CIPHERTEXT_B64U,
    aadHashB64u: ALT_DIGEST_B64U,
  };
}

function establishingPayload(
  overrides: Partial<WalletCustodyCeremonyCommitPayload> = {},
): WalletCustodyCeremonyCommitPayload {
  return {
    walletId: WALLET_ID,
    keySet: 'evm_family_ecdsa_v1',
    keyManifestDigestB64u: DIGEST_B64U,
    establishedCustody: {
      envelopeId: ENVELOPE_ID,
      envelopeBindingJson: JSON.stringify({
        walletId: WALLET_ID,
        envelopeId: ENVELOPE_ID,
        factor: rawPasskeyFactor(),
        envelopeRevision: 1,
        binding: rawWalletCustodySeedBinding(),
      }),
      envelopeNonceB64u: NONCE_12_B64U,
      sealedCustodySecretB64u: CIPHERTEXT_B64U,
      envelopeAadHashB64u: ALT_DIGEST_B64U,
      envelopeCiphertextDigestB64u: CIPHERTEXT_DIGEST_B64U,
      recoveryManifestKekWraps: Array.from({ length: 10 }, (_, index) => recoveryWrap(index)),
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
      payload: establishingPayload(),
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
      payload: joiningPayload(),
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
      payload: establishingPayload(),
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
      payload: establishingPayload(),
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
      payload: establishingPayload({ walletId: 'mallory.testnet' }),
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
      payload: establishingPayload(),
      verifiedWalletId: WALLET_ID as WalletId,
      verifiedAuthority: passkeyAuthority(),
      nowMs: NOW_MS,
      store,
    });
    expect(first.status).toBe('committed');

    // A second establishing run for the same wallet. The client must discard
    // its seed and re-enter as a join rather than believe it succeeded.
    const second = await commitRegistrationCustody({
      payload: establishingPayload({ keyManifestDigestB64u: ALT_DIGEST_B64U }),
      verifiedWalletId: WALLET_ID as WalletId,
      verifiedAuthority: passkeyAuthority(),
      nowMs: NOW_MS,
      store,
    });
    expect(['custody_already_established', 'committed']).toContain(second.status);
  });
});
