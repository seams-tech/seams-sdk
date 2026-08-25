import { expect, test } from '@playwright/test';
import { createTemporaryD1Database, cleanupTemporaryD1Database } from '../helpers/sqliteD1';
import { createCloudflareD1RouterApiAuthService } from '../../packages/wallet-server/src/router/cloudflare/d1/auth/d1RouterApiAuthService';
import {
  applySignerMigrations,
  insertSignerWallet,
  insertWalletAuthMethod,
  seedFoundingPasskeyAuthority,
} from './helpers/cloudflareD1RouterApiAuthService.fixtures';
import { CloudflareD1PasskeyCustodyEnvelopeStore } from '../../packages/wallet-server/src/router/cloudflare/d1/passkeyCustody/d1PasskeyCustodyEnvelopeStore';
import {
  buildActiveMethodBoundPasskeyCustodyEnvelopeFixture,
  buildActiveMethodBoundEmailOtpCustodyEnvelopeFixture,
  ENROLLMENT_ID,
} from './helpers/passkeyCustodyEnvelope.fixtures';
import { parseWalletAuthMethodId } from '../../packages/shared-ts/src/utils/domainIds';
import { D1WalletAuthMethodStore } from '../../packages/wallet-server/src/core/d1WalletAuthMethodStore';
import { walletIdFromString } from '../../packages/shared-ts/src/utils/registrationIntent';

/**
 * Refactor 109C Phase 0: exact method revocation between two SIBLINGS on ONE
 * authority, in both proof directions.
 *
 * The configuration R109C creates, and the only one that proves the sibling
 * guard. Revocation between methods on separate authorities — which the linked
 * device suite already covers — cannot: there the authority itself distinguishes
 * them, so a rule that keyed on authority rather than method would still pass.
 *
 * The source is pre-verified here because that is the shape the service takes:
 * the route verifies the proof and hands down which method it proved. The two
 * directions are exactly which sibling is that verified source.
 */

const SCOPE = {
  namespace: 'r109c-sibling-revocation',
  orgId: 'org-a',
  projectId: 'project-a',
  envId: 'env-a',
} as const;

const WALLET_ID = 'sibling-revocation.testnet';
const AUTHORITY_ID = 'wallet-authority:sibling-revocation';
const PASSKEY_METHOD_ID = 'wallet-auth-method:sibling-passkey';
const EMAIL_METHOD_ID = 'wallet-auth-method:sibling-email';
const RP_ID = 'sibling.example.test';
const EMAIL_HASH_HEX = 'a'.repeat(64);

function required<T>(
  result: { ok: true; value: T } | { ok: false; error: { message: string } },
): T {
  if (!result.ok) throw new Error(result.error.message);
  return result.value;
}

/**
 * One authority holding both families, each owning its exact custody envelope —
 * the state an R109C addition leaves behind.
 */
async function seedAuthorityWithBothSiblings(
  database: Parameters<typeof insertSignerWallet>[0]['database'],
) {
  const walletId = walletIdFromString(WALLET_ID);
  await insertSignerWallet({ database, ...SCOPE, walletId });
  const founding = await seedFoundingPasskeyAuthority({
    database,
    ...SCOPE,
    identity: {
      walletId: WALLET_ID,
      authorityId: AUTHORITY_ID,
      walletAuthMethodId: PASSKEY_METHOD_ID,
      rpId: RP_ID,
    },
  });
  /* The sibling: same wallet, same authority, other family. */
  await insertWalletAuthMethod({
    database,
    ...SCOPE,
    record: {
      kind: 'email_otp',
      walletAuthMethodId: EMAIL_METHOD_ID,
      walletAuthorityId: AUTHORITY_ID,
      walletId: WALLET_ID,
      emailHashHex: EMAIL_HASH_HEX,
      registrationAuthorityId: 'sibling@example.test',
      createdAtMs: 1_000,
      updatedAtMs: 1_000,
    },
  });
  const envelopes = new CloudflareD1PasskeyCustodyEnvelopeStore({ database, scope: SCOPE });
  await envelopes.createEnvelope(
    buildActiveMethodBoundPasskeyCustodyEnvelopeFixture({
      walletId: WALLET_ID,
      envelopeId: 'passkey-envelope:sibling',
      rpId: String(founding.authMethod.rpId),
      credentialIdB64u: String(founding.authMethod.credentialIdB64u),
      walletAuthMethodId: PASSKEY_METHOD_ID,
    }),
  );
  await envelopes.createEnvelope(
    buildActiveMethodBoundEmailOtpCustodyEnvelopeFixture({
      walletId: WALLET_ID,
      envelopeId: 'email-envelope:sibling',
      enrollmentId: ENROLLMENT_ID,
      enrollmentSealKeyVersion: 'v1',
      walletAuthMethodId: EMAIL_METHOD_ID,
    }),
  );
  return { walletId, envelopes };
}

function revocationCommand(input: {
  readonly walletId: ReturnType<typeof walletIdFromString>;
  readonly revokeMethodId: string;
  readonly verifiedSourceMethodId: string;
}) {
  return {
    subject: { kind: 'wallet_auth_method_management' as const, walletId: input.walletId },
    walletAuthMethodId: required(parseWalletAuthMethodId(input.revokeMethodId)),
    requestedAtMs: 5_000,
    verifiedSource: {
      walletAuthMethodId: required(parseWalletAuthMethodId(input.verifiedSourceMethodId)),
      verifiedAtMs: 4_900,
    },
    sourceProof: { kind: 'verified_source' as const },
  };
}

test('a Passkey sibling revokes the Email OTP method on its own authority', async () => {
  const { database, tempDir } = createTemporaryD1Database();
  try {
    await applySignerMigrations(database);
    const { walletId, envelopes } = await seedAuthorityWithBothSiblings(database);
    const service = createCloudflareD1RouterApiAuthService({ database, ...SCOPE });

    const revoked = await service.walletAuthMethods.revokeWalletAuthMethod(
      revocationCommand({
        walletId,
        revokeMethodId: EMAIL_METHOD_ID,
        verifiedSourceMethodId: PASSKEY_METHOD_ID,
      }),
    );
    expect(revoked, JSON.stringify(revoked)).toMatchObject({ ok: true });

    const methods = await new D1WalletAuthMethodStore({
      database,
      ...SCOPE,
      ensureSchema: false,
    }).listForWalletV2({ walletId });
    const byId = new Map(methods.map((m) => [String(m.walletAuthMethodId), m.status]));
    expect(byId.get(EMAIL_METHOD_ID)).toBe('revoked');
    /* The sibling is untouched: revocation is per method, not per authority. */
    expect(byId.get(PASSKEY_METHOD_ID)).toBe('active');

    const remaining = await envelopes.listWalletEnvelopes(walletId, { limit: 10 });
    const emailEnvelope = remaining.find((e) => String(e.envelopeId) === 'email-envelope:sibling');
    const passkeyEnvelope = remaining.find(
      (e) => String(e.envelopeId) === 'passkey-envelope:sibling',
    );
    expect(emailEnvelope?.lifecycle.state).toBe('revoked');
    expect(passkeyEnvelope?.lifecycle.state).toBe('active');
  } finally {
    cleanupTemporaryD1Database(tempDir);
  }
});

test('an Email OTP sibling revokes the Passkey method on its own authority', async () => {
  const { database, tempDir } = createTemporaryD1Database();
  try {
    await applySignerMigrations(database);
    const { walletId, envelopes } = await seedAuthorityWithBothSiblings(database);
    const service = createCloudflareD1RouterApiAuthService({ database, ...SCOPE });

    const revoked = await service.walletAuthMethods.revokeWalletAuthMethod(
      revocationCommand({
        walletId,
        revokeMethodId: PASSKEY_METHOD_ID,
        verifiedSourceMethodId: EMAIL_METHOD_ID,
      }),
    );
    expect(revoked, JSON.stringify(revoked)).toMatchObject({ ok: true });

    const methods = await new D1WalletAuthMethodStore({
      database,
      ...SCOPE,
      ensureSchema: false,
    }).listForWalletV2({ walletId });
    const byId = new Map(methods.map((m) => [String(m.walletAuthMethodId), m.status]));
    expect(byId.get(PASSKEY_METHOD_ID)).toBe('revoked');
    expect(byId.get(EMAIL_METHOD_ID)).toBe('active');

    const remaining = await envelopes.listWalletEnvelopes(walletId, { limit: 10 });
    expect(
      remaining.find((e) => String(e.envelopeId) === 'passkey-envelope:sibling')?.lifecycle.state,
    ).toBe('revoked');
    expect(
      remaining.find((e) => String(e.envelopeId) === 'email-envelope:sibling')?.lifecycle.state,
    ).toBe('active');
  } finally {
    cleanupTemporaryD1Database(tempDir);
  }
});

test('the last remaining method on the authority cannot be revoked by its revoked sibling', async () => {
  const { database, tempDir } = createTemporaryD1Database();
  try {
    await applySignerMigrations(database);
    const { walletId } = await seedAuthorityWithBothSiblings(database);
    const service = createCloudflareD1RouterApiAuthService({ database, ...SCOPE });

    await service.walletAuthMethods.revokeWalletAuthMethod(
      revocationCommand({
        walletId,
        revokeMethodId: EMAIL_METHOD_ID,
        verifiedSourceMethodId: PASSKEY_METHOD_ID,
      }),
    );
    /* A revoked method is not a source, so it cannot take the wallet's last
       way in with it. */
    const second = await service.walletAuthMethods.revokeWalletAuthMethod(
      revocationCommand({
        walletId,
        revokeMethodId: PASSKEY_METHOD_ID,
        verifiedSourceMethodId: EMAIL_METHOD_ID,
      }),
    );
    expect(second.ok).toBe(false);
  } finally {
    cleanupTemporaryD1Database(tempDir);
  }
});

test('a method cannot revoke itself', async () => {
  const { database, tempDir } = createTemporaryD1Database();
  try {
    await applySignerMigrations(database);
    const { walletId } = await seedAuthorityWithBothSiblings(database);
    const service = createCloudflareD1RouterApiAuthService({ database, ...SCOPE });
    const selfRevoke = await service.walletAuthMethods.revokeWalletAuthMethod(
      revocationCommand({
        walletId,
        revokeMethodId: PASSKEY_METHOD_ID,
        verifiedSourceMethodId: PASSKEY_METHOD_ID,
      }),
    );
    expect(selfRevoke).toMatchObject({ ok: false, code: 'unauthorized' });
  } finally {
    cleanupTemporaryD1Database(tempDir);
  }
});
