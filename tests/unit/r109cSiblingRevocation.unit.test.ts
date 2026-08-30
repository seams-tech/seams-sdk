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
import { CloudflareD1AuthorizationStore } from '../../packages/wallet-server/src/router/cloudflare/d1/authorization/d1AuthorizationStore';
import {
  parsePrincipalId,
  parseWalletSessionMintId,
  parseTenantId,
  type PrincipalId,
  type TenantId,
} from '../../packages/shared-ts/src/authorization/capabilityKinds';
import { buildExactWalletSessionAuthorizationFixture } from './helpers/exactWalletSessionAuthorization.fixtures';
import { parseSessionOrigin } from '../../packages/wallet-server/src/authorization/domain';

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
type SiblingDatabase = Parameters<typeof insertSignerWallet>[0]['database'];

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
  return { walletId, authority: founding.authority, envelopes };
}

async function seedExactSiblingWalletSessions(input: {
  readonly database: SiblingDatabase;
  readonly authority: Awaited<ReturnType<typeof seedAuthorityWithBothSiblings>>['authority'];
}) {
  const tenantId = required(parseTenantId(SCOPE.orgId));
  const principalId = required(parsePrincipalId('principal:r109c-sibling-revocation'));
  const authorizationStore = new CloudflareD1AuthorizationStore({
    database: input.database,
    namespace: SCOPE.namespace,
    walletSignerScope: SCOPE,
  });
  const passkey = buildExactWalletSessionAuthorizationFixture({
    label: 'r109c-passkey',
    tenantId,
    principalId,
    authority: input.authority,
    walletAuthMethodId: required(parseWalletAuthMethodId(PASSKEY_METHOD_ID)),
    issuedAtMs: 3_000,
    expiresAtMs: 10_000,
    remainingUses: 3,
  });
  await authorizationStore.putWalletSessionAuthorizationV2(passkey);
  const email = buildExactWalletSessionAuthorizationFixture({
    label: 'r109c-email',
    tenantId,
    principalId,
    authority: input.authority,
    walletAuthMethodId: required(parseWalletAuthMethodId(EMAIL_METHOD_ID)),
    issuedAtMs: 3_000,
    expiresAtMs: 10_000,
    remainingUses: 3,
  });
  await authorizationStore.putWalletSessionAuthorizationV2(email);
  return { authorizationStore, tenantId, principalId };
}

async function readExactSiblingWalletSessions(input: {
  readonly database: SiblingDatabase;
  readonly tenantId: TenantId;
  readonly principalId: PrincipalId;
}) {
  return await input.database
    .prepare(
      `SELECT session.wallet_auth_method_id,
              session.retired_at_ms,
              quota.remaining_uses,
              quota.lifecycle_kind
         FROM wallet_session_authorizations_v2 AS session
         JOIN authorization_wallet_session_quotas AS quota
           ON quota.namespace = session.namespace
          AND quota.tenant_id = session.tenant_id
          AND quota.quota_id = session.quota_id
        WHERE session.namespace = ?
          AND session.tenant_id = ?
          AND session.principal_id = ?
        ORDER BY session.wallet_auth_method_id`,
    )
    .bind(SCOPE.namespace, input.tenantId, input.principalId)
    .all<{
      readonly wallet_auth_method_id: string;
      readonly retired_at_ms: number | null;
      readonly remaining_uses: number;
      readonly lifecycle_kind: string;
    }>();
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

test('method revocation retires only its exact V2 sessions and exhausts their quotas', async () => {
  const { database, tempDir } = createTemporaryD1Database();
  try {
    await applySignerMigrations(database);
    const { walletId, authority } = await seedAuthorityWithBothSiblings(database);
    const service = createCloudflareD1RouterApiAuthService({ database, ...SCOPE });
    const hostedTenantId = required(parseTenantId(SCOPE.orgId));
    const hostedPrincipalId = required(parsePrincipalId('principal:r109c-hosted-revocation'));
    const hostedParent =
      await service.authorizationSessions.issueDirectWalletSessionAuthorizationV2({
        tenantId: hostedTenantId,
        principalId: hostedPrincipalId,
        walletId,
        authority,
        walletAuthMethodId: required(parseWalletAuthMethodId(EMAIL_METHOD_ID)),
        mintId: required(parseWalletSessionMintId('mint:r109c-hosted-revocation')),
        remainingUses: 3,
        issuedAtMs: 3_500,
        expiresAtMs: 10_000,
      });
    expect(hostedParent.kind).toBe('issued');
    if (hostedParent.kind !== 'issued') throw new Error('hosted parent did not issue');
    const appOrigin = parseSessionOrigin('https://app.r109c.example.test');
    const walletOrigin = parseSessionOrigin('https://wallet.r109c.example.test');
    const hostedDelivery = await service.authorizationSessions.mintHostedWalletSeamsSessionExchange(
      {
        authorization: hostedParent,
        appOrigin,
        walletOrigin,
        issuedAtMs: 4_000,
        expiresAtMs: 9_000,
      },
    );
    const hostedCredential =
      await service.authorizationSessions.redeemHostedWalletSeamsSessionExchange({
        exchangeCode: hostedDelivery.exchangeCode,
        nonce: hostedDelivery.nonce,
        appOrigin,
        walletOrigin,
        redeemedAtMs: 4_100,
      });
    expect(hostedCredential.kind).toBe('redeemed');
    if (hostedCredential.kind !== 'redeemed') throw new Error('hosted child did not redeem');
    await service.authorizationSessions.mintHostedWalletSeamsSessionExchange({
      authorization: hostedParent,
      appOrigin,
      walletOrigin,
      issuedAtMs: 4_200,
      expiresAtMs: 9_000,
    });
    const exact = await seedExactSiblingWalletSessions({ database, authority });

    const revoked = await service.walletAuthMethods.revokeWalletAuthMethod(
      revocationCommand({
        walletId,
        revokeMethodId: EMAIL_METHOD_ID,
        verifiedSourceMethodId: PASSKEY_METHOD_ID,
      }),
    );
    expect(revoked, JSON.stringify(revoked)).toMatchObject({ ok: true });

    expect(
      (
        await readExactSiblingWalletSessions({
          database,
          tenantId: exact.tenantId,
          principalId: exact.principalId,
        })
      ).results,
    ).toEqual([
      {
        wallet_auth_method_id: EMAIL_METHOD_ID,
        retired_at_ms: 5_000,
        remaining_uses: 0,
        lifecycle_kind: 'exhausted',
      },
      {
        wallet_auth_method_id: PASSKEY_METHOD_ID,
        retired_at_ms: null,
        remaining_uses: 3,
        lifecycle_kind: 'active',
      },
    ]);
    await expect(
      database
        .prepare(
          `SELECT lifecycle_kind, retired_at_ms
             FROM wallet_session_hosted_credentials_v2
            WHERE namespace = ? AND tenant_id = ? AND wallet_auth_method_id = ?`,
        )
        .bind(SCOPE.namespace, hostedTenantId, EMAIL_METHOD_ID)
        .first(),
    ).resolves.toEqual({ lifecycle_kind: 'retired', retired_at_ms: 5_000 });
    await expect(
      database
        .prepare(
          `SELECT COUNT(*) AS count
             FROM wallet_session_hosted_exchange_codes_v2
            WHERE namespace = ? AND tenant_id = ? AND wallet_auth_method_id = ?
              AND lifecycle_kind = 'issued'`,
        )
        .bind(SCOPE.namespace, hostedTenantId, EMAIL_METHOD_ID)
        .first<{ readonly count?: unknown }>(),
    ).resolves.toEqual({ count: 0 });

    await exact.authorizationStore.retireWalletSessionAuthorizationsForAuthMethod({
      tenantId: exact.tenantId,
      walletId,
      walletAuthMethodId: required(parseWalletAuthMethodId(EMAIL_METHOD_ID)),
      nowMs: 6_000,
    });
    expect(
      (
        await readExactSiblingWalletSessions({
          database,
          tenantId: exact.tenantId,
          principalId: exact.principalId,
        })
      ).results,
    ).toEqual([
      {
        wallet_auth_method_id: EMAIL_METHOD_ID,
        retired_at_ms: 5_000,
        remaining_uses: 0,
        lifecycle_kind: 'exhausted',
      },
      {
        wallet_auth_method_id: PASSKEY_METHOD_ID,
        retired_at_ms: null,
        remaining_uses: 3,
        lifecycle_kind: 'active',
      },
    ]);
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
