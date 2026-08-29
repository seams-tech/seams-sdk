/**
 * Seeds one exact wallet/authority/method tuple plus its directly issued V2
 * Wallet Session into a temporary signer D1, so status lifecycle tests observe
 * the rows production writes.
 *
 * The authority and auth method come from the shared linked-device management
 * factory and reach D1 through `D1WalletAuthorityStore`'s commit/activate
 * transition; the session, quota, and primary credential digest come from the
 * direct V2 issuer. Tests that need an unavailable authority, method, or
 * capability mutate the seeded state through the helpers below, which rewrite
 * whole records rather than individual columns.
 */
import {
  buildPendingWalletAuthorityV1,
  buildRevokedWalletAuthorityV1,
  computeWalletAuthorityDigestB64u,
  type ActiveWalletAuthorityV1,
} from '@shared/authorization/walletAuthority';
import {
  parseReusableWalletSessionMintId,
  parsePrincipalId,
  parseTenantId,
  WALLET_SESSION_CLIENT_CAPABILITY_V1,
  type MpcWalletSigningQuotaId,
  type PrincipalId,
  type TenantId,
  type WalletSessionId,
} from '@shared/authorization/capabilityKinds';
import { buildWalletAuthMethodRecordV2 } from '@shared/utils/registrationIntent';
import { base64UrlEncode } from '@shared/utils/base64';
import { parseDigestB64u } from '@shared/utils/canonicalPrimitives';
import type { WalletId } from '@shared/utils/domainIds';
import type { WalletSessionOperationCredentialV1 } from '@shared/device-linking/contracts';
import { AuthorizationService } from '../../../packages/wallet-server/src/authorization/service';
import {
  buildWalletSessionAuthorizationV2,
  parseWalletSessionAuthorizationV2,
  WALLET_UNLOCK_EXACT_RESPONSE_FAMILY_V1,
} from '../../../packages/wallet-server/src/authorization/domain';
import { CloudflareD1AuthorizationStore } from '../../../packages/wallet-server/src/router/cloudflare/d1/authorization/d1AuthorizationStore';
import { D1WalletAuthorityStore } from '../../../packages/wallet-server/src/router/cloudflare/d1/wallet/d1WalletAuthorityStore';
import { capabilityPolicyPort } from '../../../packages/wallet-server/src/authorization/capabilityPolicy';
import {
  applyD1MigrationFiles,
  cleanupTemporaryD1Database,
  createTemporaryD1Database,
  listD1MigrationFiles,
} from '../../helpers/sqliteD1';
import {
  buildLinkedDeviceManagementAuthorityFixture,
  fullOwnerPermissionsForManagementFixture,
  type LinkedDeviceManagementAuthorityFixture,
} from './linkedDeviceManagement.fixtures';
import { buildMpcMaterialActivationRefFixture } from './ecdsaMaterialRef.fixtures';

type D1DatabaseForTest = Parameters<typeof applyD1MigrationFiles>[0];
type ActiveAuthMethod = LinkedDeviceManagementAuthorityFixture['authMethod'];

const SIGNER_MIGRATIONS = listD1MigrationFiles('d1-signer');
const STORE_SCOPE = { orgId: 'test-org', projectId: 'test-project', envId: 'test-env' } as const;

export const UNKNOWN_PRIMARY_CREDENTIAL_TOKEN = `wst_${base64UrlEncode(new Uint8Array(32).fill(7))}`;

export type ExactWalletSessionStatusPersistenceFixture = {
  readonly database: D1DatabaseForTest;
  readonly namespace: string;
  readonly service: AuthorizationService;
  readonly authority: ActiveWalletAuthorityV1;
  readonly authMethod: ActiveAuthMethod;
  readonly tenantId: TenantId;
  readonly principalId: PrincipalId;
  readonly walletId: WalletId;
  readonly walletSessionId: WalletSessionId;
  readonly quotaId: MpcWalletSigningQuotaId;
  readonly operationCredential: WalletSessionOperationCredentialV1;
  readonly issuedAtMs: number;
  readonly expiresAtMs: number;
  readonly cleanup: () => void;
};

function required<T>(
  result:
    | { readonly ok: true; readonly value: T }
    | { readonly ok: false; readonly error: { readonly message: string } },
): T {
  if (!result.ok) throw new Error(result.error.message);
  return result.value;
}

/**
 * Rebuilds the pre-activation pair the authority store's CAS transition
 * expects, from the shared factory's already-active records.
 */
async function pendingRecordsFor(fixture: LinkedDeviceManagementAuthorityFixture) {
  const draft = buildPendingWalletAuthorityV1({
    kind: fixture.authority.kind,
    authorityId: fixture.authority.authorityId,
    walletId: fixture.authority.walletId,
    principal: fixture.authority.principal,
    provenance: fixture.authority.provenance,
    permissions: fixture.authority.permissions,
    signerActivations: fixture.authority.signerActivations,
    signerActivationSetDigestB64u: fixture.authority.signerActivationSetDigestB64u,
    authorityDigestB64u: fixture.authority.authorityDigestB64u,
    revocationEpoch: 0,
    createdAtMs: fixture.authority.createdAtMs,
    updatedAtMs: fixture.authority.createdAtMs,
    state: 'pending_local_install',
    localInstallPackageSetDigestB64u: fixture.authority.signerActivationSetDigestB64u,
  });
  const authority = buildPendingWalletAuthorityV1({
    ...draft,
    authorityDigestB64u: parseDigestB64u(await computeWalletAuthorityDigestB64u(draft)),
  });
  const authMethod = buildWalletAuthMethodRecordV2({
    version: fixture.authMethod.version,
    walletAuthMethodId: fixture.authMethod.walletAuthMethodId,
    walletId: fixture.authMethod.walletId,
    walletAuthorityId: fixture.authMethod.walletAuthorityId,
    kind: 'passkey',
    status: 'pending_local_install',
    rpId: fixture.authMethod.rpId,
    credentialIdB64u: fixture.authMethod.credentialIdB64u,
    credentialPublicKeyB64u: fixture.authMethod.credentialPublicKeyB64u,
    counter: fixture.authMethod.counter,
    createdAtMs: fixture.authMethod.createdAtMs,
    updatedAtMs: fixture.authMethod.createdAtMs,
  });
  if (authMethod.status !== 'pending_local_install') {
    throw new Error('pending Passkey auth method fixture changed branch');
  }
  return { authority, authMethod };
}

/**
 * Creates the temporary database, activates the exact authority tuple, and
 * issues one direct V2 Wallet Session with its primary operation credential.
 * Callers must invoke `cleanup()`.
 */
export async function seedExactWalletSessionStatusFixture(input: {
  readonly label: string;
}): Promise<ExactWalletSessionStatusPersistenceFixture> {
  const temporary = createTemporaryD1Database();
  try {
    await applyD1MigrationFiles(temporary.database, SIGNER_MIGRATIONS);
    const namespace = `status-${input.label}`;
    const tenantId = required(parseTenantId(`tenant:${input.label}`));
    const principalId = required(parsePrincipalId(`principal:${input.label}`));
    const issuedAtMs = 300;
    const expiresAtMs = 400;
    const records = await buildLinkedDeviceManagementAuthorityFixture({
      label: input.label,
      permissions: fullOwnerPermissionsForManagementFixture(),
      provenance: 'wallet_registration',
      tenantId: String(tenantId),
      principalId: String(principalId),
      expiresAtMs,
      identity: {
        walletId: `wallet:${input.label}`,
        authorityId: `authority:${input.label}`,
        walletAuthMethodId: `wallet-auth-method:${input.label}`,
        rpId: 'wallet.example.test',
      },
    });
    const pending = await pendingRecordsFor(records);

    const authorityStore = new D1WalletAuthorityStore({
      database: temporary.database,
      scope: { namespace, ...STORE_SCOPE },
      ensureSchema: false,
    });
    await authorityStore.commitPendingAuthority({
      authority: pending.authority,
      authMethod: pending.authMethod,
    });
    const activated = await authorityStore.activatePendingAuthority({
      pendingAuthority: pending.authority,
      activeAuthority: records.authority,
      pendingAuthMethod: pending.authMethod,
      activeAuthMethod: records.authMethod,
    });
    if (activated.kind !== 'activated') {
      throw new Error(`exact status authority fixture activation failed: ${activated.kind}`);
    }

    const store = new CloudflareD1AuthorizationStore({
      database: temporary.database,
      namespace,
      walletSignerScope: { namespace, ...STORE_SCOPE },
    });
    const service = new AuthorizationService({
      policy: capabilityPolicyPort,
      sessions: store,
      evidence: store,
      grants: store,
      authorizedOperations: store,
      audit: store,
    });
    const issued = await service.issueDirectWalletSessionAuthorizationV2({
      tenantId,
      principalId,
      walletId: records.authority.walletId,
      authority: records.authority,
      walletAuthMethodId: records.authMethod.walletAuthMethodId,
      mintId: required(parseReusableWalletSessionMintId(`mint:${input.label}`)),
      remainingUses: 3,
      issuedAtMs,
      expiresAtMs,
      walletSessionClientCapability: WALLET_SESSION_CLIENT_CAPABILITY_V1,
      responseFamily: WALLET_UNLOCK_EXACT_RESPONSE_FAMILY_V1,
    });
    if (issued.kind !== 'issued') {
      throw new Error(`exact status Wallet Session fixture was not issued: ${issued.kind}`);
    }

    return {
      database: temporary.database,
      namespace,
      service,
      authority: records.authority,
      authMethod: records.authMethod,
      tenantId,
      principalId,
      walletId: records.authority.walletId,
      walletSessionId: issued.session.walletSessionId,
      quotaId: issued.session.quotaId,
      operationCredential: issued.operationCredential,
      issuedAtMs,
      expiresAtMs,
      cleanup: () => cleanupTemporaryD1Database(temporary.tempDir),
    };
  } catch (error) {
    cleanupTemporaryD1Database(temporary.tempDir);
    throw error;
  }
}

/** Every seeded-state deviation a status lifecycle test needs. */
export type SeededStatusTransition =
  | 'revoke_authority'
  | 'revoke_auth_method'
  | 'retarget_session_material'
  | 'exhaust_quota'
  | 'retire_authorization';

/** Deviations land 5ms after issuance, well inside the seeded session lifetime. */
export const SEEDED_TRANSITION_AT_MS = 305;

/**
 * Revokes the seeded authority. Revocation advances the epoch and rewrites the
 * whole record, because the schema rejects both a revoked epoch-0 authority and
 * any column that disagrees with `record_json`.
 */
async function revokeAuthority(fixture: ExactWalletSessionStatusPersistenceFixture): Promise<void> {
  const draft = buildRevokedWalletAuthorityV1({
    ...fixture.authority,
    revocationEpoch: fixture.authority.revocationEpoch + 1,
    updatedAtMs: SEEDED_TRANSITION_AT_MS,
    state: 'revoked',
    revokedAtMs: SEEDED_TRANSITION_AT_MS,
  });
  const revoked = buildRevokedWalletAuthorityV1({
    ...draft,
    authorityDigestB64u: parseDigestB64u(await computeWalletAuthorityDigestB64u(draft)),
  });
  await fixture.database
    .prepare(
      `UPDATE wallet_authorities
          SET lifecycle_state = ?, authority_digest_b64u = ?, revocation_epoch = ?,
              record_json = ?, updated_at_ms = ?, revoked_at_ms = ?
        WHERE namespace = ? AND org_id = ? AND project_id = ? AND env_id = ?
          AND authority_id = ?`,
    )
    .bind(
      revoked.state,
      String(revoked.authorityDigestB64u),
      revoked.revocationEpoch,
      JSON.stringify(revoked),
      revoked.updatedAtMs,
      revoked.revokedAtMs,
      fixture.namespace,
      STORE_SCOPE.orgId,
      STORE_SCOPE.projectId,
      STORE_SCOPE.envId,
      String(revoked.authorityId),
    )
    .run();
}

/**
 * Retargets the stored session's signing subjects onto material the authority
 * does not hold — what a lost authority-promotion projection leaves behind. The
 * authority row is untouched, so only the capability stops resolving.
 */
async function retargetSessionMaterial(
  fixture: ExactWalletSessionStatusPersistenceFixture,
): Promise<void> {
  const row = await fixture.database
    .prepare(
      `SELECT record_json
         FROM wallet_session_authorizations_v2
        WHERE namespace = ? AND tenant_id = ? AND wallet_session_id = ?`,
    )
    .bind(fixture.namespace, String(fixture.tenantId), String(fixture.walletSessionId))
    .first<{ readonly record_json: string }>();
  if (!row) throw new Error('seeded exact authorization row is missing');
  const stored = parseWalletSessionAuthorizationV2(JSON.parse(row.record_json));
  const materialActivation = buildMpcMaterialActivationRefFixture(
    `${fixture.namespace}-retargeted`,
  );
  const [first, ...rest] = stored.capabilitySubjects.map((subject) =>
    subject.kind === 'sign' || subject.kind === 'export_keys'
      ? { ...subject, materialActivation }
      : subject,
  );
  if (!first) throw new Error('seeded exact authorization has no capability subjects');
  const retargeted = buildWalletSessionAuthorizationV2({
    ...stored,
    capabilitySubjects: [first, ...rest],
  });
  await fixture.database
    .prepare(
      `UPDATE wallet_session_authorizations_v2
          SET record_json = ?, capability_subjects_json = ?
        WHERE namespace = ? AND tenant_id = ? AND wallet_session_id = ?`,
    )
    .bind(
      JSON.stringify(retargeted),
      JSON.stringify(retargeted.capabilitySubjects),
      fixture.namespace,
      String(fixture.tenantId),
      String(fixture.walletSessionId),
    )
    .run();
}

/**
 * Applies one deviation to the seeded state. Each rewrites whole records so the
 * schema's record/column coherence checks stay satisfied.
 */
export async function applySeededStatusTransition(
  fixture: ExactWalletSessionStatusPersistenceFixture,
  transition: SeededStatusTransition,
): Promise<void> {
  switch (transition) {
    case 'revoke_authority':
      return await revokeAuthority(fixture);
    case 'retarget_session_material':
      return await retargetSessionMaterial(fixture);
    case 'revoke_auth_method': {
      const revoked = buildWalletAuthMethodRecordV2({
        ...fixture.authMethod,
        status: 'revoked',
        updatedAtMs: SEEDED_TRANSITION_AT_MS,
        revokedAtMs: SEEDED_TRANSITION_AT_MS,
      });
      await fixture.database
        .prepare(
          `UPDATE wallet_auth_methods
              SET status = ?, record_json = ?, updated_at_ms = ?, revoked_at_ms = ?
            WHERE namespace = ? AND org_id = ? AND project_id = ? AND env_id = ?
              AND wallet_auth_method_id = ?`,
        )
        .bind(
          revoked.status,
          JSON.stringify(revoked),
          SEEDED_TRANSITION_AT_MS,
          SEEDED_TRANSITION_AT_MS,
          fixture.namespace,
          STORE_SCOPE.orgId,
          STORE_SCOPE.projectId,
          STORE_SCOPE.envId,
          String(revoked.walletAuthMethodId),
        )
        .run();
      return;
    }
    case 'exhaust_quota':
      await fixture.database
        .prepare(
          `UPDATE authorization_wallet_session_quotas
              SET remaining_uses = 0, lifecycle_kind = 'exhausted'
            WHERE namespace = ? AND tenant_id = ? AND quota_id = ?`,
        )
        .bind(fixture.namespace, String(fixture.tenantId), String(fixture.quotaId))
        .run();
      return;
    case 'retire_authorization':
      await fixture.database
        .prepare(
          `UPDATE wallet_session_authorizations_v2
              SET retired_at_ms = ?
            WHERE namespace = ? AND tenant_id = ? AND wallet_session_id = ?`,
        )
        .bind(
          SEEDED_TRANSITION_AT_MS,
          fixture.namespace,
          String(fixture.tenantId),
          String(fixture.walletSessionId),
        )
        .run();
      return;
  }
}
