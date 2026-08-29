import {
  applyD1MigrationFiles,
  cleanupTemporaryD1Database,
  createTemporaryD1Database,
  listD1MigrationFiles,
  type TemporaryD1Database,
} from '../../helpers/sqliteD1';
import {
  runRegistrationCredentialRemediation,
  type RegistrationCredentialRemediationInput,
  type RegistrationCredentialRemediationReportV1,
} from '../../../packages/wallet-server/src/router/cloudflare/d1/registration/d1RegistrationCredentialRemediation';
import { digestOpaqueValue } from '../../../packages/wallet-server/src/authorization/service';
import {
  parseTenantId,
  type TenantId,
} from '../../../packages/shared-ts/src/authorization/capabilityKinds';

const NOW_MS = 2_000_000;
const EXPIRES_AT_MS = 2_250_000;
const JOURNAL_SCOPE = {
  namespace: 'router-ab-test',
  orgId: 'org-remediation',
  projectId: 'project-remediation',
  envId: 'env-remediation',
} as const;
const AUTHORIZATION_NAMESPACE = 'authorization-remediation';
const AUTHORIZATION_TENANT_ID = requireTenantId('tenant-remediation');
const WALLET_ID = 'wallet-remediation';
const AUTHORIZATION_ID = 'authorization-remediation';
const WALLET_SESSION_ID = 'wallet-session-remediation';
const QUOTA_ID = 'quota-remediation';

type HistoricalCurve = 'ecdsa' | 'ed25519';
type HistoricalOperation = 'registration_activate' | 'near_provisioning';

export type RegistrationCredentialRemediationFixture = {
  readonly ecdsaToken: string;
  readonly ed25519Token: string;
  cleanup(): void;
  input(
    overrides?: Partial<Pick<RegistrationCredentialRemediationInput, 'nowMs'>>,
  ): RegistrationCredentialRemediationInput;
  run(
    overrides?: Partial<Pick<RegistrationCredentialRemediationInput, 'nowMs'>>,
  ): Promise<RegistrationCredentialRemediationReportV1>;
  insertLegacySession(): Promise<void>;
  insertOrdinaryBearer(curve: HistoricalCurve, token: string): Promise<void>;
  insertHistoricalCompletion(
    operation: HistoricalOperation,
    bearers: readonly { readonly curve: HistoricalCurve; readonly token: string }[],
  ): Promise<void>;
  insertUnknownPrefixedRow(): Promise<void>;
  removeUnknownPrefixedRow(): Promise<void>;
  removeOrdinaryBearers(): Promise<void>;
  insertCurrentCompletion(): Promise<void>;
  insertHistoricalCredentialFreeError(): Promise<void>;
  insertUnrelatedCredentialRow(): Promise<void>;
  ordinaryBearerCount(): Promise<number>;
  sessionLifecycle(): Promise<unknown>;
  quotaLifecycle(): Promise<Record<string, unknown> | null>;
  journalRowExists(recordKey: string): Promise<boolean>;
};

export async function createRegistrationCredentialRemediationFixture(): Promise<RegistrationCredentialRemediationFixture> {
  const temporary = createTemporaryD1Database();
  await applyD1MigrationFiles(temporary.database, listD1MigrationFiles('d1-signer'));
  return new RegistrationCredentialRemediationFixtureImpl(temporary);
}

class RegistrationCredentialRemediationFixtureImpl implements RegistrationCredentialRemediationFixture {
  readonly ecdsaToken = `wst_${'a'.repeat(43)}`;
  readonly ed25519Token = `wst_${'b'.repeat(43)}`;

  constructor(private readonly temporary: TemporaryD1Database) {}

  cleanup(): void {
    cleanupTemporaryD1Database(this.temporary.tempDir);
  }

  input(
    overrides: Partial<Pick<RegistrationCredentialRemediationInput, 'nowMs'>> = {},
  ): RegistrationCredentialRemediationInput {
    return {
      database: this.temporary.database,
      journalScope: JOURNAL_SCOPE,
      authorizationNamespace: AUTHORIZATION_NAMESPACE,
      authorizationTenantId: AUTHORIZATION_TENANT_ID,
      nowMs: overrides.nowMs ?? NOW_MS,
      quiescence: {
        kind: 'registration_completion_writer_quiescence_v1',
        token: 'quiescence-proof-remediation',
        oldCompletionWritersQuiescedAtMs: 1_000_000,
        inFlightWindowEndsAtMs: 1_100_000,
      },
      repeatCheck: {
        kind: 'registration_remediation_repeat_check_v1',
        token: 'quiescence-proof-remediation',
        checkedAtMs: NOW_MS,
      },
      mode: 'delete_historical_v1_completion_rows',
    };
  }

  async run(
    overrides: Partial<Pick<RegistrationCredentialRemediationInput, 'nowMs'>> = {},
  ): Promise<RegistrationCredentialRemediationReportV1> {
    return await runRegistrationCredentialRemediation(this.input(overrides));
  }

  async insertLegacySession(): Promise<void> {
    await this.temporary.database
      .prepare(
        `INSERT INTO authorization_wallet_session_quotas (
           namespace, tenant_id, quota_id, wallet_session_id, principal_id,
           remaining_uses, lifecycle_kind, expires_at_ms
         ) VALUES (?1, ?2, ?3, ?4, ?5, 7, 'active', ?6)`,
      )
      .bind(
        AUTHORIZATION_NAMESPACE,
        AUTHORIZATION_TENANT_ID,
        QUOTA_ID,
        WALLET_SESSION_ID,
        WALLET_ID,
        EXPIRES_AT_MS,
      )
      .run();
    await this.temporary.database
      .prepare(
        `INSERT INTO reusable_wallet_sessions (
           namespace, tenant_id, wallet_session_id, principal_id, wallet_id,
           authority_digest, mint_id, quota_id, lifecycle_kind, created_at_ms,
           expires_at_ms, authorization_id, wallet_auth_method_id
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 'active', ?9, ?10, ?11, ?12)`,
      )
      .bind(
        AUTHORIZATION_NAMESPACE,
        AUTHORIZATION_TENANT_ID,
        WALLET_SESSION_ID,
        WALLET_ID,
        WALLET_ID,
        'authority-digest-remediation',
        'mint-remediation',
        QUOTA_ID,
        1_500_000,
        EXPIRES_AT_MS,
        AUTHORIZATION_ID,
        'auth-method-remediation',
      )
      .run();
  }

  async insertOrdinaryBearer(curve: HistoricalCurve, token: string): Promise<void> {
    const digest = await digestOpaqueValue(token);
    await this.temporary.database
      .prepare(
        `INSERT INTO opaque_wallet_session_tokens (
           namespace, tenant_id, token_hash, curve, wallet_session_id, binding_json
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)`,
      )
      .bind(
        AUTHORIZATION_NAMESPACE,
        AUTHORIZATION_TENANT_ID,
        digest,
        curve,
        WALLET_SESSION_ID,
        JSON.stringify({ kind: 'test_binding' }),
      )
      .run();
  }

  async insertHistoricalCompletion(
    operation: HistoricalOperation,
    bearers: readonly { readonly curve: HistoricalCurve; readonly token: string }[],
  ): Promise<void> {
    const recordKey =
      operation === 'registration_activate'
        ? 'wallet-registration-activate:historical'
        : 'wallet-registration-near-provisioning:historical';
    const session = historicalSession(bearers);
    const response =
      operation === 'registration_activate'
        ? {
            ok: true,
            kind: 'evm_family_ecdsa',
            walletId: WALLET_ID,
            ecdsa: { bootstrap: { kind: 'historical_bootstrap' } },
            registrationEstablishedSession: session,
          }
        : {
            ok: true,
            kind: 'near_ed25519',
            walletId: WALLET_ID,
            registrationEstablishedSession: session,
          };
    await this.insertJournalRow(recordKey, {
      kind: 'router_ab_ed25519_yao_registration_side_effect_completion_v1',
      operation,
      requestFingerprint: 'request-fingerprint-remediation',
      preparedArtifactFingerprint: 'prepared-fingerprint-remediation',
      claimedAtMs: 1_600_000,
      completedAtMs: 1_700_000,
      prepared: preparedOperation(),
      response,
    });
  }

  async insertUnknownPrefixedRow(): Promise<void> {
    await this.insertJournalRow('wallet-registration-near-provisioning:unknown', {
      kind: 'unknown_registration_completion',
    });
  }

  async removeUnknownPrefixedRow(): Promise<void> {
    await this.deleteJournalRow('wallet-registration-near-provisioning:unknown');
  }

  async removeOrdinaryBearers(): Promise<void> {
    await this.temporary.database.prepare('DELETE FROM opaque_wallet_session_tokens').run();
  }

  async insertCurrentCompletion(): Promise<void> {
    await this.insertJournalRow('wallet-registration-activate:current', currentCompletion());
  }

  async insertHistoricalCredentialFreeError(): Promise<void> {
    await this.insertJournalRow('wallet-registration-near-provisioning:historical-error', {
      kind: 'router_ab_ed25519_yao_registration_side_effect_completion_v1',
      operation: 'near_provisioning',
      requestFingerprint: 'request-fingerprint-historical-error',
      preparedArtifactFingerprint: 'prepared-fingerprint-historical-error',
      claimedAtMs: 1_600_000,
      completedAtMs: 1_700_000,
      prepared: preparedOperation(),
      response: { ok: false, code: 'known_error', message: 'credential-free failure' },
    });
  }

  async insertUnrelatedCredentialRow(): Promise<void> {
    await this.insertJournalRow('unrelated:credential-bearing', {
      walletSessionToken: this.ecdsaToken,
    });
  }

  async ordinaryBearerCount(): Promise<number> {
    const row = await this.temporary.database
      .prepare('SELECT COUNT(*) AS count FROM opaque_wallet_session_tokens')
      .first<{ readonly count?: unknown }>();
    return Number(row?.count);
  }

  async sessionLifecycle(): Promise<unknown> {
    const row = await this.temporary.database
      .prepare(
        `SELECT lifecycle_kind FROM reusable_wallet_sessions
          WHERE namespace = ?1 AND tenant_id = ?2 AND wallet_session_id = ?3`,
      )
      .bind(AUTHORIZATION_NAMESPACE, AUTHORIZATION_TENANT_ID, WALLET_SESSION_ID)
      .first<{ readonly lifecycle_kind?: unknown }>();
    return row?.lifecycle_kind;
  }

  async quotaLifecycle(): Promise<Record<string, unknown> | null> {
    return await this.temporary.database
      .prepare(
        `SELECT lifecycle_kind, remaining_uses FROM authorization_wallet_session_quotas
          WHERE namespace = ?1 AND tenant_id = ?2 AND quota_id = ?3`,
      )
      .bind(AUTHORIZATION_NAMESPACE, AUTHORIZATION_TENANT_ID, QUOTA_ID)
      .first<Record<string, unknown>>();
  }

  async journalRowExists(recordKey: string): Promise<boolean> {
    const row = await this.temporary.database
      .prepare(
        `SELECT COUNT(*) AS count FROM router_ab_yao_versioned_json_records
          WHERE namespace = ?1 AND org_id = ?2 AND project_id = ?3 AND env_id = ?4
            AND record_key = ?5`,
      )
      .bind(
        JOURNAL_SCOPE.namespace,
        JOURNAL_SCOPE.orgId,
        JOURNAL_SCOPE.projectId,
        JOURNAL_SCOPE.envId,
        recordKey,
      )
      .first<{ readonly count?: unknown }>();
    return Number(row?.count) === 1;
  }

  private async insertJournalRow(recordKey: string, value: unknown): Promise<void> {
    await this.temporary.database
      .prepare(
        `INSERT INTO router_ab_yao_versioned_json_records (
           namespace, org_id, project_id, env_id, record_key, version, record_json
         ) VALUES (?1, ?2, ?3, ?4, ?5, 1, ?6)`,
      )
      .bind(
        JOURNAL_SCOPE.namespace,
        JOURNAL_SCOPE.orgId,
        JOURNAL_SCOPE.projectId,
        JOURNAL_SCOPE.envId,
        recordKey,
        JSON.stringify(value),
      )
      .run();
  }

  private async deleteJournalRow(recordKey: string): Promise<void> {
    await this.temporary.database
      .prepare(
        `DELETE FROM router_ab_yao_versioned_json_records
          WHERE namespace = ?1 AND org_id = ?2 AND project_id = ?3 AND env_id = ?4
            AND record_key = ?5`,
      )
      .bind(
        JOURNAL_SCOPE.namespace,
        JOURNAL_SCOPE.orgId,
        JOURNAL_SCOPE.projectId,
        JOURNAL_SCOPE.envId,
        recordKey,
      )
      .run();
  }
}

function historicalSession(
  bearers: readonly { readonly curve: HistoricalCurve; readonly token: string }[],
): Record<string, unknown> {
  const ecdsa = bearers.find((bearer) => bearer.curve === 'ecdsa');
  const ed25519 = bearers.find((bearer) => bearer.curve === 'ed25519');
  let tokens: Record<string, unknown>;
  if (ecdsa && ed25519) {
    tokens = {
      kind: 'near_ed25519_and_evm_family_ecdsa',
      ecdsa: historicalEcdsaBearer(ecdsa.token),
      ed25519: historicalEd25519Bearer(ed25519.token),
    };
  } else if (ecdsa) {
    tokens = { kind: 'evm_family_ecdsa', ecdsa: historicalEcdsaBearer(ecdsa.token) };
  } else if (ed25519) {
    tokens = { kind: 'near_ed25519', ed25519: historicalEd25519Bearer(ed25519.token) };
  } else {
    throw new Error('Historical session fixture requires a bearer');
  }
  return {
    kind: 'registration_established_wallet_session_v1',
    walletId: WALLET_ID,
    authorizationId: AUTHORIZATION_ID,
    walletSessionId: WALLET_SESSION_ID,
    quotaId: QUOTA_ID,
    expiresAtMs: EXPIRES_AT_MS,
    remainingUses: 7,
    tokens,
  };
}

function historicalEcdsaBearer(token: string): Record<string, unknown> {
  return {
    walletSessionToken: token,
    thresholdSessionId: 'threshold-ecdsa-remediation',
    keyHandle: 'key-handle-remediation',
    runtimePolicyScope: { kind: 'runtime-policy-remediation' },
    routerAbEcdsaDerivationNormalSigning: { kind: 'ecdsa-normal-signing-remediation' },
  };
}

function historicalEd25519Bearer(token: string): Record<string, unknown> {
  return {
    walletSessionToken: token,
    thresholdSessionId: 'threshold-ed25519-remediation',
    nearAccountId: 'remediation.testnet',
    nearEd25519SigningKeyId: 'near-signing-key-remediation',
    runtimePolicyScope: { kind: 'runtime-policy-remediation' },
    routerAbNormalSigning: { kind: 'ed25519-normal-signing-remediation' },
  };
}

function currentCompletion(): Record<string, unknown> {
  return {
    kind: 'router_ab_ed25519_yao_registration_side_effect_completion_v2',
    operation: 'registration_activate',
    requestFingerprint: 'request-fingerprint-current',
    preparedArtifactFingerprint: 'prepared-fingerprint-current',
    claimedAtMs: 1_600_000,
    completedAtMs: 1_700_000,
    prepared: preparedOperation(),
    receipt: {
      kind: 'wallet_registration_session_commit_receipt_v2',
      operation: 'registration_activate',
      operationFingerprint: 'operation-fingerprint-current',
      registrationCeremonyId: 'ceremony-current',
      committed: {
        kind: 'error',
        error: { ok: false, code: 'current-error', message: 'current receipt' },
      },
    },
  };
}

function preparedOperation(): Record<string, unknown> {
  return {
    kind: 'd1_wallet_registration_operation_prepared_v1',
    walletAuthorityId: 'authority-remediation',
    deviceId: 'device-remediation',
    walletAuthMethodId: 'auth-method-remediation',
  };
}

function requireTenantId(value: string): TenantId {
  const parsed = parseTenantId(value);
  if (!parsed.ok) throw new Error(parsed.error.message);
  return parsed.value;
}
