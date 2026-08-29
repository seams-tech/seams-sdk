import {
  parseWalletAuthMethodId,
  parseWalletAuthorityId,
  parseWalletId,
  type WalletId,
} from '@shared/utils/domainIds';
import {
  parseDeviceId,
  parseMpcWalletSigningQuotaId,
  parseWalletSessionAuthorizationId,
  parseWalletSessionId,
  type MpcWalletSigningQuotaId,
  type TenantId,
  type WalletSessionAuthorizationId,
  type WalletSessionId,
} from '@shared/authorization/capabilityKinds';
import { digestOpaqueValue } from '../../../../authorization/service';
import type { D1DatabaseLike, D1PreparedStatementLike } from '../../../../storage/tenantRoute';
import type { CloudflareD1VersionedJsonRecordScopeV1 } from '../versionedJson/d1VersionedJsonRecordStore';

const ACTIVATE_PREFIX = 'wallet-registration-activate:';
const NEAR_PREFIX = 'wallet-registration-near-provisioning:';
const CAS_GUARD_SQL = `INSERT INTO router_ab_yao_versioned_json_cas_guard (guard_id)
SELECT 1
 WHERE changes() = 0`;

const CREDENTIAL_FIELD_NAMES = new Set([
  'walletSessionToken',
  'primaryOperationCredential',
  'childOperationCredential',
  'operationCredential',
  'clientRootProof',
  'passkeyBootstrapAuthorization',
]);

type RegistrationJournalOperation = 'registration_activate' | 'near_provisioning';
type HistoricalBearerCurve = 'ecdsa' | 'ed25519';
type HistoricalBearerSource = 'ordinary' | 'registration_replay';

type HistoricalBearer = {
  readonly curve: HistoricalBearerCurve;
  readonly plaintext: string;
};

type HistoricalCompletionProjection = {
  readonly operation: RegistrationJournalOperation;
  readonly recordKey: string;
  readonly expectedVersion: number;
  readonly walletId: WalletId;
  readonly authorizationId: WalletSessionAuthorizationId;
  readonly walletSessionId: WalletSessionId;
  readonly quotaId: MpcWalletSigningQuotaId;
  readonly expiresAtMs: number;
  readonly bearers: readonly [HistoricalBearer, ...HistoricalBearer[]];
};

type CandidateRow = {
  readonly record_key?: unknown;
  readonly version?: unknown;
  readonly record_json?: unknown;
};

type CandidateInventory = {
  readonly selectedRows: number;
  readonly credentialBearingRows: number;
  readonly bearerCount: number;
  readonly historical: readonly HistoricalCompletionProjection[];
};

type HistoricalBearerMapping = {
  readonly source: HistoricalBearerSource;
  readonly curve: HistoricalBearerCurve;
  readonly tokenHash: string;
};

type PreparedHistoricalRetirement = {
  readonly completion: HistoricalCompletionProjection;
  readonly bearers: readonly [HistoricalBearerMapping, ...HistoricalBearerMapping[]];
};

export type RegistrationCompletionWriterQuiescenceV1 = {
  readonly kind: 'registration_completion_writer_quiescence_v1';
  readonly token: string;
  readonly oldCompletionWritersQuiescedAtMs: number;
  readonly inFlightWindowEndsAtMs: number;
};

export type RegistrationRemediationRepeatCheckV1 = {
  readonly kind: 'registration_remediation_repeat_check_v1';
  readonly token: string;
  readonly checkedAtMs: number;
};

export type RegistrationCredentialRemediationInput = {
  readonly database: D1DatabaseLike;
  readonly journalScope: CloudflareD1VersionedJsonRecordScopeV1;
  readonly authorizationNamespace: string;
  readonly authorizationTenantId: TenantId;
  readonly nowMs: number;
  readonly quiescence: RegistrationCompletionWriterQuiescenceV1;
  readonly repeatCheck: RegistrationRemediationRepeatCheckV1;
  readonly mode: 'delete_historical_v1_completion_rows';
};

export type RegistrationCredentialRemediationReportV1 = {
  readonly kind: 'registration_credential_remediation_report_v1';
  readonly before: {
    readonly selectedRows: number;
    readonly credentialBearingRows: number;
    readonly bearerCount: number;
  };
  readonly retired: {
    readonly tokenRows: number;
    readonly sessionRows: number;
    readonly quotaRows: number;
    readonly deletedCompletionRows: number;
  };
  readonly after: {
    readonly selectedRows: number;
    readonly credentialBearingRows: number;
  };
  readonly repeat: {
    readonly checkedAtMs: number;
    readonly credentialBearingRows: number;
  };
  readonly quiescence: {
    readonly kind: RegistrationCompletionWriterQuiescenceV1['kind'];
    readonly oldCompletionWritersQuiescedAtMs: number;
    readonly inFlightWindowEndsAtMs: number;
  };
};

export async function runRegistrationCredentialRemediation(
  input: RegistrationCredentialRemediationInput,
): Promise<RegistrationCredentialRemediationReportV1> {
  validateInvocation(input);
  const before = await readCandidateInventory(input);
  const prepared = await prepareHistoricalRetirements(input, before.historical);
  if (prepared.length > 0) {
    await retireHistoricalCompletions(input, prepared);
  }
  const after = await readCandidateInventory(input);
  if (after.credentialBearingRows !== 0) {
    throw new Error('Registration credential remediation left credential-bearing rows');
  }
  const repeat = await readCandidateInventory(input);
  if (repeat.credentialBearingRows !== 0) {
    throw new Error('Registration credential remediation repeat check is non-zero');
  }
  let tokenRows = 0;
  for (const retirement of prepared) tokenRows += retirement.bearers.length;
  return {
    kind: 'registration_credential_remediation_report_v1',
    before: {
      selectedRows: before.selectedRows,
      credentialBearingRows: before.credentialBearingRows,
      bearerCount: before.bearerCount,
    },
    retired: {
      tokenRows,
      sessionRows: prepared.length,
      quotaRows: prepared.length,
      deletedCompletionRows: prepared.length,
    },
    after: {
      selectedRows: after.selectedRows,
      credentialBearingRows: after.credentialBearingRows,
    },
    repeat: {
      checkedAtMs: input.repeatCheck.checkedAtMs,
      credentialBearingRows: repeat.credentialBearingRows,
    },
    quiescence: {
      kind: input.quiescence.kind,
      oldCompletionWritersQuiescedAtMs: input.quiescence.oldCompletionWritersQuiescedAtMs,
      inFlightWindowEndsAtMs: input.quiescence.inFlightWindowEndsAtMs,
    },
  };
}

function validateInvocation(input: RegistrationCredentialRemediationInput): void {
  if (input.mode !== 'delete_historical_v1_completion_rows') {
    throw new Error('Registration credential remediation mode is invalid');
  }
  if (
    input.quiescence.kind !== 'registration_completion_writer_quiescence_v1' ||
    input.repeatCheck.kind !== 'registration_remediation_repeat_check_v1' ||
    !input.quiescence.token.trim() ||
    input.repeatCheck.token !== input.quiescence.token
  ) {
    throw new Error('Registration credential remediation quiescence proof is invalid');
  }
  for (const timestamp of [
    input.nowMs,
    input.quiescence.oldCompletionWritersQuiescedAtMs,
    input.quiescence.inFlightWindowEndsAtMs,
    input.repeatCheck.checkedAtMs,
  ]) {
    if (!Number.isSafeInteger(timestamp) || timestamp <= 0) {
      throw new Error('Registration credential remediation timestamp is invalid');
    }
  }
  if (
    input.quiescence.inFlightWindowEndsAtMs < input.quiescence.oldCompletionWritersQuiescedAtMs ||
    input.nowMs < input.quiescence.inFlightWindowEndsAtMs ||
    input.repeatCheck.checkedAtMs < input.nowMs
  ) {
    throw new Error('Registration credential remediation in-flight window has not elapsed');
  }
  if (
    !input.journalScope.namespace.trim() ||
    !input.journalScope.orgId.trim() ||
    !input.journalScope.projectId.trim() ||
    !input.journalScope.envId.trim() ||
    !input.authorizationNamespace.trim()
  ) {
    throw new Error('Registration credential remediation scope is invalid');
  }
}

async function readCandidateInventory(
  input: RegistrationCredentialRemediationInput,
): Promise<CandidateInventory> {
  const result = await input.database
    .prepare(
      `SELECT record_key, version, record_json
         FROM router_ab_yao_versioned_json_records
        WHERE namespace = ?1
          AND org_id = ?2
          AND project_id = ?3
          AND env_id = ?4
          AND (record_key LIKE ?5 ESCAPE '\\' OR record_key LIKE ?6 ESCAPE '\\')
        ORDER BY record_key`,
    )
    .bind(
      input.journalScope.namespace,
      input.journalScope.orgId,
      input.journalScope.projectId,
      input.journalScope.envId,
      `${ACTIVATE_PREFIX}%`,
      `${NEAR_PREFIX}%`,
    )
    .all<CandidateRow>();
  if (!result.success || !Array.isArray(result.results)) {
    throw new Error('Registration credential remediation inventory failed');
  }
  const historical: HistoricalCompletionProjection[] = [];
  let bearerCount = 0;
  for (const row of result.results) {
    const classified = classifyCandidateRow(row);
    if (classified !== null) {
      historical.push(classified);
      bearerCount += classified.bearers.length;
    }
  }
  const credentialBearingRows = await countCredentialBearingRows(input);
  return {
    selectedRows: result.results.length,
    credentialBearingRows,
    bearerCount,
    historical,
  };
}

async function countCredentialBearingRows(
  input: RegistrationCredentialRemediationInput,
): Promise<number> {
  const row = await input.database
    .prepare(
      `SELECT COUNT(DISTINCT records.record_key) AS count
         FROM router_ab_yao_versioned_json_records AS records,
              json_tree(records.record_json) AS tree
        WHERE records.namespace = ?1
          AND records.org_id = ?2
          AND records.project_id = ?3
          AND records.env_id = ?4
          AND (records.record_key LIKE ?5 ESCAPE '\\' OR records.record_key LIKE ?6 ESCAPE '\\')
          AND tree.key IN (
            'walletSessionToken',
            'primaryOperationCredential',
            'childOperationCredential',
            'operationCredential',
            'clientRootProof',
            'passkeyBootstrapAuthorization'
          )`,
    )
    .bind(
      input.journalScope.namespace,
      input.journalScope.orgId,
      input.journalScope.projectId,
      input.journalScope.envId,
      `${ACTIVATE_PREFIX}%`,
      `${NEAR_PREFIX}%`,
    )
    .first<{ readonly count?: unknown }>();
  const count = typeof row?.count === 'number' ? row.count : Number(row?.count);
  if (!Number.isSafeInteger(count) || count < 0) {
    throw new Error('Registration credential remediation count is invalid');
  }
  return count;
}

function classifyCandidateRow(row: CandidateRow): HistoricalCompletionProjection | null {
  const recordKey = requireCandidateRecordKey(row.record_key);
  const operation = operationForRecordKey(recordKey);
  const expectedVersion = requirePositiveSafeInteger(row.version);
  if (typeof row.record_json !== 'string') {
    throw new Error('Registration credential remediation found an invalid row body');
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(row.record_json);
  } catch {
    throw new Error('Registration credential remediation found malformed JSON');
  }
  if (!isRecord(parsed) || typeof parsed.kind !== 'string') {
    throw new Error('Registration credential remediation found an unknown row');
  }
  if (parsed.kind === 'router_ab_ed25519_yao_registration_side_effect_claim_v1') {
    validateCurrentClaim(parsed, operation);
    return null;
  }
  if (parsed.kind === 'router_ab_ed25519_yao_registration_side_effect_completion_v2') {
    validateCurrentCompletion(parsed, operation);
    if (containsCredentialField(parsed)) {
      throw new Error('Registration credential remediation found a credential-bearing V2 row');
    }
    return null;
  }
  if (parsed.kind !== 'router_ab_ed25519_yao_registration_side_effect_completion_v1') {
    throw new Error('Registration credential remediation found an unsupported row kind');
  }
  return parseHistoricalCompletion(parsed, operation, recordKey, expectedVersion);
}

function validateCurrentClaim(
  record: Record<string, unknown>,
  operation: RegistrationJournalOperation,
): void {
  if (
    !hasExactKeys(record, [
      'kind',
      'operation',
      'requestFingerprint',
      'preparedArtifactFingerprint',
      'claimedAtMs',
      'prepared',
    ]) ||
    record.operation !== operation ||
    !isNonEmptyString(record.requestFingerprint) ||
    !isNonEmptyString(record.preparedArtifactFingerprint) ||
    !isNonNegativeSafeInteger(record.claimedAtMs) ||
    !isPreparedRegistrationOperation(record.prepared)
  ) {
    throw new Error('Registration credential remediation found an invalid claim row');
  }
}

function validateCurrentCompletion(
  record: Record<string, unknown>,
  operation: RegistrationJournalOperation,
): void {
  if (
    !hasExactKeys(record, [
      'kind',
      'operation',
      'requestFingerprint',
      'preparedArtifactFingerprint',
      'claimedAtMs',
      'completedAtMs',
      'prepared',
      'receipt',
    ]) ||
    record.operation !== operation ||
    !isNonEmptyString(record.requestFingerprint) ||
    !isNonEmptyString(record.preparedArtifactFingerprint) ||
    !isNonNegativeSafeInteger(record.claimedAtMs) ||
    !isNonNegativeSafeInteger(record.completedAtMs) ||
    Number(record.completedAtMs) < Number(record.claimedAtMs) ||
    !isPreparedRegistrationOperation(record.prepared) ||
    !isCredentialFreeRegistrationReceipt(record.receipt, operation)
  ) {
    throw new Error('Registration credential remediation found an invalid V2 completion row');
  }
}

function parseHistoricalCompletion(
  record: Record<string, unknown>,
  operation: RegistrationJournalOperation,
  recordKey: string,
  expectedVersion: number,
): HistoricalCompletionProjection | null {
  if (
    !hasExactKeys(record, [
      'kind',
      'operation',
      'requestFingerprint',
      'preparedArtifactFingerprint',
      'claimedAtMs',
      'completedAtMs',
      'prepared',
      'response',
    ]) ||
    record.operation !== operation ||
    !isNonEmptyString(record.requestFingerprint) ||
    !isNonEmptyString(record.preparedArtifactFingerprint) ||
    !isNonNegativeSafeInteger(record.claimedAtMs) ||
    !isNonNegativeSafeInteger(record.completedAtMs) ||
    Number(record.completedAtMs) < Number(record.claimedAtMs) ||
    !isPreparedRegistrationOperation(record.prepared) ||
    !isRecord(record.response)
  ) {
    throw new Error('Registration credential remediation found an invalid V1 completion row');
  }
  const response = record.response;
  if (isKnownCredentialFreeHistoricalResponse(response, operation)) return null;
  if (response.ok !== true || response.kind !== responseKindForOperation(operation)) {
    throw new Error('Registration credential remediation found an unsupported V1 response');
  }
  if (
    operation === 'registration_activate' &&
    (!isRecord(response.ecdsa) || !isRecord(response.ecdsa.bootstrap))
  ) {
    throw new Error('Registration credential remediation found an incomplete activation response');
  }
  const responseWalletId = parseWalletId(response.walletId);
  if (!responseWalletId.ok) {
    throw new Error('Registration credential remediation found an invalid wallet identity');
  }
  const session = parseHistoricalSession(response.registrationEstablishedSession);
  if (session.walletId !== responseWalletId.value) {
    throw new Error('Registration credential remediation found a mismatched wallet identity');
  }
  return {
    operation,
    recordKey,
    expectedVersion,
    walletId: session.walletId,
    authorizationId: session.authorizationId,
    walletSessionId: session.walletSessionId,
    quotaId: session.quotaId,
    expiresAtMs: session.expiresAtMs,
    bearers: session.bearers,
  };
}

function isKnownCredentialFreeHistoricalResponse(
  response: Record<string, unknown>,
  operation: RegistrationJournalOperation,
): boolean {
  if (containsCredentialField(response)) return false;
  if (response.ok === false) {
    const expectedKeys =
      response.retryAfterMs === undefined
        ? ['ok', 'code', 'message']
        : ['ok', 'code', 'message', 'retryAfterMs'];
    return (
      hasExactKeys(response, expectedKeys) &&
      isNonEmptyString(response.code) &&
      isNonEmptyString(response.message) &&
      (response.retryAfterMs === undefined || isNonNegativeSafeInteger(response.retryAfterMs))
    );
  }
  return (
    operation === 'registration_activate' &&
    response.ok === true &&
    response.kind === 'near_ed25519' &&
    isRecord(response.nearProvisioning) &&
    hasExactKeys(response.nearProvisioning, ['status']) &&
    response.nearProvisioning.status === 'near_pending'
  );
}

function parseHistoricalSession(
  raw: unknown,
): Omit<HistoricalCompletionProjection, 'operation' | 'recordKey' | 'expectedVersion'> {
  if (
    !isRecord(raw) ||
    !hasExactKeys(raw, [
      'kind',
      'walletId',
      'authorizationId',
      'walletSessionId',
      'quotaId',
      'expiresAtMs',
      'remainingUses',
      'tokens',
    ]) ||
    raw.kind !== 'registration_established_wallet_session_v1'
  ) {
    throw new Error('Registration credential remediation found an invalid established session');
  }
  const walletId = parseWalletId(raw.walletId);
  const authorizationId = parseWalletSessionAuthorizationId(raw.authorizationId);
  const walletSessionId = parseWalletSessionId(raw.walletSessionId);
  const quotaId = parseMpcWalletSigningQuotaId(raw.quotaId);
  const expiresAtMs = requirePositiveSafeInteger(raw.expiresAtMs);
  const remainingUses = requirePositiveSafeInteger(raw.remainingUses);
  if (
    !walletId.ok ||
    !authorizationId.ok ||
    !walletSessionId.ok ||
    !quotaId.ok ||
    remainingUses <= 0
  ) {
    throw new Error('Registration credential remediation found an invalid session identity');
  }
  if (new Set([authorizationId.value, walletSessionId.value, quotaId.value]).size !== 3) {
    throw new Error('Registration credential remediation found colliding session identities');
  }
  const bearers = parseHistoricalSessionBearers(raw.tokens);
  return {
    walletId: walletId.value,
    authorizationId: authorizationId.value,
    walletSessionId: walletSessionId.value,
    quotaId: quotaId.value,
    expiresAtMs,
    bearers,
  };
}

function parseHistoricalSessionBearers(
  raw: unknown,
): readonly [HistoricalBearer, ...HistoricalBearer[]] {
  if (!isRecord(raw) || typeof raw.kind !== 'string') {
    throw new Error('Registration credential remediation found invalid session tokens');
  }
  switch (raw.kind) {
    case 'evm_family_ecdsa':
      if (!hasExactKeys(raw, ['kind', 'ecdsa'])) {
        throw new Error('Registration credential remediation found invalid ECDSA tokens');
      }
      return [parseHistoricalBearer(raw.ecdsa, 'ecdsa')];
    case 'near_ed25519':
      if (!hasExactKeys(raw, ['kind', 'ed25519'])) {
        throw new Error('Registration credential remediation found invalid Ed25519 tokens');
      }
      return [parseHistoricalBearer(raw.ed25519, 'ed25519')];
    case 'near_ed25519_and_evm_family_ecdsa':
      if (!hasExactKeys(raw, ['kind', 'ecdsa', 'ed25519'])) {
        throw new Error('Registration credential remediation found invalid mixed tokens');
      }
      return [
        parseHistoricalBearer(raw.ecdsa, 'ecdsa'),
        parseHistoricalBearer(raw.ed25519, 'ed25519'),
      ];
    default:
      throw new Error('Registration credential remediation found an unknown token branch');
  }
}

function parseHistoricalBearer(raw: unknown, curve: HistoricalBearerCurve): HistoricalBearer {
  const expectedKeys =
    curve === 'ecdsa'
      ? [
          'walletSessionToken',
          'thresholdSessionId',
          'keyHandle',
          'runtimePolicyScope',
          'routerAbEcdsaDerivationNormalSigning',
        ]
      : [
          'walletSessionToken',
          'thresholdSessionId',
          'nearAccountId',
          'nearEd25519SigningKeyId',
          'runtimePolicyScope',
          'routerAbNormalSigning',
        ];
  if (!isRecord(raw) || !hasExactKeys(raw, expectedKeys)) {
    throw new Error('Registration credential remediation found an invalid bearer projection');
  }
  if (
    !isNonEmptyString(raw.thresholdSessionId) ||
    !isRecord(raw.runtimePolicyScope) ||
    (curve === 'ecdsa' &&
      (!isNonEmptyString(raw.keyHandle) || !isRecord(raw.routerAbEcdsaDerivationNormalSigning))) ||
    (curve === 'ed25519' &&
      (!isNonEmptyString(raw.nearAccountId) ||
        !isNonEmptyString(raw.nearEd25519SigningKeyId) ||
        !isRecord(raw.routerAbNormalSigning)))
  ) {
    throw new Error('Registration credential remediation found invalid bearer metadata');
  }
  const plaintext = typeof raw.walletSessionToken === 'string' ? raw.walletSessionToken.trim() : '';
  if (!/^wst_[A-Za-z0-9_-]{43}$/u.test(plaintext)) {
    throw new Error('Registration credential remediation found an invalid bearer');
  }
  return { curve, plaintext };
}

async function prepareHistoricalRetirements(
  input: RegistrationCredentialRemediationInput,
  completions: readonly HistoricalCompletionProjection[],
): Promise<readonly PreparedHistoricalRetirement[]> {
  const prepared: PreparedHistoricalRetirement[] = [];
  for (const completion of completions) {
    const mappings: HistoricalBearerMapping[] = [];
    for (const bearer of completion.bearers) {
      const tokenHash = String(await digestOpaqueValue(bearer.plaintext));
      const source = await resolveHistoricalBearerSource(
        input,
        completion,
        bearer.curve,
        tokenHash,
      );
      mappings.push({ source, curve: bearer.curve, tokenHash });
    }
    const first = mappings[0];
    if (!first) throw new Error('Registration credential remediation prepared no bearer');
    prepared.push({ completion, bearers: [first, ...mappings.slice(1)] });
  }
  return prepared;
}

async function resolveHistoricalBearerSource(
  input: RegistrationCredentialRemediationInput,
  completion: HistoricalCompletionProjection,
  curve: HistoricalBearerCurve,
  tokenHash: string,
): Promise<HistoricalBearerSource> {
  const result = await input.database
    .prepare(historicalBearerMappingSql())
    .bind(
      input.authorizationNamespace,
      input.authorizationTenantId,
      tokenHash,
      curve,
      completion.walletSessionId,
      completion.authorizationId,
      completion.quotaId,
      completion.walletId,
      completion.expiresAtMs,
      input.nowMs,
    )
    .all<{ readonly token_source?: unknown }>();
  if (!result.success || !Array.isArray(result.results) || result.results.length !== 1) {
    throw new Error('Registration credential remediation bearer mapping is not unique');
  }
  const source = result.results[0]?.token_source;
  if (source === 'ordinary' || source === 'registration_replay') return source;
  throw new Error('Registration credential remediation bearer mapping is invalid');
}

function historicalBearerMappingSql(): string {
  return `SELECT 'ordinary' AS token_source
            FROM opaque_wallet_session_tokens AS token
            JOIN reusable_wallet_sessions AS session
              ON session.namespace = token.namespace
             AND session.tenant_id = token.tenant_id
             AND session.wallet_session_id = token.wallet_session_id
            JOIN authorization_wallet_session_quotas AS quota
              ON quota.namespace = session.namespace
             AND quota.tenant_id = session.tenant_id
             AND quota.quota_id = session.quota_id
           WHERE token.namespace = ?1
             AND token.tenant_id = ?2
             AND token.token_hash = ?3
             AND token.curve = ?4
             AND token.wallet_session_id = ?5
             AND session.authorization_id = ?6
             AND session.quota_id = ?7
             AND session.wallet_id = ?8
             AND session.expires_at_ms = ?9
             AND session.lifecycle_kind = 'active'
             AND session.expires_at_ms > ?10
             AND quota.wallet_session_id = session.wallet_session_id
             AND quota.lifecycle_kind = 'active'
             AND quota.remaining_uses > 0
             AND quota.expires_at_ms = session.expires_at_ms
             AND quota.expires_at_ms > ?10
          UNION ALL
          SELECT 'registration_replay' AS token_source
            FROM registration_replay_opaque_wallet_session_tokens_v1 AS token
            JOIN reusable_wallet_sessions AS session
              ON session.namespace = token.namespace
             AND session.tenant_id = token.tenant_id
             AND session.wallet_session_id = token.wallet_session_id
            JOIN authorization_wallet_session_quotas AS quota
              ON quota.namespace = session.namespace
             AND quota.tenant_id = session.tenant_id
             AND quota.quota_id = session.quota_id
           WHERE token.namespace = ?1
             AND token.tenant_id = ?2
             AND token.token_hash = ?3
             AND token.curve = ?4
             AND token.wallet_session_id = ?5
             AND token.authorization_id = ?6
             AND token.quota_id = ?7
             AND token.wallet_id = ?8
             AND token.session_expires_at_ms = ?9
             AND token.token_expires_at_ms = ?9
             AND token.token_expires_at_ms > ?10
             AND session.authorization_id = ?6
             AND session.quota_id = ?7
             AND session.wallet_id = ?8
             AND session.expires_at_ms = ?9
             AND session.lifecycle_kind = 'active'
             AND session.expires_at_ms > ?10
             AND quota.wallet_session_id = session.wallet_session_id
             AND quota.lifecycle_kind = 'active'
             AND quota.remaining_uses > 0
             AND quota.expires_at_ms = session.expires_at_ms
             AND quota.expires_at_ms > ?10`;
}

async function retireHistoricalCompletions(
  input: RegistrationCredentialRemediationInput,
  retirements: readonly PreparedHistoricalRetirement[],
): Promise<void> {
  const statements: D1PreparedStatementLike[] = [];
  for (const retirement of retirements) {
    for (const bearer of retirement.bearers) {
      statements.push(prepareBearerDelete(input, retirement.completion, bearer));
      statements.push(input.database.prepare(CAS_GUARD_SQL));
    }
    statements.push(prepareQuotaRetirement(input, retirement.completion));
    statements.push(input.database.prepare(CAS_GUARD_SQL));
    statements.push(prepareSessionRetirement(input, retirement.completion));
    statements.push(input.database.prepare(CAS_GUARD_SQL));
    statements.push(prepareCompletionDelete(input, retirement.completion));
    statements.push(input.database.prepare(CAS_GUARD_SQL));
  }
  const results = await input.database.batch<{ readonly success?: unknown }>(statements);
  if (results.length !== statements.length) {
    throw new Error('Registration credential remediation batch was incomplete');
  }
  for (const result of results) {
    if (result.success !== true) {
      throw new Error('Registration credential remediation batch failed');
    }
  }
}

function prepareBearerDelete(
  input: RegistrationCredentialRemediationInput,
  completion: HistoricalCompletionProjection,
  bearer: HistoricalBearerMapping,
): D1PreparedStatementLike {
  const table =
    bearer.source === 'ordinary'
      ? 'opaque_wallet_session_tokens'
      : 'registration_replay_opaque_wallet_session_tokens_v1';
  const replayPredicates =
    bearer.source === 'registration_replay'
      ? 'AND token_expires_at_ms = ?9 AND session_expires_at_ms = ?9'
      : '';
  return input.database
    .prepare(
      `DELETE FROM ${table}
        WHERE namespace = ?1
          AND tenant_id = ?2
          AND token_hash = ?3
          AND curve = ?4
          AND wallet_session_id = ?5
          ${replayPredicates}
          AND EXISTS (
            SELECT 1
              FROM reusable_wallet_sessions AS session
              JOIN authorization_wallet_session_quotas AS quota
                ON quota.namespace = session.namespace
               AND quota.tenant_id = session.tenant_id
               AND quota.quota_id = session.quota_id
             WHERE session.namespace = ?1
               AND session.tenant_id = ?2
               AND session.wallet_session_id = ?5
               AND session.authorization_id = ?6
               AND session.quota_id = ?7
               AND session.wallet_id = ?8
               AND session.expires_at_ms = ?9
               AND session.lifecycle_kind = 'active'
               AND session.expires_at_ms > ?10
               AND quota.wallet_session_id = session.wallet_session_id
               AND quota.lifecycle_kind = 'active'
               AND quota.remaining_uses > 0
               AND quota.expires_at_ms = session.expires_at_ms
               AND quota.expires_at_ms > ?10
          )`,
    )
    .bind(
      input.authorizationNamespace,
      input.authorizationTenantId,
      bearer.tokenHash,
      bearer.curve,
      completion.walletSessionId,
      completion.authorizationId,
      completion.quotaId,
      completion.walletId,
      completion.expiresAtMs,
      input.nowMs,
    );
}

function prepareQuotaRetirement(
  input: RegistrationCredentialRemediationInput,
  completion: HistoricalCompletionProjection,
): D1PreparedStatementLike {
  return input.database
    .prepare(
      `UPDATE authorization_wallet_session_quotas
          SET remaining_uses = 0,
              lifecycle_kind = 'exhausted'
        WHERE namespace = ?1
          AND tenant_id = ?2
          AND quota_id = ?3
          AND wallet_session_id = ?4
          AND lifecycle_kind = 'active'
          AND remaining_uses > 0
          AND expires_at_ms = ?5
          AND expires_at_ms > ?6`,
    )
    .bind(
      input.authorizationNamespace,
      input.authorizationTenantId,
      completion.quotaId,
      completion.walletSessionId,
      completion.expiresAtMs,
      input.nowMs,
    );
}

function prepareSessionRetirement(
  input: RegistrationCredentialRemediationInput,
  completion: HistoricalCompletionProjection,
): D1PreparedStatementLike {
  return input.database
    .prepare(
      `UPDATE reusable_wallet_sessions
          SET lifecycle_kind = 'superseded'
        WHERE namespace = ?1
          AND tenant_id = ?2
          AND wallet_session_id = ?3
          AND authorization_id = ?4
          AND quota_id = ?5
          AND wallet_id = ?6
          AND lifecycle_kind = 'active'
          AND expires_at_ms = ?7
          AND expires_at_ms > ?8`,
    )
    .bind(
      input.authorizationNamespace,
      input.authorizationTenantId,
      completion.walletSessionId,
      completion.authorizationId,
      completion.quotaId,
      completion.walletId,
      completion.expiresAtMs,
      input.nowMs,
    );
}

function prepareCompletionDelete(
  input: RegistrationCredentialRemediationInput,
  completion: HistoricalCompletionProjection,
): D1PreparedStatementLike {
  return input.database
    .prepare(
      `DELETE FROM router_ab_yao_versioned_json_records
        WHERE namespace = ?1
          AND org_id = ?2
          AND project_id = ?3
          AND env_id = ?4
          AND record_key = ?5
          AND version = ?6`,
    )
    .bind(
      input.journalScope.namespace,
      input.journalScope.orgId,
      input.journalScope.projectId,
      input.journalScope.envId,
      completion.recordKey,
      completion.expectedVersion,
    );
}

function isPreparedRegistrationOperation(raw: unknown): boolean {
  if (
    !isRecord(raw) ||
    !hasExactKeys(raw, ['kind', 'walletAuthorityId', 'deviceId', 'walletAuthMethodId']) ||
    raw.kind !== 'd1_wallet_registration_operation_prepared_v1'
  ) {
    return false;
  }
  return (
    parseWalletAuthorityId(raw.walletAuthorityId).ok &&
    parseDeviceId(raw.deviceId).ok &&
    parseWalletAuthMethodId(raw.walletAuthMethodId).ok
  );
}

function isCredentialFreeRegistrationReceipt(
  raw: unknown,
  operation: RegistrationJournalOperation,
): boolean {
  return (
    isRecord(raw) &&
    raw.kind === 'wallet_registration_session_commit_receipt_v2' &&
    raw.operation === operation &&
    isNonEmptyString(raw.operationFingerprint) &&
    isNonEmptyString(raw.registrationCeremonyId) &&
    isRecord(raw.committed) &&
    isNonEmptyString(raw.committed.kind) &&
    !containsCredentialField(raw)
  );
}

function containsCredentialField(value: unknown): boolean {
  if (Array.isArray(value)) {
    for (const item of value) {
      if (containsCredentialField(item)) return true;
    }
    return false;
  }
  if (!isRecord(value)) return false;
  for (const [key, child] of Object.entries(value)) {
    if (CREDENTIAL_FIELD_NAMES.has(key) || containsCredentialField(child)) return true;
  }
  return false;
}

function operationForRecordKey(recordKey: string): RegistrationJournalOperation {
  if (recordKey.startsWith(ACTIVATE_PREFIX)) return 'registration_activate';
  if (recordKey.startsWith(NEAR_PREFIX)) return 'near_provisioning';
  throw new Error('Registration credential remediation selected an unexpected prefix');
}

function responseKindForOperation(operation: RegistrationJournalOperation): string {
  return operation === 'registration_activate' ? 'evm_family_ecdsa' : 'near_ed25519';
}

function requireCandidateRecordKey(value: unknown): string {
  if (!isNonEmptyString(value) || value.length > 2048) {
    throw new Error('Registration credential remediation found an invalid record key');
  }
  return value;
}

function requirePositiveSafeInteger(value: unknown): number {
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value <= 0) {
    throw new Error('Registration credential remediation found an invalid positive integer');
  }
  return value;
}

function isNonNegativeSafeInteger(value: unknown): boolean {
  return typeof value === 'number' && Number.isSafeInteger(value) && value >= 0;
}

function isNonEmptyString(value: unknown): value is string {
  return typeof value === 'string' && value.trim().length > 0;
}

function hasExactKeys(record: Record<string, unknown>, keys: readonly string[]): boolean {
  const actual = Object.keys(record);
  if (actual.length !== keys.length) return false;
  for (const key of keys) {
    if (!Object.prototype.hasOwnProperty.call(record, key)) return false;
  }
  return true;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}
