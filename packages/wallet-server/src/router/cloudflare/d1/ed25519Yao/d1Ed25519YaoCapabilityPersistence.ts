import { alphabetizeStringify } from '@shared/utils/digests';
import { mpcMaterialActivationRefsEqual, parseWalletId } from '@shared/utils/domainIds';
import {
  parseWalletAuthorityV1,
  replaceActiveWalletAuthorityEd25519MaterialActivationV1,
  type ActiveWalletAuthorityV1,
} from '@shared/authorization/walletAuthority';
import {
  buildWalletSessionAuthorizationV2,
  buildWalletSessionCapabilitySubjectsV1,
  parseWalletSessionAuthorizationV2,
  type WalletSessionAuthorizationV2,
} from '../../../../authorization/domain';
import type { WalletEd25519YaoActiveCapabilityRecord } from '../../../../core/WalletStore';
import type { D1WalletStore, D1WalletStoreScope } from '../../../../core/d1WalletStore';
import type {
  D1DatabaseLike,
  D1PreparedStatementLike,
  D1ResultLike,
} from '../../../../storage/tenantRoute';
import type {
  RouterAbEd25519YaoCapabilityReplacementOperationV1,
  RouterAbEd25519YaoCapabilityPersistenceResultV1,
  RouterAbEd25519YaoCapabilityPersistenceV1,
} from '../../../domains/ed25519Yao/recovery/routerAbEd25519YaoRecovery';
import {
  ed25519NearPublicKeyFromBytes,
  replaceYaoEd25519WalletSignerActiveCapability,
} from './d1Ed25519YaoWalletSigner';
import { routerAbMpcMaterialActivationRefFromWire } from '@shared/utils/routerAbNormalSigningIdentity';

export const ROUTER_AB_ED25519_YAO_CAPABILITY_REPLACEMENT_TABLE_V1 =
  'router_ab_yao_capability_replacements';

const CAPABILITY_REPLACEMENT_SCHEMA_SQL = `
  CREATE TABLE IF NOT EXISTS ${ROUTER_AB_ED25519_YAO_CAPABILITY_REPLACEMENT_TABLE_V1} (
    namespace TEXT NOT NULL,
    org_id TEXT NOT NULL,
    project_id TEXT NOT NULL,
    env_id TEXT NOT NULL,
    operation_id TEXT NOT NULL,
    operation_fingerprint TEXT NOT NULL,
    previous_capability_binding_json TEXT NOT NULL,
    next_capability_binding_json TEXT NOT NULL,
    created_at_ms INTEGER NOT NULL,
    PRIMARY KEY (namespace, org_id, project_id, env_id, operation_id),
    CHECK (length(operation_id) > 0),
    CHECK (length(operation_fingerprint) > 0),
    CHECK (json_valid(previous_capability_binding_json)),
    CHECK (json_valid(next_capability_binding_json)),
    CHECK (created_at_ms >= 0)
  )
`;

type CapabilityReplacementReceiptRow = {
  readonly operation_fingerprint?: unknown;
  readonly previous_capability_binding_json?: unknown;
  readonly next_capability_binding_json?: unknown;
};

type RecordJsonRow = {
  readonly record_json?: unknown;
};

type ActiveAuthorityReplacement = {
  readonly previous: ActiveWalletAuthorityV1;
  readonly next: ActiveWalletAuthorityV1;
  readonly sessions: readonly WalletSessionAuthorizationV2[];
};

type CapabilityPersistenceFailure = Extract<
  RouterAbEd25519YaoCapabilityPersistenceResultV1,
  { readonly ok: false }
>;

export type CloudflareD1RouterAbEd25519YaoCapabilityPersistenceOptions = {
  readonly database: D1DatabaseLike;
  readonly scope: D1WalletStoreScope;
  readonly walletStore: D1WalletStore;
  readonly ensureSchema?: boolean;
  readonly now?: () => number;
};

function activeCapabilityApplication(capability: WalletEd25519YaoActiveCapabilityRecord) {
  return capability.admissionRequest.application_binding;
}

function activeCapabilityParticipants(
  capability: WalletEd25519YaoActiveCapabilityRecord,
): readonly [number, number] {
  return capability.admissionRequest.participant_ids;
}

function activeCapabilitySigningWorkerId(
  capability: WalletEd25519YaoActiveCapabilityRecord,
): string {
  return capability.admissionRequest.scope.signing_worker_id;
}

function activeCapabilityPublicKey(capability: WalletEd25519YaoActiveCapabilityRecord): string {
  return ed25519NearPublicKeyFromBytes(
    capability.activationResult.public_receipt.registered_public_key,
  );
}

function capabilityBindingMatches(
  left: WalletEd25519YaoActiveCapabilityRecord,
  right: WalletEd25519YaoActiveCapabilityRecord,
): boolean {
  return (
    alphabetizeStringify(left.activeCapabilityBinding) ===
    alphabetizeStringify(right.activeCapabilityBinding)
  );
}

function persistenceFailure(code: string, message: string): CapabilityPersistenceFailure {
  return { ok: false, disposition: 'rejected', code, message };
}

function persistenceUncertain(error: unknown): CapabilityPersistenceFailure {
  return {
    ok: false,
    disposition: 'uncertain',
    code: 'capability_persistence_uncertain',
    message: error instanceof Error ? error.message : String(error),
  };
}

function parseRecordJson(value: unknown): unknown {
  if (typeof value !== 'string' || !value) {
    throw new Error('D1 record JSON is missing');
  }
  return JSON.parse(value) as unknown;
}

export class CloudflareD1RouterAbEd25519YaoCapabilityPersistence implements RouterAbEd25519YaoCapabilityPersistenceV1 {
  private readonly database: D1DatabaseLike;
  private readonly scope: D1WalletStoreScope;
  private readonly walletStore: D1WalletStore;
  private readonly ensureSchemaOnUse: boolean;
  private readonly now: () => number;
  private schemaReady = false;

  constructor(options: CloudflareD1RouterAbEd25519YaoCapabilityPersistenceOptions) {
    this.database = options.database;
    this.scope = options.scope;
    this.walletStore = options.walletStore;
    this.ensureSchemaOnUse = options.ensureSchema ?? true;
    this.now = options.now ?? Date.now;
  }

  async replaceActiveCapability(input: {
    readonly operation: RouterAbEd25519YaoCapabilityReplacementOperationV1;
    readonly previous: WalletEd25519YaoActiveCapabilityRecord;
    readonly next: WalletEd25519YaoActiveCapabilityRecord;
  }): Promise<RouterAbEd25519YaoCapabilityPersistenceResultV1> {
    const operation = validateReplacementOperation(input.operation);
    if (!operation.ok) return operation.failure;
    await this.ensureSchema();
    const existingReceipt = await this.readReceipt(operation.value.operationId);
    const receiptMatch = matchReceipt(existingReceipt, operation.value, input);
    if (receiptMatch === 'match') {
      return { ok: true, disposition: 'exact_retry' };
    }
    if (receiptMatch === 'conflict') {
      return persistenceFailure(
        'operation_conflict',
        'capability replacement operation belongs to a different activation',
      );
    }

    const application = activeCapabilityApplication(input.next);
    const walletId = parseWalletId(application.wallet_id);
    if (!walletId.ok) {
      return persistenceFailure('invalid_wallet', 'promoted Yao capability wallet ID is invalid');
    }
    const signer = await this.walletStore.getEd25519SignerBySlot({
      walletId: walletId.value,
      signerSlot: application.key_creation_signer_slot,
    });
    if (!signer) {
      return persistenceFailure('signer_not_found', 'promoted Yao capability signer was not found');
    }
    if (!capabilityBindingMatches(signer.activeYaoCapability, input.previous)) {
      return persistenceFailure(
        'capability_conflict',
        'durable Yao capability changed before recovery promotion',
      );
    }
    if (
      signer.walletId !== application.wallet_id ||
      signer.nearAccountId !== input.next.nearAccountId ||
      signer.nearEd25519SigningKeyId !== application.near_ed25519_signing_key_id ||
      signer.signerSlot !== application.key_creation_signer_slot ||
      signer.signingRootId !== application.signing_root_id ||
      signer.signingRootVersion !== input.next.admissionRequest.scope.root_share_epoch ||
      signer.signingWorkerId !== activeCapabilitySigningWorkerId(input.next) ||
      signer.publicKey !== activeCapabilityPublicKey(input.next) ||
      alphabetizeStringify(signer.participantIds) !==
        alphabetizeStringify(activeCapabilityParticipants(input.next)) ||
      alphabetizeStringify(signer.runtimePolicyScope) !==
        alphabetizeStringify(input.next.runtimePolicyScope)
    ) {
      return persistenceFailure(
        'identity_mismatch',
        'promoted Yao capability does not match its durable signer',
      );
    }
    const now = this.now();
    const replacement = replaceYaoEd25519WalletSignerActiveCapability({
      signer,
      activeYaoCapability: input.next,
      now,
    });
    const authorityReplacements = await this.prepareActiveAuthorityReplacements({
      walletId: String(walletId.value),
      previous: input.previous,
      next: input.next,
      now,
      selection:
        input.operation.authorityProjection.kind === 'replace_active_authority_projection'
          ? 'exactly_one'
          : 'all_matching',
    });
    if (!authorityReplacements) {
      return persistenceFailure(
        'authority_conflict',
        input.operation.authorityProjection.kind === 'replace_active_authority_projection'
          ? 'promoted Yao capability does not resolve one exact active Wallet Authority'
          : 'promoted Yao capability does not resolve active continuity authorities',
      );
    }
    const previousJson = JSON.stringify(signer);
    const nextJson = JSON.stringify(replacement);
    const previousBindingJson = JSON.stringify(input.previous.activeCapabilityBinding);
    const nextBindingJson = JSON.stringify(input.next.activeCapabilityBinding);
    try {
      const statements: D1PreparedStatementLike[] = [
        this.database
          .prepare(
            `UPDATE wallet_signers
                SET record_json = ?,
                    updated_at_ms = ?
              WHERE namespace = ?
                AND org_id = ?
                AND project_id = ?
                AND env_id = ?
                AND wallet_id = ?
                AND signer_family = 'ed25519'
                AND signer_id = ?
                AND record_json = ?`,
          )
          .bind(
            nextJson,
            now,
            this.scope.namespace,
            this.scope.orgId,
            this.scope.projectId,
            this.scope.envId,
            signer.walletId,
            signer.signerId,
            previousJson,
          ),
      ];
      /* The receipt insert must run directly after the guarded signer update:
         its changes() guard reads the immediately preceding statement, and a
         later authority or session replacement that legitimately matches zero
         rows would otherwise skip the receipt while the signer row commits —
         leaving a durable promotion the retry can no longer recognize. */
      statements.push(
        this.database
          .prepare(
            `INSERT INTO ${ROUTER_AB_ED25519_YAO_CAPABILITY_REPLACEMENT_TABLE_V1} (
              namespace,
              org_id,
              project_id,
              env_id,
              operation_id,
              operation_fingerprint,
              previous_capability_binding_json,
              next_capability_binding_json,
              created_at_ms
            )
            SELECT ?, ?, ?, ?, ?, ?, ?, ?, ?
             WHERE changes() = 1`,
          )
          .bind(
            this.scope.namespace,
            this.scope.orgId,
            this.scope.projectId,
            this.scope.envId,
            operation.value.operationId,
            operation.value.operationFingerprint,
            previousBindingJson,
            nextBindingJson,
            now,
          ),
      );
      for (const authorityReplacement of authorityReplacements) {
        statements.push(this.prepareAuthorityReplacementStatement(authorityReplacement));
        for (const session of authorityReplacement.sessions) {
          statements.push(
            this.prepareSessionAuthorityProjectionReplacementStatement({
              previous: session,
              authority: authorityReplacement.next,
            }),
          );
        }
      }
      const results = await this.database.batch<D1ResultLike>(statements);
      requireSuccessfulBatch(results, statements.length);
    } catch (error: unknown) {
      return await this.reconcileAfterUncertainWrite(operation.value, input, error);
    }
    const receipt = await this.readReceipt(operation.value.operationId);
    const committed = matchReceipt(receipt, operation.value, input);
    if (committed === 'match') return { ok: true, disposition: 'applied' };
    if (committed === 'conflict') {
      return persistenceFailure(
        'operation_conflict',
        'capability replacement operation raced with a different activation',
      );
    }
    return persistenceFailure(
      'capability_conflict',
      'durable Yao capability changed before recovery promotion',
    );
  }

  private async ensureSchema(): Promise<void> {
    if (!this.ensureSchemaOnUse || this.schemaReady) return;
    await this.database.exec(CAPABILITY_REPLACEMENT_SCHEMA_SQL);
    this.schemaReady = true;
  }

  private async prepareActiveAuthorityReplacements(input: {
    readonly walletId: string;
    readonly previous: WalletEd25519YaoActiveCapabilityRecord;
    readonly next: WalletEd25519YaoActiveCapabilityRecord;
    readonly now: number;
    readonly selection: 'exactly_one' | 'all_matching';
  }): Promise<readonly ActiveAuthorityReplacement[] | null> {
    const rows = await this.database
      .prepare(
        `SELECT record_json
           FROM wallet_authorities
          WHERE namespace = ?
            AND org_id = ?
            AND project_id = ?
            AND env_id = ?
            AND wallet_id = ?
            AND lifecycle_state = 'active'`,
      )
      .bind(
        this.scope.namespace,
        this.scope.orgId,
        this.scope.projectId,
        this.scope.envId,
        input.walletId,
      )
      .all<RecordJsonRow>();
    const previousActivation = routerAbMpcMaterialActivationRefFromWire(
      input.previous.activationResult.binding.material_activation,
    );
    const matches: ActiveWalletAuthorityV1[] = [];
    for (const row of rows.results ?? []) {
      const parsed = parseWalletAuthorityV1(parseRecordJson(row.record_json));
      if (
        parsed.ok &&
        parsed.value.state === 'active' &&
        parsed.value.signerActivations.ed25519 &&
        mpcMaterialActivationRefsEqual(
          parsed.value.signerActivations.ed25519.materialActivation,
          previousActivation,
        )
      ) {
        matches.push(parsed.value);
      }
    }
    if (matches.length === 0 || (input.selection === 'exactly_one' && matches.length !== 1)) {
      return null;
    }
    const replacements: ActiveAuthorityReplacement[] = [];
    for (const previousAuthority of matches) {
      const nextAuthority = await replaceActiveWalletAuthorityEd25519MaterialActivationV1({
        authority: previousAuthority,
        materialActivation: routerAbMpcMaterialActivationRefFromWire(
          input.next.activationResult.binding.material_activation,
        ),
        updatedAtMs: input.now,
      });
      const sessionRows = await this.database
        .prepare(
          `SELECT record_json
             FROM wallet_session_authorizations_v2
            WHERE namespace = ?
              AND org_id = ?
              AND project_id = ?
              AND env_id = ?
              AND wallet_id = ?
              AND authority_id = ?
              AND retired_at_ms IS NULL`,
        )
        .bind(
          this.scope.namespace,
          this.scope.orgId,
          this.scope.projectId,
          this.scope.envId,
          input.walletId,
          String(previousAuthority.authorityId),
        )
        .all<RecordJsonRow>();
      const sessions: WalletSessionAuthorizationV2[] = [];
      for (const row of sessionRows.results ?? []) {
        sessions.push(parseWalletSessionAuthorizationV2(parseRecordJson(row.record_json)));
      }
      replacements.push({ previous: previousAuthority, next: nextAuthority, sessions });
    }
    return replacements;
  }

  private prepareAuthorityReplacementStatement(
    replacement: ActiveAuthorityReplacement,
  ): D1PreparedStatementLike {
    return this.database
      .prepare(
        `UPDATE wallet_authorities
            SET signer_activations_json = ?,
                signer_activation_set_digest_b64u = ?,
                authority_digest_b64u = ?,
                record_json = ?,
                updated_at_ms = ?
          WHERE namespace = ?
            AND org_id = ?
            AND project_id = ?
            AND env_id = ?
            AND authority_id = ?
            AND wallet_id = ?
            AND lifecycle_state = 'active'
            AND record_json = ?`,
      )
      .bind(
        JSON.stringify(replacement.next.signerActivations),
        String(replacement.next.signerActivationSetDigestB64u),
        String(replacement.next.authorityDigestB64u),
        JSON.stringify(replacement.next),
        replacement.next.updatedAtMs,
        this.scope.namespace,
        this.scope.orgId,
        this.scope.projectId,
        this.scope.envId,
        String(replacement.previous.authorityId),
        String(replacement.previous.walletId),
        JSON.stringify(replacement.previous),
      );
  }

  private prepareSessionAuthorityProjectionReplacementStatement(input: {
    readonly previous: WalletSessionAuthorizationV2;
    readonly authority: ActiveWalletAuthorityV1;
  }): D1PreparedStatementLike {
    const next = buildWalletSessionAuthorizationV2({
      tenantId: input.previous.tenantId,
      principalId: input.previous.principalId,
      walletId: input.previous.walletId,
      authorityId: input.previous.authorityId,
      walletAuthMethodId: input.previous.walletAuthMethodId,
      authorityDigestB64u: input.authority.authorityDigestB64u,
      authorityRevocationEpoch: input.authority.revocationEpoch,
      mintId: input.previous.mintId,
      authorizationId: input.previous.authorizationId,
      walletSessionId: input.previous.walletSessionId,
      quotaId: input.previous.quotaId,
      capabilitySubjects: buildWalletSessionCapabilitySubjectsV1(input.authority),
      createdAtMs: input.previous.createdAtMs,
      expiresAtMs: input.previous.expiresAtMs,
    });
    return this.database
      .prepare(
        `UPDATE wallet_session_authorizations_v2
            SET authority_digest_b64u = ?,
                capability_subjects_json = ?,
                record_json = ?
          WHERE namespace = ?
            AND org_id = ?
            AND project_id = ?
            AND env_id = ?
            AND authorization_id = ?
            AND authority_id = ?
            AND record_json = ?
            AND retired_at_ms IS NULL`,
      )
      .bind(
        String(next.authorityDigestB64u),
        JSON.stringify(next.capabilitySubjects),
        JSON.stringify(next),
        this.scope.namespace,
        this.scope.orgId,
        this.scope.projectId,
        this.scope.envId,
        String(next.authorizationId),
        String(next.authorityId),
        JSON.stringify(input.previous),
      );
  }

  private async readReceipt(operationId: string): Promise<CapabilityReplacementReceiptRow | null> {
    return await this.database
      .prepare(
        `SELECT operation_fingerprint,
                previous_capability_binding_json,
                next_capability_binding_json
           FROM ${ROUTER_AB_ED25519_YAO_CAPABILITY_REPLACEMENT_TABLE_V1}
          WHERE namespace = ?
            AND org_id = ?
            AND project_id = ?
            AND env_id = ?
            AND operation_id = ?
          LIMIT 1`,
      )
      .bind(
        this.scope.namespace,
        this.scope.orgId,
        this.scope.projectId,
        this.scope.envId,
        operationId,
      )
      .first<CapabilityReplacementReceiptRow>();
  }

  private async reconcileAfterUncertainWrite(
    operation: RouterAbEd25519YaoCapabilityReplacementOperationV1,
    input: {
      readonly previous: WalletEd25519YaoActiveCapabilityRecord;
      readonly next: WalletEd25519YaoActiveCapabilityRecord;
    },
    error: unknown,
  ): Promise<RouterAbEd25519YaoCapabilityPersistenceResultV1> {
    try {
      const receipt = await this.readReceipt(operation.operationId);
      const matched = matchReceipt(receipt, operation, input);
      if (matched === 'match') return { ok: true, disposition: 'exact_retry' };
      if (matched === 'conflict') {
        return persistenceFailure(
          'operation_conflict',
          'capability replacement operation belongs to a different activation',
        );
      }
    } catch {
      return persistenceUncertain(error);
    }
    return persistenceUncertain(error);
  }
}

type ReplacementOperationValidation =
  | {
      readonly ok: true;
      readonly value: RouterAbEd25519YaoCapabilityReplacementOperationV1;
    }
  | {
      readonly ok: false;
      readonly failure: CapabilityPersistenceFailure;
    };

function validateReplacementOperation(
  operation: RouterAbEd25519YaoCapabilityReplacementOperationV1,
): ReplacementOperationValidation {
  const operationId = operation.operationId.trim();
  const operationFingerprint = operation.operationFingerprint;
  if (
    operation.kind !== 'router_ab_ed25519_yao_capability_replacement_operation_v1' ||
    (operation.authorityProjection.kind !== 'replace_continuity_authority_projections' &&
      operation.authorityProjection.kind !== 'replace_active_authority_projection') ||
    !operationId ||
    operationId.length > 256 ||
    !/^[\x21-\x7e]+$/u.test(operationId) ||
    !operationFingerprint.trim()
  ) {
    return {
      ok: false,
      failure: persistenceFailure(
        'invalid_operation',
        'capability replacement operation is invalid',
      ),
    };
  }
  return {
    ok: true,
    value: {
      kind: 'router_ab_ed25519_yao_capability_replacement_operation_v1',
      operationId,
      operationFingerprint,
      authorityProjection: operation.authorityProjection,
    },
  };
}

function matchReceipt(
  receipt: CapabilityReplacementReceiptRow | null,
  operation: RouterAbEd25519YaoCapabilityReplacementOperationV1,
  input: {
    readonly previous: WalletEd25519YaoActiveCapabilityRecord;
    readonly next: WalletEd25519YaoActiveCapabilityRecord;
  },
): 'missing' | 'match' | 'conflict' {
  if (!receipt) return 'missing';
  return receipt.operation_fingerprint === operation.operationFingerprint &&
    receipt.previous_capability_binding_json ===
      JSON.stringify(input.previous.activeCapabilityBinding) &&
    receipt.next_capability_binding_json === JSON.stringify(input.next.activeCapabilityBinding)
    ? 'match'
    : 'conflict';
}

function requireSuccessfulBatch(results: readonly D1ResultLike[], expectedLength: number): void {
  if (results.length !== expectedLength || results.some((result) => result.success !== true)) {
    throw new Error('capability replacement D1 batch failed');
  }
}
