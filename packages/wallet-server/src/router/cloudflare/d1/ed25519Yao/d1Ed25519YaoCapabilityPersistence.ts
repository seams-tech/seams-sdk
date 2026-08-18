import { alphabetizeStringify } from '@shared/utils/digests';
import { parseWalletId } from '@shared/utils/domainIds';
import type { WalletEd25519YaoActiveCapabilityRecord } from '../../../../core/WalletStore';
import type { D1WalletStore, D1WalletStoreScope } from '../../../../core/d1WalletStore';
import type { D1DatabaseLike, D1ResultLike } from '../../../../storage/tenantRoute';
import type {
  RouterAbEd25519YaoCapabilityReplacementOperationV1,
  RouterAbEd25519YaoCapabilityPersistenceResultV1,
  RouterAbEd25519YaoCapabilityPersistenceV1,
} from '../../../domains/ed25519Yao/recovery/routerAbEd25519YaoRecovery';
import {
  ed25519NearPublicKeyFromBytes,
  replaceYaoEd25519WalletSignerActiveCapability,
} from './d1Ed25519YaoWalletSigner';

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
    const previousJson = JSON.stringify(signer);
    const nextJson = JSON.stringify(replacement);
    const previousBindingJson = JSON.stringify(input.previous.activeCapabilityBinding);
    const nextBindingJson = JSON.stringify(input.next.activeCapabilityBinding);
    try {
      const results = await this.database.batch<D1ResultLike>([
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
      ]);
      requireSuccessfulBatch(results);
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

function requireSuccessfulBatch(results: readonly D1ResultLike[]): void {
  if (results.length !== 2 || results.some((result) => result.success !== true)) {
    throw new Error('capability replacement D1 batch failed');
  }
}
