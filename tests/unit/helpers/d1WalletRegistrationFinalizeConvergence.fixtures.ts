import type {
  CloudflareDurableObjectNamespaceLike,
  CloudflareDurableObjectStubLike,
} from '../../../packages/sdk-server-ts/src/core/types';
import {
  buildStoredWalletRegistrationNearEd25519YaoAuthorizedBranch,
  buildStoredWalletRegistrationPreparedContext,
  type StoredWalletRegistrationCeremony,
} from '../../../packages/sdk-server-ts/src/core/RegistrationCeremonyStore';
import { normalizeLogger } from '../../../packages/sdk-server-ts/src/core/logger';
import { createRouterAbSigningRuntimes } from '../../../packages/sdk-server-ts/src/core/routerAbSigning/createRouterAbSigningRuntimes';
import {
  parseRouterAbNormalSigningRuntimeConfig,
  RouterAbNormalSigningRuntime,
} from '../../../packages/sdk-server-ts/src/core/routerAbSigning/RouterAbNormalSigningRuntime';
import {
  createEcdsaWalletSessionStore,
  createEd25519WalletSessionStore,
  createWalletSigningBudgetSessionStore,
} from '../../../packages/sdk-server-ts/src/core/ThresholdService/stores/WalletSessionStore';
import type { WalletRegistrationFinalizeRequest } from '../../../packages/sdk-server-ts/src/core/registrationContracts';
import {
  createCloudflareD1RouterApiAuthService,
  type CloudflareD1RouterApiAuthService,
} from '../../../packages/sdk-server-ts/src/router/cloudflare/d1RouterApiAuthService';
import { buildRegistrationIntent } from '../../../packages/sdk-server-ts/src/router/cloudflare/d1RegistrationCeremonyRecords';
import { CloudflareD1RegistrationCeremonyIntentStore } from '../../../packages/sdk-server-ts/src/router/cloudflare/d1RegistrationCeremonyStore';
import type {
  D1DatabaseLike,
  D1PreparedStatementLike,
} from '../../../packages/sdk-server-ts/src/storage/tenantRoute';
import {
  createRouterAbEd25519YaoProductRegistrationStatefulCompositionV1,
  createRouterAbEd25519YaoProductRegistrationStateV1,
  type RouterAbEd25519YaoProductRegistrationRuntimeV1,
} from '../../../packages/sdk-server-ts/src/router/routerAbEd25519YaoProductRegistration';
import {
  InMemoryRouterAbEd25519YaoRegistrationService,
  type RouterAbEd25519YaoRegistrationBackend,
  type RouterAbEd25519YaoRegistrationBackendResult,
} from '../../../packages/sdk-server-ts/src/router/routerAbEd25519YaoRegistration';
import type {
  RouterAbEd25519YaoCapabilityPersistenceV1,
  RouterAbEd25519YaoCapabilityPersistenceResultV1,
} from '../../../packages/sdk-server-ts/src/router/routerAbEd25519YaoRecovery';
import type { RouterAbEd25519YaoRecoveryBackend } from '../../../packages/sdk-server-ts/src/router/routerAbEd25519YaoRecovery';
import type { RouterAbEd25519YaoExportBackend } from '../../../packages/sdk-server-ts/src/router/routerAbEd25519YaoExport';
import type { RouterAbEcdsaStrictRegistrationPort } from '../../../packages/sdk-server-ts/src/router/routerAbEcdsaStrictRegistration';
import {
  implicitNearAccountProvisioning,
  registrationNearEd25519BranchKey,
  registrationSignerPlanFromSelection,
  walletIdFromString,
  type RegistrationAuthority,
  type RegistrationSignerSetSelection,
  type WalletId,
} from '../../../packages/shared-ts/src/utils/registrationIntent';
import {
  parseRouterAbEd25519YaoRegistrationActivationAdmissionReceiptV1,
  parseRouterAbEd25519YaoRegistrationActivationExecuteRequestV1,
  type RouterAbEd25519YaoActivationAdmissionReceiptV1,
  type RouterAbEd25519YaoActivationExecuteRequestV1,
  type RouterAbEd25519YaoActivationResultV1,
  type RouterAbEd25519YaoRegistrationAdmissionRequestV1,
} from '../../../packages/shared-ts/src/utils/routerAbEd25519Yao';
import { parseWebAuthnRpId } from '../../../packages/shared-ts/src/utils/domainIds';
import { unknownWebAuthnAuthenticatorDeviceInfo } from '../../../packages/shared-ts/src/utils/webauthnDeviceInfo';
import { buildEd25519YaoCapabilityFixture } from '../../helpers/ed25519YaoCapabilityFixtures';
import { cleanupTemporaryD1Database, createTemporaryD1Database } from '../../helpers/sqliteD1';
import { applySignerMigrations } from './cloudflareD1RouterApiAuthService.fixtures';
import { StaticWalletSessionAdapter } from './routerAbEd25519YaoRegistrationBridge.fixtures';

const TEST_SCOPE = {
  namespace: 'registration-finalize-convergence',
  orgId: 'org-finalize',
  projectId: 'project-finalize',
  envId: 'env-finalize',
} as const;
const THRESHOLD_PREFIX = 'registration-finalize-convergence';
const REGISTRATION_STORE_PREFIX = `${THRESHOLD_PREFIX}:wallet-registration:`;
const SIGNING_WORKER_ID = 'signing-worker-finalize';
const REGISTRATION_CEREMONY_ID = 'registration-ceremony-finalize-1';
const IDEMPOTENCY_KEY = 'registration-finalize-convergence-1';

export type FinalizeConvergenceFault =
  | 'activation_consume_response_loss'
  | 'session_mint_response_loss'
  | 'normal_signing_response_loss'
  | 'wallet_commit_response_loss'
  | 'capability_install_response_loss'
  | 'finalize_replay_response_loss'
  | 'ceremony_delete_response_loss'
  | 'finalize_claim_response_loss'
  | 'finalize_completion_response_loss';

type YaoFault =
  | 'activation_consume_response_loss'
  | 'session_mint_response_loss'
  | 'capability_install_response_loss';

function bytes(seed: number, length = 32): number[] {
  return new Array<number>(length).fill(seed);
}

function parsedValue<T>(
  result:
    | { readonly ok: true; readonly value: T }
    | { readonly ok: false; readonly message: string },
): T {
  if (!result.ok) throw new Error(result.message);
  return result.value;
}

function jsonResponse(body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status: 200,
    headers: { 'content-type': 'application/json' },
  });
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

class FinalizeCeremonyDurableObjectStub implements CloudflareDurableObjectStubLike {
  readonly values = new Map<string, unknown>();
  private loseSetResponseForKey: string | null = null;
  private loseDeleteResponseForKey: string | null = null;

  armSetResponseLoss(key: string): void {
    this.loseSetResponseForKey = key;
  }

  armDeleteResponseLoss(key: string): void {
    this.loseDeleteResponseForKey = key;
  }

  async fetch(_input: RequestInfo, init?: RequestInit): Promise<Response> {
    const request = this.parseRequest(init?.body);
    const key = String(request.key || '').trim();
    switch (request.op) {
      case 'set':
        this.values.set(key, request.value);
        if (this.loseSetResponseForKey === key) {
          this.loseSetResponseForKey = null;
          throw new Error('simulated finalize replay response loss');
        }
        return jsonResponse({ ok: true, value: true });
      case 'get':
        return jsonResponse({ ok: true, value: this.values.get(key) ?? null });
      case 'del': {
        const deleted = this.values.delete(key);
        if (this.loseDeleteResponseForKey === key) {
          this.loseDeleteResponseForKey = null;
          throw new Error('simulated ceremony delete response loss');
        }
        return jsonResponse({ ok: true, value: deleted });
      }
      default:
        return jsonResponse({
          ok: false,
          code: 'unsupported_op',
          message: `Unsupported finalize fixture operation: ${String(request.op || '')}`,
        });
    }
  }

  private parseRequest(body: BodyInit | null | undefined): Record<string, unknown> {
    if (typeof body !== 'string') return {};
    const parsed: unknown = JSON.parse(body);
    return isRecord(parsed) ? parsed : {};
  }
}

class FinalizeCeremonyDurableObjectNamespace implements CloudflareDurableObjectNamespaceLike {
  readonly stub = new FinalizeCeremonyDurableObjectStub();

  idFromName(name: string): string {
    return name;
  }

  get(): CloudflareDurableObjectStubLike {
    return this.stub;
  }
}

class ResponseLossD1Database implements D1DatabaseLike {
  private loseWalletCommitResponse = false;
  private loseFinalizeClaimResponse = false;
  private loseFinalizeCompletionResponse = false;

  constructor(readonly delegate: D1DatabaseLike) {}

  armBatchResponseLoss(): void {
    this.loseWalletCommitResponse = true;
  }

  armFinalizeClaimResponseLoss(): void {
    this.loseFinalizeClaimResponse = true;
  }

  armFinalizeCompletionResponseLoss(): void {
    this.loseFinalizeCompletionResponse = true;
  }

  prepare(query: string): D1PreparedStatementLike {
    return new InspectableD1PreparedStatement(this, query, [], this.delegate.prepare(query));
  }

  async batch<T = unknown>(statements: readonly D1PreparedStatementLike[]): Promise<readonly T[]> {
    const inspected = statements.map(requireInspectableD1PreparedStatement);
    const result = await this.delegate.batch<T>(inspected.map((statement) => statement.delegate));
    if (
      this.loseWalletCommitResponse &&
      inspected.some((statement) => /\bINSERT\s+INTO\s+wallets\b/iu.test(statement.query))
    ) {
      this.loseWalletCommitResponse = false;
      throw new Error('simulated wallet commit response loss');
    }
    return result;
  }

  async exec(query: string): Promise<unknown> {
    return await this.delegate.exec(query);
  }

  loseRunResponse(query: string, values: readonly unknown[]): void {
    const recordKey = String(values[4] || '');
    if (!recordKey.startsWith('wallet-registration-finalize:')) return;
    if (
      this.loseFinalizeClaimResponse &&
      /\bINSERT\s+OR\s+IGNORE\s+INTO\s+router_ab_yao_versioned_json_records\b/iu.test(query)
    ) {
      this.loseFinalizeClaimResponse = false;
      throw new Error('simulated finalize claim response loss');
    }
    if (
      this.loseFinalizeCompletionResponse &&
      /\bUPDATE\s+router_ab_yao_versioned_json_records\b/iu.test(query)
    ) {
      this.loseFinalizeCompletionResponse = false;
      throw new Error('simulated finalize completion response loss');
    }
  }
}

class InspectableD1PreparedStatement implements D1PreparedStatementLike {
  constructor(
    private readonly database: ResponseLossD1Database,
    readonly query: string,
    readonly values: readonly unknown[],
    readonly delegate: D1PreparedStatementLike,
  ) {}

  bind(...values: readonly unknown[]): D1PreparedStatementLike {
    return new InspectableD1PreparedStatement(
      this.database,
      this.query,
      values,
      this.delegate.bind(...values),
    );
  }

  async first<T = unknown>(columnName?: string): Promise<T | null> {
    return await this.delegate.first<T>(columnName);
  }

  async all<T = unknown>() {
    return await this.delegate.all<T>();
  }

  async run<T = unknown>() {
    const result = await this.delegate.run<T>();
    this.database.loseRunResponse(this.query, this.values);
    return result;
  }
}

function requireInspectableD1PreparedStatement(
  statement: D1PreparedStatementLike,
): InspectableD1PreparedStatement {
  if (!(statement instanceof InspectableD1PreparedStatement)) {
    throw new Error('Finalize convergence batch received an uninspectable statement');
  }
  return statement;
}

class FinalizeYaoBackend
  implements
    RouterAbEd25519YaoRegistrationBackend,
    RouterAbEd25519YaoRecoveryBackend,
    RouterAbEd25519YaoExportBackend
{
  constructor(
    private readonly admissionReceipt: RouterAbEd25519YaoActivationAdmissionReceiptV1<'registration'>,
    private readonly activationResult: RouterAbEd25519YaoActivationResultV1<'registration'>,
  ) {}

  admit(): RouterAbEd25519YaoRegistrationBackendResult {
    return { ok: true, body: this.admissionReceipt };
  }

  execute(): RouterAbEd25519YaoRegistrationBackendResult {
    return { ok: true, body: this.activationResult };
  }

  admitRecovery(): never {
    throw new Error('Recovery is outside the finalize convergence fixture');
  }

  executeRecovery(): never {
    throw new Error('Recovery is outside the finalize convergence fixture');
  }

  activateRecovery(): never {
    throw new Error('Recovery is outside the finalize convergence fixture');
  }

  admitExport(): never {
    throw new Error('Export is outside the finalize convergence fixture');
  }

  executeExport(): never {
    throw new Error('Export is outside the finalize convergence fixture');
  }
}

class AppliedCapabilityPersistence implements RouterAbEd25519YaoCapabilityPersistenceV1 {
  async replaceActiveCapability(): Promise<RouterAbEd25519YaoCapabilityPersistenceResultV1> {
    return { ok: true, disposition: 'applied' };
  }
}

class UnusedEcdsaStrictRegistration implements RouterAbEcdsaStrictRegistrationPort {
  topology(): never {
    throw new Error('ECDSA is outside the finalize convergence fixture');
  }

  async register(): Promise<never> {
    throw new Error('ECDSA is outside the finalize convergence fixture');
  }

  async activate(): Promise<never> {
    throw new Error('ECDSA is outside the finalize convergence fixture');
  }
}

class FailureInjectingYaoRuntime implements RouterAbEd25519YaoProductRegistrationRuntimeV1 {
  readonly kind = 'router_ab_ed25519_yao_product_registration_runtime_v1' as const;
  readonly signingWorkerId: string;
  private fault: YaoFault | null = null;

  constructor(private readonly delegate: RouterAbEd25519YaoProductRegistrationRuntimeV1) {
    this.signingWorkerId = delegate.signingWorkerId;
  }

  arm(fault: YaoFault): void {
    this.fault = fault;
  }

  async bindVerifiedIntent(
    input: Parameters<RouterAbEd25519YaoProductRegistrationRuntimeV1['bindVerifiedIntent']>[0],
  ): Promise<
    Awaited<ReturnType<RouterAbEd25519YaoProductRegistrationRuntimeV1['bindVerifiedIntent']>>
  > {
    return await this.delegate.bindVerifiedIntent(input);
  }

  async consumeActivated(
    input: Parameters<RouterAbEd25519YaoProductRegistrationRuntimeV1['consumeActivated']>[0],
  ): Promise<
    Awaited<ReturnType<RouterAbEd25519YaoProductRegistrationRuntimeV1['consumeActivated']>>
  > {
    const result = await this.delegate.consumeActivated(input);
    this.throwAfter('activation_consume_response_loss');
    return result;
  }

  async installRegistrationFinalizeCapability(
    input: Parameters<
      RouterAbEd25519YaoProductRegistrationRuntimeV1['installRegistrationFinalizeCapability']
    >[0],
  ): Promise<
    Awaited<
      ReturnType<
        RouterAbEd25519YaoProductRegistrationRuntimeV1['installRegistrationFinalizeCapability']
      >
    >
  > {
    const result = await this.delegate.installRegistrationFinalizeCapability(input);
    this.throwAfter('capability_install_response_loss');
    return result;
  }

  async installPersistedActiveCapability(
    input: Parameters<
      RouterAbEd25519YaoProductRegistrationRuntimeV1['installPersistedActiveCapability']
    >[0],
  ): Promise<
    Awaited<
      ReturnType<RouterAbEd25519YaoProductRegistrationRuntimeV1['installPersistedActiveCapability']>
    >
  > {
    return await this.delegate.installPersistedActiveCapability(input);
  }

  async resolveActiveCapability(
    input: Parameters<RouterAbEd25519YaoProductRegistrationRuntimeV1['resolveActiveCapability']>[0],
  ): Promise<
    Awaited<ReturnType<RouterAbEd25519YaoProductRegistrationRuntimeV1['resolveActiveCapability']>>
  > {
    return await this.delegate.resolveActiveCapability(input);
  }

  async mintWalletSession(
    input: Parameters<RouterAbEd25519YaoProductRegistrationRuntimeV1['mintWalletSession']>[0],
  ): Promise<
    Awaited<ReturnType<RouterAbEd25519YaoProductRegistrationRuntimeV1['mintWalletSession']>>
  > {
    const result = await this.delegate.mintWalletSession(input);
    this.throwAfter('session_mint_response_loss');
    return result;
  }

  private throwAfter(fault: YaoFault): void {
    if (this.fault !== fault) return;
    this.fault = null;
    throw new Error(`simulated ${fault}`);
  }
}

class FailureInjectingNormalSigningRuntime extends RouterAbNormalSigningRuntime {
  private loseProvisionResponse = false;

  constructor() {
    const config = {
      kind: 'in-memory' as const,
      ROUTER_AB_NORMAL_SIGNING_WORKER_ID: SIGNING_WORKER_ID,
    };
    const storeInput = { config, logger: normalizeLogger(null), isNode: true };
    super({
      walletSessionStore: createEd25519WalletSessionStore(storeInput),
      ecdsaWalletSessionStore: createEcdsaWalletSessionStore(storeInput),
      walletBudgetSessionStore: createWalletSigningBudgetSessionStore(storeInput),
      config: parseRouterAbNormalSigningRuntimeConfig(config),
    });
  }

  armProvisionResponseLoss(): void {
    this.loseProvisionResponse = true;
  }

  override async provisionRouterAbEd25519YaoNormalSigningSession(
    input: Parameters<
      RouterAbNormalSigningRuntime['provisionRouterAbEd25519YaoNormalSigningSession']
    >[0],
  ): Promise<
    Awaited<
      ReturnType<RouterAbNormalSigningRuntime['provisionRouterAbEd25519YaoNormalSigningSession']>
    >
  > {
    const result = await super.provisionRouterAbEd25519YaoNormalSigningSession(input);
    if (this.loseProvisionResponse) {
      this.loseProvisionResponse = false;
      throw new Error('simulated normal-signing provision response loss');
    }
    return result;
  }
}

function buildAdmissionReceipt(
  activationResult: RouterAbEd25519YaoActivationResultV1<'registration'>,
): RouterAbEd25519YaoActivationAdmissionReceiptV1<'registration'> {
  return parsedValue(
    parseRouterAbEd25519YaoRegistrationActivationAdmissionReceiptV1({
      binding: activationResult.binding,
      keyset: {
        deriver_a_input_public_key: bytes(41),
        deriver_b_input_public_key: bytes(42),
        signing_worker_recipient_public_key: bytes(43),
      },
    }),
  );
}

function buildExecuteRequest(
  receipt: RouterAbEd25519YaoActivationAdmissionReceiptV1<'registration'>,
): RouterAbEd25519YaoActivationExecuteRequestV1<'registration'> {
  const encryptedInput = (deriver: 'deriver_a' | 'deriver_b', seed: number) => ({
    kind: 'activation',
    deriver,
    operation: 'registration',
    session: receipt.binding.session_id,
    stable_context_binding: receipt.binding.stable_key_context_binding,
    encapsulated_key: bytes(seed),
    ciphertext: bytes(seed + 1, 16),
  });
  return parsedValue(
    parseRouterAbEd25519YaoRegistrationActivationExecuteRequestV1({
      binding: receipt.binding,
      deriver_a_input: encryptedInput('deriver_a', 44),
      deriver_b_input: encryptedInput('deriver_b', 46),
    }),
  );
}

function testPasskeyAuthority(
  walletId: WalletId,
  rpId: ReturnType<typeof testRpId>,
): Extract<RegistrationAuthority, { readonly kind: 'passkey' }> {
  return {
    kind: 'passkey',
    walletId,
    rpId,
    credentialIdB64u: 'finalize-convergence-credential',
    credentialPublicKeyB64u: 'finalize-convergence-public-key',
    counter: 0,
    device: unknownWebAuthnAuthenticatorDeviceInfo(),
    registrationIntentDigestB64u: 'finalize-convergence-intent-digest',
  };
}

function testRpId() {
  const parsed = parseWebAuthnRpId('example.com');
  if (!parsed.ok) throw new Error(parsed.error.message);
  return parsed.value;
}

function buildCeremony(input: {
  readonly walletId: WalletId;
  readonly admissionRequest: RouterAbEd25519YaoRegistrationAdmissionRequestV1;
}): StoredWalletRegistrationCeremony {
  const signerSelection: RegistrationSignerSetSelection = {
    kind: 'signer_set',
    signers: [
      {
        kind: 'near_ed25519',
        accountProvisioning: implicitNearAccountProvisioning(),
        signerSlot: 1,
        participantIds: [1, 2],
        derivationVersion: 1,
      },
    ],
  };
  const signerPlan = registrationSignerPlanFromSelection(signerSelection);
  if (!signerPlan.ok) throw new Error(signerPlan.message);
  const runtimePolicyScope = {
    ...TEST_SCOPE,
    signingRootVersion: 'root-finalize-v1',
  };
  const intent = buildRegistrationIntent({
    walletId: input.walletId,
    authMethod: { kind: 'passkey', rpId: testRpId() },
    signerSelection,
    runtimePolicyScope,
  });
  return {
    registrationCeremonyId: REGISTRATION_CEREMONY_ID,
    intent,
    digestB64u: 'finalize-convergence-intent-digest',
    signerPlan: signerPlan.value,
    preparedContext: buildStoredWalletRegistrationPreparedContext({
      signingRootId: `${TEST_SCOPE.projectId}:${TEST_SCOPE.envId}`,
      signingRootVersion: runtimePolicyScope.signingRootVersion,
      runtimePolicyScope,
      ecdsaChainTargets: null,
    }),
    orgId: TEST_SCOPE.orgId,
    signingRootId: `${TEST_SCOPE.projectId}:${TEST_SCOPE.envId}`,
    signingRootVersion: runtimePolicyScope.signingRootVersion,
    expectedOrigin: 'https://app.example.com',
    expiresAtMs: Date.now() + 60_000,
    authority: testPasskeyAuthority(input.walletId, testRpId()),
    signerState: {
      kind: 'signer_set_registration',
      branches: [
        buildStoredWalletRegistrationNearEd25519YaoAuthorizedBranch({
          branchKey: registrationNearEd25519BranchKey(1),
          admissionRequest: input.admissionRequest,
        }),
      ],
    },
  };
}

async function activatedRuntimeFixture(): Promise<{
  readonly runtime: FailureInjectingYaoRuntime;
  readonly admissionRequest: RouterAbEd25519YaoRegistrationAdmissionRequestV1;
  readonly activationResult: RouterAbEd25519YaoActivationResultV1<'registration'>;
}> {
  const walletId = walletIdFromString('finalize-convergence-wallet');
  const capability = buildEd25519YaoCapabilityFixture({
    walletId,
    nearAccountId: 'finalize-convergence.testnet',
    nearEd25519SigningKeyId: 'near-ed25519-finalize-convergence',
    thresholdSessionId: 'threshold-finalize-convergence',
    signerSlot: 1,
    signingWorkerId: SIGNING_WORKER_ID,
    participantIds: [1, 2],
    runtimePolicyScope: {
      ...TEST_SCOPE,
      signingRootVersion: 'root-finalize-v1',
    },
    seed: 93,
  });
  if (capability.capability.version !== 'wallet_ed25519_yao_registration_capability_v1') {
    throw new Error('Finalize fixture must build a registration capability');
  }
  const admissionRequest = capability.capability.admissionRequest;
  const activationResult = capability.capability.activationResult;
  const admissionReceipt = buildAdmissionReceipt(activationResult);
  const executeRequest = buildExecuteRequest(admissionReceipt);
  const state = createRouterAbEd25519YaoProductRegistrationStateV1();
  const backend = new FinalizeYaoBackend(admissionReceipt, activationResult);
  const registration = new InMemoryRouterAbEd25519YaoRegistrationService(
    backend,
    state.registration,
  );
  const admitted = await registration.admit(admissionRequest);
  if (!admitted.ok) throw new Error(admitted.message);
  const executed = await registration.execute(executeRequest);
  if (!executed.ok) throw new Error(executed.message);
  const composition = createRouterAbEd25519YaoProductRegistrationStatefulCompositionV1({
    signingWorkerId: SIGNING_WORKER_ID,
    backend,
    session: new StaticWalletSessionAdapter(),
    webAuthn: {
      async verifyWebAuthnAuthenticationLite(): Promise<never> {
        throw new Error('WebAuthn export is outside the finalize convergence fixture');
      },
    },
    state,
    capabilityPersistence: new AppliedCapabilityPersistence(),
  });
  return {
    runtime: new FailureInjectingYaoRuntime(composition.runtime),
    admissionRequest,
    activationResult,
  };
}

function createSigningRuntimeBundle(normalSigning: FailureInjectingNormalSigningRuntime) {
  const base = createRouterAbSigningRuntimes({
    authService: {
      async getRelayerAccount() {
        return { accountId: 'relayer.finalize.testnet', publicKey: 'ed25519:relayer-public-key' };
      },
    },
    thresholdStore: {
      kind: 'in-memory',
      ROUTER_AB_NORMAL_SIGNING_WORKER_ID: SIGNING_WORKER_ID,
      ROUTER_AB_SIGNING_WORKER_URL: 'https://signing-worker.finalize.invalid',
      ROUTER_AB_INTERNAL_SERVICE_AUTH_SECRET: 'finalize-internal-secret',
    },
    isNode: true,
  });
  return {
    normalSigning,
    localSigningSeed: base.localSigningSeed,
    ecdsaPresign: base.ecdsaPresign,
  };
}

export type FinalizeConvergenceHarness = {
  readonly service: CloudflareD1RouterApiAuthService;
  readonly request: WalletRegistrationFinalizeRequest;
  readonly database: D1DatabaseLike;
  readonly cleanup: () => void;
  readonly arm: (fault: FinalizeConvergenceFault) => void;
  readonly expireFinalizeClaim: () => Promise<void>;
  readonly countRows: (table: string) => Promise<number>;
};

export function buildMismatchedFinalizeConvergenceRequest(
  request: WalletRegistrationFinalizeRequest,
): WalletRegistrationFinalizeRequest {
  if (request.kind !== 'near_ed25519') {
    throw new Error('Finalize convergence fixture requires the near_ed25519 branch');
  }
  return {
    registrationCeremonyId: request.registrationCeremonyId,
    idempotencyKey: request.idempotencyKey,
    kind: 'near_ed25519',
    ed25519: {
      activationReference: {
        ...request.ed25519.activationReference,
        lifecycle_id: 'registration-lifecycle-mismatch',
      },
    },
  };
}

export async function createFinalizeConvergenceHarness(): Promise<FinalizeConvergenceHarness> {
  const temporary = createTemporaryD1Database();
  await applySignerMigrations(temporary.database);
  const database = new ResponseLossD1Database(temporary.database);
  const durableObjects = new FinalizeCeremonyDurableObjectNamespace();
  const yao = await activatedRuntimeFixture();
  const normalSigning = new FailureInjectingNormalSigningRuntime();
  const thresholdStore = {
    kind: 'cloudflare-do' as const,
    namespace: durableObjects,
    THRESHOLD_PREFIX,
  };
  const service = createCloudflareD1RouterApiAuthService({
    database,
    ...TEST_SCOPE,
    thresholdStore,
    routerAbSigningRuntimes: createSigningRuntimeBundle(normalSigning),
    ed25519YaoProductRegistration: yao.runtime,
    ecdsaStrictRegistration: new UnusedEcdsaStrictRegistration(),
  });
  const ceremonyStore = new CloudflareD1RegistrationCeremonyIntentStore({
    namespace: durableObjects,
    objectName: 'threshold-store',
    prefix: REGISTRATION_STORE_PREFIX,
  });
  const walletId = walletIdFromString(yao.admissionRequest.application_binding.wallet_id);
  await ceremonyStore.putCeremony(
    buildCeremony({
      walletId,
      admissionRequest: yao.admissionRequest,
    }),
  );
  const request: WalletRegistrationFinalizeRequest = {
    kind: 'near_ed25519',
    registrationCeremonyId: REGISTRATION_CEREMONY_ID,
    idempotencyKey: IDEMPOTENCY_KEY,
    ed25519: {
      activationReference: {
        kind: 'router_ab_ed25519_yao_activation_reference_v1',
        lifecycle_id: yao.admissionRequest.scope.lifecycle_id,
        session_id: yao.activationResult.binding.session_id,
      },
    },
  };
  return {
    service,
    request,
    database,
    cleanup: () => cleanupTemporaryD1Database(temporary.tempDir),
    expireFinalizeClaim: async () => {
      await database
        .prepare(
          `UPDATE router_ab_yao_versioned_json_records
             SET record_json = json_set(record_json, '$.claimedAtMs', 0)
           WHERE record_key LIKE '%wallet-registration-finalize:%'
             AND json_extract(record_json, '$.kind') =
               'router_ab_ed25519_yao_registration_side_effect_claim_v1'`,
        )
        .run();
    },
    arm: (fault) => {
      switch (fault) {
        case 'activation_consume_response_loss':
        case 'session_mint_response_loss':
        case 'capability_install_response_loss':
          yao.runtime.arm(fault);
          return;
        case 'normal_signing_response_loss':
          normalSigning.armProvisionResponseLoss();
          return;
        case 'wallet_commit_response_loss':
          database.armBatchResponseLoss();
          return;
        case 'finalize_replay_response_loss':
          durableObjects.stub.armSetResponseLoss(
            `${REGISTRATION_STORE_PREFIX}finalize-replay:${REGISTRATION_CEREMONY_ID}:${IDEMPOTENCY_KEY}`,
          );
          return;
        case 'ceremony_delete_response_loss':
          durableObjects.stub.armDeleteResponseLoss(
            `${REGISTRATION_STORE_PREFIX}ceremony:${REGISTRATION_CEREMONY_ID}`,
          );
          return;
        case 'finalize_claim_response_loss':
          database.armFinalizeClaimResponseLoss();
          return;
        case 'finalize_completion_response_loss':
          database.armFinalizeCompletionResponseLoss();
          return;
      }
    },
    countRows: async (table) => {
      const row = await database.prepare(`SELECT COUNT(*) AS count FROM ${table}`).first<{
        readonly count?: unknown;
      }>();
      return Number(row?.count || 0);
    },
  };
}
