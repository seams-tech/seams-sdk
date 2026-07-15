import { expect, test } from '@playwright/test';
import { readFileSync } from 'node:fs';
import type { SigningRootKekProvider } from '../../packages/sdk-server-ts/src/core/ThresholdService/signingRootKekProvider';
import type {
  CloudflareDurableObjectNamespaceLike,
  CloudflareDurableObjectStubLike,
} from '../../packages/sdk-server-ts/src/core/types';
import type { RouterAbNormalSigningAdmissionInput } from '../../packages/sdk-server-ts/src/router/routerAbPrivateSigningWorker';
import {
  buildRouterAbEcdsaHssNormalSigningStateForBootstrap,
  signRouterAbEcdsaHssWalletSessionJwt,
} from '../../packages/sdk-server-ts/src/router/commonRouterUtils';
import {
  createCloudflareD1ConsoleOnlyServiceBundle,
  createCloudflareD1ConsoleServiceBundle,
} from '../../packages/console-server-ts/src/router/cloudflare/d1ConsoleServices';
import { createCloudflareD1RouterApiAuthService } from '../../packages/sdk-server-ts/src/router/cloudflare/d1RouterApiAuthService';
import { createHmacSessionAdapter } from '../../packages/console-server-ts/src/router/cloudflare/d1StagingSession';
import { ThresholdStoreDurableObject } from '../../packages/sdk-server-ts/src/router/cloudflare/durableObjects/thresholdStore';
import type {
  D1DatabaseLike,
  D1PreparedStatementLike,
  D1ResultLike,
} from '../../packages/sdk-server-ts/src/storage/tenantRoute';
import type { CfExecutionContext } from '../../packages/sdk-server-ts/src/router/cloudflare/cloudflare.types';
import localD1DevWorker from '../../packages/console-server-ts/src/router/cloudflare/d1LocalDevWorker';
import { parseEcdsaHssClientBootstrapRequest } from '../../packages/sdk-server-ts/src/core/ThresholdService/validation';
import type { SponsoredEvmCallExecutorConfig } from '../../packages/console-server-ts/src/sponsorship/evmExecutorTypes';
import {
  computeEcdsaHssRoleLocalRelayerKeyId,
  computeEcdsaHssRoleLocalThresholdKeyId,
} from '../../packages/shared-ts/src/threshold/ecdsaHssRoleLocalBootstrap';
import { deriveEvmFamilySigningKeySlotId } from '../../packages/shared-ts/src/signing-lanes';
import { parseWebAuthnRpId } from '../../packages/shared-ts/src/utils/domainIds';
import {
  ROUTER_AB_ECDSA_HSS_PRESIGNATURE_POOL_FILL_INIT_PATH,
  ROUTER_AB_ECDSA_HSS_PRESIGNATURE_POOL_FILL_STEP_PATH,
  type RouterAbEcdsaHssNormalSigningScopeV1,
} from '../../packages/shared-ts/src/utils/routerAbEcdsaHss';
import {
  parseRouterAbPublicKeysetV2,
  ROUTER_AB_PUBLIC_KEYSET_VERSION_V2,
  type RouterAbPublicKeysetV2,
} from '../../packages/shared-ts/src/utils/routerAbPublicKeyset';
import { initSync as initEcdsaClientSignerWasmSync } from '../../wasm/ecdsa_client_signer/pkg/ecdsa_client_signer.js';
import { prepareResolvedEmailOtpRootEcdsaClientBootstrapForTest } from '../helpers/thresholdEcdsaClientBootstrap';
import { createFixtureSigningRootShareResolverForUnitTests } from '../helpers/thresholdServiceTestUtils';
import {
  applyD1MigrationFiles,
  cleanupTemporaryD1Database,
  createTemporaryD1Database,
  listD1MigrationFiles,
} from '../helpers/sqliteD1';

type LocalD1WorkflowEnv = Parameters<typeof localD1DevWorker.fetch>[1];
type JsonRecord = Record<string, unknown>;

const LOCAL_D1_WORKFLOW_NAMESPACE = 'seams-local-workflow-smoke';
const LOCAL_D1_WORKFLOW_ORG_ID = 'org-local-workflow';
const LOCAL_D1_WORKFLOW_PROJECT_ID = 'project-local-workflow';
const LOCAL_D1_WORKFLOW_ENV_ID = 'env-local-workflow';
const LOCAL_D1_WORKFLOW_SIGNING_ROOT_VERSION = 'root-v1';
const LOCAL_D1_WORKFLOW_SIGNING_ROOT_ID = `${LOCAL_D1_WORKFLOW_PROJECT_ID}:${LOCAL_D1_WORKFLOW_ENV_ID}`;
const LOCAL_D1_WORKFLOW_SIGNING_WORKER_ID = 'signing-worker.local';
const LOCAL_POOL_FILL_SESSION_SECRET = 'local-pool-fill-session-secret-for-d1-do-smoke';
const LOCAL_POOL_FILL_SESSION_ISSUER = 'local-pool-fill-issuer';
const LOCAL_POOL_FILL_SESSION_AUDIENCE = 'local-pool-fill-audience';
const ECDSA_CLIENT_SIGNER_WASM_URL = new URL(
  '../../wasm/ecdsa_client_signer/pkg/ecdsa_client_signer_bg.wasm',
  import.meta.url,
);

let ecdsaClientSignerWasmInitialized = false;

class FakeD1PreparedStatement implements D1PreparedStatementLike {
  constructor(private readonly query: string) {}

  bind(): D1PreparedStatementLike {
    return this;
  }

  async first<T = unknown>(): Promise<T | null> {
    return firstFakeD1Row<T>(this.query);
  }

  async all<T = unknown>(): Promise<D1ResultLike<T>> {
    return {
      success: true,
      results: [] as readonly T[],
    };
  }

  async run<T = unknown>(): Promise<D1ResultLike<T>> {
    return {
      success: true,
      results: [] as readonly T[],
      meta: { changes: 0, rows_written: 0 },
    };
  }
}

class FakeD1Database implements D1DatabaseLike {
  readonly queries: string[] = [];

  prepare(query: string): D1PreparedStatementLike {
    this.queries.push(query);
    return new FakeD1PreparedStatement(query);
  }

  async batch<T = unknown>(): Promise<readonly T[]> {
    return [];
  }

  async exec(): Promise<unknown> {
    return null;
  }
}

type TestDurableObjectStorageLike = {
  get(key: string): Promise<unknown>;
  put(key: string, value: unknown, opts?: { expirationTtl?: number }): Promise<void>;
  delete(key: string): Promise<boolean>;
  transaction<T>(fn: (txn: TestDurableObjectStorageLike) => Promise<T>): Promise<T>;
};

class MemoryDurableObjectStorage implements TestDurableObjectStorageLike {
  private readonly values = new Map<string, unknown>();
  private transactionTail: Promise<void> = Promise.resolve();

  async get(key: string): Promise<unknown> {
    return this.values.get(key) ?? null;
  }

  async put(key: string, value: unknown): Promise<void> {
    this.values.set(key, value);
  }

  async delete(key: string): Promise<boolean> {
    return this.values.delete(key);
  }

  async transaction<T>(fn: (txn: TestDurableObjectStorageLike) => Promise<T>): Promise<T> {
    const run = runSerializedStorageTransaction(this.transactionTail, this, fn);
    this.transactionTail = settleStorageTransaction(run);
    return await run;
  }
}

class MemoryDurableObjectStub implements CloudflareDurableObjectStubLike {
  private readonly durableObject: ThresholdStoreDurableObject;

  constructor() {
    this.durableObject = new ThresholdStoreDurableObject(
      { storage: new MemoryDurableObjectStorage() },
      {},
    );
  }

  fetch(request: RequestInfo, init?: RequestInit): Promise<Response> {
    return this.durableObject.fetch(
      request instanceof Request ? request : new Request(request, init),
    );
  }
}

class MemoryDurableObjectNamespace implements CloudflareDurableObjectNamespaceLike {
  private readonly objects = new Map<string, CloudflareDurableObjectStubLike>();

  idFromName(name: string): string {
    return name;
  }

  get(id: unknown): CloudflareDurableObjectStubLike {
    const key = String(id);
    const existing = this.objects.get(key);
    if (existing) return existing;
    const stub = new MemoryDurableObjectStub();
    this.objects.set(key, stub);
    return stub;
  }
}

function createSponsoredEvmCallExecutorConfig(): SponsoredEvmCallExecutorConfig {
  return {
    executorsByChain: new Map([
      [
        42_431,
        {
          chainId: 42_431,
          rpcUrl: 'https://rpc.example.test',
          sponsorAddress: '0x2222222222222222222222222222222222222222',
          sponsorPrivateKeyHex:
            '0x1111111111111111111111111111111111111111111111111111111111111111',
          maxPriorityFeePerGasFloor: 2_000_000_000n,
          maxFeePerGasFloor: 40_000_000_000n,
        },
      ],
    ]),
  };
}

function createLocalSponsoredEvmExecutorsJson(): string {
  return JSON.stringify({
    '42431': {
      sponsorPrivateKeyHex: '0x1111111111111111111111111111111111111111111111111111111111111111',
      rpcUrl: 'https://rpc.example.test',
    },
  });
}

async function runSerializedStorageTransaction<T>(
  previous: Promise<void>,
  storage: TestDurableObjectStorageLike,
  fn: (txn: TestDurableObjectStorageLike) => Promise<T>,
): Promise<T> {
  await previous;
  return await fn(storage);
}

function settleStorageTransaction<T>(promise: Promise<T>): Promise<void> {
  return promise.then(noop, noop);
}

function noop(): void {}

function firstFakeD1Row<T>(query: string): T | null {
  if (query.includes('sqlite_master') && query.includes('runtime_snapshot_outbox')) {
    return { table_count: 41 } as T;
  }
  if (query.includes('sqlite_master') && query.includes('email_otp_registration_attempts')) {
    return { table_count: 21 } as T;
  }
  return null;
}

function createFakeExecutionContext(): CfExecutionContext {
  return {
    waitUntil,
    passThroughOnException,
  };
}

function waitUntil(_promise: Promise<unknown>): void {}

function passThroughOnException(): void {}

function webAuthnRpId(value: string) {
  const parsed = parseWebAuthnRpId(value);
  if (!parsed.ok) {
    throw new Error(parsed.error.message);
  }
  return parsed.value;
}

function createKekProvider(): SigningRootKekProvider {
  return {
    kind: 'worker_secret',
    workerSecretsByKekId: {
      'signing-root-kek-test-r1': 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
    },
    encoding: 'base64url',
  };
}

function createAdmissionInput(): RouterAbNormalSigningAdmissionInput {
  return {
    curve: 'ed25519',
    phase: 'prepare',
    walletId: 'alice.testnet',
    authorityScope: {
      kind: 'passkey_rp',
      rpId: webAuthnRpId('example.localhost'),
    },
    thresholdSessionId: 'threshold-session-1',
    signingGrantId: 'signing-grant-1',
    requestId: 'request-1',
    expiresAtMs: Date.now() + 60_000,
    signingWorkerId: 'signing-worker-a',
    runtimePolicyScope: {
      orgId: 'org_1',
      projectId: 'project_1',
      envId: 'env_1',
      signingRootVersion: 'root-v1',
    },
  };
}

function createLocalD1WorkflowEnv(input: {
  readonly consoleDatabase: D1DatabaseLike;
  readonly signerDatabase: D1DatabaseLike;
}): LocalD1WorkflowEnv {
  return {
    CONSOLE_DB: input.consoleDatabase,
    SIGNER_DB: input.signerDatabase,
    THRESHOLD_STORE: new MemoryDurableObjectNamespace(),
    SEAMS_TENANT_STORAGE_NAMESPACE: 'seams-local-workflow-smoke',
    SEAMS_LOCAL_CONSOLE_USER_ID: 'local-workflow-user',
    SEAMS_LOCAL_CONSOLE_ORG_ID: 'org-local-workflow',
    SEAMS_LOCAL_CONSOLE_PROJECT_ID: 'project-local-workflow',
    SEAMS_LOCAL_CONSOLE_ENVIRONMENT_ID: 'env-local-workflow',
    SEAMS_LOCAL_CONSOLE_ROLES:
      'owner,admin,platform_admin,billing_admin,ops,developer,security_admin',
    ROUTER_AB_NORMAL_SIGNING_WORKER_ID: 'signing-worker.local',
    DERIVER_A_ENVELOPE_HPKE_KEY_EPOCH: 'epoch-1',
    DERIVER_A_ENVELOPE_HPKE_PUBLIC_KEY:
      'x25519:1111111111111111111111111111111111111111111111111111111111111111',
    DERIVER_B_ENVELOPE_HPKE_KEY_EPOCH: 'epoch-1',
    DERIVER_B_ENVELOPE_HPKE_PUBLIC_KEY:
      'x25519:2222222222222222222222222222222222222222222222222222222222222222',
    DERIVER_A_PEER_VERIFYING_KEY_HEX:
      '5afa80b305e72e02615ed1f580144a40a42a71dfcac175809ceb5d79e740d015',
    DERIVER_B_PEER_VERIFYING_KEY_HEX:
      '0c700dd63695221e508f3164b528f190bed63a4437d38e882308f9a57acc1bc3',
    SIGNING_WORKER_SERVER_OUTPUT_HPKE_KEY_EPOCH: 'epoch-1',
    SIGNING_WORKER_SERVER_OUTPUT_HPKE_PUBLIC_KEY:
      'x25519:3333333333333333333333333333333333333333333333333333333333333333',
    ACCOUNT_ID_DERIVATION_SECRET: 'local-workflow-account-id-derivation-secret',
  };
}

function createLocalWorkflowRequest(input: {
  readonly method: 'GET' | 'POST';
  readonly path: string;
  readonly body?: JsonRecord;
  readonly headers?: HeadersInit;
}): Request {
  const headers = new Headers(input.headers);
  let body: string | undefined;
  if (input.body) {
    body = JSON.stringify(input.body);
    if (!headers.has('content-type')) headers.set('content-type', 'application/json');
  }
  return new Request(`http://127.0.0.1:8787${input.path}`, {
    method: input.method,
    headers,
    body,
  });
}

async function callLocalWorkflowWorker(
  env: LocalD1WorkflowEnv,
  input: {
    readonly method: 'GET' | 'POST';
    readonly path: string;
    readonly body?: JsonRecord;
    readonly headers?: HeadersInit;
  },
): Promise<Response> {
  return await localD1DevWorker.fetch(
    createLocalWorkflowRequest(input),
    env,
    createFakeExecutionContext(),
  );
}

async function readJsonRecord(response: Response): Promise<JsonRecord> {
  const parsed: unknown = await response.json();
  if (!isJsonRecord(parsed)) {
    throw new Error(`Expected JSON object response, got ${typeof parsed}`);
  }
  return parsed;
}

function jsonRecordField(record: JsonRecord, key: string): JsonRecord {
  const value = record[key];
  if (!isJsonRecord(value)) {
    throw new Error(`Expected JSON object field ${key}`);
  }
  return value;
}

function jsonArrayField(record: JsonRecord, key: string): readonly unknown[] {
  const value = record[key];
  if (!Array.isArray(value)) {
    throw new Error(`Expected JSON array field ${key}`);
  }
  return value;
}

function jsonRecordAt(items: readonly unknown[], index: number): JsonRecord {
  const value = items[index];
  if (!isJsonRecord(value)) {
    throw new Error(`Expected JSON object at array index ${index}`);
  }
  return value;
}

function booleanField(record: JsonRecord, key: string): boolean {
  const value = record[key];
  if (typeof value !== 'boolean') {
    throw new Error(`Expected boolean field ${key}`);
  }
  return value;
}

function numberField(record: JsonRecord, key: string): number {
  const value = Number(record[key]);
  if (!Number.isFinite(value)) {
    throw new Error(`Expected finite numeric field ${key}`);
  }
  return value;
}

function stringField(record: JsonRecord, key: string): string {
  const value = record[key];
  if (typeof value !== 'string') {
    throw new Error(`Expected string field ${key}`);
  }
  return value;
}

function isJsonRecord(value: unknown): value is JsonRecord {
  return Boolean(value && typeof value === 'object' && !Array.isArray(value));
}

function ensureHssClientSignerWasm(): void {
  if (ecdsaClientSignerWasmInitialized) return;
  initEcdsaClientSignerWasmSync({ module: readFileSync(ECDSA_CLIENT_SIGNER_WASM_URL) });
  ecdsaClientSignerWasmInitialized = true;
}

function rootShare32B64u(byte: number): string {
  const bytes = Buffer.alloc(32, 0);
  bytes[31] = byte;
  return bytes.toString('base64url');
}

function createLocalPoolFillWorkflowEnv(input: {
  readonly consoleDatabase: D1DatabaseLike;
  readonly signerDatabase: D1DatabaseLike;
}): LocalD1WorkflowEnv {
  return {
    ...createLocalD1WorkflowEnv(input),
    RELAY_SESSION_HMAC_SECRET: LOCAL_POOL_FILL_SESSION_SECRET,
    RELAY_SESSION_ISSUER: LOCAL_POOL_FILL_SESSION_ISSUER,
    RELAY_SESSION_AUDIENCE: LOCAL_POOL_FILL_SESSION_AUDIENCE,
  };
}

function createLocalPoolFillRouterAbPublicKeyset(): RouterAbPublicKeysetV2 {
  return parseRouterAbPublicKeysetV2({
    keyset_version: ROUTER_AB_PUBLIC_KEYSET_VERSION_V2,
    signer_envelope_hpke: {
      current: {
        deriver_a: {
          role: 'signer_a',
          key_epoch: 'epoch-1',
          public_key: `x25519:${'11'.repeat(32)}`,
        },
        deriver_b: {
          role: 'signer_b',
          key_epoch: 'epoch-1',
          public_key: `x25519:${'22'.repeat(32)}`,
        },
      },
    },
    signer_peer_verifying_keys: {
      deriver_a: {
        role: 'signer_a',
        verifying_key_hex: '5afa80b305e72e02615ed1f580144a40a42a71dfcac175809ceb5d79e740d015',
      },
      deriver_b: {
        role: 'signer_b',
        verifying_key_hex: '0c700dd63695221e508f3164b528f190bed63a4437d38e882308f9a57acc1bc3',
      },
    },
    signing_worker_server_output_hpke: {
      key_epoch: 'epoch-1',
      public_key: `x25519:${'33'.repeat(32)}`,
    },
  });
}

function createLocalPoolFillAuthService(input: {
  readonly env: LocalD1WorkflowEnv;
  readonly signerDatabase: D1DatabaseLike;
}) {
  return createCloudflareD1RouterApiAuthService({
    database: input.signerDatabase,
    namespace: LOCAL_D1_WORKFLOW_NAMESPACE,
    orgId: LOCAL_D1_WORKFLOW_ORG_ID,
    projectId: LOCAL_D1_WORKFLOW_PROJECT_ID,
    envId: LOCAL_D1_WORKFLOW_ENV_ID,
    relayerAccount: 'local-pool-fill-relayer.testnet',
    relayerPublicKey: 'local-pool-fill-relayer-public-key',
    thresholdStore: {
      kind: 'cloudflare-do',
      namespace: input.env.THRESHOLD_STORE,
      THRESHOLD_PREFIX: LOCAL_D1_WORKFLOW_NAMESPACE,
      ROUTER_AB_NORMAL_SIGNING_WORKER_ID: LOCAL_D1_WORKFLOW_SIGNING_WORKER_ID,
      signingRootShareResolver: createFixtureSigningRootShareResolverForUnitTests(),
    },
  });
}

async function bootstrapLocalPoolFillEcdsaSession(input: {
  readonly env: LocalD1WorkflowEnv;
  readonly signerDatabase: D1DatabaseLike;
}): Promise<{
  readonly jwt: string;
  readonly keyHandle: string;
  readonly scope: RouterAbEcdsaHssNormalSigningScopeV1;
}> {
  ensureHssClientSignerWasm();
  const walletId = 'local-pool-fill-wallet';
  const evmFamilySigningKeySlotId = deriveEvmFamilySigningKeySlotId({
    walletId,
    signingRootId: LOCAL_D1_WORKFLOW_SIGNING_ROOT_ID,
    signingRootVersion: LOCAL_D1_WORKFLOW_SIGNING_ROOT_VERSION,
  });
  const ecdsaThresholdKeyId = await computeEcdsaHssRoleLocalThresholdKeyId({
    walletId,
    evmFamilySigningKeySlotId,
    signingRootId: LOCAL_D1_WORKFLOW_SIGNING_ROOT_ID,
    signingRootVersion: LOCAL_D1_WORKFLOW_SIGNING_ROOT_VERSION,
  });
  const relayerKeyId = await computeEcdsaHssRoleLocalRelayerKeyId({
    walletId,
    evmFamilySigningKeySlotId,
  });
  const preparedClient = prepareResolvedEmailOtpRootEcdsaClientBootstrapForTest({
    context: {
      walletId,
      ecdsaThresholdKeyId,
      signingRootId: LOCAL_D1_WORKFLOW_SIGNING_ROOT_ID,
      signingRootVersion: LOCAL_D1_WORKFLOW_SIGNING_ROOT_VERSION,
    },
    clientRootShare32B64u: rootShare32B64u(71),
  });
  const bootstrapRequest = parseEcdsaHssClientBootstrapRequest({
    formatVersion: 'ecdsa-hss-role-local',
    walletId,
    evmFamilySigningKeySlotId,
    ecdsaThresholdKeyId,
    signingRootId: LOCAL_D1_WORKFLOW_SIGNING_ROOT_ID,
    signingRootVersion: LOCAL_D1_WORKFLOW_SIGNING_ROOT_VERSION,
    keyScope: 'evm-family',
    relayerKeyId,
    hssClientSharePublicKey33B64u: preparedClient.hssClientSharePublicKey33B64u,
    clientShareRetryCounter: preparedClient.clientShareRetryCounter,
    contextBinding32B64u: preparedClient.contextBinding32B64u,
    requestId: 'local-pool-fill-bootstrap-request',
    sessionId: 'tehss-local-pool-fill',
    signingGrantId: 'wss-local-pool-fill',
    ttlMs: 60_000,
    remainingUses: 3,
    participantIds: [1, 2],
  });
  if (!bootstrapRequest) {
    throw new Error('Local ECDSA-HSS pool-fill bootstrap request did not parse');
  }

  const service = createLocalPoolFillAuthService(input);
  const runtime = service.thresholdRuntime.getRouterAbEcdsaBootstrapExportRuntime();
  if (!runtime) {
    throw new Error('Local ECDSA-HSS bootstrap/export runtime is not configured');
  }
  const bootstrap = await runtime.ecdsaHssRoleLocalBootstrap(bootstrapRequest);
  expect(bootstrap, JSON.stringify(bootstrap)).toMatchObject({ ok: true });
  if (!bootstrap.ok) throw new Error(bootstrap.message);

  const normalSigning = buildRouterAbEcdsaHssNormalSigningStateForBootstrap({
    bootstrap: bootstrap.value,
    routerAbPublicKeyset: createLocalPoolFillRouterAbPublicKeyset(),
    signingWorkerId: LOCAL_D1_WORKFLOW_SIGNING_WORKER_ID,
  });
  expect(normalSigning, JSON.stringify(normalSigning)).toMatchObject({ ok: true });
  if (!normalSigning.ok) throw new Error(normalSigning.message);

  const session = createHmacSessionAdapter({
    secret: LOCAL_POOL_FILL_SESSION_SECRET,
    issuer: LOCAL_POOL_FILL_SESSION_ISSUER,
    audience: LOCAL_POOL_FILL_SESSION_AUDIENCE,
  });
  const signed = await signRouterAbEcdsaHssWalletSessionJwt({
    session,
    userId: walletId,
    evmFamilySigningKeySlotId,
    relayerKeyId,
    sessionInfo: {
      sessionKind: 'jwt',
      thresholdSessionId: bootstrap.value.thresholdSessionId,
      signingGrantId: bootstrap.value.signingGrantId,
      expiresAtMs: bootstrap.value.expiresAtMs,
      participantIds: bootstrap.value.participantIds,
      runtimePolicyScope: {
        orgId: LOCAL_D1_WORKFLOW_ORG_ID,
        projectId: LOCAL_D1_WORKFLOW_PROJECT_ID,
        envId: LOCAL_D1_WORKFLOW_ENV_ID,
        signingRootVersion: LOCAL_D1_WORKFLOW_SIGNING_ROOT_VERSION,
      },
      keyHandle: bootstrap.value.keyHandle,
      stableKeyContext: {
        walletId,
        evmFamilySigningKeySlotId,
        keyScope: 'evm-family',
        ecdsaThresholdKeyId,
        signingRootId: LOCAL_D1_WORKFLOW_SIGNING_ROOT_ID,
        signingRootVersion: LOCAL_D1_WORKFLOW_SIGNING_ROOT_VERSION,
        applicationBindingDigestB64u: bootstrap.value.applicationBindingDigestB64u,
        contextBinding32B64u: bootstrap.value.contextBinding32B64u,
      },
      publicIdentity: bootstrap.value.publicIdentity,
      activationEpoch: bootstrap.value.thresholdSessionId,
      signingWorkerId: LOCAL_D1_WORKFLOW_SIGNING_WORKER_ID,
      routerAbEcdsaHssNormalSigning: normalSigning.state,
    },
    fallbackParticipantIds: bootstrap.value.participantIds,
    requireJwtErrorMessage: 'threshold_ecdsa.session_kind must be jwt',
    invalidPayloadErrorMessage: 'invalid local ECDSA-HSS pool-fill Wallet Session payload',
  });
  expect(signed, JSON.stringify(signed)).toMatchObject({ ok: true });
  if (!signed.ok) throw new Error(signed.message);

  return {
    jwt: signed.jwt,
    keyHandle: bootstrap.value.keyHandle,
    scope: normalSigning.state.scope,
  };
}

async function runLocalPoolFillRouteSmoke(input: {
  readonly env: LocalD1WorkflowEnv;
  readonly jwt: string;
  readonly keyHandle: string;
  readonly scope: RouterAbEcdsaHssNormalSigningScopeV1;
  readonly requestTag: string;
}): Promise<void> {
  const authHeaders = { authorization: `Bearer ${input.jwt}` };
  const initResponse = await callLocalWorkflowWorker(input.env, {
    method: 'POST',
    path: ROUTER_AB_ECDSA_HSS_PRESIGNATURE_POOL_FILL_INIT_PATH,
    headers: authHeaders,
    body: {
      sessionKind: 'jwt',
      keyHandle: input.keyHandle,
      count: 1,
      requestTag: input.requestTag,
      poolFill: {
        kind: 'router_ab_ecdsa_hss_signing_worker_pool',
        scope: input.scope,
        expiresAtMs: Date.now() + 30_000,
      },
    },
  });
  const initBody = await readJsonRecord(initResponse);
  expect(initResponse.status, JSON.stringify(initBody)).toBe(200);
  expect(booleanField(initBody, 'ok'), JSON.stringify(initBody)).toBe(true);
  expect(['triples', 'triples_done']).toContain(stringField(initBody, 'stage'));
  const presignSessionId = stringField(initBody, 'presignSessionId');

  const freshHandlerEnv = {
    ...input.env,
    THRESHOLD_STORE: input.env.THRESHOLD_STORE,
  };
  const stepResponse = await callLocalWorkflowWorker(freshHandlerEnv, {
    method: 'POST',
    path: ROUTER_AB_ECDSA_HSS_PRESIGNATURE_POOL_FILL_STEP_PATH,
    headers: authHeaders,
    body: {
      sessionKind: 'jwt',
      presignSessionId,
      stage: 'triples',
      outgoingMessagesB64u: [],
      requestTag: input.requestTag,
    },
  });
  const stepBody = await readJsonRecord(stepResponse);
  expect(stepResponse.status, JSON.stringify(stepBody)).toBe(200);
  expect(booleanField(stepBody, 'ok'), JSON.stringify(stepBody)).toBe(true);
  expect(['triples', 'triples_done', 'presign', 'done']).toContain(stringField(stepBody, 'stage'));
}

test('Cloudflare D1 service bundle wires DO-backed normal-signing admission into relay options', async () => {
  const database = new FakeD1Database();
  const sponsorshipPricing = {
    async estimateSponsoredExecutionSpend() {
      return {
        spendMinor: 1,
        pricingVersion: 'test-pricing-v1',
      };
    },
    async finalizeSponsoredExecutionSpend() {
      return {
        spendMinor: 1,
        pricingVersion: 'test-pricing-v1',
      };
    },
  };
  const bundle = await createCloudflareD1ConsoleServiceBundle({
    bindings: {
      consoleDatabase: database,
      signerMetadataDatabase: database,
      thresholdStore: new MemoryDurableObjectNamespace(),
      kekProvider: createKekProvider(),
    },
    route: {
      namespace: 'seams',
    },
    adapters: {
      ensureSchema: false,
      sponsorshipPricing,
    },
  });

  const admission = bundle.routerApiRouterOptions.routerAbNormalSigningAdmission;
  const input = createAdmissionInput();

  await expect(admission.evaluate(input)).resolves.toEqual({ ok: true });
  await expect(admission.evaluate(input)).resolves.toEqual({ ok: true });
  expect(bundle.routerApiRouterOptions).not.toHaveProperty('signedDelegate');
  expect(bundle.routerApiRouterOptions).not.toHaveProperty('sponsorship');
  expect(bundle.routerApiRouterOptions).not.toHaveProperty('sponsoredEvmCall');
  expect(bundle.routerApiRouterOptions.bootstrapTokenVerifier).toBeTruthy();
  expect(bundle.routerApiRouterOptions.orgProjectEnv).toBe(bundle.orgProjectEnv);
  expect(bundle.routerApiRouterOptions).not.toHaveProperty('observabilityIngestion');
  expect(typeof bundle.routerApiRouterOptions.apiKeyAuth.authenticate).toBe('function');
  expect(typeof bundle.routerApiRouterOptions.publishableKeyAuth.authenticate).toBe('function');
  expect(typeof bundle.routerApiRouterOptions.apiKeyUsageMeter.recordEvent).toBe('function');
  expect(bundle.routerApiRouterOptions).not.toHaveProperty('wallets');
  expect(bundle.routerApiRouterOptions).not.toHaveProperty('bootstrapGrantBroker');
  expect(bundle.routerApiRouterOptions.routeExtensions.length).toBeGreaterThan(0);
  expect(
    bundle.routerApiRouterOptions.routeExtensions
      .flatMap((extension) => extension.routes)
      .some((route) => route.id === 'sponsored_evm_call'),
  ).toBe(false);
});

test('Cloudflare D1 console-only bundle omits signer custody bindings', async () => {
  const database = new FakeD1Database();
  const bundle = await createCloudflareD1ConsoleOnlyServiceBundle({
    bindings: {
      consoleDatabase: database,
    },
    route: {
      namespace: 'seams',
    },
    adapters: {
      ensureSchema: false,
    },
  });

  expect(bundle).not.toHaveProperty('tenantStorageRouteResolver');
  expect(bundle).not.toHaveProperty('routerApiRouterOptions');
  expect(bundle).not.toHaveProperty('bootstrapTokens');
  expect(bundle).not.toHaveProperty('spendCaps');
  expect(bundle.consoleRouterOptions).not.toHaveProperty('tenantStorageRouteResolver');
  expect(bundle.consoleRouterOptions).not.toHaveProperty('tenantStorageNamespace');
  expect(bundle.consoleRouterOptions.keyExports).toBe(bundle.keyExports);
  expect(bundle.consoleRouterOptions.billing).toBe(bundle.billing);
  expect(bundle.consoleRouterOptions.sponsoredCalls).toBe(bundle.sponsoredCalls);
});

test('D1 Router API storage options attach sponsored EVM route extension with executor config', async () => {
  const database = new FakeD1Database();
  const sponsoredEvmCallConfig = createSponsoredEvmCallExecutorConfig();
  const bundle = await createCloudflareD1ConsoleServiceBundle({
    bindings: {
      consoleDatabase: database,
      signerMetadataDatabase: database,
      thresholdStore: new MemoryDurableObjectNamespace(),
      kekProvider: createKekProvider(),
    },
    route: {
      namespace: 'seams',
    },
    adapters: {
      ensureSchema: false,
      sponsoredEvmCallConfig,
    },
  });

  const extensionRoutes = bundle.routerApiRouterOptions.routeExtensions.flatMap(
    (extension) => extension.routes,
  );
  const sponsoredRoute = extensionRoutes.find((route) => route.id === 'sponsored_evm_call');
  expect(bundle.routerApiRouterOptions).not.toHaveProperty('sponsoredEvmCall');
  expect(sponsoredRoute).toMatchObject({
    method: 'POST',
    path: '/sponsorships/evm/call',
    metering: { kind: 'gas', ledger: 'evm' },
    requiredServices: ['routerApiSponsoredEvmCall'],
  });
  expect(sponsoredEvmCallConfig.executorsByChain.size).toBe(1);
});

test('local D1 Worker ready smoke validates D1 tables and DO admission', async () => {
  const database = new FakeD1Database();
  const response = await localD1DevWorker.fetch(
    new Request('http://127.0.0.1:8787/readyz'),
    {
      CONSOLE_DB: database,
      SIGNER_DB: database,
      THRESHOLD_STORE: new MemoryDurableObjectNamespace(),
      SEAMS_TENANT_STORAGE_NAMESPACE: 'seams-local-test',
    },
    createFakeExecutionContext(),
  );

  expect(response.status).toBe(200);
  await expect(response.json()).resolves.toMatchObject({
    ok: true,
    backend: 'cloudflare_d1_do',
    namespace: 'seams-local-test',
    schemas: {
      consoleTables: 41,
      signerTables: 21,
    },
    admission: {
      durableObject: 'configured',
      quotaReservation: 'accepted',
    },
  });
});

test('local D1 Worker routes smoke requests through the Router API handler', async () => {
  const database = new FakeD1Database();
  const env = {
    CONSOLE_DB: database,
    SIGNER_DB: database,
    THRESHOLD_STORE: new MemoryDurableObjectNamespace(),
    SEAMS_TENANT_STORAGE_NAMESPACE: 'seams-local-test',
  };
  const ctx = createFakeExecutionContext();

  const health = await localD1DevWorker.fetch(
    new Request('http://127.0.0.1:8787/relay/healthz'),
    env,
    ctx,
  );
  expect(health.status).toBe(200);
  await expect(health.json()).resolves.toMatchObject({
    ok: true,
    thresholdEd25519: { configured: true },
    cors: {
      allowedOrigins: [
        'https://localhost',
        'https://localhost:8443',
        'https://localhost:9444',
        'http://127.0.0.1:9090',
        'http://localhost:9090',
        'http://127.0.0.1:8787',
        'http://localhost:8787',
      ],
    },
  });

  const emailRecovery = await localD1DevWorker.fetch(
    new Request('http://127.0.0.1:8787/relay/email-recovery/prepare', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: '{}',
    }),
    env,
    ctx,
  );
  expect(emailRecovery.status).toBe(400);
  await expect(emailRecovery.json()).resolves.toMatchObject({
    ok: false,
    code: 'invalid_body',
    message: 'account_id is required',
  });

  const sponsored = await localD1DevWorker.fetch(
    new Request('http://127.0.0.1:8787/relay/sponsorships/evm/call', {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        origin: 'http://127.0.0.1:8787',
      },
      body: JSON.stringify({
        environmentId: 'project_local:local',
        walletId: 'wallet_local_1',
        walletAddress: '0x1111111111111111111111111111111111111111',
        chainId: 1,
        call: {
          to: '0x2222222222222222222222222222222222222222',
          data: '0x12345678',
          gasLimit: '21000',
          value: '0',
        },
        idempotencyKey: 'intent_local_1',
      }),
    }),
    env,
    ctx,
  );
  expect(sponsored.status).toBe(404);

  const bootstrapGrant = await localD1DevWorker.fetch(
    new Request('http://127.0.0.1:8787/v1/registration/bootstrap-grants', {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        origin: 'https://localhost:8443',
      },
      body: JSON.stringify({
        environmentId: 'project_local:local',
        authority: { kind: 'passkey_rp', rpId: 'localhost' },
        flow: 'registration_v1',
      }),
    }),
    env,
    ctx,
  );
  expect(bootstrapGrant.status).toBe(401);
  await expect(bootstrapGrant.json()).resolves.toMatchObject({
    ok: false,
    code: 'publishable_key_missing',
  });

  const apiWallets = await localD1DevWorker.fetch(
    new Request('http://127.0.0.1:8787/v1/wallets', {
      method: 'GET',
    }),
    env,
    ctx,
  );
  expect(apiWallets.status).toBe(401);
  await expect(apiWallets.json()).resolves.toMatchObject({
    ok: false,
    code: 'secret_key_missing',
  });
});

test('local D1 Worker mounts the shared Ed25519 Yao product composition', async () => {
  const database = new FakeD1Database();
  const baseEnv = createLocalD1WorkflowEnv({
    consoleDatabase: database,
    signerDatabase: database,
  });
  const response = await callLocalWorkflowWorker(
    {
      ...baseEnv,
      DERIVER_A_URL: 'http://127.0.0.1:8811',
      DERIVER_B_URL: 'http://127.0.0.1:8812',
      SIGNING_WORKER_URL: 'http://127.0.0.1:8813',
      SIGNING_WORKER_ID: LOCAL_D1_WORKFLOW_SIGNING_WORKER_ID,
      ROUTER_AB_INTERNAL_SERVICE_AUTH_SECRET: 'local-yao-internal-auth',
      DERIVER_A_ED25519_YAO_INPUT_PUBLIC_KEY: `x25519:${'44'.repeat(32)}`,
      DERIVER_B_ED25519_YAO_INPUT_PUBLIC_KEY: `x25519:${'55'.repeat(32)}`,
    },
    {
      method: 'POST',
      path: '/relay/router-ab/ed25519/yao/registration/admit',
      body: {},
    },
  );

  expect(response.status).toBe(400);
  await expect(response.json()).resolves.toMatchObject({
    ok: false,
    code: 'invalid_body',
  });
});

test('local D1 Worker mounts direct sponsored EVM Router API route when local executor config is present', async () => {
  const database = new FakeD1Database();
  const response = await localD1DevWorker.fetch(
    new Request('http://127.0.0.1:8787/sponsorships/evm/call', {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        origin: 'http://127.0.0.1:8787',
      },
      body: JSON.stringify({
        environmentId: 'local',
        walletId: 'local.sponsored.testnet',
        walletAddress: '0x1111111111111111111111111111111111111111',
        chainId: 42_431,
        call: {
          to: '0x2222222222222222222222222222222222222222',
          data: '0x12345678',
          gasLimit: '21000',
          value: '0',
        },
        idempotencyKey: 'local-sponsored-route-mounted',
      }),
    }),
    {
      CONSOLE_DB: database,
      SIGNER_DB: database,
      THRESHOLD_STORE: new MemoryDurableObjectNamespace(),
      SEAMS_TENANT_STORAGE_NAMESPACE: 'seams-local-test',
      SPONSORED_EVM_EXECUTORS_JSON: createLocalSponsoredEvmExecutorsJson(),
    },
    createFakeExecutionContext(),
  );

  expect(response.status).toBe(401);
  await expect(response.json()).resolves.toMatchObject({
    ok: false,
    code: 'publishable_key_missing',
  });
});

test('local D1 Worker serves Router A/B public keyset from local Worker env', async () => {
  const database = new FakeD1Database();
  const env = createLocalD1WorkflowEnv({
    consoleDatabase: database,
    signerDatabase: database,
  });
  const response = await callLocalWorkflowWorker(env, {
    method: 'GET',
    path: '/router-ab/keyset',
  });

  expect(response.status).toBe(200);
  await expect(readJsonRecord(response)).resolves.toMatchObject({
    keyset_version: 'router_ab_keyset_v2',
    signer_envelope_hpke: {
      current: {
        deriver_a: {
          role: 'signer_a',
          key_epoch: 'epoch-1',
        },
        deriver_b: {
          role: 'signer_b',
          key_epoch: 'epoch-1',
        },
      },
    },
    signing_worker_server_output_hpke: {
      key_epoch: 'epoch-1',
    },
  });
});

test('local D1 Worker runs a representative signer smoke through relay prefix', async () => {
  const database = new FakeD1Database();
  const response = await localD1DevWorker.fetch(
    new Request('http://127.0.0.1:8787/relay/auth/passkey/options', {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        origin: 'http://127.0.0.1:8787',
      },
      body: JSON.stringify({
        user_id: 'alice.testnet',
        rp_id: 'localhost',
      }),
    }),
    {
      CONSOLE_DB: database,
      SIGNER_DB: database,
      THRESHOLD_STORE: new MemoryDurableObjectNamespace(),
      SEAMS_TENANT_STORAGE_NAMESPACE: 'seams-local-test',
    },
    createFakeExecutionContext(),
  );

  expect(response.status).toBe(200);
  await expect(response.json()).resolves.toMatchObject({
    ok: true,
  });
  expect(database.queries.some((query) => query.includes('INSERT INTO webauthn_challenges'))).toBe(
    true,
  );
});

test('local D1 Worker serves console routes through D1 console services', async () => {
  const database = new FakeD1Database();
  const response = await localD1DevWorker.fetch(
    new Request('http://127.0.0.1:8787/console/readyz', {
      headers: {
        'x-console-user-id': 'local-user',
        'x-console-org-id': 'local-org',
        'x-console-roles': 'owner,admin',
      },
    }),
    {
      CONSOLE_DB: database,
      SIGNER_DB: database,
      THRESHOLD_STORE: new MemoryDurableObjectNamespace(),
      SEAMS_TENANT_STORAGE_NAMESPACE: 'seams-local-test',
    },
    createFakeExecutionContext(),
  );

  expect(response.status).toBe(200);
  await expect(response.json()).resolves.toMatchObject({
    ok: true,
    service: 'console',
  });
});

test('local D1 Worker serves dashboard Google options at the root auth path', async () => {
  const database = new FakeD1Database();
  const response = await localD1DevWorker.fetch(
    new Request('http://127.0.0.1:9090/auth/google/options', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: '{}',
    }),
    {
      CONSOLE_DB: database,
      SIGNER_DB: database,
      THRESHOLD_STORE: new MemoryDurableObjectNamespace(),
      SEAMS_TENANT_STORAGE_NAMESPACE: 'seams-local-test',
      GOOGLE_OIDC_CLIENT_ID: 'local-google-client.apps.googleusercontent.com',
    },
    createFakeExecutionContext(),
  );

  expect(response.status).toBe(200);
  await expect(response.json()).resolves.toMatchObject({
    ok: true,
    configured: true,
    clientId: 'local-google-client.apps.googleusercontent.com',
  });
});

test('local D1 Worker routes dashboard session exchange and state at root paths', async () => {
  const database = new FakeD1Database();
  const env = {
    CONSOLE_DB: database,
    SIGNER_DB: database,
    THRESHOLD_STORE: new MemoryDurableObjectNamespace(),
    SEAMS_TENANT_STORAGE_NAMESPACE: 'seams-local-test',
    GOOGLE_OIDC_CLIENT_ID: 'local-google-client.apps.googleusercontent.com',
  };
  const ctx = createFakeExecutionContext();

  const exchange = await localD1DevWorker.fetch(
    new Request('http://127.0.0.1:9090/session/exchange', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        session_kind: 'cookie',
        exchange: {
          type: 'oidc_jwt',
          provider: 'google',
          token: 'not-a-jwt',
        },
      }),
    }),
    env,
    ctx,
  );
  expect(exchange.status).toBe(400);
  await expect(exchange.json()).resolves.toMatchObject({
    ok: false,
    code: 'invalid_body',
    message: 'id_token must be a JWT (3 segments)',
  });

  const state = await localD1DevWorker.fetch(
    new Request('http://127.0.0.1:9090/session/state'),
    env,
    ctx,
  );
  expect(state.status).toBe(200);
  await expect(state.json()).resolves.toMatchObject({
    authenticated: false,
    code: 'unauthorized',
  });
});

test('local D1 Worker serves dashboard onboarding state through D1 services', async () => {
  const consoleTemp = createTemporaryD1Database();
  const signerTemp = createTemporaryD1Database();

  try {
    await applyD1MigrationFiles(consoleTemp.database, listD1MigrationFiles('d1-console'));
    await applyD1MigrationFiles(signerTemp.database, listD1MigrationFiles('d1-signer'));
    const env = createLocalD1WorkflowEnv({
      consoleDatabase: consoleTemp.database,
      signerDatabase: signerTemp.database,
    });

    const response = await callLocalWorkflowWorker(env, {
      method: 'GET',
      path: '/console/onboarding/state',
    });

    expect(response.status).toBe(200);
    await expect(readJsonRecord(response)).resolves.toMatchObject({
      ok: true,
      state: {
        orgId: 'org-local-workflow',
        hasOrganization: false,
        hasProject: false,
        hasEnvironment: false,
        onboardingComplete: false,
        currentStep: 'organization',
      },
    });
  } finally {
    cleanupTemporaryD1Database(consoleTemp.tempDir);
    cleanupTemporaryD1Database(signerTemp.tempDir);
  }
});

test('local D1 publishable key creation publishes Tempo sponsorship runtime snapshot', async () => {
  test.setTimeout(60_000);
  const consoleTemp = createTemporaryD1Database();
  const signerTemp = createTemporaryD1Database();

  try {
    await applyD1MigrationFiles(consoleTemp.database, listD1MigrationFiles('d1-console'));
    await applyD1MigrationFiles(signerTemp.database, listD1MigrationFiles('d1-signer'));
    const env = {
      ...createLocalD1WorkflowEnv({
        consoleDatabase: consoleTemp.database,
        signerDatabase: signerTemp.database,
      }),
      SPONSORED_EVM_EXECUTORS_JSON: createLocalSponsoredEvmExecutorsJson(),
    };

    const organizationResponse = await callLocalWorkflowWorker(env, {
      method: 'POST',
      path: '/console/onboarding/organization',
      body: {
        org: { name: 'Tempo Snapshot Org', slug: 'tempo-snapshot-org' },
      },
    });
    expect(organizationResponse.status).toBe(201);

    const projectResponse = await callLocalWorkflowWorker(env, {
      method: 'POST',
      path: '/console/onboarding/project',
      body: {
        project: { id: 'proj_tempo_snapshot', name: 'Tempo Snapshot Project' },
        environment: { id: 'proj_tempo_snapshot-dev', name: 'Development' },
      },
    });
    expect(projectResponse.status).toBe(201);
    const projectResult = jsonRecordField(await readJsonRecord(projectResponse), 'result');
    const projectId = stringField(jsonRecordField(projectResult, 'project'), 'id');
    const environmentId = stringField(jsonRecordField(projectResult, 'environment'), 'id');

    const apiKeyResponse = await callLocalWorkflowWorker(env, {
      method: 'POST',
      path: '/console/api-keys',
      body: {
        kind: 'publishable_key',
        name: 'tempo-snapshot-browser',
        environmentId,
        allowedOrigins: ['https://localhost:8443'],
        rateLimitBucket: 'default_web_v1',
        quotaBucket: 'free_registrations_v1',
      },
    });
    expect(apiKeyResponse.status).toBe(201);

    const snapshotResponse = await callLocalWorkflowWorker(env, {
      method: 'GET',
      path: `/console/runtime-snapshots/latest?environmentId=${encodeURIComponent(
        environmentId,
      )}&projectId=${encodeURIComponent(projectId)}`,
    });
    expect(snapshotResponse.status).toBe(200);
    const snapshot = jsonRecordField(await readJsonRecord(snapshotResponse), 'snapshot');
    expect(stringField(snapshot, 'environmentId')).toBe(environmentId);
    expect(numberField(snapshot, 'version')).toBeGreaterThanOrEqual(1);
    const gasSponsorship = jsonRecordField(jsonRecordField(snapshot, 'payload'), 'gasSponsorship');
    expect(stringField(gasSponsorship, 'status')).toBe('resolved');
    const resolvedPolicies = jsonArrayField(gasSponsorship, 'resolvedPolicies');
    expect(resolvedPolicies).toHaveLength(1);
    const policy = jsonRecordAt(resolvedPolicies, 0);
    const pricingRow = await consoleTemp.database
      .prepare(
        `SELECT pricing_version
           FROM sponsorship_pricing_rules
          WHERE namespace = ?
            AND environment_id = ?
            AND policy_id = ?
            AND chain_id = ?
            AND status = 'active'`,
      )
      .bind('seams-local-workflow-smoke', environmentId, stringField(policy, 'policyId'), 42_431)
      .first<{ pricing_version?: string }>();
    expect(pricingRow?.pricing_version).toBe(
      `tempo-testnet-static-v1:${stringField(policy, 'policyId')}`,
    );
  } finally {
    cleanupTemporaryD1Database(consoleTemp.tempDir);
    cleanupTemporaryD1Database(signerTemp.tempDir);
  }
});

test('local D1 Worker runs dashboard, signer, billing, and reconciliation smoke on real D1', async () => {
  test.setTimeout(60_000);
  const consoleTemp = createTemporaryD1Database();
  const signerTemp = createTemporaryD1Database();

  try {
    await applyD1MigrationFiles(consoleTemp.database, listD1MigrationFiles('d1-console'));
    await applyD1MigrationFiles(signerTemp.database, listD1MigrationFiles('d1-signer'));
    const env = createLocalD1WorkflowEnv({
      consoleDatabase: consoleTemp.database,
      signerDatabase: signerTemp.database,
    });

    const readyResponse = await callLocalWorkflowWorker(env, {
      method: 'GET',
      path: '/readyz',
    });
    expect(readyResponse.status).toBe(200);
    await expect(readJsonRecord(readyResponse)).resolves.toMatchObject({
      ok: true,
      backend: 'cloudflare_d1_do',
      namespace: 'seams-local-workflow-smoke',
      schemas: {
        consoleTables: 41,
        signerTables: 21,
      },
      admission: {
        durableObject: 'configured',
        quotaReservation: 'accepted',
      },
    });

    const consoleReadyResponse = await callLocalWorkflowWorker(env, {
      method: 'GET',
      path: '/console/readyz',
    });
    expect(consoleReadyResponse.status).toBe(200);
    await expect(readJsonRecord(consoleReadyResponse)).resolves.toMatchObject({
      ok: true,
      service: 'console',
    });

    const supportCreditResponse = await callLocalWorkflowWorker(env, {
      method: 'POST',
      path: '/console/billing/adjustments/support-credit',
      body: {
        amountMinor: 5000,
        reasonCode: 'local_workflow_smoke_credit',
        note: 'Seed local D1 workflow smoke prepaid balance',
        idempotencyKey: 'local-workflow-smoke-credit',
      },
    });
    expect(supportCreditResponse.status).toBe(201);
    const supportCredit = jsonRecordField(await readJsonRecord(supportCreditResponse), 'result');
    expect(booleanField(supportCredit, 'created')).toBe(true);
    expect(numberField(jsonRecordField(supportCredit, 'adjustment'), 'amountMinor')).toBe(5000);

    const duplicateCreditResponse = await callLocalWorkflowWorker(env, {
      method: 'POST',
      path: '/console/billing/adjustments/support-credit',
      body: {
        amountMinor: 5000,
        reasonCode: 'local_workflow_smoke_credit',
        note: 'Seed local D1 workflow smoke prepaid balance',
        idempotencyKey: 'local-workflow-smoke-credit',
      },
    });
    expect(duplicateCreditResponse.status).toBe(200);
    const duplicateCredit = jsonRecordField(
      await readJsonRecord(duplicateCreditResponse),
      'result',
    );
    expect(booleanField(duplicateCredit, 'created')).toBe(false);

    const overviewResponse = await callLocalWorkflowWorker(env, {
      method: 'GET',
      path: '/console/billing/overview',
    });
    expect(overviewResponse.status).toBe(200);
    const overview = jsonRecordField(await readJsonRecord(overviewResponse), 'overview');
    expect(numberField(overview, 'creditBalanceMinor')).toBe(5000);

    const activityResponse = await callLocalWorkflowWorker(env, {
      method: 'GET',
      path: '/console/billing/account/activity?limit=5',
    });
    expect(activityResponse.status).toBe(200);
    const activity = jsonRecordField(await readJsonRecord(activityResponse), 'activity');
    const entries = jsonArrayField(activity, 'entries');
    expect(entries).toHaveLength(1);
    expect(numberField(jsonRecordAt(entries, 0), 'amountMinor')).toBe(5000);

    const signerResponse = await callLocalWorkflowWorker(env, {
      method: 'POST',
      path: '/relay/auth/passkey/options',
      headers: {
        origin: 'http://127.0.0.1:8787',
      },
      body: {
        user_id: 'local.workflow.testnet',
        rp_id: 'localhost',
      },
    });
    expect(signerResponse.status).toBe(200);
    await expect(readJsonRecord(signerResponse)).resolves.toMatchObject({
      ok: true,
    });

    const sponsoredHistoryResponse = await callLocalWorkflowWorker(env, {
      method: 'GET',
      path: '/console/billing/sponsored-executions',
    });
    expect(sponsoredHistoryResponse.status).toBe(200);
    const sponsoredHistoryPage = jsonRecordField(
      await readJsonRecord(sponsoredHistoryResponse),
      'page',
    );
    expect(jsonArrayField(sponsoredHistoryPage, 'items')).toHaveLength(0);

    const reconciliationResponse = await callLocalWorkflowWorker(env, {
      method: 'GET',
      path: '/console/billing/sponsored-executions/reconciliation',
    });
    expect(reconciliationResponse.status).toBe(200);
    const reconciliationPage = jsonRecordField(
      await readJsonRecord(reconciliationResponse),
      'page',
    );
    expect(jsonArrayField(reconciliationPage, 'items')).toHaveLength(0);
    expect(jsonRecordField(reconciliationPage, 'summary')).toMatchObject({
      matchedCount: 0,
      missingBillingDebitCount: 0,
      amountMismatchCount: 0,
      unexpectedBillingDebitCount: 0,
    });
  } finally {
    cleanupTemporaryD1Database(consoleTemp.tempDir);
    cleanupTemporaryD1Database(signerTemp.tempDir);
  }
});

test('local D1 Worker advances ECDSA-HSS pool-fill routes through D1 and Durable Objects', async () => {
  test.setTimeout(90_000);
  const consoleTemp = createTemporaryD1Database();
  const signerTemp = createTemporaryD1Database();

  try {
    await applyD1MigrationFiles(consoleTemp.database, listD1MigrationFiles('d1-console'));
    await applyD1MigrationFiles(signerTemp.database, listD1MigrationFiles('d1-signer'));
    const env = createLocalPoolFillWorkflowEnv({
      consoleDatabase: consoleTemp.database,
      signerDatabase: signerTemp.database,
    });
    const committed = await bootstrapLocalPoolFillEcdsaSession({
      env,
      signerDatabase: signerTemp.database,
    });

    await runLocalPoolFillRouteSmoke({
      env,
      jwt: committed.jwt,
      keyHandle: committed.keyHandle,
      scope: committed.scope,
      requestTag: 'tempo-testnet-local-pool-fill-smoke',
    });
    await runLocalPoolFillRouteSmoke({
      env,
      jwt: committed.jwt,
      keyHandle: committed.keyHandle,
      scope: committed.scope,
      requestTag: 'arc-testnet-local-pool-fill-smoke',
    });
  } finally {
    cleanupTemporaryD1Database(consoleTemp.tempDir);
    cleanupTemporaryD1Database(signerTemp.tempDir);
  }
});
