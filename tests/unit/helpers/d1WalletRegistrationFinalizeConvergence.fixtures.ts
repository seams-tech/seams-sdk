import { createPrivateKey, createPublicKey } from 'node:crypto';
import { once } from 'node:events';
import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import { Buffer } from 'node:buffer';
import {
  buildStoredWalletRegistrationNearEd25519YaoAuthorizedBranch,
  buildStoredWalletRegistrationPreparedContext,
  type StoredWalletRegistrationCeremony,
} from '../../../packages/wallet-server/src/core/RegistrationCeremonyStore';
import type { WalletRegistrationFinalizeRequest } from '../../../packages/wallet-server/src/core/registrationContracts';
import {
  createCloudflareD1RouterApiAuthService,
  type CloudflareD1RouterApiAuthService,
} from '../../../packages/wallet-server/src/router/cloudflare/d1/auth/d1RouterApiAuthService';
import { buildRegistrationIntent } from '../../../packages/wallet-server/src/router/cloudflare/d1/registration/d1RegistrationCeremonyRecords';
import { CloudflareD1RegistrationCeremonyIntentStore } from '../../../packages/wallet-server/src/router/cloudflare/d1/registration/d1RegistrationCeremonyStore';
import type {
  D1DatabaseLike,
  D1PreparedStatementLike,
} from '../../../packages/wallet-server/src/storage/tenantRoute';
import {
  createRouterAbEd25519YaoProductRegistrationCompositionFromPortsV1,
  createRouterAbEd25519YaoProductRegistrationStateV1,
  type RouterAbEd25519YaoProductRegistrationRuntimeV1,
} from '../../../packages/wallet-server/src/router/domains/ed25519Yao/capabilityLifecycle/routerAbEd25519YaoProductRegistration';
import {
  InMemoryRouterAbEd25519YaoRegistrationService,
  type RouterAbEd25519YaoRegistrationBackend,
  type RouterAbEd25519YaoRegistrationBackendResult,
} from '../../../packages/wallet-server/src/router/domains/ed25519Yao/registration/routerAbEd25519YaoRegistration';
import { InMemoryRouterAbEd25519YaoRegistrationIntentAuthorizationAdapter } from '../../../packages/wallet-server/src/router/domains/ed25519Yao/registration/routerAbEd25519YaoRegistrationIntentAuthorization';
import {
  InMemoryRouterAbEd25519YaoRecoveryService,
  type RouterAbEd25519YaoCapabilityPersistenceV1,
  type RouterAbEd25519YaoCapabilityPersistenceResultV1,
  type RouterAbEd25519YaoRecoveryBackend,
} from '../../../packages/wallet-server/src/router/domains/ed25519Yao/recovery/routerAbEd25519YaoRecovery';
import { RouterAbEd25519YaoRecoveryWalletSessionAuthorizationAdapter } from '../../../packages/wallet-server/src/router/domains/ed25519Yao/recovery/routerAbEd25519YaoRecoveryWalletSessionAuthorization';
import {
  InMemoryRouterAbEd25519YaoExportService,
  type RouterAbEd25519YaoExportBackend,
  type RouterAbEd25519YaoExportAuthorizationAdapter,
  type RouterAbEd25519YaoExportAuthorizationInput,
} from '../../../packages/wallet-server/src/router/domains/ed25519Yao/export/routerAbEd25519YaoExport';
import type { RouterAbEcdsaStrictRegistrationPort } from '../../../packages/wallet-server/src/router/domains/ecdsa/routerAbEcdsaStrictRegistration';
import {
  implicitNearAccountProvisioning,
  registrationNearEd25519BranchKey,
  registrationSignerPlanFromSelection,
  sponsoredNamedNearAccountProvisioning,
  walletIdFromString,
  type RegistrationNearAccountProvisioning,
  type RegistrationAuthority,
  type RegistrationSignerSetSelection,
  type WalletId,
} from '../../../packages/shared-ts/src/utils/registrationIntent';
import { base58Encode } from '../../../packages/shared-ts/src/utils/base58';
import { parseNamedNearAccountId } from '../../../packages/shared-ts/src/utils/near';
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
const SIGNING_WORKER_ID = 'signing-worker-finalize';
const REGISTRATION_CEREMONY_ID = 'registration-ceremony-finalize-1';
const IDEMPOTENCY_KEY = 'registration-finalize-convergence-1';
const SPONSORED_ACCOUNT_ID = 'sponsored-finalize-convergence.testnet';
const RELAYER_ACCOUNT_ID = 'relayer.finalize.testnet';
const RELAYER_ACCESS_KEY_NONCE = 7;
const FINAL_BLOCK_HASH = base58Encode(bytes(9));

type JsonRpcRequest = {
  readonly id: unknown;
  readonly method: string;
  readonly params: Record<string, unknown>;
};

type DeterministicNearCredentials = {
  readonly privateKey: string;
  readonly publicKey: string;
};

export type FinalizeConvergenceFault =
  | 'activation_consume_response_loss'
  | 'session_mint_response_loss'
  | 'wallet_commit_response_loss'
  | 'capability_install_response_loss'
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

function deterministicNearCredentials(seed: number): DeterministicNearCredentials {
  const seedBytes = Uint8Array.from(bytes(seed));
  const pkcs8Prefix = Uint8Array.from([
    0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
  ]);
  const pkcs8 = new Uint8Array(pkcs8Prefix.length + seedBytes.length);
  pkcs8.set(pkcs8Prefix);
  pkcs8.set(seedBytes, pkcs8Prefix.length);
  const privateKey = createPrivateKey({ key: Buffer.from(pkcs8), format: 'der', type: 'pkcs8' });
  const publicDer = createPublicKey(privateKey).export({ format: 'der', type: 'spki' });
  const publicKeyBytes = new Uint8Array(publicDer.subarray(publicDer.length - 32));
  const secretKeyBytes = new Uint8Array(64);
  secretKeyBytes.set(seedBytes);
  secretKeyBytes.set(publicKeyBytes, 32);
  return {
    privateKey: `ed25519:${base58Encode(secretKeyBytes)}`,
    publicKey: `ed25519:${base58Encode(publicKeyBytes)}`,
  };
}

function parseJsonRpcRequest(value: unknown): JsonRpcRequest {
  if (!isRecord(value) || typeof value.method !== 'string' || !isRecord(value.params)) {
    throw new Error('Sponsored NEAR RPC fixture received an invalid JSON-RPC request');
  }
  return { id: value.id, method: value.method, params: value.params };
}

function writeJsonRpcResult(
  response: ServerResponse,
  request: JsonRpcRequest,
  result: unknown,
): void {
  response.writeHead(200, { 'content-type': 'application/json' });
  response.end(JSON.stringify({ jsonrpc: '2.0', id: request.id, result }));
}

function writeJsonRpcError(
  response: ServerResponse,
  request: JsonRpcRequest,
  name: 'UNKNOWN_ACCOUNT' | 'UNKNOWN_ACCESS_KEY',
): void {
  response.writeHead(200, { 'content-type': 'application/json' });
  response.end(
    JSON.stringify({
      jsonrpc: '2.0',
      id: request.id,
      error: {
        code: -32000,
        name: 'HANDLER_ERROR',
        message: 'Server error',
        data: { name: 'HANDLER_ERROR', cause: { name, info: {} } },
      },
    }),
  );
}

class SponsoredNearJsonRpcFixture {
  private readonly server: Server;
  private transactionLanded = false;
  private transactionVisible = false;
  private transactionHash = '';
  broadcastCount = 0;
  txStatusCount = 0;

  constructor() {
    this.server = createServer(this.handle.bind(this));
  }

  async start(): Promise<string> {
    const listening = once(this.server, 'listening');
    this.server.listen(0, '127.0.0.1');
    await listening;
    const address = this.server.address();
    if (!address || typeof address === 'string') {
      throw new Error('Sponsored NEAR RPC fixture did not bind a TCP address');
    }
    return `http://127.0.0.1:${address.port}`;
  }

  async close(): Promise<void> {
    const closed = once(this.server, 'close');
    this.server.close();
    await closed;
  }

  private async handle(request: IncomingMessage, response: ServerResponse): Promise<void> {
    const chunks: Uint8Array[] = [];
    for await (const chunk of request) {
      chunks.push(typeof chunk === 'string' ? Buffer.from(chunk) : chunk);
    }
    const body = Buffer.concat(chunks).toString('utf8');
    const rpc = parseJsonRpcRequest(JSON.parse(body));
    switch (rpc.method) {
      case 'query':
        this.handleQuery(rpc, response);
        return;
      case 'block':
        writeJsonRpcResult(response, rpc, { header: { hash: FINAL_BLOCK_HASH } });
        return;
      case 'send_tx':
        this.broadcastCount += 1;
        this.transactionLanded = true;
        request.socket.destroy();
        return;
      case 'EXPERIMENTAL_tx_status':
        this.txStatusCount += 1;
        this.transactionHash = String(rpc.params.tx_hash || '');
        this.transactionVisible = this.transactionLanded;
        writeJsonRpcResult(response, rpc, this.successfulOutcome());
        return;
      default:
        throw new Error(`Unsupported sponsored NEAR RPC fixture method: ${rpc.method}`);
    }
  }

  private handleQuery(request: JsonRpcRequest, response: ServerResponse): void {
    const requestType = String(request.params.request_type || '');
    const accountId = String(request.params.account_id || '');
    if (requestType === 'view_access_key' && accountId === RELAYER_ACCOUNT_ID) {
      writeJsonRpcResult(response, request, {
        nonce: RELAYER_ACCESS_KEY_NONCE,
        permission: 'FullAccess',
        block_height: 1,
        block_hash: FINAL_BLOCK_HASH,
      });
      return;
    }
    if (!this.transactionVisible) {
      writeJsonRpcError(
        response,
        request,
        requestType === 'view_access_key' ? 'UNKNOWN_ACCESS_KEY' : 'UNKNOWN_ACCOUNT',
      );
      return;
    }
    if (requestType === 'view_account') {
      writeJsonRpcResult(response, request, {
        amount: '1000000000000000000000000',
        locked: '0',
        code_hash: '11111111111111111111111111111111',
        storage_usage: 0,
        storage_paid_at: 0,
        block_height: 1,
        block_hash: FINAL_BLOCK_HASH,
      });
      return;
    }
    writeJsonRpcResult(response, request, {
      nonce: 0,
      permission: 'FullAccess',
      block_height: 1,
      block_hash: FINAL_BLOCK_HASH,
    });
  }

  private successfulOutcome(): Record<string, unknown> {
    const hash = this.transactionHash || 'transaction-hash';
    const execution = {
      logs: [],
      receipt_ids: [],
      gas_burnt: 0,
      tokens_burnt: '0',
      executor_id: RELAYER_ACCOUNT_ID,
      status: { SuccessValue: '' },
    };
    return {
      final_execution_status: 'FINAL',
      status: { SuccessValue: '' },
      transaction: { hash },
      transaction_outcome: { id: hash, outcome: execution },
      receipts_outcome: [],
    };
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function mutateSignedTransactionSignatureByte(value: unknown): string {
  if (typeof value !== 'string' || value.length === 0) {
    throw new Error('Sponsored prepared artifact is missing signed transaction bytes');
  }
  const signedTransactionBytes = Buffer.from(value, 'base64url');
  if (signedTransactionBytes.length < 65) {
    throw new Error('Sponsored prepared artifact is too short to contain an Ed25519 signature');
  }
  const signatureByteIndex = signedTransactionBytes.length - 1;
  const signatureByte = signedTransactionBytes[signatureByteIndex];
  if (signatureByte === undefined) {
    throw new Error('Sponsored prepared artifact signature byte is missing');
  }
  signedTransactionBytes[signatureByteIndex] = signatureByte ^ 0x01;
  return signedTransactionBytes.toString('base64url');
}

async function corruptStoredSponsoredPreparedSignature(database: D1DatabaseLike): Promise<void> {
  const row = await database
    .prepare(
      `SELECT json_extract(
          record_json,
          '$.prepared.signedTransactionBorshB64u'
        ) AS signed_transaction_borsh_b64u
       FROM router_ab_yao_versioned_json_records
       WHERE record_key LIKE 'router-ab-yao-sponsored-account:%'`,
    )
    .first<{ readonly signed_transaction_borsh_b64u?: unknown }>();
  const corruptedSignature = mutateSignedTransactionSignatureByte(
    row?.signed_transaction_borsh_b64u,
  );
  await database
    .prepare(
      `UPDATE router_ab_yao_versioned_json_records
          SET record_json = json_set(
            record_json,
            '$.prepared.signedTransactionBorshB64u',
            ?
          )
        WHERE record_key LIKE 'router-ab-yao-sponsored-account:%'`,
    )
    .bind(corruptedSignature)
    .run();
}

class ResponseLossD1Database implements D1DatabaseLike {
  private loseWalletCommitResponse = false;
  private loseFinalizeClaimResponse = false;
  private loseFinalizeCompletionResponse = false;
  private loseCeremonyDeleteResponse = false;

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

  armCeremonyDeleteResponseLoss(): void {
    this.loseCeremonyDeleteResponse = true;
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
    const registrationScope = String(values[4] || '');
    const registrationRecordId = String(values[5] || '');
    if (
      this.loseCeremonyDeleteResponse &&
      registrationScope === 'ceremony' &&
      registrationRecordId.endsWith(REGISTRATION_CEREMONY_ID) &&
      /\bDELETE\s+FROM\s+registration_ceremony_records\b/iu.test(query)
    ) {
      this.loseCeremonyDeleteResponse = false;
      throw new Error('simulated ceremony delete response loss');
    }
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

  async prepareActivation(): Promise<never> {
    throw new Error('ECDSA is outside the finalize convergence fixture');
  }

  async activate(): Promise<never> {
    throw new Error('ECDSA is outside the finalize convergence fixture');
  }

  async queryActivation(): Promise<never> {
    throw new Error('ECDSA is outside the finalize convergence fixture');
  }
}

class FailureInjectingYaoRuntime implements RouterAbEd25519YaoProductRegistrationRuntimeV1 {
  readonly kind = 'router_ab_ed25519_yao_product_registration_runtime_v1' as const;
  readonly signingWorkerId: string;
  private fault: YaoFault | null = null;
  private lastConsumerBinding: string | null = null;

  constructor(private readonly delegate: RouterAbEd25519YaoProductRegistrationRuntimeV1) {
    this.signingWorkerId = delegate.signingWorkerId;
  }

  arm(fault: YaoFault): void {
    this.fault = fault;
  }

  consumerBinding(): string | null {
    return this.lastConsumerBinding;
  }

  async bindVerifiedIntent(
    input: Parameters<RouterAbEd25519YaoProductRegistrationRuntimeV1['bindVerifiedIntent']>[0],
  ): Promise<
    Awaited<ReturnType<RouterAbEd25519YaoProductRegistrationRuntimeV1['bindVerifiedIntent']>>
  > {
    return await this.delegate.bindVerifiedIntent(input);
  }

  async bindAndAdmitVerifiedRegistration(
    input: Parameters<
      RouterAbEd25519YaoProductRegistrationRuntimeV1['bindAndAdmitVerifiedRegistration']
    >[0],
  ): Promise<
    Awaited<
      ReturnType<RouterAbEd25519YaoProductRegistrationRuntimeV1['bindAndAdmitVerifiedRegistration']>
    >
  > {
    return await this.delegate.bindAndAdmitVerifiedRegistration(input);
  }

  async consumeActivated(
    input: Parameters<RouterAbEd25519YaoProductRegistrationRuntimeV1['consumeActivated']>[0],
  ): Promise<
    Awaited<ReturnType<RouterAbEd25519YaoProductRegistrationRuntimeV1['consumeActivated']>>
  > {
    this.lastConsumerBinding = input.consumerBinding;
    const result = await this.delegate.consumeActivated(input);
    this.throwAfter('activation_consume_response_loss');
    return result;
  }

  async replayActivatedRegistration(
    input: Parameters<
      RouterAbEd25519YaoProductRegistrationRuntimeV1['replayActivatedRegistration']
    >[0],
  ): Promise<
    Awaited<
      ReturnType<RouterAbEd25519YaoProductRegistrationRuntimeV1['replayActivatedRegistration']>
    >
  > {
    return await this.delegate.replayActivatedRegistration(input);
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
  readonly admissionReceipt: RouterAbEd25519YaoActivationAdmissionReceiptV1<'registration'>;
  readonly accountProvisioning: RegistrationNearAccountProvisioning;
}): StoredWalletRegistrationCeremony {
  const signerSelection: RegistrationSignerSetSelection = {
    kind: 'signer_set',
    signers: [
      {
        kind: 'near_ed25519',
        accountProvisioning: input.accountProvisioning,
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
    authorityState: {
      kind: 'verified',
      authority: testPasskeyAuthority(input.walletId, testRpId()),
    },
    signerState: {
      kind: 'signer_set_registration',
      branches: [
        buildStoredWalletRegistrationNearEd25519YaoAuthorizedBranch({
          branchKey: registrationNearEd25519BranchKey(1),
          admissionRequest: input.admissionRequest,
          admissionReceipt: input.admissionReceipt,
        }),
      ],
    },
  };
}

/**
 * Builds the fixture against a concrete admission request when one is given,
 * so a runtime can satisfy whatever ceremony actually arrives instead of only
 * its own fixed ids. The receipt binding mirrors the request scope, so every
 * field it needs is derivable from that request.
 */
/** Splits an admission request's `signing_root_id` back into scope fields. */
function incomingSigningRootScope(
  incoming: RouterAbEd25519YaoRegistrationAdmissionRequestV1 | undefined,
): { projectId?: string; envId?: string } {
  if (!incoming) return {};
  const [projectId, envId] = String(incoming.application_binding.signing_root_id).split(':');
  return projectId && envId ? { projectId, envId } : {};
}

export async function createActivatedFinalizeYaoRuntimeFixture(overrides?: {
  readonly admissionRequest: RouterAbEd25519YaoRegistrationAdmissionRequestV1;
  readonly signingRootVersion?: string;
}): Promise<{
  readonly runtime: FailureInjectingYaoRuntime;
  readonly admissionRequest: RouterAbEd25519YaoRegistrationAdmissionRequestV1;
  readonly admissionReceipt: RouterAbEd25519YaoActivationAdmissionReceiptV1<'registration'>;
  readonly activationResult: RouterAbEd25519YaoActivationResultV1<'registration'>;
}> {
  const incoming = overrides?.admissionRequest;
  const walletId = incoming
    ? walletIdFromString(incoming.application_binding.wallet_id)
    : walletIdFromString('finalize-convergence-wallet');
  const capability = buildEd25519YaoCapabilityFixture({
    walletId,
    nearAccountId: 'finalize-convergence.testnet',
    nearEd25519SigningKeyId: incoming
      ? incoming.application_binding.near_ed25519_signing_key_id
      : 'near-ed25519-finalize-convergence',
    thresholdSessionId: incoming
      ? incoming.scope.threshold_session_id
      : 'threshold-finalize-convergence',
    signerSlot: incoming ? incoming.application_binding.key_creation_signer_slot : 1,
    signingWorkerId: incoming ? incoming.scope.signing_worker_id : SIGNING_WORKER_ID,
    participantIds: [1, 2],
    runtimePolicyScope: {
      ...TEST_SCOPE,
      /* The ceremony's own project/env, so the signing root id this fixture
         derives equals the one the incoming request carries. */
      ...incomingSigningRootScope(incoming),
      signingRootVersion:
        incoming?.scope.root_share_epoch ?? overrides?.signingRootVersion ?? 'root-finalize-v1',
    },
    seed: 93,
    ...(incoming
      ? {
          lifecycleId: incoming.scope.lifecycle_id,
          signerSetId: incoming.scope.signer_set_id,
          /* Everything the incoming request already decided is carried rather
             than re-invented, so the admission request this rebuilds is byte-
             equal to the one admitted — which is what finalize compares its
             stored signer branch against. */
          materialActivation: incoming.scope.material_activation as never,
        }
      : {}),
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
  const session = new StaticWalletSessionAdapter();
  const recoveryService = new InMemoryRouterAbEd25519YaoRecoveryService(
    backend,
    state.recovery,
    new AppliedCapabilityPersistence(),
  );
  const exportService = new InMemoryRouterAbEd25519YaoExportService(
    backend,
    recoveryService,
    state.export,
  );
  const exportAuthorization: RouterAbEd25519YaoExportAuthorizationAdapter = {
    async authorize(input: RouterAbEd25519YaoExportAuthorizationInput) {
      const rawSessionId =
        input.kind === 'admit'
          ? input.body.scope.threshold_session_id
          : input.body.binding.ceremony.lifecycle.session_id;
      const thresholdSessionId = parseThresholdEd25519SessionId(rawSessionId);
      if (!thresholdSessionId.ok) {
        return {
          ok: false as const,
          status: 403 as const,
          code: 'invalid_body',
          message: thresholdSessionId.error.message,
        };
      }
      return { ok: true as const, authorizationIdentity: { thresholdSessionId: thresholdSessionId.value } };
    },
    async resolveAuthorizationIdentity() {
      const thresholdSessionId = parseThresholdEd25519SessionId(
        admissionRequest.scope.threshold_session_id,
      );
      if (!thresholdSessionId.ok) {
        return {
          ok: false as const,
          status: 403 as const,
          code: 'invalid_body',
          message: thresholdSessionId.error.message,
        };
      }
      return { ok: true as const, authorizationIdentity: { thresholdSessionId: thresholdSessionId.value } };
    },
  };
  const composition = createRouterAbEd25519YaoProductRegistrationCompositionFromPortsV1({
    signingWorkerId: SIGNING_WORKER_ID,
    registrationService: registration,
    authorization: new InMemoryRouterAbEd25519YaoRegistrationIntentAuthorizationAdapter(
      state.authorization,
    ),
    recoveryService,
    capabilities: recoveryService,
    recoveryAuthorization: new RouterAbEd25519YaoRecoveryWalletSessionAuthorizationAdapter(session),
    exportService,
    exportAuthorization,
    session,
  });
  return {
    runtime: new FailureInjectingYaoRuntime(composition.runtime),
    admissionRequest,
    admissionReceipt,
    activationResult,
  };
}

export type FinalizeConvergenceHarness = {
  readonly service: CloudflareD1RouterApiAuthService;
  readonly request: WalletRegistrationFinalizeRequest;
  readonly database: D1DatabaseLike;
  readonly cleanup: () => Promise<void>;
  readonly arm: (fault: FinalizeConvergenceFault) => void;
  readonly activationConsumerBinding: () => string | null;
  readonly expireFinalizeClaim: () => Promise<void>;
  readonly countRows: (table: string) => Promise<number>;
};

export type SponsoredFinalizeConvergenceHarness = FinalizeConvergenceHarness & {
  readonly corruptSponsoredPreparedArtifact: () => Promise<void>;
  readonly corruptSponsoredPreparedSignature: () => Promise<void>;
  readonly sponsoredNearRpcCounts: () => {
    readonly broadcastCount: number;
    readonly txStatusCount: number;
  };
};

type FinalizeConvergenceHarnessMode =
  | { readonly kind: 'implicit' }
  | {
      readonly kind: 'sponsored';
      readonly rpc: SponsoredNearJsonRpcFixture;
      readonly nearRpcUrl: string;
      readonly credentials: DeterministicNearCredentials;
    };

function sponsoredFinalizeAccountProvisioning(): RegistrationNearAccountProvisioning {
  const accountId = parseNamedNearAccountId(SPONSORED_ACCOUNT_ID);
  if (!accountId.ok) throw new Error(accountId.message);
  return sponsoredNamedNearAccountProvisioning(accountId.value);
}

function accountProvisioningForMode(
  mode: FinalizeConvergenceHarnessMode,
): RegistrationNearAccountProvisioning {
  switch (mode.kind) {
    case 'implicit':
      return implicitNearAccountProvisioning();
    case 'sponsored':
      return sponsoredFinalizeAccountProvisioning();
  }
}

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

async function createFinalizeConvergenceHarnessForMode(
  mode: FinalizeConvergenceHarnessMode,
): Promise<FinalizeConvergenceHarness> {
  const temporary = createTemporaryD1Database();
  await applySignerMigrations(temporary.database);
  const database = new ResponseLossD1Database(temporary.database);
  const yao = await createActivatedFinalizeYaoRuntimeFixture();
  const service = createCloudflareD1RouterApiAuthService({
    database,
    ...TEST_SCOPE,
    ed25519YaoProductRegistration: yao.runtime,
    ecdsaStrictRegistration: new UnusedEcdsaStrictRegistration(),
    ...(mode.kind === 'sponsored'
      ? {
          relayerAccount: RELAYER_ACCOUNT_ID,
          relayerPublicKey: mode.credentials.publicKey,
          relayerPrivateKey: mode.credentials.privateKey,
          nearRpcUrl: mode.nearRpcUrl,
          accountInitialBalance: '1000000000000000000000000',
        }
      : {}),
  });
  const ceremonyStore = new CloudflareD1RegistrationCeremonyIntentStore({
    kind: 'partitioned_d1',
    database,
    scope: TEST_SCOPE,
    keyPrefix: 'gateway-registration:',
  });
  const walletId = walletIdFromString(yao.admissionRequest.application_binding.wallet_id);
  await ceremonyStore.putCeremony(
    buildCeremony({
      walletId,
      admissionRequest: yao.admissionRequest,
      admissionReceipt: buildAdmissionReceipt(yao.activationResult),
      accountProvisioning: accountProvisioningForMode(mode),
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
    cleanup: async () => {
      if (mode.kind === 'sponsored') await mode.rpc.close();
      cleanupTemporaryD1Database(temporary.tempDir);
    },
    expireFinalizeClaim: async () => {
      await database
        .prepare(
          `UPDATE router_ab_yao_versioned_json_records
             SET record_json = json_set(record_json, '$.claimedAtMs', 0)
           WHERE json_extract(record_json, '$.kind') =
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
        case 'wallet_commit_response_loss':
          database.armBatchResponseLoss();
          return;
        case 'ceremony_delete_response_loss':
          database.armCeremonyDeleteResponseLoss();
          return;
        case 'finalize_claim_response_loss':
          database.armFinalizeClaimResponseLoss();
          return;
        case 'finalize_completion_response_loss':
          database.armFinalizeCompletionResponseLoss();
          return;
      }
    },
    activationConsumerBinding: () => yao.runtime.consumerBinding(),
    countRows: async (table) => {
      const row = await database.prepare(`SELECT COUNT(*) AS count FROM ${table}`).first<{
        readonly count?: unknown;
      }>();
      return Number(row?.count || 0);
    },
  };
}

export async function createFinalizeConvergenceHarness(): Promise<FinalizeConvergenceHarness> {
  return await createFinalizeConvergenceHarnessForMode({ kind: 'implicit' });
}

export async function createSponsoredFinalizeConvergenceHarness(): Promise<SponsoredFinalizeConvergenceHarness> {
  const rpc = new SponsoredNearJsonRpcFixture();
  const nearRpcUrl = await rpc.start();
  try {
    const harness = await createFinalizeConvergenceHarnessForMode({
      kind: 'sponsored',
      rpc,
      nearRpcUrl,
      credentials: deterministicNearCredentials(71),
    });
    return {
      ...harness,
      corruptSponsoredPreparedArtifact: async () => {
        await harness.database
          .prepare(
            `UPDATE router_ab_yao_versioned_json_records
                SET record_json = json_set(
                  record_json,
                  '$.prepared.accountId',
                  'corrupted-sponsored-account.testnet'
                )
              WHERE record_key LIKE 'router-ab-yao-sponsored-account:%'`,
          )
          .run();
      },
      corruptSponsoredPreparedSignature: async () => {
        await corruptStoredSponsoredPreparedSignature(harness.database);
      },
      sponsoredNearRpcCounts: () => ({
        broadcastCount: rpc.broadcastCount,
        txStatusCount: rpc.txStatusCount,
      }),
    };
  } catch (error: unknown) {
    await rpc.close();
    throw error;
  }
}
