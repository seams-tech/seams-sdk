import { expect, test } from '@playwright/test';
import { spawnSync } from 'node:child_process';
import { createPublicKey, verify } from 'node:crypto';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { type RouterAbEd25519YaoRegistrationAdmissionRequestV1 } from '@shared/utils/routerAbEd25519Yao';
import { coerceRouterLogger } from '../../packages/sdk-server-ts/src/router/logger';
import { createRouterAbEd25519YaoHttpRegistrationBackendFromEnv } from '../../packages/sdk-server-ts/src/router/routerAbEd25519YaoHttpRegistrationBackend';
import {
  InMemoryRouterAbEd25519YaoRegistrationService,
  createRouterAbEd25519YaoRegistrationModule,
  type RouterAbEd25519YaoRegistrationAuthorizationAdapter,
  type RouterAbEd25519YaoRegistrationAuthorizationInput,
  type RouterAbEd25519YaoRegistrationAuthorizationResult,
} from '../../packages/sdk-server-ts/src/router/routerAbEd25519YaoRegistration';
import type { RouterApiRouteExtension } from '../../packages/sdk-server-ts/src/router/routeExtensions';
import type { RouteDefinition } from '../../packages/sdk-server-ts/src/router/routeDefinitions';
import {
  handleRouterAbEd25519NormalSigningRouteCore,
  ROUTER_AB_ED25519_PRIVATE_SIGNING_PATHS,
  type RouterAbNormalSigningAdmissionAdapter,
  type RouterAbNormalSigningRouteRuntime,
} from '../../packages/sdk-server-ts/src/router/routerAbPrivateSigningWorker';
import type { SessionAdapter } from '../../packages/sdk-server-ts/src/router/routerApi';
import type {
  RouterAbNormalSigningBudgetFinalizeInput,
  RouterAbNormalSigningBudgetReleaseInput,
  RouterAbNormalSigningBudgetReservationInput,
  RouterAbNormalSigningPrepareReplayReservationInput,
  RouterAbSigningWorkerPrivateTransport,
} from '../../packages/sdk-server-ts/src/core/routerAbSigning/RouterAbNormalSigningRuntime';
import {
  buildRouterAbEd25519Nep413PrepareRequestV2,
  routerAbEd25519Nep413CanonicalMessageB64uV2,
} from '../../packages/sdk-web/src/core/rpcClients/relayer/routerAbNormalSigning';
import {
  RouterAbEd25519YaoClientV1,
  type RouterAbEd25519YaoActiveClientV1,
  type RouterAbEd25519YaoClientSigningInputV1,
  type RouterAbEd25519YaoRegistrationTransportRequestV1,
  type RouterAbEd25519YaoRegistrationTransportResultV1,
  type RouterAbEd25519YaoRegistrationTransportV1,
} from '../../packages/sdk-web/src/core/signingEngine/threshold/ed25519/yaoClient';
import { base64UrlDecode, base64UrlEncode } from '../../packages/shared-ts/src/utils/base64';
import { ROUTER_AB_ED25519_WALLET_SESSION_JWT_KIND } from '../../packages/shared-ts/src/utils/sessionTokens';
import { ROUTER_AB_ED25519_NORMAL_SIGNING_STATE_KIND } from '../../packages/shared-ts/src/utils/signingSessionSeal';

const REPO_ROOT = fileURLToPath(new URL('../..', import.meta.url));
const DEV_MANIFEST = join(REPO_ROOT, 'crates/router-ab-dev/Cargo.toml');
const DEV_TARGET = join(REPO_ROOT, 'crates/router-ab-dev/target/debug');
const CLIENT_CRATE = join(REPO_ROOT, 'crates/router-ab-ed25519-yao-client');
const ROUTER_ENV_FILE = '.env.router-ab.router.local';

type LocalProcessState = { kind: 'running' } | { kind: 'stopped' };

type LocalSigningBudgetState =
  | { kind: 'available' }
  | {
      kind: 'reserved';
      reservationId: string;
      signingGrantId: string;
      signingWorkerId: string;
      operationId: string;
      requestDigest: string;
    }
  | { kind: 'committed'; reservationId: string }
  | { kind: 'released'; reservationId: string };

type LocalPublicSigningRoutePhase = 'prepare' | 'finalize';

type LocalPublicSigningRouteResult = {
  status: number;
  body: unknown;
};

type LocalRegistrationTransportState =
  | { kind: 'awaiting_execution' }
  | {
      kind: 'executed';
      request: Extract<RouterAbEd25519YaoRegistrationTransportRequestV1, { kind: 'execute' }>;
      result: unknown;
    };

class AllowLocalRegistrationAuthorization implements RouterAbEd25519YaoRegistrationAuthorizationAdapter {
  authorize(
    _input: RouterAbEd25519YaoRegistrationAuthorizationInput,
  ): RouterAbEd25519YaoRegistrationAuthorizationResult {
    return { ok: true };
  }
}

class InProcessRouterAbEd25519YaoRegistrationTransport implements RouterAbEd25519YaoRegistrationTransportV1 {
  private state: LocalRegistrationTransportState = { kind: 'awaiting_execution' };

  constructor(private readonly extension: RouterApiRouteExtension) {}

  async send(
    request: RouterAbEd25519YaoRegistrationTransportRequestV1,
  ): Promise<RouterAbEd25519YaoRegistrationTransportResultV1> {
    try {
      const response = await invokeRoute(this.extension, request.path, request.body);
      const body: unknown = await response.json();
      if (response.status !== 200) {
        return {
          ok: false,
          code: 'router_rejected',
          status: response.status,
          message: JSON.stringify(body),
        };
      }
      if (request.kind === 'execute') {
        this.recordExecution(request, body);
      }
      return { ok: true, value: body };
    } catch (error: unknown) {
      return {
        ok: false,
        code: 'transport_failed',
        status: 0,
        message: error instanceof Error ? error.message : String(error),
      };
    }
  }

  async retryRecordedExecution(): Promise<{ first: unknown; retry: unknown }> {
    switch (this.state.kind) {
      case 'awaiting_execution':
        throw new Error('Registration execution has not been recorded');
      case 'executed': {
        const response = await invokeRoute(
          this.extension,
          this.state.request.path,
          this.state.request.body,
        );
        const retry = await requireOkJson(response, 'registration execution retry');
        return { first: this.state.result, retry };
      }
      default:
        return assertNever(this.state);
    }
  }

  private recordExecution(
    request: Extract<RouterAbEd25519YaoRegistrationTransportRequestV1, { kind: 'execute' }>,
    result: unknown,
  ): void {
    switch (this.state.kind) {
      case 'awaiting_execution':
        this.state = { kind: 'executed', request, result };
        return;
      case 'executed':
        throw new Error('Registration transport received duplicate execution');
      default:
        return assertNever(this.state);
    }
  }
}

class AllowLocalSigningAdmission implements RouterAbNormalSigningAdmissionAdapter {
  async evaluate(): Promise<{ ok: true }> {
    return { ok: true };
  }
}

class LocalWalletSessionAdapter implements SessionAdapter {
  constructor(private readonly claims: Readonly<Record<string, unknown>>) {}

  async signJwt(): Promise<string> {
    return 'unused.local.jwt';
  }

  async parse(): Promise<{ ok: true; claims: Record<string, unknown> }> {
    return { ok: true, claims: { ...this.claims } };
  }

  buildSetCookie(): string {
    return 'unused-local-cookie';
  }

  buildClearCookie(): string {
    return 'unused-local-clear-cookie';
  }

  async refresh(): Promise<{ ok: false }> {
    return { ok: false };
  }
}

type ConfiguredSigningWorkerTransport = Extract<
  RouterAbSigningWorkerPrivateTransport,
  { readonly kind: 'configured' }
>;

class LocalNormalSigningRuntime implements RouterAbNormalSigningRouteRuntime {
  private readonly replayRequestIds = new Set<string>();
  private budget: LocalSigningBudgetState = { kind: 'available' };

  constructor(private readonly config: ConfiguredSigningWorkerTransport) {}

  getSigningWorkerPrivateTransport(): ConfiguredSigningWorkerTransport {
    return this.config;
  }

  async reservePrepareReplay(
    input: RouterAbNormalSigningPrepareReplayReservationInput,
  ): Promise<{ ok: true } | { ok: false; status: number; code: string; message: string }> {
    const key = `${input.curve}:prepare:${input.thresholdSessionId}:${input.requestId}`;
    if (this.replayRequestIds.has(key)) {
      return {
        ok: false,
        status: 400,
        code: 'one_use_replay_rejected',
        message: 'Router A/B normal-signing prepare request id already used',
      };
    }
    this.replayRequestIds.add(key);
    return { ok: true };
  }

  async reserveBudget(input: RouterAbNormalSigningBudgetReservationInput): Promise<
    | {
        ok: true;
        reservationId: string;
        remainingUses: number;
        reservedUses: number;
        availableUses: number;
      }
    | { ok: false; status: number; code: string; message: string }
  > {
    if (this.budget.kind !== 'available') return localBudgetUnavailable();
    const reservationId = 'local-yao-budget-reservation-1';
    this.budget = {
      kind: 'reserved',
      reservationId,
      signingGrantId: input.signingGrantId,
      signingWorkerId: input.signingWorkerId,
      operationId: input.operationId,
      requestDigest: input.requestDigest,
    };
    return {
      ok: true,
      reservationId,
      remainingUses: 1,
      reservedUses: 1,
      availableUses: 0,
    };
  }

  async validateBudget(
    input: RouterAbNormalSigningBudgetFinalizeInput,
  ): Promise<{ ok: true; remainingUses: number } | ReturnType<typeof localBudgetUnavailable>> {
    return this.matchesReservedBudget(input)
      ? { ok: true, remainingUses: 1 }
      : localBudgetUnavailable();
  }

  async commitBudget(
    input: RouterAbNormalSigningBudgetFinalizeInput,
  ): Promise<{ ok: true; remainingUses: number } | ReturnType<typeof localBudgetUnavailable>> {
    if (!this.matchesReservedBudget(input)) return localBudgetUnavailable();
    this.budget = { kind: 'committed', reservationId: input.reservationId };
    return { ok: true, remainingUses: 0 };
  }

  async releaseBudget(input: RouterAbNormalSigningBudgetReleaseInput): Promise<
    | {
        ok: true;
        released: boolean;
        remainingUses: number;
        reservedUses: number;
        availableUses: number;
      }
    | ReturnType<typeof localBudgetUnavailable>
  > {
    if (this.budget.kind !== 'reserved' || this.budget.reservationId !== input.reservationId) {
      return localBudgetUnavailable();
    }
    this.budget = { kind: 'released', reservationId: input.reservationId };
    return localBudgetReleased();
  }

  async releaseBudgetForIdentity(input: RouterAbNormalSigningBudgetFinalizeInput): Promise<
    | {
        ok: true;
        released: boolean;
        remainingUses: number;
        reservedUses: number;
        availableUses: number;
      }
    | ReturnType<typeof localBudgetUnavailable>
  > {
    if (!this.matchesReservedBudget(input)) return localBudgetUnavailable();
    this.budget = { kind: 'released', reservationId: input.reservationId };
    return localBudgetReleased();
  }

  private matchesReservedBudget(input: RouterAbNormalSigningBudgetFinalizeInput): boolean {
    return (
      this.budget.kind === 'reserved' &&
      this.budget.reservationId === input.reservationId &&
      this.budget.signingGrantId === input.signingGrantId &&
      this.budget.signingWorkerId === input.signingWorkerId &&
      this.budget.operationId === input.operationId &&
      this.budget.requestDigest === input.requestDigest
    );
  }
}

class LocalPublicEd25519SigningRouter {
  private readonly admission = new AllowLocalSigningAdmission();
  private readonly session: SessionAdapter;
  private readonly runtime: LocalNormalSigningRuntime;

  constructor(input: {
    processes: LocalWorkerProcesses;
    walletId: string;
    nearAccountId: string;
    thresholdSessionId: string;
    signingGrantId: string;
    signingWorkerId: string;
    expiresAtMs: number;
  }) {
    this.session = new LocalWalletSessionAdapter(localWalletSessionClaims(input));
    this.runtime = new LocalNormalSigningRuntime({
      kind: 'configured',
      signingWorkerBaseUrl: requireEnv(input.processes.routerEnv, 'SIGNING_WORKER_URL'),
      auth: {
        kind: 'internal_service_auth_secret',
        secret: requireEnv(input.processes.routerEnv, 'ROUTER_AB_INTERNAL_SERVICE_AUTH_SECRET'),
      },
    });
  }

  async handle(
    phase: LocalPublicSigningRoutePhase,
    body: Record<string, unknown>,
  ): Promise<LocalPublicSigningRouteResult> {
    return await handleRouterAbEd25519NormalSigningRouteCore({
      body,
      rawBody: body,
      headers: { authorization: 'Bearer local-wallet-session.jwt' },
      session: this.session,
      runtime: this.runtime,
      admissionAdapter: this.admission,
      privatePath:
        phase === 'prepare'
          ? ROUTER_AB_ED25519_PRIVATE_SIGNING_PATHS.prepare
          : ROUTER_AB_ED25519_PRIVATE_SIGNING_PATHS.finalize,
      phase,
    });
  }
}

function localBudgetUnavailable(): {
  ok: false;
  status: number;
  code: string;
  message: string;
} {
  return {
    ok: false,
    status: 409,
    code: 'wallet_budget_exhausted',
    message: 'Local Router A/B signing reservation is unavailable',
  };
}

function localBudgetReleased(): {
  ok: true;
  released: true;
  remainingUses: number;
  reservedUses: number;
  availableUses: number;
} {
  return {
    ok: true,
    released: true,
    remainingUses: 1,
    reservedUses: 0,
    availableUses: 1,
  };
}

function localWalletSessionClaims(input: {
  walletId: string;
  nearAccountId: string;
  thresholdSessionId: string;
  signingGrantId: string;
  signingWorkerId: string;
  expiresAtMs: number;
}): Record<string, unknown> {
  return {
    sub: input.walletId,
    walletId: input.walletId,
    nearAccountId: input.nearAccountId,
    nearEd25519SigningKeyId: 'near-ed25519-key-local-yao',
    kind: ROUTER_AB_ED25519_WALLET_SESSION_JWT_KIND,
    thresholdSessionId: input.thresholdSessionId,
    signingGrantId: input.signingGrantId,
    relayerKeyId: 'near-relayer-key-local-yao',
    authority: {
      walletId: input.walletId,
      factor: { kind: 'passkey', credentialIdB64u: 'local-yao-credential' },
      verifier: { kind: 'webauthn', rpId: 'localhost' },
      bindingId: 'passkey:localhost:local-yao-credential',
    },
    authorityScope: { kind: 'passkey_rp', rpId: 'localhost' },
    runtimePolicyScope: {
      orgId: 'local-org',
      projectId: 'local-project',
      envId: 'local-development',
      signingRootVersion: 'local-root-v1',
    },
    thresholdExpiresAtMs: input.expiresAtMs,
    participantIds: [1, 2],
    routerAbNormalSigning: {
      kind: ROUTER_AB_ED25519_NORMAL_SIGNING_STATE_KIND,
      signingWorkerId: input.signingWorkerId,
    },
  };
}

class LocalWorkerProcesses {
  private state: LocalProcessState = { kind: 'running' };

  private constructor(
    readonly root: string,
    readonly routerEnv: Readonly<Record<string, string>>,
    readonly wasmPackagePath: string,
  ) {}

  static start(): LocalWorkerProcesses {
    const root = mkdtempSync(join(tmpdir(), 'seams-yaos-sdk-local-'));
    try {
      runCommand('cargo', [
        'build',
        '--offline',
        '--manifest-path',
        DEV_MANIFEST,
        '--bin',
        'router_ab_local_worker',
        '--bin',
        'router_ab_local_init',
        '--bin',
        'router_ab_local_up',
        '--bin',
        'router_ab_local_down',
      ]);
      runCommand(join(DEV_TARGET, 'router_ab_local_init'), ['--root', root, '--ephemeral-ports']);
      runCommand(join(DEV_TARGET, 'router_ab_local_up'), ['--root', root]);
      const wasmPackagePath = join(root, 'wasm-client');
      runCommand('wasm-pack', [
        'build',
        CLIENT_CRATE,
        '--target',
        'web',
        '--out-dir',
        wasmPackagePath,
        '--dev',
      ]);
      const routerEnv = parseEnvFile(join(root, ROUTER_ENV_FILE));
      return new LocalWorkerProcesses(root, routerEnv, wasmPackagePath);
    } catch (error: unknown) {
      stopLocalWorkers(root);
      rmSync(root, { recursive: true, force: true });
      throw error;
    }
  }

  stop(): void {
    switch (this.state.kind) {
      case 'running':
        stopLocalWorkers(this.root);
        rmSync(this.root, { recursive: true, force: true });
        this.state = { kind: 'stopped' };
        return;
      case 'stopped':
        return;
      default:
        assertNever(this.state);
    }
  }
}

async function runLocalRegistrationTest(): Promise<void> {
  const processes = LocalWorkerProcesses.start();
  try {
    const backend = createRouterAbEd25519YaoHttpRegistrationBackendFromEnv({
      env: processes.routerEnv,
      fetch: globalThis.fetch,
    });
    const service = new InMemoryRouterAbEd25519YaoRegistrationService(backend);
    const module = createRouterAbEd25519YaoRegistrationModule({
      service,
      authorization: new AllowLocalRegistrationAuthorization(),
    });
    const extension = module.routeExtensions[0];
    if (!extension) throw new Error('SDK Router registration extension is required');
    const admissionRequest = registrationAdmissionRequest(
      requireEnv(processes.routerEnv, 'SIGNING_WORKER_ID'),
    );
    const client = await RouterAbEd25519YaoClientV1.initialize(
      new Uint8Array(
        readFileSync(join(processes.wasmPackagePath, 'router_ab_ed25519_yao_client_bg.wasm')),
      ),
    );
    const transport = new InProcessRouterAbEd25519YaoRegistrationTransport(extension);
    const ownedPasskeyPrfFirst = randomBytes32();
    expect(isZeroized(ownedPasskeyPrfFirst)).toBe(false);
    const registration = await client.register({
      request: admissionRequest,
      factor: { kind: 'passkey_prf_first', ownedSecret32: ownedPasskeyPrfFirst },
      transport,
    });
    expect(isZeroized(ownedPasskeyPrfFirst)).toBe(true);
    if (!registration.ok) {
      throw new Error(
        `SDK Yao Client registration failed (${registration.code}): ${registration.message}`,
      );
    }

    const activeClient = registration.activeClient;
    try {
      const metadata = activeClient.metadata();
      expect(metadata.registeredPublicKey).toHaveLength(32);
      expect(metadata.stateEpoch).toBe(1n);
      expect(metadata.scope).toEqual(admissionRequest.scope);

      const signingRouter = new LocalPublicEd25519SigningRouter({
        processes,
        walletId: admissionRequest.scope.account_id,
        nearAccountId: 'alice.testnet',
        thresholdSessionId: admissionRequest.scope.wallet_session_id,
        signingGrantId: 'local-yao-signing-grant-1',
        signingWorkerId: admissionRequest.scope.signing_worker_id,
        expiresAtMs: Date.now() + 10 * 60_000,
      });
      const signingInput = await signWithActivatedYaoShares({
        signingRouter,
        activeClient,
        admissionRequest,
      });

      const retriedExecution = await transport.retryRecordedExecution();
      expect(retriedExecution.retry).toEqual(retriedExecution.first);

      activeClient.dispose();
      await expect(activeClient.createSigningShare(signingInput)).rejects.toThrow(
        'Ed25519 Yao Client state is disposed',
      );
    } finally {
      activeClient.dispose();
    }
  } finally {
    processes.stop();
  }
}

async function signWithActivatedYaoShares(input: {
  signingRouter: LocalPublicEd25519SigningRouter;
  activeClient: RouterAbEd25519YaoActiveClientV1;
  admissionRequest: RouterAbEd25519YaoRegistrationAdmissionRequestV1;
}): Promise<RouterAbEd25519YaoClientSigningInputV1> {
  const message = 'local Yao signing works';
  const recipient = 'local-router.test.near';
  const nonce = base64UrlEncode(randomBytes32());
  const canonicalMessage = routerAbEd25519Nep413CanonicalMessageB64uV2({
    message,
    recipient,
    nonce,
  });
  const admittedDigest = new Uint8Array(
    await globalThis.crypto.subtle.digest('SHA-256', base64UrlDecode(canonicalMessage)),
  );
  const signingWorkerId = input.admissionRequest.scope.signing_worker_id;
  const prepare = await buildRouterAbEd25519Nep413PrepareRequestV2({
    scope: {
      request_id: 'sdk-local-signing-1',
      account_id: input.admissionRequest.scope.account_id,
      session_id: input.admissionRequest.scope.wallet_session_id,
      signing_worker_id: signingWorkerId,
    },
    expiresAtMs: Date.now() + 60_000,
    operationId: 'sdk-local-nep413-1',
    operationFingerprint: 'sdk-local-nep413-fingerprint-1',
    nearAccountId: 'alice.testnet',
    nearNetworkId: 'testnet',
    message,
    recipient,
    nonce,
    expectedSigningDigestB64u: base64UrlEncode(admittedDigest),
  });
  const prepareRaw = await requireOkPublicSigningResult(
    input.signingRouter.handle('prepare', prepare.request),
    'public normal-signing prepare',
  );
  const prepareResponse = parsePrepareResponse(prepareRaw);
  const signingInput: RouterAbEd25519YaoClientSigningInputV1 = {
    admittedDigest,
    signingWorkerCommitments: prepareResponse.serverCommitments,
    signingWorkerVerifyingShare: base64UrlDecode(prepareResponse.serverVerifyingShareB64u),
  };
  const clientShare = await input.activeClient.createSigningShare(signingInput);
  const finalizeRequest = {
    scope: prepare.request.scope,
    expires_at_ms: prepare.request.expires_at_ms,
    prepare_binding: {
      server_round1_handle: prepareResponse.serverRound1Handle,
      round1_binding_digest: prepareResponse.round1BindingDigest,
      intent_digest: prepare.admissionMaterial.intentDigest,
      signing_payload_digest: prepare.admissionMaterial.signingPayloadDigest,
    },
    budget_reservation_id: prepareResponse.budgetReservationId,
    budget_operation_id: prepareResponse.budgetOperationId,
    protocol: {
      kind: 'ed25519_two_party_frost_finalize_v1',
      client_commitments: clientShare.clientCommitments,
      server_commitments: prepareResponse.serverCommitments,
      client_verifying_share_b64u: base64UrlEncode(clientShare.clientVerifyingShare),
      server_verifying_share_b64u: prepareResponse.serverVerifyingShareB64u,
      client_signature_share_b64u: clientShare.clientSignatureShareB64u,
    },
  };
  const signingRaw = await requireOkPublicSigningResult(
    input.signingRouter.handle('finalize', finalizeRequest),
    'public normal-signing finalize',
  );
  const signingResponse = requireRecord(signingRaw, 'normal-signing response');
  const signature = parseCanonicalBytes64(signingResponse.signature, 'normal-signing signature');
  const metadata = input.activeClient.metadata();
  const publicKey = createPublicKey({
    key: Buffer.concat([
      Buffer.from('302a300506032b6570032100', 'hex'),
      Buffer.from(metadata.registeredPublicKey),
    ]),
    format: 'der',
    type: 'spki',
  });
  expect(verify(null, Buffer.from(admittedDigest), publicKey, Buffer.from(signature))).toBe(true);
  const replay = await input.signingRouter.handle('finalize', finalizeRequest);
  expect(replay.status).toBe(409);
  expect(JSON.stringify(replay.body)).toContain('reservation is unavailable');
  return signingInput;
}

async function requireOkPublicSigningResult(
  resultPromise: Promise<LocalPublicSigningRouteResult>,
  label: string,
): Promise<unknown> {
  const result = await resultPromise;
  if (result.status !== 200) {
    throw new Error(`${label} returned HTTP ${result.status}: ${JSON.stringify(result.body)}`);
  }
  return result.body;
}

function parsePrepareResponse(value: unknown): {
  serverRound1Handle: string;
  round1BindingDigest: unknown;
  serverCommitments: Readonly<{ hiding: string; binding: string }>;
  serverVerifyingShareB64u: string;
  budgetReservationId: string;
  budgetOperationId: string;
} {
  const response = requireRecord(value, 'normal-signing prepare response');
  return {
    serverRound1Handle: requireString(response.server_round1_handle, 'server round-one handle'),
    round1BindingDigest: response.round1_binding_digest,
    serverCommitments: parseCommitments(response.server_commitments, 'SigningWorker commitments'),
    serverVerifyingShareB64u: requireString(
      response.server_verifying_share_b64u,
      'SigningWorker verifying share',
    ),
    budgetReservationId: requireString(
      response.budget_reservation_id,
      'normal-signing budget reservation id',
    ),
    budgetOperationId: requireString(
      response.budget_operation_id,
      'normal-signing budget operation id',
    ),
  };
}

function parseCommitments(
  value: unknown,
  label: string,
): Readonly<{ hiding: string; binding: string }> {
  const commitments = requireRecord(value, label);
  return {
    hiding: requireString(commitments.hiding, `${label}.hiding`),
    binding: requireString(commitments.binding, `${label}.binding`),
  };
}

function parseCanonicalBytes64(value: unknown, label: string): Uint8Array {
  const wire = requireRecord(value, label);
  if (!Array.isArray(wire.bytes) || wire.bytes.length !== 64) {
    throw new Error(`${label} must contain 64 bytes`);
  }
  const parsed = wire.bytes.map((entry) => Number(entry));
  if (parsed.some((entry) => !Number.isInteger(entry) || entry < 0 || entry > 255)) {
    throw new Error(`${label} must contain bytes`);
  }
  return Uint8Array.from(parsed);
}

function registrationAdmissionRequest(
  signingWorkerId: string,
): RouterAbEd25519YaoRegistrationAdmissionRequestV1 {
  return {
    scope: {
      lifecycle_id: 'sdk-local-registration-1',
      root_share_epoch: 'epoch-1',
      account_id: 'account-1',
      wallet_session_id: 'wallet-session-1',
      signer_set_id: 'signer-set-1',
      signing_worker_id: signingWorkerId,
    },
    application_binding: {
      wallet_id: 'wallet-sdk-local',
      near_ed25519_signing_key_id: 'ed25519ks_sdk_local',
      signing_root_id: 'project-sdk:local',
      key_creation_signer_slot: 1,
    },
    participant_ids: [1, 2],
  };
}

async function invokeRoute(
  extension: RouterApiRouteExtension,
  path: string,
  body: unknown,
): Promise<Response> {
  const route = requireRouteByPath(extension.routes, path);
  const request = new Request(`http://router.local${path}`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', authorization: 'Bearer local-grant' },
    body: JSON.stringify(body),
  });
  return await extension.handleCloudflareRoute({
    request,
    route,
    pathname: route.path,
    method: 'POST',
    logger: coerceRouterLogger(null),
  });
}

function requireRouteByPath(routes: readonly RouteDefinition[], path: string): RouteDefinition {
  for (const route of routes) {
    if (route.path === path) return route;
  }
  throw new Error(`SDK Router route ${path} is missing`);
}

function randomBytes32(): Uint8Array {
  return globalThis.crypto.getRandomValues(new Uint8Array(32));
}

function isZeroized(bytes: Uint8Array): boolean {
  let aggregate = 0;
  for (const byte of bytes) aggregate |= byte;
  return aggregate === 0;
}

function parseEnvFile(path: string): Readonly<Record<string, string>> {
  const env: Record<string, string> = {};
  for (const line of readFileSync(path, 'utf8').split('\n')) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) continue;
    const separator = trimmed.indexOf('=');
    if (separator <= 0) throw new Error(`invalid local env line: ${trimmed}`);
    env[trimmed.slice(0, separator)] = trimmed.slice(separator + 1);
  }
  return env;
}

function requireEnv(env: Readonly<Record<string, string>>, key: string): string {
  const value = env[key];
  if (!value) throw new Error(`${key} is required`);
  return value;
}

function runCommand(command: string, args: readonly string[]): string {
  const result = spawnSync(command, args, {
    cwd: REPO_ROOT,
    encoding: 'utf8',
    env: process.env,
  });
  if (result.status !== 0) {
    throw new Error(
      `${command} failed with status ${String(result.status)}\n${result.stdout}\n${result.stderr}`,
    );
  }
  return result.stdout;
}

function stopLocalWorkers(root: string): void {
  const binary = join(DEV_TARGET, 'router_ab_local_down');
  const result = spawnSync(binary, ['--root', root], {
    cwd: REPO_ROOT,
    encoding: 'utf8',
    env: process.env,
  });
  if (result.error) return;
}

function requireRecord(value: unknown, label: string): Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error(`${label} must be an object`);
  }
  return Object.fromEntries(Object.entries(value));
}

function requireString(value: unknown, label: string): string {
  if (typeof value !== 'string') throw new Error(`${label} must be a string`);
  return value;
}

async function requireOkJson(response: Response, label: string): Promise<unknown> {
  const body: unknown = await response.json();
  if (response.status !== 200) {
    throw new Error(`${label} returned HTTP ${response.status}: ${JSON.stringify(body)}`);
  }
  return body;
}

function assertNever(value: never): never {
  throw new Error(`Unhandled local Yao state: ${String(value)}`);
}

test(
  'registers and signs through SDK Router, WASM, A, B, and SigningWorker boundaries',
  runLocalRegistrationTest,
);
