import { expect, test } from '@playwright/test';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { type RouterAbEd25519YaoRegistrationAdmissionRequestV1 } from '@shared/utils/routerAbEd25519Yao';
import { coerceRouterLogger } from '../../packages/sdk-server-ts/src/router/framework/logger';
import { createRouterAbEd25519YaoHttpRegistrationBackendFromEnv } from '../../packages/sdk-server-ts/src/router/domains/ed25519Yao/registration/routerAbEd25519YaoHttpRegistrationBackend';
import {
  InMemoryRouterAbEd25519YaoRegistrationService,
  createRouterAbEd25519YaoRegistrationModule,
  type RouterAbEd25519YaoRegistrationAuthorizationAdapter,
  type RouterAbEd25519YaoRegistrationAuthorizationInput,
  type RouterAbEd25519YaoRegistrationAuthorizationResult,
} from '../../packages/sdk-server-ts/src/router/domains/ed25519Yao/registration/routerAbEd25519YaoRegistration';
import type { RouterApiRouteExtension } from '../../packages/sdk-server-ts/src/router/framework/routeExtensions';
import type { RouteDefinition } from '../../packages/sdk-server-ts/src/router/framework/routeDefinitions';
import {
  RouterAbEd25519YaoClientV1,
  type RouterAbEd25519YaoRegistrationTransportRequestV1,
  type RouterAbEd25519YaoRegistrationTransportResultV1,
  type RouterAbEd25519YaoRegistrationTransportV1,
} from '../../packages/sdk-web/src/core/signingEngine/threshold/ed25519/yaoClient';
import { base64UrlEncode } from '../../packages/shared-ts/src/utils/base64';

const REPO_ROOT = fileURLToPath(new URL('../..', import.meta.url));
const DEV_MANIFEST = join(REPO_ROOT, 'crates/router-ab-dev/Cargo.toml');
const DEV_TARGET = join(REPO_ROOT, 'crates/router-ab-dev/target/debug');
const CLIENT_CRATE = join(REPO_ROOT, 'crates/router-ab-ed25519-yao-client');
const ROUTER_ENV_FILE = '.env.router-ab.router.local';

type LocalProcessState = { kind: 'running' } | { kind: 'stopped' };


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

      const retriedExecution = await transport.retryRecordedExecution();
      expect(retriedExecution.retry).toEqual(retriedExecution.first);

      activeClient.dispose();
      expect(() => activeClient.metadata()).toThrow('Ed25519 Yao Client state is disposed');
    } finally {
      activeClient.dispose();
    }
  } finally {
    processes.stop();
  }
}

function registrationAdmissionRequest(
  signingWorkerId: string,
): RouterAbEd25519YaoRegistrationAdmissionRequestV1 {
  return {
    scope: {
      lifecycle_id: 'sdk-local-registration-1',
      root_share_epoch: 'epoch-1',
      account_id: 'account-1',
      threshold_session_id: 'wallet-session-1',
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
