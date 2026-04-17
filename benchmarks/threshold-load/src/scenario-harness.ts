#!/usr/bin/env node
import http from 'node:http';
import expressImport from 'express';
import { performance } from 'node:perf_hooks';
import { AuthService } from '../../../server/src/core/AuthService.ts';
import {
  createThresholdSigningService,
  type SigningRootShareId,
  type SigningRootShareProvider,
  type SealedSigningRootShareRecord,
} from '../../../server/src/core/ThresholdService/index.ts';
import { createRelayRouter } from '../../../server/src/router/express-adaptor.ts';
import { Ed25519WalletActor } from './actors/ed25519Wallet.mjs';
import { startSystemStatsCollector, summarizeNumbers } from './system-stats.mjs';

type ExpressMiddleware = (req: unknown, res: unknown, next: (err?: unknown) => void) => unknown;
type ExpressAppLike = ((req: unknown, res: unknown) => unknown) & {
  use: (...args: unknown[]) => unknown;
};
type ExpressLike = { (): ExpressAppLike; json: (options?: unknown) => ExpressMiddleware };

const express: ExpressLike = (() => {
  const maybeDefault = (expressImport as unknown as { default?: unknown }).default;
  if (typeof maybeDefault === 'function') return maybeDefault as ExpressLike;
  return expressImport as unknown as ExpressLike;
})();

const THRESHOLD_ED25519_KEY_VERSION_V1 = 'threshold-ed25519-hss-v1';
const SUMMARY_MARKER = '@@THRESHOLD_LOAD_SUMMARY@@';
const SIGNING_ROOT_SHARE_WIRES: ReadonlyArray<{
  readonly shareId: SigningRootShareId;
  readonly wireHex: string;
}> = [
  {
    shareId: 1,
    wireHex: '011ba5f9c2f4003d409a9358a20b40b37eb32a28daacc5676a468b64a203c1e303',
  },
  {
    shareId: 2,
    wireHex: '021bb9834016ae79b9a815f68d1f456b35acb1b5631dd04e1cab9f640852aaed0d',
  },
  {
    shareId: 3,
    wireHex: '032ef917611df8a3dae0fa9bd6545044d7a43843ed8dda35ce0fb4646ea093f707',
  },
];

type ParsedArgs = {
  scenarioId: string;
  wallets: number;
  signsPerWallet: number;
  maxConcurrency: number;
  profile: 'steady' | 'burst';
};

function parseArgs(argv: string[]): ParsedArgs {
  const out: ParsedArgs = {
    scenarioId: 'ed25519_local_steady',
    wallets: 6,
    signsPerWallet: 2,
    maxConcurrency: 3,
    profile: 'steady',
  };

  for (let index = 0; index < argv.length; index += 1) {
    const token = argv[index];
    if (token === '--scenario' && argv[index + 1]) {
      out.scenarioId = String(argv[++index]).trim();
      continue;
    }
    if (token === '--wallets' && argv[index + 1]) {
      out.wallets = Math.max(1, Math.floor(Number(argv[++index] || out.wallets)));
      continue;
    }
    if (token === '--signs-per-wallet' && argv[index + 1]) {
      out.signsPerWallet = Math.max(1, Math.floor(Number(argv[++index] || out.signsPerWallet)));
      continue;
    }
    if (token === '--max-concurrency' && argv[index + 1]) {
      out.maxConcurrency = Math.max(1, Math.floor(Number(argv[++index] || out.maxConcurrency)));
      continue;
    }
    if (token === '--profile' && argv[index + 1]) {
      const profile = String(argv[++index]).trim().toLowerCase();
      out.profile = profile === 'burst' ? 'burst' : 'steady';
      continue;
    }
  }
  return out;
}

function toBase64UrlUtf8(json: string): string {
  return Buffer.from(json, 'utf8').toString('base64url');
}

function fromBase64UrlUtf8(b64u: string): string {
  return Buffer.from(b64u, 'base64url').toString('utf8');
}

function createBenchmarkSigningRootShareProvider(): SigningRootShareProvider {
  const shares = new Map<SigningRootShareId, Uint8Array>(
    SIGNING_ROOT_SHARE_WIRES.map((share) => [
      share.shareId,
      new Uint8Array(Buffer.from(share.wireHex, 'hex')),
    ]),
  );
  return {
    listSealedSigningRootShares: async (input) =>
      Array.from(shares.keys())
        .sort((a, b) => a - b)
        .map(
          (shareId): SealedSigningRootShareRecord => ({
            projectId: input.projectId,
            ...(input.rootVersion ? { rootVersion: input.rootVersion } : {}),
            shareId,
            sealedShare: new Uint8Array([shareId]),
            storageId: `benchmark-signing-root-${shareId}`,
            kekId: 'benchmark-fixture',
          }),
        ),
    decryptSigningRootShare: async (record) => {
      const wire = shares.get(record.shareId);
      if (!wire) throw new Error(`missing benchmark signing-root share ${record.shareId}`);
      return new Uint8Array(wire);
    },
  };
}

function createSessionAdapter() {
  return {
    signJwt: async (sub: string, extra?: Record<string, unknown>) => {
      const claims = { sub, ...(extra || {}) };
      return `testjwt-${toBase64UrlUtf8(JSON.stringify(claims))}`;
    },
    parse: async (headers: Record<string, string | string[] | undefined>) => {
      const authHeaderRaw = headers['authorization'] ?? headers['Authorization'];
      const authHeader = Array.isArray(authHeaderRaw) ? authHeaderRaw[0] : authHeaderRaw;
      const token =
        typeof authHeader === 'string' ? authHeader.replace(/^Bearer\s+/i, '').trim() : '';
      if (!token.startsWith('testjwt-')) return { ok: false as const };
      try {
        const claims = JSON.parse(fromBase64UrlUtf8(token.slice('testjwt-'.length))) as unknown;
        if (!claims || typeof claims !== 'object' || Array.isArray(claims)) {
          return { ok: false as const };
        }
        return { ok: true as const, claims: claims as Record<string, unknown> };
      } catch {
        return { ok: false as const };
      }
    },
    buildSetCookie: (token: string) =>
      `tatchi-jwt=${token}; Path=/; HttpOnly; Secure; SameSite=Lax`,
    buildClearCookie: () => `tatchi-jwt=; Path=/; Max-Age=0`,
    refresh: async () => ({ ok: false as const, code: 'not_eligible', message: 'not eligible' }),
  };
}

async function startExpressRouter(router: unknown): Promise<{
  baseUrl: string;
  close: () => Promise<void>;
}> {
  const app = express();
  app.use(express.json({ limit: '1mb' }));
  app.use(router);

  const server: http.Server = http.createServer(app);
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));

  const address = server.address();
  if (!address || typeof address === 'string') {
    throw new Error('Failed to bind benchmark relay server');
  }

  return {
    baseUrl: `http://127.0.0.1:${address.port}`,
    close: () =>
      new Promise<void>((resolve, reject) => {
        server.close((error) => (error ? reject(error) : resolve()));
      }),
  };
}

function createRouteDurationMap(routeTimings: Array<{ route: string; durationMs: number }>) {
  const grouped = new Map<string, number[]>();
  for (const entry of routeTimings) {
    const list = grouped.get(entry.route) || [];
    list.push(entry.durationMs);
    grouped.set(entry.route, list);
  }
  const out: Record<string, ReturnType<typeof summarizeNumbers>> = {};
  for (const [route, values] of grouped.entries()) {
    out[route] = summarizeNumbers(values);
  }
  return out;
}

async function runLimited<T, R>(
  items: T[],
  limit: number,
  fn: (item: T, index: number) => Promise<R>,
): Promise<Array<PromiseSettledResult<R>>> {
  const results: Array<PromiseSettledResult<R>> = new Array(items.length);
  let cursor = 0;

  async function worker() {
    while (true) {
      const index = cursor;
      cursor += 1;
      if (index >= items.length) return;
      try {
        const value = await fn(items[index] as T, index);
        results[index] = { status: 'fulfilled', value };
      } catch (reason) {
        results[index] = { status: 'rejected', reason };
      }
    }
  }

  const workers = Array.from({ length: Math.min(limit, items.length) }, () => worker());
  await Promise.all(workers);
  return results;
}

async function createLocalRelayContext() {
  const keysOnChainByAccount = new Map<string, Set<string>>();
  const thresholdConfig = {
    kind: 'in-memory',
    THRESHOLD_NODE_ROLE: 'coordinator',
    signingRootShareProvider: createBenchmarkSigningRootShareProvider(),
  } as const;

  const service = new AuthService({
    relayerAccount: 'relayer.testnet',
    relayerPrivateKey: 'ed25519:dummy',
    nearRpcUrl: 'https://rpc.testnet.near.org',
    networkId: 'testnet',
    accountInitialBalance: '1',
    createAccountAndRegisterGas: '1',
    thresholdStore: thresholdConfig,
    logger: null,
  });

  (
    service as unknown as {
      verifyWebAuthnAuthenticationLite: (
        req: unknown,
      ) => Promise<{ success: boolean; verified: boolean }>;
    }
  ).verifyWebAuthnAuthenticationLite = async (_req: unknown) => ({ success: true, verified: true });

  (
    service as unknown as {
      nearClient: { viewAccessKeyList: (accountId: string) => Promise<unknown> };
    }
  ).nearClient.viewAccessKeyList = async (accountId: string) => {
    const keys = Array.from(keysOnChainByAccount.get(accountId) || []).map((publicKey) => ({
      public_key: publicKey,
      access_key: { nonce: 0, permission: 'FullAccess' as const },
    }));
    return { keys };
  };

  const threshold = createThresholdSigningService({
    authService: service,
    thresholdStore: thresholdConfig,
    logger: null,
  });

  const router = createRelayRouter(service, { threshold, session: createSessionAdapter() });
  const server = await startExpressRouter(router);

  return {
    baseUrl: server.baseUrl,
    close: server.close,
    threshold,
    putRelayerKeyMaterial: async (record: {
      relayerKeyId: string;
      nearAccountId: string;
      rpId: string;
      publicKey: string;
      relayerSigningShareB64u: string;
      relayerVerifyingShareB64u: string;
      keyVersion: string;
      recoveryExportCapable: true;
    }) => {
      await (
        threshold as unknown as {
          keyStore: { put: (keyId: string, value: unknown) => Promise<void> };
        }
      ).keyStore.put(record.relayerKeyId, {
        nearAccountId: record.nearAccountId,
        rpId: record.rpId,
        publicKey: record.publicKey,
        relayerSigningShareB64u: record.relayerSigningShareB64u,
        relayerVerifyingShareB64u: record.relayerVerifyingShareB64u,
        keyVersion: record.keyVersion,
        recoveryExportCapable: true,
      });
    },
    markAccessKeyOnChain: (nearAccountId: string, publicKey: string) => {
      const existing = keysOnChainByAccount.get(nearAccountId) || new Set<string>();
      existing.add(publicKey);
      keysOnChainByAccount.set(nearAccountId, existing);
    },
  };
}

async function runEd25519Scenario(args: ParsedArgs) {
  const relay = await createLocalRelayContext();
  try {
    const actors = Array.from({ length: args.wallets }, (_, walletIndex) => {
      const accountId = `bench-wallet-${walletIndex + 1}.testnet`;
      return new Ed25519WalletActor({
        walletIndex: walletIndex + 1,
        baseUrl: relay.baseUrl,
        nearAccountId: accountId,
        receiverId: 'receiver.testnet',
        rpId: 'bench.example.localhost',
        clientParticipantId: 1,
        relayerParticipantId: 2,
        sessionTtlMs: 300000,
        remainingUses: args.signsPerWallet + 2,
        keyVersion: THRESHOLD_ED25519_KEY_VERSION_V1,
      });
    });

    const bootstrapStartedAt = performance.now();
    const bootstrapResults = await runLimited(
      actors,
      Math.min(args.maxConcurrency, actors.length),
      (actor) =>
        actor.bootstrap({
          putRelayerKeyMaterial: relay.putRelayerKeyMaterial,
          markAccessKeyOnChain: relay.markAccessKeyOnChain,
        }),
    );
    const bootstrapDurationMs = Number((performance.now() - bootstrapStartedAt).toFixed(2));

    const bootstrapFailures = bootstrapResults.filter((entry) => entry.status === 'rejected');
    if (bootstrapFailures.length > 0) {
      throw new Error(
        `wallet bootstrap failed: ${String(bootstrapFailures[0]?.reason?.message || bootstrapFailures[0]?.reason || 'unknown')}`,
      );
    }

    const bootstrapFulfilled = bootstrapResults
      .filter(
        (
          entry,
        ): entry is PromiseFulfilledResult<{
          bootstrapMs: number;
          sessionMintMs: number;
          routeTimings: Array<{ route: string; durationMs: number }>;
        }> => entry.status === 'fulfilled',
      )
      .map((entry) => entry.value);

    const bootstrapRouteTimings = bootstrapFulfilled.flatMap((entry) => entry.routeTimings);
    const systemCollector = startSystemStatsCollector({ sampleIntervalMs: 200 });
    const signingStartedAt = performance.now();

    let signResults: Array<
      PromiseSettledResult<{
        endToEndMs: number;
        routeTimings: Array<{ route: string; durationMs: number }>;
      }>
    >;
    if (args.profile === 'burst') {
      const rounds = Array.from({ length: args.signsPerWallet }, (_, roundIndex) => roundIndex);
      const settled: Array<
        PromiseSettledResult<{
          endToEndMs: number;
          routeTimings: Array<{ route: string; durationMs: number }>;
        }>
      > = [];
      for (const _round of rounds) {
        const wave = await Promise.allSettled(actors.map((actor) => actor.signOnce()));
        settled.push(...wave);
      }
      signResults = settled;
    } else {
      const work = actors.flatMap((actor) =>
        Array.from({ length: args.signsPerWallet }, () => actor),
      );
      signResults = await runLimited(work, args.maxConcurrency, (actor) => actor.signOnce());
    }

    const signingDurationMs = Number((performance.now() - signingStartedAt).toFixed(2));
    const system = systemCollector.stop();

    const successfulSigns = signResults.filter(
      (
        entry,
      ): entry is PromiseFulfilledResult<{
        endToEndMs: number;
        routeTimings: Array<{ route: string; durationMs: number }>;
      }> => entry.status === 'fulfilled',
    );
    const failedSigns = signResults.filter((entry) => entry.status === 'rejected');
    const routeTimings = successfulSigns.flatMap((entry) => entry.value.routeTimings);
    const endToEndMs = successfulSigns.map((entry) => entry.value.endToEndMs);
    const totalAttempts = signResults.length;
    const totalSuccess = successfulSigns.length;
    const totalFailure = failedSigns.length;

    return {
      reportVersion: 'threshold_load_scenario_v1',
      curve: 'ed25519',
      topology: 'local_2p',
      mode: 'warm_touchless',
      scenarioId: args.scenarioId,
      profile: args.profile,
      wallets: args.wallets,
      signsPerWallet: args.signsPerWallet,
      maxConcurrency: args.maxConcurrency,
      bootstrap: {
        durationMs: bootstrapDurationMs,
        sessionMintMs: summarizeNumbers(bootstrapFulfilled.map((entry) => entry.sessionMintMs)),
        routeDurations: createRouteDurationMap(bootstrapRouteTimings),
      },
      signing: {
        durationMs: signingDurationMs,
        totalAttempts,
        totalSuccess,
        totalFailure,
        successRate: totalAttempts > 0 ? totalSuccess / totalAttempts : null,
        throughputSignsPerSec:
          signingDurationMs > 0
            ? Number(((totalSuccess * 1000) / signingDurationMs).toFixed(4))
            : null,
        endToEndMs: summarizeNumbers(endToEndMs),
        routeDurations: createRouteDurationMap(routeTimings),
      },
      system,
    };
  } finally {
    await relay.close();
  }
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  if (!args.scenarioId.startsWith('ed25519_local_')) {
    throw new Error(`Unsupported scenario: ${args.scenarioId}`);
  }

  console.log(
    `[threshold-load] scenario=${args.scenarioId} profile=${args.profile} wallets=${args.wallets} signs_per_wallet=${args.signsPerWallet} max_concurrency=${args.maxConcurrency}`,
  );
  const summary = await runEd25519Scenario(args);
  console.log(SUMMARY_MARKER + JSON.stringify(summary));
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
