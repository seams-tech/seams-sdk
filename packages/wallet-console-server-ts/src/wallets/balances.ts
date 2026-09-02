import {
  d1Integer,
  parseD1JsonColumn,
  type D1DatabaseLike,
  type D1Row,
} from '@seams/wallet-server/cloud-host';
import { ConsoleWalletError } from './errors';
import type {
  ConsoleWalletBalanceRefreshResult,
  ConsoleWalletService,
  ConsoleWalletsContext,
  RefreshConsoleWalletBalancesRequest,
} from './service';
import type { ConsoleWallet, ConsoleWalletGasBalances } from './types';

const DEFAULT_NEAR_RPC_URL = 'https://rpc.testnet.near.org';
const DEFAULT_TEMPO_RPC_URL = 'https://rpc.moderato.tempo.xyz';
const DEFAULT_ARC_RPC_URL = 'https://rpc.drpc.testnet.arc.network';
const TEMPO_ALPHA_USD_TOKEN = '0x20c0000000000000000000000000000000000001';
const BALANCE_OF_SELECTOR = '0x70a08231';
const BALANCE_CACHE_TTL_MS = 5 * 60 * 1_000;
const MAX_REFRESH_WALLETS = 10;
const RPC_TIMEOUT_MS = 8_000;
const TEMPO_ALPHA_USD_MINOR_DIVISOR = 10_000n;
const ARC_NATIVE_MINOR_DIVISOR = 10_000_000_000_000_000n;

type JsonRecord = Record<string, unknown>;

type WalletSignerIdentity = {
  readonly nearAccountId: string;
  readonly evmAddress: `0x${string}`;
};

type WalletBalanceSnapshot = {
  readonly walletId: string;
  readonly nearAccountId: string;
  readonly evmAddress: `0x${string}`;
  readonly nearBalanceYocto: string;
  readonly tempoAlphaUsdRaw: string;
  readonly arcBalanceWei: string;
  readonly stablecoinBalanceMinor: number;
  readonly funded: boolean;
  readonly observedAtMs: number;
};

type WalletRefreshOutcome =
  | {
      readonly kind: 'refreshed';
      readonly snapshot: WalletBalanceSnapshot;
    }
  | {
      readonly kind: 'failed';
      readonly walletId: string;
      readonly message: string;
    };

type JsonRpcResponse = {
  readonly result?: unknown;
  readonly error?: unknown;
};

class JsonRpcRequestError extends Error {
  constructor(
    message: string,
    readonly causeName: string,
  ) {
    super(message);
    this.name = 'JsonRpcRequestError';
  }
}

export interface D1ConsoleWalletBalanceReaderOptions {
  readonly signerDatabase: D1DatabaseLike;
  readonly nearRpcUrl?: string;
  readonly tempoRpcUrl?: string;
  readonly arcRpcUrl?: string;
  readonly fetchImpl?: typeof fetch;
}

export interface RefreshD1ConsoleWalletBalancesInput {
  readonly consoleDatabase: D1DatabaseLike;
  readonly namespace: string;
  readonly now: () => Date;
  readonly reader: D1ConsoleWalletBalanceReaderOptions;
  readonly ctx: ConsoleWalletsContext;
  readonly wallets: readonly ConsoleWallet[];
}

function isJsonRecord(value: unknown): value is JsonRecord {
  return Boolean(value && typeof value === 'object' && !Array.isArray(value));
}

function requiredString(value: unknown, label: string): string {
  const normalized = String(value || '').trim();
  if (!normalized) throw new Error(`${label} is missing`);
  return normalized;
}

function parseEvmAddress(value: unknown, label: string): `0x${string}` {
  const normalized = requiredString(value, label).toLowerCase();
  if (!/^0x[0-9a-f]{40}$/.test(normalized)) {
    throw new Error(`${label} is invalid`);
  }
  return normalized as `0x${string}`;
}

function parseHexQuantity(value: unknown, label: string): bigint {
  const normalized = requiredString(value, label);
  if (!/^0x[0-9a-fA-F]+$/.test(normalized)) {
    throw new Error(`${label} is invalid`);
  }
  return BigInt(normalized);
}

function parseUnsignedDecimal(value: unknown, label: string): bigint {
  const normalized = requiredString(value, label);
  if (!/^\d+$/.test(normalized)) throw new Error(`${label} is invalid`);
  return BigInt(normalized);
}

function stablecoinMinorToNumber(value: bigint): number {
  if (value > BigInt(Number.MAX_SAFE_INTEGER)) return Number.MAX_SAFE_INTEGER;
  return Number(value);
}

function jsonRpcRequestError(raw: unknown, method: string): JsonRpcRequestError {
  const error = isJsonRecord(raw) ? raw : null;
  const cause = isJsonRecord(error?.cause) ? error.cause : null;
  const message = String(error?.data || error?.message || '').trim() || `${method} failed`;
  return new JsonRpcRequestError(message, String(cause?.name || '').trim());
}

function uniqueWalletIds(raw: readonly string[]): readonly string[] {
  const walletIds = raw.map((value) => String(value || '').trim()).filter(Boolean);
  const unique = [...new Set(walletIds)];
  if (unique.length === 0) {
    throw new ConsoleWalletError(
      'invalid_body',
      400,
      'walletIds must contain at least one wallet id',
    );
  }
  if (unique.length > MAX_REFRESH_WALLETS) {
    throw new ConsoleWalletError(
      'invalid_body',
      400,
      `walletIds cannot contain more than ${MAX_REFRESH_WALLETS} wallet ids`,
    );
  }
  return unique;
}

export function parseRefreshConsoleWalletBalancesRequest(
  raw: unknown,
): RefreshConsoleWalletBalancesRequest {
  if (!isJsonRecord(raw) || !Array.isArray(raw.walletIds)) {
    throw new ConsoleWalletError('invalid_body', 400, 'walletIds must be an array');
  }
  if (raw.walletIds.some((value) => typeof value !== 'string')) {
    throw new ConsoleWalletError('invalid_body', 400, 'walletIds must contain only strings');
  }
  return { walletIds: uniqueWalletIds(raw.walletIds) };
}

async function postJsonRpc(input: {
  readonly fetchImpl: typeof fetch;
  readonly rpcUrl: string;
  readonly method: string;
  readonly params: readonly unknown[] | JsonRecord;
}): Promise<unknown> {
  const controller = new AbortController();
  const timeoutId = globalThis.setTimeout(() => controller.abort(), RPC_TIMEOUT_MS);
  try {
    const response = await input.fetchImpl(input.rpcUrl, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        jsonrpc: '2.0',
        id: Date.now(),
        method: input.method,
        params: input.params,
      }),
      signal: controller.signal,
    });
    if (!response.ok) throw new Error(`${input.method} returned HTTP ${response.status}`);
    const raw: unknown = await response.json();
    if (!isJsonRecord(raw)) throw new Error(`${input.method} returned an invalid response`);
    const payload: JsonRpcResponse = raw;
    if (payload.error !== undefined) {
      throw jsonRpcRequestError(payload.error, input.method);
    }
    if (!Object.prototype.hasOwnProperty.call(payload, 'result')) {
      throw new Error(`${input.method} returned no result`);
    }
    return payload.result;
  } finally {
    globalThis.clearTimeout(timeoutId);
  }
}

async function readNearBalance(input: {
  readonly fetchImpl: typeof fetch;
  readonly rpcUrl: string;
  readonly nearAccountId: string;
}): Promise<bigint> {
  try {
    const result = await postJsonRpc({
      fetchImpl: input.fetchImpl,
      rpcUrl: input.rpcUrl,
      method: 'query',
      params: {
        request_type: 'view_account',
        finality: 'final',
        account_id: input.nearAccountId,
      },
    });
    if (!isJsonRecord(result)) throw new Error('NEAR view_account returned an invalid result');
    return parseUnsignedDecimal(result.amount, 'NEAR account balance');
  } catch (error: unknown) {
    if (error instanceof JsonRpcRequestError && error.causeName === 'UNKNOWN_ACCOUNT') return 0n;
    throw error;
  }
}

async function readTempoAlphaUsdBalance(input: {
  readonly fetchImpl: typeof fetch;
  readonly rpcUrl: string;
  readonly evmAddress: `0x${string}`;
}): Promise<bigint> {
  const encodedAddress = input.evmAddress.slice(2).padStart(64, '0');
  const result = await postJsonRpc({
    fetchImpl: input.fetchImpl,
    rpcUrl: input.rpcUrl,
    method: 'eth_call',
    params: [
      {
        to: TEMPO_ALPHA_USD_TOKEN,
        data: `${BALANCE_OF_SELECTOR}${encodedAddress}`,
      },
      'latest',
    ],
  });
  return parseHexQuantity(result, 'Tempo AlphaUSD balance');
}

async function readArcBalance(input: {
  readonly fetchImpl: typeof fetch;
  readonly rpcUrl: string;
  readonly evmAddress: `0x${string}`;
}): Promise<bigint> {
  const result = await postJsonRpc({
    fetchImpl: input.fetchImpl,
    rpcUrl: input.rpcUrl,
    method: 'eth_getBalance',
    params: [input.evmAddress, 'latest'],
  });
  return parseHexQuantity(result, 'Arc native balance');
}

async function readWalletBalanceSnapshot(input: {
  readonly walletId: string;
  readonly identity: WalletSignerIdentity;
  readonly observedAtMs: number;
  readonly reader: D1ConsoleWalletBalanceReaderOptions;
}): Promise<WalletBalanceSnapshot> {
  const fetchImpl = input.reader.fetchImpl || fetch.bind(globalThis);
  const [nearBalanceYocto, tempoAlphaUsdRaw, arcBalanceWei] = await Promise.all([
    readNearBalance({
      fetchImpl,
      rpcUrl: String(input.reader.nearRpcUrl || DEFAULT_NEAR_RPC_URL).trim(),
      nearAccountId: input.identity.nearAccountId,
    }),
    readTempoAlphaUsdBalance({
      fetchImpl,
      rpcUrl: String(input.reader.tempoRpcUrl || DEFAULT_TEMPO_RPC_URL).trim(),
      evmAddress: input.identity.evmAddress,
    }),
    readArcBalance({
      fetchImpl,
      rpcUrl: String(input.reader.arcRpcUrl || DEFAULT_ARC_RPC_URL).trim(),
      evmAddress: input.identity.evmAddress,
    }),
  ]);
  const stablecoinBalanceMinor = stablecoinMinorToNumber(
    tempoAlphaUsdRaw / TEMPO_ALPHA_USD_MINOR_DIVISOR + arcBalanceWei / ARC_NATIVE_MINOR_DIVISOR,
  );
  return {
    walletId: input.walletId,
    nearAccountId: input.identity.nearAccountId,
    evmAddress: input.identity.evmAddress,
    nearBalanceYocto: nearBalanceYocto.toString(),
    tempoAlphaUsdRaw: tempoAlphaUsdRaw.toString(),
    arcBalanceWei: arcBalanceWei.toString(),
    stablecoinBalanceMinor,
    funded: nearBalanceYocto > 0n || tempoAlphaUsdRaw > 0n || arcBalanceWei > 0n,
    observedAtMs: input.observedAtMs,
  };
}

function signerProjectMatchesWallet(row: D1Row, wallet: ConsoleWallet): boolean {
  const projectId = String(row.project_id || '').trim();
  return projectId === wallet.projectId;
}

function signerRecord(row: D1Row): JsonRecord | null {
  const parsed = parseD1JsonColumn(row.record_json);
  return isJsonRecord(parsed) ? parsed : null;
}

function resolveWalletSignerIdentity(
  wallet: ConsoleWallet,
  signerRows: readonly D1Row[],
): WalletSignerIdentity {
  let nearAccountId = '';
  let evmAddress: `0x${string}` | null = null;
  for (const row of signerRows) {
    if (
      String(row.wallet_id || '').trim() !== wallet.id ||
      !signerProjectMatchesWallet(row, wallet)
    ) {
      continue;
    }
    const record = signerRecord(row);
    if (!record) continue;
    const family = String(row.signer_family || '').trim();
    if (family === 'ed25519') {
      nearAccountId = String(record.nearAccountId || '').trim() || nearAccountId;
      continue;
    }
    if (family === 'ecdsa' && isJsonRecord(record.walletKey)) {
      const candidate = String(record.walletKey.thresholdOwnerAddress || '').trim();
      if (candidate) evmAddress = parseEvmAddress(candidate, 'threshold owner address');
    }
  }
  if (!nearAccountId || !evmAddress) {
    throw new Error('wallet signer identities are incomplete');
  }
  return { nearAccountId, evmAddress };
}

async function loadFreshSnapshotWalletIds(input: {
  readonly database: D1DatabaseLike;
  readonly namespace: string;
  readonly orgId: string;
  readonly walletIds: readonly string[];
  readonly staleBeforeMs: number;
}): Promise<ReadonlySet<string>> {
  if (input.walletIds.length === 0) return new Set();
  const placeholders = input.walletIds.map(() => '?').join(', ');
  const out = await input.database
    .prepare(
      `SELECT wallet_id, observed_at_ms
         FROM wallet_balance_snapshots
        WHERE namespace = ?
          AND org_id = ?
          AND wallet_id IN (${placeholders})`,
    )
    .bind(input.namespace, input.orgId, ...input.walletIds)
    .all<D1Row>();
  return new Set(
    (out.results || [])
      .filter((row) => d1Integer(row.observed_at_ms) >= input.staleBeforeMs)
      .map((row) => String(row.wallet_id || '').trim())
      .filter(Boolean),
  );
}

async function loadSignerRows(input: {
  readonly database: D1DatabaseLike;
  readonly namespace: string;
  readonly orgId: string;
  readonly walletIds: readonly string[];
}): Promise<readonly D1Row[]> {
  if (input.walletIds.length === 0) return [];
  const placeholders = input.walletIds.map(() => '?').join(', ');
  const out = await input.database
    .prepare(
      `SELECT project_id, env_id, wallet_id, signer_family, record_json
         FROM wallet_signers
        WHERE namespace = ?
          AND org_id = ?
          AND wallet_id IN (${placeholders})`,
    )
    .bind(input.namespace, input.orgId, ...input.walletIds)
    .all<D1Row>();
  return out.results || [];
}

async function refreshWallet(input: {
  readonly wallet: ConsoleWallet;
  readonly signerRows: readonly D1Row[];
  readonly observedAtMs: number;
  readonly reader: D1ConsoleWalletBalanceReaderOptions;
}): Promise<WalletRefreshOutcome> {
  try {
    const identity = resolveWalletSignerIdentity(input.wallet, input.signerRows);
    const snapshot = await readWalletBalanceSnapshot({
      walletId: input.wallet.id,
      identity,
      observedAtMs: input.observedAtMs,
      reader: input.reader,
    });
    return { kind: 'refreshed', snapshot };
  } catch (error: unknown) {
    return {
      kind: 'failed',
      walletId: input.wallet.id,
      message: error instanceof Error ? error.message : String(error),
    };
  }
}

function snapshotStatements(input: {
  readonly database: D1DatabaseLike;
  readonly namespace: string;
  readonly orgId: string;
  readonly snapshot: WalletBalanceSnapshot;
}) {
  const snapshot = input.snapshot;
  return [
    input.database
      .prepare(
        `INSERT INTO wallet_balance_snapshots (
           namespace,
           org_id,
           wallet_id,
           near_account_id,
           evm_address,
           near_balance_yocto,
           tempo_alpha_usd_raw,
           arc_balance_wei,
           stablecoin_balance_minor,
           funded,
           observed_at_ms
         )
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
         ON CONFLICT (namespace, org_id, wallet_id)
         DO UPDATE SET
           near_account_id = EXCLUDED.near_account_id,
           evm_address = EXCLUDED.evm_address,
           near_balance_yocto = EXCLUDED.near_balance_yocto,
           tempo_alpha_usd_raw = EXCLUDED.tempo_alpha_usd_raw,
           arc_balance_wei = EXCLUDED.arc_balance_wei,
           stablecoin_balance_minor = EXCLUDED.stablecoin_balance_minor,
           funded = EXCLUDED.funded,
           observed_at_ms = EXCLUDED.observed_at_ms`,
      )
      .bind(
        input.namespace,
        input.orgId,
        snapshot.walletId,
        snapshot.nearAccountId,
        snapshot.evmAddress,
        snapshot.nearBalanceYocto,
        snapshot.tempoAlphaUsdRaw,
        snapshot.arcBalanceWei,
        snapshot.stablecoinBalanceMinor,
        snapshot.funded ? 1 : 0,
        snapshot.observedAtMs,
      ),
    input.database
      .prepare(
        `UPDATE wallet_index
            SET balance_minor = ?,
                updated_at_ms = ?
          WHERE namespace = ?
            AND org_id = ?
            AND id = ?`,
      )
      .bind(
        snapshot.stablecoinBalanceMinor,
        snapshot.observedAtMs,
        input.namespace,
        input.orgId,
        snapshot.walletId,
      ),
  ];
}

function applySnapshots(
  wallets: readonly ConsoleWallet[],
  snapshots: readonly WalletBalanceSnapshot[],
): ConsoleWallet[] {
  const snapshotsByWalletId = new Map(snapshots.map((snapshot) => [snapshot.walletId, snapshot]));
  return wallets.map((wallet) => {
    const snapshot = snapshotsByWalletId.get(wallet.id);
    if (!snapshot) return wallet;
    return {
      ...wallet,
      balanceMinor: snapshot.stablecoinBalanceMinor,
      funded: snapshot.funded,
      gasBalances: gasBalancesFromSnapshot(snapshot),
      updatedAt: new Date(snapshot.observedAtMs).toISOString(),
    };
  });
}

function gasBalancesFromSnapshot(snapshot: WalletBalanceSnapshot): ConsoleWalletGasBalances {
  return {
    observedAt: new Date(snapshot.observedAtMs).toISOString(),
    near: {
      accountId: snapshot.nearAccountId,
      balanceYocto: snapshot.nearBalanceYocto,
    },
    tempo: {
      address: snapshot.evmAddress,
      alphaUsdRaw: snapshot.tempoAlphaUsdRaw,
    },
    arc: {
      address: snapshot.evmAddress,
      usdcRaw: snapshot.arcBalanceWei,
    },
  };
}

export async function refreshD1ConsoleWalletBalances(
  input: RefreshD1ConsoleWalletBalancesInput,
): Promise<ConsoleWalletBalanceRefreshResult> {
  const wallets = input.wallets;
  const observedAtMs = input.now().getTime();
  const freshWalletIds = await loadFreshSnapshotWalletIds({
    database: input.consoleDatabase,
    namespace: input.namespace,
    orgId: input.ctx.orgId,
    walletIds: wallets.map((wallet) => wallet.id),
    staleBeforeMs: observedAtMs - BALANCE_CACHE_TTL_MS,
  });
  const staleWallets = wallets.filter((wallet) => !freshWalletIds.has(wallet.id));
  const signerRows = await loadSignerRows({
    database: input.reader.signerDatabase,
    namespace: input.namespace,
    orgId: input.ctx.orgId,
    walletIds: staleWallets.map((wallet) => wallet.id),
  });
  const outcomes = await Promise.all(
    staleWallets.map((wallet) =>
      refreshWallet({ wallet, signerRows, observedAtMs, reader: input.reader }),
    ),
  );
  const snapshots = outcomes.flatMap((outcome) =>
    outcome.kind === 'refreshed' ? [outcome.snapshot] : [],
  );
  const statements = snapshots.flatMap((snapshot) =>
    snapshotStatements({
      database: input.consoleDatabase,
      namespace: input.namespace,
      orgId: input.ctx.orgId,
      snapshot,
    }),
  );
  if (statements.length > 0) await input.consoleDatabase.batch(statements);
  return {
    wallets: applySnapshots(wallets, snapshots),
    refreshedWalletIds: snapshots.map((snapshot) => snapshot.walletId),
    freshWalletIds: [...freshWalletIds],
    failures: outcomes.flatMap((outcome) =>
      outcome.kind === 'failed' ? [{ walletId: outcome.walletId, message: outcome.message }] : [],
    ),
  };
}

export function hasWalletBalanceRefresh(
  service: ConsoleWalletService,
): service is ConsoleWalletService & Required<Pick<ConsoleWalletService, 'refreshBalances'>> {
  return typeof service.refreshBalances === 'function';
}
