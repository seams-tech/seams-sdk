import type { AccountId } from '@/core/types/accountIds';
import { toAccountId } from '@/core/types/accountIds';
import { normalizeOptionalNonEmptyString } from '@shared/utils/normalize';
import {
  normalizeIndexedDbAccountAddress as normalizeAccountAddress,
  normalizeIndexedDbAccountModel as normalizeAccountModel,
  normalizeIndexedDbChainIdKey as normalizeChainIdKey,
  normalizeIndexedDbOptionalChainIdNumber as normalizeOptionalChainIdNumber,
  toIndexedDbChainIdKey as toChainIdKey,
} from '@/core/indexedDB/normalization';
import type {
  ChainAccountRecord,
  UpsertChainAccountInput,
} from '@/core/indexedDB/passkeyClientDB.types';
import type { EvmSigningRequest } from '../chainAdaptors/evm/types';
import type { TempoSigningRequest } from '../chainAdaptors/tempo/types';

export type SmartAccountDeploymentChain = 'evm' | 'tempo';

export type SmartAccountDeploymentTarget = {
  chain: SmartAccountDeploymentChain;
  chainIdCandidates: number[];
  accountModelCandidates: string[];
};

export type SmartAccountDeployerResult = {
  ok: boolean;
  deploymentTxHash?: string;
  code?: string;
  message?: string;
};

export type SmartAccountDeployerInput = {
  nearAccountId: AccountId;
  chain: SmartAccountDeploymentChain;
  chainId: number;
  account: ChainAccountRecord;
};

export type SmartAccountStatePort = {
  resolveNearAccountContext: (
    nearAccountId: AccountId,
  ) => Promise<{ profileId: string; sourceChainIdKey: string; sourceAccountAddress: string } | null>;
  listChainAccountsByProfile?: (profileId: string) => Promise<ChainAccountRecord[]>;
  listChainAccountsByProfileAndChain: (
    profileId: string,
    chainIdKey: string,
  ) => Promise<ChainAccountRecord[]>;
  upsertChainAccount: (input: UpsertChainAccountInput) => Promise<ChainAccountRecord>;
};

export type EnsureSmartAccountDeployedStatus =
  | 'skipped_missing_context'
  | 'skipped_missing_account'
  | 'already_deployed'
  | 'needs_deploy'
  | 'deployed'
  | 'deploy_failed';

export type EnsureSmartAccountDeployedResult = {
  status: EnsureSmartAccountDeployedStatus;
  chainId?: number;
  accountAddress?: string;
  deploymentTxHash?: string;
  failureCode?: string;
  failureMessage?: string;
  attempts: number;
  checkedAt: number;
};

type DeploymentIdentity = {
  profileId: string;
  chainIdKey: string;
  accountModel: string;
  accountAddress: string;
};

const deploymentInFlightByIdentity = new Map<string, Promise<void>>();

function normalizeRetryAttempts(value: unknown): number {
  if (typeof value !== 'number' || !Number.isFinite(value)) return 1;
  const rounded = Math.trunc(value);
  if (rounded < 1) return 1;
  if (rounded > 5) return 5;
  return rounded;
}

function isRetriableDeployFailure(codeRaw: unknown, messageRaw: unknown): boolean {
  const code = String(codeRaw || '')
    .trim()
    .toLowerCase();
  const message = String(messageRaw || '')
    .trim()
    .toLowerCase();
  if (
    code === 'request_failed' ||
    code === 'timeout' ||
    code === 'timed_out' ||
    code === 'network_error' ||
    code === 'service_unavailable' ||
    code === 'temporarily_unavailable' ||
    code === 'rate_limited' ||
    code === 'http_429' ||
    code === 'http_503' ||
    code === 'http_504'
  ) {
    return true;
  }
  return (
    message.includes('timeout') ||
    message.includes('timed out') ||
    message.includes('network') ||
    message.includes('fetch') ||
    message.includes('temporar') ||
    message.includes('rate limit') ||
    message.includes('429') ||
    message.includes('503') ||
    message.includes('504')
  );
}

function dedupeChainIds(chainIds: number[]): number[] {
  const seen = new Set<number>();
  const out: number[] = [];
  for (const chainIdRaw of chainIds) {
    const chainId = normalizeOptionalChainIdNumber(chainIdRaw);
    if (typeof chainId !== 'number' || seen.has(chainId)) continue;
    seen.add(chainId);
    out.push(chainId);
  }
  return out;
}

function toDeploymentIdentity(account: ChainAccountRecord): DeploymentIdentity {
  return {
    profileId: String(account.profileId || '').trim(),
    chainIdKey: normalizeChainIdKey(account.chainIdKey),
    accountModel: normalizeAccountModel(account.accountModel),
    accountAddress: normalizeAccountAddress(account.accountAddress),
  };
}

function deploymentIdentityKey(identity: DeploymentIdentity): string {
  return [
    identity.profileId,
    identity.chainIdKey,
    identity.accountModel,
    identity.accountAddress,
  ].join('|');
}

async function findChainAccountByIdentity(args: {
  clientDB: SmartAccountStatePort;
  profileId: string;
  chainIdKey: string;
  accountModel: string;
  accountAddress: string;
}): Promise<ChainAccountRecord | null> {
  const rows = await args.clientDB
    .listChainAccountsByProfileAndChain(args.profileId, args.chainIdKey)
    .catch(() => []);
  return (
    rows.find(
      (row) =>
        normalizeAccountModel(row.accountModel) === args.accountModel &&
        normalizeAccountAddress(row.accountAddress) === args.accountAddress,
    ) || null
  );
}

async function withDeploymentIdentityLock<T>(args: {
  identity: DeploymentIdentity;
  task: (ctx: { waited: boolean }) => Promise<T>;
}): Promise<T> {
  const key = deploymentIdentityKey(args.identity);
  const hadPrevious = deploymentInFlightByIdentity.has(key);
  const previous = deploymentInFlightByIdentity.get(key) || Promise.resolve();
  const waitForPrevious = previous.catch(() => undefined);

  let release!: () => void;
  const gate = new Promise<void>((resolve) => {
    release = resolve;
  });
  const next = waitForPrevious.then(() => gate);
  deploymentInFlightByIdentity.set(key, next);

  await waitForPrevious;
  try {
    return await args.task({ waited: hadPrevious });
  } finally {
    release();
    if (deploymentInFlightByIdentity.get(key) === next) {
      deploymentInFlightByIdentity.delete(key);
    }
  }
}

function deriveMirrorAccountDefaults(chain: SmartAccountDeploymentChain): {
  mirrorChainIdKey: string;
  mirrorAccountModel: string;
  seedAccountModelCandidates: string[];
} {
  if (chain === 'evm') {
    return {
      mirrorChainIdKey: 'evm:unknown',
      mirrorAccountModel: 'erc4337',
      seedAccountModelCandidates: ['tempo-native'],
    };
  }
  return {
    mirrorChainIdKey: 'tempo:42431',
    mirrorAccountModel: 'tempo-native',
    seedAccountModelCandidates: ['erc4337'],
  };
}

function selectPreferredChainAccount(args: {
  rows: ChainAccountRecord[];
  accountModelCandidates: string[];
}): ChainAccountRecord | null {
  const modelAllow = new Set(
    args.accountModelCandidates.map((value) => normalizeAccountModel(value)).filter(Boolean),
  );
  const modelFiltered = modelAllow.size
    ? args.rows.filter((row) => modelAllow.has(normalizeAccountModel(row.accountModel)))
    : args.rows;
  if (!modelFiltered.length) return null;
  const primary = modelFiltered.find((row) => !!row.isPrimary);
  return primary || modelFiltered[0] || null;
}

async function mirrorMissingSmartAccountRowFromCounterpart(args: {
  clientDB: SmartAccountStatePort;
  profileId: string;
  nearAccountId: AccountId;
  chain: SmartAccountDeploymentChain;
}): Promise<ChainAccountRecord | null> {
  if (typeof args.clientDB.listChainAccountsByProfile !== 'function') return null;

  const allRows = await args.clientDB.listChainAccountsByProfile(args.profileId).catch(() => []);
  if (!Array.isArray(allRows) || !allRows.length) return null;

  const mirror = deriveMirrorAccountDefaults(args.chain);
  const seed = selectPreferredChainAccount({
    rows: allRows,
    accountModelCandidates: mirror.seedAccountModelCandidates,
  });
  if (!seed) return null;

  const seeded = await args.clientDB
    .upsertChainAccount({
      profileId: args.profileId,
      chainIdKey: mirror.mirrorChainIdKey,
      accountAddress: seed.accountAddress,
      accountModel: mirror.mirrorAccountModel,
      isPrimary: true,
      factory: seed.factory,
      entryPoint: seed.entryPoint,
      salt: seed.salt,
      counterfactualAddress: seed.counterfactualAddress || seed.accountAddress,
      deployed: false,
      deploymentTxHash: null,
      lastDeploymentCheckAt: null,
    })
    .catch(() => null);

  return seeded;
}

function resolveChainIdFromChainAccount(args: {
  account: ChainAccountRecord;
  chainIdCandidates: readonly number[];
}): number | undefined {
  const parsedFromAccount = normalizeOptionalChainIdNumber(args.account.chainIdKey, {
    allowChainIdKeySuffix: true,
  });
  if (typeof parsedFromAccount === 'number') return parsedFromAccount;
  if (args.chainIdCandidates.length === 1) return args.chainIdCandidates[0];
  return undefined;
}

export function deriveSmartAccountDeploymentTargetFromSigningRequest(
  request: EvmSigningRequest | TempoSigningRequest,
): SmartAccountDeploymentTarget {
  if (request.chain === 'evm') {
    return {
      chain: 'evm',
      chainIdCandidates: [request.tx.chainId],
      accountModelCandidates: ['erc4337'],
    };
  }
  return {
    chain: 'tempo',
    chainIdCandidates: [request.tx.chainId],
    accountModelCandidates: ['tempo-native'],
  };
}

async function upsertDeploymentCheckState(args: {
  clientDB: SmartAccountStatePort;
  account: ChainAccountRecord;
  checkedAt: number;
  deployed?: boolean;
  deploymentTxHash?: string;
}): Promise<ChainAccountRecord> {
  return await args.clientDB.upsertChainAccount({
    profileId: args.account.profileId,
    chainIdKey: args.account.chainIdKey,
    accountAddress: args.account.accountAddress,
    accountModel: args.account.accountModel,
    isPrimary: args.account.isPrimary,
    factory: args.account.factory,
    entryPoint: args.account.entryPoint,
    salt: args.account.salt,
    counterfactualAddress: args.account.counterfactualAddress,
    ...(typeof args.deployed === 'boolean' ? { deployed: args.deployed } : {}),
    ...(args.deploymentTxHash ? { deploymentTxHash: args.deploymentTxHash } : {}),
    lastDeploymentCheckAt: args.checkedAt,
  });
}

export async function ensureSmartAccountDeployed(args: {
  clientDB: SmartAccountStatePort;
  nearAccountId: AccountId | string;
  chain: SmartAccountDeploymentChain;
  chainIdCandidates: number[];
  accountModelCandidates: string[];
  deploy?: (input: SmartAccountDeployerInput) => Promise<SmartAccountDeployerResult>;
  enforce?: boolean;
  maxDeployAttempts?: number;
  now?: () => number;
}): Promise<EnsureSmartAccountDeployedResult> {
  const checkedAt = (args.now || Date.now)();
  const nearAccountId = toAccountId(args.nearAccountId);
  const enforce = !!args.enforce;
  const maxDeployAttempts = normalizeRetryAttempts(args.maxDeployAttempts);
  const chainIds = dedupeChainIds(args.chainIdCandidates);
  const chainIdKeys = chainIds.map((chainId) => toChainIdKey(args.chain, chainId));

  const context = await args.clientDB.resolveNearAccountContext(nearAccountId).catch(() => null);
  if (!context?.profileId) {
    if (enforce) {
      throw new Error(
        `[deployment] missing profile/account mapping for ${String(nearAccountId)}; cannot enforce smart-account deployment`,
      );
    }
    return { status: 'skipped_missing_context', checkedAt, attempts: 0 };
  }

  const chainRows: ChainAccountRecord[] = [];
  for (const chainIdKey of chainIdKeys) {
    const rows = await args.clientDB
      .listChainAccountsByProfileAndChain(context.profileId, chainIdKey)
      .catch(() => []);
    if (rows.length) chainRows.push(...rows);
  }

  let account = selectPreferredChainAccount({
    rows: chainRows,
    accountModelCandidates: args.accountModelCandidates,
  });
  if (!account) {
    const mirrored = await mirrorMissingSmartAccountRowFromCounterpart({
      clientDB: args.clientDB,
      profileId: context.profileId,
      nearAccountId,
      chain: args.chain,
    });
    if (mirrored) {
      chainRows.push(mirrored);
      account = selectPreferredChainAccount({
        rows: chainRows,
        accountModelCandidates: args.accountModelCandidates,
      });
    }
  }
  if (!account) {
    if (enforce) {
      throw new Error(
        `[deployment] no smart-account row found for profile ${context.profileId} (${chainIdKeys.join(', ')})`,
      );
    }
    return { status: 'skipped_missing_account', checkedAt, attempts: 0 };
  }

  const touched = await upsertDeploymentCheckState({
    clientDB: args.clientDB,
    account,
    checkedAt,
  });

  if (touched.deployed) {
    const chainId = resolveChainIdFromChainAccount({
      account: touched,
      chainIdCandidates: chainIds,
    });
    return {
      status: 'already_deployed',
      ...(typeof chainId === 'number' ? { chainId } : {}),
      accountAddress: touched.accountAddress,
      deploymentTxHash: touched.deploymentTxHash,
      attempts: 0,
      checkedAt,
    };
  }

  if (!args.deploy) {
    if (enforce) {
      throw new Error(
        `[deployment] smart account ${touched.accountAddress} (${touched.chainIdKey}) is undeployed and no deployer is configured`,
      );
    }
    const chainId = resolveChainIdFromChainAccount({
      account: touched,
      chainIdCandidates: chainIds,
    });
    return {
      status: 'needs_deploy',
      ...(typeof chainId === 'number' ? { chainId } : {}),
      accountAddress: touched.accountAddress,
      attempts: 0,
      checkedAt,
    };
  }

  const identity = toDeploymentIdentity(touched);
  return await withDeploymentIdentityLock({
    identity,
    task: async ({ waited }) => {
      let current = touched;
      if (waited) {
        const refreshed = await findChainAccountByIdentity({
          clientDB: args.clientDB,
          profileId: identity.profileId,
          chainIdKey: identity.chainIdKey,
          accountModel: identity.accountModel,
          accountAddress: identity.accountAddress,
        });
        if (refreshed?.deployed) {
          const chainId = resolveChainIdFromChainAccount({
            account: refreshed,
            chainIdCandidates: chainIds,
          });
          return {
            status: 'already_deployed',
            ...(typeof chainId === 'number' ? { chainId } : {}),
            accountAddress: refreshed.accountAddress,
            deploymentTxHash: refreshed.deploymentTxHash,
            attempts: 0,
            checkedAt,
          };
        }
        if (refreshed) {
          current = refreshed;
        }
      }

      let failureCode: string | undefined;
      let failureMessage: string | undefined;
      for (let attempt = 1; attempt <= maxDeployAttempts; attempt += 1) {
        const resolvedChainId = resolveChainIdFromChainAccount({
          account: current,
          chainIdCandidates: chainIds,
        });
        if (typeof resolvedChainId !== 'number') {
          if (enforce) {
            throw new Error(
              `[deployment] unable to resolve numeric chainId for ${args.chain} deployment row (${String(current.chainIdKey || 'unknown')})`,
            );
          }
          return {
            status: 'deploy_failed',
            accountAddress: current.accountAddress,
            failureMessage: 'unable to resolve numeric chainId',
            attempts: attempt,
            checkedAt,
          };
        }
        const deployResult = await args.deploy!({
          nearAccountId,
          chain: args.chain,
          chainId: resolvedChainId,
          account: current,
        });
        if (deployResult.ok) {
          const deployed = await upsertDeploymentCheckState({
            clientDB: args.clientDB,
            account: current,
            checkedAt,
            deployed: true,
            deploymentTxHash: normalizeOptionalNonEmptyString(deployResult.deploymentTxHash),
          });
          const chainId = resolveChainIdFromChainAccount({
            account: deployed,
            chainIdCandidates: chainIds,
          });
          return {
            status: 'deployed',
            ...(typeof chainId === 'number' ? { chainId } : {}),
            accountAddress: deployed.accountAddress,
            deploymentTxHash: deployed.deploymentTxHash,
            attempts: attempt,
            checkedAt,
          };
        }

        failureCode = normalizeOptionalNonEmptyString(deployResult.code);
        failureMessage =
          normalizeOptionalNonEmptyString(deployResult.message) || 'deployment failed';
        const retriable = isRetriableDeployFailure(failureCode, failureMessage);
        const isLastAttempt = attempt >= maxDeployAttempts;
        if (!retriable || isLastAttempt) {
          if (enforce) {
            throw new Error(
              `[deployment] smart-account deployment failed${failureCode ? ` (${failureCode})` : ''} after ${attempt}/${maxDeployAttempts} attempt${maxDeployAttempts === 1 ? '' : 's'}: ${failureMessage}`,
            );
          }
          const chainId = resolveChainIdFromChainAccount({
            account: current,
            chainIdCandidates: chainIds,
          });
          return {
            status: 'deploy_failed',
            ...(typeof chainId === 'number' ? { chainId } : {}),
            accountAddress: current.accountAddress,
            ...(failureCode ? { failureCode } : {}),
            ...(failureMessage ? { failureMessage } : {}),
            attempts: attempt,
            checkedAt,
          };
        }
      }

      if (enforce) {
        throw new Error('[deployment] smart-account deployment failed after retries');
      }
      const chainId = resolveChainIdFromChainAccount({
        account: current,
        chainIdCandidates: chainIds,
      });
      return {
        status: 'deploy_failed',
        ...(typeof chainId === 'number' ? { chainId } : {}),
        accountAddress: current.accountAddress,
        ...(failureCode ? { failureCode } : {}),
        ...(failureMessage ? { failureMessage } : {}),
        attempts: maxDeployAttempts,
        checkedAt,
      };
    },
  });
}
