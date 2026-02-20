import type { AccountId } from '@/core/types/accountIds';
import { toAccountId } from '@/core/types/accountIds';
import type {
  ChainAccountRecord,
  UpsertChainAccountInput,
} from '@/core/indexedDB/passkeyClientDB.types';
import type { EvmSigningRequest } from '../../chainAdaptors/evm/types';
import type { TempoSigningRequest } from '../../chainAdaptors/tempo/types';

export type SmartAccountDeploymentChain = 'evm' | 'tempo';

export type SmartAccountDeploymentTarget = {
  chain: SmartAccountDeploymentChain;
  chainIdCandidates: string[];
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
  chainId: string;
  account: ChainAccountRecord;
};

export type SmartAccountStatePort = {
  resolveNearAccountContext: (
    nearAccountId: AccountId,
  ) => Promise<{ profileId: string; sourceChainId: string; sourceAccountAddress: string } | null>;
  listChainAccountsByProfile?: (
    profileId: string,
  ) => Promise<ChainAccountRecord[]>;
  listChainAccountsByProfileAndChain: (
    profileId: string,
    chainId: string,
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
  chainId?: string;
  accountAddress?: string;
  deploymentTxHash?: string;
  failureCode?: string;
  failureMessage?: string;
  attempts: number;
  checkedAt: number;
};

type DeploymentIdentity = {
  profileId: string;
  chainId: string;
  accountModel: string;
  accountAddress: string;
};

const deploymentInFlightByIdentity = new Map<string, Promise<void>>();

function normalizeChainId(value: unknown): string {
  return String(value || '').trim().toLowerCase();
}

function normalizeAccountModel(value: unknown): string {
  return String(value || '').trim().toLowerCase();
}

function normalizeOptionalString(value: unknown): string | undefined {
  const normalized = String(value || '').trim();
  return normalized || undefined;
}

function normalizeAccountAddress(value: unknown): string {
  return String(value || '').trim().toLowerCase();
}

function normalizeRetryAttempts(value: unknown): number {
  if (typeof value !== 'number' || !Number.isFinite(value)) return 1;
  const rounded = Math.trunc(value);
  if (rounded < 1) return 1;
  if (rounded > 5) return 5;
  return rounded;
}

function isRetriableDeployFailure(codeRaw: unknown, messageRaw: unknown): boolean {
  const code = String(codeRaw || '').trim().toLowerCase();
  const message = String(messageRaw || '').trim().toLowerCase();
  if (
    code === 'request_failed'
    || code === 'timeout'
    || code === 'timed_out'
    || code === 'network_error'
    || code === 'service_unavailable'
    || code === 'temporarily_unavailable'
    || code === 'rate_limited'
    || code === 'http_429'
    || code === 'http_503'
    || code === 'http_504'
  ) {
    return true;
  }
  return (
    message.includes('timeout')
    || message.includes('timed out')
    || message.includes('network')
    || message.includes('fetch')
    || message.includes('temporar')
    || message.includes('rate limit')
    || message.includes('429')
    || message.includes('503')
    || message.includes('504')
  );
}

function dedupeChainIds(chainIds: string[]): string[] {
  const seen = new Set<string>();
  const out: string[] = [];
  for (const chainIdRaw of chainIds) {
    const chainId = normalizeChainId(chainIdRaw);
    if (!chainId || seen.has(chainId)) continue;
    seen.add(chainId);
    out.push(chainId);
  }
  return out;
}

function toDeploymentIdentity(account: ChainAccountRecord): DeploymentIdentity {
  return {
    profileId: String(account.profileId || '').trim(),
    chainId: normalizeChainId(account.chainId),
    accountModel: normalizeAccountModel(account.accountModel),
    accountAddress: normalizeAccountAddress(account.accountAddress),
  };
}

function deploymentIdentityKey(identity: DeploymentIdentity): string {
  return [
    identity.profileId,
    identity.chainId,
    identity.accountModel,
    identity.accountAddress,
  ].join('|');
}

async function findChainAccountByIdentity(args: {
  clientDB: SmartAccountStatePort;
  profileId: string;
  chainId: string;
  accountModel: string;
  accountAddress: string;
}): Promise<ChainAccountRecord | null> {
  const rows = await args.clientDB
    .listChainAccountsByProfileAndChain(args.profileId, args.chainId)
    .catch(() => []);
  return (
    rows.find(
      (row) =>
        normalizeAccountModel(row.accountModel) === args.accountModel
        && normalizeAccountAddress(row.accountAddress) === args.accountAddress,
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
  mirrorChainId: string;
  mirrorAccountModel: string;
  seedAccountModelCandidates: string[];
} {
  if (chain === 'evm') {
    return {
      mirrorChainId: 'eip155:unknown',
      mirrorAccountModel: 'erc4337',
      seedAccountModelCandidates: ['tempo-native'],
    };
  }
  return {
    mirrorChainId: 'tempo:unknown',
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

  const seeded = await args.clientDB.upsertChainAccount({
    profileId: args.profileId,
    chainId: mirror.mirrorChainId,
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
  }).catch(() => null);

  return seeded;
}

function toChainIdFromBigint(prefix: 'eip155' | 'tempo', chainId: bigint): string {
  return `${prefix}:${String(chainId)}`;
}

export function deriveSmartAccountDeploymentTargetFromSigningRequest(
  request: EvmSigningRequest | TempoSigningRequest,
): SmartAccountDeploymentTarget {
  if (request.chain === 'evm') {
    return {
      chain: 'evm',
      chainIdCandidates: [
        toChainIdFromBigint('eip155', request.tx.chainId),
        'eip155:unknown',
      ],
      accountModelCandidates: ['erc4337'],
    };
  }
  return {
    chain: 'tempo',
    chainIdCandidates: [
      toChainIdFromBigint('tempo', request.tx.chainId),
      'tempo:unknown',
    ],
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
    chainId: args.account.chainId,
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
  chainIdCandidates: string[];
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
  for (const chainId of chainIds) {
    const rows = await args.clientDB
      .listChainAccountsByProfileAndChain(context.profileId, chainId)
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
        `[deployment] no smart-account row found for profile ${context.profileId} (${chainIds.join(', ')})`,
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
    return {
      status: 'already_deployed',
      chainId: touched.chainId,
      accountAddress: touched.accountAddress,
      deploymentTxHash: touched.deploymentTxHash,
      attempts: 0,
      checkedAt,
    };
  }

  if (!args.deploy) {
    if (enforce) {
      throw new Error(
        `[deployment] smart account ${touched.accountAddress} (${touched.chainId}) is undeployed and no deployer is configured`,
      );
    }
    return {
      status: 'needs_deploy',
      chainId: touched.chainId,
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
          chainId: identity.chainId,
          accountModel: identity.accountModel,
          accountAddress: identity.accountAddress,
        });
        if (refreshed?.deployed) {
          return {
            status: 'already_deployed',
            chainId: refreshed.chainId,
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
        const deployResult = await args.deploy!({
          nearAccountId,
          chain: args.chain,
          chainId: current.chainId,
          account: current,
        });
        if (deployResult.ok) {
          const deployed = await upsertDeploymentCheckState({
            clientDB: args.clientDB,
            account: current,
            checkedAt,
            deployed: true,
            deploymentTxHash: normalizeOptionalString(deployResult.deploymentTxHash),
          });
          return {
            status: 'deployed',
            chainId: deployed.chainId,
            accountAddress: deployed.accountAddress,
            deploymentTxHash: deployed.deploymentTxHash,
            attempts: attempt,
            checkedAt,
          };
        }

        failureCode = normalizeOptionalString(deployResult.code);
        failureMessage = normalizeOptionalString(deployResult.message) || 'deployment failed';
        const retriable = isRetriableDeployFailure(failureCode, failureMessage);
        const isLastAttempt = attempt >= maxDeployAttempts;
        if (!retriable || isLastAttempt) {
          if (enforce) {
            throw new Error(
              `[deployment] smart-account deployment failed${failureCode ? ` (${failureCode})` : ''} after ${attempt}/${maxDeployAttempts} attempt${maxDeployAttempts === 1 ? '' : 's'}: ${failureMessage}`,
            );
          }
          return {
            status: 'deploy_failed',
            chainId: current.chainId,
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
      return {
        status: 'deploy_failed',
        chainId: current.chainId,
        accountAddress: current.accountAddress,
        ...(failureCode ? { failureCode } : {}),
        ...(failureMessage ? { failureMessage } : {}),
        attempts: maxDeployAttempts,
        checkedAt,
      };
    },
  });
}
