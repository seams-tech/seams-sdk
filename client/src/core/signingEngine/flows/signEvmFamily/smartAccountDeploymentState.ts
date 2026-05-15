import type { AccountId } from '@/core/types/accountIds';
import { toAccountId } from '@/core/types/accountIds';
import { buildNearAccountRefs } from '@/core/accountData/near/accountRefs';
import { normalizeOptionalNonEmptyString } from '@shared/utils/normalize';
import { resolveProfileAccountContextFromCandidates } from '@/core/indexedDB/profileAccountProjection';
import {
  normalizeIndexedDbAccountAddress as normalizeAccountAddress,
  normalizeIndexedDbAccountModel as normalizeAccountModel,
  normalizeIndexedDbChainIdKey as normalizeChainIdKey,
  toIndexedDbChainTargetKey,
} from '@/core/indexedDB/normalization';
import type {
  ChainAccountRecord,
  UpsertChainAccountInput,
} from '@/core/indexedDB/passkeyClientDB.types';
import type { EvmSigningRequest } from '../../chains/evm/types';
import type { TempoSigningRequest } from '../../chains/tempo/types';
import { normalizeSmartAccountDeploymentAttempts } from './smartAccountDeploymentNormalization';
import {
  thresholdEcdsaChainTargetFromChainFamily,
  type ThresholdEcdsaChainTarget,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';

export type SmartAccountDeploymentTarget = {
  chainTargetCandidates: ThresholdEcdsaChainTarget[];
  accountModelCandidates: string[];
};

export type SmartAccountDeployerResult = {
  ok: boolean;
  deploymentTxHash?: string;
  code?: string;
  message?: string;
};

export type SmartAccountDeployerInput = {
  walletId: AccountId;
  chainTarget: ThresholdEcdsaChainTarget;
  account: ChainAccountRecord;
};

export type SmartAccountDeploymentReporterInput = SmartAccountDeployerInput & {
  deploymentTxHash?: string;
};

export type SmartAccountStatePort = {
  resolveProfileAccountContext: (args: {
    chainIdKey: string;
    accountAddress: string;
  }) => Promise<{ profileId: string; accountRef: { chainIdKey: string; accountAddress: string } } | null>;
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
  chainTarget?: ThresholdEcdsaChainTarget;
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

function resolveTargetFromChainAccount(args: {
  account: ChainAccountRecord;
  targetsByKey: ReadonlyMap<string, ThresholdEcdsaChainTarget>;
}): ThresholdEcdsaChainTarget | undefined {
  const key = normalizeChainIdKey(args.account.chainIdKey);
  const target = args.targetsByKey.get(key);
  if (target) return target;
  return undefined;
}

export function deriveSmartAccountDeploymentTargetFromSigningRequest(
  request: EvmSigningRequest | TempoSigningRequest,
): SmartAccountDeploymentTarget {
  if (request.chain === 'evm') {
    return {
      chainTargetCandidates: [
        thresholdEcdsaChainTargetFromChainFamily({
          chain: 'evm',
          chainId: request.tx.chainId,
        }),
      ],
      accountModelCandidates: ['erc4337'],
    };
  }
  return {
    chainTargetCandidates: [
      thresholdEcdsaChainTargetFromChainFamily({
        chain: 'tempo',
        chainId: request.tx.chainId,
      }),
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
  walletId: AccountId | string;
  chainTargetCandidates: ThresholdEcdsaChainTarget[];
  accountModelCandidates: string[];
  deploy?: (input: SmartAccountDeployerInput) => Promise<SmartAccountDeployerResult>;
  reportDeployed?: (input: SmartAccountDeploymentReporterInput) => Promise<unknown>;
  enforce?: boolean;
  maxDeployAttempts?: number;
  now?: () => number;
}): Promise<EnsureSmartAccountDeployedResult> {
  const checkedAt = (args.now || Date.now)();
  const walletId = toAccountId(args.walletId);
  const enforce = !!args.enforce;
  const maxDeployAttempts = normalizeSmartAccountDeploymentAttempts(args.maxDeployAttempts, 1);
  const targetsByKey = new Map<string, ThresholdEcdsaChainTarget>();
  for (const target of args.chainTargetCandidates) {
    targetsByKey.set(toIndexedDbChainTargetKey(target), target);
  }
  const chainIdKeys = [...targetsByKey.keys()];

  const context = await resolveProfileAccountContextFromCandidates(
    args.clientDB as any,
    buildNearAccountRefs(walletId),
  ).catch(() => null);
  if (!context?.profileId) {
    if (enforce) {
      throw new Error(
        `[deployment] missing profile/account mapping for ${String(walletId)}; cannot enforce smart-account deployment`,
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
    const chainTarget = resolveTargetFromChainAccount({
      account: touched,
      targetsByKey,
    });
    return {
      status: 'already_deployed',
      ...(chainTarget ? { chainTarget, chainId: chainTarget.chainId } : {}),
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
    const chainTarget = resolveTargetFromChainAccount({
      account: touched,
      targetsByKey,
    });
    return {
      status: 'needs_deploy',
      ...(chainTarget ? { chainTarget, chainId: chainTarget.chainId } : {}),
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
          const chainTarget = resolveTargetFromChainAccount({
            account: refreshed,
            targetsByKey,
          });
          return {
            status: 'already_deployed',
            ...(chainTarget ? { chainTarget, chainId: chainTarget.chainId } : {}),
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
        const resolvedChainTarget = resolveTargetFromChainAccount({
          account: current,
          targetsByKey,
        });
        if (!resolvedChainTarget) {
          if (enforce) {
            throw new Error(
              `[deployment] unable to resolve concrete chain target for deployment row (${String(current.chainIdKey || 'unknown')})`,
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
          walletId,
          chainTarget: resolvedChainTarget,
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
          if (typeof args.reportDeployed === 'function') {
            await args
              .reportDeployed({
                walletId,
                chainTarget: resolvedChainTarget,
                account: deployed,
                deploymentTxHash: normalizeOptionalNonEmptyString(deployResult.deploymentTxHash),
              })
              .catch(() => undefined);
          }
          const chainTarget = resolveTargetFromChainAccount({
            account: deployed,
            targetsByKey,
          });
          return {
            status: 'deployed',
            ...(chainTarget ? { chainTarget, chainId: chainTarget.chainId } : {}),
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
          const chainTarget = resolveTargetFromChainAccount({
            account: current,
            targetsByKey,
          });
          return {
            status: 'deploy_failed',
            ...(chainTarget ? { chainTarget, chainId: chainTarget.chainId } : {}),
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
      const chainTarget = resolveTargetFromChainAccount({
        account: current,
        targetsByKey,
      });
      return {
        status: 'deploy_failed',
        ...(chainTarget ? { chainTarget, chainId: chainTarget.chainId } : {}),
        accountAddress: current.accountAddress,
        ...(failureCode ? { failureCode } : {}),
        ...(failureMessage ? { failureMessage } : {}),
        attempts: maxDeployAttempts,
        checkedAt,
      };
    },
  });
}
