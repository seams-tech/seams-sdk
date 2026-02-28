import { ConsoleGasSponsorshipError } from './errors';
import type {
  ConsoleGasSponsorshipChainBudget,
  ConsoleGasSponsorshipConfig,
  ConsoleGasSponsorshipScopeType,
  CreateConsoleGasSponsorshipRequest,
  ListConsoleGasSponsorshipRequest,
  UpdateConsoleGasSponsorshipRequest,
} from './types';

export interface ConsoleGasSponsorshipContext {
  orgId: string;
  actorUserId: string;
  roles: string[];
}

export interface InMemoryConsoleGasSponsorshipServiceOptions {
  now?: () => Date;
}

export interface ConsoleGasSponsorshipService {
  listConfigs(
    ctx: ConsoleGasSponsorshipContext,
    request?: ListConsoleGasSponsorshipRequest,
  ): Promise<ConsoleGasSponsorshipConfig[]>;
  createConfig(
    ctx: ConsoleGasSponsorshipContext,
    request: CreateConsoleGasSponsorshipRequest,
  ): Promise<ConsoleGasSponsorshipConfig>;
  updateConfig(
    ctx: ConsoleGasSponsorshipContext,
    configId: string,
    request: UpdateConsoleGasSponsorshipRequest,
  ): Promise<ConsoleGasSponsorshipConfig | null>;
}

function makeId(prefix: string, now: Date): string {
  const ts = now.getTime().toString(36);
  const rand = Math.random().toString(36).slice(2, 10);
  return `${prefix}_${ts}_${rand}`;
}

function toIso(date: Date): string {
  return date.toISOString();
}

function normalizeString(value: unknown): string | null {
  const out = String(value || '').trim();
  return out || null;
}

function cloneBudgets(input: ConsoleGasSponsorshipChainBudget[]): ConsoleGasSponsorshipChainBudget[] {
  return input.map((entry) => ({
    chain: entry.chain,
    period: entry.period,
    budgetMinor: entry.budgetMinor,
    quotaTransactions: entry.quotaTransactions,
  }));
}

function cloneConfig(config: ConsoleGasSponsorshipConfig): ConsoleGasSponsorshipConfig {
  return {
    ...config,
    chainBudgets: cloneBudgets(config.chainBudgets),
    telemetry: { ...config.telemetry },
  };
}

function validateScope(input: {
  scopeType: ConsoleGasSponsorshipScopeType;
  projectId: string | null;
  environmentId: string | null;
  policyId: string | null;
  walletSegmentId: string | null;
}): void {
  if (input.scopeType === 'ORG') return;
  if (input.scopeType === 'PROJECT' && input.projectId) return;
  if (input.scopeType === 'ENVIRONMENT' && input.environmentId) return;
  if (input.scopeType === 'POLICY' && input.policyId) return;
  if (input.scopeType === 'WALLET_SEGMENT' && input.walletSegmentId) return;
  throw new ConsoleGasSponsorshipError(
    'invalid_scope',
    400,
    `Scope ${input.scopeType} is missing a required identifier`,
  );
}

function sortConfigs(configs: ConsoleGasSponsorshipConfig[]): ConsoleGasSponsorshipConfig[] {
  return [...configs].sort((a, b) => {
    const updatedCompare = b.updatedAt.localeCompare(a.updatedAt);
    if (updatedCompare !== 0) return updatedCompare;
    return b.createdAt.localeCompare(a.createdAt);
  });
}

function normalizeBudgets(
  input: ConsoleGasSponsorshipChainBudget[] | undefined,
): ConsoleGasSponsorshipChainBudget[] {
  const raw = Array.isArray(input) ? input : [];
  const deduped = new Map<string, ConsoleGasSponsorshipChainBudget>();
  raw.forEach((entry) => {
    const chain = String(entry.chain || '').trim();
    if (!chain) return;
    const key = `${chain.toLowerCase()}:${entry.period}`;
    deduped.set(key, {
      chain,
      period: entry.period,
      budgetMinor: Math.max(0, Number(entry.budgetMinor || 0)),
      quotaTransactions: Math.max(0, Number(entry.quotaTransactions || 0)),
    });
  });
  return Array.from(deduped.values());
}

export function createInMemoryConsoleGasSponsorshipService(
  opts: InMemoryConsoleGasSponsorshipServiceOptions = {},
): ConsoleGasSponsorshipService {
  const now = opts.now || (() => new Date());
  const stores = new Map<string, Map<string, ConsoleGasSponsorshipConfig>>();

  function requireOrgStore(orgId: string): Map<string, ConsoleGasSponsorshipConfig> {
    let store = stores.get(orgId);
    if (!store) {
      store = new Map<string, ConsoleGasSponsorshipConfig>();
      stores.set(orgId, store);
    }
    return store;
  }

  return {
    async listConfigs(ctx, request = {}): Promise<ConsoleGasSponsorshipConfig[]> {
      const store = requireOrgStore(ctx.orgId);
      const rows = sortConfigs(Array.from(store.values()));
      return rows
        .filter((row) => {
          if (request.scopeType && row.scopeType !== request.scopeType) return false;
          if (request.projectId && row.projectId !== request.projectId) return false;
          if (request.environmentId && row.environmentId !== request.environmentId) return false;
          if (request.policyId && row.policyId !== request.policyId) return false;
          if (request.walletSegmentId && row.walletSegmentId !== request.walletSegmentId) return false;
          return true;
        })
        .map(cloneConfig);
    },

    async createConfig(ctx, request): Promise<ConsoleGasSponsorshipConfig> {
      const createdAt = now();
      const iso = toIso(createdAt);
      const scopeType = request.scopeType;
      const projectId = normalizeString(request.projectId);
      const environmentId = normalizeString(request.environmentId);
      const policyId = normalizeString(request.policyId);
      const walletSegmentId = normalizeString(request.walletSegmentId);
      validateScope({ scopeType, projectId, environmentId, policyId, walletSegmentId });

      const config: ConsoleGasSponsorshipConfig = {
        id: normalizeString(request.id) || makeId('gs', createdAt),
        orgId: ctx.orgId,
        scopeType,
        projectId,
        environmentId,
        policyId,
        walletSegmentId,
        enabled: request.enabled ?? true,
        paymasterMode: request.paymasterMode || 'AUTO',
        fallbackBehavior: request.fallbackBehavior || 'ALLOW_UNSPONSORED',
        chainBudgets: normalizeBudgets(request.chainBudgets),
        telemetry: {
          sponsoredTransactionCount: 0,
          failedTransactionCount: 0,
          spendMinor: 0,
          budgetUtilizationPct: 0,
        },
        createdAt: iso,
        updatedAt: iso,
      };

      const store = requireOrgStore(ctx.orgId);
      if (store.has(config.id)) {
        throw new ConsoleGasSponsorshipError(
          'config_exists',
          409,
          `Gas sponsorship config ${config.id} already exists`,
        );
      }
      store.set(config.id, config);
      return cloneConfig(config);
    },

    async updateConfig(ctx, configId, request): Promise<ConsoleGasSponsorshipConfig | null> {
      const store = requireOrgStore(ctx.orgId);
      const current = store.get(configId);
      if (!current) return null;

      const next: ConsoleGasSponsorshipConfig = {
        ...current,
        scopeType: request.scopeType || current.scopeType,
        projectId: request.projectId === undefined ? current.projectId : normalizeString(request.projectId),
        environmentId:
          request.environmentId === undefined
            ? current.environmentId
            : normalizeString(request.environmentId),
        policyId: request.policyId === undefined ? current.policyId : normalizeString(request.policyId),
        walletSegmentId:
          request.walletSegmentId === undefined
            ? current.walletSegmentId
            : normalizeString(request.walletSegmentId),
        enabled: request.enabled === undefined ? current.enabled : request.enabled,
        paymasterMode: request.paymasterMode || current.paymasterMode,
        fallbackBehavior: request.fallbackBehavior || current.fallbackBehavior,
        chainBudgets:
          request.chainBudgets === undefined
            ? cloneBudgets(current.chainBudgets)
            : normalizeBudgets(request.chainBudgets),
        updatedAt: toIso(now()),
      };

      validateScope({
        scopeType: next.scopeType,
        projectId: next.projectId,
        environmentId: next.environmentId,
        policyId: next.policyId,
        walletSegmentId: next.walletSegmentId,
      });

      store.set(configId, next);
      return cloneConfig(next);
    },
  };
}
