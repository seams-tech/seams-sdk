import { ConsoleSmartWalletError } from './errors';
import type { ConsolePolicyService } from '../policies/service';
import type {
  ConsoleSmartWalletConfig,
  ConsoleSmartWalletScopeType,
  CreateConsoleSmartWalletRequest,
  ListConsoleSmartWalletRequest,
  UpdateConsoleSmartWalletRequest,
} from './types';

export interface ConsoleSmartWalletContext {
  orgId: string;
  actorUserId: string;
  roles: string[];
}

export interface InMemoryConsoleSmartWalletServiceOptions {
  now?: () => Date;
  policies?: ConsolePolicyService | null;
}

export interface ConsoleSmartWalletService {
  listConfigs(
    ctx: ConsoleSmartWalletContext,
    request?: ListConsoleSmartWalletRequest,
  ): Promise<ConsoleSmartWalletConfig[]>;
  createConfig(
    ctx: ConsoleSmartWalletContext,
    request: CreateConsoleSmartWalletRequest,
  ): Promise<ConsoleSmartWalletConfig>;
  updateConfig(
    ctx: ConsoleSmartWalletContext,
    configId: string,
    request: UpdateConsoleSmartWalletRequest,
  ): Promise<ConsoleSmartWalletConfig | null>;
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

function cloneConfig(config: ConsoleSmartWalletConfig): ConsoleSmartWalletConfig {
  return {
    ...config,
    bundler: config.bundler ? { ...config.bundler } : null,
  };
}

function toPolicyContext(ctx: ConsoleSmartWalletContext): {
  orgId: string;
  actorUserId: string;
  roles: string[];
} {
  return {
    orgId: ctx.orgId,
    actorUserId: ctx.actorUserId,
    roles: ctx.roles,
  };
}

function validateScope(input: {
  scopeType: ConsoleSmartWalletScopeType;
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
  throw new ConsoleSmartWalletError(
    'invalid_scope',
    400,
    `Scope ${input.scopeType} is missing a required identifier`,
  );
}

function sortConfigs(configs: ConsoleSmartWalletConfig[]): ConsoleSmartWalletConfig[] {
  return [...configs].sort((a, b) => {
    const updatedCompare = b.updatedAt.localeCompare(a.updatedAt);
    if (updatedCompare !== 0) return updatedCompare;
    return b.createdAt.localeCompare(a.createdAt);
  });
}

export function createInMemoryConsoleSmartWalletService(
  opts: InMemoryConsoleSmartWalletServiceOptions = {},
): ConsoleSmartWalletService {
  const now = opts.now || (() => new Date());
  const policies = opts.policies || null;
  const stores = new Map<string, Map<string, ConsoleSmartWalletConfig>>();

  function requireOrgStore(orgId: string): Map<string, ConsoleSmartWalletConfig> {
    let store = stores.get(orgId);
    if (!store) {
      store = new Map<string, ConsoleSmartWalletConfig>();
      stores.set(orgId, store);
    }
    return store;
  }

  async function requirePolicyName(
    ctx: ConsoleSmartWalletContext,
    policyId: string | null,
  ): Promise<string | null> {
    if (!policyId) return null;
    if (!policies) {
      throw new ConsoleSmartWalletError(
        'internal',
        500,
        'Policy service is required for policy-scoped smart wallet configs',
      );
    }
    const policy = await policies.getPolicy(toPolicyContext(ctx), policyId);
    if (!policy) {
      throw new ConsoleSmartWalletError(
        'policy_not_found',
        404,
        `Policy ${policyId} was not found`,
      );
    }
    return policy.name || policy.id;
  }

  async function projectConfig(
    ctx: ConsoleSmartWalletContext,
    config: ConsoleSmartWalletConfig,
  ): Promise<ConsoleSmartWalletConfig> {
    return {
      ...cloneConfig(config),
      policyName: await requirePolicyName(ctx, config.policyId),
    };
  }

  return {
    async listConfigs(ctx, request = {}): Promise<ConsoleSmartWalletConfig[]> {
      const store = requireOrgStore(ctx.orgId);
      const rows = sortConfigs(Array.from(store.values()));
      return await Promise.all(
        rows.filter((row) => {
          if (request.scopeType && row.scopeType !== request.scopeType) return false;
          if (request.projectId && row.projectId !== request.projectId) return false;
          if (request.environmentId && row.environmentId !== request.environmentId) return false;
          if (request.policyId && row.policyId !== request.policyId) return false;
          if (request.walletSegmentId && row.walletSegmentId !== request.walletSegmentId) return false;
          return true;
        }).map(async (row) => await projectConfig(ctx, row)),
      );
    },

    async createConfig(ctx, request): Promise<ConsoleSmartWalletConfig> {
      const createdAt = now();
      const iso = toIso(createdAt);
      const scopeType = request.scopeType;
      const projectId = normalizeString(request.projectId);
      const environmentId = normalizeString(request.environmentId);
      const policyId = normalizeString(request.policyId);
      const walletSegmentId = normalizeString(request.walletSegmentId);
      validateScope({ scopeType, projectId, environmentId, policyId, walletSegmentId });
      const policyName = await requirePolicyName(ctx, policyId);

      const config: ConsoleSmartWalletConfig = {
        id: normalizeString(request.id) || makeId('sw', createdAt),
        orgId: ctx.orgId,
        scopeType,
        projectId,
        environmentId,
        policyId,
        policyName,
        walletSegmentId,
        enabled: request.enabled ?? true,
        mode: request.mode || 'OPTIONAL',
        accountType: request.accountType || 'SMART_ACCOUNT',
        paymasterMode: request.paymasterMode || 'AUTO',
        fallbackBehavior: request.fallbackBehavior || 'FALLBACK_TO_EOA',
        bundler: request.bundler ? { ...request.bundler } : null,
        createdAt: iso,
        updatedAt: iso,
      };

      const store = requireOrgStore(ctx.orgId);
      if (store.has(config.id)) {
        throw new ConsoleSmartWalletError(
          'config_exists',
          409,
          `Smart-wallet config ${config.id} already exists`,
        );
      }
      store.set(config.id, config);
      return await projectConfig(ctx, config);
    },

    async updateConfig(ctx, configId, request): Promise<ConsoleSmartWalletConfig | null> {
      const store = requireOrgStore(ctx.orgId);
      const current = store.get(configId);
      if (!current) return null;

      const next: ConsoleSmartWalletConfig = {
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
        mode: request.mode || current.mode,
        accountType: request.accountType || current.accountType,
        paymasterMode: request.paymasterMode || current.paymasterMode,
        fallbackBehavior: request.fallbackBehavior || current.fallbackBehavior,
        bundler:
          request.bundler === undefined
            ? (current.bundler ? { ...current.bundler } : null)
            : (request.bundler ? { ...request.bundler } : null),
        updatedAt: toIso(now()),
      };

      validateScope({
        scopeType: next.scopeType,
        projectId: next.projectId,
        environmentId: next.environmentId,
        policyId: next.policyId,
        walletSegmentId: next.walletSegmentId,
      });
      next.policyName = await requirePolicyName(ctx, next.policyId);

      store.set(configId, next);
      return await projectConfig(ctx, next);
    },
  };
}
