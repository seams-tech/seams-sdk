import { ConsoleGasSponsorshipError } from './errors';
import type { ConsolePolicyService } from '../policies/service';
import type {
  ConsoleGasSponsorshipAllowedCall,
  ConsoleGasSponsorshipCallMode,
  ConsoleGasSponsorshipConfig,
  ConsoleGasSponsorshipNetworkClass,
  ConsoleGasSponsorshipScopeType,
  ConsoleGasSponsorshipSpendCap,
  ConsoleGasSponsorshipSpendCapMode,
  ConsoleGasSponsorshipSpendCapPeriod,
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
  policies?: ConsolePolicyService | null;
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

function cloneSpendCap(input: ConsoleGasSponsorshipSpendCap): ConsoleGasSponsorshipSpendCap {
  return {
    mode: input.mode,
    period: input.period,
    capsByChain: input.capsByChain.map((entry) => ({
      chainId: entry.chainId,
      capMinor: entry.capMinor,
    })),
  };
}

function normalizeAddress(value: unknown): string | null {
  const normalized = String(value || '').trim();
  return /^0x[0-9a-fA-F]{40}$/.test(normalized) ? normalized : null;
}

function normalizeSelector(value: unknown): string | null {
  const normalized = String(value || '').trim();
  return /^0x[0-9a-fA-F]{8}$/.test(normalized) ? normalized.toLowerCase() : null;
}

function cloneAllowedCalls(input: ConsoleGasSponsorshipAllowedCall[]): ConsoleGasSponsorshipAllowedCall[] {
  return input.map((entry) => ({
    chainId: entry.chainId,
    to: entry.to,
    selector: entry.selector,
  }));
}

function cloneAllowedChainIds(input: number[]): number[] {
  return [...input];
}

function normalizeNetworkClass(value: unknown): ConsoleGasSponsorshipNetworkClass {
  const normalized = String(value || '')
    .trim()
    .toUpperCase();
  if (normalized === 'TESTNET' || normalized === 'MAINNET') return normalized;
  return 'ANY';
}

function normalizeCallMode(
  value: unknown,
  inputAllowedCalls: ConsoleGasSponsorshipAllowedCall[] | undefined,
): ConsoleGasSponsorshipCallMode {
  const normalized = String(value || '')
    .trim()
    .toUpperCase();
  if (normalized === 'ALLOW_ALL' || normalized === 'ALLOWLIST') return normalized;
  return Array.isArray(inputAllowedCalls) && inputAllowedCalls.length > 0 ? 'ALLOWLIST' : 'ALLOW_ALL';
}

function normalizeAllowedChainIds(
  input: number[] | undefined,
  inputAllowedCalls: ConsoleGasSponsorshipAllowedCall[] | undefined,
): number[] {
  const source =
    Array.isArray(input) && input.length > 0
      ? input
      : Array.isArray(inputAllowedCalls)
        ? inputAllowedCalls.map((entry) => Number(entry.chainId || 0))
        : [];
  const out: number[] = [];
  const seen = new Set<number>();
  source.forEach((entry) => {
    const chainId = Math.max(0, Math.floor(Number(entry) || 0));
    if (!chainId || seen.has(chainId)) return;
    seen.add(chainId);
    out.push(chainId);
  });
  return out;
}

function normalizeSpendCapMode(value: unknown): ConsoleGasSponsorshipSpendCapMode {
  const normalized = String(value || '')
    .trim()
    .toUpperCase();
  if (normalized === 'CHAIN_TOTAL' || normalized === 'WALLET_CHAIN_TOTAL') {
    return normalized;
  }
  return 'NONE';
}

function normalizeSpendCapPeriod(value: unknown): ConsoleGasSponsorshipSpendCapPeriod {
  const normalized = String(value || '')
    .trim()
    .toUpperCase();
  return normalized === 'WEEKLY' ? 'WEEKLY' : 'MONTHLY';
}

function normalizeSpendCap(input: ConsoleGasSponsorshipSpendCap | undefined): ConsoleGasSponsorshipSpendCap {
  const mode = normalizeSpendCapMode(input?.mode);
  const capsByChain = new Map<number, { chainId: number; capMinor: number }>();
  const rawCaps = Array.isArray(input?.capsByChain) ? input?.capsByChain : [];
  rawCaps.forEach((entry) => {
    const chainId = Math.max(0, Math.floor(Number(entry.chainId) || 0));
    if (!chainId) return;
    capsByChain.set(chainId, {
      chainId,
      capMinor: Math.max(0, Math.floor(Number(entry.capMinor) || 0)),
    });
  });
  return {
    mode,
    period: normalizeSpendCapPeriod(input?.period),
    capsByChain: mode === 'NONE' ? [] : Array.from(capsByChain.values()),
  };
}

function cloneConfig(config: ConsoleGasSponsorshipConfig): ConsoleGasSponsorshipConfig {
  return {
    ...config,
    allowedChainIds: cloneAllowedChainIds(config.allowedChainIds),
    spendCap: cloneSpendCap(config.spendCap),
    allowedCalls: cloneAllowedCalls(config.allowedCalls),
    telemetry: { ...config.telemetry },
  };
}

function toPolicyContext(ctx: ConsoleGasSponsorshipContext): {
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

function validatePolicyRules(input: {
  allowedChainIds: number[];
  callMode: ConsoleGasSponsorshipCallMode;
  allowedCalls: ConsoleGasSponsorshipAllowedCall[];
  spendCap: ConsoleGasSponsorshipSpendCap;
}): void {
  if (input.allowedChainIds.length === 0) {
    throw new ConsoleGasSponsorshipError(
      'invalid_allowed_chains',
      400,
      'At least one allowed chain is required.',
    );
  }
  if (input.callMode === 'ALLOWLIST' && input.allowedCalls.length === 0) {
    throw new ConsoleGasSponsorshipError(
      'invalid_allowed_calls',
      400,
      'Allowlist mode requires at least one allowed contract function.',
    );
  }
  const chainIdSet = new Set(input.allowedChainIds);
  if (input.callMode === 'ALLOWLIST') {
    const invalidCall = input.allowedCalls.find((entry) => !chainIdSet.has(entry.chainId));
    if (invalidCall) {
      throw new ConsoleGasSponsorshipError(
        'invalid_allowed_calls',
        400,
        `Allowed call chain ${invalidCall.chainId} is not part of the selected chains.`,
      );
    }
  }
  if (input.spendCap.mode === 'NONE') return;
  const invalidSpendCap = input.spendCap.capsByChain.find((entry) => !chainIdSet.has(entry.chainId));
  if (invalidSpendCap) {
    throw new ConsoleGasSponsorshipError(
      'invalid_spend_cap',
      400,
      `Spend cap chain ${invalidSpendCap.chainId} is not part of the selected chains.`,
    );
  }
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

function normalizeAllowedCalls(
  input: ConsoleGasSponsorshipAllowedCall[] | undefined,
): ConsoleGasSponsorshipAllowedCall[] {
  const raw = Array.isArray(input) ? input : [];
  const deduped = new Map<string, ConsoleGasSponsorshipAllowedCall>();
  raw.forEach((entry) => {
    const chainId = Math.max(0, Math.floor(Number(entry.chainId) || 0));
    const to = normalizeAddress(entry.to);
    const selector = normalizeSelector(entry.selector);
    if (!chainId || !to || !selector) return;
    deduped.set(`${chainId}:${to.toLowerCase()}:${selector}`, {
      chainId,
      to,
      selector,
    });
  });
  return Array.from(deduped.values());
}

export function createInMemoryConsoleGasSponsorshipService(
  opts: InMemoryConsoleGasSponsorshipServiceOptions = {},
): ConsoleGasSponsorshipService {
  const now = opts.now || (() => new Date());
  const policies = opts.policies || null;
  const stores = new Map<string, Map<string, ConsoleGasSponsorshipConfig>>();

  function requireOrgStore(orgId: string): Map<string, ConsoleGasSponsorshipConfig> {
    let store = stores.get(orgId);
    if (!store) {
      store = new Map<string, ConsoleGasSponsorshipConfig>();
      stores.set(orgId, store);
    }
    return store;
  }

  async function requirePolicyName(
    ctx: ConsoleGasSponsorshipContext,
    policyId: string | null,
  ): Promise<string | null> {
    if (!policyId) return null;
    if (!policies) {
      throw new ConsoleGasSponsorshipError(
        'internal',
        500,
        'Policy service is required for policy-scoped gas sponsorship configs',
      );
    }
    const policy = await policies.getPolicy(toPolicyContext(ctx), policyId);
    if (!policy) {
      throw new ConsoleGasSponsorshipError(
        'policy_not_found',
        404,
        `Policy ${policyId} was not found`,
      );
    }
    return policy.name || policy.id;
  }

  async function projectConfig(
    ctx: ConsoleGasSponsorshipContext,
    config: ConsoleGasSponsorshipConfig,
  ): Promise<ConsoleGasSponsorshipConfig> {
    return {
      ...cloneConfig(config),
      policyName: await requirePolicyName(ctx, config.policyId),
    };
  }

  return {
    async listConfigs(ctx, request = {}): Promise<ConsoleGasSponsorshipConfig[]> {
      const store = requireOrgStore(ctx.orgId);
      const rows = sortConfigs(Array.from(store.values()));
      return await Promise.all(
        rows
          .filter((row) => {
          if (request.scopeType && row.scopeType !== request.scopeType) return false;
          if (request.projectId && row.projectId !== request.projectId) return false;
          if (request.environmentId && row.environmentId !== request.environmentId) return false;
          if (request.policyId && row.policyId !== request.policyId) return false;
          if (request.walletSegmentId && row.walletSegmentId !== request.walletSegmentId) return false;
          if (request.templateId && row.templateId !== request.templateId) return false;
          return true;
        })
          .map(async (row) => await projectConfig(ctx, row)),
      );
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
      const policyName = await requirePolicyName(ctx, policyId);

      const config: ConsoleGasSponsorshipConfig = {
        id: normalizeString(request.id) || makeId('gs', createdAt),
        orgId: ctx.orgId,
        scopeType,
        projectId,
        environmentId,
        policyId,
        policyName,
        walletSegmentId,
        name: String(request.name || '').trim() || 'Gas Sponsorship Policy',
        templateId: normalizeString(request.templateId),
        networkClass: normalizeNetworkClass(request.networkClass),
        enabled: request.enabled ?? true,
        allowedChainIds: normalizeAllowedChainIds(request.allowedChainIds, request.allowedCalls),
        callMode: normalizeCallMode(request.callMode, request.allowedCalls),
        spendCap: normalizeSpendCap(request.spendCap),
        allowedCalls: normalizeAllowedCalls(request.allowedCalls),
        telemetry: {
          sponsoredTransactionCount: 0,
          failedTransactionCount: 0,
          spendMinor: 0,
          budgetUtilizationPct: 0,
        },
        createdAt: iso,
        updatedAt: iso,
      };
      config.allowedCalls = config.callMode === 'ALLOW_ALL' ? [] : config.allowedCalls;
      validatePolicyRules(config);

      const store = requireOrgStore(ctx.orgId);
      if (store.has(config.id)) {
        throw new ConsoleGasSponsorshipError(
          'config_exists',
          409,
          `Gas sponsorship config ${config.id} already exists`,
        );
      }
      store.set(config.id, config);
      return await projectConfig(ctx, config);
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
        name: request.name === undefined ? current.name : String(request.name || '').trim() || current.name,
        templateId:
          request.templateId === undefined ? current.templateId : normalizeString(request.templateId),
        networkClass:
          request.networkClass === undefined
            ? current.networkClass
            : normalizeNetworkClass(request.networkClass),
        enabled: request.enabled === undefined ? current.enabled : request.enabled,
        allowedChainIds:
          request.allowedChainIds === undefined
            ? cloneAllowedChainIds(current.allowedChainIds)
            : normalizeAllowedChainIds(request.allowedChainIds, request.allowedCalls),
        callMode:
          request.callMode === undefined
            ? current.callMode
            : normalizeCallMode(request.callMode, request.allowedCalls),
        spendCap:
          request.spendCap === undefined
            ? cloneSpendCap(current.spendCap)
            : normalizeSpendCap(request.spendCap),
        allowedCalls:
          request.allowedCalls === undefined
            ? cloneAllowedCalls(current.allowedCalls)
            : normalizeAllowedCalls(request.allowedCalls),
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
      next.allowedCalls = next.callMode === 'ALLOW_ALL' ? [] : next.allowedCalls;
      validatePolicyRules(next);

      store.set(configId, next);
      return await projectConfig(ctx, next);
    },
  };
}
