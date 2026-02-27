import { ConsolePolicyError } from './errors';
import {
  normalizePolicyScopeType as normalizeScopeType,
  policyScopeKey as scopeKey,
} from './normalization';
import type {
  ConsolePolicyAssignment,
  ConsolePolicyWalletScopeRef,
  ConsolePolicy,
  CreateConsolePolicyRequest,
  ListConsolePolicyAssignmentsRequest,
  PublishConsolePolicyResult,
  SimulateConsolePolicyRequest,
  SimulateConsolePolicyResult,
  UpsertConsolePolicyAssignmentRequest,
  UpdateConsolePolicyRequest,
} from './types';

export interface ConsolePoliciesContext {
  orgId: string;
  actorUserId: string;
  roles: string[];
}

export interface ConsolePolicyService {
  listPolicies(ctx: ConsolePoliciesContext): Promise<ConsolePolicy[]>;
  createPolicy(ctx: ConsolePoliciesContext, request: CreateConsolePolicyRequest): Promise<ConsolePolicy>;
  updatePolicy(
    ctx: ConsolePoliciesContext,
    policyId: string,
    request: UpdateConsolePolicyRequest,
  ): Promise<ConsolePolicy | null>;
  publishPolicy(
    ctx: ConsolePoliciesContext,
    policyId: string,
  ): Promise<PublishConsolePolicyResult | null>;
  simulatePolicy(
    ctx: ConsolePoliciesContext,
    policyId: string,
    request: SimulateConsolePolicyRequest,
  ): Promise<SimulateConsolePolicyResult | null>;
  listAssignments(
    ctx: ConsolePoliciesContext,
    request?: ListConsolePolicyAssignmentsRequest,
  ): Promise<ConsolePolicyAssignment[]>;
  upsertAssignment(
    ctx: ConsolePoliciesContext,
    request: UpsertConsolePolicyAssignmentRequest,
  ): Promise<ConsolePolicyAssignment>;
  deleteAssignment(
    ctx: ConsolePoliciesContext,
    assignmentId: string,
  ): Promise<{ removed: boolean; assignment: ConsolePolicyAssignment | null }>;
  resolvePoliciesForWallets(
    ctx: ConsolePoliciesContext,
    wallets: ConsolePolicyWalletScopeRef[],
  ): Promise<Record<string, string | null>>;
}

export interface InMemoryConsolePolicyServiceOptions {
  now?: () => Date;
}

interface OrgPolicyStore {
  policies: Map<string, ConsolePolicy>;
  assignments: Map<string, ConsolePolicyAssignment>;
  assignmentsByScope: Map<string, string>;
}

function makeId(prefix: string, now: Date): string {
  const ts = now.getTime().toString(36);
  const rand = Math.random().toString(36).slice(2, 10);
  return `${prefix}_${ts}_${rand}`;
}

function toIso(now: Date): string {
  return now.toISOString();
}

function clonePolicy(policy: ConsolePolicy): ConsolePolicy {
  return {
    ...policy,
    rules: { ...policy.rules },
  };
}

function cloneAssignment(assignment: ConsolePolicyAssignment): ConsolePolicyAssignment {
  return {
    ...assignment,
  };
}

function listStringValues(input: unknown): string[] {
  if (!Array.isArray(input)) return [];
  return input
    .map((entry) => String(entry || '').trim())
    .filter(Boolean);
}

function evaluatePolicyRules(
  policy: ConsolePolicy,
  request: SimulateConsolePolicyRequest,
): SimulateConsolePolicyResult['decision'] | null {
  const rules = policy.rules || {};
  const blockedActions = listStringValues((rules as Record<string, unknown>).blockedActions).map(
    (entry) => entry.toLowerCase(),
  );
  if (blockedActions.includes(String(request.action || '').toLowerCase())) return 'DENY';

  const allowedChains = listStringValues((rules as Record<string, unknown>).allowedChains).map(
    (entry) => entry.toLowerCase(),
  );
  if (allowedChains.length > 0 && request.chain) {
    if (!allowedChains.includes(String(request.chain || '').toLowerCase())) return 'DENY';
  }

  const maxAmountMinorRaw = (rules as Record<string, unknown>).maxAmountMinor;
  if (maxAmountMinorRaw !== undefined && request.amountMinor !== undefined) {
    const maxAmountMinor = Number(maxAmountMinorRaw);
    if (Number.isFinite(maxAmountMinor) && request.amountMinor > maxAmountMinor) return 'DENY';
  }

  return 'ALLOW';
}

export function createInMemoryConsolePolicyService(
  opts: InMemoryConsolePolicyServiceOptions = {},
): ConsolePolicyService {
  const nowFn = opts.now || (() => new Date());
  const stores = new Map<string, OrgPolicyStore>();

  function ensureOrgStore(ctx: ConsolePoliciesContext): OrgPolicyStore {
    let store = stores.get(ctx.orgId);
    if (!store) {
      const now = nowFn();
      const createdAt = toIso(now);
      const defaultPolicy: ConsolePolicy = {
        id: `${ctx.orgId}:policy:default`,
        orgId: ctx.orgId,
        name: 'Default Policy',
        description: 'Default policy profile for this organization',
        status: 'PUBLISHED',
        version: 1,
        rules: {
          blockedActions: [],
          allowedChains: [],
        },
        createdAt,
        updatedAt: createdAt,
        publishedAt: createdAt,
      };
      const defaultAssignment: ConsolePolicyAssignment = {
        id: `${ctx.orgId}:policy-assignment:org-default`,
        orgId: ctx.orgId,
        scopeType: 'ORG',
        scopeId: ctx.orgId,
        policyId: defaultPolicy.id,
        createdAt,
        updatedAt: createdAt,
      };
      store = {
        policies: new Map([[defaultPolicy.id, defaultPolicy]]),
        assignments: new Map([[defaultAssignment.id, defaultAssignment]]),
        assignmentsByScope: new Map([[
          scopeKey(defaultAssignment.scopeType, defaultAssignment.scopeId),
          defaultAssignment.id,
        ]]),
      };
      stores.set(ctx.orgId, store);
    }
    return store;
  }

  return {
    async listPolicies(ctx): Promise<ConsolePolicy[]> {
      const store = ensureOrgStore(ctx);
      return Array.from(store.policies.values())
        .sort((a, b) => b.updatedAt.localeCompare(a.updatedAt))
        .map((policy) => clonePolicy(policy));
    },

    async createPolicy(ctx, request): Promise<ConsolePolicy> {
      const store = ensureOrgStore(ctx);
      const now = nowFn();
      const policyId = String(request.id || makeId('policy', now)).trim();
      if (store.policies.has(policyId)) {
        throw new ConsolePolicyError('policy_already_exists', 409, `Policy ${policyId} already exists`);
      }
      const ts = toIso(now);
      const policy: ConsolePolicy = {
        id: policyId,
        orgId: ctx.orgId,
        name: request.name,
        description: request.description || null,
        status: 'DRAFT',
        version: 0,
        rules: { ...(request.rules || {}) },
        createdAt: ts,
        updatedAt: ts,
        publishedAt: null,
      };
      store.policies.set(policy.id, policy);
      return clonePolicy(policy);
    },

    async updatePolicy(ctx, policyId, request): Promise<ConsolePolicy | null> {
      const store = ensureOrgStore(ctx);
      const current = store.policies.get(policyId);
      if (!current) return null;
      if (current.status === 'ARCHIVED') {
        throw new ConsolePolicyError(
          'policy_archived',
          409,
          `Policy ${policyId} is archived and cannot be updated`,
        );
      }
      if (request.name) current.name = request.name;
      if (request.description) current.description = request.description;
      if (request.rules) current.rules = { ...request.rules };
      current.status = 'DRAFT';
      current.updatedAt = toIso(nowFn());
      store.policies.set(current.id, current);
      return clonePolicy(current);
    },

    async publishPolicy(ctx, policyId): Promise<PublishConsolePolicyResult | null> {
      const store = ensureOrgStore(ctx);
      const current = store.policies.get(policyId);
      if (!current) return null;
      if (current.status === 'ARCHIVED') {
        throw new ConsolePolicyError(
          'policy_archived',
          409,
          `Policy ${policyId} is archived and cannot be published`,
        );
      }
      const now = nowFn();
      current.status = 'PUBLISHED';
      current.version += 1;
      current.updatedAt = toIso(now);
      current.publishedAt = current.updatedAt;
      store.policies.set(current.id, current);
      return {
        published: true,
        policy: clonePolicy(current),
      };
    },

    async simulatePolicy(ctx, policyId, request): Promise<SimulateConsolePolicyResult | null> {
      const store = ensureOrgStore(ctx);
      const policy = store.policies.get(policyId);
      if (!policy) return null;
      const decision = evaluatePolicyRules(policy, request);
      const reasons: string[] = [];
      if (decision === 'DENY') {
        reasons.push('One or more policy rules denied this request');
      } else {
        reasons.push('All evaluated rules passed');
      }
      return {
        policyId: policy.id,
        decision: decision || 'DENY',
        reasons,
        evaluatedAt: toIso(nowFn()),
        policyVersion: policy.version,
      };
    },

    async listAssignments(ctx, request = {}): Promise<ConsolePolicyAssignment[]> {
      const store = ensureOrgStore(ctx);
      const scopeType = request.scopeType ? normalizeScopeType(request.scopeType) : '';
      const scopeId = String(request.scopeId || '').trim();
      return Array.from(store.assignments.values())
        .filter((assignment) => {
          if (scopeType && normalizeScopeType(assignment.scopeType) !== scopeType) return false;
          if (scopeId && String(assignment.scopeId || '').trim() !== scopeId) return false;
          return true;
        })
        .sort((a, b) => b.updatedAt.localeCompare(a.updatedAt))
        .map((assignment) => cloneAssignment(assignment));
    },

    async upsertAssignment(ctx, request): Promise<ConsolePolicyAssignment> {
      const store = ensureOrgStore(ctx);
      const policy = store.policies.get(request.policyId);
      if (!policy) {
        throw new ConsolePolicyError('policy_not_found', 404, `Policy ${request.policyId} was not found`);
      }

      const key = scopeKey(request.scopeType, request.scopeId);
      const nowIso = toIso(nowFn());
      const existingAssignmentId = store.assignmentsByScope.get(key);
      if (existingAssignmentId) {
        const existing = store.assignments.get(existingAssignmentId);
        if (!existing) {
          store.assignmentsByScope.delete(key);
        } else {
          existing.policyId = request.policyId;
          existing.updatedAt = nowIso;
          store.assignments.set(existing.id, existing);
          return cloneAssignment(existing);
        }
      }

      const assignment: ConsolePolicyAssignment = {
        id: makeId('policy_assignment', nowFn()),
        orgId: ctx.orgId,
        scopeType: request.scopeType,
        scopeId: request.scopeId,
        policyId: request.policyId,
        createdAt: nowIso,
        updatedAt: nowIso,
      };
      store.assignments.set(assignment.id, assignment);
      store.assignmentsByScope.set(key, assignment.id);
      return cloneAssignment(assignment);
    },

    async deleteAssignment(
      ctx,
      assignmentId,
    ): Promise<{ removed: boolean; assignment: ConsolePolicyAssignment | null }> {
      const store = ensureOrgStore(ctx);
      const existing = store.assignments.get(assignmentId);
      if (!existing) return { removed: false, assignment: null };
      store.assignments.delete(assignmentId);
      store.assignmentsByScope.delete(scopeKey(existing.scopeType, existing.scopeId));
      return {
        removed: true,
        assignment: cloneAssignment(existing),
      };
    },

    async resolvePoliciesForWallets(
      ctx,
      wallets,
    ): Promise<Record<string, string | null>> {
      const store = ensureOrgStore(ctx);
      const assignmentsByScope = store.assignmentsByScope;
      const assignments = store.assignments;
      const resolved: Record<string, string | null> = {};

      const orgAssignmentId = assignmentsByScope.get(scopeKey('ORG', ctx.orgId));
      const orgPolicyId = orgAssignmentId ? assignments.get(orgAssignmentId)?.policyId || null : null;

      for (const wallet of wallets) {
        const walletId = String(wallet.walletId || '').trim();
        if (!walletId) continue;
        const walletAssignmentId = assignmentsByScope.get(scopeKey('WALLET', walletId));
        if (walletAssignmentId) {
          resolved[walletId] = assignments.get(walletAssignmentId)?.policyId || null;
          continue;
        }
        const envId = String(wallet.environmentId || '').trim();
        if (envId) {
          const environmentAssignmentId = assignmentsByScope.get(scopeKey('ENVIRONMENT', envId));
          if (environmentAssignmentId) {
            resolved[walletId] = assignments.get(environmentAssignmentId)?.policyId || null;
            continue;
          }
        }
        const projectId = String(wallet.projectId || '').trim();
        if (projectId) {
          const projectAssignmentId = assignmentsByScope.get(scopeKey('PROJECT', projectId));
          if (projectAssignmentId) {
            resolved[walletId] = assignments.get(projectAssignmentId)?.policyId || null;
            continue;
          }
        }
        resolved[walletId] = orgPolicyId || wallet.fallbackPolicyId || null;
      }

      return resolved;
    },
  };
}
