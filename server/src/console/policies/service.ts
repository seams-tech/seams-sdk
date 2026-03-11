import { ConsolePolicyError } from './errors';
import {
  normalizePolicyScopeType as normalizeScopeType,
  policyScopeKey as scopeKey,
} from './normalization';
import {
  cloneConsolePolicyRules,
  createDefaultConsolePolicyRules,
  evaluateConsolePolicyRules,
  parseConsolePolicyRulesInput,
} from './rules';
import type {
  ConsolePolicyAssignment,
  ConsolePolicyWalletScopeRef,
  ConsolePolicy,
  ConsolePolicyVersion,
  CreateConsolePolicyRequest,
  DeleteConsolePolicyResult,
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
  getPolicy(ctx: ConsolePoliciesContext, policyId: string): Promise<ConsolePolicy | null>;
  listPolicyVersions(
    ctx: ConsolePoliciesContext,
    policyId: string,
  ): Promise<ConsolePolicyVersion[] | null>;
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
  deletePolicy(
    ctx: ConsolePoliciesContext,
    policyId: string,
  ): Promise<DeleteConsolePolicyResult>;
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
  versions: Map<string, ConsolePolicyVersion[]>;
  assignments: Map<string, ConsolePolicyAssignment>;
  assignmentsByScope: Map<string, string>;
}

const DEFAULT_POLICY_NAME = 'Default Policy';
const DEFAULT_POLICY_DESCRIPTION = 'Default policy profile for this organization';

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
    rules: cloneConsolePolicyRules(policy.rules),
  };
}

function cloneAssignment(assignment: ConsolePolicyAssignment): ConsolePolicyAssignment {
  return {
    ...assignment,
  };
}

function clonePolicyVersion(version: ConsolePolicyVersion): ConsolePolicyVersion {
  return {
    ...version,
    rules: cloneConsolePolicyRules(version.rules),
  };
}

function hasPublishedPolicyVersion(policy: ConsolePolicy | null | undefined): boolean {
  return Boolean(policy && String(policy.publishedAt || '').trim() && Number(policy.version || 0) > 0);
}

function generateUniquePolicyId(store: OrgPolicyStore, now: Date): string {
  for (let attempt = 0; attempt < 8; attempt += 1) {
    const candidate = makeId('policy', now);
    if (!store.policies.has(candidate)) return candidate;
  }
  throw new ConsolePolicyError('internal', 500, 'Failed to generate a unique policy id');
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
      const defaultPolicyId = makeId('policy', now);
      const defaultPolicy: ConsolePolicy = {
        id: defaultPolicyId,
        orgId: ctx.orgId,
        isSystemDefault: true,
        name: DEFAULT_POLICY_NAME,
        description: DEFAULT_POLICY_DESCRIPTION,
        status: 'PUBLISHED',
        version: 1,
        rules: createDefaultConsolePolicyRules(),
        createdAt,
        updatedAt: createdAt,
        publishedAt: createdAt,
      };
      const defaultAssignment: ConsolePolicyAssignment = {
        id: makeId('policy_assignment', now),
        orgId: ctx.orgId,
        scopeType: 'ORG',
        scopeId: ctx.orgId,
        policyId: defaultPolicy.id,
        createdAt,
        updatedAt: createdAt,
      };
      store = {
        policies: new Map([[defaultPolicy.id, defaultPolicy]]),
        versions: new Map([
          [
            defaultPolicy.id,
            [
              {
                policyId: defaultPolicy.id,
                version: defaultPolicy.version,
                status: defaultPolicy.status,
                rules: cloneConsolePolicyRules(defaultPolicy.rules),
                publishedAt: defaultPolicy.publishedAt,
                createdAt,
                actorUserId: 'system-bootstrap',
              },
            ],
          ],
        ]),
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

  function upsertAssignmentInStore(
    store: OrgPolicyStore,
    ctx: ConsolePoliciesContext,
    request: UpsertConsolePolicyAssignmentRequest,
    nowIso: string = toIso(nowFn()),
  ): ConsolePolicyAssignment {
    const key = scopeKey(request.scopeType, request.scopeId);
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
  }

  return {
    async listPolicies(ctx): Promise<ConsolePolicy[]> {
      const store = ensureOrgStore(ctx);
      return Array.from(store.policies.values())
        .sort((a, b) => b.updatedAt.localeCompare(a.updatedAt))
        .map((policy) => clonePolicy(policy));
    },

    async getPolicy(ctx, policyId): Promise<ConsolePolicy | null> {
      const store = ensureOrgStore(ctx);
      const policy = store.policies.get(policyId);
      return policy ? clonePolicy(policy) : null;
    },

    async listPolicyVersions(ctx, policyId): Promise<ConsolePolicyVersion[] | null> {
      const store = ensureOrgStore(ctx);
      if (!store.policies.has(policyId)) return null;
      return [...(store.versions.get(policyId) || [])]
        .sort((a, b) => b.version - a.version || b.createdAt.localeCompare(a.createdAt))
        .map((version) => clonePolicyVersion(version));
    },

    async createPolicy(ctx, request): Promise<ConsolePolicy> {
      const store = ensureOrgStore(ctx);
      const now = nowFn();
      const policyId = generateUniquePolicyId(store, now);
      const ts = toIso(now);
      const policy: ConsolePolicy = {
        id: policyId,
        orgId: ctx.orgId,
        isSystemDefault: false,
        name: request.name,
        description: request.description || null,
        status: 'DRAFT',
        version: 0,
        rules: parseConsolePolicyRulesInput(request.rules),
        createdAt: ts,
        updatedAt: ts,
        publishedAt: null,
      };
      store.policies.set(policy.id, policy);
      if (request.assignment) {
        upsertAssignmentInStore(store, ctx, {
          scopeType: request.assignment.scopeType,
          scopeId: request.assignment.scopeId,
          policyId: policy.id,
        }, ts);
      }
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
      if (request.description !== undefined) current.description = request.description || null;
      if (request.rules) current.rules = parseConsolePolicyRulesInput(request.rules);
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
      const nextVersions = [
        ...(store.versions.get(current.id) || []).filter((entry) => entry.version !== current.version),
        {
          policyId: current.id,
          version: current.version,
          status: current.status,
          rules: cloneConsolePolicyRules(current.rules),
          publishedAt: current.publishedAt,
          createdAt: current.updatedAt,
          actorUserId: ctx.actorUserId,
        },
      ].sort((a, b) => b.version - a.version || b.createdAt.localeCompare(a.createdAt));
      store.versions.set(current.id, nextVersions);
      return {
        published: true,
        policy: clonePolicy(current),
      };
    },

    async deletePolicy(ctx, policyId): Promise<DeleteConsolePolicyResult> {
      const store = ensureOrgStore(ctx);
      const current = store.policies.get(policyId);
      if (!current) {
        return { removed: false, policy: null };
      }
      if (current.isSystemDefault) {
        throw new ConsolePolicyError(
          'default_policy_protected',
          409,
          `Policy ${policyId} is the organization default and cannot be deleted`,
        );
      }
      for (const assignment of Array.from(store.assignments.values())) {
        if (assignment.policyId !== policyId) continue;
        store.assignments.delete(assignment.id);
        store.assignmentsByScope.delete(scopeKey(assignment.scopeType, assignment.scopeId));
      }
      store.policies.delete(policyId);
      store.versions.delete(policyId);
      return {
        removed: true,
        policy: clonePolicy(current),
      };
    },

    async simulatePolicy(ctx, policyId, request): Promise<SimulateConsolePolicyResult | null> {
      const store = ensureOrgStore(ctx);
      const policy = store.policies.get(policyId);
      if (!policy) return null;
      const evaluation = evaluateConsolePolicyRules(policy.rules, request);
      return {
        policyId: policy.id,
        decision: evaluation.decision,
        denyReasons: evaluation.denyReasons,
        evaluatedAt: toIso(nowFn()),
        policyVersion: policy.version,
        normalizedRequest: evaluation.normalizedRequest,
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

      return upsertAssignmentInStore(store, ctx, request);
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

      const resolveLiveAssignedPolicyId = (
        scopeType: ConsolePolicyAssignment['scopeType'],
        scopeId: string,
      ): string | null => {
        const assignmentId = assignmentsByScope.get(scopeKey(scopeType, scopeId));
        if (!assignmentId) return null;
        const assignment = assignments.get(assignmentId);
        if (!assignment) return null;
        const policy = store.policies.get(assignment.policyId);
        return hasPublishedPolicyVersion(policy) ? assignment.policyId : null;
      };

      const orgPolicyId = resolveLiveAssignedPolicyId('ORG', ctx.orgId);

      for (const wallet of wallets) {
        const walletId = String(wallet.walletId || '').trim();
        if (!walletId) continue;
        const walletPolicyId = resolveLiveAssignedPolicyId('WALLET', walletId);
        if (walletPolicyId) {
          resolved[walletId] = walletPolicyId;
          continue;
        }
        const envId = String(wallet.environmentId || '').trim();
        if (envId) {
          const environmentPolicyId = resolveLiveAssignedPolicyId('ENVIRONMENT', envId);
          if (environmentPolicyId) {
            resolved[walletId] = environmentPolicyId;
            continue;
          }
        }
        const projectId = String(wallet.projectId || '').trim();
        if (projectId) {
          const projectPolicyId = resolveLiveAssignedPolicyId('PROJECT', projectId);
          if (projectPolicyId) {
            resolved[walletId] = projectPolicyId;
            continue;
          }
        }
        resolved[walletId] = orgPolicyId || wallet.fallbackPolicyId || null;
      }

      return resolved;
    },
  };
}
