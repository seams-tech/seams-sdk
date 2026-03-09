import { ConsoleAuditError } from './errors';
import type {
  AppendConsoleAuditEvidenceRequest,
  AppendConsoleAuditEventRequest,
  ConsoleAuditEvidenceRecord,
  ConsoleAuditEvent,
  ListConsoleAuditEventsRequest,
  ListConsoleAuditEvidenceRequest,
} from './types';

export interface ConsoleAuditContext {
  orgId: string;
  actorUserId: string;
  roles: string[];
  projectId?: string;
  environmentId?: string;
}

export interface InMemoryConsoleAuditServiceOptions {
  now?: () => Date;
  seedDemoData?: boolean;
}

export interface ConsoleAuditService {
  listEvents(
    ctx: ConsoleAuditContext,
    request?: ListConsoleAuditEventsRequest,
  ): Promise<ConsoleAuditEvent[]>;
  listEvidence(
    ctx: ConsoleAuditContext,
    request?: ListConsoleAuditEvidenceRequest,
  ): Promise<ConsoleAuditEvidenceRecord[]>;
  appendEvent(
    ctx: ConsoleAuditContext,
    request: AppendConsoleAuditEventRequest,
  ): Promise<ConsoleAuditEvent>;
  appendEvidence(
    ctx: ConsoleAuditContext,
    request: AppendConsoleAuditEvidenceRequest,
  ): Promise<ConsoleAuditEvidenceRecord>;
}

interface OrgStore {
  events: Map<string, ConsoleAuditEvent>;
  evidence: Map<string, ConsoleAuditEvidenceRecord>;
  seeded: boolean;
}

function makeId(prefix: string, now: Date): string {
  return `${prefix}_${now.getTime().toString(36)}_${Math.random().toString(36).slice(2, 10)}`;
}

function toIso(date: Date): string {
  return date.toISOString();
}

function parseTimestamp(value: string): number {
  const parsed = Date.parse(value);
  return Number.isFinite(parsed) ? parsed : 0;
}

function cloneEvent(input: ConsoleAuditEvent): ConsoleAuditEvent {
  return {
    ...input,
    ...(input.projectId ? { projectId: input.projectId } : {}),
    ...(input.environmentId ? { environmentId: input.environmentId } : {}),
    metadata: { ...input.metadata },
  };
}

function cloneEvidence(input: ConsoleAuditEvidenceRecord): ConsoleAuditEvidenceRecord {
  return {
    ...input,
    ...(input.projectId ? { projectId: input.projectId } : {}),
    ...(input.environmentId ? { environmentId: input.environmentId } : {}),
    eventIds: [...input.eventIds],
    references: input.references.map((entry) => ({ ...entry })),
  };
}

function sortEvents(items: ConsoleAuditEvent[]): ConsoleAuditEvent[] {
  return [...items].sort((a, b) => {
    const tsDiff = parseTimestamp(b.createdAt) - parseTimestamp(a.createdAt);
    if (tsDiff !== 0) return tsDiff;
    return b.id.localeCompare(a.id);
  });
}

function sortEvidence(items: ConsoleAuditEvidenceRecord[]): ConsoleAuditEvidenceRecord[] {
  return [...items].sort((a, b) => {
    const tsDiff = parseTimestamp(b.createdAt) - parseTimestamp(a.createdAt);
    if (tsDiff !== 0) return tsDiff;
    return b.id.localeCompare(a.id);
  });
}

function normalizeOptionalString(value: unknown): string | undefined {
  const normalized = String(value || '').trim();
  return normalized || undefined;
}

function coerceEventIds(input: unknown): string[] {
  if (!Array.isArray(input)) return [];
  const out: string[] = [];
  const seen = new Set<string>();
  for (const row of input) {
    const value = String(row || '').trim();
    if (!value || seen.has(value)) continue;
    seen.add(value);
    out.push(value);
  }
  return out;
}

function ensureReasonableSummary(field: string, value: string): string {
  const out = String(value || '').trim();
  if (!out) {
    throw new ConsoleAuditError('invalid_body', 400, `Field ${field} is required`);
  }
  if (out.length > 1024) {
    throw new ConsoleAuditError(
      'invalid_body',
      400,
      `Field ${field} must be 1024 characters or less`,
    );
  }
  return out;
}

export function createInMemoryConsoleAuditService(
  opts: InMemoryConsoleAuditServiceOptions = {},
): ConsoleAuditService {
  const now = opts.now || (() => new Date());
  const seedDemoData = opts.seedDemoData ?? true;
  const stores = new Map<string, OrgStore>();

  function requireOrgStore(ctx: ConsoleAuditContext): OrgStore {
    let store = stores.get(ctx.orgId);
    if (!store) {
      store = {
        events: new Map<string, ConsoleAuditEvent>(),
        evidence: new Map<string, ConsoleAuditEvidenceRecord>(),
        seeded: false,
      };
      stores.set(ctx.orgId, store);
    }

    if (!seedDemoData || store.seeded) return store;

    const seedNow = now().getTime();
    const projectId = normalizeOptionalString(ctx.projectId) || 'proj_console_core';
    const environmentId = normalizeOptionalString(ctx.environmentId) || `${projectId}-prod`;

    const seededEvents: ConsoleAuditEvent[] = [
      {
        id: `aud_${(seedNow - 4 * 60_000).toString(36)}`,
        orgId: ctx.orgId,
        projectId,
        environmentId,
        actorUserId: 'console-security',
        actorType: 'USER',
        category: 'POLICY',
        action: 'policy.publish',
        outcome: 'SUCCESS',
        summary: 'Published policy v12 to production environment',
        metadata: { policyId: 'pol_default', version: 12 },
        createdAt: new Date(seedNow - 4 * 60_000).toISOString(),
      },
      {
        id: `aud_${(seedNow - 9 * 60_000).toString(36)}`,
        orgId: ctx.orgId,
        projectId,
        environmentId,
        actorUserId: 'console-admin',
        actorType: 'USER',
        category: 'API_KEY',
        action: 'api_key.update',
        outcome: 'SUCCESS',
        summary: 'Updated publishable_key allowed origins for the production environment',
        metadata: { environmentId, apiKeyId: 'ak_publishable_prod' },
        createdAt: new Date(seedNow - 9 * 60_000).toISOString(),
      },
      {
        id: `aud_${(seedNow - 25 * 60_000).toString(36)}`,
        orgId: ctx.orgId,
        projectId,
        environmentId,
        actorUserId: 'console-billing',
        actorType: 'USER',
        category: 'BILLING',
        action: 'invoice.payment.settled',
        outcome: 'SUCCESS',
        summary: 'Invoice inv_2026_02 settled via card rail',
        metadata: { invoiceId: 'inv_2026_02', rail: 'CARD', paymentIntentId: 'pi_demo_01' },
        createdAt: new Date(seedNow - 25 * 60_000).toISOString(),
      },
      {
        id: `aud_${(seedNow - 46 * 60_000).toString(36)}`,
        orgId: ctx.orgId,
        projectId,
        environmentId,
        actorUserId: 'console-owner',
        actorType: 'USER',
        category: 'TEAM',
        action: 'member.roles.update',
        outcome: 'SUCCESS',
        summary: 'Updated team member role scopes for project operations',
        metadata: { memberId: 'member_console_devops', roles: ['developer', 'ops'] },
        createdAt: new Date(seedNow - 46 * 60_000).toISOString(),
      },
    ];

    for (const event of seededEvents) {
      store.events.set(event.id, event);
    }

    const seededEvidence: ConsoleAuditEvidenceRecord[] = [
      {
        id: `evd_${(seedNow - 3 * 60_000).toString(36)}`,
        orgId: ctx.orgId,
        projectId,
        environmentId,
        domain: 'POLICY',
        title: 'Policy publish evidence bundle',
        summary: 'Evidence links for policy publish and approval chain',
        eventIds: [seededEvents[0]!.id, seededEvents[1]!.id],
        references: [
          { kind: 'APPROVAL', referenceId: 'apr_2026_001', label: 'Approval request' },
          { kind: 'LOG', referenceId: 'pol_default:v12', label: 'Policy version log' },
        ],
        createdAt: new Date(seedNow - 3 * 60_000).toISOString(),
      },
      {
        id: `evd_${(seedNow - 20 * 60_000).toString(36)}`,
        orgId: ctx.orgId,
        projectId,
        environmentId,
        domain: 'BILLING',
        title: 'Invoice settlement evidence',
        summary: 'Invoice, payment intent, and settlement trace references',
        eventIds: [seededEvents[2]!.id],
        references: [
          { kind: 'PAYMENT', referenceId: 'pi_demo_01', label: 'Stripe payment intent' },
          { kind: 'LOG', referenceId: 'inv_2026_02', label: 'Invoice ledger record' },
        ],
        createdAt: new Date(seedNow - 20 * 60_000).toISOString(),
      },
    ];

    for (const evidence of seededEvidence) {
      store.evidence.set(evidence.id, evidence);
    }
    store.seeded = true;
    return store;
  }

  return {
    async listEvents(ctx, request = {}): Promise<ConsoleAuditEvent[]> {
      const store = requireOrgStore(ctx);
      const fromTs = request.from ? parseTimestamp(request.from) : Number.NEGATIVE_INFINITY;
      const toTs = request.to ? parseTimestamp(request.to) : Number.POSITIVE_INFINITY;
      const limit = Math.max(1, Math.min(Number(request.limit || 50), 200));

      return sortEvents(Array.from(store.events.values()))
        .filter((entry) => {
          if (request.projectId && entry.projectId !== request.projectId) return false;
          if (request.environmentId && entry.environmentId !== request.environmentId) return false;
          if (request.category && entry.category !== request.category) return false;
          if (request.actorUserId && entry.actorUserId !== request.actorUserId) return false;
          if (request.outcome && entry.outcome !== request.outcome) return false;
          const createdAtTs = parseTimestamp(entry.createdAt);
          if (createdAtTs < fromTs || createdAtTs > toTs) return false;
          return true;
        })
        .slice(0, limit)
        .map(cloneEvent);
    },

    async listEvidence(ctx, request = {}): Promise<ConsoleAuditEvidenceRecord[]> {
      const store = requireOrgStore(ctx);
      const fromTs = request.from ? parseTimestamp(request.from) : Number.NEGATIVE_INFINITY;
      const toTs = request.to ? parseTimestamp(request.to) : Number.POSITIVE_INFINITY;
      const limit = Math.max(1, Math.min(Number(request.limit || 50), 200));

      return sortEvidence(Array.from(store.evidence.values()))
        .filter((entry) => {
          if (request.projectId && entry.projectId !== request.projectId) return false;
          if (request.environmentId && entry.environmentId !== request.environmentId) return false;
          if (request.domain && entry.domain !== request.domain) return false;
          const createdAtTs = parseTimestamp(entry.createdAt);
          if (createdAtTs < fromTs || createdAtTs > toTs) return false;
          return true;
        })
        .slice(0, limit)
        .map(cloneEvidence);
    },

    async appendEvent(ctx, request): Promise<ConsoleAuditEvent> {
      const store = requireOrgStore(ctx);
      const nowValue = now();
      const event: ConsoleAuditEvent = {
        id: normalizeOptionalString(request.id) || makeId('aud', nowValue),
        orgId: ctx.orgId,
        ...(normalizeOptionalString(request.projectId)
          ? { projectId: normalizeOptionalString(request.projectId) }
          : {}),
        ...(normalizeOptionalString(request.environmentId)
          ? { environmentId: normalizeOptionalString(request.environmentId) }
          : {}),
        actorUserId: normalizeOptionalString(request.actorUserId) || ctx.actorUserId,
        actorType: request.actorType || 'USER',
        category: request.category,
        action: ensureReasonableSummary('action', request.action),
        outcome: request.outcome,
        summary: ensureReasonableSummary('summary', request.summary),
        metadata:
          request.metadata &&
          typeof request.metadata === 'object' &&
          !Array.isArray(request.metadata)
            ? { ...request.metadata }
            : {},
        createdAt: toIso(nowValue),
      };
      if (store.events.has(event.id)) {
        throw new ConsoleAuditError(
          'event_already_exists',
          409,
          `Audit event ${event.id} already exists`,
        );
      }
      store.events.set(event.id, event);
      return cloneEvent(event);
    },

    async appendEvidence(ctx, request): Promise<ConsoleAuditEvidenceRecord> {
      const store = requireOrgStore(ctx);
      const nowValue = now();
      const evidence: ConsoleAuditEvidenceRecord = {
        id: normalizeOptionalString(request.id) || makeId('evd', nowValue),
        orgId: ctx.orgId,
        ...(normalizeOptionalString(request.projectId)
          ? { projectId: normalizeOptionalString(request.projectId) }
          : {}),
        ...(normalizeOptionalString(request.environmentId)
          ? { environmentId: normalizeOptionalString(request.environmentId) }
          : {}),
        domain: request.domain,
        title: ensureReasonableSummary('title', request.title),
        summary: ensureReasonableSummary('summary', request.summary),
        eventIds: coerceEventIds(request.eventIds),
        references: Array.isArray(request.references)
          ? request.references
              .map((entry) => ({
                kind: entry.kind,
                referenceId: String(entry.referenceId || '').trim(),
                label: String(entry.label || '').trim(),
              }))
              .filter((entry) => entry.referenceId && entry.label)
          : [],
        createdAt: toIso(nowValue),
      };
      if (store.evidence.has(evidence.id)) {
        throw new ConsoleAuditError(
          'evidence_already_exists',
          409,
          `Audit evidence ${evidence.id} already exists`,
        );
      }
      store.evidence.set(evidence.id, evidence);
      return cloneEvidence(evidence);
    },
  };
}
