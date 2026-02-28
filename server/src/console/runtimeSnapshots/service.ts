import type {
  ConsoleRuntimeSnapshot,
  ConsoleRuntimeSnapshotPayload,
  GetLatestConsoleRuntimeSnapshotRequest,
  ListConsoleRuntimeSnapshotsRequest,
  PublishConsoleRuntimeSnapshotRequest,
} from './types';

export interface ConsoleRuntimeSnapshotContext {
  orgId: string;
  actorUserId: string;
  roles: string[];
}

export interface InMemoryConsoleRuntimeSnapshotServiceOptions {
  now?: () => Date;
}

export interface ConsoleRuntimeSnapshotService {
  listSnapshots(
    ctx: ConsoleRuntimeSnapshotContext,
    request: ListConsoleRuntimeSnapshotsRequest,
  ): Promise<ConsoleRuntimeSnapshot[]>;
  getLatestSnapshot(
    ctx: ConsoleRuntimeSnapshotContext,
    request: GetLatestConsoleRuntimeSnapshotRequest,
  ): Promise<ConsoleRuntimeSnapshot | null>;
  publishSnapshot(
    ctx: ConsoleRuntimeSnapshotContext,
    request: PublishConsoleRuntimeSnapshotRequest,
  ): Promise<ConsoleRuntimeSnapshot>;
}

function normalizeProjectId(projectId: string | undefined | null): string | null {
  const value = String(projectId || '').trim();
  return value || null;
}

function makeScopeKey(projectId: string | null, environmentId: string): string {
  return `${projectId || ''}::${environmentId}`;
}

function cloneObject(input: Record<string, unknown>): Record<string, unknown> {
  return JSON.parse(JSON.stringify(input || {})) as Record<string, unknown>;
}

function clonePayload(input: ConsoleRuntimeSnapshotPayload): ConsoleRuntimeSnapshotPayload {
  return {
    policy: cloneObject(input.policy),
    settings: cloneObject(input.settings),
    gasSponsorship: cloneObject(input.gasSponsorship),
    smartWallets: cloneObject(input.smartWallets),
    ...(input.metadata ? { metadata: cloneObject(input.metadata) } : {}),
  };
}

function cloneSnapshot(input: ConsoleRuntimeSnapshot): ConsoleRuntimeSnapshot {
  return {
    ...input,
    payload: clonePayload(input.payload),
  };
}

function stableJsonStringify(value: unknown): string {
  if (value === null || value === undefined) return 'null';
  if (typeof value === 'number') return Number.isFinite(value) ? String(value) : 'null';
  if (typeof value === 'boolean') return value ? 'true' : 'false';
  if (typeof value === 'string') return JSON.stringify(value);
  if (Array.isArray(value)) {
    return `[${value.map((entry) => stableJsonStringify(entry)).join(',')}]`;
  }
  if (typeof value === 'object') {
    const row = value as Record<string, unknown>;
    const keys = Object.keys(row).sort();
    const entries: string[] = [];
    for (const key of keys) {
      entries.push(`${JSON.stringify(key)}:${stableJsonStringify(row[key])}`);
    }
    return `{${entries.join(',')}}`;
  }
  return 'null';
}

function hashFNV1A32(input: string): string {
  let hash = 0x811c9dc5;
  for (let i = 0; i < input.length; i += 1) {
    hash ^= input.charCodeAt(i);
    hash = Math.imul(hash, 0x01000193);
  }
  const hex = (hash >>> 0).toString(16).padStart(8, '0');
  return `fnv1a32:${hex}`;
}

export function computeConsoleRuntimeSnapshotChecksum(input: {
  orgId: string;
  projectId: string | null;
  environmentId: string;
  snapshotId: string;
  version: number;
  effectiveAt: string;
  payload: ConsoleRuntimeSnapshotPayload;
}): string {
  const serialized = stableJsonStringify({
    orgId: input.orgId,
    projectId: input.projectId,
    environmentId: input.environmentId,
    snapshotId: input.snapshotId,
    version: input.version,
    effectiveAt: input.effectiveAt,
    payload: input.payload,
  });
  return hashFNV1A32(serialized);
}

function makeSnapshotId(now: Date): string {
  return `runtime_snapshot_${now.getTime().toString(36)}_${Math.random().toString(16).slice(2, 10)}`;
}

function readEffectiveAt(input: string | undefined, fallback: Date): string {
  if (!input) return fallback.toISOString();
  const asDate = new Date(input);
  if (!Number.isFinite(asDate.getTime())) return fallback.toISOString();
  return asDate.toISOString();
}

interface SnapshotStore {
  rows: ConsoleRuntimeSnapshot[];
}

function sortByVersionDesc(rows: ConsoleRuntimeSnapshot[]): ConsoleRuntimeSnapshot[] {
  return [...rows].sort((a, b) => {
    if (b.version !== a.version) return b.version - a.version;
    return Date.parse(b.createdAt) - Date.parse(a.createdAt);
  });
}

export function createInMemoryConsoleRuntimeSnapshotService(
  opts: InMemoryConsoleRuntimeSnapshotServiceOptions = {},
): ConsoleRuntimeSnapshotService {
  const nowFn = opts.now || (() => new Date());
  const stores = new Map<string, Map<string, SnapshotStore>>();

  function requireOrgStore(orgId: string): Map<string, SnapshotStore> {
    let store = stores.get(orgId);
    if (!store) {
      store = new Map<string, SnapshotStore>();
      stores.set(orgId, store);
    }
    return store;
  }

  function requireScopeStore(
    orgId: string,
    environmentId: string,
    projectId: string | null,
  ): SnapshotStore {
    const orgStore = requireOrgStore(orgId);
    const key = makeScopeKey(projectId, environmentId);
    let scope = orgStore.get(key);
    if (!scope) {
      scope = { rows: [] };
      orgStore.set(key, scope);
    }
    return scope;
  }

  function listScopeRows(
    orgId: string,
    environmentId: string,
    projectId: string | null,
  ): ConsoleRuntimeSnapshot[] {
    const orgStore = stores.get(orgId);
    if (!orgStore) return [];
    const key = makeScopeKey(projectId, environmentId);
    const scope = orgStore.get(key);
    if (!scope) return [];
    return sortByVersionDesc(scope.rows).map((row) => cloneSnapshot(row));
  }

  return {
    async listSnapshots(ctx, request): Promise<ConsoleRuntimeSnapshot[]> {
      const projectId = normalizeProjectId(request.projectId);
      const limit = request.limit || 20;
      return listScopeRows(ctx.orgId, request.environmentId, projectId).slice(0, limit);
    },

    async getLatestSnapshot(ctx, request): Promise<ConsoleRuntimeSnapshot | null> {
      const projectId = normalizeProjectId(request.projectId);
      const rows = listScopeRows(ctx.orgId, request.environmentId, projectId);
      return rows[0] || null;
    },

    async publishSnapshot(ctx, request): Promise<ConsoleRuntimeSnapshot> {
      const now = nowFn();
      const projectId = normalizeProjectId(request.projectId);
      const scope = requireScopeStore(ctx.orgId, request.environmentId, projectId);
      const version = scope.rows.length + 1;
      const snapshotId = String(request.snapshotId || makeSnapshotId(now)).trim();
      const effectiveAt = readEffectiveAt(request.effectiveAt, now);
      const payload = clonePayload(request.payload);
      const checksum = computeConsoleRuntimeSnapshotChecksum({
        orgId: ctx.orgId,
        projectId,
        environmentId: request.environmentId,
        snapshotId,
        version,
        effectiveAt,
        payload,
      });
      const createdAt = now.toISOString();
      const snapshot: ConsoleRuntimeSnapshot = {
        orgId: ctx.orgId,
        projectId,
        environmentId: request.environmentId,
        snapshotId,
        version,
        effectiveAt,
        checksum,
        payload,
        createdAt,
        createdBy: ctx.actorUserId,
      };
      scope.rows.push(cloneSnapshot(snapshot));
      return cloneSnapshot(snapshot);
    },
  };
}
