export const DASHBOARD_SESSION_DRAFT_VERSION = 'v1' as const;
const DASHBOARD_SESSION_DRAFT_PREFIX = 'dashboard-draft';

export type DashboardDraftMode = 'create' | 'edit';

export interface DashboardDraftIdentity {
  route: string;
  builderId: string;
  mode: DashboardDraftMode;
  orgId: string;
  projectId: string;
  environmentId: string;
  resourceId?: string;
}

export interface StoredDashboardDraft<TForm> {
  version: typeof DASHBOARD_SESSION_DRAFT_VERSION;
  route: string;
  builderId: string;
  mode: DashboardDraftMode;
  resourceId: string | null;
  orgId: string;
  projectId: string;
  environmentId: string;
  savedAt: string;
  form: TForm;
}

export interface ReadSessionDashboardDraftArgs<TForm> {
  identity: DashboardDraftIdentity;
  parseForm: (raw: unknown) => TForm | null;
}

interface HydratedDashboardDraftRow {
  version: string;
  route: string;
  builderId: string;
  mode: DashboardDraftMode;
  resourceId: string | null;
  orgId: string;
  projectId: string;
  environmentId: string;
  savedAt: string;
  form: unknown;
}

function trimString(value: string): string {
  return String(value || '').trim();
}

function normalizeDraftIdentity(
  identity: DashboardDraftIdentity,
): Required<DashboardDraftIdentity> {
  return {
    route: trimString(identity.route),
    builderId: trimString(identity.builderId),
    mode: identity.mode,
    orgId: trimString(identity.orgId),
    projectId: trimString(identity.projectId),
    environmentId: trimString(identity.environmentId),
    resourceId: trimString(identity.resourceId || ''),
  };
}

function getSessionStorage(): Storage | null {
  if (typeof window === 'undefined') return null;
  try {
    return window.sessionStorage;
  } catch {
    return null;
  }
}

function removeDraftSilently(storage: Storage, key: string): void {
  try {
    storage.removeItem(key);
  } catch {
    // Ignore storage failures and keep in-memory form usable.
  }
}

function readStringField(record: Record<string, unknown>, key: string): string {
  const raw = record[key];
  if (typeof raw !== 'string') return '';
  return trimString(raw);
}

function isRecord(raw: unknown): raw is Record<string, unknown> {
  return Boolean(raw) && typeof raw === 'object' && !Array.isArray(raw);
}

function isDraftMode(raw: unknown): raw is DashboardDraftMode {
  return raw === 'create' || raw === 'edit';
}

function matchesIdentity(
  draft: HydratedDashboardDraftRow,
  identity: Required<DashboardDraftIdentity>,
): boolean {
  return (
    draft.version === DASHBOARD_SESSION_DRAFT_VERSION &&
    draft.route === identity.route &&
    draft.builderId === identity.builderId &&
    draft.mode === identity.mode &&
    (draft.resourceId || '') === identity.resourceId &&
    draft.orgId === identity.orgId &&
    draft.projectId === identity.projectId &&
    draft.environmentId === identity.environmentId
  );
}

export function buildDashboardDraftStorageKey(identity: DashboardDraftIdentity): string {
  const normalized = normalizeDraftIdentity(identity);
  const parts = [
    DASHBOARD_SESSION_DRAFT_PREFIX,
    DASHBOARD_SESSION_DRAFT_VERSION,
    normalized.route,
    normalized.builderId,
    normalized.orgId,
    normalized.projectId,
    normalized.environmentId,
    normalized.mode,
    normalized.resourceId,
  ];
  return parts.map((entry) => encodeURIComponent(entry)).join(':');
}

export function readSessionDashboardDraft<TForm>({
  identity,
  parseForm,
}: ReadSessionDashboardDraftArgs<TForm>): StoredDashboardDraft<TForm> | null {
  const storage = getSessionStorage();
  if (!storage) return null;
  const normalized = normalizeDraftIdentity(identity);
  const key = buildDashboardDraftStorageKey(normalized);
  try {
    const raw = storage.getItem(key);
    if (!raw) return null;
    const parsed = JSON.parse(raw);
    if (!isRecord(parsed)) {
      removeDraftSilently(storage, key);
      return null;
    }

    const modeRaw = parsed.mode;
    if (!isDraftMode(modeRaw)) {
      removeDraftSilently(storage, key);
      return null;
    }

    const hydrated: HydratedDashboardDraftRow = {
      version: readStringField(parsed, 'version'),
      route: readStringField(parsed, 'route'),
      builderId: readStringField(parsed, 'builderId'),
      mode: modeRaw,
      resourceId: readStringField(parsed, 'resourceId') || null,
      orgId: readStringField(parsed, 'orgId'),
      projectId: readStringField(parsed, 'projectId'),
      environmentId: readStringField(parsed, 'environmentId'),
      savedAt: readStringField(parsed, 'savedAt'),
      form: parsed.form,
    };

    if (!matchesIdentity(hydrated, normalized)) {
      removeDraftSilently(storage, key);
      return null;
    }

    const form = parseForm(hydrated.form);
    if (!form) {
      removeDraftSilently(storage, key);
      return null;
    }

    return {
      ...hydrated,
      version: DASHBOARD_SESSION_DRAFT_VERSION,
      form,
    };
  } catch {
    removeDraftSilently(storage, key);
    return null;
  }
}

export function writeSessionDashboardDraft<TForm>(
  identity: DashboardDraftIdentity,
  form: TForm,
): void {
  const storage = getSessionStorage();
  if (!storage) return;
  const normalized = normalizeDraftIdentity(identity);
  const key = buildDashboardDraftStorageKey(normalized);
  const payload: StoredDashboardDraft<TForm> = {
    version: DASHBOARD_SESSION_DRAFT_VERSION,
    route: normalized.route,
    builderId: normalized.builderId,
    mode: normalized.mode,
    resourceId: normalized.resourceId || null,
    orgId: normalized.orgId,
    projectId: normalized.projectId,
    environmentId: normalized.environmentId,
    savedAt: new Date().toISOString(),
    form,
  };
  try {
    storage.setItem(key, JSON.stringify(payload));
  } catch {
    // Ignore storage failures and keep in-memory form usable.
  }
}

export function clearSessionDashboardDraft(identity: DashboardDraftIdentity): void {
  const storage = getSessionStorage();
  if (!storage) return;
  const key = buildDashboardDraftStorageKey(identity);
  removeDraftSilently(storage, key);
}

export function clearSessionDashboardDraftByKey(storageKey: string): void {
  const storage = getSessionStorage();
  if (!storage) return;
  removeDraftSilently(storage, storageKey);
}
