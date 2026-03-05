const DASHBOARD_ACTOR_STORAGE_KEY = 'tatchi.dashboard.actor_user_id.v1';

function normalizeActorUserId(raw: unknown): string {
  return String(raw || '').trim();
}

export function readDashboardActorUserId(): string | undefined {
  if (typeof window === 'undefined') return undefined;
  try {
    const raw = window.localStorage.getItem(DASHBOARD_ACTOR_STORAGE_KEY);
    const normalized = normalizeActorUserId(raw);
    return normalized || undefined;
  } catch {
    return undefined;
  }
}

export function writeDashboardActorUserId(userId: string): void {
  if (typeof window === 'undefined') return;
  const normalized = normalizeActorUserId(userId);
  if (!normalized) return;
  try {
    window.localStorage.setItem(DASHBOARD_ACTOR_STORAGE_KEY, normalized);
  } catch {
    // no-op
  }
}

export function clearDashboardActorUserId(): void {
  if (typeof window === 'undefined') return;
  try {
    window.localStorage.removeItem(DASHBOARD_ACTOR_STORAGE_KEY);
  } catch {
    // no-op
  }
}

