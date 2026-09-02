import type { LastProfileState } from './passkeyClientDB.types';
import { normalizeLastUserScope } from './normalization';

export function parseLastProfileState(raw: unknown): LastProfileState | null {
  if (raw == null || typeof raw !== 'object') return null;

  const profileId =
    typeof (raw as { profileId?: unknown }).profileId === 'string'
      ? String((raw as { profileId?: string }).profileId).trim()
      : '';
  if (!profileId) return null;

  const activeSignerSlot = Number((raw as { activeSignerSlot?: unknown }).activeSignerSlot);
  if (!Number.isSafeInteger(activeSignerSlot) || activeSignerSlot < 1) return null;

  const scope = normalizeLastUserScope((raw as { scope?: unknown }).scope);
  return scope != null
    ? { profileId, activeSignerSlot, scope }
    : { profileId, activeSignerSlot };
}
