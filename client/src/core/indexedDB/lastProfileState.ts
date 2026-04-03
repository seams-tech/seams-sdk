import type { LastProfileState } from './passkeyClientDB.types';
import { normalizeLastUserScope } from './normalization';

export function parseLastProfileState(raw: unknown): LastProfileState | null {
  if (raw == null || typeof raw !== 'object') return null;

  const profileId =
    typeof (raw as { profileId?: unknown }).profileId === 'string'
      ? String((raw as { profileId?: string }).profileId).trim()
      : '';
  if (!profileId) return null;

  const deviceNumber = Number((raw as { deviceNumber?: unknown }).deviceNumber);
  if (!Number.isSafeInteger(deviceNumber) || deviceNumber < 1) return null;

  const scope = normalizeLastUserScope((raw as { scope?: unknown }).scope);
  return scope != null ? { profileId, deviceNumber, scope } : { profileId, deviceNumber };
}
