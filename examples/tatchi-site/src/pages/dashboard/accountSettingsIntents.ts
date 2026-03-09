const DASHBOARD_OPEN_SELF_MEMBER_SETTINGS_STORAGE_KEY = 'dashboard:open-self-member-settings';

export const DASHBOARD_OPEN_SELF_MEMBER_SETTINGS_EVENT = 'dashboard:open-self-member-settings';

export function requestOpenSelfMemberSettings(): void {
  if (typeof window === 'undefined') return;
  try {
    window.sessionStorage.setItem(DASHBOARD_OPEN_SELF_MEMBER_SETTINGS_STORAGE_KEY, '1');
  } catch {
    // no-op
  }
  window.dispatchEvent(new Event(DASHBOARD_OPEN_SELF_MEMBER_SETTINGS_EVENT));
}

export function consumeOpenSelfMemberSettingsRequest(): boolean {
  if (typeof window === 'undefined') return false;
  try {
    const requested =
      String(
        window.sessionStorage.getItem(DASHBOARD_OPEN_SELF_MEMBER_SETTINGS_STORAGE_KEY) || '',
      ).trim() === '1';
    if (requested) {
      window.sessionStorage.removeItem(DASHBOARD_OPEN_SELF_MEMBER_SETTINGS_STORAGE_KEY);
    }
    return requested;
  } catch {
    return false;
  }
}
