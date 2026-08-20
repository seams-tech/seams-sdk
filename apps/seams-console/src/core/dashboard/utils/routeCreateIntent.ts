/* Sidebar "+" affordances deep-link straight into a route's create modal.
   The intent rides in the query string so a normal link navigation carries it,
   then the route clears it so a reload does not reopen the dialog. */

export const DASHBOARD_CREATE_INTENT_PARAM = 'new';

export function dashboardCreateIntentHref(path: string): string {
  return `${path}?${DASHBOARD_CREATE_INTENT_PARAM}=1`;
}

export function readDashboardCreateIntent(): boolean {
  if (typeof window === 'undefined') return false;
  return new URLSearchParams(window.location.search).get(DASHBOARD_CREATE_INTENT_PARAM) === '1';
}

export function clearDashboardCreateIntent(): void {
  if (typeof window === 'undefined') return;
  const url = new URL(window.location.href);
  if (!url.searchParams.has(DASHBOARD_CREATE_INTENT_PARAM)) return;
  url.searchParams.delete(DASHBOARD_CREATE_INTENT_PARAM);
  window.history.replaceState({}, '', `${url.pathname}${url.search}${url.hash}`);
}
