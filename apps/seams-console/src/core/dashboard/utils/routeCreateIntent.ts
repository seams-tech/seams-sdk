/* Sidebar "+" affordances deep-link straight into a route's create modal.
   The intent rides in the query string so a normal link navigation carries it,
   then the route clears it so a reload does not reopen the dialog. */

import * as React from 'react';

import type { DashboardRoute } from '../types';

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

/* Consuming the intent is a navigation event, not a mount event. The rail's
   "+" pushes ?new=1 even when its own route is already on screen, and that
   push re-renders nothing the route depends on — so a mount-scoped read fires
   for the first click of a session and never again. Re-read on every
   navigation instead, and gate on `ready` so the dialog waits for the scope
   and permissions it needs.

   `route` is not decoration: the page you are leaving is still mounted when
   the "+" of another route pushes its intent, and without the check it would
   swallow the param and open its own dialog before the router swaps. */
export function useDashboardCreateIntent(
  route: DashboardRoute,
  ready: boolean,
  openCreateModal: () => void,
): void {
  const openCreateModalRef = React.useRef(openCreateModal);
  openCreateModalRef.current = openCreateModal;

  React.useEffect(() => {
    if (typeof window === 'undefined') return;
    if (!ready) return;
    const consumeCreateIntent = () => {
      if (window.location.pathname !== route) return;
      if (!readDashboardCreateIntent()) return;
      /* Clearing uses replaceState, which fires no navigation event, so this
         cannot re-enter. */
      clearDashboardCreateIntent();
      openCreateModalRef.current();
    };
    consumeCreateIntent();
    window.addEventListener('popstate', consumeCreateIntent);
    window.addEventListener('site:navigate', consumeCreateIntent as EventListener);
    return () => {
      window.removeEventListener('popstate', consumeCreateIntent);
      window.removeEventListener('site:navigate', consumeCreateIntent as EventListener);
    };
  }, [ready, route]);
}
