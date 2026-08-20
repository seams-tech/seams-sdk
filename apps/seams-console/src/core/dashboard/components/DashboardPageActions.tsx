import React from 'react';
import { createPortal } from 'react-dom';

export const DASHBOARD_PAGE_ACTIONS_SLOT_ID = 'dashboard-page-actions';

/* The page title is owned by the shell, but each route owns its primary
   action. Rather than duplicate the heading per route, routes portal their
   action into the slot the shell renders next to the <h1>, so every page reads
   as one header row instead of a title stacked on a section header. */
export function DashboardPageActions({
  children,
}: {
  children: React.ReactNode;
}): React.JSX.Element | null {
  const [slot, setSlot] = React.useState<HTMLElement | null>(null);

  React.useEffect(() => {
    setSlot(document.getElementById(DASHBOARD_PAGE_ACTIONS_SLOT_ID));
  }, []);

  if (!slot) return null;
  return createPortal(children, slot);
}
