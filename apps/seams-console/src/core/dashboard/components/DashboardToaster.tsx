import * as React from 'react';
import { Toaster } from 'sonner';

/* One toast host for the whole console. Mounted at the app root rather than in
   the dashboard shell so the login route and the shell share a single stack —
   two hosts would render a mutation confirmation twice. */
export function DashboardToaster(): React.JSX.Element {
  return (
    <Toaster
      className="dashboard-toaster"
      position="bottom-right"
      offset={20}
      gap={10}
      duration={4000}
      visibleToasts={4}
      /* Width is an inline sonner variable, so it has to travel as a prop. */
      style={{ '--width': '380px' } as React.CSSProperties}
      toastOptions={{ className: 'dashboard-toast' }}
    />
  );
}

export default DashboardToaster;
