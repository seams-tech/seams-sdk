import React from 'react';
import { useDashboardConsoleSession } from '../../consoleSession';
import { useDashboardSelectedContext } from '../../selectedContext';

export function ExportKeysSettingsPage(): React.JSX.Element {
  const session = useDashboardConsoleSession();
  const selectedContext = useDashboardSelectedContext();

  return (
    <div className="dashboard-view" aria-label="Export keys settings page">
      {session.loading ? (
        <section className="dashboard-view__section">
          <p>Loading export policy...</p>
        </section>
      ) : !session.claims ? (
        <section className="dashboard-view__section">
          <p>Export policy unavailable: {session.errorMessage || 'unauthorized'}.</p>
        </section>
      ) : (
        <section className="dashboard-view__section" aria-label="Private key export policy">
          <h2>User-controlled private key exports</h2>
          <p>End users can export their own private keys directly in the wallet experience.</p>
          <p>
            Dashboard admin request and approval controls for private key exports have been removed.
          </p>
          <p>Context environment {selectedContext.environment || '-'}.</p>
        </section>
      )}
    </div>
  );
}

export default ExportKeysSettingsPage;
