import React from 'react';
import type { TopbarContextState } from './types';

const EMPTY_DASHBOARD_SELECTED_CONTEXT: TopbarContextState = {
  organization: '',
  project: '',
  environment: '',
  accountSettings: '',
};

const DashboardSelectedContext = React.createContext<TopbarContextState>(
  EMPTY_DASHBOARD_SELECTED_CONTEXT,
);

export function DashboardSelectedContextProvider({
  value,
  children,
}: {
  value: TopbarContextState;
  children: React.ReactNode;
}): React.JSX.Element {
  return (
    <DashboardSelectedContext.Provider value={value}>{children}</DashboardSelectedContext.Provider>
  );
}

export function useDashboardSelectedContext(): TopbarContextState {
  return React.useContext(DashboardSelectedContext);
}
