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
const DashboardSelectedContextDisplay = React.createContext<TopbarContextState>(
  EMPTY_DASHBOARD_SELECTED_CONTEXT,
);

export function DashboardSelectedContextProvider({
  value,
  displayValue,
  children,
}: {
  value: TopbarContextState;
  displayValue?: TopbarContextState;
  children: React.ReactNode;
}): React.JSX.Element {
  return (
    <DashboardSelectedContext.Provider value={value}>
      <DashboardSelectedContextDisplay.Provider value={displayValue || value}>
        {children}
      </DashboardSelectedContextDisplay.Provider>
    </DashboardSelectedContext.Provider>
  );
}

export function useDashboardSelectedContext(): TopbarContextState {
  return React.useContext(DashboardSelectedContext);
}

export function useDashboardSelectedContextDisplay(): TopbarContextState {
  return React.useContext(DashboardSelectedContextDisplay);
}
