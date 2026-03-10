import React from 'react';
import { BillingConsoleShell } from './BillingConsoleShell';

export function BillingAccountPage(): React.JSX.Element {
  return <BillingConsoleShell defaultPath="/dashboard/billing/account" />;
}

export default BillingAccountPage;
