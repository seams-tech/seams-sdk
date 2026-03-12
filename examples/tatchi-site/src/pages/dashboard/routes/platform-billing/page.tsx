import React from 'react';
import { BillingConsoleShell } from '../billing/BillingConsoleShell';

export function PlatformBillingPage(): React.JSX.Element {
  return <BillingConsoleShell defaultPath="/platform/billing" />;
}

export default PlatformBillingPage;
