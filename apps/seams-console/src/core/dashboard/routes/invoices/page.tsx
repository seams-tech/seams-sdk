import React from 'react';
import { BillingConsoleShell } from '../billing/BillingConsoleShell';

export function InvoicesPage(): React.JSX.Element {
  return <BillingConsoleShell defaultPath="/dashboard/invoices" />;
}

export default InvoicesPage;
