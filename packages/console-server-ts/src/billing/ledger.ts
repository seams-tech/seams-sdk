import { ConsoleBillingError } from './errors';
import type {
  BillingBalancedPostings,
  BillingLedgerAccountCode,
  BillingLedgerEntry,
  BillingLedgerEntryType,
} from './types';

const ORG_PREPAID_ACCOUNT = 'org_prepaid_liability' as const;

function assertNever(value: never): never {
  throw new Error(`Unhandled billing ledger entry type: ${String(value)}`);
}

function requireEntryDirection(type: BillingLedgerEntryType, amountMinor: number): void {
  if (!Number.isInteger(amountMinor) || amountMinor === 0) {
    throw new ConsoleBillingError(
      'invalid_ledger_entry',
      500,
      'Billing ledger amount must be a non-zero integer',
    );
  }
  switch (type) {
    case 'CREDIT_PURCHASE':
    case 'DISPUTE_WON':
      if (amountMinor > 0) return;
      break;
    case 'USAGE_DEBIT':
    case 'PRODUCT_EXECUTION_DEBIT':
    case 'REFUND':
    case 'DISPUTE_OPENED':
      if (amountMinor < 0) return;
      break;
    case 'MANUAL_ADJUSTMENT':
      return;
    default:
      return assertNever(type);
  }
  throw new ConsoleBillingError(
    'invalid_ledger_entry',
    500,
    `${type} has an invalid amount direction`,
  );
}

function counterpartAccount(type: BillingLedgerEntryType): BillingLedgerAccountCode {
  switch (type) {
    case 'CREDIT_PURCHASE':
    case 'REFUND':
      return 'stripe_cash_clearing';
    case 'USAGE_DEBIT':
      return 'revenue_usage';
    case 'PRODUCT_EXECUTION_DEBIT':
      return 'revenue_product_execution';
    case 'MANUAL_ADJUSTMENT':
      return 'manual_adjustment_clearing';
    case 'DISPUTE_OPENED':
    case 'DISPUTE_WON':
      return 'stripe_dispute_clearing';
    default:
      return assertNever(type);
  }
}

export function buildBillingBalancedPostings(input: {
  entryId: string;
  type: BillingLedgerEntryType;
  amountMinor: number;
  createdAt: string;
}): BillingBalancedPostings {
  requireEntryDirection(input.type, input.amountMinor);
  const amountMinor = Math.abs(input.amountMinor);
  const counterpart = counterpartAccount(input.type);
  const debitAccount = input.amountMinor > 0 ? counterpart : ORG_PREPAID_ACCOUNT;
  const creditAccount = input.amountMinor > 0 ? ORG_PREPAID_ACCOUNT : counterpart;
  return [
    {
      id: `${input.entryId}:debit`,
      ledgerEntryId: input.entryId,
      accountCode: debitAccount,
      direction: 'DEBIT',
      amountMinor,
      createdAt: input.createdAt,
    },
    {
      id: `${input.entryId}:credit`,
      ledgerEntryId: input.entryId,
      accountCode: creditAccount,
      direction: 'CREDIT',
      amountMinor,
      createdAt: input.createdAt,
    },
  ];
}

export function assertBillingEntryBalances(entry: BillingLedgerEntry): void {
  const [debit, credit] = entry.postings;
  if (
    debit.direction !== 'DEBIT' ||
    credit.direction !== 'CREDIT' ||
    debit.amountMinor !== credit.amountMinor ||
    debit.ledgerEntryId !== entry.id ||
    credit.ledgerEntryId !== entry.id
  ) {
    throw new ConsoleBillingError(
      'corrupt_billing_ledger',
      500,
      `Billing ledger entry ${entry.id} does not have balanced postings`,
    );
  }
}

export function billingBalanceFromEntries(entries: readonly BillingLedgerEntry[]): number {
  let balanceMinor = 0;
  for (const entry of entries) {
    assertBillingEntryBalances(entry);
    for (const posting of entry.postings) {
      if (posting.accountCode !== ORG_PREPAID_ACCOUNT) continue;
      balanceMinor += posting.direction === 'CREDIT' ? posting.amountMinor : -posting.amountMinor;
    }
  }
  return balanceMinor;
}
