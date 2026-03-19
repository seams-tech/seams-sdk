import type { ConsoleBillingContext, ConsoleBillingService } from '../billing/service';
import type { BillingSponsoredExecutionDebitEntry } from '../billing/types';
import type { ConsoleSponsoredCallService } from './service';
import type {
  ConsoleSponsoredCallReconciliationEntry,
  ConsoleSponsoredCallReconciliationPage,
  ConsoleSponsoredCallReconciliationStatus,
  ConsoleSponsoredCallRecord,
  ListConsoleSponsoredCallRecordsRequest,
} from './types';

function buildReconciliationEntry(
  record: ConsoleSponsoredCallRecord,
  billingDebit: BillingSponsoredExecutionDebitEntry | null,
): ConsoleSponsoredCallReconciliationEntry {
  const mismatchReasons: string[] = [];
  if (record.charged) {
    if (!record.billingLedgerEntryId) {
      mismatchReasons.push('charged_record_missing_billing_link');
    }
    if (!billingDebit) {
      mismatchReasons.push('charged_record_missing_billing_debit');
    }
    if (billingDebit && billingDebit.amountMinor >= 0) {
      mismatchReasons.push('billing_debit_amount_must_be_negative');
    }
    if (
      billingDebit &&
      record.settledSpendMinor != null &&
      Math.abs(billingDebit.amountMinor) !== record.settledSpendMinor
    ) {
      mismatchReasons.push('settled_spend_minor_does_not_match_billing_amount');
    }
  } else if (record.billingLedgerEntryId || billingDebit) {
    mismatchReasons.push('uncharged_record_has_billing_debit');
  }

  let status: ConsoleSponsoredCallReconciliationStatus;
  if (mismatchReasons.includes('uncharged_record_has_billing_debit')) {
    status = 'unexpected_billing_debit';
  } else if (
    mismatchReasons.includes('billing_debit_amount_must_be_negative') ||
    mismatchReasons.includes('settled_spend_minor_does_not_match_billing_amount')
  ) {
    status = 'amount_mismatch';
  } else if (
    mismatchReasons.includes('charged_record_missing_billing_link') ||
    mismatchReasons.includes('charged_record_missing_billing_debit')
  ) {
    status = 'missing_billing_debit';
  } else if (!record.charged) {
    status = 'not_charged';
  } else {
    status = 'matched';
  }

  return {
    record,
    billingDebit,
    status,
    mismatchReasons,
  };
}

export async function listConsoleSponsoredCallReconciliationPage(input: {
  sponsoredCalls: ConsoleSponsoredCallService;
  billing: ConsoleBillingService;
  ctx: ConsoleBillingContext;
  request?: ListConsoleSponsoredCallRecordsRequest;
}): Promise<ConsoleSponsoredCallReconciliationPage> {
  const page = await input.sponsoredCalls.listRecords(input.ctx, input.request);
  const ledgerEntryIds = Array.from(
    new Set(
      page.items
        .map((record) => String(record.billingLedgerEntryId || '').trim())
        .filter((entryId) => entryId.length > 0),
    ),
  );
  const billingDebits = await input.billing.getSponsoredExecutionDebitsByIds(input.ctx, ledgerEntryIds);
  const billingDebitById = new Map(billingDebits.map((entry) => [entry.id, entry] as const));
  const items = page.items.map((record) =>
    buildReconciliationEntry(
      record,
      record.billingLedgerEntryId ? billingDebitById.get(record.billingLedgerEntryId) || null : null,
    ),
  );

  return {
    items,
    nextCursor: page.nextCursor,
    summary: {
      matchedCount: items.filter((item) => item.status === 'matched').length,
      notChargedCount: items.filter((item) => item.status === 'not_charged').length,
      missingBillingDebitCount: items.filter((item) => item.status === 'missing_billing_debit').length,
      amountMismatchCount: items.filter((item) => item.status === 'amount_mismatch').length,
      unexpectedBillingDebitCount: items.filter((item) => item.status === 'unexpected_billing_debit').length,
      mismatchCount: items.filter((item) => item.status !== 'matched' && item.status !== 'not_charged').length,
    },
  };
}
