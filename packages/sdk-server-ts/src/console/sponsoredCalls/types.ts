import type { BillingSponsoredExecutionDebitEntry } from '../billing/types';

export type ConsoleSponsoredCallApiKeyKind = 'secret_key' | 'publishable_key';
export type ConsoleSponsoredCallChainFamily = 'evm' | 'near';
export type ConsoleSponsoredCallIntentKind = 'evm_call' | 'near_delegate';
export type ConsoleSponsoredCallFeeUnit = 'wei' | 'yocto_near';
export type ConsoleSponsoredCallExecutorKind = 'evm_eoa' | 'near_delegate';

export type ConsoleSponsoredCallReceiptStatus =
  | 'success'
  | 'reverted'
  | 'broadcast_failed'
  | 'rpc_rejected';

export interface ConsoleSponsoredCallRecord {
  id: string;
  orgId: string;
  environmentId: string;
  apiKeyId: string;
  apiKeyKind: ConsoleSponsoredCallApiKeyKind;
  route: string;
  policyId: string;
  policyNameAtEvent: string | null;
  templateId: string | null;
  chainFamily: ConsoleSponsoredCallChainFamily;
  intentKind: ConsoleSponsoredCallIntentKind;
  executorKind: ConsoleSponsoredCallExecutorKind;
  accountRef: string;
  targetRef: string;
  sponsorRef: string;
  txOrExecutionRef: string | null;
  receiptStatus: ConsoleSponsoredCallReceiptStatus;
  feeUnit: ConsoleSponsoredCallFeeUnit;
  feeAmount: string;
  detailsJson: string;
  estimatedSpendMinor: number | null;
  settledSpendMinor: number | null;
  pricingVersion: string | null;
  pricingSource: string | null;
  billingLedgerEntryId: string | null;
  prepaidReservationId: string | null;
  charged: boolean;
  chargedReason: string | null;
  settledAt: string | null;
  errorCode: string | null;
  errorMessage: string | null;
  idempotencyKey: string;
  createdAt: string;
  updatedAt: string;
}

export interface ListConsoleSponsoredCallRecordsRequest {
  environmentId?: string;
  policyId?: string;
  chainFamily?: ConsoleSponsoredCallChainFamily;
  receiptStatus?: ConsoleSponsoredCallReceiptStatus;
  charged?: boolean;
  limit?: number;
  cursor?: string;
  lookbackDays?: number;
}

export interface ConsoleSponsoredCallRecordPage {
  items: ConsoleSponsoredCallRecord[];
  nextCursor: string | null;
}

export type ConsoleSponsoredCallReconciliationStatus =
  | 'matched'
  | 'not_charged'
  | 'missing_billing_debit'
  | 'amount_mismatch'
  | 'unexpected_billing_debit';

export interface ConsoleSponsoredCallReconciliationEntry {
  record: ConsoleSponsoredCallRecord;
  billingDebit: BillingSponsoredExecutionDebitEntry | null;
  status: ConsoleSponsoredCallReconciliationStatus;
  mismatchReasons: string[];
}

export interface ConsoleSponsoredCallReconciliationSummary {
  matchedCount: number;
  notChargedCount: number;
  missingBillingDebitCount: number;
  amountMismatchCount: number;
  unexpectedBillingDebitCount: number;
  mismatchCount: number;
}

export interface ConsoleSponsoredCallReconciliationPage {
  items: ConsoleSponsoredCallReconciliationEntry[];
  nextCursor: string | null;
  summary: ConsoleSponsoredCallReconciliationSummary;
}

export interface ConsoleSponsoredCallOverviewWindowSummary {
  lookbackDays: number;
  chargedExecutionCount: number;
  chargedSettledSpendMinor: number;
}

export interface ConsoleSponsoredCallOverviewSummary {
  trailing30Days: ConsoleSponsoredCallOverviewWindowSummary;
  trailing90Days: ConsoleSponsoredCallOverviewWindowSummary;
}

export interface CreateConsoleSponsoredCallRecordRequest {
  id?: string;
  environmentId: string;
  apiKeyId: string;
  apiKeyKind: ConsoleSponsoredCallApiKeyKind;
  route: string;
  policyId: string;
  policyNameAtEvent?: string | null;
  templateId?: string | null;
  chainFamily: ConsoleSponsoredCallChainFamily;
  intentKind: ConsoleSponsoredCallIntentKind;
  executorKind: ConsoleSponsoredCallExecutorKind;
  accountRef: string;
  targetRef: string;
  sponsorRef: string;
  txOrExecutionRef?: string | null;
  receiptStatus: ConsoleSponsoredCallReceiptStatus;
  feeUnit: ConsoleSponsoredCallFeeUnit;
  feeAmount: string;
  detailsJson: string;
  estimatedSpendMinor?: number | null;
  settledSpendMinor?: number | null;
  pricingVersion?: string | null;
  pricingSource?: string | null;
  billingLedgerEntryId?: string | null;
  prepaidReservationId?: string | null;
  charged?: boolean;
  chargedReason?: string | null;
  settledAt?: string | null;
  errorCode?: string | null;
  errorMessage?: string | null;
  idempotencyKey: string;
}
