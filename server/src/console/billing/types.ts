export type BillingUsageMetricVersion = 'maw_v1';
export type BillingDocumentType = 'PURCHASE_RECEIPT' | 'USAGE_STATEMENT';
export type InvoiceStatus = 'OPEN' | 'PAID' | 'VOID' | 'UNCOLLECTIBLE';
export type BillingInvoiceLineItemType =
  | 'CREDIT_TOP_UP'
  | 'MAW_USAGE_DEBIT'
  | 'SPONSORED_EXECUTION_DEBIT'
  | 'MANUAL_ADJUSTMENT';
export type BillingCreditPackId = 'usd_10' | 'usd_25' | 'usd_50' | 'usd_custom';
export type BillingCreditPurchaseStatus = 'PENDING' | 'SETTLED' | 'CANCELED';
export type BillingLiveEnvironmentState = 'HEALTHY' | 'LOW_BALANCE' | 'BLOCKED';
export type BillingLedgerEntryType =
  | 'CREDIT_PURCHASE'
  | 'USAGE_DEBIT'
  | 'SPONSORED_EXECUTION_DEBIT'
  | 'MANUAL_ADJUSTMENT'
  | 'REFUND'
  | 'REVERSAL';

export interface BillingCreditPack {
  id: Exclude<BillingCreditPackId, 'usd_custom'>;
  label: string;
  description: string;
  amountMinor: number;
}

export interface BillingOverview {
  usageMetricVersion: BillingUsageMetricVersion;
  currentMonthUtc: string;
  monthlyActiveWallets: number;
  creditBalanceMinor: number;
  lowBalanceThresholdMinor: number;
  liveEnvironmentState: BillingLiveEnvironmentState;
  recentUsageDebitMinor: number;
  recentCreditPurchasedMinor: number;
  documentCount: number;
}

export interface BillingCreditPurchase {
  id: string;
  orgId: string;
  creditPackId: BillingCreditPackId;
  status: BillingCreditPurchaseStatus;
  amountMinor: number;
  currency: 'USD';
  provider: 'stripe';
  providerCheckoutSessionRef: string;
  providerCustomerRef: string | null;
  relatedInvoiceId: string | null;
  settledAt: string | null;
  createdAt: string;
  updatedAt: string;
}

export interface BillingLedgerEntry {
  id: string;
  orgId: string;
  type: BillingLedgerEntryType;
  amountMinor: number;
  currency: 'USD';
  description: string;
  monthUtc: string | null;
  relatedInvoiceId: string | null;
  relatedPurchaseId: string | null;
  sourceEventId: string | null;
  actorType: BillingInvoiceActivityActorType;
  actorUserId: string | null;
  reasonCode: string | null;
  note: string | null;
  idempotencyKey: string | null;
  createdAt: string;
}

export interface BillingSponsoredExecutionDebitEntry extends BillingLedgerEntry {
  type: 'SPONSORED_EXECUTION_DEBIT';
}

export type BillingUsageAction =
  | 'transfer'
  | 'swap'
  | 'approve'
  | 'contract_call'
  | 'wallet_created';

export interface BillingUsageEventRequest {
  walletId: string;
  action: BillingUsageAction;
  succeeded: boolean;
  isSimulation?: boolean;
  isInternalRetry?: boolean;
  occurredAt?: string;
  sourceEventId?: string;
}

export interface BillingUsageEventResult {
  accepted: boolean;
  counted: boolean;
  monthUtc: string;
  monthlyActiveWallets: number;
  debitAppliedMinor: number;
  creditBalanceMinor: number;
  statementId: string | null;
}

export interface BillingSponsoredExecutionDebitRequest {
  amountMinor: number;
  sourceEventId: string;
  walletId: string;
  occurredAt?: string;
  txOrExecutionRef?: string | null;
  pricingVersion?: string | null;
  note?: string | null;
}

export interface BillingSponsoredExecutionDebitResult {
  accepted: boolean;
  debitAppliedMinor: number;
  ledgerEntryId: string | null;
  creditBalanceMinor: number;
  monthUtc: string;
  statementId: string | null;
}

export interface BillingMonthlyActiveWallets {
  usageMetricVersion: BillingUsageMetricVersion;
  monthUtc: string;
  monthlyActiveWallets: number;
}

export interface BillingInvoice {
  id: string;
  orgId: string;
  documentType: BillingDocumentType;
  status: InvoiceStatus;
  currency: 'USD';
  amountDueMinor: number;
  amountPaidMinor: number;
  periodMonthUtc: string;
  createdAt: string;
  dueAt: string | null;
}

export interface BillingInvoiceListRequest {
  status?: InvoiceStatus;
  overdueOnly?: boolean;
  periodMonthUtc?: string;
  documentType?: BillingDocumentType;
  limit?: number;
  cursor?: string;
}

export interface BillingInvoiceListSummary {
  totalCount: number;
  openCount: number;
  overdueCount: number;
  paidCount: number;
  outstandingAmountMinor: number;
  latestPeriodMonthUtc: string | null;
  receiptCount: number;
  statementCount: number;
}

export interface BillingInvoiceListResult {
  invoices: BillingInvoice[];
  nextCursor: string | null;
  totalCount: number;
  summary: BillingInvoiceListSummary;
}

export interface BillingInvoiceLineItem {
  id: string;
  orgId: string;
  invoiceId: string;
  periodMonthUtc: string;
  itemType: BillingInvoiceLineItemType;
  description: string;
  quantity: number;
  unitAmountMinor: number;
  amountMinor: number;
  createdAt: string;
}

export interface GenerateMonthlyInvoiceRequest {
  periodMonthUtc: string;
}

export interface GenerateMonthlyInvoiceResult {
  generated: boolean;
  invoice: BillingInvoice;
  lineItems: BillingInvoiceLineItem[];
  monthlyActiveWallets: number;
  pricing: {
    mawUnitPriceMinor: number;
  };
}

export type BillingInvoiceActivityEntryType = 'DOCUMENT' | 'LEDGER';
export type BillingInvoiceActivityActorType = 'USER' | 'SYSTEM' | 'PROVIDER';
export type BillingInvoiceActivityVisibility = 'CUSTOMER' | 'INTERNAL';

export interface BillingInvoiceActivityEntry {
  id: string;
  type: BillingInvoiceActivityEntryType;
  invoiceId: string;
  fromState: string | null;
  toState: string;
  occurredAt: string;
  actorType: BillingInvoiceActivityActorType;
  actorUserId: string | null;
  reason: string | null;
  sourceEventId: string | null;
  summary: string;
  visibility: BillingInvoiceActivityVisibility;
}

export interface BillingInvoiceActivity {
  invoice: BillingInvoice;
  entries: BillingInvoiceActivityEntry[];
}

export interface BillingManualAdjustmentRequest {
  amountMinor: number;
  reasonCode: string;
  note: string;
  idempotencyKey: string;
  relatedInvoiceId?: string;
}

export interface BillingManualAdjustmentResult {
  created: boolean;
  adjustment: BillingLedgerEntry;
  creditBalanceMinor: number;
}

export interface BillingAccountActivityRequest {
  limit?: number;
  periodMonthUtc?: string;
  eventType?: BillingLedgerEntryType;
}

export interface BillingAccountActivityResult {
  entries: BillingLedgerEntry[];
}

export interface StripeCheckoutSessionRequest {
  successUrl: string;
  cancelUrl: string;
  creditPackId: BillingCreditPackId;
  customAmountMinor?: number;
}

export interface StripeCheckoutSession {
  id: string;
  url: string;
  customerRef: string;
  creditPackId: BillingCreditPackId;
  amountMinor: number;
  expiresAt: string;
}

export interface StripeCheckoutSessionReconcileRequest {
  checkoutSessionId: string;
}

export interface StripeWebhookEventRequest {
  eventId: string;
  eventType?: 'checkout.session.completed';
  orgId?: string;
  providerCustomerRef?: string;
  checkoutSessionId?: string;
  providerRef?: string;
}

export interface StripeCheckoutSessionReconcileResult {
  settled: boolean;
  settledNow: boolean;
  purchase: BillingCreditPurchase | null;
  invoice: BillingInvoice | null;
  orgId: string | null;
  paymentStatus: string | null;
  checkoutStatus: string | null;
}

export interface StripeWebhookEventResult {
  accepted: boolean;
  purchase: BillingCreditPurchase | null;
  invoice: BillingInvoice | null;
  orgId: string | null;
}
