export type BillingUsageMetricVersion = 'active_resource_v1';
export type BillingDocumentType = 'PURCHASE_RECEIPT' | 'USAGE_STATEMENT';
export type InvoiceStatus = 'OPEN' | 'PAID' | 'VOID' | 'UNCOLLECTIBLE';
export type BillingInvoiceLineItemType =
  | 'CREDIT_TOP_UP'
  | 'ACTIVE_RESOURCE_USAGE_DEBIT'
  | 'PRODUCT_EXECUTION_DEBIT'
  | 'MANUAL_ADJUSTMENT';
export type BillingCreditPackId = 'usd_10' | 'usd_25' | 'usd_50';
export type BillingLiveEnvironmentState = 'HEALTHY' | 'LOW_BALANCE' | 'BLOCKED';
export type BillingLedgerEntryType =
  | 'CREDIT_PURCHASE'
  | 'USAGE_DEBIT'
  | 'PRODUCT_EXECUTION_DEBIT'
  | 'MANUAL_ADJUSTMENT'
  | 'REFUND'
  | 'DISPUTE_OPENED'
  | 'DISPUTE_WON';
export type BillingLedgerPostingDirection = 'DEBIT' | 'CREDIT';
export type BillingLedgerAccountCode =
  | 'org_prepaid_liability'
  | 'stripe_cash_clearing'
  | 'revenue_usage'
  | 'revenue_product_execution'
  | 'manual_adjustment_clearing'
  | 'stripe_dispute_clearing';

export interface BillingCreditPack {
  id: BillingCreditPackId;
  label: string;
  description: string;
  amountMinor: number;
}

interface BillingCreditPurchaseBase {
  id: string;
  orgId: string;
  creditPackId: BillingCreditPackId;
  amountMinor: number;
  currency: 'USD';
  provider: 'stripe';
  createdAt: string;
  updatedAt: string;
}

export type BillingCreditPurchase =
  | (BillingCreditPurchaseBase & {
      status: 'PENDING';
      providerCheckoutSessionRef: string | null;
      providerCustomerRef: string | null;
      providerPaymentRef: null;
      relatedInvoiceId: null;
      settledAt: null;
    })
  | (BillingCreditPurchaseBase & {
      status: 'SETTLED';
      providerCheckoutSessionRef: string;
      providerCustomerRef: string;
      providerPaymentRef: string;
      relatedInvoiceId: string;
      settledAt: string;
    })
  | (BillingCreditPurchaseBase & {
      status: 'CANCELED';
      providerCheckoutSessionRef: string | null;
      providerCustomerRef: string | null;
      providerPaymentRef: null;
      relatedInvoiceId: null;
      settledAt: null;
    });

export type BillingCreditPurchaseStatus = BillingCreditPurchase['status'];

export interface BillingLedgerDebitPosting {
  id: string;
  ledgerEntryId: string;
  accountCode: BillingLedgerAccountCode;
  direction: 'DEBIT';
  amountMinor: number;
  createdAt: string;
}

export interface BillingLedgerCreditPosting {
  id: string;
  ledgerEntryId: string;
  accountCode: BillingLedgerAccountCode;
  direction: 'CREDIT';
  amountMinor: number;
  createdAt: string;
}

export type BillingBalancedPostings = readonly [
  BillingLedgerDebitPosting,
  BillingLedgerCreditPosting,
];

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
  postings: BillingBalancedPostings;
  createdAt: string;
}

export interface BillingProductExecutionDebitEntry extends BillingLedgerEntry {
  type: 'PRODUCT_EXECUTION_DEBIT';
}

export interface BillingOverview {
  usageMetricVersion: BillingUsageMetricVersion;
  currentMonthUtc: string;
  monthlyActiveResources: number;
  creditBalanceMinor: number;
  lowBalanceThresholdMinor: number;
  liveEnvironmentState: BillingLiveEnvironmentState;
  recentUsageDebitMinor: number;
  recentCreditPurchasedMinor: number;
  documentCount: number;
}

export interface BillingUsageEventRequest {
  resourceId: string;
  shouldCount: boolean;
  occurredAt?: string;
  sourceEventId?: string;
}

export interface BillingUsageEventResult {
  accepted: boolean;
  counted: boolean;
  monthUtc: string;
  monthlyActiveResources: number;
  debitAppliedMinor: number;
  creditBalanceMinor: number;
  statementId: string | null;
}

export interface BillingProductExecutionDebitRequest {
  amountMinor: number;
  sourceEventId: string;
  resourceId: string;
  occurredAt?: string;
  txOrExecutionRef?: string | null;
  pricingVersion?: string | null;
  note?: string | null;
}

export interface BillingProductExecutionDebitResult {
  accepted: boolean;
  debitAppliedMinor: number;
  ledgerEntryId: string | null;
  creditBalanceMinor: number;
  monthUtc: string;
  statementId: string | null;
}

export interface BillingMonthlyActiveResources {
  usageMetricVersion: BillingUsageMetricVersion;
  monthUtc: string;
  monthlyActiveResources: number;
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
  monthlyActiveResources: number;
  pricing: {
    activeResourceUnitPriceMinor: number;
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

export interface BillingRefundRequest {
  purchaseId: string;
  amountMinor: number;
  reason: string;
  idempotencyKey: string;
}

export interface BillingRefundReconcileRequest {
  refundId: string;
}

interface BillingRefundBase {
  id: string;
  orgId: string;
  purchaseId: string;
  amountMinor: number;
  currency: 'USD';
  reason: string;
  origin: 'console' | 'provider';
  requesterUserId: string;
  idempotencyKey: string;
  createdAt: string;
  updatedAt: string;
}

export type BillingRefund =
  | (BillingRefundBase & {
      status: 'requested';
      providerRefundId: null;
      failureCode: null;
      journalEntryId: null;
    })
  | (BillingRefundBase & {
      status: 'provider_pending';
      providerRefundId: string;
      failureCode: null;
      journalEntryId: null;
    })
  | (BillingRefundBase & {
      status: 'succeeded';
      providerRefundId: string;
      failureCode: null;
      journalEntryId: string;
    })
  | (BillingRefundBase & {
      status: 'failed';
      providerRefundId: string | null;
      failureCode: string;
      journalEntryId: null;
    })
  | (BillingRefundBase & {
      status: 'canceled';
      providerRefundId: string;
      failureCode: null;
      journalEntryId: null;
    });

export type BillingRefundStatus = BillingRefund['status'];

export interface BillingRefundResult {
  created: boolean;
  refund: BillingRefund;
  creditBalanceMinor: number;
}

export type BillingDisputeStatus = 'open' | 'won' | 'lost';

export type BillingDispute =
  | {
      id: string;
      orgId: string;
      purchaseId: string;
      providerDisputeId: string;
      amountMinor: number;
      status: 'open';
      openedJournalEntryId: string;
      resolutionJournalEntryId: null;
      createdAt: string;
      updatedAt: string;
    }
  | {
      id: string;
      orgId: string;
      purchaseId: string;
      providerDisputeId: string;
      amountMinor: number;
      status: 'won';
      openedJournalEntryId: string;
      resolutionJournalEntryId: string;
      createdAt: string;
      updatedAt: string;
    }
  | {
      id: string;
      orgId: string;
      purchaseId: string;
      providerDisputeId: string;
      amountMinor: number;
      status: 'lost';
      openedJournalEntryId: string;
      resolutionJournalEntryId: null;
      createdAt: string;
      updatedAt: string;
    };

export interface StripeCheckoutSessionRequest {
  creditPackId: BillingCreditPackId;
}

export interface StripeCheckoutSession {
  id: string;
  purchaseId: string;
  url: string;
  customerRef: string;
  creditPackId: BillingCreditPackId;
  amountMinor: number;
  expiresAt: string;
}

export interface StripeCheckoutSessionReconcileRequest {
  checkoutSessionId: string;
}

export type StripeProviderRefundStatus = 'pending' | 'succeeded' | 'failed' | 'canceled';

export interface StripeRefundEventItem {
  providerRefundId: string;
  refundId: string | null;
  purchaseId: string | null;
  orgId: string | null;
  providerPaymentRef: string;
  amountMinor: number;
  status: StripeProviderRefundStatus;
  reason: string;
  failureCode: string | null;
}

export type StripeWebhookEventRequest =
  | {
      eventId: string;
      eventType: 'checkout.session.completed';
      orgId: string | null;
      providerCustomerRef: string | null;
      checkoutSessionId: string;
      providerPaymentRef: string;
      providerRef: string;
      purchaseId: string;
      creditPackId: BillingCreditPackId;
      amountMinor: number;
      currency: 'USD';
      paymentStatus: 'paid';
    }
  | {
      eventId: string;
      eventType: 'checkout.session.expired';
      orgId: string | null;
      checkoutSessionId: string;
      providerRef: string;
      purchaseId: string;
    }
  | {
      eventId: string;
      eventType: 'refund.created' | 'refund.updated';
      refund: StripeRefundEventItem;
    }
  | {
      eventId: string;
      eventType: 'charge.refunded';
      orgId: string | null;
      purchaseId: string | null;
      providerPaymentRef: string;
      refunds: readonly StripeRefundEventItem[];
    }
  | {
      eventId: string;
      eventType: 'charge.dispute.created';
      orgId: string | null;
      purchaseId: string | null;
      providerPaymentRef: string;
      providerDisputeId: string;
      amountMinor: number;
    }
  | {
      eventId: string;
      eventType: 'charge.dispute.closed';
      orgId: string | null;
      purchaseId: string | null;
      providerPaymentRef: string;
      providerDisputeId: string;
      amountMinor: number;
      outcome: 'won' | 'lost';
    };

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
  refunds: BillingRefund[];
  dispute: BillingDispute | null;
  orgId: string | null;
}
