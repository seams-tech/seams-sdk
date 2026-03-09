import type { PaymentState } from './paymentStateMachine';
import type {
  ChainFinalityPolicy,
  StablecoinAssetSymbol,
  StablecoinSettlementChain,
} from './stablecoinAssets';

export type BillingUsageMetricVersion = 'maw_v1';
export type InvoiceStatus = 'OPEN' | 'PAID' | 'VOID' | 'UNCOLLECTIBLE';
export type InvoicePaymentRail = 'CARD' | 'STABLECOIN';
export type BillingInvoiceLineItemType = 'PLAN_BASE_FEE' | 'MAW_USAGE';
export type BillingSubscriptionStatus = 'ACTIVE' | 'PAST_DUE' | 'CANCELED';

export interface BillingOverview {
  planId: string;
  planName: string;
  usageMetricVersion: BillingUsageMetricVersion;
  currentMonthUtc: string;
  monthlyActiveWallets: number;
  creditBalanceMinor: number;
  upcomingChargeEstimateMinor: number;
  openInvoiceCount: number;
}

export interface BillingSubscription {
  id: string;
  orgId: string;
  provider: 'stripe';
  providerCustomerRef: string | null;
  providerSubscriptionRef: string | null;
  planId: string;
  planName: string;
  status: BillingSubscriptionStatus;
  cancelAtPeriodEnd: boolean;
  currentPeriodStart: string;
  currentPeriodEnd: string;
  cancelAt: string | null;
  canceledAt: string | null;
  createdAt: string;
  updatedAt: string;
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
}

export interface BillingMonthlyActiveWallets {
  usageMetricVersion: BillingUsageMetricVersion;
  monthUtc: string;
  monthlyActiveWallets: number;
}

export interface BillingInvoice {
  id: string;
  orgId: string;
  status: InvoiceStatus;
  currency: 'USD';
  amountDueMinor: number;
  amountPaidMinor: number;
  railLock: InvoicePaymentRail | null;
  periodMonthUtc: string;
  createdAt: string;
  dueAt: string | null;
}

export interface BillingInvoiceListRequest {
  status?: InvoiceStatus;
  overdueOnly?: boolean;
  periodMonthUtc?: string;
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
    baseFeeMinor: number;
    mawUnitPriceMinor: number;
  };
}

export interface BillingPaymentMethod {
  id: string;
  orgId: string;
  provider: 'stripe';
  type: 'card';
  providerRef: string;
  brand: string;
  last4: string;
  expMonth: number;
  expYear: number;
  isDefault: boolean;
  createdAt: string;
}

export type BillingInvoiceActivityEntryType = 'INVOICE' | 'PAYMENT';
export type BillingInvoiceActivityActorType = 'USER' | 'SYSTEM' | 'PROVIDER';

export interface BillingInvoiceActivityEntry {
  id: string;
  type: BillingInvoiceActivityEntryType;
  invoiceId: string;
  paymentId: string | null;
  rail: InvoicePaymentRail | null;
  fromState: string | null;
  toState: string;
  occurredAt: string;
  actorType: BillingInvoiceActivityActorType;
  actorUserId: string | null;
  reason: string | null;
  sourceEventId: string | null;
  summary: string;
}

export interface BillingInvoiceActivity {
  invoice: BillingInvoice;
  latestPaymentState: string | null;
  latestPaymentRail: InvoicePaymentRail | null;
  entries: BillingInvoiceActivityEntry[];
}

export interface AddCardPaymentMethodRequest {
  providerRef: string;
  brand: string;
  last4: string;
  expMonth: number;
  expYear: number;
}

export interface StripeSetupIntentRequest {
  returnUrl?: string;
}

export interface StripeSetupIntent {
  id: string;
  clientSecret: string;
  customerRef: string;
  expiresAt: string;
}

export interface StripeCheckoutSessionRequest {
  successUrl: string;
  cancelUrl: string;
  planId?: string;
}

export interface StripeCheckoutSession {
  id: string;
  url: string;
  customerRef: string;
  expiresAt: string;
}

export interface StripeCustomerPortalSessionRequest {
  returnUrl: string;
}

export interface StripeCustomerPortalSession {
  id: string;
  url: string;
  customerRef: string;
  expiresAt: string;
}

export interface StripePaymentIntentRequest {
  invoiceId: string;
  paymentMethodId?: string;
}

export interface StripeWebhookEventRequest {
  eventId: string;
  eventType?: string;
  providerRef?: string;
  providerStatus?: StripePaymentIntentReconcileStatus;
  settledAmountMinor?: number;
  orgId?: string;
  providerCustomerRef?: string;
  providerSubscriptionRef?: string;
  planId?: string;
  planName?: string;
  subscriptionStatus?: BillingSubscriptionStatus;
  cancelAtPeriodEnd?: boolean;
  currentPeriodStart?: string;
  currentPeriodEnd?: string;
  cancelAt?: string | null;
  canceledAt?: string | null;
  invoiceId?: string;
  invoiceStatus?: InvoiceStatus;
  invoiceAmountDueMinor?: number;
  invoiceAmountPaidMinor?: number;
}

export interface StripeWebhookEventResult {
  accepted: boolean;
  paymentIntent: StripePaymentIntent | null;
  subscription: BillingSubscription | null;
  invoice: BillingInvoice | null;
  orgId: string | null;
}

export type StripePaymentIntentReconcileStatus =
  | 'ACTION_REQUIRED'
  | 'PENDING'
  | 'SUCCEEDED'
  | 'FAILED'
  | 'CANCELED';

export interface StripePaymentIntentReconcileRequest {
  providerStatus: StripePaymentIntentReconcileStatus;
  settledAmountMinor?: number;
  sourceEventId?: string;
}

export interface StripePaymentIntent {
  id: string;
  providerRef: string;
  invoiceId: string;
  amountMinor: number;
  currency: 'USD';
  paymentMethodId: string | null;
  state: PaymentState;
  clientSecret: string;
  createdAt: string;
  rail: 'CARD';
}

export interface StablecoinQuoteRequest {
  invoiceId: string;
  asset: StablecoinAssetSymbol;
  chain: StablecoinSettlementChain;
}

export interface StablecoinPaymentQuote {
  id: string;
  orgId: string;
  invoiceId: string;
  asset: StablecoinAssetSymbol;
  chain: StablecoinSettlementChain;
  amountMinor: number;
  createdAt: string;
  expiresAt: string;
  state: 'OPEN' | 'EXPIRED';
}

export interface StablecoinPaymentIntentRequest {
  invoiceId: string;
  quoteId: string;
}

export interface StablecoinPaymentIntentReconcileRequest {
  observedAmountMinor: number;
  observedConfirmations: number;
  confirmationTimedOut?: boolean;
  sourceEventId?: string;
}

export interface StablecoinPaymentIntent {
  id: string;
  orgId: string;
  invoiceId: string;
  quoteId: string;
  asset: StablecoinAssetSymbol;
  chain: StablecoinSettlementChain;
  expectedAmountMinor: number;
  destinationAddress: string;
  state: PaymentState;
  rail: 'STABLECOIN';
  requiredConfirmations: number;
  confirmationTimeoutMinutes: number;
  reorgRiskWindowHours: number;
  settledAt: string | null;
  reorgRiskWindowEndsAt: string | null;
  withinReorgRiskWindow: boolean;
  createdAt: string;
  expiresAt: string;
}

export interface StablecoinAssetCatalogResponse {
  version: string;
  assets: Array<{
    asset: StablecoinAssetSymbol;
    chains: ChainFinalityPolicy[];
  }>;
}
