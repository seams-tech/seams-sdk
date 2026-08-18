export type ConsoleBillingPrepaidReservationStatus =
  | 'RESERVED'
  | 'SETTLED'
  | 'RELEASED'
  | 'EXPIRED';

export interface ConsoleBillingPrepaidReservation {
  id: string;
  orgId: string;
  environmentId: string;
  policyId: string | null;
  sourceEventId: string;
  requestedMinor: number;
  settledMinor: number;
  releasedMinor: number;
  status: ConsoleBillingPrepaidReservationStatus;
  txOrExecutionRef: string | null;
  pricingVersion: string | null;
  expiresAt: string;
  createdAt: string;
  updatedAt: string;
}

export interface ConsoleBillingPrepaidReservationSummary {
  orgId: string;
  reservedMinor: number;
  activeReservationCount: number;
  createdAt: string;
  updatedAt: string;
}

export interface ReserveConsoleBillingPrepaidReservationRequest {
  sourceEventId: string;
  environmentId: string;
  policyId?: string | null;
  postedBalanceMinor: number;
  estimatedSpendMinor: number;
  expiresAt?: string;
}

export interface SettleConsoleBillingPrepaidReservationRequest {
  sourceEventId: string;
  settledSpendMinor: number;
  txOrExecutionRef?: string | null;
  pricingVersion?: string | null;
}

export interface ReleaseConsoleBillingPrepaidReservationRequest {
  sourceEventId: string;
}

export interface ExpireConsoleBillingPrepaidReservationsRequest {
  at?: Date;
  limit?: number;
}

export interface ConsoleBillingPrepaidReservationReserveOutcome {
  reservation: ConsoleBillingPrepaidReservation;
  summary: ConsoleBillingPrepaidReservationSummary;
  postedBalanceMinor: number;
  availableBalanceMinor: number;
}

export interface ConsoleBillingPrepaidReservationMutationOutcome {
  reservation: ConsoleBillingPrepaidReservation;
  summary: ConsoleBillingPrepaidReservationSummary;
}

export interface ExpireConsoleBillingPrepaidReservationsResult {
  expiredCount: number;
  reservationIds: string[];
}
