import type {
  ConsoleGasSponsorshipSpendCapMode,
  ConsoleGasSponsorshipSpendCapPeriod,
} from '../gasSponsorship/types';

export type ConsoleSponsorshipSpendCapMode = Exclude<
  ConsoleGasSponsorshipSpendCapMode,
  'NONE'
>;
export type ConsoleSponsorshipSpendCapPeriod = ConsoleGasSponsorshipSpendCapPeriod;
export type ConsoleSponsorshipSpendCapReservationStatus = 'RESERVED' | 'SETTLED' | 'RELEASED';

export interface ConsoleSponsorshipSpendCapReservation {
  id: string;
  orgId: string;
  environmentId: string;
  sponsorshipConfigId: string;
  accountRef: string | null;
  chainId: number;
  mode: ConsoleSponsorshipSpendCapMode;
  period: ConsoleSponsorshipSpendCapPeriod;
  capMinor: number;
  requestedMinor: number;
  settledMinor: number;
  releasedMinor: number;
  status: ConsoleSponsorshipSpendCapReservationStatus;
  sourceEventId: string;
  windowStartAt: string;
  windowEndAt: string;
  createdAt: string;
  updatedAt: string;
}

export interface ConsoleSponsorshipSpendCapWindowUsage {
  orgId: string;
  environmentId: string;
  sponsorshipConfigId: string;
  accountRef: string | null;
  chainId: number;
  mode: ConsoleSponsorshipSpendCapMode;
  period: ConsoleSponsorshipSpendCapPeriod;
  capMinor: number;
  reservedMinor: number;
  settledMinor: number;
  availableMinor: number;
  windowStartAt: string;
  windowEndAt: string;
  createdAt: string;
  updatedAt: string;
}

export interface ReserveConsoleSponsorshipSpendCapRequest {
  sourceEventId: string;
  environmentId: string;
  sponsorshipConfigId: string;
  accountRef?: string | null;
  chainId: number;
  mode: ConsoleSponsorshipSpendCapMode;
  period: ConsoleSponsorshipSpendCapPeriod;
  capMinor: number;
  estimatedSpendMinor: number;
}

export interface SettleConsoleSponsorshipSpendCapRequest {
  sourceEventId: string;
  settledSpendMinor: number;
}

export interface ReleaseConsoleSponsorshipSpendCapRequest {
  sourceEventId: string;
}

export interface GetConsoleSponsorshipSpendCapWindowUsageRequest {
  environmentId: string;
  sponsorshipConfigId: string;
  accountRef?: string | null;
  chainId: number;
  mode: ConsoleSponsorshipSpendCapMode;
  period: ConsoleSponsorshipSpendCapPeriod;
  at?: Date;
}

export interface ConsoleSponsorshipSpendCapReservationOutcome {
  reservation: ConsoleSponsorshipSpendCapReservation;
  usage: ConsoleSponsorshipSpendCapWindowUsage;
}
