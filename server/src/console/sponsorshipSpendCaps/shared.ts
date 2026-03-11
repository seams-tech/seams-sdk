import { ConsoleSponsorshipSpendCapError } from './errors';
import type {
  ConsoleSponsorshipSpendCapMode,
  ConsoleSponsorshipSpendCapPeriod,
  ConsoleSponsorshipSpendCapReservation,
  ConsoleSponsorshipSpendCapWindowUsage,
  GetConsoleSponsorshipSpendCapWindowUsageRequest,
  ReleaseConsoleSponsorshipSpendCapRequest,
  ReserveConsoleSponsorshipSpendCapRequest,
  SettleConsoleSponsorshipSpendCapRequest,
} from './types';

export type NormalizedConsoleSponsorshipSpendCapBucket = {
  environmentId: string;
  sponsorshipConfigId: string;
  accountRef: string | null;
  storedAccountRef: string;
  chainId: number;
  mode: ConsoleSponsorshipSpendCapMode;
  period: ConsoleSponsorshipSpendCapPeriod;
  windowStartMs: number;
  windowEndMs: number;
  windowStartAt: string;
  windowEndAt: string;
};

type ReserveNormalized = NormalizedConsoleSponsorshipSpendCapBucket & {
  sourceEventId: string;
  capMinor: number;
  estimatedSpendMinor: number;
};

type SettleNormalized = {
  sourceEventId: string;
  settledSpendMinor: number;
};

type ReleaseNormalized = {
  sourceEventId: string;
};

function normalizeRequiredString(value: unknown, label: string): string {
  const normalized = String(value || '').trim();
  if (!normalized) {
    throw new ConsoleSponsorshipSpendCapError('invalid_request', 400, `${label} is required`);
  }
  return normalized;
}

function normalizeOptionalString(value: unknown): string | null {
  const normalized = String(value || '').trim();
  return normalized || null;
}

function parseNonNegativeInteger(value: unknown, label: string): number {
  const parsed = typeof value === 'number' ? value : Number(value);
  if (!Number.isInteger(parsed) || parsed < 0) {
    throw new ConsoleSponsorshipSpendCapError(
      'invalid_request',
      400,
      `${label} must be an integer >= 0`,
    );
  }
  return parsed;
}

function parsePositiveInteger(value: unknown, label: string): number {
  const parsed = typeof value === 'number' ? value : Number(value);
  if (!Number.isInteger(parsed) || parsed <= 0) {
    throw new ConsoleSponsorshipSpendCapError(
      'invalid_request',
      400,
      `${label} must be an integer > 0`,
    );
  }
  return parsed;
}

export function toStoredAccountRef(
  mode: ConsoleSponsorshipSpendCapMode,
  accountRef: string | null,
): string {
  return mode === 'CHAIN_TOTAL' ? '' : accountRef || '';
}

export function fromStoredAccountRef(
  mode: ConsoleSponsorshipSpendCapMode,
  accountRef: unknown,
): string | null {
  const normalized = normalizeOptionalString(accountRef);
  return mode === 'CHAIN_TOTAL' ? null : normalized;
}

function normalizeAccountRef(
  mode: ConsoleSponsorshipSpendCapMode,
  accountRef: unknown,
  label: string,
): string | null {
  if (mode === 'CHAIN_TOTAL') return null;
  return normalizeRequiredString(accountRef, label);
}

export function resolveConsoleSponsorshipSpendCapWindow(
  period: ConsoleSponsorshipSpendCapPeriod,
  at: Date,
): {
  startMs: number;
  endMs: number;
  startAt: string;
  endAt: string;
} {
  if (!(at instanceof Date) || Number.isNaN(at.getTime())) {
    throw new ConsoleSponsorshipSpendCapError('invalid_request', 400, 'Invalid window date');
  }
  const year = at.getUTCFullYear();
  const month = at.getUTCMonth();
  const day = at.getUTCDate();
  const weekday = at.getUTCDay();
  let startMs = 0;
  let endMs = 0;
  if (period === 'MONTHLY') {
    startMs = Date.UTC(year, month, 1, 0, 0, 0, 0);
    endMs = Date.UTC(year, month + 1, 1, 0, 0, 0, 0);
  } else {
    const daysSinceMonday = (weekday + 6) % 7;
    startMs = Date.UTC(year, month, day - daysSinceMonday, 0, 0, 0, 0);
    endMs = startMs + 7 * 24 * 60 * 60 * 1000;
  }
  return {
    startMs,
    endMs,
    startAt: new Date(startMs).toISOString(),
    endAt: new Date(endMs).toISOString(),
  };
}

export function normalizeReserveRequest(
  input: ReserveConsoleSponsorshipSpendCapRequest,
  now: Date,
): ReserveNormalized {
  const sourceEventId = normalizeRequiredString(input.sourceEventId, 'sourceEventId');
  const environmentId = normalizeRequiredString(input.environmentId, 'environmentId');
  const sponsorshipConfigId = normalizeRequiredString(
    input.sponsorshipConfigId,
    'sponsorshipConfigId',
  );
  const mode = input.mode;
  const period = input.period;
  if (mode !== 'CHAIN_TOTAL' && mode !== 'WALLET_CHAIN_TOTAL') {
    throw new ConsoleSponsorshipSpendCapError('invalid_request', 400, 'Invalid spend cap mode');
  }
  if (period !== 'WEEKLY' && period !== 'MONTHLY') {
    throw new ConsoleSponsorshipSpendCapError('invalid_request', 400, 'Invalid spend cap period');
  }
  const accountRef = normalizeAccountRef(mode, input.accountRef, 'accountRef');
  const chainId = parsePositiveInteger(input.chainId, 'chainId');
  const capMinor = parseNonNegativeInteger(input.capMinor, 'capMinor');
  const estimatedSpendMinor = parseNonNegativeInteger(
    input.estimatedSpendMinor,
    'estimatedSpendMinor',
  );
  const window = resolveConsoleSponsorshipSpendCapWindow(period, now);
  return {
    sourceEventId,
    environmentId,
    sponsorshipConfigId,
    accountRef,
    storedAccountRef: toStoredAccountRef(mode, accountRef),
    chainId,
    mode,
    period,
    capMinor,
    estimatedSpendMinor,
    windowStartMs: window.startMs,
    windowEndMs: window.endMs,
    windowStartAt: window.startAt,
    windowEndAt: window.endAt,
  };
}

export function normalizeSettleRequest(
  input: SettleConsoleSponsorshipSpendCapRequest,
): SettleNormalized {
  return {
    sourceEventId: normalizeRequiredString(input.sourceEventId, 'sourceEventId'),
    settledSpendMinor: parseNonNegativeInteger(input.settledSpendMinor, 'settledSpendMinor'),
  };
}

export function normalizeReleaseRequest(
  input: ReleaseConsoleSponsorshipSpendCapRequest,
): ReleaseNormalized {
  return {
    sourceEventId: normalizeRequiredString(input.sourceEventId, 'sourceEventId'),
  };
}

export function normalizeWindowUsageRequest(
  input: GetConsoleSponsorshipSpendCapWindowUsageRequest,
): NormalizedConsoleSponsorshipSpendCapBucket {
  const environmentId = normalizeRequiredString(input.environmentId, 'environmentId');
  const sponsorshipConfigId = normalizeRequiredString(
    input.sponsorshipConfigId,
    'sponsorshipConfigId',
  );
  const mode = input.mode;
  const period = input.period;
  if (mode !== 'CHAIN_TOTAL' && mode !== 'WALLET_CHAIN_TOTAL') {
    throw new ConsoleSponsorshipSpendCapError('invalid_request', 400, 'Invalid spend cap mode');
  }
  if (period !== 'WEEKLY' && period !== 'MONTHLY') {
    throw new ConsoleSponsorshipSpendCapError('invalid_request', 400, 'Invalid spend cap period');
  }
  const accountRef = normalizeAccountRef(mode, input.accountRef, 'accountRef');
  const chainId = parsePositiveInteger(input.chainId, 'chainId');
  const window = resolveConsoleSponsorshipSpendCapWindow(period, input.at || new Date());
  return {
    environmentId,
    sponsorshipConfigId,
    accountRef,
    storedAccountRef: toStoredAccountRef(mode, accountRef),
    chainId,
    mode,
    period,
    windowStartMs: window.startMs,
    windowEndMs: window.endMs,
    windowStartAt: window.startAt,
    windowEndAt: window.endAt,
  };
}

export function buildConsoleSponsorshipSpendCapWindowKey(
  bucket: Pick<
    NormalizedConsoleSponsorshipSpendCapBucket,
    | 'environmentId'
    | 'sponsorshipConfigId'
    | 'storedAccountRef'
    | 'chainId'
    | 'mode'
    | 'period'
    | 'windowStartMs'
  >,
): string {
  return [
    bucket.environmentId,
    bucket.sponsorshipConfigId,
    bucket.storedAccountRef,
    bucket.chainId,
    bucket.mode,
    bucket.period,
    bucket.windowStartMs,
  ].join(':');
}

export function buildConsoleSponsorshipSpendCapWindowKeyFromReservation(
  reservation: Pick<
    ConsoleSponsorshipSpendCapReservation,
    | 'environmentId'
    | 'sponsorshipConfigId'
    | 'accountRef'
    | 'chainId'
    | 'mode'
    | 'period'
    | 'windowStartAt'
  >,
): string {
  return buildConsoleSponsorshipSpendCapWindowKey({
    environmentId: reservation.environmentId,
    sponsorshipConfigId: reservation.sponsorshipConfigId,
    storedAccountRef: toStoredAccountRef(reservation.mode, reservation.accountRef),
    chainId: reservation.chainId,
    mode: reservation.mode,
    period: reservation.period,
    windowStartMs: Date.parse(reservation.windowStartAt),
  });
}

export function buildConsoleSponsorshipSpendCapWindowUsage(
  input: {
    orgId: string;
    createdAt: string;
    updatedAt: string;
    capMinor: number;
    reservedMinor: number;
    settledMinor: number;
  } & Omit<NormalizedConsoleSponsorshipSpendCapBucket, 'storedAccountRef'>,
): ConsoleSponsorshipSpendCapWindowUsage {
  return {
    orgId: input.orgId,
    environmentId: input.environmentId,
    sponsorshipConfigId: input.sponsorshipConfigId,
    accountRef: input.accountRef,
    chainId: input.chainId,
    mode: input.mode,
    period: input.period,
    capMinor: input.capMinor,
    reservedMinor: input.reservedMinor,
    settledMinor: input.settledMinor,
    availableMinor: input.capMinor - input.reservedMinor - input.settledMinor,
    windowStartAt: input.windowStartAt,
    windowEndAt: input.windowEndAt,
    createdAt: input.createdAt,
    updatedAt: input.updatedAt,
  };
}

export function createSpendCapExceededError(input: {
  capMinor: number;
  reservedMinor: number;
  settledMinor: number;
  requestedMinor: number;
}): ConsoleSponsorshipSpendCapError {
  return new ConsoleSponsorshipSpendCapError(
    'spend_cap_exceeded',
    409,
    'Spend cap exceeded for the requested bucket',
    {
      capMinor: input.capMinor,
      reservedMinor: input.reservedMinor,
      settledMinor: input.settledMinor,
      requestedMinor: input.requestedMinor,
      availableMinor: input.capMinor - input.reservedMinor - input.settledMinor,
    },
  );
}
