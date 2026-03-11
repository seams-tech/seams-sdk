import { ConsoleSponsorshipSpendCapError } from './errors';
import {
  buildConsoleSponsorshipSpendCapWindowKey,
  buildConsoleSponsorshipSpendCapWindowKeyFromReservation,
  buildConsoleSponsorshipSpendCapWindowUsage,
  createSpendCapExceededError,
  normalizeReleaseRequest,
  normalizeReserveRequest,
  normalizeSettleRequest,
  normalizeWindowUsageRequest,
} from './shared';
import type {
  ConsoleSponsorshipSpendCapReservation,
  ConsoleSponsorshipSpendCapReservationOutcome,
  ConsoleSponsorshipSpendCapWindowUsage,
  GetConsoleSponsorshipSpendCapWindowUsageRequest,
  ReleaseConsoleSponsorshipSpendCapRequest,
  ReserveConsoleSponsorshipSpendCapRequest,
  SettleConsoleSponsorshipSpendCapRequest,
} from './types';

export interface ConsoleSponsorshipSpendCapContext {
  orgId: string;
  actorUserId: string;
  roles: string[];
}

export interface InMemoryConsoleSponsorshipSpendCapServiceOptions {
  now?: () => Date;
}

export interface ConsoleSponsorshipSpendCapService {
  getReservationBySourceEventId(
    ctx: ConsoleSponsorshipSpendCapContext,
    sourceEventId: string,
  ): Promise<ConsoleSponsorshipSpendCapReservation | null>;
  getWindowUsage(
    ctx: ConsoleSponsorshipSpendCapContext,
    request: GetConsoleSponsorshipSpendCapWindowUsageRequest,
  ): Promise<ConsoleSponsorshipSpendCapWindowUsage | null>;
  reserve(
    ctx: ConsoleSponsorshipSpendCapContext,
    request: ReserveConsoleSponsorshipSpendCapRequest,
  ): Promise<ConsoleSponsorshipSpendCapReservationOutcome>;
  settle(
    ctx: ConsoleSponsorshipSpendCapContext,
    request: SettleConsoleSponsorshipSpendCapRequest,
  ): Promise<ConsoleSponsorshipSpendCapReservationOutcome | null>;
  release(
    ctx: ConsoleSponsorshipSpendCapContext,
    request: ReleaseConsoleSponsorshipSpendCapRequest,
  ): Promise<ConsoleSponsorshipSpendCapReservationOutcome | null>;
}

type OrgStore = {
  reservationsById: Map<string, ConsoleSponsorshipSpendCapReservation>;
  reservationIdsBySourceEventId: Map<string, string>;
  windowsByKey: Map<string, ConsoleSponsorshipSpendCapWindowUsage>;
};

function toIso(date: Date): string {
  return date.toISOString();
}

function makeId(prefix: string, now: Date): string {
  const ts = now.getTime().toString(36);
  const rand = Math.random().toString(36).slice(2, 10);
  return `${prefix}_${ts}_${rand}`;
}

function cloneReservation(
  reservation: ConsoleSponsorshipSpendCapReservation,
): ConsoleSponsorshipSpendCapReservation {
  return { ...reservation };
}

function cloneUsage(usage: ConsoleSponsorshipSpendCapWindowUsage): ConsoleSponsorshipSpendCapWindowUsage {
  return { ...usage };
}

function requireOrgStore(stores: Map<string, OrgStore>, orgId: string): OrgStore {
  let store = stores.get(orgId);
  if (!store) {
    store = {
      reservationsById: new Map<string, ConsoleSponsorshipSpendCapReservation>(),
      reservationIdsBySourceEventId: new Map<string, string>(),
      windowsByKey: new Map<string, ConsoleSponsorshipSpendCapWindowUsage>(),
    };
    stores.set(orgId, store);
  }
  return store;
}

function requireUsageForReservation(
  store: OrgStore,
  reservation: ConsoleSponsorshipSpendCapReservation,
): ConsoleSponsorshipSpendCapWindowUsage {
  const key = buildConsoleSponsorshipSpendCapWindowKeyFromReservation(reservation);
  const usage = store.windowsByKey.get(key);
  if (usage) return usage;
  const windowStartMs = Date.parse(reservation.windowStartAt);
  const windowEndMs = Date.parse(reservation.windowEndAt);
  return buildConsoleSponsorshipSpendCapWindowUsage({
    orgId: reservation.orgId,
    environmentId: reservation.environmentId,
    sponsorshipConfigId: reservation.sponsorshipConfigId,
    accountRef: reservation.accountRef,
    chainId: reservation.chainId,
    mode: reservation.mode,
    period: reservation.period,
    capMinor: reservation.capMinor,
    reservedMinor: reservation.status === 'RESERVED' ? reservation.requestedMinor : 0,
    settledMinor: reservation.status === 'SETTLED' ? reservation.settledMinor : 0,
    windowStartMs,
    windowEndMs,
    windowStartAt: reservation.windowStartAt,
    windowEndAt: reservation.windowEndAt,
    createdAt: reservation.createdAt,
    updatedAt: reservation.updatedAt,
  });
}

function buildOutcome(
  store: OrgStore,
  reservation: ConsoleSponsorshipSpendCapReservation,
): ConsoleSponsorshipSpendCapReservationOutcome {
  return {
    reservation: cloneReservation(reservation),
    usage: cloneUsage(requireUsageForReservation(store, reservation)),
  };
}

export function createInMemoryConsoleSponsorshipSpendCapService(
  options: InMemoryConsoleSponsorshipSpendCapServiceOptions = {},
): ConsoleSponsorshipSpendCapService {
  const now = options.now || (() => new Date());
  const stores = new Map<string, OrgStore>();

  return {
    async getReservationBySourceEventId(ctx, sourceEventId) {
      const store = requireOrgStore(stores, ctx.orgId);
      const reservationId = store.reservationIdsBySourceEventId.get(String(sourceEventId || '').trim());
      if (!reservationId) return null;
      const reservation = store.reservationsById.get(reservationId);
      return reservation ? cloneReservation(reservation) : null;
    },

    async getWindowUsage(ctx, request) {
      const normalized = normalizeWindowUsageRequest(request);
      const key = buildConsoleSponsorshipSpendCapWindowKey(normalized);
      const store = requireOrgStore(stores, ctx.orgId);
      const usage = store.windowsByKey.get(key);
      return usage ? cloneUsage(usage) : null;
    },

    async reserve(ctx, request) {
      const createdAt = now();
      const createdAtIso = toIso(createdAt);
      const normalized = normalizeReserveRequest(request, createdAt);
      const store = requireOrgStore(stores, ctx.orgId);
      const existingReservationId = store.reservationIdsBySourceEventId.get(normalized.sourceEventId);
      if (existingReservationId) {
        const existing = store.reservationsById.get(existingReservationId);
        if (existing) return buildOutcome(store, existing);
      }

      const usageKey = buildConsoleSponsorshipSpendCapWindowKey(normalized);
      const currentUsage =
        store.windowsByKey.get(usageKey) ||
        buildConsoleSponsorshipSpendCapWindowUsage({
          orgId: ctx.orgId,
          environmentId: normalized.environmentId,
          sponsorshipConfigId: normalized.sponsorshipConfigId,
          accountRef: normalized.accountRef,
          chainId: normalized.chainId,
          mode: normalized.mode,
          period: normalized.period,
          capMinor: normalized.capMinor,
          reservedMinor: 0,
          settledMinor: 0,
          windowStartMs: normalized.windowStartMs,
          windowEndMs: normalized.windowEndMs,
          windowStartAt: normalized.windowStartAt,
          windowEndAt: normalized.windowEndAt,
          createdAt: createdAtIso,
          updatedAt: createdAtIso,
        });
      currentUsage.capMinor = normalized.capMinor;
      currentUsage.updatedAt = createdAtIso;
      if (
        currentUsage.reservedMinor + currentUsage.settledMinor + normalized.estimatedSpendMinor >
        currentUsage.capMinor
      ) {
        throw createSpendCapExceededError({
          capMinor: currentUsage.capMinor,
          reservedMinor: currentUsage.reservedMinor,
          settledMinor: currentUsage.settledMinor,
          requestedMinor: normalized.estimatedSpendMinor,
        });
      }
      currentUsage.reservedMinor += normalized.estimatedSpendMinor;
      currentUsage.availableMinor =
        currentUsage.capMinor - currentUsage.reservedMinor - currentUsage.settledMinor;
      store.windowsByKey.set(usageKey, currentUsage);

      const reservation: ConsoleSponsorshipSpendCapReservation = {
        id: makeId('sscr', createdAt),
        orgId: ctx.orgId,
        environmentId: normalized.environmentId,
        sponsorshipConfigId: normalized.sponsorshipConfigId,
        accountRef: normalized.accountRef,
        chainId: normalized.chainId,
        mode: normalized.mode,
        period: normalized.period,
        capMinor: normalized.capMinor,
        requestedMinor: normalized.estimatedSpendMinor,
        settledMinor: 0,
        releasedMinor: 0,
        status: 'RESERVED',
        sourceEventId: normalized.sourceEventId,
        windowStartAt: normalized.windowStartAt,
        windowEndAt: normalized.windowEndAt,
        createdAt: createdAtIso,
        updatedAt: createdAtIso,
      };
      store.reservationsById.set(reservation.id, reservation);
      store.reservationIdsBySourceEventId.set(reservation.sourceEventId, reservation.id);
      return buildOutcome(store, reservation);
    },

    async settle(ctx, request) {
      const updatedAt = now();
      const updatedAtIso = toIso(updatedAt);
      const normalized = normalizeSettleRequest(request);
      const store = requireOrgStore(stores, ctx.orgId);
      const reservationId = store.reservationIdsBySourceEventId.get(normalized.sourceEventId);
      if (!reservationId) return null;
      const reservation = store.reservationsById.get(reservationId);
      if (!reservation) return null;
      if (reservation.status === 'SETTLED') {
        if (reservation.settledMinor !== normalized.settledSpendMinor) {
          throw new ConsoleSponsorshipSpendCapError(
            'invalid_state',
            409,
            'Spend cap reservation is already settled with a different amount',
          );
        }
        return buildOutcome(store, reservation);
      }
      if (reservation.status === 'RELEASED') {
        throw new ConsoleSponsorshipSpendCapError(
          'invalid_state',
          409,
          'Released spend cap reservations cannot be settled',
        );
      }

      const usageKey = buildConsoleSponsorshipSpendCapWindowKeyFromReservation(reservation);
      const usage = requireUsageForReservation(store, reservation);
      const nextUsedMinor =
        usage.reservedMinor + usage.settledMinor - reservation.requestedMinor + normalized.settledSpendMinor;
      if (nextUsedMinor > usage.capMinor) {
        throw createSpendCapExceededError({
          capMinor: usage.capMinor,
          reservedMinor: usage.reservedMinor - reservation.requestedMinor,
          settledMinor: usage.settledMinor,
          requestedMinor: normalized.settledSpendMinor,
        });
      }
      usage.reservedMinor -= reservation.requestedMinor;
      usage.settledMinor += normalized.settledSpendMinor;
      usage.availableMinor = usage.capMinor - usage.reservedMinor - usage.settledMinor;
      usage.updatedAt = updatedAtIso;
      store.windowsByKey.set(usageKey, usage);

      reservation.status = 'SETTLED';
      reservation.settledMinor = normalized.settledSpendMinor;
      reservation.releasedMinor = Math.max(reservation.requestedMinor - normalized.settledSpendMinor, 0);
      reservation.updatedAt = updatedAtIso;
      store.reservationsById.set(reservation.id, reservation);
      return buildOutcome(store, reservation);
    },

    async release(ctx, request) {
      const updatedAt = now();
      const updatedAtIso = toIso(updatedAt);
      const normalized = normalizeReleaseRequest(request);
      const store = requireOrgStore(stores, ctx.orgId);
      const reservationId = store.reservationIdsBySourceEventId.get(normalized.sourceEventId);
      if (!reservationId) return null;
      const reservation = store.reservationsById.get(reservationId);
      if (!reservation) return null;
      if (reservation.status !== 'RESERVED') {
        return buildOutcome(store, reservation);
      }

      const usageKey = buildConsoleSponsorshipSpendCapWindowKeyFromReservation(reservation);
      const usage = requireUsageForReservation(store, reservation);
      if (usage.reservedMinor < reservation.requestedMinor) {
        throw new ConsoleSponsorshipSpendCapError(
          'invalid_state',
          409,
          'Spend cap window usage is inconsistent with the reservation',
        );
      }
      usage.reservedMinor -= reservation.requestedMinor;
      usage.availableMinor = usage.capMinor - usage.reservedMinor - usage.settledMinor;
      usage.updatedAt = updatedAtIso;
      store.windowsByKey.set(usageKey, usage);

      reservation.status = 'RELEASED';
      reservation.releasedMinor = reservation.requestedMinor;
      reservation.updatedAt = updatedAtIso;
      store.reservationsById.set(reservation.id, reservation);
      return buildOutcome(store, reservation);
    },
  };
}
