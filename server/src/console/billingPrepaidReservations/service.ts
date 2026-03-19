import { ConsoleBillingPrepaidReservationError } from './errors';
import {
  buildEmptySummary,
  cloneReservation,
  cloneSummary,
  createInsufficientAvailableBalanceError,
  normalizeExpireRequest,
  normalizeReleaseRequest,
  normalizeReserveRequest,
  normalizeSettleRequest,
  toIso,
} from './shared';
import type {
  ConsoleBillingPrepaidReservation,
  ConsoleBillingPrepaidReservationMutationOutcome,
  ConsoleBillingPrepaidReservationReserveOutcome,
  ConsoleBillingPrepaidReservationSummary,
  ExpireConsoleBillingPrepaidReservationsRequest,
  ExpireConsoleBillingPrepaidReservationsResult,
  ReleaseConsoleBillingPrepaidReservationRequest,
  ReserveConsoleBillingPrepaidReservationRequest,
  SettleConsoleBillingPrepaidReservationRequest,
} from './types';

export interface ConsoleBillingPrepaidReservationContext {
  orgId: string;
  actorUserId: string;
  roles: string[];
}

export interface InMemoryConsoleBillingPrepaidReservationServiceOptions {
  now?: () => Date;
  defaultReservationTtlMs?: number;
}

export interface ConsoleBillingPrepaidReservationService {
  getReservationBySourceEventId(
    ctx: ConsoleBillingPrepaidReservationContext,
    sourceEventId: string,
  ): Promise<ConsoleBillingPrepaidReservation | null>;
  getSummary(
    ctx: ConsoleBillingPrepaidReservationContext,
  ): Promise<ConsoleBillingPrepaidReservationSummary>;
  reserve(
    ctx: ConsoleBillingPrepaidReservationContext,
    request: ReserveConsoleBillingPrepaidReservationRequest,
  ): Promise<ConsoleBillingPrepaidReservationReserveOutcome>;
  settle(
    ctx: ConsoleBillingPrepaidReservationContext,
    request: SettleConsoleBillingPrepaidReservationRequest,
  ): Promise<ConsoleBillingPrepaidReservationMutationOutcome | null>;
  release(
    ctx: ConsoleBillingPrepaidReservationContext,
    request: ReleaseConsoleBillingPrepaidReservationRequest,
  ): Promise<ConsoleBillingPrepaidReservationMutationOutcome | null>;
  expireStaleReservations(
    request?: ExpireConsoleBillingPrepaidReservationsRequest,
  ): Promise<ExpireConsoleBillingPrepaidReservationsResult>;
}

type OrgStore = {
  reservationsById: Map<string, ConsoleBillingPrepaidReservation>;
  reservationIdsBySourceEventId: Map<string, string>;
  summary: ConsoleBillingPrepaidReservationSummary;
};

const DEFAULT_RESERVATION_TTL_MS = 5 * 60_000;

function makeId(prefix: string, now: Date): string {
  const ts = now.getTime().toString(36);
  const rand = Math.random().toString(36).slice(2, 10);
  return `${prefix}_${ts}_${rand}`;
}

function requireOrgStore(stores: Map<string, OrgStore>, orgId: string, now: Date): OrgStore {
  let store = stores.get(orgId);
  if (!store) {
    store = {
      reservationsById: new Map(),
      reservationIdsBySourceEventId: new Map(),
      summary: buildEmptySummary(orgId, toIso(now)),
    };
    stores.set(orgId, store);
  }
  return store;
}

function buildReserveOutcome(
  store: OrgStore,
  reservation: ConsoleBillingPrepaidReservation,
  postedBalanceMinor: number,
): ConsoleBillingPrepaidReservationReserveOutcome {
  return {
    reservation: cloneReservation(reservation),
    summary: cloneSummary(store.summary),
    postedBalanceMinor,
    availableBalanceMinor: postedBalanceMinor - store.summary.reservedMinor,
  };
}

function buildMutationOutcome(
  store: OrgStore,
  reservation: ConsoleBillingPrepaidReservation,
): ConsoleBillingPrepaidReservationMutationOutcome {
  return {
    reservation: cloneReservation(reservation),
    summary: cloneSummary(store.summary),
  };
}

function expireReservationInStore(
  store: OrgStore,
  reservation: ConsoleBillingPrepaidReservation,
  updatedAtIso: string,
): void {
  if (reservation.status !== 'RESERVED') return;
  store.summary.reservedMinor = Math.max(0, store.summary.reservedMinor - reservation.requestedMinor);
  store.summary.activeReservationCount = Math.max(0, store.summary.activeReservationCount - 1);
  store.summary.updatedAt = updatedAtIso;
  reservation.status = 'EXPIRED';
  reservation.releasedMinor = reservation.requestedMinor;
  reservation.updatedAt = updatedAtIso;
}

export function createInMemoryConsoleBillingPrepaidReservationService(
  options: InMemoryConsoleBillingPrepaidReservationServiceOptions = {},
): ConsoleBillingPrepaidReservationService {
  const now = options.now || (() => new Date());
  const defaultReservationTtlMs = Math.max(
    1,
    Math.trunc(options.defaultReservationTtlMs || DEFAULT_RESERVATION_TTL_MS),
  );
  const stores = new Map<string, OrgStore>();

  return {
    async getReservationBySourceEventId(ctx, sourceEventId) {
      const store = requireOrgStore(stores, ctx.orgId, now());
      const reservationId = store.reservationIdsBySourceEventId.get(String(sourceEventId || '').trim());
      if (!reservationId) return null;
      const reservation = store.reservationsById.get(reservationId);
      return reservation ? cloneReservation(reservation) : null;
    },

    async getSummary(ctx) {
      const store = requireOrgStore(stores, ctx.orgId, now());
      return cloneSummary(store.summary);
    },

    async reserve(ctx, request) {
      const createdAt = now();
      const createdAtIso = toIso(createdAt);
      const normalized = normalizeReserveRequest(request, createdAt, defaultReservationTtlMs);
      const store = requireOrgStore(stores, ctx.orgId, createdAt);

      const existingReservationId = store.reservationIdsBySourceEventId.get(normalized.sourceEventId);
      if (existingReservationId) {
        const existing = store.reservationsById.get(existingReservationId);
        if (existing) {
          return buildReserveOutcome(store, existing, normalized.postedBalanceMinor);
        }
      }

      for (const reservation of store.reservationsById.values()) {
        if (reservation.status !== 'RESERVED') continue;
        if (Date.parse(reservation.expiresAt) > createdAt.getTime()) continue;
        expireReservationInStore(store, reservation, createdAtIso);
      }

      if (store.summary.reservedMinor + normalized.estimatedSpendMinor > normalized.postedBalanceMinor) {
        throw createInsufficientAvailableBalanceError({
          postedBalanceMinor: normalized.postedBalanceMinor,
          reservedMinor: store.summary.reservedMinor,
          requestedMinor: normalized.estimatedSpendMinor,
        });
      }

      const reservation: ConsoleBillingPrepaidReservation = {
        id: makeId('bpr', createdAt),
        orgId: ctx.orgId,
        environmentId: normalized.environmentId,
        policyId: normalized.policyId,
        sourceEventId: normalized.sourceEventId,
        requestedMinor: normalized.estimatedSpendMinor,
        settledMinor: 0,
        releasedMinor: 0,
        status: 'RESERVED',
        txOrExecutionRef: null,
        pricingVersion: null,
        expiresAt: normalized.expiresAt,
        createdAt: createdAtIso,
        updatedAt: createdAtIso,
      };

      store.summary.reservedMinor += normalized.estimatedSpendMinor;
      store.summary.activeReservationCount += 1;
      store.summary.updatedAt = createdAtIso;
      store.reservationsById.set(reservation.id, reservation);
      store.reservationIdsBySourceEventId.set(reservation.sourceEventId, reservation.id);
      return buildReserveOutcome(store, reservation, normalized.postedBalanceMinor);
    },

    async settle(ctx, request) {
      const updatedAt = now();
      const updatedAtIso = toIso(updatedAt);
      const normalized = normalizeSettleRequest(request);
      const store = requireOrgStore(stores, ctx.orgId, updatedAt);
      const reservationId = store.reservationIdsBySourceEventId.get(normalized.sourceEventId);
      if (!reservationId) return null;
      const reservation = store.reservationsById.get(reservationId);
      if (!reservation) return null;
      if (reservation.status === 'SETTLED') {
        if (reservation.settledMinor !== normalized.settledSpendMinor) {
          throw new ConsoleBillingPrepaidReservationError(
            'invalid_state',
            409,
            'Prepaid reservation is already settled with a different amount',
          );
        }
        return buildMutationOutcome(store, reservation);
      }
      if (reservation.status === 'RELEASED' || reservation.status === 'EXPIRED') {
        throw new ConsoleBillingPrepaidReservationError(
          'invalid_state',
          409,
          'Released or expired prepaid reservations cannot be settled',
        );
      }

      store.summary.reservedMinor = Math.max(0, store.summary.reservedMinor - reservation.requestedMinor);
      store.summary.activeReservationCount = Math.max(0, store.summary.activeReservationCount - 1);
      store.summary.updatedAt = updatedAtIso;
      reservation.status = 'SETTLED';
      reservation.settledMinor = normalized.settledSpendMinor;
      reservation.releasedMinor = Math.max(reservation.requestedMinor - normalized.settledSpendMinor, 0);
      reservation.txOrExecutionRef = normalized.txOrExecutionRef;
      reservation.pricingVersion = normalized.pricingVersion;
      reservation.updatedAt = updatedAtIso;
      return buildMutationOutcome(store, reservation);
    },

    async release(ctx, request) {
      const updatedAt = now();
      const updatedAtIso = toIso(updatedAt);
      const normalized = normalizeReleaseRequest(request);
      const store = requireOrgStore(stores, ctx.orgId, updatedAt);
      const reservationId = store.reservationIdsBySourceEventId.get(normalized.sourceEventId);
      if (!reservationId) return null;
      const reservation = store.reservationsById.get(reservationId);
      if (!reservation) return null;
      if (reservation.status === 'RELEASED' || reservation.status === 'EXPIRED') {
        return buildMutationOutcome(store, reservation);
      }
      if (reservation.status === 'SETTLED') {
        throw new ConsoleBillingPrepaidReservationError(
          'invalid_state',
          409,
          'Settled prepaid reservations cannot be released',
        );
      }

      store.summary.reservedMinor = Math.max(0, store.summary.reservedMinor - reservation.requestedMinor);
      store.summary.activeReservationCount = Math.max(0, store.summary.activeReservationCount - 1);
      store.summary.updatedAt = updatedAtIso;
      reservation.status = 'RELEASED';
      reservation.releasedMinor = reservation.requestedMinor;
      reservation.updatedAt = updatedAtIso;
      return buildMutationOutcome(store, reservation);
    },

    async expireStaleReservations(request) {
      const normalized = normalizeExpireRequest(request, now());
      const expiredReservationIds: string[] = [];
      const updatedAtIso = new Date(normalized.atMs).toISOString();
      for (const store of stores.values()) {
        for (const reservation of store.reservationsById.values()) {
          if (expiredReservationIds.length >= normalized.limit) break;
          if (reservation.status !== 'RESERVED') continue;
          if (Date.parse(reservation.expiresAt) > normalized.atMs) continue;
          expireReservationInStore(store, reservation, updatedAtIso);
          expiredReservationIds.push(reservation.id);
        }
        if (expiredReservationIds.length >= normalized.limit) break;
      }
      return {
        expiredCount: expiredReservationIds.length,
        reservationIds: expiredReservationIds,
      };
    },
  };
}
