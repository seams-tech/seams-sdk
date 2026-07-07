import { ConsoleWebhookError } from './errors';
import type {
  ConsoleWebhooksContext,
  ConsoleWebhookDelivery,
  ConsoleWebhookDeliveryAttempt,
  ConsoleWebhookDeadLetter,
  ConsoleWebhookEndpoint,
  ConsoleWebhookPage,
  CreateConsoleWebhookEndpointRequest,
  EmitConsoleWebhookEventRequest,
  EmitConsoleWebhookEventResult,
  ListConsoleWebhookDeliveriesRequest,
  ListConsoleWebhookAttemptsRequest,
  ListConsoleWebhookDeadLettersRequest,
  ReplayConsoleWebhookDeliveryRequest,
  ReplayConsoleWebhookDeliveryResult,
  UpdateConsoleWebhookEndpointRequest,
} from './types';
import {
  appendConsoleWebhookObservabilitySignals,
  normalizeConsoleWebhookEndpointDegradedThreshold,
  type ConsoleWebhookObservabilityOptions,
  type ConsoleWebhookObservabilitySignal,
} from './observability';
import {
  coerceIsoDate,
  defaultDispatchWebhook,
  makeId,
  makeSecretPreview,
  makeSigningSecret,
  normalizeEventCategory,
  signPayload,
  toDispatchHeaders,
  truncateResponseBody,
} from './shared';
import { paginateByCursor } from './pagination';

interface StoredWebhookEndpoint extends ConsoleWebhookEndpoint {
  signingSecret: string;
}

interface StoredWebhookDelivery extends ConsoleWebhookDelivery {
  payload: Record<string, unknown>;
}

interface StoredWebhookDeliveryAttempt extends ConsoleWebhookDeliveryAttempt {
  attemptedAtMs: number;
}

interface StoredWebhookDeadLetter extends ConsoleWebhookDeadLetter {
  movedToDlqAtMs: number;
}

interface OrgWebhookStore {
  endpoints: Map<string, StoredWebhookEndpoint>;
  deliveriesByEndpoint: Map<string, StoredWebhookDelivery[]>;
  attemptsByDelivery: Map<string, StoredWebhookDeliveryAttempt[]>;
  deadLettersByDelivery: Map<string, StoredWebhookDeadLetter>;
}

export interface WebhookDispatchRequest {
  endpointId: string;
  endpointUrl: string;
  eventId: string;
  eventType: string;
  body: string;
  headers: Record<string, string>;
}

export interface WebhookDispatchResult {
  ok: boolean;
  statusCode: number;
  responseBody?: string;
  errorMessage?: string;
}

export interface WebhookDispatchAdapter {
  dispatch(input: WebhookDispatchRequest): Promise<WebhookDispatchResult> | WebhookDispatchResult;
}

export interface InMemoryConsoleWebhookServiceOptions extends ConsoleWebhookObservabilityOptions {
  now?: () => Date;
  dispatcher?: WebhookDispatchAdapter;
}

export interface ConsoleWebhookService {
  listEndpoints(ctx: ConsoleWebhooksContext): Promise<ConsoleWebhookEndpoint[]>;
  createEndpoint(
    ctx: ConsoleWebhooksContext,
    request: CreateConsoleWebhookEndpointRequest,
  ): Promise<ConsoleWebhookEndpoint>;
  updateEndpoint(
    ctx: ConsoleWebhooksContext,
    endpointId: string,
    request: UpdateConsoleWebhookEndpointRequest,
  ): Promise<ConsoleWebhookEndpoint | null>;
  deleteEndpoint(
    ctx: ConsoleWebhooksContext,
    endpointId: string,
  ): Promise<{ removed: boolean; endpoint: ConsoleWebhookEndpoint | null }>;
  listDeliveries(
    ctx: ConsoleWebhooksContext,
    endpointId: string,
    request?: ListConsoleWebhookDeliveriesRequest,
  ): Promise<ConsoleWebhookPage<ConsoleWebhookDelivery>>;
  listAttempts(
    ctx: ConsoleWebhooksContext,
    endpointId: string,
    request: ListConsoleWebhookAttemptsRequest,
  ): Promise<ConsoleWebhookPage<ConsoleWebhookDeliveryAttempt>>;
  listDeadLetters(
    ctx: ConsoleWebhooksContext,
    endpointId: string,
    request: ListConsoleWebhookDeadLettersRequest,
  ): Promise<ConsoleWebhookPage<ConsoleWebhookDeadLetter>>;
  replayDelivery(
    ctx: ConsoleWebhooksContext,
    endpointId: string,
    request: ReplayConsoleWebhookDeliveryRequest,
  ): Promise<ReplayConsoleWebhookDeliveryResult>;
  emitEvent(
    ctx: ConsoleWebhooksContext,
    request: EmitConsoleWebhookEventRequest,
  ): Promise<EmitConsoleWebhookEventResult>;
}

function cloneEndpoint(endpoint: StoredWebhookEndpoint): ConsoleWebhookEndpoint {
  return {
    id: endpoint.id,
    orgId: endpoint.orgId,
    url: endpoint.url,
    eventCategories: [...endpoint.eventCategories],
    status: endpoint.status,
    secretVersion: endpoint.secretVersion,
    secretPreview: endpoint.secretPreview,
    createdAt: endpoint.createdAt,
    updatedAt: endpoint.updatedAt,
  };
}

function cloneDelivery(delivery: StoredWebhookDelivery): ConsoleWebhookDelivery {
  return {
    id: delivery.id,
    orgId: delivery.orgId,
    endpointId: delivery.endpointId,
    eventId: delivery.eventId,
    eventType: delivery.eventType,
    status: delivery.status,
    attemptCount: delivery.attemptCount,
    replayCount: delivery.replayCount,
    responseStatus: delivery.responseStatus,
    responseBody: delivery.responseBody,
    errorMessage: delivery.errorMessage,
    deliveredAt: delivery.deliveredAt,
    lastAttemptAt: delivery.lastAttemptAt,
    createdAt: delivery.createdAt,
    updatedAt: delivery.updatedAt,
  };
}

function cloneAttempt(attempt: StoredWebhookDeliveryAttempt): ConsoleWebhookDeliveryAttempt {
  return {
    id: attempt.id,
    orgId: attempt.orgId,
    endpointId: attempt.endpointId,
    deliveryId: attempt.deliveryId,
    attemptNo: attempt.attemptNo,
    status: attempt.status,
    responseStatus: attempt.responseStatus,
    responseBody: attempt.responseBody,
    errorMessage: attempt.errorMessage,
    attemptedAt: attempt.attemptedAt,
    isReplay: attempt.isReplay,
  };
}

function cloneDeadLetter(deadLetter: StoredWebhookDeadLetter): ConsoleWebhookDeadLetter {
  return {
    id: deadLetter.id,
    orgId: deadLetter.orgId,
    endpointId: deadLetter.endpointId,
    deliveryId: deadLetter.deliveryId,
    eventId: deadLetter.eventId,
    eventType: deadLetter.eventType,
    failedAttempts: deadLetter.failedAttempts,
    lastResponseStatus: deadLetter.lastResponseStatus,
    lastErrorMessage: deadLetter.lastErrorMessage,
    movedToDlqAt: deadLetter.movedToDlqAt,
    resolvedAt: deadLetter.resolvedAt,
  };
}

function sortEndpointsByNewest(items: StoredWebhookEndpoint[]): StoredWebhookEndpoint[] {
  return [...items].sort((a, b) => b.createdAt.localeCompare(a.createdAt));
}

function sortDeliveriesByNewest(items: StoredWebhookDelivery[]): StoredWebhookDelivery[] {
  return [...items].sort((a, b) => b.createdAt.localeCompare(a.createdAt));
}

function sortAttemptsByNewest(
  items: StoredWebhookDeliveryAttempt[],
): StoredWebhookDeliveryAttempt[] {
  return [...items].sort((a, b) => {
    if (b.attemptedAtMs !== a.attemptedAtMs) return b.attemptedAtMs - a.attemptedAtMs;
    return b.attemptNo - a.attemptNo;
  });
}

function sortDeadLettersByNewest(items: StoredWebhookDeadLetter[]): StoredWebhookDeadLetter[] {
  return [...items].sort((a, b) => b.movedToDlqAtMs - a.movedToDlqAtMs);
}

export function createInMemoryConsoleWebhookService(
  opts: InMemoryConsoleWebhookServiceOptions = {},
): ConsoleWebhookService {
  const now = opts.now || (() => new Date());
  const dispatchAdapter: WebhookDispatchAdapter = opts.dispatcher || {
    dispatch: defaultDispatchWebhook,
  };
  const endpointDegradedThreshold = normalizeConsoleWebhookEndpointDegradedThreshold(
    opts.endpointDegradedThreshold,
  );
  const observabilityOptions: ConsoleWebhookObservabilityOptions = {
    observabilityIngestion: opts.observabilityIngestion,
    observabilityLogger: opts.observabilityLogger || (console as Pick<Console, 'warn'>),
    endpointDegradedThreshold,
  };

  const stores = new Map<string, OrgWebhookStore>();

  function requireOrgStore(orgId: string): OrgWebhookStore {
    let store = stores.get(orgId);
    if (!store) {
      store = {
        endpoints: new Map<string, StoredWebhookEndpoint>(),
        deliveriesByEndpoint: new Map<string, StoredWebhookDelivery[]>(),
        attemptsByDelivery: new Map<string, StoredWebhookDeliveryAttempt[]>(),
        deadLettersByDelivery: new Map<string, StoredWebhookDeadLetter>(),
      };
      stores.set(orgId, store);
    }
    return store;
  }

  function getEndpoint(
    store: OrgWebhookStore,
    endpointId: string,
  ): StoredWebhookEndpoint | undefined {
    return store.endpoints.get(endpointId);
  }

  function getEndpointOrThrow(store: OrgWebhookStore, endpointId: string): StoredWebhookEndpoint {
    const endpoint = getEndpoint(store, endpointId);
    if (endpoint) return endpoint;
    throw new ConsoleWebhookError(
      'webhook_not_found',
      404,
      `Webhook endpoint ${endpointId} was not found`,
    );
  }

  function getEndpointDeliveries(
    store: OrgWebhookStore,
    endpointId: string,
  ): StoredWebhookDelivery[] {
    const existing = store.deliveriesByEndpoint.get(endpointId);
    if (existing) return existing;
    const created: StoredWebhookDelivery[] = [];
    store.deliveriesByEndpoint.set(endpointId, created);
    return created;
  }

  function getDeliveryAttempts(
    store: OrgWebhookStore,
    deliveryId: string,
  ): StoredWebhookDeliveryAttempt[] {
    const existing = store.attemptsByDelivery.get(deliveryId);
    if (existing) return existing;
    const created: StoredWebhookDeliveryAttempt[] = [];
    store.attemptsByDelivery.set(deliveryId, created);
    return created;
  }

  function countUnresolvedDeadLettersForEndpoint(store: OrgWebhookStore, endpointId: string): number {
    let count = 0;
    for (const delivery of getEndpointDeliveries(store, endpointId)) {
      const deadLetter = store.deadLettersByDelivery.get(delivery.id);
      if (!deadLetter || deadLetter.resolvedAt) continue;
      count += 1;
    }
    return count;
  }

  function findDelivery(
    store: OrgWebhookStore,
    endpointId: string,
    deliveryId: string,
  ): StoredWebhookDelivery | undefined {
    return getEndpointDeliveries(store, endpointId).find((entry) => entry.id === deliveryId);
  }

  function shouldDeliverToEndpoint(endpoint: StoredWebhookEndpoint, eventType: string): boolean {
    if (endpoint.status !== 'ACTIVE') return false;
    const category = normalizeEventCategory(eventType);
    if (!category) return false;
    return endpoint.eventCategories.includes(category);
  }

  async function deliver(
    store: OrgWebhookStore,
    ctx: ConsoleWebhooksContext,
    endpoint: StoredWebhookEndpoint,
    delivery: StoredWebhookDelivery,
    isReplay: boolean,
  ): Promise<void> {
    const current = now();
    let result: WebhookDispatchResult;
    try {
      const timestamp = String(Math.floor(current.getTime() / 1000));
      const eventPayload = {
        id: delivery.eventId,
        type: delivery.eventType,
        createdAt: coerceIsoDate(current),
        data: delivery.payload,
      };
      const body = JSON.stringify(eventPayload);
      const signature = await signPayload(endpoint.signingSecret, `${timestamp}.${body}`);
      const headers = toDispatchHeaders({
        endpointId: endpoint.id,
        eventId: delivery.eventId,
        eventType: delivery.eventType,
        signature,
        timestamp,
      });

      result = await dispatchAdapter.dispatch({
        endpointId: endpoint.id,
        endpointUrl: endpoint.url,
        eventId: delivery.eventId,
        eventType: delivery.eventType,
        headers,
        body,
      });
    } catch (error: unknown) {
      result = {
        ok: false,
        statusCode: 0,
        errorMessage: error instanceof Error ? error.message : String(error),
      };
    }

    const attemptedAt = coerceIsoDate(current);
    const nextAttemptNo = delivery.attemptCount + 1;
    const responseStatus =
      Number.isInteger(result.statusCode) && result.statusCode > 0 ? result.statusCode : null;
    const responseBody = truncateResponseBody(result.responseBody);
    const errorMessage = result.ok ? null : result.errorMessage || `HTTP ${result.statusCode || 0}`;
    const attempt: StoredWebhookDeliveryAttempt = {
      id: makeId('whatt', current),
      orgId: delivery.orgId,
      endpointId: endpoint.id,
      deliveryId: delivery.id,
      attemptNo: nextAttemptNo,
      status: result.ok ? 'SUCCEEDED' : 'FAILED',
      responseStatus,
      responseBody,
      errorMessage,
      attemptedAt,
      attemptedAtMs: current.getTime(),
      isReplay,
    };
    getDeliveryAttempts(store, delivery.id).push(attempt);
    const signals: ConsoleWebhookObservabilitySignal[] = [];
    const unresolvedDeadLettersBeforeFailure = countUnresolvedDeadLettersForEndpoint(
      store,
      endpoint.id,
    );

    delivery.attemptCount += 1;
    delivery.replayCount += isReplay ? 1 : 0;
    delivery.responseStatus = responseStatus;
    delivery.responseBody = responseBody;
    delivery.errorMessage = errorMessage;
    delivery.lastAttemptAt = attemptedAt;
    delivery.updatedAt = attemptedAt;
    if (result.ok) {
      delivery.status = 'SUCCEEDED';
      delivery.deliveredAt = attemptedAt;
      const deadLetter = store.deadLettersByDelivery.get(delivery.id);
      if (deadLetter) {
        deadLetter.resolvedAt = attemptedAt;
      }
    } else {
      delivery.status = 'FAILED';
      const existingDeadLetter = store.deadLettersByDelivery.get(delivery.id);
      if (existingDeadLetter) {
        existingDeadLetter.failedAttempts = delivery.attemptCount;
        existingDeadLetter.lastResponseStatus = responseStatus;
        existingDeadLetter.lastErrorMessage = errorMessage;
        existingDeadLetter.movedToDlqAt = attemptedAt;
        existingDeadLetter.movedToDlqAtMs = current.getTime();
        existingDeadLetter.resolvedAt = null;
      } else {
        store.deadLettersByDelivery.set(delivery.id, {
          id: makeId('whdlq', current),
          orgId: delivery.orgId,
          endpointId: endpoint.id,
          deliveryId: delivery.id,
          eventId: delivery.eventId,
          eventType: delivery.eventType,
          failedAttempts: delivery.attemptCount,
          lastResponseStatus: responseStatus,
          lastErrorMessage: errorMessage,
          movedToDlqAt: attemptedAt,
          movedToDlqAtMs: current.getTime(),
          resolvedAt: null,
        });
      }
      const unresolvedDeadLettersAfterFailure = countUnresolvedDeadLettersForEndpoint(
        store,
        endpoint.id,
      );
      if (!existingDeadLetter || existingDeadLetter.resolvedAt) {
        signals.push({
          kind: 'DEAD_LETTER',
          orgId: delivery.orgId,
          endpointId: endpoint.id,
          deliveryId: delivery.id,
          webhookEventId: delivery.eventId,
          webhookEventType: delivery.eventType,
          failedAttempts: delivery.attemptCount,
          lastResponseStatus: responseStatus,
          lastErrorMessage: errorMessage,
          movedToDlqAt: attemptedAt,
        });
      }
      if (
        unresolvedDeadLettersBeforeFailure < endpointDegradedThreshold &&
        unresolvedDeadLettersAfterFailure >= endpointDegradedThreshold
      ) {
        signals.push({
          kind: 'ENDPOINT_DEGRADED',
          orgId: delivery.orgId,
          endpointId: endpoint.id,
          unresolvedDeadLetterCount: unresolvedDeadLettersAfterFailure,
          degradationThreshold: endpointDegradedThreshold,
          latestDeliveryId: delivery.id,
          latestWebhookEventId: delivery.eventId,
          latestWebhookEventType: delivery.eventType,
          lastResponseStatus: responseStatus,
          lastErrorMessage: errorMessage,
          degradedAt: attemptedAt,
        });
      }
    }
    await appendConsoleWebhookObservabilitySignals(observabilityOptions, ctx, signals);
  }

  return {
    async listEndpoints(ctx: ConsoleWebhooksContext): Promise<ConsoleWebhookEndpoint[]> {
      const store = requireOrgStore(ctx.orgId);
      return sortEndpointsByNewest([...store.endpoints.values()]).map(cloneEndpoint);
    },

    async createEndpoint(
      ctx: ConsoleWebhooksContext,
      request: CreateConsoleWebhookEndpointRequest,
    ): Promise<ConsoleWebhookEndpoint> {
      const store = requireOrgStore(ctx.orgId);
      const createdAt = now();
      const signingSecret = makeSigningSecret(createdAt);
      const endpoint: StoredWebhookEndpoint = {
        id: makeId('wh', createdAt),
        orgId: ctx.orgId,
        url: request.url,
        eventCategories: [...request.eventCategories],
        status: request.status || 'ACTIVE',
        secretVersion: 1,
        secretPreview: makeSecretPreview(signingSecret),
        signingSecret,
        createdAt: coerceIsoDate(createdAt),
        updatedAt: coerceIsoDate(createdAt),
      };
      store.endpoints.set(endpoint.id, endpoint);
      getEndpointDeliveries(store, endpoint.id);
      return cloneEndpoint(endpoint);
    },

    async updateEndpoint(
      ctx: ConsoleWebhooksContext,
      endpointId: string,
      request: UpdateConsoleWebhookEndpointRequest,
    ): Promise<ConsoleWebhookEndpoint | null> {
      const store = requireOrgStore(ctx.orgId);
      const endpoint = getEndpoint(store, endpointId);
      if (!endpoint) return null;

      if (request.url !== undefined) endpoint.url = request.url;
      if (request.eventCategories !== undefined) {
        endpoint.eventCategories = [...request.eventCategories];
      }
      if (request.status !== undefined) endpoint.status = request.status;
      endpoint.updatedAt = coerceIsoDate(now());

      return cloneEndpoint(endpoint);
    },

    async deleteEndpoint(
      ctx: ConsoleWebhooksContext,
      endpointId: string,
    ): Promise<{ removed: boolean; endpoint: ConsoleWebhookEndpoint | null }> {
      const store = requireOrgStore(ctx.orgId);
      const endpoint = getEndpoint(store, endpointId);
      const deliveryIds = getEndpointDeliveries(store, endpointId).map((entry) => entry.id);
      const removed = store.endpoints.delete(endpointId);
      if (removed) {
        store.deliveriesByEndpoint.delete(endpointId);
        for (const deliveryId of deliveryIds) {
          store.attemptsByDelivery.delete(deliveryId);
          store.deadLettersByDelivery.delete(deliveryId);
        }
      }
      return {
        removed,
        endpoint: endpoint ? cloneEndpoint(endpoint) : null,
      };
    },

    async listDeliveries(
      ctx: ConsoleWebhooksContext,
      endpointId: string,
      request: ListConsoleWebhookDeliveriesRequest = {},
    ): Promise<ConsoleWebhookPage<ConsoleWebhookDelivery>> {
      const store = requireOrgStore(ctx.orgId);
      getEndpointOrThrow(store, endpointId);
      const page = paginateByCursor({
        items: sortDeliveriesByNewest(getEndpointDeliveries(store, endpointId)),
        limit: request.limit,
        cursor: request.cursor,
        getSortMs: (item) => Date.parse(item.createdAt),
        getId: (item) => item.id,
      });
      return {
        items: page.items.map(cloneDelivery),
        ...(page.nextCursor ? { nextCursor: page.nextCursor } : {}),
      };
    },

    async listAttempts(
      ctx: ConsoleWebhooksContext,
      endpointId: string,
      request: ListConsoleWebhookAttemptsRequest,
    ): Promise<ConsoleWebhookPage<ConsoleWebhookDeliveryAttempt>> {
      const store = requireOrgStore(ctx.orgId);
      getEndpointOrThrow(store, endpointId);

      const deliveryId = String(request.deliveryId || '').trim();
      if (deliveryId) {
        const delivery = findDelivery(store, endpointId, deliveryId);
        if (!delivery) {
          throw new ConsoleWebhookError(
            'delivery_not_found',
            404,
            `Webhook delivery ${deliveryId} was not found`,
          );
        }
        const page = paginateByCursor({
          items: sortAttemptsByNewest(getDeliveryAttempts(store, delivery.id)),
          limit: request.limit,
          cursor: request.cursor,
          getSortMs: (item) => item.attemptedAtMs,
          getId: (item) => item.id,
        });
        return {
          items: page.items.map(cloneAttempt),
          ...(page.nextCursor ? { nextCursor: page.nextCursor } : {}),
        };
      }

      const attempts = getEndpointDeliveries(store, endpointId).flatMap((delivery) =>
        getDeliveryAttempts(store, delivery.id),
      );
      const page = paginateByCursor({
        items: sortAttemptsByNewest(attempts),
        limit: request.limit,
        cursor: request.cursor,
        getSortMs: (item) => item.attemptedAtMs,
        getId: (item) => item.id,
      });
      return {
        items: page.items.map(cloneAttempt),
        ...(page.nextCursor ? { nextCursor: page.nextCursor } : {}),
      };
    },

    async listDeadLetters(
      ctx: ConsoleWebhooksContext,
      endpointId: string,
      request: ListConsoleWebhookDeadLettersRequest,
    ): Promise<ConsoleWebhookPage<ConsoleWebhookDeadLetter>> {
      const store = requireOrgStore(ctx.orgId);
      getEndpointOrThrow(store, endpointId);

      const deliveryId = String(request.deliveryId || '').trim();
      const includeResolved = Boolean(request.includeResolved);
      let deadLetters = getEndpointDeliveries(store, endpointId)
        .map((delivery) => store.deadLettersByDelivery.get(delivery.id))
        .filter((entry): entry is StoredWebhookDeadLetter => Boolean(entry));

      if (deliveryId) {
        deadLetters = deadLetters.filter((entry) => entry.deliveryId === deliveryId);
      }
      if (!includeResolved) {
        deadLetters = deadLetters.filter((entry) => !entry.resolvedAt);
      }
      const page = paginateByCursor({
        items: sortDeadLettersByNewest(deadLetters),
        limit: request.limit,
        cursor: request.cursor,
        getSortMs: (item) => item.movedToDlqAtMs,
        getId: (item) => item.id,
      });
      return {
        items: page.items.map(cloneDeadLetter),
        ...(page.nextCursor ? { nextCursor: page.nextCursor } : {}),
      };
    },

    async replayDelivery(
      ctx: ConsoleWebhooksContext,
      endpointId: string,
      request: ReplayConsoleWebhookDeliveryRequest,
    ): Promise<ReplayConsoleWebhookDeliveryResult> {
      const store = requireOrgStore(ctx.orgId);
      const endpoint = getEndpoint(store, endpointId);
      if (!endpoint) {
        return {
          replayed: false,
          delivery: null,
          reason: 'endpoint_not_found',
        };
      }
      const deliveries = getEndpointDeliveries(store, endpointId);
      const target = request.deliveryId
        ? deliveries.find((entry) => entry.id === request.deliveryId)
        : sortDeliveriesByNewest(deliveries).find((entry) => entry.status !== 'SUCCEEDED');

      if (!target) {
        return {
          replayed: false,
          delivery: null,
          reason: request.deliveryId ? 'delivery_not_found' : 'no_replayable_delivery',
        };
      }

      await deliver(store, ctx, endpoint, target, true);
      return {
        replayed: true,
        delivery: cloneDelivery(target),
      };
    },

    async emitEvent(
      ctx: ConsoleWebhooksContext,
      request: EmitConsoleWebhookEventRequest,
    ): Promise<EmitConsoleWebhookEventResult> {
      const store = requireOrgStore(ctx.orgId);
      const eventType = String(request.eventType || '').trim();
      if (!eventType) {
        throw new ConsoleWebhookError('invalid_event_type', 400, 'eventType is required');
      }
      if (
        !request.payload ||
        typeof request.payload !== 'object' ||
        Array.isArray(request.payload)
      ) {
        throw new ConsoleWebhookError('invalid_payload', 400, 'payload must be a JSON object');
      }

      const eventId = String(request.eventId || '').trim() || makeId('wevt', now());
      const targets = [...store.endpoints.values()].filter((endpoint) =>
        shouldDeliverToEndpoint(endpoint, eventType),
      );
      let delivered = 0;
      let failed = 0;

      for (const endpoint of targets) {
        const createdAt = coerceIsoDate(now());
        const delivery: StoredWebhookDelivery = {
          id: makeId('whd', now()),
          orgId: ctx.orgId,
          endpointId: endpoint.id,
          eventId,
          eventType,
          status: 'FAILED',
          attemptCount: 0,
          replayCount: 0,
          responseStatus: null,
          responseBody: null,
          errorMessage: null,
          deliveredAt: null,
          lastAttemptAt: null,
          createdAt,
          updatedAt: createdAt,
          payload: { ...request.payload },
        };
        getEndpointDeliveries(store, endpoint.id).push(delivery);
        await deliver(store, ctx, endpoint, delivery, false);
        if (delivery.status === 'SUCCEEDED') delivered += 1;
        else failed += 1;
      }

      return {
        eventId,
        attempted: targets.length,
        delivered,
        failed,
      };
    },
  };
}
