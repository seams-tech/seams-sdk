import {
  buildConsoleAcceptHeaders,
  buildConsoleJsonHeaders,
  consoleErrorMessage,
  parseConsoleJson,
  requireConsoleBaseUrl,
} from '../../consoleHttp';

export interface DashboardConsoleWebhookEndpoint {
  id: string;
  orgId: string;
  url: string;
  subscriptions: string[];
  status: string;
  secretVersion: number;
  secretPreview: string;
  createdAt: string;
  updatedAt: string;
}

export interface DashboardConsoleWebhookDelivery {
  id: string;
  orgId: string;
  endpointId: string;
  eventId: string;
  eventType: string;
  status: string;
  attemptCount: number;
  replayCount: number;
  responseStatus: number | null;
  errorMessage: string | null;
  deliveredAt: string | null;
  lastAttemptAt: string | null;
  createdAt: string;
  updatedAt: string;
}

export interface DashboardConsoleWebhookDeadLetter {
  id: string;
  orgId: string;
  endpointId: string;
  deliveryId: string;
  eventId: string;
  eventType: string;
  failedAttempts: number;
  lastResponseStatus: number | null;
  lastErrorMessage: string | null;
  movedToDlqAt: string;
  resolvedAt: string | null;
}

interface ConsoleWebhookEndpointsResponse {
  ok?: boolean;
  code?: string;
  message?: string;
  endpoints?: unknown;
}

interface ConsoleWebhookEndpointResponse {
  ok?: boolean;
  code?: string;
  message?: string;
  endpoint?: unknown;
  removed?: unknown;
}

interface ConsoleWebhookDeliveriesResponse {
  ok?: boolean;
  code?: string;
  message?: string;
  deliveries?: unknown;
  nextCursor?: unknown;
}

interface ConsoleWebhookDeadLettersResponse {
  ok?: boolean;
  code?: string;
  message?: string;
  deadLetters?: unknown;
  nextCursor?: unknown;
}

function readStringArray(raw: unknown): string[] {
  if (!Array.isArray(raw)) return [];
  const out: string[] = [];
  const seen = new Set<string>();
  for (const entry of raw) {
    const value = String(entry || '').trim();
    if (!value) continue;
    const key = value.toLowerCase();
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(value);
  }
  return out;
}

function decodeEndpoint(raw: unknown): DashboardConsoleWebhookEndpoint | null {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return null;
  const row = raw as Record<string, unknown>;
  const id = String(row.id || '').trim();
  const orgId = String(row.orgId || '').trim();
  const url = String(row.url || '').trim();
  if (!id || !orgId || !url) return null;
  return {
    id,
    orgId,
    url,
    subscriptions: readStringArray(row.subscriptions),
    status: String(row.status || '').trim() || 'ACTIVE',
    secretVersion: Number(row.secretVersion || 0),
    secretPreview: String(row.secretPreview || '').trim(),
    createdAt: String(row.createdAt || '').trim(),
    updatedAt: String(row.updatedAt || '').trim(),
  };
}

function decodeDelivery(raw: unknown): DashboardConsoleWebhookDelivery | null {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return null;
  const row = raw as Record<string, unknown>;
  const id = String(row.id || '').trim();
  const endpointId = String(row.endpointId || '').trim();
  const orgId = String(row.orgId || '').trim();
  if (!id || !endpointId || !orgId) return null;
  return {
    id,
    orgId,
    endpointId,
    eventId: String(row.eventId || '').trim(),
    eventType: String(row.eventType || '').trim(),
    status: String(row.status || '').trim() || 'FAILED',
    attemptCount: Number(row.attemptCount || 0),
    replayCount: Number(row.replayCount || 0),
    responseStatus:
      row.responseStatus === undefined || row.responseStatus === null
        ? null
        : Number(row.responseStatus || 0),
    errorMessage:
      row.errorMessage === undefined || row.errorMessage === null
        ? null
        : String(row.errorMessage || '').trim() || null,
    deliveredAt:
      row.deliveredAt === undefined || row.deliveredAt === null
        ? null
        : String(row.deliveredAt || '').trim() || null,
    lastAttemptAt:
      row.lastAttemptAt === undefined || row.lastAttemptAt === null
        ? null
        : String(row.lastAttemptAt || '').trim() || null,
    createdAt: String(row.createdAt || '').trim(),
    updatedAt: String(row.updatedAt || '').trim(),
  };
}

function decodeDeadLetter(raw: unknown): DashboardConsoleWebhookDeadLetter | null {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return null;
  const row = raw as Record<string, unknown>;
  const id = String(row.id || '').trim();
  const endpointId = String(row.endpointId || '').trim();
  const orgId = String(row.orgId || '').trim();
  if (!id || !endpointId || !orgId) return null;
  return {
    id,
    orgId,
    endpointId,
    deliveryId: String(row.deliveryId || '').trim(),
    eventId: String(row.eventId || '').trim(),
    eventType: String(row.eventType || '').trim(),
    failedAttempts: Number(row.failedAttempts || 0),
    lastResponseStatus:
      row.lastResponseStatus === undefined || row.lastResponseStatus === null
        ? null
        : Number(row.lastResponseStatus || 0),
    lastErrorMessage:
      row.lastErrorMessage === undefined || row.lastErrorMessage === null
        ? null
        : String(row.lastErrorMessage || '').trim() || null,
    movedToDlqAt: String(row.movedToDlqAt || '').trim(),
    resolvedAt:
      row.resolvedAt === undefined || row.resolvedAt === null
        ? null
        : String(row.resolvedAt || '').trim() || null,
  };
}

export async function listDashboardWebhookEndpoints(): Promise<DashboardConsoleWebhookEndpoint[]> {
  const base = requireConsoleBaseUrl();
  const response = await fetch(`${base}/console/webhooks`, {
    method: 'GET',
    headers: buildConsoleAcceptHeaders(),
    credentials: 'include',
    cache: 'no-store',
  });
  const body = (await parseConsoleJson(response)) as ConsoleWebhookEndpointsResponse | null;
  if (!response.ok || body?.ok !== true) {
    throw new Error(consoleErrorMessage(response, body, 'Webhook endpoints request failed'));
  }
  const rows = Array.isArray(body?.endpoints) ? body.endpoints : [];
  return rows
    .map((entry) => decodeEndpoint(entry))
    .filter((entry): entry is DashboardConsoleWebhookEndpoint => entry !== null);
}

export async function createDashboardWebhookEndpoint(input: {
  url: string;
  subscriptions: string[];
  status?: 'ACTIVE' | 'DISABLED';
}): Promise<DashboardConsoleWebhookEndpoint> {
  const base = requireConsoleBaseUrl();
  const response = await fetch(`${base}/console/webhooks`, {
    method: 'POST',
    headers: buildConsoleJsonHeaders(),
    credentials: 'include',
    cache: 'no-store',
    body: JSON.stringify(input),
  });
  const body = (await parseConsoleJson(response)) as ConsoleWebhookEndpointResponse | null;
  if (!response.ok || body?.ok !== true) {
    throw new Error(consoleErrorMessage(response, body, 'Create webhook endpoint request failed'));
  }
  const endpoint = decodeEndpoint(body?.endpoint);
  if (!endpoint) throw new Error('Create webhook endpoint response missing endpoint');
  return endpoint;
}

export async function updateDashboardWebhookEndpoint(input: {
  endpointId: string;
  status?: 'ACTIVE' | 'DISABLED';
  url?: string;
  subscriptions?: string[];
}): Promise<DashboardConsoleWebhookEndpoint> {
  const endpointId = String(input.endpointId || '').trim();
  if (!endpointId) throw new Error('Endpoint id is required');
  const base = requireConsoleBaseUrl();
  const response = await fetch(`${base}/console/webhooks/${encodeURIComponent(endpointId)}`, {
    method: 'PATCH',
    headers: buildConsoleJsonHeaders(),
    credentials: 'include',
    cache: 'no-store',
    body: JSON.stringify({
      ...(input.status ? { status: input.status } : {}),
      ...(input.url ? { url: input.url } : {}),
      ...(input.subscriptions ? { subscriptions: input.subscriptions } : {}),
    }),
  });
  const body = (await parseConsoleJson(response)) as ConsoleWebhookEndpointResponse | null;
  if (!response.ok || body?.ok !== true) {
    throw new Error(consoleErrorMessage(response, body, 'Update webhook endpoint request failed'));
  }
  const endpoint = decodeEndpoint(body?.endpoint);
  if (!endpoint) throw new Error('Update webhook endpoint response missing endpoint');
  return endpoint;
}

export async function deleteDashboardWebhookEndpoint(input: {
  endpointId: string;
}): Promise<boolean> {
  const endpointId = String(input.endpointId || '').trim();
  if (!endpointId) throw new Error('Endpoint id is required');
  const base = requireConsoleBaseUrl();
  const response = await fetch(`${base}/console/webhooks/${encodeURIComponent(endpointId)}`, {
    method: 'DELETE',
    headers: buildConsoleAcceptHeaders(),
    credentials: 'include',
    cache: 'no-store',
  });
  const body = (await parseConsoleJson(response)) as ConsoleWebhookEndpointResponse | null;
  if (!response.ok || body?.ok !== true) {
    throw new Error(consoleErrorMessage(response, body, 'Delete webhook endpoint request failed'));
  }
  return body?.removed === true;
}

export async function listDashboardWebhookDeliveries(input: {
  endpointId: string;
  limit?: number;
  cursor?: string;
}): Promise<{ deliveries: DashboardConsoleWebhookDelivery[]; nextCursor?: string }> {
  const endpointId = String(input.endpointId || '').trim();
  if (!endpointId) throw new Error('Endpoint id is required');
  const params = new URLSearchParams();
  params.set('limit', String(input.limit || 20));
  if (input.cursor) params.set('cursor', input.cursor);
  const base = requireConsoleBaseUrl();
  const response = await fetch(
    `${base}/console/webhooks/${encodeURIComponent(endpointId)}/deliveries?${params.toString()}`,
    {
      method: 'GET',
      headers: buildConsoleAcceptHeaders(),
      credentials: 'include',
      cache: 'no-store',
    },
  );
  const body = (await parseConsoleJson(response)) as ConsoleWebhookDeliveriesResponse | null;
  if (!response.ok || body?.ok !== true) {
    throw new Error(consoleErrorMessage(response, body, 'Webhook deliveries request failed'));
  }
  const rows = Array.isArray(body?.deliveries) ? body.deliveries : [];
  const deliveries = rows
    .map((entry) => decodeDelivery(entry))
    .filter((entry): entry is DashboardConsoleWebhookDelivery => entry !== null);
  const nextCursor = String(body?.nextCursor || '').trim();
  return {
    deliveries,
    ...(nextCursor ? { nextCursor } : {}),
  };
}

export async function replayDashboardWebhookDelivery(input: {
  endpointId: string;
  deliveryId?: string;
}): Promise<void> {
  const endpointId = String(input.endpointId || '').trim();
  if (!endpointId) throw new Error('Endpoint id is required');
  const base = requireConsoleBaseUrl();
  const response = await fetch(`${base}/console/webhooks/${encodeURIComponent(endpointId)}/replay`, {
    method: 'POST',
    headers: buildConsoleJsonHeaders(),
    credentials: 'include',
    cache: 'no-store',
    body: JSON.stringify(input.deliveryId ? { deliveryId: input.deliveryId } : {}),
  });
  const body = await parseConsoleJson(response);
  if (!response.ok || body?.ok !== true) {
    throw new Error(consoleErrorMessage(response, body, 'Webhook replay request failed'));
  }
}

export async function listDashboardWebhookDeadLetters(input: {
  endpointId: string;
  includeResolved?: boolean;
  limit?: number;
  cursor?: string;
}): Promise<{ deadLetters: DashboardConsoleWebhookDeadLetter[]; nextCursor?: string }> {
  const endpointId = String(input.endpointId || '').trim();
  if (!endpointId) throw new Error('Endpoint id is required');
  const params = new URLSearchParams();
  params.set('limit', String(input.limit || 20));
  if (input.includeResolved === true) params.set('includeResolved', 'true');
  if (input.cursor) params.set('cursor', input.cursor);
  const base = requireConsoleBaseUrl();
  const response = await fetch(
    `${base}/console/webhooks/${encodeURIComponent(endpointId)}/dead-letters?${params.toString()}`,
    {
      method: 'GET',
      headers: buildConsoleAcceptHeaders(),
      credentials: 'include',
      cache: 'no-store',
    },
  );
  const body = (await parseConsoleJson(response)) as ConsoleWebhookDeadLettersResponse | null;
  if (!response.ok || body?.ok !== true) {
    throw new Error(consoleErrorMessage(response, body, 'Webhook dead-letters request failed'));
  }
  const rows = Array.isArray(body?.deadLetters) ? body.deadLetters : [];
  const deadLetters = rows
    .map((entry) => decodeDeadLetter(entry))
    .filter((entry): entry is DashboardConsoleWebhookDeadLetter => entry !== null);
  const nextCursor = String(body?.nextCursor || '').trim();
  return {
    deadLetters,
    ...(nextCursor ? { nextCursor } : {}),
  };
}
