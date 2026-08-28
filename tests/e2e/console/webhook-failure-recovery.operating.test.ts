import { createHmac, timingSafeEqual } from 'node:crypto';
import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import { expect, test } from './harness';

type JsonObject = Record<string, unknown>;

type WebhookObservation = {
  readonly endpointId: string;
  readonly eventId: string;
  readonly eventType: string;
  readonly timestamp: string;
  readonly body: string;
  readonly payload: JsonObject;
  readonly signatureValid: boolean;
  readonly responseStatus: number;
};

type ReceiverState = {
  readonly secret: { value: string };
  readonly observations: WebhookObservation[];
  readonly waiters: Map<number, Array<(observation: WebhookObservation) => void>>;
  responseStatus: number;
};

type WebhookReceiver = {
  readonly url: string;
  readonly observations: readonly WebhookObservation[];
  setSecret(secret: string): void;
  waitForRequest(index: number): Promise<WebhookObservation>;
  close(): Promise<void>;
};

function isRecord(value: unknown): value is JsonObject {
  return Boolean(value) && typeof value === 'object' && !Array.isArray(value);
}

function requireRecord(value: unknown, label: string): JsonObject {
  if (!isRecord(value)) throw new Error(`${label} must be an object`);
  return value;
}

function requireString(value: unknown, label: string): string {
  const result = String(value ?? '').trim();
  if (!result) throw new Error(`${label} must be a non-empty string`);
  return result;
}

async function readSuccessJson(
  response: { ok(): boolean; status(): number; text(): Promise<string> },
  label: string,
): Promise<JsonObject> {
  const raw = await response.text();
  let body: unknown = null;
  try {
    body = JSON.parse(raw) as unknown;
  } catch {
    body = null;
  }
  if (!response.ok()) throw new Error(`${label} failed with HTTP ${response.status()}: ${raw}`);
  const result = requireRecord(body, label);
  if (result.ok !== true) throw new Error(`${label} returned an unsuccessful response`);
  return result;
}

function readHeader(request: IncomingMessage, name: string): string {
  const value = request.headers[name.toLowerCase()];
  return Array.isArray(value) ? String(value[0] || '') : String(value || '');
}

async function readRequestBody(request: IncomingMessage): Promise<string> {
  const chunks: Buffer[] = [];
  for await (const chunk of request) {
    chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(String(chunk)));
  }
  return Buffer.concat(chunks).toString('utf8');
}

function verifySignature(secret: string, timestamp: string, body: string, header: string): boolean {
  const received = header.trim().replace(/^v1=/, '');
  const expected = createHmac('sha256', secret)
    .update(`${timestamp}.${body}`, 'utf8')
    .digest('hex');
  const receivedBytes = Buffer.from(received, 'utf8');
  const expectedBytes = Buffer.from(expected, 'utf8');
  return (
    receivedBytes.length === expectedBytes.length && timingSafeEqual(receivedBytes, expectedBytes)
  );
}

function resolveReceiverWaiters(state: ReceiverState, observation: WebhookObservation): void {
  const waiters = state.waiters.get(state.observations.length - 1) || [];
  state.waiters.delete(state.observations.length - 1);
  for (const resolve of waiters) resolve(observation);
}

function handleReceiverRequest(
  state: ReceiverState,
  request: IncomingMessage,
  response: ServerResponse,
): void {
  void readRequestBody(request)
    .then((body) => {
      let payload: JsonObject = {};
      try {
        payload = requireRecord(JSON.parse(body) as unknown, 'Webhook body');
      } catch {
        payload = {};
      }
      const timestamp = readHeader(request, 'x-console-webhook-timestamp');
      const responseStatus = state.responseStatus;
      const observation: WebhookObservation = {
        endpointId: readHeader(request, 'x-console-webhook-id'),
        eventId: readHeader(request, 'x-console-webhook-event-id'),
        eventType: readHeader(request, 'x-console-webhook-event-type'),
        timestamp,
        body,
        payload,
        signatureValid: verifySignature(
          state.secret.value,
          timestamp,
          body,
          readHeader(request, 'x-console-webhook-signature'),
        ),
        responseStatus,
      };
      state.observations.push(observation);
      resolveReceiverWaiters(state, observation);
      response.statusCode = responseStatus;
      state.responseStatus = 200;
      response.setHeader('content-type', 'text/plain');
      response.end(responseStatus === 200 ? 'accepted' : 'failed');
    })
    .catch(() => {
      response.statusCode = 500;
      response.end('receiver error');
    });
}

async function createWebhookReceiver(): Promise<WebhookReceiver> {
  const state: ReceiverState = {
    secret: { value: '' },
    observations: [],
    waiters: new Map(),
    responseStatus: 500,
  };
  const server: Server = createServer(handleReceiverRequest.bind(null, state));
  await new Promise<void>((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => resolve());
  });
  const address = server.address();
  if (!address || typeof address === 'string') {
    await closeServer(server);
    throw new Error('Webhook receiver did not expose an ephemeral port');
  }
  return {
    url: `http://127.0.0.1:${address.port}/webhooks/seams`,
    get observations() {
      return state.observations;
    },
    setSecret(secret: string): void {
      state.secret.value = secret;
    },
    waitForRequest(index: number): Promise<WebhookObservation> {
      const existing = state.observations[index];
      if (existing) return Promise.resolve(existing);
      return new Promise((resolve) => {
        const waiters = state.waiters.get(index) || [];
        waiters.push(resolve);
        state.waiters.set(index, waiters);
      });
    },
    close: async () => await closeServer(server),
  };
}

async function closeServer(server: Server): Promise<void> {
  if (!server.listening) return;
  server.closeAllConnections();
  await new Promise<void>((resolve, reject) => {
    server.close((error) => (error ? reject(error) : resolve()));
  });
}

function findByField(rows: unknown[], field: string, value: string, label: string): JsonObject {
  const row = rows.find((entry) => isRecord(entry) && String(entry[field] || '').trim() === value);
  return requireRecord(row, label);
}

test('webhook delivery verifies HMAC, records a dead letter, and recovers on replay', async ({
  console,
}) => {
  const receiver = await createWebhookReceiver();
  try {
    const { page, api, tenant } = console;
    await console.provisionCompletedTenant();

    await page.goto('/dashboard/webhooks');
    await expect(page.getByLabel('Webhooks page')).toBeVisible();
    await page.getByRole('button', { name: 'Add endpoint', exact: true }).click();
    const createModal = page.getByRole('dialog', { name: 'Add endpoint', exact: true });
    await createModal.getByLabel('Endpoint URL').fill(receiver.url);
    await createModal
      .getByRole('group', { name: 'Select events to listen to' })
      .getByLabel('Policy changes')
      .check();
    await createModal.getByRole('button', { name: 'Add endpoint', exact: true }).click();

    const revealModal = page.getByRole('dialog', { name: 'Endpoint added', exact: true });
    const signingSecret = requireString(
      await revealModal.getByText(/^whsec_/).textContent(),
      'Webhook signing secret',
    );
    expect(signingSecret).toMatch(/^whsec_/);
    receiver.setSecret(signingSecret);
    await revealModal.getByRole('button', { name: /saved it/i }).click();

    const endpointsResponse = await api.get('/console/webhooks');
    const endpointsBody = await readSuccessJson(endpointsResponse, 'Webhook endpoint list');
    const endpoints = Array.isArray(endpointsBody.endpoints) ? endpointsBody.endpoints : [];
    const endpoint = findByField(endpoints, 'url', receiver.url, 'Created webhook endpoint');
    const endpointId = requireString(endpoint.id, 'Webhook endpoint id');
    expect(String(endpoint.status || '').toUpperCase()).toBe('ACTIVE');
    expect(endpoint.eventCategories).toEqual(expect.arrayContaining(['policy']));

    const policyResponse = await api.post('/console/policies', {
      data: {
        name: `Webhook trigger ${tenant.orgId}`,
        rules: { blockedActions: ['delete_key'] },
        assignment: { scopeType: 'ENVIRONMENT', scopeId: tenant.environmentId },
      },
    });
    const policyBody = await readSuccessJson(policyResponse, 'Webhook trigger policy');
    const policy = requireRecord(policyBody.policy, 'Webhook trigger policy');
    const policyId = requireString(policy.id, 'Webhook trigger policy id');

    const approvalResponse = await api.post('/console/approvals', {
      data: {
        operationType: 'POLICY_PUBLISH',
        reason: 'Webhook operating path trigger',
        projectId: tenant.projectId,
        environmentId: tenant.environmentId,
        resourceType: 'policy',
        resourceId: policyId,
      },
    });
    await readSuccessJson(approvalResponse, 'Webhook trigger approval');

    const failedObservation = await receiver.waitForRequest(0);
    expect(failedObservation.endpointId).toBe(endpointId);
    expect(failedObservation.eventId).toBeTruthy();
    expect(failedObservation.eventType).toMatch(/^policy\./);
    expect(Number(failedObservation.timestamp)).toBeGreaterThan(0);
    expect(failedObservation.signatureValid).toBe(true);
    expect(requireString(failedObservation.payload.id, 'Webhook payload id')).toBe(
      failedObservation.eventId,
    );
    expect(requireString(failedObservation.payload.type, 'Webhook payload type')).toBe(
      failedObservation.eventType,
    );
    expect(isRecord(failedObservation.payload.data)).toBe(true);
    expect(failedObservation.responseStatus).toBe(500);

    const deliveriesResponse = await api.get(
      `/console/webhooks/${encodeURIComponent(endpointId)}/deliveries?limit=20`,
    );
    const deliveriesBody = await readSuccessJson(deliveriesResponse, 'Webhook delivery list');
    const deliveries = Array.isArray(deliveriesBody.deliveries) ? deliveriesBody.deliveries : [];
    const failedDelivery = findByField(
      deliveries,
      'eventId',
      failedObservation.eventId,
      'Failed webhook delivery',
    );
    const deliveryId = requireString(failedDelivery.id, 'Webhook delivery id');
    expect(String(failedDelivery.status || '').toUpperCase()).toBe('FAILED');
    expect(Number(failedDelivery.attemptCount)).toBe(1);
    expect(Number(failedDelivery.responseStatus)).toBe(500);

    const deadLettersResponse = await api.get(
      `/console/webhooks/${encodeURIComponent(endpointId)}/dead-letters?limit=20`,
    );
    const deadLettersBody = await readSuccessJson(deadLettersResponse, 'Webhook dead-letter list');
    const deadLetters = Array.isArray(deadLettersBody.deadLetters)
      ? deadLettersBody.deadLetters
      : [];
    const deadLetter = findByField(deadLetters, 'deliveryId', deliveryId, 'Webhook dead letter');
    expect(Number(deadLetter.failedAttempts)).toBe(1);
    expect(Number(deadLetter.lastResponseStatus)).toBe(500);
    expect(deadLetter.resolvedAt ?? null).toBeNull();

    await page.reload();
    const deliveriesTable = page.getByRole('table', { name: 'Webhook deliveries table' });
    const failedRow = deliveriesTable
      .getByRole('row')
      .filter({ hasText: failedObservation.eventType });
    await expect(failedRow).toBeVisible();
    await expect(failedRow).toContainText('Failed');
    await expect(failedRow).toContainText('500');
    await expect(failedRow).toContainText('1');

    const replayRequest = receiver.waitForRequest(1);
    await failedRow.getByRole('button', { name: 'Replay', exact: true }).click();
    const replayObservation = await replayRequest;
    expect(replayObservation.endpointId).toBe(endpointId);
    expect(replayObservation.eventId).toBe(failedObservation.eventId);
    expect(replayObservation.eventType).toBe(failedObservation.eventType);
    expect(replayObservation.signatureValid).toBe(true);
    expect(replayObservation.responseStatus).toBe(200);
    await expect(failedRow).toContainText('Succeeded');
    await expect(failedRow).toContainText('2');

    const recoveredDeadLettersResponse = await api.get(
      `/console/webhooks/${encodeURIComponent(endpointId)}/dead-letters?limit=20&includeResolved=true`,
    );
    const recoveredDeadLettersBody = await readSuccessJson(
      recoveredDeadLettersResponse,
      'Recovered webhook dead-letter list',
    );
    const recoveredDeadLetters = Array.isArray(recoveredDeadLettersBody.deadLetters)
      ? recoveredDeadLettersBody.deadLetters
      : [];
    const recoveredDeadLetter = findByField(
      recoveredDeadLetters,
      'deliveryId',
      deliveryId,
      'Recovered webhook dead letter',
    );
    expect(
      requireString(recoveredDeadLetter.resolvedAt, 'Dead-letter resolution time'),
    ).toBeTruthy();

    await page.reload();
    await expect(page.getByLabel('Webhooks page')).toBeVisible();
    await expect(page.getByRole('button', { name: receiver.url, exact: true })).toBeVisible();
    const persistedRow = page
      .getByRole('table', { name: 'Webhook deliveries table' })
      .getByRole('row')
      .filter({ hasText: failedObservation.eventType });
    await expect(persistedRow).toContainText('Succeeded');
    await expect(persistedRow).toContainText('2');
  } finally {
    await receiver.close();
  }
});
