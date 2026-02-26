import { test, expect } from '@playwright/test';
import {
  createPostgresConsoleWebhookService,
  type ConsoleWebhookService,
} from '@server/router/express-adaptor';
import { getPostgresPool } from '../../server/src/storage/postgres';

function randomNamespace(prefix: string): string {
  return `${prefix}:${Date.now()}:${Math.random().toString(16).slice(2)}`;
}

test.describe('console webhooks postgres service', () => {
  const postgresUrl = String(process.env.POSTGRES_URL || '').trim();
  const enabled = Boolean(postgresUrl);
  const namespace = randomNamespace('test:console-webhooks:postgres');
  let service: ConsoleWebhookService | null = null;

  test.beforeAll(async () => {
    test.skip(!enabled, 'POSTGRES_URL not set');
    let dispatchCalls = 0;
    service = await createPostgresConsoleWebhookService({
      postgresUrl,
      namespace,
      logger: console as any,
      ensureSchema: true,
      dispatcher: {
        dispatch: async () => {
          dispatchCalls += 1;
          if (dispatchCalls === 1) {
            return {
              ok: false,
              statusCode: 500,
              responseBody: 'temporary failure',
              errorMessage: 'upstream unavailable',
            };
          }
          return {
            ok: true,
            statusCode: 200,
            responseBody: 'ok',
          };
        },
      },
    });
  });

  test.afterAll(async () => {
    if (!enabled) return;
    const pool = await getPostgresPool(postgresUrl);
    await pool.query('DELETE FROM console_webhook_attempts WHERE namespace = $1', [namespace]);
    await pool.query('DELETE FROM console_webhook_dead_letters WHERE namespace = $1', [namespace]);
    await pool.query('DELETE FROM console_webhook_deliveries WHERE namespace = $1', [namespace]);
    await pool.query('DELETE FROM console_webhook_endpoints WHERE namespace = $1', [namespace]);
  });

  test('endpoint lifecycle supports create/list/update/delete', async () => {
    test.skip(!enabled, 'POSTGRES_URL not set');
    const ctx = {
      orgId: 'org-webhooks-postgres-crud',
      actorUserId: 'admin-webhooks-crud',
      roles: ['admin'],
    };

    const created = await service!.createEndpoint(ctx, {
      url: 'https://example.com/webhooks/postgres-crud',
      subscriptions: ['billing', 'wallet'],
    });
    expect(created.id).toBeTruthy();
    expect(created.secretVersion).toBe(1);
    expect(created.secretPreview).toContain('...');
    expect(created.status).toBe('ACTIVE');

    const listed = await service!.listEndpoints(ctx);
    expect(listed.some((entry) => entry.id === created.id)).toBe(true);

    const updated = await service!.updateEndpoint(ctx, created.id, {
      status: 'DISABLED',
      subscriptions: ['billing'],
    });
    expect(updated?.id).toBe(created.id);
    expect(updated?.status).toBe('DISABLED');
    expect(updated?.subscriptions).toEqual(['billing']);

    const removed = await service!.deleteEndpoint(ctx, created.id);
    expect(removed.removed).toBe(true);
    const listedAfterDelete = await service!.listEndpoints(ctx);
    expect(listedAfterDelete.some((entry) => entry.id === created.id)).toBe(false);
  });

  test('emit/replay persists deliveries, attempts, and DLQ lifecycle', async () => {
    test.skip(!enabled, 'POSTGRES_URL not set');
    const ctx = {
      orgId: 'org-webhooks-postgres-delivery',
      actorUserId: 'ops-webhooks-delivery',
      roles: ['ops'],
    };

    const endpoint = await service!.createEndpoint(ctx, {
      url: 'https://example.com/webhooks/postgres-delivery',
      subscriptions: ['billing'],
    });

    const emitted = await service!.emitEvent(ctx, {
      eventType: 'billing.invoice.paid',
      payload: {
        invoiceId: 'inv_postgres_1',
      },
    });
    expect(emitted.attempted).toBe(1);
    expect(emitted.delivered).toBe(0);
    expect(emitted.failed).toBe(1);

    const deliveries = await service!.listDeliveries(ctx, endpoint.id);
    expect(deliveries.items.length).toBe(1);
    expect(deliveries.items[0].status).toBe('FAILED');
    expect(deliveries.items[0].attemptCount).toBe(1);
    const deliveryId = deliveries.items[0].id;

    const attemptsBeforeReplay = await service!.listAttempts(ctx, endpoint.id, {});
    expect(attemptsBeforeReplay.items.length).toBe(1);
    expect(attemptsBeforeReplay.items[0].deliveryId).toBe(deliveryId);
    expect(attemptsBeforeReplay.items[0].attemptNo).toBe(1);
    expect(attemptsBeforeReplay.items[0].status).toBe('FAILED');
    expect(attemptsBeforeReplay.items[0].isReplay).toBe(false);

    const unresolvedDeadLetters = await service!.listDeadLetters(ctx, endpoint.id, {});
    expect(unresolvedDeadLetters.items.length).toBe(1);
    expect(unresolvedDeadLetters.items[0].deliveryId).toBe(deliveryId);
    expect(unresolvedDeadLetters.items[0].resolvedAt).toBeNull();

    const replay = await service!.replayDelivery(ctx, endpoint.id, { deliveryId });
    expect(replay.replayed).toBe(true);
    expect(replay.delivery?.id).toBe(deliveryId);
    expect(replay.delivery?.status).toBe('SUCCEEDED');
    expect(replay.delivery?.attemptCount).toBe(2);
    expect(replay.delivery?.replayCount).toBe(1);

    const replayNone = await service!.replayDelivery(ctx, endpoint.id, {});
    expect(replayNone.replayed).toBe(false);
    expect(replayNone.reason).toBe('no_replayable_delivery');

    const attemptsAfterReplay = await service!.listAttempts(ctx, endpoint.id, {
      deliveryId,
      limit: 1,
    });
    expect(attemptsAfterReplay.items.length).toBe(1);
    expect(attemptsAfterReplay.items[0].attemptNo).toBe(2);
    expect(attemptsAfterReplay.items[0].status).toBe('SUCCEEDED');
    expect(attemptsAfterReplay.items[0].isReplay).toBe(true);
    expect(String(attemptsAfterReplay.nextCursor || '')).toBeTruthy();

    const unresolvedAfterReplay = await service!.listDeadLetters(ctx, endpoint.id, {});
    expect(unresolvedAfterReplay.items.length).toBe(0);

    const resolvedDeadLetters = await service!.listDeadLetters(ctx, endpoint.id, {
      includeResolved: true,
    });
    expect(resolvedDeadLetters.items.length).toBe(1);
    expect(resolvedDeadLetters.items[0].deliveryId).toBe(deliveryId);
    expect(Boolean(resolvedDeadLetters.items[0].resolvedAt)).toBe(true);

    const pool = await getPostgresPool(postgresUrl);
    const attempts = await pool.query(
      `SELECT attempt_no, status, is_replay, response_status
         FROM console_webhook_attempts
        WHERE namespace = $1 AND delivery_id = $2
        ORDER BY attempt_no ASC`,
      [namespace, deliveryId],
    );
    expect(attempts.rows.length).toBe(2);
    expect(String((attempts.rows[0] as any).status)).toBe('FAILED');
    expect(Boolean((attempts.rows[0] as any).is_replay)).toBe(false);
    expect(Number((attempts.rows[0] as any).response_status || 0)).toBe(500);
    expect(String((attempts.rows[1] as any).status)).toBe('SUCCEEDED');
    expect(Boolean((attempts.rows[1] as any).is_replay)).toBe(true);
    expect(Number((attempts.rows[1] as any).response_status || 0)).toBe(200);

    const deadLetter = await pool.query(
      `SELECT failed_attempts, resolved_at_ms
         FROM console_webhook_dead_letters
        WHERE namespace = $1 AND delivery_id = $2`,
      [namespace, deliveryId],
    );
    expect(deadLetter.rows.length).toBe(1);
    expect(Number((deadLetter.rows[0] as any).failed_attempts || 0)).toBe(1);
    expect(Number((deadLetter.rows[0] as any).resolved_at_ms || 0)).toBeGreaterThan(0);
  });

  test('pagination cursors advance consistently across deliveries, attempts, and dead letters', async () => {
    test.skip(!enabled, 'POSTGRES_URL not set');
    const ctx = {
      orgId: 'org-webhooks-postgres-pagination',
      actorUserId: 'ops-webhooks-pagination',
      roles: ['ops'],
    };

    const endpoint = await service!.createEndpoint(ctx, {
      url: 'https://example.com/webhooks/postgres-pagination',
      subscriptions: ['billing'],
    });

    const baseMs = Date.parse('2026-01-01T00:00:00.000Z');
    const seededDeliveries = [
      {
        deliveryId: 'whd_pg_page_1',
        eventId: 'evt_pg_page_1',
        deadLetterId: 'whdlq_pg_page_1',
        createdAtMs: baseMs + 1000,
      },
      {
        deliveryId: 'whd_pg_page_2',
        eventId: 'evt_pg_page_2',
        deadLetterId: 'whdlq_pg_page_2',
        createdAtMs: baseMs + 2000,
      },
      {
        deliveryId: 'whd_pg_page_3',
        eventId: 'evt_pg_page_3',
        deadLetterId: 'whdlq_pg_page_3',
        createdAtMs: baseMs + 3000,
      },
    ];

    const pool = await getPostgresPool(postgresUrl);
    for (const seed of seededDeliveries) {
      const attemptedAtMs = seed.createdAtMs + 200;
      const movedToDlqAtMs = seed.createdAtMs + 400;
      await pool.query(
        `INSERT INTO console_webhook_deliveries
          (namespace, id, org_id, endpoint_id, event_id, event_type, status, attempt_count,
           replay_count, response_status, response_body, error_message, payload_json,
           delivered_at_ms, last_attempt_at_ms, created_at_ms, updated_at_ms)
         VALUES
          ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13::jsonb, $14, $15, $16, $17)`,
        [
          namespace,
          seed.deliveryId,
          ctx.orgId,
          endpoint.id,
          seed.eventId,
          'billing.invoice.created',
          'FAILED',
          1,
          0,
          500,
          'temporary failure',
          'upstream unavailable',
          JSON.stringify({ invoiceId: seed.eventId }),
          null,
          attemptedAtMs,
          seed.createdAtMs,
          attemptedAtMs,
        ],
      );
      await pool.query(
        `INSERT INTO console_webhook_attempts
          (namespace, delivery_id, org_id, endpoint_id, attempt_no, status, response_status,
           response_body, error_message, attempted_at_ms, is_replay)
         VALUES
          ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`,
        [
          namespace,
          seed.deliveryId,
          ctx.orgId,
          endpoint.id,
          1,
          'FAILED',
          500,
          'temporary failure',
          'upstream unavailable',
          attemptedAtMs,
          false,
        ],
      );
      await pool.query(
        `INSERT INTO console_webhook_dead_letters
          (namespace, id, org_id, endpoint_id, delivery_id, event_id, event_type, failed_attempts,
           last_response_status, last_error_message, payload_json, moved_to_dlq_at_ms, resolved_at_ms)
         VALUES
          ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11::jsonb, $12, NULL)`,
        [
          namespace,
          seed.deadLetterId,
          ctx.orgId,
          endpoint.id,
          seed.deliveryId,
          seed.eventId,
          'billing.invoice.created',
          1,
          500,
          'upstream unavailable',
          JSON.stringify({ invoiceId: seed.eventId }),
          movedToDlqAtMs,
        ],
      );
    }

    const expectedOrder = [
      seededDeliveries[2].deliveryId,
      seededDeliveries[1].deliveryId,
      seededDeliveries[0].deliveryId,
    ];

    const deliveriesPageOne = await service!.listDeliveries(ctx, endpoint.id, { limit: 2 });
    expect(deliveriesPageOne.items.map((entry) => entry.id)).toEqual(expectedOrder.slice(0, 2));
    expect(String(deliveriesPageOne.nextCursor || '')).toBeTruthy();

    const deliveriesPageTwo = await service!.listDeliveries(ctx, endpoint.id, {
      limit: 2,
      cursor: deliveriesPageOne.nextCursor,
    });
    expect(deliveriesPageTwo.items.map((entry) => entry.id)).toEqual(expectedOrder.slice(2));
    expect(String(deliveriesPageTwo.nextCursor || '')).toBe('');

    const attemptsPageOne = await service!.listAttempts(ctx, endpoint.id, { limit: 2 });
    expect(attemptsPageOne.items.map((entry) => entry.deliveryId)).toEqual(
      expectedOrder.slice(0, 2),
    );
    expect(String(attemptsPageOne.nextCursor || '')).toBeTruthy();

    const attemptsPageTwo = await service!.listAttempts(ctx, endpoint.id, {
      limit: 2,
      cursor: attemptsPageOne.nextCursor,
    });
    expect(attemptsPageTwo.items.map((entry) => entry.deliveryId)).toEqual(expectedOrder.slice(2));
    expect(String(attemptsPageTwo.nextCursor || '')).toBe('');

    const deadLettersPageOne = await service!.listDeadLetters(ctx, endpoint.id, { limit: 2 });
    expect(deadLettersPageOne.items.map((entry) => entry.deliveryId)).toEqual(
      expectedOrder.slice(0, 2),
    );
    expect(String(deadLettersPageOne.nextCursor || '')).toBeTruthy();

    const deadLettersPageTwo = await service!.listDeadLetters(ctx, endpoint.id, {
      limit: 2,
      cursor: deadLettersPageOne.nextCursor,
    });
    expect(deadLettersPageTwo.items.map((entry) => entry.deliveryId)).toEqual(
      expectedOrder.slice(2),
    );
    expect(String(deadLettersPageTwo.nextCursor || '')).toBe('');
  });

  test('pagination uses id tie-breakers when timestamps are identical', async () => {
    test.skip(!enabled, 'POSTGRES_URL not set');
    const ctx = {
      orgId: 'org-webhooks-postgres-pagination-tie',
      actorUserId: 'ops-webhooks-pagination-tie',
      roles: ['ops'],
    };

    const endpoint = await service!.createEndpoint(ctx, {
      url: 'https://example.com/webhooks/postgres-pagination-tie',
      subscriptions: ['billing'],
    });

    const createdAtMs = Date.parse('2026-01-02T00:00:00.000Z');
    const attemptedAtMs = createdAtMs + 200;
    const movedToDlqAtMs = createdAtMs + 400;
    const pool = await getPostgresPool(postgresUrl);
    const seeds = [
      {
        deliveryId: 'whd_pg_tie_a',
        eventId: 'evt_pg_tie_a',
        deadLetterId: 'whdlq_pg_tie_a',
      },
      {
        deliveryId: 'whd_pg_tie_b',
        eventId: 'evt_pg_tie_b',
        deadLetterId: 'whdlq_pg_tie_b',
      },
    ];

    for (const seed of seeds) {
      await pool.query(
        `INSERT INTO console_webhook_deliveries
          (namespace, id, org_id, endpoint_id, event_id, event_type, status, attempt_count,
           replay_count, response_status, response_body, error_message, payload_json,
           delivered_at_ms, last_attempt_at_ms, created_at_ms, updated_at_ms)
         VALUES
          ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13::jsonb, $14, $15, $16, $17)`,
        [
          namespace,
          seed.deliveryId,
          ctx.orgId,
          endpoint.id,
          seed.eventId,
          'billing.invoice.failed',
          'FAILED',
          1,
          0,
          500,
          'temporary failure',
          'upstream unavailable',
          JSON.stringify({ invoiceId: seed.eventId }),
          null,
          attemptedAtMs,
          createdAtMs,
          attemptedAtMs,
        ],
      );
      await pool.query(
        `INSERT INTO console_webhook_attempts
          (namespace, delivery_id, org_id, endpoint_id, attempt_no, status, response_status,
           response_body, error_message, attempted_at_ms, is_replay)
         VALUES
          ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`,
        [
          namespace,
          seed.deliveryId,
          ctx.orgId,
          endpoint.id,
          1,
          'FAILED',
          500,
          'temporary failure',
          'upstream unavailable',
          attemptedAtMs,
          false,
        ],
      );
      await pool.query(
        `INSERT INTO console_webhook_dead_letters
          (namespace, id, org_id, endpoint_id, delivery_id, event_id, event_type, failed_attempts,
           last_response_status, last_error_message, payload_json, moved_to_dlq_at_ms, resolved_at_ms)
         VALUES
          ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11::jsonb, $12, NULL)`,
        [
          namespace,
          seed.deadLetterId,
          ctx.orgId,
          endpoint.id,
          seed.deliveryId,
          seed.eventId,
          'billing.invoice.failed',
          1,
          500,
          'upstream unavailable',
          JSON.stringify({ invoiceId: seed.eventId }),
          movedToDlqAtMs,
        ],
      );
    }

    const expectedDeliveryOrder = ['whd_pg_tie_b', 'whd_pg_tie_a'];

    const deliveriesPageOne = await service!.listDeliveries(ctx, endpoint.id, { limit: 1 });
    expect(deliveriesPageOne.items.map((entry) => entry.id)).toEqual(
      expectedDeliveryOrder.slice(0, 1),
    );
    const deliveriesPageTwo = await service!.listDeliveries(ctx, endpoint.id, {
      limit: 1,
      cursor: deliveriesPageOne.nextCursor,
    });
    expect(deliveriesPageTwo.items.map((entry) => entry.id)).toEqual(
      expectedDeliveryOrder.slice(1),
    );
    expect(String(deliveriesPageTwo.nextCursor || '')).toBe('');

    const attemptsPageOne = await service!.listAttempts(ctx, endpoint.id, { limit: 1 });
    expect(attemptsPageOne.items.map((entry) => entry.deliveryId)).toEqual(
      expectedDeliveryOrder.slice(0, 1),
    );
    const attemptsPageTwo = await service!.listAttempts(ctx, endpoint.id, {
      limit: 1,
      cursor: attemptsPageOne.nextCursor,
    });
    expect(attemptsPageTwo.items.map((entry) => entry.deliveryId)).toEqual(
      expectedDeliveryOrder.slice(1),
    );
    expect(String(attemptsPageTwo.nextCursor || '')).toBe('');

    const deadLettersPageOne = await service!.listDeadLetters(ctx, endpoint.id, { limit: 1 });
    expect(deadLettersPageOne.items.map((entry) => entry.deliveryId)).toEqual(
      expectedDeliveryOrder.slice(0, 1),
    );
    const deadLettersPageTwo = await service!.listDeadLetters(ctx, endpoint.id, {
      limit: 1,
      cursor: deadLettersPageOne.nextCursor,
    });
    expect(deadLettersPageTwo.items.map((entry) => entry.deliveryId)).toEqual(
      expectedDeliveryOrder.slice(1),
    );
    expect(String(deadLettersPageTwo.nextCursor || '')).toBe('');
  });

  test('attempt cursor rejects non-numeric id component', async () => {
    test.skip(!enabled, 'POSTGRES_URL not set');
    const ctx = {
      orgId: 'org-webhooks-postgres-invalid-attempt-cursor',
      actorUserId: 'ops-webhooks-invalid-attempt-cursor',
      roles: ['ops'],
    };

    const endpoint = await service!.createEndpoint(ctx, {
      url: 'https://example.com/webhooks/postgres-invalid-attempt-cursor',
      subscriptions: ['billing'],
    });

    let caught: any;
    try {
      await service!.listAttempts(ctx, endpoint.id, {
        cursor: `${Date.parse('2026-01-03T00:00:00.000Z')}:non_numeric_attempt_id`,
      });
    } catch (error: unknown) {
      caught = error;
    }
    expect(caught).toBeTruthy();
    expect(String(caught?.code || '')).toBe('invalid_query');
  });
});
