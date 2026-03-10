import { expect, test } from '@playwright/test';
import {
  createConsoleRouter,
  createInMemoryConsoleWebhookService,
  type ConsoleAuthAdapter,
} from '@server/router/express-adaptor';
import { fetchJson, startExpressRouter } from './helpers';

function makeConsoleAuthAdapter(
  roles: string[],
  orgId = 'org-webhooks-contract',
  userId = 'user-webhooks-contract',
): ConsoleAuthAdapter {
  return {
    authenticate: async () => ({
      ok: true,
      claims: {
        userId,
        orgId,
        roles,
      },
    }),
  };
}

test.describe('console webhook router contract', () => {
  test('POST /console/webhooks rejects legacy subscriptions payloads', async () => {
    const router = createConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin']),
      webhooks: createInMemoryConsoleWebhookService(),
    });
    const server = await startExpressRouter(router);
    try {
      const response = await fetchJson(`${server.baseUrl}/console/webhooks`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          url: 'https://example.com/webhooks/legacy-contract',
          subscriptions: ['billing'],
          status: 'ACTIVE',
        }),
      });

      expect(response.status).toBe(400);
      expect(response.json?.code).toBe('invalid_body');
      expect(response.json?.message).toBe('Field eventCategories must be a non-empty array');
    } finally {
      await server.close();
    }
  });
});
