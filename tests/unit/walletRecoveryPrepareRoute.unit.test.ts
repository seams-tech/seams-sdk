import { expect, test } from '@playwright/test';
import {
  createRouterApiRouteDefinitions,
  findRouteDefinitionById,
} from '../../packages/sdk-server-ts/src/router/framework/routeDefinitions';

test('the admitted prepare route is registered without a consume-first route', () => {
  const routeDefinitions = createRouterApiRouteDefinitions();
  const route = findRouteDefinitionById(routeDefinitions, 'wallet_recovery_prepare');
  expect(route?.path).toBe('/wallets/recovery/prepare');
  expect(findRouteDefinitionById(routeDefinitions, 'wallet_recovery_code_spend')).toBeNull();
});
