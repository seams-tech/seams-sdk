import { expect, test } from '@playwright/test';
import {
  deriveDashboardOrganizationSlug,
  generateDashboardOrganizationId,
} from '../../apps/web-client/src/pages/dashboard/utils/organizationIdentity';

test.describe('dashboard organization identity helpers', () => {
  test('derive slug from organization name and generate org ids in the expected format', () => {
    expect(deriveDashboardOrganizationSlug('Pokopia Labs')).toBe('pokopia-labs');
    expect(deriveDashboardOrganizationSlug('  Pokopia_Labs::Japan  ')).toBe('pokopia-labs-japan');
    expect(generateDashboardOrganizationId()).toMatch(/^org_[a-z0-9]{12}$/);
  });
});
