import {
  expect,
  readEnabledConsoleDestinations,
  consoleDestinationUrlPattern,
  test,
} from './harness';

test.describe('Console operating paths', () => {
  test('Console route and data smoke', async ({ console }) => {
    await console.provisionCompletedTenant();

    const { page, tenant } = console;
    await page.goto('/dashboard');
    await expect(page).toHaveURL(consoleDestinationUrlPattern('/dashboard/overview'));
    await expect(page.getByRole('main', { name: 'Dashboard workspace' })).toBeVisible();
    await expect(
      page.getByRole('button', { name: `${tenant.projectName}, Development`, exact: true }),
    ).toBeVisible();

    const navigation = page.getByRole('complementary', {
      name: 'Primary dashboard navigation',
    });
    await expect(navigation).toBeVisible();
    const destinations = await readEnabledConsoleDestinations(navigation);
    expect(destinations.length).toBeGreaterThan(1);

    for (const destination of destinations) {
      const link = navigation.getByRole('link', { name: destination.name, exact: true });
      await expect(link).toBeVisible();
      await link.click();
      await expect(page).toHaveURL(consoleDestinationUrlPattern(destination.pathname));
      await expect(page.getByRole('main', { name: 'Dashboard workspace' })).toBeVisible();
      await page.waitForLoadState('networkidle');
      await expect(
        page.getByRole('alert').filter({ hasText: /failed|error|unavailable|not found|unable/i }),
      ).toHaveCount(0);
    }
  });
});
