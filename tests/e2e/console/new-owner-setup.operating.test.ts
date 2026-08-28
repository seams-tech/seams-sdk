import { expect, test } from './harness';

const FULL_PUBLISHABLE_SECRET = /^pk_[A-Za-z0-9]{32}$/;

test.describe('Console operating paths', () => {
  test('new owner setup creates a publishable key that reveals once and survives reload', async ({
    console,
  }) => {
    const { page, tenant } = console;
    await page.goto('/dashboard');
    await expect(page).toHaveURL(/\/dashboard\/onboarding\/?$/);
    await expect(page.getByRole('heading', { level: 1, name: /Onboarding/i })).toBeVisible();

    const navigation = page.getByRole('complementary', {
      name: 'Primary dashboard navigation',
    });
    await expect(navigation).toHaveCount(0);

    const organizationForm = page.getByRole('region', { name: 'Create organization' });
    await organizationForm.getByLabel('Organization name').fill(tenant.organizationName);
    await organizationForm
      .getByRole('button', { name: 'Continue to project setup', exact: true })
      .click();

    const projectForm = page.getByRole('region', { name: 'Create project' });
    await expect(projectForm).toBeVisible();
    await projectForm.getByLabel('Project name').fill(tenant.projectName);
    await projectForm.getByRole('button', { name: 'Finish onboarding', exact: true }).click();

    await expect(
      page.getByRole('heading', { name: 'Onboarding complete', exact: true }),
    ).toBeVisible();
    await page.getByRole('button', { name: 'Go to credentials', exact: true }).click();
    await expect(page).toHaveURL(/\/dashboard\/api-keys\/?$/);
    await expect(navigation).toBeVisible();
    await expect(
      navigation.getByRole('link', { name: 'API Keys', exact: true }),
    ).not.toHaveAttribute('aria-disabled', 'true');
    await expect(page.getByRole('heading', { level: 1 })).toHaveText('API Keys');
    await expect(
      page.getByRole('button', { name: `${tenant.projectName}, Development`, exact: true }),
    ).toBeVisible();

    await page.getByRole('button', { name: 'Create credential', exact: true }).click();
    const createDialog = page.getByRole('dialog', { name: 'Create credential modal' });
    await expect(createDialog).toBeVisible();
    await createDialog.getByRole('button', { name: /Browser publishable_key/ }).click();
    await createDialog.getByLabel('Name').fill(`${tenant.projectName} browser key`);
    await createDialog.getByRole('button', { name: 'Create publishable_key', exact: true }).click();

    const secret = page.locator('code').filter({ hasText: FULL_PUBLISHABLE_SECRET });
    await expect(secret).toHaveCount(1);
    const revealedSecret = String(await secret.textContent()).trim();
    expect(revealedSecret).toMatch(FULL_PUBLISHABLE_SECRET);

    const keyName = `${tenant.projectName} browser key`;
    const credentialsTable = page.getByRole('table', { name: 'Credentials table' });
    await expect(credentialsTable.getByRole('row').filter({ hasText: keyName })).toBeVisible();

    await page.reload();
    await expect(page).toHaveURL(/\/dashboard\/api-keys\/?$/);
    await expect(credentialsTable.getByRole('row').filter({ hasText: keyName })).toBeVisible();
    await expect(page.locator('code').filter({ hasText: FULL_PUBLISHABLE_SECRET })).toHaveCount(0);

    const resources = await console.readTenantResources();
    expect(resources.organization.id).toBe(tenant.orgId);
    expect(resources.organization.name).toBe(tenant.organizationName);
    expect(resources.project.id).toMatch(/^proj_/);
    expect(resources.project.name).toBe(tenant.projectName);
    expect(resources.environment.id).toBe(`${resources.project.id}:dev`);
    expect(resources.environment.projectId).toBe(resources.project.id);
    expect(resources.environment.key).toBe('dev');
    const createdKey = resources.apiKeys.find((entry) => entry.name === keyName);
    expect(createdKey).toBeDefined();
    expect(createdKey?.kind).toBe('publishable_key');
    expect(createdKey?.environmentId).toBe(resources.environment.id);
    expect(createdKey?.secretPreview.startsWith('pk_')).toBe(true);
    expect(createdKey?.secretPreview).not.toBe(revealedSecret);
  });
});
