import { expect, test } from './harness';

type JsonObject = Record<string, unknown>;

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

function findPolicy(rows: unknown[], policyName: string): JsonObject {
  const policy = rows
    .map((row) => (isRecord(row) ? row : null))
    .find((row) => String(row?.name || '').trim() === policyName);
  return requireRecord(policy, `Policy ${policyName}`);
}

function findSnapshotPolicy(snapshot: JsonObject, policyId: string): JsonObject {
  const payload = requireRecord(snapshot.payload, 'Runtime snapshot payload');
  const policy = requireRecord(payload.policy, 'Runtime snapshot policy payload');
  const policies = Array.isArray(policy.policies) ? policy.policies : [];
  const match = policies.find((row) => isRecord(row) && String(row.id || '').trim() === policyId);
  return requireRecord(match, `Runtime snapshot policy ${policyId}`);
}

function findSnapshotAssignment(snapshot: JsonObject, policyId: string): JsonObject {
  const payload = requireRecord(snapshot.payload, 'Runtime snapshot payload');
  const policy = requireRecord(payload.policy, 'Runtime snapshot policy payload');
  const assignments = Array.isArray(policy.assignments) ? policy.assignments : [];
  const match = assignments.find(
    (row) => isRecord(row) && String(row.policyId || '').trim() === policyId,
  );
  return requireRecord(match, `Runtime snapshot assignment for ${policyId}`);
}

test('policy governance publishes an effective runtime snapshot and audit deep link', async ({
  console,
}) => {
  const { page, api, tenant } = console;
  await console.provisionCompletedTenant();

  const policyName = `Operating policy ${tenant.orgId}`;
  await page.goto('/dashboard/policy-engine');
  await expect(page.getByLabel('Policy engine page')).toBeVisible();

  await page.getByRole('button', { name: 'Create policy', exact: true }).click();
  const createModal = page.getByRole('dialog', { name: 'Create policy modal' });
  await expect(createModal).toBeVisible();
  await createModal.getByLabel('Policy name').fill(policyName);
  await createModal.getByLabel('Max amount per transaction (minor units)').fill('5000');
  await createModal.getByRole('button', { name: 'Create draft', exact: true }).click();
  await expect(createModal).toBeHidden();

  const policiesResponse = await api.get('/console/policies?kind=TRANSACTION');
  const policiesBody = await readSuccessJson(policiesResponse, 'Policy list');
  const policyRows = Array.isArray(policiesBody.policies) ? policiesBody.policies : [];
  const policy = findPolicy(policyRows, policyName);
  const policyId = requireString(policy.id, 'Created policy id');
  const policyVersion = Number(policy.version);
  expect(Number.isInteger(policyVersion)).toBe(true);
  await expect(
    page.getByRole('row').filter({ hasText: policyName }).getByText(`v${policyVersion}`),
  ).toBeVisible();

  const policyRow = page.getByRole('row').filter({ hasText: policyName });
  await policyRow.getByRole('button', { name: `More actions for ${policyName}` }).click();
  await page.getByRole('menuitem', { name: 'Simulate', exact: true }).click();
  const simulateModal = page.getByRole('dialog', { name: 'Simulate policy modal' });
  await simulateModal.getByLabel('Action').selectOption('transfer');
  await simulateModal.getByLabel('Chain').selectOption('Ethereum');
  await simulateModal.getByLabel('Amount (minor units)').fill('1000');
  await simulateModal.getByRole('button', { name: 'Run simulation', exact: true }).click();
  await expect(simulateModal).toContainText('Decision ALLOW');
  await simulateModal.getByRole('button', { name: 'Close', exact: true }).click();

  await page
    .getByRole('row')
    .filter({ hasText: policyName })
    .getByRole('button', { name: `More actions for ${policyName}` })
    .click();
  await page.getByRole('menuitem', { name: 'Simulate', exact: true }).click();
  const rejectedSimulation = page.getByRole('dialog', { name: 'Simulate policy modal' });
  await rejectedSimulation.getByLabel('Action').selectOption('delete_key');
  await rejectedSimulation.getByLabel('Chain').selectOption('Ethereum');
  await rejectedSimulation.getByLabel('Amount (minor units)').fill('1000');
  await rejectedSimulation.getByRole('button', { name: 'Run simulation', exact: true }).click();
  await expect(rejectedSimulation).toContainText('Decision DENY');
  await rejectedSimulation.getByRole('button', { name: 'Close', exact: true }).click();

  await page
    .getByRole('row')
    .filter({ hasText: policyName })
    .getByRole('button', { name: `More actions for ${policyName}` })
    .click();
  await page.getByRole('menuitem', { name: 'Go live', exact: true }).click();
  const publishModal = page.getByRole('dialog', { name: 'Schedule live policy change modal' });
  await publishModal.getByRole('button', { name: 'Create approval request', exact: true }).click();
  await expect(publishModal.getByRole('button', { name: 'Approve', exact: true })).toBeVisible();
  await publishModal.getByRole('button', { name: 'Approve', exact: true }).click();
  const approvedRequest = publishModal.getByLabel('Approved request for live publish');
  await expect(approvedRequest.locator('option').filter({ hasText: 'APPROVED' })).toHaveCount(1);
  await approvedRequest.selectOption({ index: 1 });
  await publishModal.getByRole('button', { name: 'Publish live', exact: true }).click();
  await expect(publishModal).toBeHidden();
  await expect(page.getByRole('row').filter({ hasText: policyName })).toContainText('Published');

  const republishResponse = await api.post('/console/runtime-snapshots/publish-current', {
    data: { environmentId: tenant.environmentId, projectId: tenant.projectId },
  });
  await readSuccessJson(republishResponse, 'Current runtime snapshot publication');

  const snapshotResponse = await api.get(
    `/console/runtime-snapshots/latest?environmentId=${encodeURIComponent(tenant.environmentId)}&projectId=${encodeURIComponent(tenant.projectId)}`,
  );
  const snapshotBody = await readSuccessJson(snapshotResponse, 'Latest runtime snapshot');
  const snapshot = requireRecord(snapshotBody.snapshot, 'Latest runtime snapshot');
  expect(requireString(snapshot.orgId, 'Runtime snapshot organization')).toBe(tenant.orgId);
  expect(requireString(snapshot.environmentId, 'Runtime snapshot environment')).toBe(
    tenant.environmentId,
  );
  const snapshotPolicy = findSnapshotPolicy(snapshot, policyId);
  expect(requireString(snapshotPolicy.id, 'Snapshot policy id')).toBe(policyId);
  expect(Number(snapshotPolicy.version)).toBeGreaterThanOrEqual(policyVersion);
  expect(String(snapshotPolicy.status || '').toUpperCase()).toBe('PUBLISHED');
  const snapshotRules = requireRecord(snapshotPolicy.rules, 'Snapshot policy rules');
  expect(Number(snapshotRules.maxAmountMinor)).toBe(5000);
  expect(snapshotRules.blockedActions).toEqual(expect.arrayContaining(['delete_key']));
  const snapshotAssignment = findSnapshotAssignment(snapshot, policyId);
  expect(String(snapshotAssignment.scopeType || '').toUpperCase()).toBe('ENVIRONMENT');
  expect(requireString(snapshotAssignment.scopeId, 'Snapshot assignment scope')).toBe(
    tenant.environmentId,
  );

  await page.goto('/dashboard/audit');
  await expect(page.getByLabel('Audit logs page')).toBeVisible();
  await page.getByLabel('Search events').fill(policyName);
  const publicationRow = page
    .getByRole('row')
    .filter({ hasText: 'Published policy' })
    .filter({ hasText: policyName });
  await expect(publicationRow).toBeVisible();
  await publicationRow.getByRole('button', { name: /^View/ }).click();
  await expect(publicationRow.getByRole('button', { name: /^Hide/ })).toBeVisible();
  const policyLink = page.getByRole('link', { name: policyName, exact: true }).first();
  const policyHref = requireString(await policyLink.getAttribute('href'), 'Audit policy deep link');
  expect(policyHref).toContain(`policyId=${encodeURIComponent(policyId)}`);
  await page.goto(policyHref);
  await expect(page).toHaveURL(/\/dashboard\/policy-engine\?policyId=[^&]+/);
  await expect(page.getByRole('dialog', { name: 'Policy details modal' })).toContainText(
    policyName,
  );
});
