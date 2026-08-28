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

function findRowByField(rows: unknown[], field: string, value: string, label: string): JsonObject {
  const row = rows.find((entry) => isRecord(entry) && String(entry[field] || '').trim() === value);
  return requireRecord(row, label);
}

function readRows(body: JsonObject, field: string, label: string): unknown[] {
  const rows = body[field];
  if (!Array.isArray(rows)) throw new Error(`${label} response omitted ${field}`);
  return rows;
}

test('billing checkout funds a zero-balance account and persists its receipt document', async ({
  console,
}) => {
  const { page, api } = console;
  await console.provisionCompletedTenant();

  const initialOverviewResponse = await api.get('/console/billing/overview');
  const initialOverviewBody = await readSuccessJson(
    initialOverviewResponse,
    'Initial billing overview',
  );
  const initialOverview = requireRecord(initialOverviewBody.overview, 'Initial billing overview');
  expect(Number(initialOverview.creditBalanceMinor)).toBe(0);
  expect(String(initialOverview.liveEnvironmentState || '').toUpperCase()).toBe('BLOCKED');

  await page.goto('/dashboard/billing/account');
  const billingPage = page.getByLabel('Billing page');
  await expect(billingPage).toBeVisible();
  const summary = page.getByRole('region', { name: 'Billing account summary metrics' });
  await expect(summary).toContainText('$0.00');
  await expect(summary).toContainText('Live environments are blocked');

  await page
    .getByRole('group', { name: 'Top-up amount' })
    .getByRole('button', { name: '$25', exact: true })
    .click();
  await page.getByRole('button', { name: 'Buy $25', exact: true }).click();
  await expect(page).toHaveURL(
    /\/dashboard\/billing\/account\?checkout=success&checkout_session_id=/,
  );
  const checkoutSessionId = requireString(
    new URL(page.url()).searchParams.get('checkout_session_id'),
    'Checkout session id',
  );

  await expect(summary).toContainText('$25.00', { timeout: 30_000 });
  await expect(page.getByText('Balance updated')).toBeVisible();
  const settledOverviewResponse = await api.get('/console/billing/overview');
  const settledOverviewBody = await readSuccessJson(
    settledOverviewResponse,
    'Settled billing overview',
  );
  const settledOverview = requireRecord(settledOverviewBody.overview, 'Settled billing overview');
  expect(Number(settledOverview.creditBalanceMinor)).toBe(2500);
  expect(String(settledOverview.liveEnvironmentState || '').toUpperCase()).toBe('HEALTHY');

  const activityResponse = await api.get(
    '/console/billing/account/activity?limit=100&eventType=CREDIT_PURCHASE',
  );
  const activityBody = await readSuccessJson(activityResponse, 'Billing account activity');
  const activity = requireRecord(activityBody.activity, 'Billing account activity');
  const activityEntries = readRows(activity, 'entries', 'Billing account activity');
  expect(activityEntries).toHaveLength(1);
  const purchaseActivity = requireRecord(activityEntries[0], 'Credit purchase activity');
  expect(Number(purchaseActivity.amountMinor)).toBe(2500);
  expect(String(purchaseActivity.type || '').toUpperCase()).toBe('CREDIT_PURCHASE');
  expect(requireString(purchaseActivity.sourceEventId, 'Credit purchase source event')).toBe(
    checkoutSessionId,
  );

  const secondReconcileResponse = await api.post(
    '/console/billing/stripe/checkout-session/reconcile',
    { data: { checkoutSessionId } },
  );
  const secondReconcileBody = await readSuccessJson(
    secondReconcileResponse,
    'Second checkout reconciliation',
  );
  const secondResult = requireRecord(secondReconcileBody.result, 'Second checkout reconciliation');
  expect(secondResult.settled).toBe(true);
  expect(secondResult.settledNow).toBe(false);
  const reconciledInvoice = requireRecord(secondResult.invoice, 'Settled purchase receipt');
  const invoiceId = requireString(reconciledInvoice.id, 'Purchase receipt id');

  const invoicesResponse = await api.get(
    '/console/billing/invoices?documentType=PURCHASE_RECEIPT&limit=100',
  );
  const invoicesBody = await readSuccessJson(invoicesResponse, 'Billing document list');
  const invoices = readRows(invoicesBody, 'invoices', 'Billing document list');
  const invoice = findRowByField(invoices, 'id', invoiceId, 'Purchase receipt');
  expect(String(invoice.documentType || '').toUpperCase()).toBe('PURCHASE_RECEIPT');
  expect(Number(invoice.amountDueMinor)).toBe(2500);
  expect(Number(invoice.amountPaidMinor)).toBe(2500);

  await page.goto('/dashboard/invoices');
  await expect(page.getByLabel('Billing page')).toBeVisible();
  const invoiceRow = page.getByRole('row').filter({ hasText: invoiceId });
  await expect(invoiceRow).toBeVisible();
  await expect(invoiceRow).toContainText('Receipt');
  await expect(invoiceRow).toContainText('$25.00');
  await invoiceRow.getByRole('button', { name: 'View document', exact: true }).click();
  expect(new URL(page.url()).pathname).toBe(`/dashboard/invoices/${invoiceId}`);

  const detailHeader = page.getByRole('region', { name: 'Billing document detail header' });
  await expect(detailHeader).toContainText(invoiceId);
  await expect(
    page.getByRole('region', { name: 'Billing document summary metrics' }),
  ).toContainText('$25.00');
  await expect(
    page.getByRole('region', { name: 'Billing document activity timeline' }),
  ).toContainText('Purchase receipt');
  await expect(page.getByRole('table', { name: 'Billing document line items' })).toContainText(
    'Prepaid credit top-up',
  );

  const download = page.waitForEvent('download');
  await page
    .getByRole('region', { name: 'Billing document detail header' })
    .getByRole('button', { name: 'Download PDF', exact: true })
    .click();
  await expect(await download).toBeTruthy();

  const pdfResponse = await api.get(
    `/console/billing/invoices/${encodeURIComponent(invoiceId)}/pdf`,
  );
  expect(pdfResponse.ok()).toBe(true);
  expect(String(pdfResponse.headers()['content-type'] || '').toLowerCase()).toContain(
    'application/pdf',
  );
  const pdfBody = await pdfResponse.body();
  expect(pdfBody.byteLength).toBeGreaterThan(0);
  expect(pdfBody.subarray(0, 4).toString('ascii')).toBe('%PDF');

  await page.reload();
  await expect(page.getByRole('region', { name: 'Billing document detail header' })).toContainText(
    invoiceId,
  );
  const finalOverviewResponse = await api.get('/console/billing/overview');
  const finalOverviewBody = await readSuccessJson(finalOverviewResponse, 'Final billing overview');
  const finalOverview = requireRecord(finalOverviewBody.overview, 'Final billing overview');
  expect(Number(finalOverview.creditBalanceMinor)).toBe(2500);
  const finalActivityResponse = await api.get(
    '/console/billing/account/activity?limit=100&eventType=CREDIT_PURCHASE',
  );
  const finalActivityBody = await readSuccessJson(
    finalActivityResponse,
    'Final billing account activity',
  );
  const finalActivity = requireRecord(finalActivityBody.activity, 'Final billing account activity');
  expect(readRows(finalActivity, 'entries', 'Final billing account activity')).toHaveLength(1);
});
