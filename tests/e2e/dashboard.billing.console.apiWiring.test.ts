import { expect, test, type Page, type Route } from '@playwright/test';

function iso(ts: string): string {
  return new Date(ts).toISOString();
}

function parseJsonBody(raw: string | null): Record<string, unknown> {
  if (!raw) return {};
  try {
    const parsed = JSON.parse(raw);
    if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) {
      return parsed as Record<string, unknown>;
    }
  } catch {}
  return {};
}

async function fulfillJson(route: Route, body: unknown, status = 200): Promise<void> {
  await route.fulfill({
    status,
    contentType: 'application/json',
    body: JSON.stringify(body),
  });
}

async function routeWorkspaceScaffold(
  page: Page,
  _consoleOrigin: string,
  input: {
    userId: string;
    roles?: string[];
    org: Record<string, unknown>;
    project: Record<string, unknown>;
    environment: Record<string, unknown>;
    handleBillingRequest: (
      route: Route,
      pathname: string,
      method: string,
      url: URL,
    ) => Promise<boolean>;
  },
): Promise<void> {
  await page.route(/^https?:\/\/[^/]+\/console\/.*/i, async (route) => {
    const req = route.request();
    const method = req.method().toUpperCase();
    const url = new URL(req.url());
    const { pathname } = url;

    if (pathname === '/console/session') {
      await fulfillJson(route, {
        ok: true,
        claims: {
          userId: input.userId,
          orgId: String(input.org.id || ''),
          roles: Array.isArray(input.roles) && input.roles.length > 0 ? input.roles : ['admin'],
          projectId: String(input.project.id || ''),
          environmentId: String(input.environment.id || ''),
        },
      });
      return;
    }

    if (pathname === '/console/onboarding/state') {
      await fulfillJson(route, {
        ok: true,
        state: {
          orgId: String(input.org.id || ''),
          organization: input.org,
          activeProjectCount: 1,
          activeEnvironmentCount: 1,
          activeApiKeyCount: 1,
          hasOrganization: true,
          hasProject: true,
          hasEnvironment: true,
          hasApiKey: true,
          accountReady: true,
          organizationReady: true,
          billingReady: true,
          projectReady: true,
          onboardingComplete: true,
          currentStep: 'complete',
          complete: true,
          selectedProjectId: String(input.project.id || ''),
          selectedEnvironmentId: String(input.environment.id || ''),
        },
      });
      return;
    }

    if (pathname === '/console/org') {
      await fulfillJson(route, { ok: true, org: input.org });
      return;
    }

    if (pathname === '/console/projects') {
      await fulfillJson(route, { ok: true, projects: [input.project] });
      return;
    }

    if (pathname === '/console/environments') {
      await fulfillJson(route, { ok: true, environments: [input.environment] });
      return;
    }

    if (await input.handleBillingRequest(route, pathname, method, url)) {
      return;
    }

    if (method === 'GET' && pathname === '/console/billing/sponsored-executions') {
      await fulfillJson(route, {
        ok: true,
        page: {
          items: [],
          nextCursor: null,
        },
      });
      return;
    }

    if (method === 'GET' && pathname === '/console/billing/sponsored-executions/reconciliation') {
      await fulfillJson(route, {
        ok: true,
        page: {
          items: [],
          nextCursor: null,
          summary: {
            matchedCount: 0,
            notChargedCount: 0,
            missingBillingDebitCount: 0,
            amountMismatchCount: 0,
            unexpectedBillingDebitCount: 0,
            mismatchCount: 0,
          },
        },
      });
      return;
    }

    await fulfillJson(
      route,
      {
        ok: false,
        code: 'not_found',
        message: `Unhandled mock path ${pathname}`,
      },
      404,
    );
  });
}

test.describe('dashboard billing prepaid console api wiring', () => {
  test('wires prepaid top-up actions', async ({ page, baseURL }) => {
    const consoleOrigin = new URL(String(baseURL || 'http://127.0.0.1:3600')).origin;
    const checkoutBodies: Record<string, unknown>[] = [];
    const checkoutReconcileBodies: Record<string, unknown>[] = [];
    let creditBalanceMinor = 0;
    let recentCreditPurchasedMinor = 0;
    let documentCount = 0;

    const org = {
      id: 'org_dash_billing_prepaid',
      name: 'Dashboard Billing Org',
      slug: 'dashboard-billing-org',
      status: 'ACTIVE',
      createdAt: iso('2026-01-01T00:00:00.000Z'),
      updatedAt: iso('2026-01-01T00:00:00.000Z'),
    };
    const project = {
      id: 'proj_dash_billing_prepaid',
      name: 'Billing Project',
      slug: 'billing-project',
      status: 'ACTIVE',
      environmentCount: 1,
      createdAt: iso('2026-01-01T00:00:00.000Z'),
      updatedAt: iso('2026-01-01T00:00:00.000Z'),
    };
    const environment = {
      id: 'env_dash_billing_prepaid',
      projectId: project.id,
      key: 'prod',
      name: 'Production',
      status: 'ACTIVE',
      createdAt: iso('2026-01-01T00:00:00.000Z'),
      updatedAt: iso('2026-01-01T00:00:00.000Z'),
    };

    await routeWorkspaceScaffold(page, consoleOrigin, {
      userId: 'user_dash_billing_prepaid',
      org,
      project,
      environment,
      handleBillingRequest: async (route, pathname, method, _url) => {
        if (method === 'GET' && pathname === '/console/billing/overview') {
          await fulfillJson(route, {
            ok: true,
            overview: {
              usageMetricVersion: 'maw_v1',
              currentMonthUtc: '2026-03',
              monthlyActiveWallets: 42,
              creditBalanceMinor,
              lowBalanceThresholdMinor: 2000,
              recentUsageDebitMinor: 12600,
              recentCreditPurchasedMinor,
              documentCount,
            },
          });
          return true;
        }

        if (method === 'GET' && pathname === '/console/billing/usage/monthly-active-wallets') {
          await fulfillJson(route, {
            ok: true,
            usage: {
              usageMetricVersion: 'maw_v1',
              monthUtc: '2026-03',
              monthlyActiveWallets: 42,
            },
          });
          return true;
        }

        if (method === 'GET' && pathname === '/console/billing/account/activity') {
          await fulfillJson(route, {
            ok: true,
            activity: {
              entries: [],
            },
          });
          return true;
        }

        if (method === 'GET' && pathname === '/console/billing/sponsored-executions') {
          await fulfillJson(route, {
            ok: true,
            page: {
              items: [
                {
                  id: 'scr_dash_billing_prepaid_1',
                  environmentId: environment.id,
                  apiKeyId: 'sk_dash_billing_prepaid',
                  apiKeyKind: 'secret_key',
                  route: 'POST /relayer/sponsored-evm-call',
                  policyId: 'policy_dash_billing_prepaid',
                  policyNameAtEvent: 'Production ERC20',
                  templateId: null,
                  chainFamily: 'evm',
                  intentKind: 'evm_call',
                  executorKind: 'evm_eoa',
                  accountRef: '0xabc123',
                  targetRef: '0xfeedbeef',
                  sponsorRef: '0xsponsor',
                  txOrExecutionRef: '0xtxhash1',
                  receiptStatus: 'success',
                  feeUnit: 'wei',
                  feeAmount: '123000000000000',
                  estimatedSpendMinor: 18,
                  settledSpendMinor: 21,
                  pricingVersion: 'static-evm-v1',
                  pricingSource: 'static',
                  billingLedgerEntryId: 'ble_dash_billing_prepaid_1',
                  prepaidReservationId: 'prr_dash_billing_prepaid_1',
                  charged: true,
                  chargedReason: 'settled_sponsor_gas',
                  settledAt: iso('2026-03-01T00:20:30.000Z'),
                  errorCode: null,
                  errorMessage: null,
                  idempotencyKey: 'idem_dash_billing_prepaid_1',
                  createdAt: iso('2026-03-01T00:20:00.000Z'),
                },
              ],
              nextCursor: null,
            },
          });
          return true;
        }

        if (
          method === 'GET' &&
          pathname === '/console/billing/sponsored-executions/reconciliation'
        ) {
          await fulfillJson(route, {
            ok: true,
            page: {
              items: [
                {
                  record: {
                    id: 'scr_dash_billing_prepaid_1',
                    environmentId: environment.id,
                    apiKeyId: 'sk_dash_billing_prepaid',
                    apiKeyKind: 'secret_key',
                    route: 'POST /relayer/sponsored-evm-call',
                    policyId: 'policy_dash_billing_prepaid',
                    policyNameAtEvent: 'Production ERC20',
                    templateId: null,
                    chainFamily: 'evm',
                    intentKind: 'evm_call',
                    executorKind: 'evm_eoa',
                    accountRef: '0xabc123',
                    targetRef: '0xfeedbeef',
                    sponsorRef: '0xsponsor',
                    txOrExecutionRef: '0xtxhash1',
                    receiptStatus: 'success',
                    feeUnit: 'wei',
                    feeAmount: '123000000000000',
                    estimatedSpendMinor: 18,
                    settledSpendMinor: 21,
                    pricingVersion: 'static-evm-v1',
                    pricingSource: 'static',
                    billingLedgerEntryId: 'ble_dash_billing_prepaid_1',
                    prepaidReservationId: 'prr_dash_billing_prepaid_1',
                    charged: true,
                    chargedReason: 'settled_sponsor_gas',
                    settledAt: iso('2026-03-01T00:20:30.000Z'),
                    errorCode: null,
                    errorMessage: null,
                    idempotencyKey: 'idem_dash_billing_prepaid_1',
                    createdAt: iso('2026-03-01T00:20:00.000Z'),
                  },
                  billingDebit: {
                    id: 'ble_dash_billing_prepaid_1',
                    orgId: org.id,
                    type: 'SPONSORED_EXECUTION_DEBIT',
                    amountMinor: 21,
                    currency: 'USD',
                    description: 'Sponsored execution debit',
                    monthUtc: '2026-03',
                    relatedInvoiceId: 'stmt_dash_billing_prepaid_1',
                    relatedPurchaseId: null,
                    sourceEventId: 'idem_dash_billing_prepaid_1',
                    actorType: 'SYSTEM',
                    actorUserId: null,
                    reasonCode: 'sponsored_execution',
                    note: null,
                    idempotencyKey: 'idem_dash_billing_prepaid_1',
                    createdAt: iso('2026-03-01T00:20:31.000Z'),
                  },
                  status: 'matched',
                  mismatchReasons: [],
                },
              ],
              nextCursor: null,
              summary: {
                matchedCount: 1,
                notChargedCount: 0,
                missingBillingDebitCount: 0,
                amountMismatchCount: 0,
                unexpectedBillingDebitCount: 0,
                mismatchCount: 0,
              },
            },
          });
          return true;
        }

        if (method === 'GET' && pathname === '/console/billing/invoices') {
          await fulfillJson(route, {
            ok: true,
            invoices:
              documentCount > 0
                ? [
                    {
                      id: 'receipt_cs_dash_billing_prepaid',
                      documentType: 'PURCHASE_RECEIPT',
                      status: 'PAID',
                      amountDueMinor: 2500,
                      amountPaidMinor: 2500,
                      periodMonthUtc: '2026-03',
                      createdAt: iso('2026-03-01T00:31:00.000Z'),
                      dueAt: null,
                    },
                  ]
                : [],
            nextCursor: null,
            totalCount: documentCount,
            summary: {
              totalCount: documentCount,
              openCount: 0,
              overdueCount: 0,
              paidCount: documentCount,
              outstandingAmountMinor: 0,
              latestPeriodMonthUtc: documentCount > 0 ? '2026-03' : null,
              receiptCount: documentCount,
              statementCount: 0,
            },
          });
          return true;
        }

        if (method === 'POST' && pathname === '/console/billing/stripe/checkout-session') {
          checkoutBodies.push(parseJsonBody(route.request().postData()));
          await fulfillJson(
            route,
            {
              ok: true,
              checkoutSession: {
                id: 'cs_dash_billing_prepaid',
                url: `${consoleOrigin}/dashboard/billing/account?checkout=success&checkout_session_id=cs_dash_billing_prepaid`,
                customerRef: 'cus_dash_billing_prepaid',
                creditPackId: 'usd_25',
                amountMinor: 2500,
                expiresAt: iso('2026-03-01T01:00:00.000Z'),
              },
            },
            201,
          );
          return true;
        }

        if (
          method === 'POST' &&
          pathname === '/console/billing/stripe/checkout-session/reconcile'
        ) {
          checkoutReconcileBodies.push(parseJsonBody(route.request().postData()));
          creditBalanceMinor = 2500;
          recentCreditPurchasedMinor = 2500;
          documentCount = 1;
          await fulfillJson(route, {
            ok: true,
            result: {
              settled: true,
              settledNow: true,
              paymentStatus: 'paid',
              checkoutStatus: 'complete',
              purchase: {
                id: 'bcp_dash_billing_prepaid',
                orgId: org.id,
                creditPackId: 'usd_25',
                status: 'SETTLED',
                amountMinor: 2500,
                currency: 'USD',
                providerCheckoutSessionRef: 'cs_dash_billing_prepaid',
                providerCustomerRef: 'cus_dash_billing_prepaid',
                relatedInvoiceId: 'receipt_cs_dash_billing_prepaid',
                settledAt: iso('2026-03-01T00:31:00.000Z'),
                createdAt: iso('2026-03-01T00:30:00.000Z'),
                updatedAt: iso('2026-03-01T00:31:00.000Z'),
              },
              invoice: {
                id: 'receipt_cs_dash_billing_prepaid',
                documentType: 'PURCHASE_RECEIPT',
                status: 'PAID',
                amountDueMinor: 2500,
                amountPaidMinor: 2500,
                periodMonthUtc: '2026-03',
                createdAt: iso('2026-03-01T00:31:00.000Z'),
                dueAt: null,
              },
            },
          });
          return true;
        }

        return false;
      },
    });

    await page.goto('/dashboard/billing/account');

    const billingScope = page.locator('section[aria-label="Billing scope and actions"]');
    await expect(billingScope).toContainText('Billing is organization-scoped');
    await expect(billingScope).toContainText('Organization');
    await expect(billingScope).toContainText(project.name);
    await expect(billingScope).toContainText(environment.name);
    await expect(billingScope).not.toContainText(environment.id);
    await expect(page.getByText(/subscription/i)).toHaveCount(0);

    const metrics = page.locator('section[aria-label="Billing account summary metrics"]');
    await expect(metrics).toContainText('Balance');
    await expect(metrics).toContainText('$0.00');
    await expect(metrics).toContainText('Recent top-ups');
    await expect(page.locator('section[aria-label="Sponsored execution history"]')).toContainText(
      'Sponsored usage history',
    );
    await expect(page.locator('section[aria-label="Sponsored execution history"]')).toContainText(
      'Production ERC20',
    );
    await expect(
      page.locator('section[aria-label="Sponsored execution reconciliation"]'),
    ).toContainText('Reconciliation');
    await expect(
      page.locator('section[aria-label="Sponsored execution reconciliation"]'),
    ).toContainText('Matched');

    await expect(page.locator('.dashboard-warning-banner')).toContainText(
      'Prepaid balance is depleted',
    );

    const topUpSection = page.locator('section[aria-label="Prepaid top-up actions"]');
    await expect(topUpSection).toContainText('Top up credits');
    await topUpSection.getByRole('button', { name: 'Buy $25' }).click();
    await expect.poll(() => checkoutBodies.length).toBe(1);
    await expect.poll(() => checkoutReconcileBodies.length).toBe(1);
    expect(String(checkoutBodies[0]?.creditPackId || '')).toBe('usd_25');
    expect(String(checkoutBodies[0]?.successUrl || '')).toContain(
      '/dashboard/billing/account?checkout=success&checkout_session_id={CHECKOUT_SESSION_ID}',
    );
    expect(String(checkoutReconcileBodies[0]?.checkoutSessionId || '')).toBe(
      'cs_dash_billing_prepaid',
    );
    await expect(page.locator('.dashboard-info-banner')).toContainText('Balance updated');
    await expect(metrics).toContainText('$25.00');
  });

  test('wires platform billing lookup, filters, and target-org adjustments for platform admin role', async ({
    page,
    baseURL,
  }) => {
    const consoleOrigin = new URL(String(baseURL || 'http://127.0.0.1:3600')).origin;
    const platformSearchRequests: Array<Record<string, string>> = [];
    const lookupRequests: Array<Record<string, string>> = [];
    const manualRequests: Record<string, unknown>[] = [];
    const recentOrganizations = [
      {
        id: 'org_recent_6',
        name: 'Zeta Labs',
        slug: 'zeta-labs',
        status: 'ACTIVE',
      },
      {
        id: 'org_recent_5',
        name: 'Yellow Systems',
        slug: 'yellow-systems',
        status: 'ACTIVE',
      },
      {
        id: 'org_recent_4',
        name: 'Xeno Payments',
        slug: 'xeno-payments',
        status: 'ACTIVE',
      },
      {
        id: 'org_recent_3',
        name: 'Willow Commerce',
        slug: 'willow-commerce',
        status: 'ACTIVE',
      },
      {
        id: 'org_recent_2',
        name: 'Vector Wallets',
        slug: 'vector-wallets',
        status: 'ACTIVE',
      },
      {
        id: 'org_recent_1',
        name: 'Archive Billing',
        slug: 'archive-billing',
        status: 'ACTIVE',
      },
    ];
    const activityEntries: Record<string, unknown>[] = [
      {
        id: 'ble_purchase_platform_1',
        orgId: 'org_dash_billing_adjustments_target',
        type: 'CREDIT_PURCHASE',
        amountMinor: 2500,
        currency: 'USD',
        description: 'Initial purchase settled',
        monthUtc: '2026-03',
        relatedInvoiceId: 'receipt_platform_1',
        relatedPurchaseId: 'bcp_platform_1',
        sourceEventId: null,
        actorType: 'PROVIDER',
        actorUserId: null,
        reasonCode: null,
        note: null,
        idempotencyKey: null,
        createdAt: iso('2026-03-19T00:00:00.000Z'),
      },
      {
        id: 'ble_usage_platform_1',
        orgId: 'org_dash_billing_adjustments_target',
        type: 'USAGE_DEBIT',
        amountMinor: -300,
        currency: 'USD',
        description: 'Monthly active wallet usage',
        monthUtc: '2026-02',
        relatedInvoiceId: 'inv_usage_202602',
        relatedPurchaseId: null,
        sourceEventId: null,
        actorType: 'SYSTEM',
        actorUserId: null,
        reasonCode: null,
        note: null,
        idempotencyKey: null,
        createdAt: iso('2026-02-28T00:00:00.000Z'),
      },
      {
        id: 'ble_adjustment_platform_1',
        orgId: 'org_dash_billing_adjustments_target',
        type: 'MANUAL_ADJUSTMENT',
        amountMinor: 500,
        currency: 'USD',
        description: 'Manual support credit (incident_credit)',
        monthUtc: '2026-03',
        relatedInvoiceId: 'inv_202603_001',
        relatedPurchaseId: null,
        sourceEventId: null,
        actorType: 'USER',
        actorUserId: 'user_dash_billing_adjustments_admin',
        reasonCode: 'incident_credit',
        note: 'Applied goodwill credit',
        idempotencyKey: 'manual-adjustment-seed',
        createdAt: iso('2026-03-18T00:00:00.000Z'),
      },
    ];
    let creditBalanceMinor = 5000;

    await routeWorkspaceScaffold(page, consoleOrigin, {
      userId: 'user_dash_billing_adjustments_admin',
      roles: ['platform_admin'],
      org: {
        id: 'org_dash_billing_adjustments',
        name: 'Dashboard Billing Adjustments Org',
        slug: 'dashboard-billing-adjustments-org',
        status: 'ACTIVE',
        createdAt: iso('2026-01-01T00:00:00.000Z'),
        updatedAt: iso('2026-01-01T00:00:00.000Z'),
      },
      project: {
        id: 'proj_dash_billing_adjustments',
        name: 'Billing Adjustments Project',
        slug: 'billing-adjustments-project',
        status: 'ACTIVE',
        environmentCount: 1,
        createdAt: iso('2026-01-01T00:00:00.000Z'),
        updatedAt: iso('2026-01-01T00:00:00.000Z'),
      },
      environment: {
        id: 'env_dash_billing_adjustments',
        projectId: 'proj_dash_billing_adjustments',
        key: 'prod',
        name: 'Production',
        status: 'ACTIVE',
        createdAt: iso('2026-01-01T00:00:00.000Z'),
        updatedAt: iso('2026-01-01T00:00:00.000Z'),
      },
      handleBillingRequest: async (route, pathname, method, url) => {
        if (method === 'GET' && pathname === '/console/platform/billing/search') {
          platformSearchRequests.push({
            query: String(url.searchParams.get('query') || ''),
            limit: String(url.searchParams.get('limit') || ''),
          });
          const query = String(url.searchParams.get('query') || '').trim();
          const limit = Number(url.searchParams.get('limit') || 0);
          await fulfillJson(route, {
            ok: true,
            organizations: query
              ? [
                  {
                    id: 'org_dash_billing_adjustments_target',
                    name: 'Target Billing Org',
                    slug: 'target-billing-org',
                    status: 'ACTIVE',
                  },
                ]
              : recentOrganizations.slice(0, limit > 0 ? limit : 10),
          });
          return true;
        }

        if (method === 'GET' && pathname === '/console/platform/billing/account') {
          lookupRequests.push({
            orgId: String(url.searchParams.get('orgId') || ''),
            projectId: String(url.searchParams.get('projectId') || ''),
            periodMonthUtc: String(url.searchParams.get('periodMonthUtc') || ''),
            eventType: String(url.searchParams.get('eventType') || ''),
          });
          const periodMonthUtc = String(url.searchParams.get('periodMonthUtc') || '').trim();
          const eventType = String(url.searchParams.get('eventType') || '')
            .trim()
            .toUpperCase();
          const filteredEntries = activityEntries.filter((entry) => {
            const entryMonthUtc = String(entry.monthUtc || '').trim();
            const entryType = String(entry.type || '')
              .trim()
              .toUpperCase();
            if (periodMonthUtc && entryMonthUtc !== periodMonthUtc) return false;
            if (eventType && entryType !== eventType) return false;
            return true;
          });
          await fulfillJson(route, {
            ok: true,
            result: {
              resolvedBy: 'org_id',
              organization: {
                id: 'org_dash_billing_adjustments_target',
                name: 'Target Billing Org',
                slug: 'target-billing-org',
                status: 'ACTIVE',
              },
              teamMembers: [
                {
                  id: 'tm_target_owner',
                  userId: 'user_target_owner',
                  email: 'owner@target.example',
                  displayName: 'Tina Owner',
                  status: 'ACTIVE',
                  access: 'OWNER',
                  addedAt: iso('2026-03-01T00:00:00.000Z'),
                },
                {
                  id: 'tm_target_admin',
                  userId: 'user_target_admin',
                  email: 'admin@target.example',
                  displayName: 'Alex Admin',
                  status: 'INVITED',
                  access: 'ADMIN',
                  addedAt: iso('2026-03-02T00:00:00.000Z'),
                },
              ],
              project: null,
              overview: {
                usageMetricVersion: 'maw_v1',
                currentMonthUtc: '2026-03',
                monthlyActiveWallets: 2,
                creditBalanceMinor,
                lowBalanceThresholdMinor: 2000,
                recentUsageDebitMinor: 300,
                recentCreditPurchasedMinor: 2500,
                documentCount: 2,
                liveEnvironmentState: 'HEALTHY',
              },
              activity: {
                entries: filteredEntries,
              },
            },
          });
          return true;
        }

        if (
          method === 'POST' &&
          pathname === '/console/platform/billing/adjustments/support-credit'
        ) {
          const body = parseJsonBody(route.request().postData());
          manualRequests.push(body);
          const amountMinor = Number(body.amountMinor || 0);
          const relatedInvoiceId = String(body.relatedInvoiceId || '').trim() || null;
          creditBalanceMinor += amountMinor;
          activityEntries.unshift({
            id: `ble_adj_${manualRequests.length}`,
            orgId: 'org_dash_billing_adjustments_target',
            type: 'MANUAL_ADJUSTMENT',
            amountMinor,
            currency: 'USD',
            description: `Manual support credit (${String(body.reasonCode || '').trim()})`,
            monthUtc: '2026-03',
            relatedInvoiceId,
            relatedPurchaseId: null,
            sourceEventId: null,
            actorType: 'USER',
            actorUserId: 'user_dash_billing_adjustments_admin',
            reasonCode: String(body.reasonCode || '').trim() || null,
            note: String(body.note || '').trim() || null,
            idempotencyKey: String(body.idempotencyKey || '').trim() || null,
            createdAt: iso('2026-03-20T00:00:00.000Z'),
          });
          await fulfillJson(
            route,
            {
              ok: true,
              result: {
                created: true,
                adjustment: activityEntries[0],
                creditBalanceMinor,
              },
            },
            201,
          );
          return true;
        }

        return false;
      },
    });

    await page.goto('/platform/billing');

    await expect(
      page.getByText(
        'Search for a customer organisation name or organisation ID to review account activity and apply bill adjustments.',
      ),
    ).toBeVisible();
    await expect(page.locator('section[aria-label="Internal billing adjustments"]')).toHaveCount(0);
    const searchCard = page.locator('.dashboard-platform-billing-search-card');
    await expect(searchCard.getByRole('button', { name: 'Clear' })).toHaveCount(0);
    await expect(searchCard.getByRole('button', { name: /^Load account$/ })).toHaveCount(0);

    const searchInput = page.getByRole('combobox', { name: 'Search' });
    await searchInput.click();
    await expect.poll(() => platformSearchRequests.length).toBe(1);
    expect(String(platformSearchRequests[0]?.query || '')).toBe('');
    expect(String(platformSearchRequests[0]?.limit || '')).toBe('5');

    const platformSearchDropdown = page.getByRole('listbox', {
      name: 'Platform billing search suggestions',
    });
    await expect(platformSearchDropdown).toContainText('Zeta Labs');
    await expect(platformSearchDropdown).toContainText('Yellow Systems');
    await expect(platformSearchDropdown).toContainText('Xeno Payments');
    await expect(platformSearchDropdown).toContainText('Willow Commerce');
    await expect(platformSearchDropdown).toContainText('Vector Wallets');
    await expect(platformSearchDropdown).not.toContainText('Archive Billing');

    await searchInput.type('org_dash_billing_adjustments_target', { delay: 20 });
    await expect.poll(() => platformSearchRequests.length).toBeGreaterThan(4);
    await expect
      .poll(() => String(platformSearchRequests[platformSearchRequests.length - 1]?.query || ''))
      .toBe('org_dash_billing_adjustments_target');

    await expect(platformSearchDropdown).toContainText('Target Billing Org');

    await platformSearchDropdown.getByRole('option', { name: /Target Billing Org/i }).click();
    await expect.poll(() => lookupRequests.length).toBe(1);
    expect(String(lookupRequests[0]?.orgId || '')).toBe('org_dash_billing_adjustments_target');
    expect(String(lookupRequests[0]?.projectId || '')).toBe('');
    await expect
      .poll(() => new URL(page.url()).searchParams.get('billingOrgId') || '')
      .toBe('org_dash_billing_adjustments_target');
    await expect
      .poll(() => new URL(page.url()).searchParams.get('billingOrgName') || '')
      .toBe('Target Billing Org');

    await expect(
      page.locator('section[aria-label="Customer organisation account summary"]'),
    ).toContainText('Target Billing Org');
    await expect(
      page.locator('section[aria-label="Customer organisation account summary"]'),
    ).toContainText('Team members');
    await expect(
      page.locator('section[aria-label="Customer organisation account summary"]'),
    ).toContainText('Tina Owner');
    await expect(
      page.locator('section[aria-label="Customer organisation account summary"]'),
    ).toContainText('Alex Admin');
    await expect(
      page.locator('section[aria-label="Customer organisation account summary"]'),
    ).toContainText('Added 2026-03-01');
    await expect(
      page.locator('section[aria-label="Customer organisation account summary"]'),
    ).toContainText('Invited 2026-03-02');
    await expect(page.getByText('$50.00').first()).toBeVisible();

    await page.reload();
    await expect.poll(() => lookupRequests.length).toBe(2);
    await expect(page.getByRole('combobox', { name: 'Search' })).toHaveValue('Target Billing Org');
    await expect(
      page.locator('section[aria-label="Customer organisation account summary"]'),
    ).toContainText('Target Billing Org');

    const activitySection = page.locator('section[aria-label="Customer account activity"]');
    await expect(activitySection).toHaveAttribute('role', 'table');
    await expect(activitySection).toContainText(
      'Latest ledger events for the resolved billing account.',
    );
    await expect(activitySection.getByRole('columnheader', { name: 'When (UTC)' })).toBeVisible();
    await expect(activitySection).toContainText('Credit purchase settled');

    await page.getByLabel('Period').fill('2026-03');
    await page.getByLabel('Event type').selectOption('MANUAL_ADJUSTMENT');
    await page.getByRole('button', { name: 'Apply filters' }).click();
    await expect.poll(() => lookupRequests.length).toBe(3);
    expect(String(lookupRequests[2]?.periodMonthUtc || '')).toBe('2026-03');
    expect(String(lookupRequests[2]?.eventType || '')).toBe('MANUAL_ADJUSTMENT');

    await expect(activitySection).toContainText('incident_credit');
    await expect(activitySection).not.toContainText('receipt_platform_1');

    const adjustmentSection = page.locator('section[aria-label="Customer billing adjustments"]');
    await expect(adjustmentSection).toBeVisible();
    const activityBox = await activitySection.boundingBox();
    const adjustmentBox = await adjustmentSection.boundingBox();
    if (!activityBox || !adjustmentBox) {
      throw new Error('Expected account activity and internal adjustment sections to be visible');
    }
    expect(activityBox.y).toBeLessThan(adjustmentBox.y);

    await adjustmentSection.getByRole('button', { name: 'Create Bill Adjustment' }).click();
    const adjustmentModal = page
      .locator('[role="dialog"]')
      .filter({ hasText: 'Create Bill Adjustment' });
    await expect(adjustmentModal).toBeVisible();
    await expect(adjustmentModal).toHaveAttribute('aria-modal', 'true');
    await expect(adjustmentModal).toContainText('Create Bill Adjustment');
    await expect(adjustmentModal.getByLabel('Adjustment type')).toBeFocused();
    await page.keyboard.press('Escape');
    await expect(adjustmentModal).toHaveCount(0);
    await expect(
      adjustmentSection.getByRole('button', { name: 'Create Bill Adjustment' }),
    ).toBeFocused();

    await adjustmentSection.getByRole('button', { name: 'Create Bill Adjustment' }).click();
    await expect(adjustmentModal).toBeVisible();
    await adjustmentModal.getByLabel('Amount (USD)').fill('15.00');
    await adjustmentModal.getByLabel('Reason code').fill('incident_credit');
    await adjustmentModal.getByLabel('Related document ID (optional)').fill('inv_202603_001');
    await adjustmentModal.getByLabel('Operator note').fill('Applied goodwill credit');

    await expect(adjustmentModal).toContainText('Impact preview: $50.00 -> $65.00 (+$15.00).');

    await adjustmentModal.locator('button[type="submit"]').click();
    await expect.poll(() => manualRequests.length).toBe(1);
    expect(String(manualRequests[0]?.orgId || '')).toBe('org_dash_billing_adjustments_target');
    expect(Number(manualRequests[0]?.amountMinor || 0)).toBe(1500);
    expect(String(manualRequests[0]?.reasonCode || '')).toBe('incident_credit');
    expect(String(manualRequests[0]?.relatedInvoiceId || '')).toBe('inv_202603_001');

    await expect(adjustmentModal).toHaveCount(0);
    await expect(adjustmentSection).toContainText(
      'Granted $15.00 customer support credit to Target Billing Org. Balance is now $65.00.',
    );
    await expect.poll(() => lookupRequests.length).toBe(4);
    await expect(page.getByText('$65.00').first()).toBeVisible();
    await expect(activitySection).toContainText('Applied goodwill credit');
  });

  test('platform billing restores selected account from query string and browser history', async ({
    page,
    baseURL,
  }) => {
    const consoleOrigin = new URL(String(baseURL || 'http://127.0.0.1:3600')).origin;
    const lookupRequests: Array<Record<string, string>> = [];
    const organizations = [
      {
        id: 'org_watchbook',
        name: 'Watchbook',
        slug: 'watch-book',
        status: 'ACTIVE',
      },
      {
        id: 'org_pokopia',
        name: 'Pokopia Labs',
        slug: 'pokopia-labs',
        status: 'ACTIVE',
      },
    ];

    await routeWorkspaceScaffold(page, consoleOrigin, {
      userId: 'user_dash_platform_billing_restore',
      roles: ['platform_admin'],
      org: {
        id: 'org_platform_admin_home',
        name: 'Platform Admin Org',
        slug: 'platform-admin-org',
        status: 'ACTIVE',
        createdAt: iso('2026-01-01T00:00:00.000Z'),
        updatedAt: iso('2026-01-01T00:00:00.000Z'),
      },
      project: {
        id: 'proj_platform_admin_home',
        name: 'Platform Admin Project',
        slug: 'platform-admin-project',
        status: 'ACTIVE',
        environmentCount: 1,
        createdAt: iso('2026-01-01T00:00:00.000Z'),
        updatedAt: iso('2026-01-01T00:00:00.000Z'),
      },
      environment: {
        id: 'env_platform_admin_home',
        projectId: 'proj_platform_admin_home',
        key: 'prod',
        name: 'Production',
        status: 'ACTIVE',
        createdAt: iso('2026-01-01T00:00:00.000Z'),
        updatedAt: iso('2026-01-01T00:00:00.000Z'),
      },
      handleBillingRequest: async (route, pathname, method, url) => {
        if (method === 'GET' && pathname === '/console/platform/billing/search') {
          const query = String(url.searchParams.get('query') || '')
            .trim()
            .toLowerCase();
          const limit = Number(url.searchParams.get('limit') || 0);
          const matches = organizations.filter((organization) => {
            if (!query) return true;
            return (
              organization.name.toLowerCase().includes(query) ||
              organization.id.toLowerCase().includes(query)
            );
          });
          await fulfillJson(route, {
            ok: true,
            organizations: matches.slice(0, limit > 0 ? limit : 10),
          });
          return true;
        }

        if (method === 'GET' && pathname === '/console/platform/billing/account') {
          const orgId = String(url.searchParams.get('orgId') || '').trim();
          lookupRequests.push({
            orgId,
            periodMonthUtc: String(url.searchParams.get('periodMonthUtc') || ''),
            eventType: String(url.searchParams.get('eventType') || ''),
          });
          const organization =
            organizations.find((entry) => entry.id === orgId) || organizations[0]!;
          await fulfillJson(route, {
            ok: true,
            result: {
              resolvedBy: 'org_id',
              organization,
              teamMembers: [
                {
                  id: `${organization.id}_owner`,
                  userId: `${organization.id}_owner_user`,
                  email: `owner@${organization.slug}.example`,
                  displayName: `${organization.name} Owner`,
                  status: 'ACTIVE',
                  access: 'OWNER',
                  addedAt: iso('2026-02-01T00:00:00.000Z'),
                },
              ],
              project: null,
              overview: {
                usageMetricVersion: 'maw_v1',
                currentMonthUtc: '2026-03',
                monthlyActiveWallets: organization.id === 'org_watchbook' ? 14 : 9,
                creditBalanceMinor: organization.id === 'org_watchbook' ? 2200 : 4100,
                lowBalanceThresholdMinor: 2000,
                recentUsageDebitMinor: organization.id === 'org_watchbook' ? 800 : 500,
                recentCreditPurchasedMinor: organization.id === 'org_watchbook' ? 1200 : 2400,
                documentCount: organization.id === 'org_watchbook' ? 2 : 1,
                liveEnvironmentState: 'HEALTHY',
              },
              activity: {
                entries: [],
              },
            },
          });
          return true;
        }

        return false;
      },
    });

    await page.goto('/platform/billing?billingOrgId=org_watchbook&billingOrgName=Watchbook');

    await expect.poll(() => lookupRequests.length).toBe(1);
    await expect(page.getByRole('combobox', { name: 'Search' })).toHaveValue('Watchbook');
    await expect(
      page.locator('section[aria-label="Customer organisation account summary"]'),
    ).toContainText('Watchbook');

    const searchInput = page.getByRole('combobox', { name: 'Search' });
    await searchInput.fill('Pokopia');
    const searchDropdown = page.getByRole('listbox', {
      name: 'Platform billing search suggestions',
    });
    await expect(searchDropdown).toContainText('Pokopia Labs');
    await searchDropdown.getByRole('option', { name: /Pokopia Labs/i }).click();

    await expect.poll(() => lookupRequests.length).toBe(2);
    await expect
      .poll(() => new URL(page.url()).searchParams.get('billingOrgId') || '')
      .toBe('org_pokopia');
    await expect
      .poll(() => new URL(page.url()).searchParams.get('billingOrgName') || '')
      .toBe('Pokopia Labs');
    await expect(page.getByRole('combobox', { name: 'Search' })).toHaveValue('Pokopia Labs');
    await expect(
      page.locator('section[aria-label="Customer organisation account summary"]'),
    ).toContainText('Pokopia Labs');

    await page.goBack();
    await expect.poll(() => lookupRequests.length).toBe(3);
    await expect(page.getByRole('combobox', { name: 'Search' })).toHaveValue('Watchbook');
    await expect(
      page.locator('section[aria-label="Customer organisation account summary"]'),
    ).toContainText('Watchbook');

    await page.goForward();
    await expect.poll(() => lookupRequests.length).toBe(4);
    await expect(page.getByRole('combobox', { name: 'Search' })).toHaveValue('Pokopia Labs');
    await expect(
      page.locator('section[aria-label="Customer organisation account summary"]'),
    ).toContainText('Pokopia Labs');
  });

  test('platform billing page is forbidden for non-platform roles', async ({ page, baseURL }) => {
    const consoleOrigin = new URL(String(baseURL || 'http://127.0.0.1:3600')).origin;

    await routeWorkspaceScaffold(page, consoleOrigin, {
      userId: 'user_dash_billing_adjustments_ops',
      roles: ['ops'],
      org: {
        id: 'org_dash_billing_adjustments_ops',
        name: 'Dashboard Billing Ops Org',
        slug: 'dashboard-billing-ops-org',
        status: 'ACTIVE',
        createdAt: iso('2026-01-01T00:00:00.000Z'),
        updatedAt: iso('2026-01-01T00:00:00.000Z'),
      },
      project: {
        id: 'proj_dash_billing_adjustments_ops',
        name: 'Billing Ops Project',
        slug: 'billing-ops-project',
        status: 'ACTIVE',
        environmentCount: 1,
        createdAt: iso('2026-01-01T00:00:00.000Z'),
        updatedAt: iso('2026-01-01T00:00:00.000Z'),
      },
      environment: {
        id: 'env_dash_billing_adjustments_ops',
        projectId: 'proj_dash_billing_adjustments_ops',
        key: 'prod',
        name: 'Production',
        status: 'ACTIVE',
        createdAt: iso('2026-01-01T00:00:00.000Z'),
        updatedAt: iso('2026-01-01T00:00:00.000Z'),
      },
      handleBillingRequest: async (route, pathname, method, _url) => {
        if (method === 'GET' && pathname === '/console/billing/overview') {
          await fulfillJson(route, {
            ok: true,
            overview: {
              usageMetricVersion: 'maw_v1',
              currentMonthUtc: '2026-03',
              monthlyActiveWallets: 0,
              creditBalanceMinor: 3000,
              lowBalanceThresholdMinor: 2000,
              recentUsageDebitMinor: 0,
              recentCreditPurchasedMinor: 0,
              documentCount: 0,
            },
          });
          return true;
        }

        if (method === 'GET' && pathname === '/console/billing/usage/monthly-active-wallets') {
          await fulfillJson(route, {
            ok: true,
            usage: {
              usageMetricVersion: 'maw_v1',
              monthUtc: '2026-03',
              monthlyActiveWallets: 0,
            },
          });
          return true;
        }

        if (method === 'GET' && pathname === '/console/billing/account/activity') {
          await fulfillJson(route, {
            ok: true,
            activity: {
              entries: [],
            },
          });
          return true;
        }

        if (method === 'GET' && pathname === '/console/billing/invoices') {
          await fulfillJson(route, {
            ok: true,
            invoices: [],
            nextCursor: null,
            totalCount: 0,
            summary: {
              totalCount: 0,
              openCount: 0,
              overdueCount: 0,
              paidCount: 0,
              outstandingAmountMinor: 0,
              latestPeriodMonthUtc: null,
              receiptCount: 0,
              statementCount: 0,
            },
          });
          return true;
        }

        return false;
      },
    });

    await page.goto('/platform/billing');
    await expect(
      page.getByText('Customer Accounts is only available to platform admin users.'),
    ).toBeVisible();
    await expect(page.locator('section[aria-label="Internal billing adjustments"]')).toHaveCount(0);
  });

  test('wires billing document navigation, filters, and PDF export actions', async ({
    page,
    baseURL,
  }) => {
    const consoleOrigin = new URL(String(baseURL || 'http://127.0.0.1:3600')).origin;
    const invoiceListUrls: string[] = [];
    let overviewRequestCount = 0;
    let usageRequestCount = 0;
    let pdfDownloadCount = 0;
    const documents = [
      {
        id: 'receipt_dash_billing_1',
        documentType: 'PURCHASE_RECEIPT',
        status: 'PAID',
        amountDueMinor: 2500,
        amountPaidMinor: 2500,
        periodMonthUtc: '2026-03',
        dueAt: null,
        createdAt: iso('2026-03-05T00:00:00.000Z'),
      },
      {
        id: 'stmt_dash_billing_1',
        documentType: 'USAGE_STATEMENT',
        status: 'PAID',
        amountDueMinor: 12600,
        amountPaidMinor: 12600,
        periodMonthUtc: '2026-03',
        dueAt: null,
        createdAt: iso('2026-03-31T00:00:00.000Z'),
      },
    ] as const;

    await page.addInitScript(() => {
      const target = window as typeof window & { __lastBillingBlobSize?: number };
      const originalCreateObjectURL = URL.createObjectURL.bind(URL);
      target.__lastBillingBlobSize = 0;
      URL.createObjectURL = ((blob: Blob) => {
        target.__lastBillingBlobSize = blob.size;
        return originalCreateObjectURL(blob);
      }) as typeof URL.createObjectURL;
    });

    await routeWorkspaceScaffold(page, consoleOrigin, {
      userId: 'user_dash_billing_invoice',
      org: {
        id: 'org_dash_billing_invoice',
        name: 'Dashboard Billing Documents Org',
        slug: 'dashboard-billing-documents-org',
        status: 'ACTIVE',
        createdAt: iso('2026-01-01T00:00:00.000Z'),
        updatedAt: iso('2026-01-01T00:00:00.000Z'),
      },
      project: {
        id: 'proj_dash_billing_invoice',
        name: 'Billing Documents Project',
        slug: 'billing-documents-project',
        status: 'ACTIVE',
        environmentCount: 1,
        createdAt: iso('2026-01-01T00:00:00.000Z'),
        updatedAt: iso('2026-01-01T00:00:00.000Z'),
      },
      environment: {
        id: 'env_dash_billing_invoice',
        projectId: 'proj_dash_billing_invoice',
        key: 'prod',
        name: 'Production',
        status: 'ACTIVE',
        createdAt: iso('2026-01-01T00:00:00.000Z'),
        updatedAt: iso('2026-01-01T00:00:00.000Z'),
      },
      handleBillingRequest: async (route, pathname, method, url) => {
        if (method === 'GET' && pathname === '/console/billing/overview') {
          overviewRequestCount += 1;
          await fulfillJson(route, {
            ok: true,
            overview: {
              usageMetricVersion: 'maw_v1',
              currentMonthUtc: '2026-03',
              monthlyActiveWallets: 42,
              creditBalanceMinor: 7400,
              lowBalanceThresholdMinor: 2000,
              recentUsageDebitMinor: 12600,
              recentCreditPurchasedMinor: 2500,
              documentCount: 2,
            },
          });
          return true;
        }

        if (method === 'GET' && pathname === '/console/billing/usage/monthly-active-wallets') {
          usageRequestCount += 1;
          await fulfillJson(route, {
            ok: true,
            usage: { usageMetricVersion: 'maw_v1', monthUtc: '2026-03', monthlyActiveWallets: 42 },
          });
          return true;
        }

        if (method === 'GET' && pathname === '/console/billing/account/activity') {
          await fulfillJson(route, {
            ok: true,
            activity: {
              entries: [],
            },
          });
          return true;
        }

        if (method === 'GET' && pathname === '/console/billing/invoices') {
          invoiceListUrls.push(url.toString());
          const documentType = String(url.searchParams.get('documentType') || '').trim();
          const filtered = documentType
            ? documents.filter((invoice) => invoice.documentType === documentType)
            : [...documents];
          await fulfillJson(route, {
            ok: true,
            invoices: filtered,
            nextCursor: null,
            totalCount: filtered.length,
            summary: {
              totalCount: filtered.length,
              openCount: 0,
              overdueCount: 0,
              paidCount: filtered.length,
              outstandingAmountMinor: 0,
              latestPeriodMonthUtc: filtered[0]?.periodMonthUtc || null,
              receiptCount: filtered.filter((entry) => entry.documentType === 'PURCHASE_RECEIPT')
                .length,
              statementCount: filtered.filter((entry) => entry.documentType === 'USAGE_STATEMENT')
                .length,
            },
          });
          return true;
        }

        const invoiceMatch = pathname.match(/^\/console\/billing\/invoices\/([^/]+)$/);
        if (method === 'GET' && invoiceMatch) {
          const invoice = documents.find(
            (entry) => entry.id === decodeURIComponent(invoiceMatch[1] || ''),
          );
          await fulfillJson(route, { ok: true, invoice: invoice || null });
          return true;
        }

        const lineItemsMatch = pathname.match(
          /^\/console\/billing\/invoices\/([^/]+)\/line-items$/,
        );
        if (method === 'GET' && lineItemsMatch) {
          const invoiceId = decodeURIComponent(lineItemsMatch[1] || '');
          const lineItems =
            invoiceId === 'receipt_dash_billing_1'
              ? [
                  {
                    id: 'li_receipt_1',
                    invoiceId,
                    itemType: 'CREDIT_TOP_UP',
                    description: 'Prepaid credit top-up (usd_25)',
                    quantity: 1,
                    unitAmountMinor: 2500,
                    amountMinor: 2500,
                    periodMonthUtc: '2026-03',
                  },
                ]
              : [
                  {
                    id: 'li_stmt_1',
                    invoiceId,
                    itemType: 'MAW_USAGE_DEBIT',
                    description: 'Monthly Active Wallet usage (2026-03)',
                    quantity: 42,
                    unitAmountMinor: 300,
                    amountMinor: 12600,
                    periodMonthUtc: '2026-03',
                  },
                ];
          await fulfillJson(route, { ok: true, lineItems });
          return true;
        }

        const activityMatch = pathname.match(/^\/console\/billing\/invoices\/([^/]+)\/activity$/);
        if (method === 'GET' && activityMatch) {
          const invoiceId = decodeURIComponent(activityMatch[1] || '');
          const invoice = documents.find((entry) => entry.id === invoiceId);
          await fulfillJson(route, {
            ok: true,
            activity: {
              invoice,
              entries: [
                {
                  id: `${invoiceId}:document`,
                  type: 'DOCUMENT',
                  invoiceId,
                  fromState: null,
                  toState: invoice?.status || 'PAID',
                  occurredAt: invoice?.createdAt || iso('2026-03-01T00:00:00.000Z'),
                  actorType: 'SYSTEM',
                  actorUserId: null,
                  reason: invoiceId.startsWith('receipt_')
                    ? 'purchase_receipt_created'
                    : 'usage_statement_created',
                  sourceEventId: null,
                  summary: invoiceId.startsWith('receipt_')
                    ? `Purchase receipt ${invoiceId} recorded for 2026-03.`
                    : `Usage statement ${invoiceId} recorded for 2026-03.`,
                  visibility: 'CUSTOMER',
                },
                {
                  id: `${invoiceId}:ledger`,
                  type: 'LEDGER',
                  invoiceId,
                  fromState: null,
                  toState: invoiceId.startsWith('receipt_') ? 'CREDIT_PURCHASE' : 'USAGE_DEBIT',
                  occurredAt: iso('2026-03-06T00:00:00.000Z'),
                  actorType: 'SYSTEM',
                  actorUserId: null,
                  reason: invoiceId.startsWith('receipt_') ? 'credit_purchase' : 'usage_debit',
                  sourceEventId: invoiceId.startsWith('receipt_')
                    ? 'cs_dash_billing_prepaid'
                    : 'evt_usage_stmt_1',
                  summary: invoiceId.startsWith('receipt_')
                    ? 'Credit pack usd_25 settled'
                    : 'MAW usage debit for March activity',
                  visibility: 'CUSTOMER',
                },
                ...(invoiceId.startsWith('receipt_')
                  ? [
                      {
                        id: `${invoiceId}:manual-adjustment`,
                        type: 'LEDGER',
                        invoiceId,
                        fromState: null,
                        toState: 'MANUAL_ADJUSTMENT',
                        occurredAt: iso('2026-03-07T00:00:00.000Z'),
                        actorType: 'USER',
                        actorUserId: 'owner_dash_billing',
                        reason: 'invoice_correction',
                        sourceEventId: null,
                        summary: 'Manual support credit linked to receipt review',
                        visibility: 'INTERNAL',
                      },
                    ]
                  : []),
              ],
            },
          });
          return true;
        }

        const pdfMatch = pathname.match(/^\/console\/billing\/invoices\/([^/]+)\/pdf$/);
        if (method === 'GET' && pdfMatch) {
          pdfDownloadCount += 1;
          const invoiceId = decodeURIComponent(pdfMatch[1] || '');
          await route.fulfill({
            status: 200,
            contentType: 'application/pdf',
            headers: {
              'Content-Disposition': `attachment; filename="invoice_${invoiceId}.pdf"`,
            },
            body: `%PDF-1.4\nBilling document\nDocument ID: ${invoiceId}\n%%EOF`,
          });
          return true;
        }

        return false;
      },
    });

    await page.goto('/dashboard/invoices');

    const invoicesTable = page.locator('section[aria-label="Billing documents table"]');
    await expect(
      page.locator('section[aria-label="Billing document sponsorship links"]'),
    ).toContainText('Usage statements stay aggregated by billing period');
    await expect(invoicesTable).toContainText('receipt_dash_billing_1');
    await expect(invoicesTable).toContainText('stmt_dash_billing_1');
    expect(invoiceListUrls.length).toBe(1);
    expect(overviewRequestCount).toBe(0);
    expect(usageRequestCount).toBe(0);

    await page.locator('select.dashboard-input').first().selectOption('PURCHASE_RECEIPT');
    await expect(invoicesTable).toContainText('receipt_dash_billing_1');
    await expect(invoicesTable).not.toContainText('stmt_dash_billing_1');
    expect(invoiceListUrls.length).toBe(1);

    await invoicesTable.locator('button:has-text("Download PDF")').click();
    await expect.poll(() => pdfDownloadCount).toBe(1);

    await invoicesTable.locator('button:has-text("View document")').click();
    await expect(page).toHaveURL(/\/dashboard\/invoices\/receipt_dash_billing_1$/);
    await expect(
      page.locator('section[aria-label="Billing document detail header"]'),
    ).toContainText('receipt_dash_billing_1');
    await expect(
      page.locator('section[aria-label="Billing document activity timeline"]'),
    ).toContainText('Credit pack usd_25 settled');
    await expect(
      page.locator('section[aria-label="Billing document activity timeline"]'),
    ).toContainText(
      'Internal manual adjustments are visible in this staff timeline only and are excluded from exported PDFs.',
    );
    await expect(
      page.locator('section[aria-label="Billing document activity timeline"]'),
    ).toContainText('Internal only');
    await expect(page.locator('section[aria-label="Billing document line items"]')).toContainText(
      'Prepaid credit top-up (usd_25)',
    );
    await expect(page.locator('section[aria-label="Payment execution table"]')).toHaveCount(0);
    expect(overviewRequestCount).toBe(0);
    expect(usageRequestCount).toBe(0);

    await page
      .locator('section[aria-label="Billing document detail header"]')
      .locator('button:has-text("Download PDF")')
      .click();
    await expect.poll(() => pdfDownloadCount).toBe(2);

    await page.getByRole('button', { name: 'Back to invoices' }).click();
    await expect(page).toHaveURL(/\/dashboard\/invoices$/);
    await page.locator('select.dashboard-input').first().selectOption('USAGE_STATEMENT');
    await invoicesTable.locator('button:has-text("View document")').click();
    await expect(page).toHaveURL(/\/dashboard\/invoices\/stmt_dash_billing_1$/);
    await expect(
      page.locator('section[aria-label="Billing document sponsorship links"]'),
    ).toContainText('This statement stays aggregated by billing period');
    await page
      .locator(
        'section[aria-label="Billing document sponsorship links"] a:has-text("Sponsored usage history")',
      )
      .click();
    await expect(page).toHaveURL(/\/dashboard\/billing\/account#billing-sponsored-history$/);
    await expect(page.locator('section[aria-label="Sponsored execution history"]')).toContainText(
      'Sponsored usage history',
    );
  });
});
