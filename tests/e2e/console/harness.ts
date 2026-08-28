import {
  request as playwrightRequest,
  test as base,
  type APIRequestContext,
  type APIResponse,
  type Locator,
  type Page,
  type Request,
  type Response,
  type TestInfo,
} from '@playwright/test';

const DEFAULT_CONSOLE_ORIGIN = 'https://localhost:4101';
const CONSOLE_ORGANIZATION_ID_PATTERN = /^org_[a-z0-9]{12}$/;

export type ConsoleTenantIdentity = {
  readonly orgId: string;
  readonly userId: string;
  readonly projectId: string;
  readonly environmentId: string;
  readonly organizationName: string;
  readonly projectName: string;
  readonly headers: Readonly<Record<string, string>>;
};

export type ConsoleOrganization = {
  readonly id: string;
  readonly name: string;
  readonly slug: string;
  readonly status: string;
};

export type ConsoleProject = {
  readonly id: string;
  readonly name: string;
  readonly status: string;
};

export type ConsoleEnvironment = {
  readonly id: string;
  readonly projectId: string;
  readonly key: string;
  readonly name: string;
  readonly status: string;
};

export type ConsoleApiKey = {
  readonly id: string;
  readonly name: string;
  readonly kind: 'secret_key' | 'publishable_key';
  readonly environmentId: string;
  readonly status: string;
  readonly secretPreview: string;
};

export type ConsoleTenantResources = {
  readonly organization: ConsoleOrganization;
  readonly project: ConsoleProject;
  readonly environment: ConsoleEnvironment;
  readonly apiKeys: readonly ConsoleApiKey[];
};

export type ConsoleOperatingHarness = {
  readonly page: Page;
  readonly api: APIRequestContext;
  readonly tenant: ConsoleTenantIdentity;
  readonly diagnostics: ConsoleDiagnostics;
  readonly provisionCompletedTenant: () => Promise<ConsoleTenantResources>;
  readonly readTenantResources: () => Promise<ConsoleTenantResources>;
};

export type ConsoleDestination = {
  readonly name: string;
  readonly pathname: string;
};

export type ConsoleFixtures = {
  readonly console: ConsoleOperatingHarness;
};

function isRecord(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === 'object' && !Array.isArray(value);
}

function readRequiredString(value: unknown, label: string): string {
  const result = String(value ?? '').trim();
  if (!result) throw new Error(`Console response omitted ${label}`);
  return result;
}

function readResponseBody(raw: string): unknown {
  try {
    return JSON.parse(raw) as unknown;
  } catch {
    return null;
  }
}

async function readSuccessfulJson(
  response: APIResponse,
  label: string,
): Promise<Record<string, unknown>> {
  const raw = await response.text();
  const body = readResponseBody(raw);
  if (!response.ok()) {
    const message = isRecord(body) ? String(body.message ?? '').trim() : '';
    throw new Error(
      `${label} failed with HTTP ${response.status()}${message ? `: ${message}` : ''}`,
    );
  }
  if (!isRecord(body) || body.ok !== true) {
    throw new Error(`${label} returned an invalid success response`);
  }
  return body;
}

function readResponseRecord(
  body: Record<string, unknown>,
  field: string,
  label: string,
): Record<string, unknown> {
  const value = body[field];
  if (!isRecord(value)) throw new Error(`${label} response omitted ${field}`);
  return value;
}

function parseOrganization(value: unknown, label: string): ConsoleOrganization {
  if (!isRecord(value)) throw new Error(`${label} did not return an organization`);
  return {
    id: readRequiredString(value.id, `${label}.id`),
    name: readRequiredString(value.name, `${label}.name`),
    slug: readRequiredString(value.slug, `${label}.slug`),
    status: readRequiredString(value.status, `${label}.status`),
  };
}

function parseProject(value: unknown, label: string): ConsoleProject {
  if (!isRecord(value)) throw new Error(`${label} did not return a project`);
  return {
    id: readRequiredString(value.id, `${label}.id`),
    name: readRequiredString(value.name, `${label}.name`),
    status: readRequiredString(value.status, `${label}.status`),
  };
}

function parseEnvironment(value: unknown, label: string): ConsoleEnvironment {
  if (!isRecord(value)) throw new Error(`${label} did not return an environment`);
  return {
    id: readRequiredString(value.id, `${label}.id`),
    projectId: readRequiredString(value.projectId, `${label}.projectId`),
    key: readRequiredString(value.key, `${label}.key`),
    name: readRequiredString(value.name, `${label}.name`),
    status: readRequiredString(value.status, `${label}.status`),
  };
}

function parseApiKey(value: unknown, label: string): ConsoleApiKey {
  if (!isRecord(value)) throw new Error(`${label} did not return an API key`);
  const kind = readRequiredString(value.kind, `${label}.kind`);
  if (kind !== 'secret_key' && kind !== 'publishable_key') {
    throw new Error(`${label}.kind was invalid`);
  }
  return {
    id: readRequiredString(value.id, `${label}.id`),
    name: readRequiredString(value.name, `${label}.name`),
    kind,
    environmentId: readRequiredString(value.environmentId, `${label}.environmentId`),
    status: readRequiredString(value.status, `${label}.status`),
    secretPreview: readRequiredString(value.secretPreview, `${label}.secretPreview`),
  };
}

function parseRecordArray(body: Record<string, unknown>, field: string, label: string): unknown[] {
  const value = body[field];
  if (!Array.isArray(value)) throw new Error(`${label} response omitted ${field}`);
  return value;
}

function fnv1aBase36(value: string): string {
  let hash = 2166136261;
  for (let index = 0; index < value.length; index += 1) {
    hash ^= value.charCodeAt(index);
    hash = Math.imul(hash, 16777619);
  }
  return (hash >>> 0).toString(36).padStart(8, '0').slice(-8);
}

function normalizeTenantLabel(value: string): string {
  return (
    value
      .replace(/[^a-z0-9]+/gi, ' ')
      .trim()
      .replace(/\s+/g, ' ')
      .slice(0, 32) || 'Console tenant'
  );
}

function createTenantIdentity(testInfo: TestInfo): ConsoleTenantIdentity {
  const runId = String(process.env.SEAMS_CONSOLE_TEST_RUN_ID || 'default').trim();
  const seed = `${runId} / ${testInfo.titlePath.join(' / ')}`;
  const suffix = fnv1aBase36(seed);
  const label = normalizeTenantLabel(testInfo.titlePath.at(-1) || 'Console tenant');
  const projectId = `proj_r117_${suffix}`;
  const orgId = `org_r117${suffix}`;
  if (!CONSOLE_ORGANIZATION_ID_PATTERN.test(orgId)) {
    throw new Error(`Generated Console organization ID was invalid: ${orgId}`);
  }
  return {
    orgId,
    userId: `refactor-117-${suffix}-owner`,
    projectId,
    environmentId: `${projectId}:dev`,
    organizationName: `Refactor 117 ${label} Organization`,
    projectName: `Refactor 117 ${label} Project`,
    headers: {
      'X-Console-User-Id': `refactor-117-${suffix}-owner`,
      'X-Console-Org-Id': orgId,
      'X-Console-Project-Id': projectId,
      'X-Console-Environment-Id': `${projectId}:dev`,
    },
  };
}

function resolveOrigin(value: string | undefined, fallback: string): string {
  const normalized = String(value || '').trim();
  return normalized || fallback;
}

function resolveConsoleApiOrigin(): string {
  return resolveOrigin(
    process.env.SEAMS_CONSOLE_API_URL ||
      process.env.SEAMS_INTENDED_ROUTER_URL ||
      process.env.VITE_CONSOLE_BASE_URL,
    DEFAULT_CONSOLE_ORIGIN,
  );
}

function escapeRegExp(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function collectDestinations(elements: HTMLElement[]): ConsoleDestination[] {
  const destinations: ConsoleDestination[] = [];
  const seen = new Set<string>();
  for (const element of elements) {
    if (element.getAttribute('aria-disabled') === 'true' || element.tabIndex === -1) continue;
    const href = element.getAttribute('href');
    if (!href) continue;
    const url = new URL(href, document.baseURI);
    if (!url.pathname.startsWith('/dashboard/') && !url.pathname.startsWith('/platform/')) {
      continue;
    }
    const name = String(element.textContent || '')
      .replace(/\s+/g, ' ')
      .trim();
    if (!name) continue;
    const destination = { name, pathname: url.pathname };
    const key = `${destination.name}:${destination.pathname}`;
    if (seen.has(key)) continue;
    seen.add(key);
    destinations.push(destination);
  }
  return destinations;
}

export async function readEnabledConsoleDestinations(
  navigation: Locator,
): Promise<readonly ConsoleDestination[]> {
  return await navigation.getByRole('link').evaluateAll(collectDestinations);
}

export function consoleDestinationUrlPattern(pathname: string): RegExp {
  return new RegExp(`${escapeRegExp(pathname)}/?$`);
}

export class ConsoleDiagnostics {
  private readonly entries: string[] = [];

  constructor(private readonly page: Page) {}

  attach(): void {
    this.page.on('pageerror', this.handlePageError);
    this.page.on('requestfailed', this.handleRequestFailed);
    this.page.on('response', this.handleResponse);
  }

  detach(): void {
    this.page.off('pageerror', this.handlePageError);
    this.page.off('requestfailed', this.handleRequestFailed);
    this.page.off('response', this.handleResponse);
  }

  hasEntries(): boolean {
    return this.entries.length > 0;
  }

  toString(): string {
    return this.entries.join('\n');
  }

  private handlePageError = (error: Error): void => {
    this.entries.push(`[pageerror] ${error.message}`);
  };

  private handleRequestFailed = (request: Request): void => {
    const failure = request.failure();
    this.entries.push(
      `[requestfailed] ${request.method()} ${request.url()}${failure?.errorText ? `: ${failure.errorText}` : ''}`,
    );
  };

  private handleResponse = (response: Response): void => {
    const status = response.status();
    if (status < 500) return;
    let pathname = '';
    try {
      pathname = new URL(response.url()).pathname;
    } catch {
      return;
    }
    if (!pathname.startsWith('/console/')) return;
    this.entries.push(`[console-${status}] ${response.url()}`);
  };
}

async function provisionOrganization(
  api: APIRequestContext,
  tenant: ConsoleTenantIdentity,
): Promise<ConsoleOrganization> {
  const response = await api.post('/console/onboarding/organization', {
    data: {
      org: {
        name: tenant.organizationName,
        slug: tenant.organizationName.toLowerCase().replace(/[^a-z0-9]+/g, '-'),
      },
    },
  });
  const body = await readSuccessfulJson(response, 'Console organization onboarding');
  const result = readResponseRecord(body, 'result', 'Console organization onboarding');
  return parseOrganization(result.organization, 'Console organization onboarding');
}

async function provisionProject(
  api: APIRequestContext,
  tenant: ConsoleTenantIdentity,
): Promise<{ readonly project: ConsoleProject; readonly environment: ConsoleEnvironment }> {
  const response = await api.post('/console/onboarding/project', {
    data: {
      project: { id: tenant.projectId, name: tenant.projectName },
      environment: { id: tenant.environmentId, name: 'Development' },
    },
  });
  const body = await readSuccessfulJson(response, 'Console project onboarding');
  const result = readResponseRecord(body, 'result', 'Console project onboarding');
  return {
    project: parseProject(result.project, 'Console project onboarding'),
    environment: parseEnvironment(result.environment, 'Console project onboarding'),
  };
}

async function readTenantResourcesFromApi(
  api: APIRequestContext,
  tenant: ConsoleTenantIdentity,
): Promise<ConsoleTenantResources> {
  const organizationResponse = await api.get('/console/org');
  const organizationBody = await readSuccessfulJson(
    organizationResponse,
    'Console organization read',
  );
  const organization = parseOrganization(organizationBody.org, 'Console organization read');

  const projectsResponse = await api.get('/console/projects?status=ACTIVE');
  const projectsBody = await readSuccessfulJson(projectsResponse, 'Console project read');
  const projectRows = parseRecordArray(projectsBody, 'projects', 'Console project read');
  const project = projectRows
    .map((row) => parseProject(row, 'Console project read'))
    .find((row) => row.name === tenant.projectName);
  if (!project) throw new Error(`Console project ${tenant.projectName} was not found`);

  const environmentsResponse = await api.get(
    `/console/environments?projectId=${encodeURIComponent(project.id)}&status=ACTIVE`,
  );
  const environmentsBody = await readSuccessfulJson(
    environmentsResponse,
    'Console environment read',
  );
  const environmentRows = parseRecordArray(
    environmentsBody,
    'environments',
    'Console environment read',
  );
  const environment = environmentRows
    .map((row) => parseEnvironment(row, 'Console environment read'))
    .find((row) => row.projectId === project.id && row.key === 'dev');
  if (!environment) throw new Error(`Development environment for ${project.id} was not found`);

  const apiKeysResponse = await api.get('/console/api-keys');
  const apiKeysBody = await readSuccessfulJson(apiKeysResponse, 'Console API key read');
  const apiKeys = parseRecordArray(apiKeysBody, 'apiKeys', 'Console API key read').map((row) =>
    parseApiKey(row, 'Console API key read'),
  );
  return { organization, project, environment, apiKeys };
}

export const test = base.extend<ConsoleFixtures>({
  console: async ({ page }, use, testInfo) => {
    const tenant = createTenantIdentity(testInfo);
    await page.context().setExtraHTTPHeaders(tenant.headers);
    const api = await playwrightRequest.newContext({
      baseURL: resolveConsoleApiOrigin(),
      extraHTTPHeaders: tenant.headers,
      ignoreHTTPSErrors: true,
    });
    const diagnostics = new ConsoleDiagnostics(page);
    diagnostics.attach();
    const harness: ConsoleOperatingHarness = {
      page,
      api,
      tenant,
      diagnostics,
      provisionCompletedTenant: async () => {
        const organization = await provisionOrganization(api, tenant);
        const { project, environment } = await provisionProject(api, tenant);
        if (organization.id !== tenant.orgId) {
          throw new Error(
            `Provisioned organization ID ${organization.id} did not match ${tenant.orgId}`,
          );
        }
        if (project.id !== tenant.projectId) {
          throw new Error(`Provisioned project ID ${project.id} did not match ${tenant.projectId}`);
        }
        if (environment.id !== tenant.environmentId) {
          throw new Error(
            `Provisioned environment ID ${environment.id} did not match ${tenant.environmentId}`,
          );
        }
        return { organization, project, environment, apiKeys: [] };
      },
      readTenantResources: async () => await readTenantResourcesFromApi(api, tenant),
    };

    let diagnosticError: Error | undefined;
    try {
      await use(harness);
    } finally {
      diagnostics.detach();
      if (diagnostics.hasEntries() && testInfo.status === testInfo.expectedStatus) {
        await testInfo.attach('console-diagnostics', {
          body: diagnostics.toString(),
          contentType: 'text/plain',
        });
        diagnosticError = new Error(`Console browser diagnostics were collected:\n${diagnostics}`);
      }
      await api.dispose();
    }
    if (diagnosticError) throw diagnosticError;
  },
});

export { expect } from '@playwright/test';
