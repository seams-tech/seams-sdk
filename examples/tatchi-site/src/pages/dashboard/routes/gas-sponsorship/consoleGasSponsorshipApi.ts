import {
  buildConsoleAcceptHeaders,
  buildConsoleJsonHeaders,
  consoleErrorMessage,
  parseConsoleJson,
  requireConsoleBaseUrl,
} from '../../consoleHttp';

export interface DashboardGasSponsorshipAllowedCall {
  chainId: number;
  to: string;
  selector: string;
  maxGasLimit: string;
  maxValueWei: string;
}

export interface DashboardGasSponsorshipConfig {
  id: string;
  scopeType: string;
  projectId: string | null;
  environmentId: string | null;
  policyId: string | null;
  walletSegmentId: string | null;
  policyName: string;
  templateId: string | null;
  networkClass: string;
  executor: string;
  enabled: boolean;
  paymasterMode: string;
  fallbackBehavior: string;
  chainBudgets: Array<{
    chain: string;
    period: string;
    budgetMinor: number;
    quotaTransactions: number;
  }>;
  allowedCalls: DashboardGasSponsorshipAllowedCall[];
  updatedAt: string;
}

interface ConsoleConfigListResponse {
  ok?: boolean;
  message?: string;
  configs?: unknown;
}

interface ConsoleConfigMutationResponse {
  ok?: boolean;
  message?: string;
  config?: unknown;
}

function decodeAllowedCalls(raw: unknown): DashboardGasSponsorshipAllowedCall[] {
  if (!Array.isArray(raw)) return [];
  return raw
    .map((entry) => {
      if (!entry || typeof entry !== 'object' || Array.isArray(entry)) return null;
      const row = entry as Record<string, unknown>;
      const to = String(row.to || '').trim();
      const selector = String(row.selector || '').trim();
      const chainId = Number(row.chainId || 0);
      if (!to || !selector || !Number.isFinite(chainId) || chainId <= 0) return null;
      return {
        chainId,
        to,
        selector,
        maxGasLimit: String(row.maxGasLimit || '0').trim() || '0',
        maxValueWei: String(row.maxValueWei || '0').trim() || '0',
      };
    })
    .filter((entry): entry is DashboardGasSponsorshipAllowedCall => entry !== null);
}

function decodeGasSponsorshipConfig(raw: unknown): DashboardGasSponsorshipConfig | null {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return null;
  const row = raw as Record<string, unknown>;
  const id = String(row.id || '').trim();
  if (!id) return null;
  const chainBudgetsRaw = Array.isArray(row.chainBudgets) ? row.chainBudgets : [];
  return {
    id,
    scopeType: String(row.scopeType || '').trim() || 'ENVIRONMENT',
    projectId: row.projectId == null ? null : String(row.projectId || '').trim() || null,
    environmentId: row.environmentId == null ? null : String(row.environmentId || '').trim() || null,
    policyId: row.policyId == null ? null : String(row.policyId || '').trim() || null,
    walletSegmentId: row.walletSegmentId == null ? null : String(row.walletSegmentId || '').trim() || null,
    policyName: String(row.policyName || '').trim() || 'Gas Sponsorship Policy',
    templateId: row.templateId == null ? null : String(row.templateId || '').trim() || null,
    networkClass: String(row.networkClass || '').trim() || 'ANY',
    executor: String(row.executor || '').trim() || 'RELAY_EOA',
    enabled: row.enabled !== false,
    paymasterMode: String(row.paymasterMode || '').trim() || 'AUTO',
    fallbackBehavior: String(row.fallbackBehavior || '').trim() || 'ALLOW_UNSPONSORED',
    chainBudgets: chainBudgetsRaw
      .map((entry) => {
        if (!entry || typeof entry !== 'object' || Array.isArray(entry)) return null;
        const budget = entry as Record<string, unknown>;
        const chain = String(budget.chain || '').trim();
        if (!chain) return null;
        return {
          chain,
          period: String(budget.period || '').trim() || 'MONTHLY',
          budgetMinor: Number(budget.budgetMinor || 0),
          quotaTransactions: Number(budget.quotaTransactions || 0),
        };
      })
      .filter(
        (entry): entry is DashboardGasSponsorshipConfig['chainBudgets'][number] => entry !== null,
      ),
    allowedCalls: decodeAllowedCalls(row.allowedCalls),
    updatedAt: String(row.updatedAt || '').trim(),
  };
}

export async function listDashboardGasSponsorship(input: {
  environmentId?: string;
  projectId?: string;
} = {}): Promise<DashboardGasSponsorshipConfig[]> {
  const base = requireConsoleBaseUrl();
  const params = new URLSearchParams();
  if (input.environmentId) params.set('environmentId', input.environmentId);
  if (input.projectId) params.set('projectId', input.projectId);
  const suffix = params.toString();
  const response = await fetch(`${base}/console/gas-sponsorship${suffix ? `?${suffix}` : ''}`, {
    method: 'GET',
    headers: buildConsoleAcceptHeaders(),
    credentials: 'include',
    cache: 'no-store',
  });
  const body = (await parseConsoleJson(response)) as ConsoleConfigListResponse | null;
  if (!response.ok || body?.ok !== true) {
    throw new Error(consoleErrorMessage(response, body, 'Gas sponsorship request failed'));
  }
  const rows = Array.isArray(body?.configs) ? body.configs : [];
  return rows
    .map((entry) => decodeGasSponsorshipConfig(entry))
    .filter((entry): entry is DashboardGasSponsorshipConfig => entry !== null);
}

export async function createDashboardGasSponsorship(
  input: Record<string, unknown>,
): Promise<DashboardGasSponsorshipConfig> {
  const base = requireConsoleBaseUrl();
  const response = await fetch(`${base}/console/gas-sponsorship`, {
    method: 'POST',
    headers: buildConsoleJsonHeaders(),
    credentials: 'include',
    cache: 'no-store',
    body: JSON.stringify(input),
  });
  const body = (await parseConsoleJson(response)) as ConsoleConfigMutationResponse | null;
  if (!response.ok || body?.ok !== true) {
    throw new Error(consoleErrorMessage(response, body, 'Create gas sponsorship request failed'));
  }
  const config = decodeGasSponsorshipConfig(body?.config);
  if (!config) throw new Error('Create gas sponsorship response was invalid');
  return config;
}

export async function updateDashboardGasSponsorship(
  configId: string,
  input: Record<string, unknown>,
): Promise<DashboardGasSponsorshipConfig> {
  const id = String(configId || '').trim();
  if (!id) throw new Error('Gas sponsorship config id is required');
  const base = requireConsoleBaseUrl();
  const response = await fetch(`${base}/console/gas-sponsorship/${encodeURIComponent(id)}`, {
    method: 'PATCH',
    headers: buildConsoleJsonHeaders(),
    credentials: 'include',
    cache: 'no-store',
    body: JSON.stringify(input),
  });
  const body = (await parseConsoleJson(response)) as ConsoleConfigMutationResponse | null;
  if (!response.ok || body?.ok !== true) {
    throw new Error(consoleErrorMessage(response, body, 'Update gas sponsorship request failed'));
  }
  const config = decodeGasSponsorshipConfig(body?.config);
  if (!config) throw new Error('Update gas sponsorship response was invalid');
  return config;
}
