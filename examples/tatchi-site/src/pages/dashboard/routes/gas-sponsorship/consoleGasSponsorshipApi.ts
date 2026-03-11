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
}

export type DashboardGasSponsorshipCallMode = 'ALLOW_ALL' | 'ALLOWLIST';
export type DashboardGasSponsorshipSpendCapMode = 'NONE' | 'CHAIN_TOTAL' | 'WALLET_CHAIN_TOTAL';
export type DashboardGasSponsorshipSpendCapPeriod = 'WEEKLY' | 'MONTHLY';

export interface DashboardGasSponsorshipSpendCap {
  mode: DashboardGasSponsorshipSpendCapMode;
  period: DashboardGasSponsorshipSpendCapPeriod;
  capsByChain: Array<{
    chainId: number;
    capMinor: number;
  }>;
}

export interface DashboardGasSponsorshipConfig {
  id: string;
  scopeType: string;
  projectId: string | null;
  environmentId: string | null;
  policyId: string | null;
  policyName: string | null;
  walletSegmentId: string | null;
  name: string;
  templateId: string | null;
  networkClass: string;
  enabled: boolean;
  allowedChainIds: number[];
  callMode: DashboardGasSponsorshipCallMode;
  spendCap: DashboardGasSponsorshipSpendCap;
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
      };
    })
    .filter((entry): entry is DashboardGasSponsorshipAllowedCall => entry !== null);
}

function decodeAllowedChainIds(
  raw: unknown,
  allowedCalls: readonly DashboardGasSponsorshipAllowedCall[],
): number[] {
  const fromField = Array.isArray(raw)
    ? raw
        .map((entry) => Number(entry || 0))
        .filter((entry) => Number.isFinite(entry) && entry > 0)
        .map((entry) => Math.floor(entry))
    : [];
  const fallback = fromField.length > 0 ? fromField : allowedCalls.map((entry) => entry.chainId);
  return Array.from(new Set(fallback));
}

function decodeSpendCap(raw: unknown): DashboardGasSponsorshipSpendCap {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) {
    return {
      mode: 'NONE',
      period: 'MONTHLY',
      capsByChain: [],
    };
  }
  const row = raw as Record<string, unknown>;
  const modeRaw = String(row.mode || '')
    .trim()
    .toUpperCase();
  const periodRaw = String(row.period || '')
    .trim()
    .toUpperCase();
  const capsByChainRaw = Array.isArray(row.capsByChain) ? row.capsByChain : [];
  const mode =
    modeRaw === 'CHAIN_TOTAL' || modeRaw === 'WALLET_CHAIN_TOTAL'
      ? (modeRaw as DashboardGasSponsorshipSpendCapMode)
      : 'NONE';
  return {
    mode,
    period: periodRaw === 'WEEKLY' ? 'WEEKLY' : 'MONTHLY',
    capsByChain: mode === 'NONE' ? [] : Array.from(
      new Map(
        capsByChainRaw
          .map((entry) => {
            if (!entry || typeof entry !== 'object' || Array.isArray(entry)) return null;
            const cap = entry as Record<string, unknown>;
            const chainId = Number(cap.chainId || 0);
            const capMinor = Number(cap.capMinor || 0);
            if (!Number.isFinite(chainId) || chainId <= 0) return null;
            if (!Number.isFinite(capMinor) || capMinor < 0) return null;
            return [Math.floor(chainId), { chainId: Math.floor(chainId), capMinor: Math.floor(capMinor) }] as const;
          })
          .filter(
            (
              entry,
            ): entry is readonly [
              number,
              DashboardGasSponsorshipSpendCap['capsByChain'][number],
            ] => entry !== null,
          ),
      ).values(),
    ),
  };
}

function decodeGasSponsorshipConfig(raw: unknown): DashboardGasSponsorshipConfig | null {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return null;
  const row = raw as Record<string, unknown>;
  const id = String(row.id || '').trim();
  if (!id) return null;
  const allowedCalls = decodeAllowedCalls(row.allowedCalls);
  const callModeRaw = String(row.callMode || '')
    .trim()
    .toUpperCase();
  return {
    id,
    scopeType: String(row.scopeType || '').trim() || 'ENVIRONMENT',
    projectId: row.projectId == null ? null : String(row.projectId || '').trim() || null,
    environmentId: row.environmentId == null ? null : String(row.environmentId || '').trim() || null,
    policyId: row.policyId == null ? null : String(row.policyId || '').trim() || null,
    policyName: row.policyName == null ? null : String(row.policyName || '').trim() || null,
    walletSegmentId: row.walletSegmentId == null ? null : String(row.walletSegmentId || '').trim() || null,
    name: String(row.name || '').trim() || 'Gas Sponsorship Policy',
    templateId: row.templateId == null ? null : String(row.templateId || '').trim() || null,
    networkClass: String(row.networkClass || '').trim() || 'ANY',
    enabled: row.enabled !== false,
    allowedChainIds: decodeAllowedChainIds(row.allowedChainIds, allowedCalls),
    callMode:
      callModeRaw === 'ALLOWLIST' || callModeRaw === 'ALLOW_ALL'
        ? (callModeRaw as DashboardGasSponsorshipCallMode)
        : allowedCalls.length > 0
          ? 'ALLOWLIST'
          : 'ALLOW_ALL',
    spendCap: decodeSpendCap(row.spendCap),
    allowedCalls,
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
