export type ConsoleApiKeyStatus = 'ACTIVE' | 'REVOKED';

export interface ConsoleApiKey {
  id: string;
  orgId: string;
  name: string;
  environmentId: string;
  scopes: string[];
  ipAllowlist: string[];
  status: ConsoleApiKeyStatus;
  secretVersion: number;
  secretPreview: string;
  createdAt: string;
  updatedAt: string;
  lastUsedAt: string | null;
  endpointUsageCounts: Record<string, number>;
  anomalyFlags: string[];
}

export interface CreateConsoleApiKeyRequest {
  name: string;
  environmentId: string;
  scopes: string[];
  ipAllowlist?: string[];
}

export interface RotateConsoleApiKeyRequest {
  reason?: string;
}

export interface CreateConsoleApiKeyResult {
  apiKey: ConsoleApiKey;
  secret: string;
}

export interface RotateConsoleApiKeyResult {
  apiKey: ConsoleApiKey;
  secret: string;
}
