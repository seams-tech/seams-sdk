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
  expiresAt: string | null;
  revokedReason: string | null;
  endpointUsageCounts: Record<string, number>;
  anomalyFlags: string[];
}

export interface CreateConsoleApiKeyRequest {
  name: string;
  environmentId: string;
  scopes: string[];
  ipAllowlist?: string[];
  expiresAt?: string;
}

export interface RotateConsoleApiKeyRequest {
  reason?: string;
}

export interface RevokeConsoleApiKeyRequest {
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

export type ConsoleApiKeyAuthFailureCode =
  | 'api_key_missing'
  | 'api_key_invalid'
  | 'api_key_revoked'
  | 'api_key_forbidden_scope'
  | 'api_key_ip_blocked'
  | 'api_key_environment_mismatch';

export interface AuthenticateConsoleApiKeyRequest {
  secret: string;
  endpoint: string;
  requiredScopes: string[];
  sourceIp?: string;
  environmentId?: string;
}

export interface AuthenticateConsoleApiKeySuccess {
  ok: true;
  apiKey: ConsoleApiKey;
}

export interface AuthenticateConsoleApiKeyFailure {
  ok: false;
  status: 401 | 403;
  code: ConsoleApiKeyAuthFailureCode;
  message: string;
}

export type AuthenticateConsoleApiKeyResult =
  | AuthenticateConsoleApiKeySuccess
  | AuthenticateConsoleApiKeyFailure;
