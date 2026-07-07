import type { ApiCredentialScope } from "../../../../console-shared-ts/src/apiKeyScopes";

export type ConsoleApiKeyStatus = 'ACTIVE' | 'REVOKED';
export type ConsoleCredentialKind = 'secret_key' | 'publishable_key';

export type ConsoleBrokerPolicyObject = Record<string, unknown>;

export interface ConsoleApiKey {
  id: string;
  kind: ConsoleCredentialKind;
  orgId: string;
  name: string;
  environmentId: string;
  scopes?: ApiCredentialScope[];
  ipAllowlist?: string[];
  allowedOrigins?: string[];
  rateLimitBucket?: string | null;
  quotaBucket?: string | null;
  riskPolicy?: ConsoleBrokerPolicyObject;
  paymentPolicy?: ConsoleBrokerPolicyObject;
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

export interface CreateConsoleSecretKeyRequest {
  kind: 'secret_key';
  name: string;
  environmentId: string;
  scopes: ApiCredentialScope[];
  ipAllowlist?: string[];
  expiresAt?: string;
}

export interface CreateConsolePublishableKeyRequest {
  kind: 'publishable_key';
  name: string;
  environmentId: string;
  allowedOrigins: string[];
  rateLimitBucket: string;
  quotaBucket: string;
  riskPolicy?: ConsoleBrokerPolicyObject;
  paymentPolicy?: ConsoleBrokerPolicyObject;
  expiresAt?: string;
}

export type CreateConsoleApiKeyRequest =
  | CreateConsoleSecretKeyRequest
  | CreateConsolePublishableKeyRequest;

export interface RotateConsoleApiKeyRequest {
  reason?: string;
}

export interface UpdateConsoleApiKeyRequest {
  name?: string;
  scopes?: ApiCredentialScope[];
  ipAllowlist?: string[];
  allowedOrigins?: string[];
  rateLimitBucket?: string;
  quotaBucket?: string;
  riskPolicy?: ConsoleBrokerPolicyObject;
  paymentPolicy?: ConsoleBrokerPolicyObject;
  expiresAt?: string | null;
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
  | 'secret_key_missing'
  | 'secret_key_invalid'
  | 'secret_key_revoked'
  | 'secret_key_forbidden_scope'
  | 'secret_key_ip_blocked'
  | 'secret_key_environment_mismatch';

export type ConsolePublishableKeyAuthFailureCode =
  | 'publishable_key_missing'
  | 'publishable_key_invalid'
  | 'publishable_key_revoked'
  | 'publishable_key_origin_blocked'
  | 'publishable_key_environment_mismatch';

export interface AuthenticateConsoleApiKeyRequest {
  secret: string;
  endpoint: string;
  requiredScopes: ApiCredentialScope[];
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

export interface AuthenticateConsolePublishableKeyRequest {
  secret: string;
  origin: string;
  environmentId?: string;
}

export interface AuthenticateConsolePublishableKeySuccess {
  ok: true;
  apiKey: ConsoleApiKey;
}

export interface AuthenticateConsolePublishableKeyFailure {
  ok: false;
  status: 401 | 403;
  code: ConsolePublishableKeyAuthFailureCode;
  message: string;
}

export type AuthenticateConsolePublishableKeyResult =
  | AuthenticateConsolePublishableKeySuccess
  | AuthenticateConsolePublishableKeyFailure;

export function isConsoleSecretKey(input: ConsoleApiKey | null | undefined): boolean {
  return Boolean(input && input.kind === 'secret_key');
}

export function isConsolePublishableKey(input: ConsoleApiKey | null | undefined): boolean {
  return Boolean(input && input.kind === 'publishable_key');
}
