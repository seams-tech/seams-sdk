export const ROUTER_API_CREDENTIAL_SCOPES = [
  'accounts.create',
  'wallets.read',
  'wallets.auth_methods.create',
  'wallets.signers.create',
] as const;

export type RouterApiCredentialScope = (typeof ROUTER_API_CREDENTIAL_SCOPES)[number];

export type RouterApiKeyAuthFailureCode =
  | 'secret_key_missing'
  | 'secret_key_invalid'
  | 'secret_key_revoked'
  | 'secret_key_forbidden_scope'
  | 'secret_key_ip_blocked'
  | 'secret_key_environment_mismatch';

export interface RouterApiKeyAuthRequest {
  secret: string;
  endpoint: string;
  requiredScopes: RouterApiCredentialScope[];
  sourceIp?: string;
  environmentId?: string;
}

export interface RouterApiKeyPrincipal {
  apiKeyId: string;
  orgId: string;
  projectId?: string;
  envId?: string;
  environmentId: string;
  scopes: RouterApiCredentialScope[];
}

export type RouterApiKeyAuthResult =
  | { ok: true; principal: RouterApiKeyPrincipal }
  | {
      ok: false;
      status: 401 | 403;
      code: RouterApiKeyAuthFailureCode;
      message: string;
    };

export interface RouterApiKeyAuthAdapter {
  authenticate(input: RouterApiKeyAuthRequest): Promise<RouterApiKeyAuthResult>;
}

export type RouterApiPublishableKeyAuthFailureCode =
  | 'publishable_key_missing'
  | 'publishable_key_invalid'
  | 'publishable_key_revoked'
  | 'publishable_key_origin_blocked'
  | 'publishable_key_environment_mismatch';

export interface RouterApiPublishableKeyAuthRequest {
  secret: string;
  origin: string;
  environmentId: string;
}

export type RouterApiPublishableKeyAuthResult =
  | { ok: true; principal: RouterApiKeyPrincipal }
  | {
      ok: false;
      status: 401 | 403;
      code: RouterApiPublishableKeyAuthFailureCode;
      message: string;
    };

export interface RouterApiPublishableKeyAuthAdapter {
  authenticate(input: RouterApiPublishableKeyAuthRequest): Promise<RouterApiPublishableKeyAuthResult>;
}

export type RouterApiUsageMeterAction = 'wallet_created';

export interface RouterApiUsageMeterEvent {
  orgId: string;
  environmentId: string;
  apiKeyId: string;
  endpoint: string;
  walletId: string;
  action: RouterApiUsageMeterAction;
  succeeded: boolean;
  occurredAt?: string;
  sourceEventId?: string;
}

export interface RouterApiUsageMeterAdapter {
  recordEvent(input: RouterApiUsageMeterEvent): Promise<void>;
}

export interface RouterApiBootstrapTokenRecord {
  id: string;
  tokenHash: string;
  tokenPrefix: string;
  publishableKeyId: string;
  orgId: string;
  projectId: string;
  environmentId: string;
  newAccountId: string;
  rpId: string;
  origin: string;
  method: string;
  path: string;
  allowedPaths: string[];
  requestHashSha256: string | null;
  maxUses: number;
  usedCount: number;
  status: 'issued' | 'redeemed' | 'expired' | 'canceled';
  riskDecision: string;
  paymentReference: string | null;
  replacementForTokenId: string | null;
  issuedAt: string;
  expiresAt: string;
  redeemedAt: string | null;
  createdAt: string;
  updatedAt: string;
}

export type RouterApiBootstrapTokenRedeemFailureCode =
  | 'bootstrap_token_missing'
  | 'bootstrap_token_invalid'
  | 'bootstrap_token_expired'
  | 'bootstrap_token_already_used'
  | 'bootstrap_token_request_mismatch'
  | 'bootstrap_token_origin_mismatch';

export interface RouterApiBootstrapTokenRedeemRequest {
  token: string;
  origin: string;
  method: string;
  path: string;
  requestHashSha256?: string;
}

export type RouterApiBootstrapTokenRedeemResult =
  | {
      ok: true;
      record: RouterApiBootstrapTokenRecord;
    }
  | {
      ok: false;
      status: 401 | 403 | 409;
      code: RouterApiBootstrapTokenRedeemFailureCode;
      message: string;
    };

export interface RouterApiBootstrapTokenVerifier {
  isBootstrapToken(token: string): boolean;
  peekTokenRecord(token: string): Promise<RouterApiBootstrapTokenRecord | null>;
  redeemToken(request: RouterApiBootstrapTokenRedeemRequest): Promise<RouterApiBootstrapTokenRedeemResult>;
}

export interface RouterApiAuthenticatedPublishableCredential {
  kind: 'publishable_key';
  apiKeyId: string;
  orgId: string;
  environmentId: string;
  rateLimitBucket?: string | null;
  quotaBucket?: string | null;
}

export type RouterApiBootstrapGrantPublishableKeyAuthResult =
  | { ok: true; credential: RouterApiAuthenticatedPublishableCredential }
  | {
      ok: false;
      status: 401 | 403;
      code: RouterApiPublishableKeyAuthFailureCode;
      message: string;
    };

export interface RouterApiProjectEnvironment {
  id: string;
  projectId: string;
  key: string;
  signingRootVersion: string;
  status?: string;
}

export interface RouterApiProjectEnvironmentResolver {
  listEnvironments(
    context: {
      orgId: string;
      actorUserId: string;
      roles: string[];
      environmentId?: string;
      projectId?: string;
    },
    filters?: { status?: string },
  ): Promise<RouterApiProjectEnvironment[]>;
}
