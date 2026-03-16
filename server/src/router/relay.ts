import type { DelegateActionPolicy } from '../delegateAction';
import type { RouterLogger } from './logger';
import type { ThresholdAnySchemeModule } from '../core/ThresholdService/schemes/types';
import type { ThresholdSchemeId } from '../core/ThresholdService/schemes/schemeIds';
import type { RelayRouterRorOptions } from './ror/provider';
import type { PrfSessionSealRoutesOptions } from '../threshold/session/prfSessionSeal/types';
import type { ConsoleBootstrapTokenService } from '../console/bootstrapTokens';
import type { ConsoleWebhookService } from '../console/webhooks';
import type { ConsoleApiKeyService } from '../console/apiKeys';
import type { ConsoleBillingService } from '../console/billing';
import type { ConsoleRuntimeSnapshotService } from '../console/runtimeSnapshots';
import type { ConsoleSponsoredCallService } from '../console/sponsoredCalls';
import type { ConsoleWalletService } from '../console/wallets';
import type { SponsoredEvmCallExecutorConfig } from '../sponsorship/evmRelay';
import { normalizeJwtCookieSessionKind } from '@shared/utils/normalize';
import type { ApiCredentialScope } from '../../../shared/src/console/apiKeyScopes';

// Minimal session adapter interface expected by the routers.
export type SessionClaims = Record<string, unknown>;

export type SessionKind = 'cookie' | 'jwt';
export const DEFAULT_SESSION_COOKIE_NAME = 'tatchi-jwt';

/**
 * Best-effort extraction of JWT `exp` claim as ISO timestamp.
 * Returns `undefined` for opaque/non-JWT tokens or invalid payloads.
 */
export function deriveJwtExpiresAtIso(jwt: string): string | undefined {
  const token = String(jwt || '').trim();
  if (!token) return undefined;
  const parts = token.split('.');
  if (parts.length < 2 || !parts[1]) return undefined;
  const payloadJson = decodeJwtPayloadUtf8(parts[1]);
  if (!payloadJson) return undefined;
  let payload: unknown;
  try {
    payload = JSON.parse(payloadJson);
  } catch {
    return undefined;
  }
  if (!payload || typeof payload !== 'object' || Array.isArray(payload)) return undefined;
  const exp = Number((payload as { exp?: unknown }).exp);
  if (!Number.isFinite(exp) || exp <= 0) return undefined;
  return new Date(exp * 1000).toISOString();
}

function decodeJwtPayloadUtf8(payloadB64u: string): string | undefined {
  const normalized = payloadB64u.replace(/-/g, '+').replace(/_/g, '/');
  const padLength = (4 - (normalized.length % 4)) % 4;
  const padded = `${normalized}${'='.repeat(padLength)}`;
  try {
    const atobFn = (globalThis as { atob?: (input: string) => string }).atob;
    const bin =
      typeof atobFn === 'function'
        ? atobFn(padded)
        : typeof Buffer !== 'undefined'
          ? Buffer.from(padded, 'base64').toString('binary')
          : '';
    if (!bin) return undefined;
    const bytes = Uint8Array.from(bin, (char) => char.charCodeAt(0));
    return new TextDecoder().decode(bytes);
  } catch {
    return undefined;
  }
}

export function parseSessionKind(body: unknown): SessionKind {
  const v =
    body && typeof body === 'object' && !Array.isArray(body)
      ? (body as Record<string, unknown>)
      : {};
  const raw = v.sessionKind ?? v.session_kind;
  return normalizeJwtCookieSessionKind(raw);
}

export interface SessionAdapter {
  signJwt(sub: string, extra?: Record<string, unknown>): Promise<string>;
  parse(
    headers: Record<string, string | string[] | undefined>,
  ): Promise<{ ok: true; claims: SessionClaims } | { ok: false }>;
  buildSetCookie(token: string): string;
  buildClearCookie(): string;
  refresh(
    headers: Record<string, string | string[] | undefined>,
  ): Promise<{ ok: boolean; jwt?: string; code?: string; message?: string }>;
}

export interface ThresholdSigningAdapter {
  getSchemeModule(schemeId: ThresholdSchemeId): ThresholdAnySchemeModule | null;
}

export interface RelayRuntimeSnapshotScope {
  orgId: string;
  environmentId: string;
  projectId?: string;
}

export interface RelayRuntimeSnapshotEnvelope {
  snapshotId: string;
  version: number;
  checksum: string;
  effectiveAt: string;
}

export interface RelayRuntimeSnapshotConsumer {
  getLatestSnapshot(
    scope: RelayRuntimeSnapshotScope,
  ): Promise<RelayRuntimeSnapshotEnvelope | null> | RelayRuntimeSnapshotEnvelope | null;
}

export interface RelayWebhookOptions {
  /**
   * Console webhook service used for relay lifecycle webhook delivery.
   */
  service: ConsoleWebhookService;
  /**
   * Optional actor metadata attached to emitted events.
   */
  actorUserId?: string;
  roles?: string[];
  /**
   * Optional fallback orgId when claims do not include a scoped org identifier.
   */
  orgId?: string;
  /**
   * Claim keys checked in order when deriving orgId from session claims.
   */
  orgIdClaimKeys?: string[];
}

export type RelayApiKeyAuthFailureCode =
  | 'secret_key_missing'
  | 'secret_key_invalid'
  | 'secret_key_revoked'
  | 'secret_key_forbidden_scope'
  | 'secret_key_ip_blocked'
  | 'secret_key_environment_mismatch';

export interface RelayApiKeyAuthRequest {
  secret: string;
  endpoint: string;
  requiredScopes: ApiCredentialScope[];
  sourceIp?: string;
  environmentId?: string;
}

export interface RelayApiKeyPrincipal {
  apiKeyId: string;
  orgId: string;
  environmentId: string;
  scopes: ApiCredentialScope[];
}

export type RelayApiKeyAuthResult =
  | { ok: true; principal: RelayApiKeyPrincipal }
  | {
      ok: false;
      status: 401 | 403;
      code: RelayApiKeyAuthFailureCode;
      message: string;
    };

export interface RelayApiKeyAuthAdapter {
  authenticate(input: RelayApiKeyAuthRequest): Promise<RelayApiKeyAuthResult>;
}

export type RelayPublishableKeyAuthFailureCode =
  | 'publishable_key_missing'
  | 'publishable_key_invalid'
  | 'publishable_key_revoked'
  | 'publishable_key_origin_blocked'
  | 'publishable_key_environment_mismatch';

export interface RelayPublishableKeyAuthRequest {
  secret: string;
  origin: string;
  environmentId: string;
}

export type RelayPublishableKeyAuthResult =
  | { ok: true; principal: RelayApiKeyPrincipal }
  | {
      ok: false;
      status: 401 | 403;
      code: RelayPublishableKeyAuthFailureCode;
      message: string;
    };

export interface RelayPublishableKeyAuthAdapter {
  authenticate(input: RelayPublishableKeyAuthRequest): Promise<RelayPublishableKeyAuthResult>;
}

export type RelayUsageMeterAction = 'wallet_created';

export interface RelayUsageMeterEvent {
  orgId: string;
  environmentId: string;
  apiKeyId: string;
  endpoint: string;
  walletId: string;
  action: RelayUsageMeterAction;
  succeeded: boolean;
  occurredAt?: string;
  sourceEventId?: string;
}

export interface RelayUsageMeterAdapter {
  recordEvent(input: RelayUsageMeterEvent): Promise<void>;
}

export type RelayBootstrapGrantMode = 'free' | 'paid';

export type RelayBootstrapGrantFailureCode =
  | 'publishable_key_missing'
  | 'publishable_key_invalid'
  | 'publishable_key_revoked'
  | 'publishable_key_origin_blocked'
  | 'publishable_key_environment_mismatch'
  | 'publishable_key_rate_limited'
  | 'publishable_key_quota_exhausted'
  | 'invalid_environment'
  | 'environment_archived'
  | 'invalid_body';

export interface RelayBootstrapGrantClientContext {
  sdk?: string;
  sdkVersion?: string;
  userAgentHint?: string;
}

export interface RelayBootstrapGrantIssueRequest {
  publishableKey: string;
  origin: string;
  environmentId: string;
  newAccountId: string;
  rpId: string;
  requestHashSha256: string;
  clientContext?: RelayBootstrapGrantClientContext;
}

export interface RelayBootstrapGrant {
  token: string;
  expiresAt: string;
  environmentId: string;
  origin: string;
  mode: RelayBootstrapGrantMode;
}

export interface RelayBootstrapGrantPaymentRequirement {
  mode: 'x402';
  productId?: string;
}

export type RelayBootstrapGrantIssueResult =
  | {
      ok: true;
      grant: RelayBootstrapGrant;
    }
  | {
      ok: false;
      status: 400 | 401 | 403 | 409 | 429 | 402;
      code: RelayBootstrapGrantFailureCode | 'payment_required' | 'payment_invalid';
      message: string;
      payment?: RelayBootstrapGrantPaymentRequirement;
    };

export interface RelayBootstrapTokenRecord {
  id: string;
  tokenHash: string;
  tokenPrefix: string;
  publishableKeyId: string;
  orgId: string;
  projectId: string;
  environmentId: string;
  origin: string;
  method: string;
  path: string;
  requestHashSha256: string;
  status: 'issued' | 'redeemed' | 'expired';
  riskDecision: string;
  paymentReference: string | null;
  replacementForTokenId: string | null;
  issuedAt: string;
  expiresAt: string;
  redeemedAt: string | null;
  createdAt: string;
  updatedAt: string;
}

export interface RelayBootstrapGrantBroker {
  authenticatePublishableKey(input: {
    publishableKey: string;
    origin: string;
    environmentId?: string;
  }): Promise<import('../console/apiKeys').AuthenticateConsolePublishableKeyResult>;
  issueGrantForAuthenticatedKey(input: Omit<RelayBootstrapGrantIssueRequest, 'publishableKey'> & {
    authenticatedApiKey: import('../console/apiKeys').ConsoleApiKey;
  }): Promise<RelayBootstrapGrantIssueResult>;
}

export type SmartAccountDeploymentChain = 'evm' | 'tempo';

export interface SmartAccountDeployRequest {
  nearAccountId: string;
  chain: SmartAccountDeploymentChain;
  chainId: number;
  accountAddress: string;
  accountModel: string;
  counterfactualAddress?: string;
  factory?: string;
  entryPoint?: string;
  salt?: string;
}

export interface SmartAccountDeployResult {
  ok: boolean;
  deploymentTxHash?: string;
  code?: string;
  message?: string;
}

export type ThresholdSchemeModuleById<S extends ThresholdSchemeId> = Extract<
  ThresholdAnySchemeModule,
  { schemeId: S }
>;

export type ResolveThresholdSchemeResult<S extends ThresholdSchemeId> =
  | { ok: true; scheme: ThresholdSchemeModuleById<S> }
  | { ok: false; code: 'threshold_disabled' | 'not_found'; message: string };

export function resolveThresholdScheme<S extends ThresholdSchemeId>(
  threshold: ThresholdSigningAdapter | null | undefined,
  schemeId: S,
  options?: { notFoundMessage?: string },
): ResolveThresholdSchemeResult<S> {
  if (!threshold) {
    return {
      ok: false,
      code: 'threshold_disabled',
      message: 'Threshold signing is not configured on this server',
    };
  }
  const scheme = threshold.getSchemeModule(schemeId);
  if (!scheme || scheme.schemeId !== schemeId) {
    return {
      ok: false,
      code: 'not_found',
      message:
        options?.notFoundMessage || `threshold scheme ${schemeId} is not enabled on this server`,
    };
  }
  return { ok: true, scheme: scheme as ThresholdSchemeModuleById<S> };
}

export interface RelayRouterOptions {
  healthz?: boolean;
  readyz?: boolean;
  /**
   * Optional list(s) of CORS origins (CSV strings or literal origins).
   * Pass raw strings; the router normalizes/merges internally.
   */
  corsOrigins?: Array<string | undefined>;
  /**
   * Optional route for submitting NEP-461 SignedDelegate meta-transactions.
   * - When omitted: disabled.
   * - When set: enabled at `route`.
   * `policy` is server-controlled and is never read from the request body.
   */
  signedDelegate?: {
    route: string;
    policy?: DelegateActionPolicy;
    billing?: ConsoleBillingService | null;
    ledger?: ConsoleSponsoredCallService | null;
  };
  // Optional: customize canonical app-session read route.
  sessionRoutes?: { state?: string };
  // Optional: pluggable session adapter
  session?: SessionAdapter | null;
  /**
   * App-session cookie name used for passive stale-session signal matching.
   * Defaults to `tatchi-jwt`.
   */
  sessionCookieName?: string;
  // Optional: pluggable threshold signing service
  threshold?: ThresholdSigningAdapter | null;
  // Optional: runtime snapshot consumer used to bind authorize requests to latest scoped config.
  runtimeSnapshots?: RelayRuntimeSnapshotConsumer | null;
  // Optional: webhook emitter for relay session/wallet lifecycle events.
  relayWebhooks?: RelayWebhookOptions | null;
  /**
   * Optional relay API-key authentication adapter for gas-costing routes.
   *
   * When omitted, runtime routes do not enforce API key auth.
   */
  apiKeyAuth?: RelayApiKeyAuthAdapter | null;
  /**
   * Optional publishable-key authentication adapter for browser-safe
   * API credential routes like signed delegate execution.
   */
  publishableKeyAuth?: RelayPublishableKeyAuthAdapter | null;
  /**
   * Optional relay usage-meter adapter used to emit runtime events for
   * billing linkage.
   */
  apiKeyUsageMeter?: RelayUsageMeterAdapter | null;
  /**
   * Optional managed bootstrap broker used by browser-safe publishable_key flows.
   */
  bootstrapGrantBroker?: RelayBootstrapGrantBroker | null;
  /**
   * Optional bootstrap-token store used to redeem managed registration grants.
   */
  bootstrapTokenStore?: ConsoleBootstrapTokenService | null;
  /**
   * Optional standalone PRF session seal/unlock routes.
   *
   * When provided and enabled, routers mount:
   * - POST `<basePath>/apply-server-seal`
   * - POST `<basePath>/remove-server-seal`
   *
   * Default `basePath` is `/threshold-ecdsa/prf-seal`.
   */
  prfSessionSeal?: PrfSessionSealRoutesOptions | null;
  /**
   * Optional internal smart-account deploy hook.
   *
   * This hook is for internal registration or provisioning flows.
   * It is not exposed as a public relay route.
   */
  smartAccountDeploy?:
    | ((
        request: SmartAccountDeployRequest,
      ) => Promise<SmartAccountDeployResult> | SmartAccountDeployResult)
    | null;
  /**
   * Optional ROR configuration for `GET /.well-known/webauthn`.
   * When omitted, the endpoint responds with an empty allowlist.
   */
  ror?: RelayRouterRorOptions;
  sponsoredEvmCall?: {
    route?: string;
    apiKeys: ConsoleApiKeyService;
    billing: ConsoleBillingService;
    ledger: ConsoleSponsoredCallService;
    runtimeSnapshots: ConsoleRuntimeSnapshotService;
    config: SponsoredEvmCallExecutorConfig | null;
  };
  /**
   * Optional high-level wallet read service used by API credential wallet routes.
   */
  wallets?: ConsoleWalletService | null;
  // Optional logger; defaults to silent.
  logger?: RouterLogger | null;
}
