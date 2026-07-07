import type { RouterLogger } from './logger';
import type { ThresholdAnySchemeModule } from '../core/ThresholdService/schemes/thresholdServiceSchemes.types';
import type { ThresholdSchemeId } from '../core/ThresholdService/schemes/schemeIds';
import type {
  ThresholdEd25519BootstrapSession,
  ThresholdEd25519AuthorityScope,
  ThresholdEd25519HssCanonicalContext,
  ThresholdEd25519HssFinalizeWithSessionRequest,
  ThresholdEd25519HssFinalizeWithSessionResponse,
  ThresholdEd25519HssAdvanceWithSessionRequest,
  ThresholdEd25519HssAdvanceWithSessionResponse,
  ThresholdEd25519HssPreparedSessionEnvelope,
  ThresholdEd25519HssPrepareWithSessionRequest,
  ThresholdEd25519HssPrepareWithSessionResponse,
  ThresholdEd25519HssRespondWithSessionRequest,
  ThresholdEd25519HssRespondWithSessionResponse,
} from '../core/types';
import type { RouterApiRorOptions } from './ror/provider';
import type { RouterApiModule } from './modules';
import type { RouterApiRouteExtension } from './routeExtensions';
import type { SigningSessionSealRoutesOptions } from '../threshold/session/signingSessionSeal/signingSessionSeal.types';
import type { ConsoleWebhookService } from '../console/webhooks';
import type { ConsoleBillingPrepaidReservationService } from '../console/billingPrepaidReservations';
import type { ConsoleObservabilityIngestionService } from '../console/observability';
import type { ConsoleSponsorshipSpendCapService } from '../console/sponsorshipSpendCaps';
import type { SponsorshipSpendPricingService } from '../console/sponsorship/spendCaps';
import { normalizeJwtCookieSessionKind } from '@shared/utils/normalize';
import { WALLET_EMAIL_OTP_EXPORT_OPERATION } from '@shared/utils/emailOtpDomain';
import type { RuntimePolicyScope } from '@shared/threshold/signingRootScope';
import type { RouterAbPublicKeysetV2 } from '@shared/utils/routerAbPublicKeyset';
import type { RouterAbNormalSigningAdmissionAdapter } from './routerAbPrivateSigningWorker';
import type { EmailRecoveryService } from '../email-recovery';
import type {
  RouterApiAuthenticatedPublishableCredential,
  RouterApiBootstrapGrantPublishableKeyAuthResult,
  RouterApiBootstrapTokenVerifier,
  RouterApiKeyAuthAdapter,
  RouterApiProjectEnvironmentResolver,
  RouterApiPublishableKeyAuthAdapter,
  RouterApiUsageMeterAdapter,
} from './apiCredentialPorts';
import type {
  FinalizeEmailRecoveryEd25519Request,
  PrepareEmailRecoveryRequest,
  RespondEmailRecoveryEd25519Request,
  RespondEmailRecoveryEcdsaRequest,
} from './emailRecoveryRequestValidation';
import type { EmailRecoveryResolvedWalletBinding } from '../core/EmailRecoveryPreparationStore';

export type {
  RouterApiAuthenticatedPublishableCredential,
  RouterApiBootstrapGrantPublishableKeyAuthResult,
  RouterApiBootstrapTokenRecord,
  RouterApiBootstrapTokenRedeemFailureCode,
  RouterApiBootstrapTokenRedeemRequest,
  RouterApiBootstrapTokenRedeemResult,
  RouterApiBootstrapTokenVerifier,
  RouterApiCredentialScope,
  RouterApiKeyAuthAdapter,
  RouterApiKeyAuthFailureCode,
  RouterApiKeyAuthRequest,
  RouterApiKeyAuthResult,
  RouterApiKeyPrincipal,
  RouterApiProjectEnvironment,
  RouterApiProjectEnvironmentResolver,
  RouterApiPublishableKeyAuthAdapter,
  RouterApiPublishableKeyAuthFailureCode,
  RouterApiPublishableKeyAuthRequest,
  RouterApiPublishableKeyAuthResult,
  RouterApiUsageMeterAction,
  RouterApiUsageMeterAdapter,
  RouterApiUsageMeterEvent,
} from './apiCredentialPorts';

// Minimal session adapter interface expected by the routers.
export type SessionClaims = Record<string, unknown>;

export type SessionKind = 'cookie' | 'jwt';
export const DEFAULT_SESSION_COOKIE_NAME = 'seams-jwt';

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
  ed25519Hss?: {
    prepareWithSession(input: {
      claims: SessionClaims;
      request: ThresholdEd25519HssPrepareWithSessionRequest;
    }): Promise<ThresholdEd25519HssPrepareWithSessionResponse>;
    respondWithSession(input: {
      claims: SessionClaims;
      request: ThresholdEd25519HssRespondWithSessionRequest;
    }): Promise<ThresholdEd25519HssRespondWithSessionResponse>;
    advanceWithSession(input: {
      claims: SessionClaims;
      request: ThresholdEd25519HssAdvanceWithSessionRequest;
    }): Promise<ThresholdEd25519HssAdvanceWithSessionResponse>;
    finalizeWithSession(input: {
      claims: SessionClaims;
      request: ThresholdEd25519HssFinalizeWithSessionRequest;
    }): Promise<ThresholdEd25519HssFinalizeWithSessionResponse>;
  };
}

export type RouterApiRuntimePolicyScope = RuntimePolicyScope;

export interface RouterApiRuntimeSnapshotEnvelope {
  snapshotId: string;
  version: number;
  checksum: string;
  effectiveAt: string;
}

export interface RouterApiRuntimeSnapshotConsumer {
  getLatestSnapshot(
    scope: RouterApiRuntimePolicyScope,
  ): Promise<RouterApiRuntimeSnapshotEnvelope | null> | RouterApiRuntimeSnapshotEnvelope | null;
}

export interface RouterApiWebhookOptions {
  /**
   * Console webhook service used for Router API lifecycle webhook delivery.
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

export type RouterApiEmailRecoveryResult =
  | {
      ok: true;
      walletId: string;
      walletBinding: EmailRecoveryResolvedWalletBinding;
      credentialIdB64u: string;
      thresholdEd25519: {
        relayerKeyId: string;
        authorityScope: ThresholdEd25519AuthorityScope;
        participantIds?: number[];
        session?: ThresholdEd25519BootstrapSession;
        hss?: {
          ceremonyHandle?: string;
          preparedSession?: ThresholdEd25519HssPreparedSessionEnvelope;
          clientOtOfferMessageB64u?: string;
          context?: ThresholdEd25519HssCanonicalContext;
          contextBindingB64u?: string;
          serverInputDeliveryB64u?: string;
        };
      };
    }
  | { ok: false; code: string; message: string };

export interface RouterApiEmailRecoveryAuthService {
  prepareEmailRecovery(
    request: PrepareEmailRecoveryRequest,
  ): Promise<RouterApiEmailRecoveryResult>;
  respondEmailRecoveryEd25519(
    request: RespondEmailRecoveryEd25519Request,
  ): Promise<RouterApiEmailRecoveryResult>;
  finalizeEmailRecoveryEd25519(
    request: FinalizeEmailRecoveryEd25519Request,
  ): Promise<RouterApiEmailRecoveryResult>;
  respondEmailRecoveryEcdsa(
    request: RespondEmailRecoveryEcdsaRequest,
  ): Promise<RouterApiEmailRecoveryResult>;
}

export type RouterApiEmailRecoveryExecutionService = Pick<
  EmailRecoveryService,
  'requestEmailRecovery'
>;

export type RouterApiEmailRecoveryOptions =
  | {
      kind: 'prepare_and_execute';
      authService: RouterApiEmailRecoveryAuthService;
      executionService: RouterApiEmailRecoveryExecutionService;
    }
  | {
      kind: 'prepare_only';
      authService: RouterApiEmailRecoveryAuthService;
      executionService?: never;
    };

export type RouterApiEmailOtpExportPolicyPhase = 'challenge' | 'verify';

export type RouterApiEmailOtpExportPolicyDecision =
  | {
      ok: true;
      decision: 'ALLOW';
      policyId?: string;
      approvalId?: string;
      reason?: string;
    }
  | {
      ok: false;
      decision: 'DENY';
      code?: string;
      message: string;
      policyId?: string;
      approvalId?: string;
      reason?: string;
    };

export interface RouterApiEmailOtpExportPolicyInput {
  operation: typeof WALLET_EMAIL_OTP_EXPORT_OPERATION;
  phase: RouterApiEmailOtpExportPolicyPhase;
  userId: string;
  walletId: string;
  orgId?: string;
  projectId?: string;
  environmentId?: string;
  appSessionVersion: string;
  challengeId?: string;
  sourceIp?: string;
}

export interface RouterApiEmailOtpExportPolicyAdapter {
  authorize(
    input: RouterApiEmailOtpExportPolicyInput,
  ): Promise<RouterApiEmailOtpExportPolicyDecision> | RouterApiEmailOtpExportPolicyDecision;
}

export type RouterApiBootstrapGrantMode = 'free' | 'paid';

export type RouterApiBootstrapGrantFailureCode =
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

export interface RouterApiBootstrapGrantClientContext {
  sdk?: string;
  sdkVersion?: string;
  userAgentHint?: string;
}

export type RouterApiBootstrapGrantIssueAuthority =
  | {
      kind: 'passkey_rp';
      rpId: string;
    }
  | {
      kind: 'wallet_auth';
      rpId?: never;
    };

export interface RouterApiBootstrapGrantIssueRequest {
  publishableKey: string;
  origin: string;
  environmentId: string;
  newAccountId?: string;
  authority: RouterApiBootstrapGrantIssueAuthority;
  flow: 'registration_v1';
  clientContext?: RouterApiBootstrapGrantClientContext;
}

export interface RouterApiBootstrapGrant {
  token: string;
  expiresAt: string;
  orgId: string;
  projectId: string;
  envId: string;
  signingRootVersion: string;
  origin: string;
  mode: RouterApiBootstrapGrantMode;
}

export interface RouterApiBootstrapGrantPaymentRequirement {
  mode: 'x402';
  productId?: string;
}

export type RouterApiBootstrapGrantIssueResult =
  | {
      ok: true;
      grant: RouterApiBootstrapGrant;
    }
  | {
      ok: false;
      status: 400 | 401 | 403 | 409 | 429 | 402;
      code: RouterApiBootstrapGrantFailureCode | 'payment_required' | 'payment_invalid';
      message: string;
      payment?: RouterApiBootstrapGrantPaymentRequirement;
    };

export interface RouterApiBootstrapGrantBroker {
  authenticatePublishableKey(input: {
    publishableKey: string;
    origin: string;
    environmentId?: string;
  }): Promise<RouterApiBootstrapGrantPublishableKeyAuthResult>;
  issueGrantForAuthenticatedKey(
    input: Omit<RouterApiBootstrapGrantIssueRequest, 'publishableKey'> & {
      authenticatedCredential: RouterApiAuthenticatedPublishableCredential;
    },
  ): Promise<RouterApiBootstrapGrantIssueResult>;
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

export interface RouterApiOptions {
  healthz?: boolean;
  readyz?: boolean;
  // Optional readiness probe hook for Router API dependencies.
  readyCheck?: (() => Promise<void> | void) | null;
  /**
   * Optional list(s) of CORS origins (CSV strings or literal origins).
   * Pass raw strings; the router normalizes/merges internally.
   */
  corsOrigins?: Array<string | undefined>;
  sponsorship?: {
    spendCaps?: ConsoleSponsorshipSpendCapService | null;
    pricing?: SponsorshipSpendPricingService | null;
    prepaidReservations?: ConsoleBillingPrepaidReservationService | null;
  };
  // Optional: customize canonical app-session read route.
  sessionRoutes?: { state?: string };
  // Optional: pluggable session adapter
  session?: SessionAdapter | null;
  /**
   * App-session cookie name used for passive stale-session signal matching.
   * Defaults to `seams-jwt`.
   */
  sessionCookieName?: string;
  // Optional: pluggable threshold signing service
  threshold?: ThresholdSigningAdapter | null;
  // Optional: runtime snapshot consumer used to bind authorize requests to latest scoped config.
  runtimeSnapshots?: RouterApiRuntimeSnapshotConsumer | null;
  // Optional: webhook emitter for Router API session/wallet lifecycle events.
  routerApiWebhooks?: RouterApiWebhookOptions | null;
  // Optional: enable DKIM/TEE email recovery prepare, respond, and ingress routes.
  emailRecovery?: RouterApiEmailRecoveryOptions | null;
  /**
   * Optional policy adapter for Email OTP key-export authorization.
   *
   * When omitted, local/dev deployments allow `export_key` by default but still
   * emit export-specific audit events with `policySource=default_allow`.
   */
  emailOtpExportPolicy?: RouterApiEmailOtpExportPolicyAdapter | null;
  // Optional observability ingestion adapter used by sponsorship runtime signals.
  observabilityIngestion?: ConsoleObservabilityIngestionService | null;
  /**
   * Optional Router API key authentication adapter for gas-costing routes.
   *
   * When omitted, runtime routes do not enforce API key auth.
   */
  apiKeyAuth?: RouterApiKeyAuthAdapter | null;
  /**
   * Optional publishable-key authentication adapter for browser-safe
   * API credential routes like signed delegate execution.
   */
  publishableKeyAuth?: RouterApiPublishableKeyAuthAdapter | null;
  /**
   * Optional Router API usage-meter adapter used to emit runtime events for
   * billing linkage.
   */
  apiKeyUsageMeter?: RouterApiUsageMeterAdapter | null;
  /**
   * Optional bootstrap-token verifier used to redeem managed registration grants.
   */
  bootstrapTokenVerifier?: RouterApiBootstrapTokenVerifier | null;
  /**
   * Optional standalone Signing-session seal/unlock routes.
   *
   * When provided, routers mount:
   * - POST `<basePath>/apply-server-seal`
   * - POST `<basePath>/remove-server-seal`
   *
   * Default `basePath` is `/wallet-session/seal`.
   */
  signingSessionSeal?: SigningSessionSealRoutesOptions | null;
  /**
   * Optional ROR configuration for `GET /.well-known/webauthn`.
   * When omitted, the endpoint responds with an empty allowlist.
   */
  ror?: RouterApiRorOptions;
  /**
   * Optional Router A/B public deployment keyset served from public discovery
   * routes for self-hosted and local Router API surfaces.
   */
  routerAbPublicKeyset?: RouterAbPublicKeysetV2 | null;
  /**
   * Optional Router-owned project-policy, quota, and abuse admission gate for
   * Router A/B normal-signing requests.
   */
  routerAbNormalSigningAdmission?: RouterAbNormalSigningAdmissionAdapter | null;
  /**
   * Optional route extensions mounted by the Router API router. Each extension declares
   * explicit runtime support so a Cloudflare Worker can expose Worker-native
   * handlers while an Express server can mount Express-native handlers.
   */
  routeExtensions?: readonly RouterApiRouteExtension[];
  /**
   * Optional high-level Router API modules. Modules compose route extensions while
   * keeping concrete feature ownership outside wallet/auth router core.
   */
  modules?: readonly RouterApiModule[];
  /**
   * Optional org/project/environment service used to resolve environment -> project scope.
   */
  orgProjectEnv?: RouterApiProjectEnvironmentResolver | null;
  // Optional logger; defaults to silent.
  logger?: RouterLogger | null;
}
