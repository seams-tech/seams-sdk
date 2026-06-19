import type { NormalizedLogger } from '../../../core/logger';
import {
  parseRouterAbEcdsaHssWalletSessionClaims,
  parseRouterAbEd25519WalletSessionClaims,
} from '../../../core/ThresholdService/validation';
import { createSigningSessionSealAuditLogger } from './observability/audit';
import { composeSigningSessionSealGuards, createSigningSessionSealRateLimitGuard } from './guards';
import { createSigningSessionSealService } from './service';
import type {
  CreateSigningSessionSealServiceOptions,
  SigningSessionSealAuditSink,
  SigningSessionSealAuthorizeInput,
  SigningSessionSealAuthorizeResult,
  SigningSessionSealCipherAdapter,
  SigningSessionSealConsumePolicy,
  SigningSessionSealGuard,
  SigningSessionSealRoutesOptions,
  SigningSessionSealServiceIdempotencyOptions,
  SigningSessionSealThresholdSessionPolicy,
  SigningSessionSealStartupCapabilities,
} from './types';
import type { CreateSigningSessionSealAuditLoggerOptions } from './observability/audit';
import type { CreateSigningSessionSealRateLimitGuardOptions } from './guards';

export interface CreateSigningSessionSealRoutesOptionsInput {
  enabled?: boolean;
  basePath?: string;
  sessionPolicy: SigningSessionSealThresholdSessionPolicy;
  cipher: SigningSessionSealCipherAdapter;
  consumePolicy?: SigningSessionSealConsumePolicy;
  idempotency?: SigningSessionSealServiceIdempotencyOptions;
  guard?: SigningSessionSealGuard | null;
  guards?: Array<SigningSessionSealGuard | null | undefined>;
  rateLimit?: Omit<CreateSigningSessionSealRateLimitGuardOptions, 'nowMs'>;
  audit?: SigningSessionSealAuditSink | null;
  logger?: NormalizedLogger | null;
  auditLogger?: Omit<CreateSigningSessionSealAuditLoggerOptions, 'logger'> | null;
  capabilities?: SigningSessionSealStartupCapabilities;
  authorize?: (
    input: SigningSessionSealAuthorizeInput,
  ) => Promise<SigningSessionSealAuthorizeResult> | SigningSessionSealAuthorizeResult;
  nowMs?: () => number;
}

function buildAuditSink(
  input: CreateSigningSessionSealRoutesOptionsInput,
): SigningSessionSealAuditSink | undefined {
  if (input.audit) return input.audit;
  if (!input.logger) return undefined;
  if (input.auditLogger === null) return undefined;
  const options: CreateSigningSessionSealAuditLoggerOptions = {
    logger: input.logger,
  };
  if (input.auditLogger?.label) {
    options.label = input.auditLogger.label;
  }
  if (input.auditLogger?.failureLevel) {
    options.failureLevel = input.auditLogger.failureLevel;
  }
  return createSigningSessionSealAuditLogger(options);
}

function buildGuard(
  input: CreateSigningSessionSealRoutesOptionsInput,
): SigningSessionSealGuard | undefined {
  const guardList: Array<SigningSessionSealGuard | null | undefined> = [];

  if (input.guard) guardList.push(input.guard);
  if (Array.isArray(input.guards)) guardList.push(...input.guards);

  if (input.rateLimit) {
    const rateLimitOptions: CreateSigningSessionSealRateLimitGuardOptions = { ...input.rateLimit };
    if (input.nowMs) {
      rateLimitOptions.nowMs = input.nowMs;
    }
    guardList.push(
      createSigningSessionSealRateLimitGuard(rateLimitOptions),
    );
  }

  const nonNullGuards = guardList.filter(Boolean) as SigningSessionSealGuard[];
  if (nonNullGuards.length === 0) return undefined;
  return composeSigningSessionSealGuards(...nonNullGuards);
}

function parseCurveBoundThresholdLookup(args: {
  claims: Record<string, unknown>;
  thresholdSessionId: string;
}): { curve: 'ecdsa' | 'ed25519'; thresholdSessionId: string } | null {
  const thresholdSessionId = String(args.thresholdSessionId || '').trim();
  if (!thresholdSessionId) return null;
  const ecdsaClaims = parseRouterAbEcdsaHssWalletSessionClaims(args.claims);
  if (ecdsaClaims) {
    return ecdsaClaims.sessionId === thresholdSessionId
      ? { curve: 'ecdsa', thresholdSessionId }
      : null;
  }
  const ed25519Claims = parseRouterAbEd25519WalletSessionClaims(args.claims);
  if (ed25519Claims) {
    return ed25519Claims.sessionId === thresholdSessionId
      ? { curve: 'ed25519', thresholdSessionId }
      : null;
  }
  return null;
}

export function createSigningSessionSealRoutesOptions(
  input: CreateSigningSessionSealRoutesOptionsInput,
): SigningSessionSealRoutesOptions {
  const guard = buildGuard(input);
  const audit = buildAuditSink(input);
  const serviceOptions: CreateSigningSessionSealServiceOptions = {
    sessionPolicy: input.sessionPolicy,
    cipher: input.cipher,
  };
  if (input.consumePolicy) {
    serviceOptions.consumePolicy = input.consumePolicy;
  }
  if (input.idempotency) {
    serviceOptions.idempotency = input.idempotency;
  }
  if (guard) {
    serviceOptions.guard = guard;
  }
  if (audit) {
    serviceOptions.audit = audit;
  }
  if (input.logger) {
    serviceOptions.logger = input.logger;
  }
  if (input.nowMs) {
    serviceOptions.nowMs = input.nowMs;
  }

  const options: SigningSessionSealRoutesOptions = {
    service: createSigningSessionSealService(serviceOptions),
    sessionPolicy: input.sessionPolicy,
  };
  if (input.enabled !== undefined) {
    options.enabled = input.enabled;
  }
  if (input.basePath) {
    options.basePath = input.basePath;
  }
  if (input.authorize) {
    options.authorize = input.authorize;
  } else {
    options.authorize = async ({ headers, session, thresholdSessionId }) => {
      if (!session) {
        return {
          ok: false,
          code: 'sessions_disabled',
          message: 'Sessions are not configured for Signing-session seal routes',
          status: 501,
        };
      }
      const parsed = await session.parse(headers);
      if (!parsed.ok) {
        return {
          ok: false,
          code: 'unauthorized',
          message: 'No valid session',
          status: 401,
        };
      }
      const claims =
        parsed.claims && typeof parsed.claims === 'object' && !Array.isArray(parsed.claims)
          ? (parsed.claims as Record<string, unknown>)
          : {};
      const userId = typeof claims.walletId === 'string' ? claims.walletId.trim() : '';
      if (!userId) {
        return {
          ok: false,
          code: 'unauthorized',
          message: 'Invalid session subject',
          status: 401,
        };
      }
      const thresholdLookup = parseCurveBoundThresholdLookup({
        claims,
        thresholdSessionId: String(thresholdSessionId || '').trim(),
      });
      if (!thresholdLookup) {
        return {
          ok: false,
          code: 'forbidden',
          message: 'Wallet Session does not match requested thresholdSessionId',
          status: 403,
        };
      }
      const thresholdSession = await input.sessionPolicy.getThresholdSession(thresholdLookup);
      if (!thresholdSession) {
        return {
          ok: false,
          code: 'unauthorized',
          message: 'Unknown or expired threshold session',
          status: 401,
        };
      }
      if (thresholdSession.userId !== userId) {
        return {
          ok: false,
          code: 'forbidden',
          message: 'thresholdSessionId does not belong to authenticated user',
          status: 403,
        };
      }
      return {
        ok: true,
        auth: {
          userId,
          claims: {
            ...claims,
            thresholdSessionId: thresholdSession.thresholdSessionId,
          },
        },
      };
    };
  }
  if (input.capabilities) {
    options.capabilities = input.capabilities;
  }
  return options;
}
