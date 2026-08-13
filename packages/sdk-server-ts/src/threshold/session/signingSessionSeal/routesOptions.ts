import type { NormalizedLogger } from '../../../core/logger';
import {
  parseRouterAbEcdsaDerivationWalletSessionClaims,
  parseRouterAbEd25519WalletSessionClaims,
} from '../../../core/ThresholdService/validation';
import {
  walletSessionFailure,
  walletSessionFailureStatus,
  walletSessionParseFailure,
} from '../../../router/auth/walletSessionFailure';
import { WALLET_SESSION_FAILURE_CODES } from '@shared/utils/walletSessionFailure';
import { createSigningSessionSealAuditLogger } from './observability/audit';
import { composeSigningSessionSealGuards, createSigningSessionSealRateLimitGuard } from './guards';
import { createSigningSessionSealService } from './service';
import type {
  CreateSigningSessionSealServiceOptions,
  SigningSessionSealAuditSink,
  SigningSessionSealAuthorizeInput,
  SigningSessionSealAuthorizeResult,
  SigningSessionSealCipherAdapter,
  SigningSessionSealGuard,
  SigningSessionSealRoutesOptions,
  SigningSessionSealServiceIdempotencyOptions,
  SigningSessionSealStartupCapabilities,
} from './signingSessionSeal.types';
import type { CreateSigningSessionSealAuditLoggerOptions } from './observability/audit';
import type { CreateSigningSessionSealRateLimitGuardOptions } from './guards';

export interface CreateSigningSessionSealRoutesOptionsInput {
  basePath?: string;
  cipher: SigningSessionSealCipherAdapter;
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
    guardList.push(createSigningSessionSealRateLimitGuard(rateLimitOptions));
  }

  const nonNullGuards = guardList.filter(Boolean) as SigningSessionSealGuard[];
  if (nonNullGuards.length === 0) return undefined;
  return composeSigningSessionSealGuards(...nonNullGuards);
}

function parseCurveBoundThresholdLookup(args: {
  claims: Record<string, unknown>;
  thresholdSessionId: string;
}): {
  curve: 'ecdsa' | 'ed25519';
  thresholdSessionId: string;
  thresholdExpiresAtMs: number;
} | null {
  const thresholdSessionId = String(args.thresholdSessionId || '').trim();
  if (!thresholdSessionId) return null;
  const ecdsaClaims = parseRouterAbEcdsaDerivationWalletSessionClaims(args.claims);
  if (ecdsaClaims?.authorizationKind === 'owner_wallet_session') {
    return ecdsaClaims.thresholdSessionId === thresholdSessionId
      ? {
          curve: 'ecdsa',
          thresholdSessionId,
          thresholdExpiresAtMs: ecdsaClaims.thresholdExpiresAtMs,
        }
      : null;
  }
  const ed25519Claims = parseRouterAbEd25519WalletSessionClaims(args.claims);
  if (ed25519Claims?.authorizationKind === 'owner_wallet_session') {
    return ed25519Claims.thresholdSessionId === thresholdSessionId
      ? {
          curve: 'ed25519',
          thresholdSessionId,
          thresholdExpiresAtMs: ed25519Claims.thresholdExpiresAtMs,
        }
      : null;
  }
  return null;
}

function signingSessionSealAuthorizationFailure(
  code: Parameters<typeof walletSessionFailure>[0],
): SigningSessionSealAuthorizeResult {
  const failure = walletSessionFailure(code);
  return {
    ...failure,
    status: walletSessionFailureStatus(code),
  };
}

export function createSigningSessionSealRoutesOptions(
  input: CreateSigningSessionSealRoutesOptionsInput,
): SigningSessionSealRoutesOptions {
  const guard = buildGuard(input);
  const audit = buildAuditSink(input);
  const serviceOptions: CreateSigningSessionSealServiceOptions = {
    cipher: input.cipher,
  };
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
  };
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
        const failure = walletSessionParseFailure(parsed.reason);
        return {
          ...failure,
          status: walletSessionFailureStatus(failure.code),
        };
      }
      const claims =
        parsed.claims && typeof parsed.claims === 'object' && !Array.isArray(parsed.claims)
          ? (parsed.claims as Record<string, unknown>)
          : {};
      const userId = typeof claims.walletId === 'string' ? claims.walletId.trim() : '';
      if (!userId) {
        return signingSessionSealAuthorizationFailure(WALLET_SESSION_FAILURE_CODES.claimsInvalid);
      }
      const thresholdLookup = parseCurveBoundThresholdLookup({
        claims,
        thresholdSessionId: String(thresholdSessionId || '').trim(),
      });
      if (!thresholdLookup) {
        return signingSessionSealAuthorizationFailure(WALLET_SESSION_FAILURE_CODES.scopeMismatch);
      }

      if (thresholdLookup.thresholdExpiresAtMs <= (input.nowMs || Date.now)()) {
        return signingSessionSealAuthorizationFailure(WALLET_SESSION_FAILURE_CODES.expired);
      }
      return {
        ok: true,
        auth: {
          userId,
          claims,
        },
      };
    };
  }
  if (input.capabilities) {
    options.capabilities = input.capabilities;
  }
  return options;
}
