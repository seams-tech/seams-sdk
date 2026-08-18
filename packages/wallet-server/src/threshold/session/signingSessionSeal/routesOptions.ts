import type { NormalizedLogger } from '../../../core/logger';
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
  if (input.authorize) options.authorize = input.authorize;
  if (input.capabilities) {
    options.capabilities = input.capabilities;
  }
  return options;
}
