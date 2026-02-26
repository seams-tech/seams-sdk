import type { NormalizedLogger } from '../../../core/logger';
import { createPrfSessionSealAuditLogger } from './observability/audit';
import {
  composePrfSessionSealGuards,
  createPrfSessionSealRateLimitGuard,
} from './guards';
import { createPrfSessionSealService } from './service';
import type {
  CreatePrfSessionSealServiceOptions,
  PrfSessionSealAuditSink,
  PrfSessionSealAuthorizeInput,
  PrfSessionSealAuthorizeResult,
  PrfSessionSealCipherAdapter,
  PrfSessionSealConsumePolicy,
  PrfSessionSealGuard,
  PrfSessionSealRoutesOptions,
  PrfSessionSealThresholdSessionPolicy,
} from './types';
import type {
  CreatePrfSessionSealAuditLoggerOptions,
} from './observability/audit';
import type {
  CreatePrfSessionSealRateLimitGuardOptions,
} from './guards';

export interface CreatePrfSessionSealRoutesOptionsInput {
  enabled?: boolean;
  basePath?: string;
  sessionPolicy: PrfSessionSealThresholdSessionPolicy;
  cipher: PrfSessionSealCipherAdapter;
  consumePolicy?: PrfSessionSealConsumePolicy;
  guard?: PrfSessionSealGuard | null;
  guards?: Array<PrfSessionSealGuard | null | undefined>;
  rateLimit?: Omit<CreatePrfSessionSealRateLimitGuardOptions, 'nowMs'>;
  audit?: PrfSessionSealAuditSink | null;
  logger?: NormalizedLogger | null;
  auditLogger?: Omit<CreatePrfSessionSealAuditLoggerOptions, 'logger'> | null;
  authorize?: (
    input: PrfSessionSealAuthorizeInput,
  ) => Promise<PrfSessionSealAuthorizeResult> | PrfSessionSealAuthorizeResult;
  nowMs?: () => number;
}

function buildAuditSink(input: CreatePrfSessionSealRoutesOptionsInput): PrfSessionSealAuditSink | undefined {
  if (input.audit) return input.audit;
  if (!input.logger) return undefined;
  if (input.auditLogger === null) return undefined;
  return createPrfSessionSealAuditLogger({
    logger: input.logger,
    ...(input.auditLogger?.label ? { label: input.auditLogger.label } : {}),
    ...(input.auditLogger?.failureLevel ? { failureLevel: input.auditLogger.failureLevel } : {}),
  });
}

function buildGuard(input: CreatePrfSessionSealRoutesOptionsInput): PrfSessionSealGuard | undefined {
  const guardList: Array<PrfSessionSealGuard | null | undefined> = [];

  if (input.guard) guardList.push(input.guard);
  if (Array.isArray(input.guards)) guardList.push(...input.guards);

  if (input.rateLimit) {
    guardList.push(createPrfSessionSealRateLimitGuard({
      ...input.rateLimit,
      ...(input.nowMs ? { nowMs: input.nowMs } : {}),
    }));
  }

  const nonNullGuards = guardList.filter(Boolean) as PrfSessionSealGuard[];
  if (nonNullGuards.length === 0) return undefined;
  return composePrfSessionSealGuards(...nonNullGuards);
}

export function createPrfSessionSealRoutesOptions(
  input: CreatePrfSessionSealRoutesOptionsInput,
): PrfSessionSealRoutesOptions {
  const guard = buildGuard(input);
  const audit = buildAuditSink(input);
  const serviceOptions: CreatePrfSessionSealServiceOptions = {
    sessionPolicy: input.sessionPolicy,
    cipher: input.cipher,
    ...(input.consumePolicy ? { consumePolicy: input.consumePolicy } : {}),
    ...(guard ? { guard } : {}),
    ...(audit ? { audit } : {}),
    ...(input.nowMs ? { nowMs: input.nowMs } : {}),
  };
  return {
    ...(input.enabled !== undefined ? { enabled: input.enabled } : {}),
    ...(input.basePath ? { basePath: input.basePath } : {}),
    service: createPrfSessionSealService(serviceOptions),
    ...(input.authorize ? { authorize: input.authorize } : {}),
  };
}
