import { normalizeCorsOrigin } from '@seams/sdk-server/internal/core/SessionService';
import { makeId } from '../apiKeys/secret';
import {
  hashBootstrapToken,
  makeBootstrapToken,
  makeBootstrapTokenLookupPrefix,
  parseBootstrapToken,
} from './secret';
import type {
  ConsoleBootstrapTokenRecord,
  CountConsoleBootstrapTokensRequest,
  CreateConsoleBootstrapTokenRequest,
  CreateConsoleBootstrapTokenResult,
  RedeemConsoleBootstrapTokenRequest,
  RedeemConsoleBootstrapTokenResult,
} from './types';

export interface ConsoleBootstrapTokensContext {
  orgId: string;
  actorUserId: string;
  roles: string[];
}

export interface ConsoleBootstrapTokenService {
  createToken(
    ctx: ConsoleBootstrapTokensContext,
    request: CreateConsoleBootstrapTokenRequest,
  ): Promise<CreateConsoleBootstrapTokenResult>;
  countIssued(
    ctx: ConsoleBootstrapTokensContext,
    request: CountConsoleBootstrapTokensRequest,
  ): Promise<number>;
  peekTokenRecord(token: string): Promise<ConsoleBootstrapTokenRecord | null>;
  redeemToken(request: RedeemConsoleBootstrapTokenRequest): Promise<RedeemConsoleBootstrapTokenResult>;
}

export interface InMemoryConsoleBootstrapTokenServiceOptions {
  now?: () => Date;
}

function normalizeMethod(method: string): string {
  return String(method || '').trim().toUpperCase();
}

function normalizePath(path: string): string {
  const trimmed = String(path || '').trim();
  return trimmed.startsWith('/') ? trimmed : `/${trimmed}`;
}

function normalizeOrigin(origin: string): string {
  return normalizeCorsOrigin(origin) || '';
}

function normalizeAllowedPaths(paths: string[] | undefined, fallbackPath: string): string[] {
  const normalized = Array.isArray(paths)
    ? Array.from(
        new Set(
          paths
            .map((entry) => normalizePath(entry))
            .filter(Boolean),
        ),
      )
    : [];
  if (normalized.length > 0) return normalized;
  return [normalizePath(fallbackPath)];
}

function cloneRecord(record: ConsoleBootstrapTokenRecord): ConsoleBootstrapTokenRecord {
  return {
    ...record,
    allowedPaths: [...record.allowedPaths],
  };
}

export function createInMemoryConsoleBootstrapTokenService(
  options: InMemoryConsoleBootstrapTokenServiceOptions = {},
): ConsoleBootstrapTokenService {
  const now = options.now || (() => new Date());
  const records = new Map<string, ConsoleBootstrapTokenRecord>();

  return {
    async createToken(ctx, request): Promise<CreateConsoleBootstrapTokenResult> {
      const currentNow = now();
      const issuedAt = currentNow.toISOString();
      const expiresAt = new Date(
        currentNow.getTime() + Math.max(1_000, Math.floor(request.ttlMs || 60_000)),
      ).toISOString();
      const tokenId = makeId('tbt', currentNow);
      const token = makeBootstrapToken({ orgId: ctx.orgId, tokenId });
      const record: ConsoleBootstrapTokenRecord = {
        id: tokenId,
        orgId: ctx.orgId,
        projectId: String(request.projectId || '').trim(),
        environmentId: String(request.environmentId || '').trim(),
        publishableKeyId: String(request.publishableKeyId || '').trim(),
        newAccountId: String(request.newAccountId || '').trim(),
        rpId: String(request.rpId || '').trim(),
        tokenPrefix: makeBootstrapTokenLookupPrefix(token),
        tokenHash: await hashBootstrapToken(token),
        method: normalizeMethod(request.method),
        path: normalizePath(request.path),
        allowedPaths: normalizeAllowedPaths(request.allowedPaths, request.path),
        origin: normalizeOrigin(request.origin),
        requestHashSha256: String(request.requestHashSha256 || '').trim() || null,
        maxUses: Math.max(1, Math.floor(Number(request.maxUses) || 1)),
        usedCount: 0,
        status: 'issued',
        riskDecision: String(request.riskDecision || '').trim() || 'allow',
        paymentReference:
          request.paymentReference == null ? null : String(request.paymentReference || '').trim(),
        replacementForTokenId:
          request.replacementForTokenId == null
            ? null
            : String(request.replacementForTokenId || '').trim(),
        issuedAt,
        expiresAt,
        redeemedAt: null,
        createdAt: issuedAt,
        updatedAt: issuedAt,
      };
      records.set(tokenId, record);
      return {
        token,
        record: cloneRecord(record),
      };
    },

    async countIssued(ctx, request): Promise<number> {
      const issuedSinceMs = request.issuedSince ? new Date(request.issuedSince).getTime() : null;
      let count = 0;
      for (const record of records.values()) {
        if (record.orgId !== ctx.orgId) continue;
        if (record.publishableKeyId !== request.publishableKeyId) continue;
        if (issuedSinceMs != null && new Date(record.issuedAt).getTime() < issuedSinceMs) continue;
        count += 1;
      }
      return count;
    },

    async peekTokenRecord(token): Promise<ConsoleBootstrapTokenRecord | null> {
      const parsed = parseBootstrapToken(token);
      if (!parsed) return null;
      const record = records.get(parsed.tokenId);
      if (!record || record.orgId !== parsed.orgId) return null;
      if (record.tokenHash !== (await hashBootstrapToken(token))) return null;
      return cloneRecord(record);
    },

    async redeemToken(request): Promise<RedeemConsoleBootstrapTokenResult> {
      const parsed = parseBootstrapToken(request.token);
      if (!parsed) {
        return {
          ok: false,
          status: 401,
          code: 'bootstrap_token_invalid',
          message: 'Invalid bootstrap token',
        };
      }
      const record = records.get(parsed.tokenId);
      if (!record || record.orgId !== parsed.orgId) {
        return {
          ok: false,
          status: 401,
          code: 'bootstrap_token_invalid',
          message: 'Invalid bootstrap token',
        };
      }
      const tokenHash = await hashBootstrapToken(request.token);
      if (record.tokenHash !== tokenHash) {
        return {
          ok: false,
          status: 401,
          code: 'bootstrap_token_invalid',
          message: 'Invalid bootstrap token',
        };
      }

      const currentNow = now();
      if (record.status === 'redeemed' || record.usedCount >= record.maxUses) {
        return {
          ok: false,
          status: 409,
          code: 'bootstrap_token_already_used',
          message: 'Bootstrap token has already been used',
        };
      }
      if (record.status === 'expired' || currentNow.getTime() >= new Date(record.expiresAt).getTime()) {
        if (record.status === 'issued') {
          record.status = 'expired';
          record.updatedAt = currentNow.toISOString();
        }
        return {
          ok: false,
          status: 401,
          code: 'bootstrap_token_expired',
          message: 'Bootstrap token has expired',
        };
      }

      const expectedOrigin = normalizeOrigin(request.origin);
      if (!expectedOrigin || record.origin !== expectedOrigin) {
        return {
          ok: false,
          status: 403,
          code: 'bootstrap_token_origin_mismatch',
          message: 'Bootstrap token origin does not match this request',
        };
      }
      if (
        record.method !== normalizeMethod(request.method) ||
        !record.allowedPaths.includes(normalizePath(request.path)) ||
        (record.requestHashSha256 &&
          record.requestHashSha256 !== String(request.requestHashSha256 || '').trim())
      ) {
        return {
          ok: false,
          status: 409,
          code: 'bootstrap_token_request_mismatch',
          message: 'Bootstrap token is not valid for this request payload',
        };
      }

      record.usedCount += 1;
      record.redeemedAt = currentNow.toISOString();
      record.updatedAt = record.redeemedAt;
      record.status = record.usedCount >= record.maxUses ? 'redeemed' : 'issued';
      return {
        ok: true,
        record: cloneRecord(record),
      };
    },
  };
}
