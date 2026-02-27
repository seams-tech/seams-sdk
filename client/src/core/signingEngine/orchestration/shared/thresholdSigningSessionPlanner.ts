import type { SigningAuthMode } from '@/core/signingEngine/touchConfirm/shared/confirmTypes';
import type {
  ThresholdPrfCachePeekResult,
  ThresholdPrfFirstCachePeekPort,
} from '@/core/signingEngine/touchConfirm';
import { normalizeBoundedPositiveInteger } from '@shared/utils/normalize';

export const THRESHOLD_SESSION_MISSING_ERROR =
  '[chains] Missing threshold signingSessionId; reconnect threshold session before signing';
export const THRESHOLD_SESSION_EXHAUSTED_ERROR =
  '[chains] threshold signingSession is exhausted; reconnect threshold session before signing';

function toThresholdSessionStatusError(code: string): string {
  return `[chains] threshold signingSession is ${code}; reconnect threshold session before signing`;
}

function normalizeUsesNeeded(usesNeeded?: number): number {
  return normalizeBoundedPositiveInteger(usesNeeded, {
    fallback: 1,
    min: 1,
  });
}

function toSessionId(value: unknown): string {
  return typeof value === 'string' ? value.trim() : '';
}

export function requireThresholdSigningSessionId(sessionIdRaw: unknown): string {
  const sessionId = toSessionId(sessionIdRaw);
  if (!sessionId) {
    throw new Error(THRESHOLD_SESSION_MISSING_ERROR);
  }
  return sessionId;
}

function toExhaustedPeekResult(): Extract<ThresholdPrfCachePeekResult, { ok: false }> {
  return {
    ok: false,
    code: 'exhausted',
    message: THRESHOLD_SESSION_EXHAUSTED_ERROR,
  };
}

export async function peekThresholdSigningSessionReadiness(args: {
  touchConfirm: ThresholdPrfFirstCachePeekPort;
  sessionId: string;
  usesNeeded?: number;
}): Promise<ThresholdPrfCachePeekResult> {
  const peek = await args.touchConfirm.peekPrfFirstForThresholdSession({
    sessionId: args.sessionId,
  });
  if (!peek.ok) {
    return {
      ok: false,
      code: peek.code,
      message: toThresholdSessionStatusError(peek.code),
    };
  }

  if (peek.remainingUses < normalizeUsesNeeded(args.usesNeeded)) {
    return toExhaustedPeekResult();
  }
  return peek;
}

export async function isThresholdSigningSessionReady(args: {
  touchConfirm: ThresholdPrfFirstCachePeekPort;
  sessionId: string;
  usesNeeded?: number;
}): Promise<boolean> {
  const sessionId = toSessionId(args.sessionId);
  if (!sessionId) return false;
  const peek = await peekThresholdSigningSessionReadiness({
    touchConfirm: args.touchConfirm,
    sessionId,
    usesNeeded: args.usesNeeded,
  });
  return peek.ok;
}

export async function assertThresholdSigningSessionReady(args: {
  touchConfirm: ThresholdPrfFirstCachePeekPort;
  sessionId: unknown;
  usesNeeded?: number;
}): Promise<Extract<ThresholdPrfCachePeekResult, { ok: true }>> {
  const sessionId = requireThresholdSigningSessionId(args.sessionId);
  const peek = await peekThresholdSigningSessionReadiness({
    touchConfirm: args.touchConfirm,
    sessionId,
    usesNeeded: args.usesNeeded,
  });
  if (!peek.ok) {
    throw new Error(peek.message || toThresholdSessionStatusError(peek.code));
  }
  return peek;
}

export async function resolveThresholdSigningAuthMode(args: {
  needsWebAuthn: boolean;
  touchConfirm: ThresholdPrfFirstCachePeekPort;
  sessionId: unknown;
  usesNeeded?: number;
}): Promise<SigningAuthMode> {
  if (args.needsWebAuthn) return 'webauthn';
  return 'warmSession';
}
