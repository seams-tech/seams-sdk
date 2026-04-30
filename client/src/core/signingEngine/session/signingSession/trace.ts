import type { SigningLaneContext, SigningLaneSummary } from './types';
import { summarizeSigningLane } from './types';
import type { SigningPlannerDecisionTraceEvent } from './planner';

export type SigningSessionTraceScope = 'evm-family' | 'near';

export type SigningLaneResolutionTraceEvent = {
  event: 'signing_lane_resolved';
  lane: SigningLaneSummary;
  reason?: string;
};

export type SigningBoundaryTraceEvent = {
  event: 'pre_confirm_readiness_checked' | 'auth_side_effect_started';
  lane?: SigningLaneSummary;
  readinessStatus?: string;
  sideEffect?: 'email_otp_challenge' | 'passkey_reauth' | 'threshold_reconnect';
  phase: 'pre_confirm' | 'confirmed';
};

export function emitSigningLaneResolutionTrace(
  scope: SigningSessionTraceScope,
  lane: SigningLaneContext | null | undefined,
  args: { reason?: string } = {},
): void {
  if (!lane || !isSigningSessionTraceEnabled()) return;

  try {
    console.debug(`[SigningLane][${scope}]`, {
      event: 'signing_lane_resolved',
      lane: summarizeSigningLane(lane),
      ...(args.reason ? { reason: args.reason } : {}),
    } satisfies SigningLaneResolutionTraceEvent);
  } catch {}
}

export function emitSigningBoundaryTrace(
  scope: SigningSessionTraceScope,
  event: SigningBoundaryTraceEvent,
): void {
  if (!isSigningSessionTraceEnabled()) return;

  try {
    console.debug(`[SigningBoundary][${scope}]`, event);
  } catch {}
}

export function createSigningBoundaryTraceEvent(args: {
  event: SigningBoundaryTraceEvent['event'];
  lane?: SigningLaneContext | null;
  readinessStatus?: string;
  sideEffect?: SigningBoundaryTraceEvent['sideEffect'];
  phase: SigningBoundaryTraceEvent['phase'];
}): SigningBoundaryTraceEvent {
  return {
    event: args.event,
    ...(args.lane ? { lane: summarizeSigningLane(args.lane) } : {}),
    ...(args.readinessStatus ? { readinessStatus: args.readinessStatus } : {}),
    ...(args.sideEffect ? { sideEffect: args.sideEffect } : {}),
    phase: args.phase,
  };
}

export function emitSigningPlannerDecisionTrace(
  scope: SigningSessionTraceScope,
  event: SigningPlannerDecisionTraceEvent,
): void {
  if (!isSigningSessionTraceEnabled()) return;

  try {
    console.debug(`[SigningSessionPlanner][${scope}]`, event);
  } catch {}
}

function isSigningSessionTraceEnabled(): boolean {
  try {
    const storage = (globalThis as { localStorage?: Storage }).localStorage;
    return storage?.getItem('seams:debug:signing-session') === '1';
  } catch {
    return false;
  }
}
