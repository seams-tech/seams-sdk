import type { SigningSessionReadiness } from './planner';
import { SigningSessionIds } from '../operationState/types';

const thresholdSessionId = SigningSessionIds.thresholdEd25519Session('threshold-session-1');

const readyReadiness: SigningSessionReadiness = {
  status: 'ready',
  thresholdSessionId,
  remainingUses: 1,
  expiresAtMs: 1_900_000_000_000,
};
void readyReadiness;

// @ts-expect-error ready readiness requires remaining budget uses.
const readyReadinessMissingRemainingUses: SigningSessionReadiness = {
  status: 'ready',
  thresholdSessionId,
  expiresAtMs: 1_900_000_000_000,
};
void readyReadinessMissingRemainingUses;

// @ts-expect-error ready readiness requires expiry.
const readyReadinessMissingExpiry: SigningSessionReadiness = {
  status: 'ready',
  thresholdSessionId,
  remainingUses: 1,
};
void readyReadinessMissingExpiry;

const exhaustedReadiness: SigningSessionReadiness = {
  status: 'exhausted',
  thresholdSessionId,
  remainingUses: 0,
  expiresAtMs: 1_900_000_000_000,
};
void exhaustedReadiness;

// @ts-expect-error exhausted readiness requires expiry for stale-status handling.
const exhaustedReadinessMissingExpiry: SigningSessionReadiness = {
  status: 'exhausted',
  thresholdSessionId,
  remainingUses: 0,
};
void exhaustedReadinessMissingExpiry;

const expiredReadiness: SigningSessionReadiness = {
  status: 'expired',
  thresholdSessionId,
  expiresAtMs: 1,
};
void expiredReadiness;

type ActiveSigningSessionReadiness = Extract<SigningSessionReadiness, { status: 'ready' }>;

function requireActiveSigningSession(_readiness: ActiveSigningSessionReadiness): void {}

requireActiveSigningSession(readyReadiness);

// @ts-expect-error expired readiness cannot cross an active-session boundary.
requireActiveSigningSession(expiredReadiness);

// @ts-expect-error expired readiness does not carry remaining uses.
const expiredReadinessWithRemainingUses: SigningSessionReadiness = {
  status: 'expired',
  thresholdSessionId,
  expiresAtMs: 1,
  remainingUses: 0,
};
void expiredReadinessWithRemainingUses;

// @ts-expect-error missing readiness does not carry budget facts.
const missingReadinessWithBudget: SigningSessionReadiness = {
  status: 'missing_session',
  thresholdSessionId,
  remainingUses: 0,
};
void missingReadinessWithBudget;

// @ts-expect-error unavailable readiness does not carry expiry.
const unavailableReadinessWithExpiry: SigningSessionReadiness = {
  status: 'status_unavailable',
  thresholdSessionId,
  expiresAtMs: 1_900_000_000_000,
};
void unavailableReadinessWithExpiry;

export {};
