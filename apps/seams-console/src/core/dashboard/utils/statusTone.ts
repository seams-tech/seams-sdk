import type { DashboardTableTone } from '@core/dashboard/components/DashboardTable';

/* Wire statuses arrive as SCREAMING_SNAKE enums. Rendering them raw is what
   makes a table read like a database dump, so every surface routes them
   through here: one tone map, one label case. */

const SUCCESS_STATUSES = new Set([
  'ACTIVE',
  'HEALTHY',
  'DELIVERED',
  'ENABLED',
  'PUBLISHED',
  'RESOLVED',
  'ACCEPTED',
  'COMPLETED',
  'APPROVED',
]);

const WARNING_STATUSES = new Set([
  'DEGRADED',
  'PAUSED',
  'RETRYING',
  'PENDING',
  'SUSPENDED',
  'DRAFT',
  'EXPIRED',
  'WARN',
  'UNKNOWN',
]);

const DANGER_STATUSES = new Set([
  'FAILING',
  'FAILED',
  'REVOKED',
  'FROZEN',
  'REMOVED',
  'ARCHIVED',
  'DECLINED',
  'DISABLED',
  'ERROR',
  'FATAL',
  'DEAD_LETTER',
]);

export function dashboardStatusTone(raw: string): DashboardTableTone {
  const key = String(raw || '')
    .trim()
    .toUpperCase();
  if (SUCCESS_STATUSES.has(key)) return 'success';
  if (WARNING_STATUSES.has(key)) return 'warning';
  if (DANGER_STATUSES.has(key)) return 'danger';
  return 'neutral';
}

/** `DEAD_LETTER` -> `Dead letter`, `active` -> `Active`, `Healthy` -> `Healthy`. */
export function dashboardStatusLabel(raw: string): string {
  const value = String(raw || '').trim();
  if (!value) return '';
  // Only flatten case for wire enums; a label that already carries mixed case
  // was written by a human and keeps its own capitalisation.
  const normalized = value === value.toUpperCase() ? value.toLowerCase() : value;
  const words = normalized.split(/[_\s]+/).filter(Boolean);
  if (words.length === 0) return '';
  const [first, ...rest] = words;
  return [`${first.charAt(0).toUpperCase()}${first.slice(1)}`, ...rest].join(' ');
}

/** Placeholder for an absent value. An em dash reads as "none", `-` as a typo. */
export const DASHBOARD_EMPTY_VALUE = '—';
