import type { DashboardConsoleAuditEvent } from './consoleAuditApi';

/* The audit toolbar reads a window of time rather than two free-typed
   instants: a preset names the span, and the window slides over it. Every
   value here is epoch milliseconds so the chart, the query, and the stepper
   all share one representation. */

export type AuditRangePresetId = 'hour' | 'day' | 'week' | 'month';

export interface AuditTimeRange {
  fromMs: number;
  toMs: number;
}

export interface AuditRangePreset {
  id: AuditRangePresetId;
  label: string;
  durationMs: number;
}

const MINUTE_MS = 60_000;
const HOUR_MS = 60 * MINUTE_MS;
const DAY_MS = 24 * HOUR_MS;

export const AUDIT_RANGE_PRESETS: readonly AuditRangePreset[] = [
  { id: 'hour', label: 'Last hour', durationMs: HOUR_MS },
  { id: 'day', label: 'Last 24 hours', durationMs: DAY_MS },
  { id: 'week', label: 'Last 7 days', durationMs: 7 * DAY_MS },
  { id: 'month', label: 'Last 30 days', durationMs: 30 * DAY_MS },
];

export const DEFAULT_AUDIT_RANGE_PRESET_ID: AuditRangePresetId = 'week';

export function auditRangePreset(id: AuditRangePresetId): AuditRangePreset {
  return (
    AUDIT_RANGE_PRESETS.find((entry) => entry.id === id) ||
    AUDIT_RANGE_PRESETS[AUDIT_RANGE_PRESETS.length - 1]
  );
}

export function auditRangeFromPreset(id: AuditRangePresetId, nowMs: number): AuditTimeRange {
  const preset = auditRangePreset(id);
  return { fromMs: nowMs - preset.durationMs, toMs: nowMs };
}

/* The window is the single source of truth, so its label is read back off
   the span rather than tracked beside it: focusing on a drag selection or
   jumping to an instant then cannot leave a stale preset name on screen. */
export function auditRangeSpanPreset(range: AuditTimeRange): AuditRangePreset | null {
  const span = range.toMs - range.fromMs;
  return AUDIT_RANGE_PRESETS.find((entry) => entry.durationMs === span) || null;
}

function formatSpanLabel(spanMs: number): string {
  const round = (value: number) => Math.max(1, Math.round(value));
  if (spanMs < 90 * MINUTE_MS) {
    const minutes = round(spanMs / MINUTE_MS);
    return `${minutes} ${minutes === 1 ? 'minute' : 'minutes'}`;
  }
  if (spanMs < 36 * HOUR_MS) {
    const hours = round(spanMs / HOUR_MS);
    return `${hours} ${hours === 1 ? 'hour' : 'hours'}`;
  }
  const days = round(spanMs / DAY_MS);
  return `${days} ${days === 1 ? 'day' : 'days'}`;
}

/* A window ending at the present is "Last 7 days"; the same span stepped
   back into history is just "7 days", because it is no longer the last
   anything. The tolerance absorbs the seconds between the clock tick that
   built the range and the one rendering it. */
export function auditRangeLabel(range: AuditTimeRange, nowMs: number): string {
  const spanMs = Math.max(1, range.toMs - range.fromMs);
  const endsNow = nowMs - range.toMs < Math.min(MINUTE_MS, spanMs / 20);
  const preset = auditRangeSpanPreset(range);
  if (preset) return endsNow ? preset.label : formatSpanLabel(spanMs);
  return endsNow ? `Last ${formatSpanLabel(spanMs)}` : formatSpanLabel(spanMs);
}

/* Stepping keeps the span fixed and slides the window, so "‹" always shows
   the same amount of history one window earlier. The window never runs past
   the present: there is nothing recorded after now, and letting it scroll
   forward would only produce empty plots. */
export function shiftAuditRange(
  range: AuditTimeRange,
  direction: -1 | 1,
  nowMs: number,
): AuditTimeRange {
  const span = Math.max(1, range.toMs - range.fromMs);
  const toMs = Math.min(range.toMs + direction * span, nowMs);
  return { fromMs: toMs - span, toMs };
}

export function canStepAuditRangeForward(range: AuditTimeRange, nowMs: number): boolean {
  return range.toMs < nowMs;
}

/* Recentre the window on one instant, clamped so it stays in the past. */
export function centreAuditRange(
  range: AuditTimeRange,
  atMs: number,
  nowMs: number,
): AuditTimeRange {
  const span = Math.max(1, range.toMs - range.fromMs);
  const toMs = Math.min(atMs + span / 2, nowMs);
  return { fromMs: toMs - span, toMs };
}

export function formatUtcOffsetLabel(atMs: number): string {
  const offsetMinutes = -new Date(atMs).getTimezoneOffset();
  const sign = offsetMinutes < 0 ? '-' : '+';
  const absolute = Math.abs(offsetMinutes);
  const hours = Math.floor(absolute / 60);
  const minutes = absolute % 60;
  return minutes ? `UTC${sign}${hours}:${String(minutes).padStart(2, '0')}` : `UTC${sign}${hours}`;
}

export interface AuditActivityBin {
  startMs: number;
  endMs: number;
  total: number;
  failures: number;
}

export function bucketAuditActivity(
  events: readonly DashboardConsoleAuditEvent[],
  range: AuditTimeRange,
  binCount: number,
): AuditActivityBin[] {
  const span = Math.max(1, range.toMs - range.fromMs);
  const count = Math.max(1, Math.floor(binCount));
  const width = span / count;
  const bins: AuditActivityBin[] = Array.from({ length: count }, (_unused, index) => ({
    startMs: range.fromMs + index * width,
    endMs: range.fromMs + (index + 1) * width,
    total: 0,
    failures: 0,
  }));

  for (const event of events) {
    const atMs = Date.parse(event.createdAt);
    if (!Number.isFinite(atMs)) continue;
    if (atMs < range.fromMs || atMs > range.toMs) continue;
    /* The final bin is closed at both ends so an event landing exactly on
       `toMs` counts instead of indexing one past the array. */
    const index = Math.min(count - 1, Math.floor((atMs - range.fromMs) / width));
    const bin = bins[index];
    if (!bin) continue;
    bin.total += 1;
    if (event.outcome === 'FAILURE') bin.failures += 1;
  }

  return bins;
}

export interface AuditActivityAxis {
  max: number;
  ticks: readonly number[];
}

/* A 1/2/5×10ⁿ ceiling keeps the midpoint tick a whole number, so the axis
   reads 0/50/100 rather than 0/41.5/83. */
function niceCeiling(value: number): number {
  if (value <= 0) return 0;
  const magnitude = 10 ** Math.floor(Math.log10(value));
  for (const step of [1, 2, 5, 10]) {
    const candidate = step * magnitude;
    if (candidate >= value) return candidate;
  }
  return 10 * magnitude;
}

export function auditActivityAxis(bins: readonly AuditActivityBin[]): AuditActivityAxis {
  const peak = bins.reduce((current, bin) => Math.max(current, bin.total), 0);
  if (peak <= 0) return { max: 1, ticks: [1, 0] };
  const max = Math.max(1, niceCeiling(peak));
  const midpoint = max / 2;
  /* Drop the midpoint when halving would repeat a tick (max of 1). */
  return Number.isInteger(midpoint) && midpoint > 0 && midpoint < max
    ? { max, ticks: [max, midpoint, 0] }
    : { max, ticks: [max, 0] };
}

export function clampAuditRangeToSpan(
  selection: AuditTimeRange,
  range: AuditTimeRange,
): AuditTimeRange {
  const fromMs = Math.max(range.fromMs, Math.min(selection.fromMs, selection.toMs));
  const toMs = Math.min(range.toMs, Math.max(selection.fromMs, selection.toMs));
  return { fromMs, toMs };
}

/* `datetime-local` reads and writes wall-clock text with no zone, so both
   directions go through the local-time parts rather than through ISO. */
export function toDateTimeLocalInput(atMs: number): string {
  const date = new Date(atMs);
  if (Number.isNaN(date.getTime())) return '';
  const pad = (value: number) => String(value).padStart(2, '0');
  return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())}T${pad(
    date.getHours(),
  )}:${pad(date.getMinutes())}`;
}

export function fromDateTimeLocalInput(value: string): number | null {
  const trimmed = String(value || '').trim();
  if (!trimmed) return null;
  const parsed = Date.parse(trimmed);
  return Number.isFinite(parsed) ? parsed : null;
}
