/* Single console-wide timestamp format: short month, day, minute precision.
   Seconds are never useful at dashboard granularity and they overflow cells. */

const DASHBOARD_TIMESTAMP_FORMAT = new Intl.DateTimeFormat('en-US', {
  month: 'short',
  day: 'numeric',
  year: 'numeric',
  hour: 'numeric',
  minute: '2-digit',
});

const DASHBOARD_DATE_FORMAT = new Intl.DateTimeFormat('en-US', {
  month: 'short',
  day: 'numeric',
  year: 'numeric',
});

function toDate(value: string | number | Date | null | undefined): Date | null {
  if (value === null || value === undefined || value === '') return null;
  const date = value instanceof Date ? value : new Date(value);
  return Number.isNaN(date.getTime()) ? null : date;
}

export function formatDashboardTimestamp(
  value: string | number | Date | null | undefined,
  fallback = '—',
): string {
  const date = toDate(value);
  return date ? DASHBOARD_TIMESTAMP_FORMAT.format(date) : fallback;
}

export function formatDashboardDate(
  value: string | number | Date | null | undefined,
  fallback = '—',
): string {
  const date = toDate(value);
  return date ? DASHBOARD_DATE_FORMAT.format(date) : fallback;
}
