import { resolveConsoleObservabilityRequestMetricPolicy } from './policy';
import type { ConsoleObservabilityRequestMetricInput } from './types';

export const REQUEST_ROLLUP_WINDOW_MS = 60_000;
export const REQUEST_ROLLUP_BUCKET_UPPER_BOUNDS_MS = [50, 100, 250, 500, 1000, 2000, 5000] as const;
export const REQUEST_ROLLUP_BUCKET_COLUMN_NAMES = [
  'latency_bucket_le_50',
  'latency_bucket_le_100',
  'latency_bucket_le_250',
  'latency_bucket_le_500',
  'latency_bucket_le_1000',
  'latency_bucket_le_2000',
  'latency_bucket_le_5000',
] as const;

export interface NormalizedConsoleObservabilityRequestMetric {
  timestampMs: number;
  projectId: string;
  environmentId: string;
  service: string;
  routeFamily: string;
  method: string;
  statusCode: number;
  statusClass: string;
  latencyMs: number;
  errorCount: number;
  histogramCounts: number[];
}

function normalizeString(raw: unknown): string {
  return String(raw || '').trim();
}

function parseIsoToMs(raw: unknown): number | null {
  const value = normalizeString(raw);
  if (!value) return null;
  const parsed = Date.parse(value);
  if (!Number.isFinite(parsed)) return null;
  return Math.floor(parsed);
}

function nowMs(now: Date): number {
  return now.getTime();
}

function toStatusClass(statusCode: number): string {
  if (statusCode >= 500) return '5xx';
  if (statusCode >= 400) return '4xx';
  if (statusCode >= 300) return '3xx';
  if (statusCode >= 200) return '2xx';
  if (statusCode >= 100) return '1xx';
  return '0xx';
}

export function toConsoleObservabilityRouteFamily(route: string): string {
  const path = normalizeString(route).split('?')[0] || '/';
  const normalizedPath = path.startsWith('/') ? path : `/${path}`;
  const parts = normalizedPath.split('/').filter(Boolean);
  if (parts.length === 0) return '/';
  if (parts[0] !== 'console') return '/other/*';
  if (parts.length === 1) return '/console/*';
  return `/console/${parts[1]}/*`;
}

export function shouldCaptureConsoleObservabilityRequestMetric(input: {
  routeFamily: string;
  method: string;
  statusCode: number;
}): boolean {
  const method = normalizeString(input.method).toUpperCase();
  if (!method || method === 'OPTIONS') return false;
  if ((method === 'GET' || method === 'HEAD') && input.statusCode < 400) return false;
  return resolveConsoleObservabilityRequestMetricPolicy(input.routeFamily) !== null;
}

export function buildConsoleObservabilityLatencyHistogramCounts(latencyMs: number): number[] {
  const counts = REQUEST_ROLLUP_BUCKET_UPPER_BOUNDS_MS.map(() => 0);
  for (let idx = 0; idx < REQUEST_ROLLUP_BUCKET_UPPER_BOUNDS_MS.length; idx += 1) {
    if (latencyMs <= REQUEST_ROLLUP_BUCKET_UPPER_BOUNDS_MS[idx]) {
      counts[idx] = 1;
      return counts;
    }
  }
  counts[counts.length - 1] = 1;
  return counts;
}

export function percentileFromConsoleObservabilityHistogram(
  counts: number[],
  quantile: number,
): number {
  const total = counts.reduce((sum, value) => sum + Math.max(0, Math.floor(value)), 0);
  if (total <= 0) return 0;
  const threshold = Math.max(1, Math.ceil(total * quantile));
  let cumulative = 0;
  for (let idx = 0; idx < REQUEST_ROLLUP_BUCKET_UPPER_BOUNDS_MS.length; idx += 1) {
    cumulative += Math.max(0, Math.floor(counts[idx] || 0));
    if (cumulative >= threshold) {
      return REQUEST_ROLLUP_BUCKET_UPPER_BOUNDS_MS[idx];
    }
  }
  return REQUEST_ROLLUP_BUCKET_UPPER_BOUNDS_MS[REQUEST_ROLLUP_BUCKET_UPPER_BOUNDS_MS.length - 1];
}

export function normalizeConsoleObservabilityRequestMetricForInsert(
  input: ConsoleObservabilityRequestMetricInput,
): NormalizedConsoleObservabilityRequestMetric | null {
  const route = normalizeString(input.route);
  const method = normalizeString(input.method).toUpperCase();
  const statusCode = Math.max(0, Math.floor(Number(input.statusCode || 0)));
  const latencyMs = Math.max(0, Number(input.latencyMs || 0));
  const timestampMs = parseIsoToMs(input.timestamp) ?? nowMs(new Date());
  const routeFamily = toConsoleObservabilityRouteFamily(route);
  const policy = resolveConsoleObservabilityRequestMetricPolicy(routeFamily);
  if (
    !policy ||
    !shouldCaptureConsoleObservabilityRequestMetric({ routeFamily, method, statusCode })
  ) {
    return null;
  }
  return {
    timestampMs,
    projectId: normalizeString(input.projectId),
    environmentId: normalizeString(input.environmentId),
    service: policy.service,
    routeFamily,
    method,
    statusCode,
    statusClass: toStatusClass(statusCode),
    latencyMs,
    errorCount: statusCode >= 500 ? 1 : 0,
    histogramCounts: buildConsoleObservabilityLatencyHistogramCounts(latencyMs),
  };
}
