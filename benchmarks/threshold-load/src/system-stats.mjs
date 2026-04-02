import { monitorEventLoopDelay } from 'node:perf_hooks';

function percentile(sortedValues, fraction) {
  if (!sortedValues.length) return null;
  const idx = Math.min(
    sortedValues.length - 1,
    Math.max(0, Math.ceil(sortedValues.length * fraction) - 1),
  );
  return sortedValues[idx];
}

export function summarizeNumbers(values, decimals = 2) {
  const nums = values.filter((value) => Number.isFinite(value)).map((value) => Number(value));
  if (!nums.length) {
    return {
      count: 0,
      min: null,
      max: null,
      mean: null,
      p50: null,
      p95: null,
      p99: null,
    };
  }
  const sorted = [...nums].sort((a, b) => a - b);
  const total = nums.reduce((sum, value) => sum + value, 0);
  const round = (value) => Number(value.toFixed(decimals));
  return {
    count: nums.length,
    min: round(sorted[0]),
    max: round(sorted[sorted.length - 1]),
    mean: round(total / nums.length),
    p50: round(percentile(sorted, 0.5)),
    p95: round(percentile(sorted, 0.95)),
    p99: round(percentile(sorted, 0.99)),
  };
}

export function startSystemStatsCollector({ sampleIntervalMs = 250 } = {}) {
  const rssMb = [];
  const heapUsedMb = [];
  const eventLoopDelayMs = [];
  const histogram = monitorEventLoopDelay({ resolution: 20 });
  histogram.enable();

  const cpuStart = process.cpuUsage();
  const startedAtMs = Date.now();

  const collectOnce = () => {
    const mem = process.memoryUsage();
    rssMb.push(mem.rss / (1024 * 1024));
    heapUsedMb.push(mem.heapUsed / (1024 * 1024));
    eventLoopDelayMs.push(histogram.percentile(95) / 1e6);
    histogram.reset();
  };

  const timer = setInterval(() => {
    collectOnce();
  }, sampleIntervalMs);

  if (typeof timer.unref === 'function') {
    timer.unref();
  }

  return {
    stop() {
      clearInterval(timer);
      collectOnce();
      histogram.disable();
      const cpu = process.cpuUsage(cpuStart);
      return {
        sampleIntervalMs,
        durationMs: Math.max(0, Date.now() - startedAtMs),
        cpuUserMsTotal: Number((cpu.user / 1000).toFixed(2)),
        cpuSystemMsTotal: Number((cpu.system / 1000).toFixed(2)),
        rssMb: summarizeNumbers(rssMb),
        heapUsedMb: summarizeNumbers(heapUsedMb),
        eventLoopDelayMs: summarizeNumbers(eventLoopDelayMs),
      };
    },
  };
}
