function extractStringField(block, key) {
  const match = new RegExp(`${key}:\\s*'([^']*)'`).exec(block);
  return match ? match[1] : undefined;
}

function extractNumberField(block, key) {
  const match = new RegExp(`${key}:\\s*(-?\\d+(?:\\.\\d+)?)`).exec(block);
  if (!match) return undefined;
  const parsed = Number(match[1]);
  return Number.isFinite(parsed) ? parsed : undefined;
}

function extractBooleanField(block, key) {
  const match = new RegExp(`${key}:\\s*(true|false)`).exec(block);
  if (!match) return undefined;
  return match[1] === 'true';
}

function extractBlocks(logText, regex) {
  const blocks = [];
  for (const match of logText.matchAll(regex)) {
    if (match[1]) blocks.push(match[1]);
  }
  return blocks;
}

function extractJsonLineEntries(logText, prefix) {
  const entries = [];
  const lines = String(logText || '').split(/\r?\n/);
  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed.startsWith(prefix)) continue;
    const payload = trimmed.slice(prefix.length).trim();
    if (!payload) continue;
    try {
      const parsed = JSON.parse(payload);
      if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) {
        entries.push(parsed);
      }
    } catch {
      // ignore malformed entries
    }
  }
  return entries;
}

export function percentile(values, p) {
  if (!Array.isArray(values) || values.length === 0) return null;
  const sorted = [...values].sort((a, b) => a - b);
  const rank = Math.ceil((p / 100) * sorted.length) - 1;
  const idx = Math.max(0, Math.min(sorted.length - 1, rank));
  return sorted[idx];
}

function summarizeSeries(values) {
  const nums = values.filter((value) => Number.isFinite(value));
  if (nums.length === 0) return null;
  const total = nums.reduce((acc, value) => acc + value, 0);
  return {
    count: nums.length,
    min: Math.min(...nums),
    max: Math.max(...nums),
    mean: total / nums.length,
    p50: percentile(nums, 50),
    p95: percentile(nums, 95),
    p99: percentile(nums, 99),
  };
}

function summarizeByRoute(responseEvents) {
  const byRoute = new Map();
  for (const event of responseEvents) {
    if (!event.route || !Number.isFinite(event.durationMs)) continue;
    const list = byRoute.get(event.route) || [];
    list.push(event.durationMs);
    byRoute.set(event.route, list);
  }
  const out = {};
  for (const [route, values] of byRoute.entries()) {
    out[route] = summarizeSeries(values);
  }
  return out;
}

function summarizePresignStepPerf(perfEvents) {
  const totalMs = summarizeSeries(perfEvents.map((entry) => entry.totalMs).filter((v) => Number.isFinite(v)));
  const wasmStepMs = summarizeSeries(perfEvents.map((entry) => entry.wasmStepMs).filter((v) => Number.isFinite(v)));
  const liveResolveMs = summarizeSeries(perfEvents.map((entry) => entry.liveResolveMs).filter((v) => Number.isFinite(v)));
  const storeCasMs = summarizeSeries(perfEvents.map((entry) => entry.storeCasMs).filter((v) => Number.isFinite(v)));
  const counterLiveHits = perfEvents.reduce((acc, entry) => acc + (entry.presign_live_cache_hit === 1 ? 1 : 0), 0);
  const counterLiveMisses = perfEvents.reduce((acc, entry) => acc + (entry.presign_live_cache_miss === 1 ? 1 : 0), 0);
  const counterStaleSessions = perfEvents.reduce((acc, entry) => acc + (entry.presign_stale_session_state === 1 ? 1 : 0), 0);
  const liveHits = (counterLiveHits + counterLiveMisses) > 0
    ? counterLiveHits
    : perfEvents.filter((entry) => entry.liveCacheStatus === 'hit').length;
  const liveMisses = (counterLiveHits + counterLiveMisses) > 0
    ? counterLiveMisses
    : perfEvents.filter((entry) => entry.liveCacheStatus === 'miss').length;
  const staleSessions = counterStaleSessions > 0
    ? counterStaleSessions
    : perfEvents.filter((entry) => entry.resultCode === 'stale_session_state').length;
  const total = perfEvents.length;
  return {
    count: total,
    totalMs,
    wasmStepMs,
    liveResolveMs,
    storeCasMs,
    liveHits,
    liveMisses,
    staleSessions,
    counters: {
      presign_live_cache_hit: liveHits,
      presign_live_cache_miss: liveMisses,
      presign_stale_session_state: staleSessions,
    },
    liveHitRatio: total > 0 ? liveHits / total : null,
    staleSessionRatio: total > 0 ? staleSessions / total : null,
  };
}

function countPoolEmptyResponses(responseEvents) {
  return responseEvents.filter((event) => event.code === 'pool_empty').length;
}

function summarizeBackgroundPresignTraffic(requestEvents) {
  const presignStepRequests = requestEvents.filter((event) => event.route === '/threshold-ecdsa/presign/step');
  if (presignStepRequests.length === 0) {
    return { total: 0, background: 0, ratio: null };
  }
  const background = presignStepRequests.filter((event) =>
    event.requestTag === 'background_presign_pool_refill'
    || event.label === 'background presign pool refill'
    || event.presignTrafficClass === 'background'
  ).length;
  return {
    total: presignStepRequests.length,
    background,
    ratio: background / presignStepRequests.length,
  };
}

function summarizePresignGateWait(requestEvents) {
  const presignRequests = requestEvents.filter((event) =>
    event.route === '/threshold-ecdsa/presign/init'
    || event.route === '/threshold-ecdsa/presign/step'
  );
  const allGateWait = presignRequests.map((event) => event.gateWaitMs).filter((v) => Number.isFinite(v));
  const foregroundGateWait = presignRequests
    .filter((event) => event.presignTrafficClass === 'foreground')
    .map((event) => event.gateWaitMs)
    .filter((v) => Number.isFinite(v));
  const backgroundGateWait = presignRequests
    .filter((event) => event.presignTrafficClass === 'background')
    .map((event) => event.gateWaitMs)
    .filter((v) => Number.isFinite(v));
  return {
    overall: summarizeSeries(allGateWait),
    foreground: summarizeSeries(foregroundGateWait),
    background: summarizeSeries(backgroundGateWait),
  };
}

export function collectMetricsFromLog(logText) {
  const requestBlocks = extractBlocks(logText, /\[threshold-ecdsa\]\s+request\s*\{([\s\S]*?)\}/g);
  const responseBlocks = extractBlocks(logText, /\[threshold-ecdsa\]\s+response\s*\{([\s\S]*?)\}/g);
  const perfBlocks = extractBlocks(logText, /\[threshold-ecdsa\]\s+presign\/step perf\s*\{([\s\S]*?)\}/g);
  const scenarioSummaryEntries = extractJsonLineEntries(logText, '[benchmark-scenario-json]');
  const scenarioSummary = scenarioSummaryEntries.length > 0
    ? scenarioSummaryEntries[scenarioSummaryEntries.length - 1]
    : null;
  const scenarioRuns = Array.isArray(scenarioSummary?.runs) ? scenarioSummary.runs : [];
  const scenarioTotalMs = summarizeSeries(
    scenarioRuns
      .map((entry) => Number(entry?.totalMs))
      .filter((value) => Number.isFinite(value)),
  );

  const requestEvents = requestBlocks.map((block) => ({
    route: extractStringField(block, 'route'),
    requestTag: extractStringField(block, 'requestTag'),
    label: extractStringField(block, 'label'),
    presignTrafficClass: extractStringField(block, 'presignTrafficClass'),
    gateWaitMs: extractNumberField(block, 'gateWaitMs'),
    gateQueuedDepth: extractNumberField(block, 'gateQueuedDepth'),
  }));

  const responseEvents = responseBlocks.map((block) => ({
    route: extractStringField(block, 'route'),
    durationMs: extractNumberField(block, 'durationMs'),
    code: extractStringField(block, 'code'),
    ok: extractBooleanField(block, 'ok'),
  }));

  const perfEvents = perfBlocks.map((block) => ({
    requestedStage: extractStringField(block, 'requestedStage'),
    totalMs: extractNumberField(block, 'totalMs'),
    wasmStepMs: extractNumberField(block, 'wasmStepMs'),
    liveResolveMs: extractNumberField(block, 'liveResolveMs'),
    storeCasMs: extractNumberField(block, 'storeCasMs'),
    presign_live_cache_hit: extractNumberField(block, 'presign_live_cache_hit'),
    presign_live_cache_miss: extractNumberField(block, 'presign_live_cache_miss'),
    presign_stale_session_state: extractNumberField(block, 'presign_stale_session_state'),
    liveCacheStatus: extractStringField(block, 'liveCacheStatus'),
    liveCacheMissReason: extractStringField(block, 'liveCacheMissReason'),
    casCode: extractStringField(block, 'casCode'),
    resultCode: extractStringField(block, 'resultCode'),
  }));

  return {
    requestEvents,
    responseEvents,
    perfEvents,
    scenarioSummary,
    scenarioTotalMs,
    routeDurations: summarizeByRoute(responseEvents),
    presignStepPerf: summarizePresignStepPerf(perfEvents),
    backgroundPresignTraffic: summarizeBackgroundPresignTraffic(requestEvents),
    presignGateWait: summarizePresignGateWait(requestEvents),
    poolEmptyResponses: countPoolEmptyResponses(responseEvents),
  };
}
