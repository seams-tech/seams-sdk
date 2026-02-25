export const SCENARIOS = [
  {
    id: 'cold_first_sign_no_pool',
    description: 'First sign with empty presign pool',
    commandEnv: 'BENCH_CMD_COLD_FIRST_SIGN_NO_POOL',
    defaultCommand: 'node ./benchmarks/threshold-ecdsa-presign/src/scenario-harness.mjs --scenario cold_first_sign_no_pool --iterations 2',
  },
  {
    id: 'warm_sign_pool_hit',
    description: 'Warm sign with available presign pool entry',
    commandEnv: 'BENCH_CMD_WARM_SIGN_POOL_HIT',
    defaultCommand: 'node ./benchmarks/threshold-ecdsa-presign/src/scenario-harness.mjs --scenario warm_sign_pool_hit --iterations 2',
  },
  {
    id: 'background_refill_contention',
    description: 'Foreground sign while background refill traffic is active',
    commandEnv: 'BENCH_CMD_BACKGROUND_REFILL_CONTENTION',
    defaultCommand: 'node ./benchmarks/threshold-ecdsa-presign/src/scenario-harness.mjs --scenario background_refill_contention --iterations 2',
  },
  {
    id: 'multi_runtime_contention',
    description: 'Duplicate runtime pressure (host + iframe/tab style)',
    commandEnv: 'BENCH_CMD_MULTI_RUNTIME_CONTENTION',
    defaultCommand: 'node ./benchmarks/threshold-ecdsa-presign/src/scenario-harness.mjs --scenario multi_runtime_contention --iterations 2',
  },
  {
    id: 'store_backend_compare',
    description: 'Store backend benchmark (Postgres vs Redis/Upstash)',
    commandEnv: 'BENCH_CMD_STORE_BACKEND_COMPARE',
    defaultCommand: 'node ./benchmarks/threshold-ecdsa-presign/src/scenario-harness.mjs --scenario store_backend_compare --iterations 2',
  },
  {
    id: 'live_cache_miss_path',
    description: 'Force live-cache miss and stale-session retry path',
    commandEnv: 'BENCH_CMD_LIVE_CACHE_MISS_PATH',
    defaultCommand: 'node ./benchmarks/threshold-ecdsa-presign/src/scenario-harness.mjs --scenario live_cache_miss_path --iterations 2',
  },
];

export function resolveScenarioById(id) {
  return SCENARIOS.find((entry) => entry.id === id) || null;
}

export function resolveScenarioCommand(scenario, env = process.env) {
  const raw = String(env[scenario.commandEnv] || '').trim();
  if (raw) return raw;
  return String(scenario.defaultCommand || '').trim() || null;
}
