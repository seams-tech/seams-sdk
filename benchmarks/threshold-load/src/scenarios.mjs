export const SCENARIOS = [
  {
    id: 'ed25519_local_steady_smoke',
    description: 'Threshold Ed25519 local warm-session steady-state smoke profile',
    groups: ['ed25519', 'smoke'],
    commandEnv: 'BENCH_CMD_ED25519_LOCAL_STEADY_SMOKE',
    defaultCommand:
      'pnpm exec tsx --tsconfig ./client/tsconfig.json ./benchmarks/threshold-load/src/scenario-harness.ts --scenario ed25519_local_steady --wallets 6 --signs-per-wallet 2 --max-concurrency 3 --profile steady',
  },
  {
    id: 'ed25519_local_burst_smoke',
    description: 'Threshold Ed25519 local warm-session synchronized burst smoke profile',
    groups: ['ed25519', 'smoke'],
    commandEnv: 'BENCH_CMD_ED25519_LOCAL_BURST_SMOKE',
    defaultCommand:
      'pnpm exec tsx --tsconfig ./client/tsconfig.json ./benchmarks/threshold-load/src/scenario-harness.ts --scenario ed25519_local_burst --wallets 8 --signs-per-wallet 1 --max-concurrency 8 --profile burst',
  },
  {
    id: 'ed25519_local_presign_pool_hit_smoke',
    description: 'Threshold Ed25519 local presign pool-hit finalize-and-dispatch smoke profile',
    groups: ['ed25519', 'smoke', 'presign'],
    commandEnv: 'BENCH_CMD_ED25519_LOCAL_PRESIGN_POOL_HIT_SMOKE',
    defaultCommand:
      'pnpm exec tsx --tsconfig ./client/tsconfig.json ./benchmarks/threshold-load/src/scenario-harness.ts --scenario ed25519_local_presign_pool_hit --wallets 6 --signs-per-wallet 2 --max-concurrency 3 --profile steady',
  },
  {
    id: 'ed25519_local_presign_pool_miss_smoke',
    description: 'Threshold Ed25519 local depleted-pool two-RTT fallback smoke profile',
    groups: ['ed25519', 'smoke', 'presign'],
    commandEnv: 'BENCH_CMD_ED25519_LOCAL_PRESIGN_POOL_MISS_SMOKE',
    defaultCommand:
      'pnpm exec tsx --tsconfig ./client/tsconfig.json ./benchmarks/threshold-load/src/scenario-harness.ts --scenario ed25519_local_presign_pool_miss --wallets 6 --signs-per-wallet 2 --max-concurrency 3 --profile steady',
  },
  {
    id: 'ed25519_local_presign_refill_smoke',
    description: 'Threshold Ed25519 local presign refill smoke profile',
    groups: ['ed25519', 'smoke', 'presign'],
    commandEnv: 'BENCH_CMD_ED25519_LOCAL_PRESIGN_REFILL_SMOKE',
    defaultCommand:
      'pnpm exec tsx --tsconfig ./client/tsconfig.json ./benchmarks/threshold-load/src/scenario-harness.ts --scenario ed25519_local_presign_refill --wallets 6 --signs-per-wallet 2 --max-concurrency 3 --profile steady',
  },
  {
    id: 'ed25519_local_presign_refill_pressure_smoke',
    description: 'Threshold Ed25519 local authenticated presign refill pressure smoke profile',
    groups: ['ed25519', 'smoke', 'presign', 'pressure'],
    commandEnv: 'BENCH_CMD_ED25519_LOCAL_PRESIGN_REFILL_PRESSURE_SMOKE',
    defaultCommand:
      'pnpm exec tsx --tsconfig ./client/tsconfig.json ./benchmarks/threshold-load/src/scenario-harness.ts --scenario ed25519_local_presign_refill_pressure --wallets 8 --signs-per-wallet 3 --max-concurrency 12 --profile steady',
  },
  {
    id: 'ed25519_local_presign_concurrent_finalize_smoke',
    description: 'Threshold Ed25519 local presign concurrent finalize pressure smoke profile',
    groups: ['ed25519', 'smoke', 'presign', 'pressure'],
    commandEnv: 'BENCH_CMD_ED25519_LOCAL_PRESIGN_CONCURRENT_FINALIZE_SMOKE',
    defaultCommand:
      'pnpm exec tsx --tsconfig ./client/tsconfig.json ./benchmarks/threshold-load/src/scenario-harness.ts --scenario ed25519_local_presign_concurrent_finalize --wallets 8 --signs-per-wallet 2 --max-concurrency 16 --profile steady',
  },
  {
    id: 'ed25519_local_presign_double_consume_smoke',
    description: 'Threshold Ed25519 local presign serverless double-consume pressure smoke profile',
    groups: ['ed25519', 'smoke', 'presign'],
    commandEnv: 'BENCH_CMD_ED25519_LOCAL_PRESIGN_DOUBLE_CONSUME_SMOKE',
    defaultCommand:
      'pnpm exec tsx --tsconfig ./client/tsconfig.json ./benchmarks/threshold-load/src/scenario-harness.ts --scenario ed25519_local_presign_double_consume --wallets 4 --signs-per-wallet 1 --max-concurrency 4 --profile steady',
  },
  {
    id: 'ed25519_local_steady_50',
    description: 'Threshold Ed25519 local warm-session medium steady-state profile (50 wallets)',
    groups: ['ed25519', 'medium'],
    commandEnv: 'BENCH_CMD_ED25519_LOCAL_STEADY_50',
    defaultCommand:
      'pnpm exec tsx --tsconfig ./client/tsconfig.json ./benchmarks/threshold-load/src/scenario-harness.ts --scenario ed25519_local_steady --wallets 50 --signs-per-wallet 2 --max-concurrency 12 --profile steady',
  },
  {
    id: 'ed25519_local_burst_50',
    description: 'Threshold Ed25519 local warm-session medium burst profile (50 wallets)',
    groups: ['ed25519', 'medium'],
    commandEnv: 'BENCH_CMD_ED25519_LOCAL_BURST_50',
    defaultCommand:
      'pnpm exec tsx --tsconfig ./client/tsconfig.json ./benchmarks/threshold-load/src/scenario-harness.ts --scenario ed25519_local_burst --wallets 50 --signs-per-wallet 1 --max-concurrency 25 --profile burst',
  },
  {
    id: 'ed25519_local_steady_100',
    description: 'Threshold Ed25519 local warm-session scale steady-state profile (100 wallets)',
    groups: ['ed25519', 'scale'],
    commandEnv: 'BENCH_CMD_ED25519_LOCAL_STEADY_100',
    defaultCommand:
      'pnpm exec tsx --tsconfig ./client/tsconfig.json ./benchmarks/threshold-load/src/scenario-harness.ts --scenario ed25519_local_steady --wallets 100 --signs-per-wallet 2 --max-concurrency 16 --profile steady',
  },
  {
    id: 'ed25519_local_burst_100',
    description: 'Threshold Ed25519 local warm-session scale burst profile (100 wallets)',
    groups: ['ed25519', 'scale'],
    commandEnv: 'BENCH_CMD_ED25519_LOCAL_BURST_100',
    defaultCommand:
      'pnpm exec tsx --tsconfig ./client/tsconfig.json ./benchmarks/threshold-load/src/scenario-harness.ts --scenario ed25519_local_burst --wallets 100 --signs-per-wallet 1 --max-concurrency 40 --profile burst',
  },
  {
    id: 'ed25519_local_steady_250',
    description: 'Threshold Ed25519 local warm-session scale steady-state profile (250 wallets)',
    groups: ['ed25519', 'scale'],
    commandEnv: 'BENCH_CMD_ED25519_LOCAL_STEADY_250',
    defaultCommand:
      'pnpm exec tsx --tsconfig ./client/tsconfig.json ./benchmarks/threshold-load/src/scenario-harness.ts --scenario ed25519_local_steady --wallets 250 --signs-per-wallet 1 --max-concurrency 32 --profile steady',
  },
  {
    id: 'ed25519_local_burst_250',
    description: 'Threshold Ed25519 local warm-session scale burst profile (250 wallets)',
    groups: ['ed25519', 'scale'],
    commandEnv: 'BENCH_CMD_ED25519_LOCAL_BURST_250',
    defaultCommand:
      'pnpm exec tsx --tsconfig ./client/tsconfig.json ./benchmarks/threshold-load/src/scenario-harness.ts --scenario ed25519_local_burst --wallets 250 --signs-per-wallet 1 --max-concurrency 64 --profile burst',
  },
  {
    id: 'ed25519_local_steady_500',
    description: 'Threshold Ed25519 local warm-session scale steady-state profile (500 wallets)',
    groups: ['ed25519', 'scale'],
    commandEnv: 'BENCH_CMD_ED25519_LOCAL_STEADY_500',
    defaultCommand:
      'pnpm exec tsx --tsconfig ./client/tsconfig.json ./benchmarks/threshold-load/src/scenario-harness.ts --scenario ed25519_local_steady --wallets 500 --signs-per-wallet 1 --max-concurrency 48 --profile steady',
  },
  {
    id: 'ed25519_local_burst_500',
    description: 'Threshold Ed25519 local warm-session scale burst profile (500 wallets)',
    groups: ['ed25519', 'scale'],
    commandEnv: 'BENCH_CMD_ED25519_LOCAL_BURST_500',
    defaultCommand:
      'pnpm exec tsx --tsconfig ./client/tsconfig.json ./benchmarks/threshold-load/src/scenario-harness.ts --scenario ed25519_local_burst --wallets 500 --signs-per-wallet 1 --max-concurrency 96 --profile burst',
  },
];

export function resolveScenarioById(id) {
  return SCENARIOS.find((entry) => entry.id === id) || null;
}

export function resolveScenarioIdsByGroup(group) {
  const normalized = String(group || '')
    .trim()
    .toLowerCase();
  if (!normalized) return [];
  return SCENARIOS.filter(
    (entry) => Array.isArray(entry.groups) && entry.groups.includes(normalized),
  ).map((entry) => entry.id);
}

export function resolveScenarioCommand(scenario, env = process.env) {
  const raw = String(env[scenario.commandEnv] || '').trim();
  if (raw) return raw;
  return String(scenario.defaultCommand || '').trim() || null;
}
