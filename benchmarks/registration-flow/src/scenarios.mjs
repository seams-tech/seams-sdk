export const SCENARIOS = [
  {
    id: 'passkey_ed25519_only_wallet_iframe',
    description: 'Passkey registration, Ed25519 only, wallet iframe runtime',
    groups: ['smoke', 'wallet_iframe', 'ed25519_only'],
    commandEnv: 'BENCH_CMD_REGISTRATION_PASSKEY_ED25519_ONLY_WALLET_IFRAME',
    defaultCommand:
      'BENCH_REGISTRATION_SCENARIO=passkey_ed25519_only_wallet_iframe BENCH_REGISTRATION_RUNS=5 pnpm -C tests exec playwright test -c ../benchmarks/registration-flow/playwright.config.ts --project=chromium --reporter=line',
  },
  {
    id: 'passkey_ed25519_only_wallet_iframe_activation',
    description:
      'Passkey registration, Ed25519 only, wallet iframe runtime with pre-mounted activation surface',
    groups: ['wallet_iframe', 'ed25519_only', 'activation_surface'],
    commandEnv: 'BENCH_CMD_REGISTRATION_PASSKEY_ED25519_ONLY_WALLET_IFRAME_ACTIVATION',
    defaultCommand:
      'BENCH_REGISTRATION_SCENARIO=passkey_ed25519_only_wallet_iframe_activation BENCH_REGISTRATION_RUNS=5 pnpm -C tests exec playwright test -c ../benchmarks/registration-flow/playwright.config.ts --project=chromium --reporter=line',
  },
  {
    id: 'passkey_ed25519_and_ecdsa_wallet_iframe',
    description: 'Passkey registration, Ed25519 plus ECDSA, wallet iframe runtime',
    groups: ['smoke', 'wallet_iframe', 'ed25519_and_ecdsa'],
    commandEnv: 'BENCH_CMD_REGISTRATION_PASSKEY_ED25519_AND_ECDSA_WALLET_IFRAME',
    defaultCommand:
      'BENCH_REGISTRATION_SCENARIO=passkey_ed25519_and_ecdsa_wallet_iframe BENCH_REGISTRATION_RUNS=5 pnpm -C tests exec playwright test -c ../benchmarks/registration-flow/playwright.config.ts --project=chromium --reporter=line',
  },
  {
    id: 'passkey_ed25519_and_ecdsa_wallet_iframe_activation',
    description:
      'Passkey registration, Ed25519 plus ECDSA, wallet iframe runtime with pre-mounted activation surface',
    groups: ['wallet_iframe', 'ed25519_and_ecdsa', 'activation_surface'],
    commandEnv:
      'BENCH_CMD_REGISTRATION_PASSKEY_ED25519_AND_ECDSA_WALLET_IFRAME_ACTIVATION',
    defaultCommand:
      'BENCH_REGISTRATION_SCENARIO=passkey_ed25519_and_ecdsa_wallet_iframe_activation BENCH_REGISTRATION_RUNS=5 pnpm -C tests exec playwright test -c ../benchmarks/registration-flow/playwright.config.ts --project=chromium --reporter=line',
  },
  {
    id: 'passkey_ed25519_only_host_origin',
    description: 'Passkey registration, Ed25519 only, host-origin runtime',
    groups: ['smoke', 'host_origin', 'ed25519_only'],
    commandEnv: 'BENCH_CMD_REGISTRATION_PASSKEY_ED25519_ONLY_HOST_ORIGIN',
    defaultCommand:
      'BENCH_REGISTRATION_SCENARIO=passkey_ed25519_only_host_origin BENCH_REGISTRATION_RUNS=5 pnpm -C tests exec playwright test -c ../benchmarks/registration-flow/playwright.config.ts --project=chromium --reporter=line',
  },
  {
    id: 'passkey_ed25519_and_ecdsa_host_origin',
    description: 'Passkey registration, Ed25519 plus ECDSA, host-origin runtime',
    groups: ['smoke', 'host_origin', 'ed25519_and_ecdsa'],
    commandEnv: 'BENCH_CMD_REGISTRATION_PASSKEY_ED25519_AND_ECDSA_HOST_ORIGIN',
    defaultCommand:
      'BENCH_REGISTRATION_SCENARIO=passkey_ed25519_and_ecdsa_host_origin BENCH_REGISTRATION_RUNS=5 pnpm -C tests exec playwright test -c ../benchmarks/registration-flow/playwright.config.ts --project=chromium --reporter=line',
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
