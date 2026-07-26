import { expect, test } from '@playwright/test';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

type GatewayCutoverConfigModule = {
  readonly GATEWAY_CUTOVER_WORKER_VAR_NAMES: readonly string[];
  readonly parseGatewayCutoverWorkerVars: (
    environment: Readonly<Record<string, string | undefined>>,
  ) => Readonly<Record<string, string>>;
};

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const gatewayCutoverConfigModule = import(
  pathToFileURL(
    path.join(repoRoot, 'packages/console-server-ts/scripts/gateway-deployment-config.mjs'),
  ).href
) as Promise<GatewayCutoverConfigModule>;

const expectedWorkerVarNames = [
  'ROUTER_AB_YAO_GATEWAY_REGISTRATION_ADMISSION_CUTOFF_MS',
  'ROUTER_AB_YAO_GATEWAY_REGISTRATION_DRAIN_UNTIL_MS',
  'ROUTER_AB_YAO_GATEWAY_RECOVERY_ADMISSION_CUTOFF_MS',
  'ROUTER_AB_YAO_GATEWAY_RECOVERY_DRAIN_UNTIL_MS',
  'ROUTER_AB_YAO_GATEWAY_EXPORT_ADMISSION_CUTOFF_MS',
  'ROUTER_AB_YAO_GATEWAY_EXPORT_DRAIN_UNTIL_MS',
] as const;

test('Gateway cutover config emits the exact six worker variables while every family is unset', async () => {
  const module = await gatewayCutoverConfigModule;
  const vars = module.parseGatewayCutoverWorkerVars({});

  expect(module.GATEWAY_CUTOVER_WORKER_VAR_NAMES).toEqual(expectedWorkerVarNames);
  expect(vars).toEqual(Object.fromEntries(expectedWorkerVarNames.map((name) => [name, ''])));
});

test('Gateway cutover config preserves independent family schedules', async () => {
  const module = await gatewayCutoverConfigModule;
  const vars = module.parseGatewayCutoverWorkerVars({
    ROUTER_AB_YAO_GATEWAY_REGISTRATION_ADMISSION_CUTOFF_MS: ' 1000 ',
    ROUTER_AB_YAO_GATEWAY_REGISTRATION_DRAIN_UNTIL_MS: '2000',
    ROUTER_AB_YAO_GATEWAY_RECOVERY_ADMISSION_CUTOFF_MS: '8000',
    ROUTER_AB_YAO_GATEWAY_RECOVERY_DRAIN_UNTIL_MS: '9000',
  });

  expect(vars).toEqual({
    ROUTER_AB_YAO_GATEWAY_REGISTRATION_ADMISSION_CUTOFF_MS: '1000',
    ROUTER_AB_YAO_GATEWAY_REGISTRATION_DRAIN_UNTIL_MS: '2000',
    ROUTER_AB_YAO_GATEWAY_RECOVERY_ADMISSION_CUTOFF_MS: '8000',
    ROUTER_AB_YAO_GATEWAY_RECOVERY_DRAIN_UNTIL_MS: '9000',
    ROUTER_AB_YAO_GATEWAY_EXPORT_ADMISSION_CUTOFF_MS: '',
    ROUTER_AB_YAO_GATEWAY_EXPORT_DRAIN_UNTIL_MS: '',
  });
});

test('Gateway cutover config rejects incomplete, invalid, and reversed family windows', async () => {
  const module = await gatewayCutoverConfigModule;

  expect(() =>
    module.parseGatewayCutoverWorkerVars({
      ROUTER_AB_YAO_GATEWAY_REGISTRATION_ADMISSION_CUTOFF_MS: '1000',
    }),
  ).toThrow(/must be set together/u);
  expect(() =>
    module.parseGatewayCutoverWorkerVars({
      ROUTER_AB_YAO_GATEWAY_RECOVERY_ADMISSION_CUTOFF_MS: 'later',
      ROUTER_AB_YAO_GATEWAY_RECOVERY_DRAIN_UNTIL_MS: '9000',
    }),
  ).toThrow(/non-negative safe integer/u);
  expect(() =>
    module.parseGatewayCutoverWorkerVars({
      ROUTER_AB_YAO_GATEWAY_EXPORT_ADMISSION_CUTOFF_MS: '9000',
      ROUTER_AB_YAO_GATEWAY_EXPORT_DRAIN_UNTIL_MS: '8000',
    }),
  ).toThrow(/must not exceed/u);
});

test('Gateway cutover config rejects obsolete tenant-wide window variables', async () => {
  const module = await gatewayCutoverConfigModule;

  expect(() =>
    module.parseGatewayCutoverWorkerVars({
      ROUTER_AB_YAO_GATEWAY_ADMISSION_CUTOFF_MS: '',
    }),
  ).toThrow(/obsolete/u);
  expect(() =>
    module.parseGatewayCutoverWorkerVars({
      ROUTER_AB_YAO_GATEWAY_DRAIN_UNTIL_MS: '9000',
    }),
  ).toThrow(/obsolete/u);
});
