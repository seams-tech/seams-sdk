import { expect, test } from '@playwright/test';
import { fileURLToPath, pathToFileURL } from 'node:url';
import path from 'node:path';

type CompatibilityModule = {
  readonly assertFrontendApiCompatible: (
    frontend: unknown,
    backendRange: unknown,
  ) => Readonly<{
    readonly gatewayApiContractVersion: string;
    readonly supportedFrontendApiContractRange: Readonly<{
      readonly minInclusive: string;
      readonly maxInclusive: string;
    }>;
  }>;
  readonly compareGatewayApiContractVersions: (left: string, right: string) => number;
  readonly createFrontendApiContract: (value: unknown) => Readonly<{
    readonly gatewayApiContractVersion: string;
  }>;
  readonly parseSupportedFrontendApiContractRange: (value: unknown) => Readonly<{
    readonly minInclusive: string;
    readonly maxInclusive: string;
  }>;
};

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const modulePath = pathToFileURL(path.join(repoRoot, 'scripts/deployment-api-compatibility.mjs'));
const compatibilityModule = import(modulePath.href) as Promise<CompatibilityModule>;

test('frontend API contracts and backend ranges parse into immutable canonical values', async () => {
  const module = await compatibilityModule;
  const contract = module.createFrontendApiContract({ gatewayApiContractVersion: '1.4.0' });
  const range = module.parseSupportedFrontendApiContractRange({
    maxInclusive: '2.0.0',
    minInclusive: '1.0.0',
  });

  expect(contract).toEqual({ gatewayApiContractVersion: '1.4.0' });
  expect(range).toEqual({ minInclusive: '1.0.0', maxInclusive: '2.0.0' });
  expect(Object.isFrozen(contract)).toBe(true);
  expect(Object.isFrozen(range)).toBe(true);
});

test('compatibility accepts versions at either inclusive range boundary', async () => {
  const module = await compatibilityModule;
  const range = { minInclusive: '1.2.0', maxInclusive: '1.4.0' };

  expect(module.assertFrontendApiCompatible({ gatewayApiContractVersion: '1.2.0' }, range)).toEqual(
    {
      gatewayApiContractVersion: '1.2.0',
      supportedFrontendApiContractRange: range,
    },
  );
  expect(module.assertFrontendApiCompatible({ gatewayApiContractVersion: '1.4.0' }, range)).toEqual(
    {
      gatewayApiContractVersion: '1.4.0',
      supportedFrontendApiContractRange: range,
    },
  );
});

test('compatibility rejects versions outside the active backend range', async () => {
  const module = await compatibilityModule;

  expect(() =>
    module.assertFrontendApiCompatible(
      { gatewayApiContractVersion: '1.1.9' },
      { minInclusive: '1.2.0', maxInclusive: '1.4.0' },
    ),
  ).toThrow('outside supported range');
  expect(() =>
    module.assertFrontendApiCompatible(
      { gatewayApiContractVersion: '1.4.1' },
      { minInclusive: '1.2.0', maxInclusive: '1.4.0' },
    ),
  ).toThrow('outside supported range');
});

test('compatibility rejects malformed, inverted, and extra-field contracts', async () => {
  const module = await compatibilityModule;

  expect(() => module.createFrontendApiContract({ gatewayApiContractVersion: 'v1' })).toThrow(
    'MAJOR.MINOR.PATCH',
  );
  expect(() =>
    module.parseSupportedFrontendApiContractRange({ minInclusive: '2.0.0', maxInclusive: '1.0.0' }),
  ).toThrow('minimum exceeds maximum');
  expect(() =>
    module.createFrontendApiContract({ gatewayApiContractVersion: '1.0.0', legacy: true }),
  ).toThrow('fields are invalid');
});

test('version comparison is numeric rather than lexical', async () => {
  const module = await compatibilityModule;

  expect(module.compareGatewayApiContractVersions('1.10.0', '1.2.0')).toBeGreaterThan(0);
  expect(module.compareGatewayApiContractVersions('2.0.0', '2.0.0')).toBe(0);
});
