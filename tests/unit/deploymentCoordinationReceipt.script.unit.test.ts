import { expect, test } from '@playwright/test';
import { fileURLToPath, pathToFileURL } from 'node:url';
import path from 'node:path';

type Receipt = {
  readonly schemaVersion: number;
  readonly kind: string;
  readonly mode: 'backend-deployment' | 'frontend-only-no-op';
  readonly target: string;
  readonly receiptRunId: string;
  readonly acceptedSourceSha: string;
  readonly acceptedValidationRunId: string;
  readonly selectedBackendComponents: readonly string[];
  readonly activeBackendSourceSha: string;
  readonly activeBackendReceiptRunId: string;
  readonly backendReleaseSetId: string;
  readonly deployedComponentDigests: readonly Readonly<{
    readonly component: string;
    readonly digestSha256: string;
  }>[];
  readonly supportedFrontendApiContractRange: Readonly<{
    readonly minInclusive: string;
    readonly maxInclusive: string;
  }>;
  readonly smokeResult: Readonly<{
    readonly status: 'passed';
    readonly completedAt: string;
    readonly checks: readonly Readonly<{ readonly name: string; readonly status: number }>[];
  }>;
  readonly createdAt: string;
  readonly receiptDigestSha256: string;
  readonly receiptId: string;
};

type ReceiptModule = {
  readonly assertBackendCoordinationReceiptMatches: (value: unknown, expected: unknown) => Receipt;
  readonly assertFrontendApiCompatibleWithBackendReceipt: (
    receipt: unknown,
    frontendContract: unknown,
  ) => Readonly<{
    readonly receipt: Receipt;
    readonly compatibility: Readonly<{
      readonly gatewayApiContractVersion: string;
      readonly supportedFrontendApiContractRange: Readonly<{
        readonly minInclusive: string;
        readonly maxInclusive: string;
      }>;
    }>;
  }>;
  readonly createBackendCoordinationReceipt: (input: unknown) => Receipt;
  readonly parseBackendCoordinationReceipt: (value: unknown) => Receipt;
};

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const modulePath = pathToFileURL(
  path.join(repoRoot, 'scripts/deployment-coordination-receipt.mjs'),
);
const receiptModule = import(modulePath.href) as Promise<ReceiptModule>;
const sourceSha = 'a'.repeat(40);
const releaseSetId = `rs_${'c'.repeat(64)}`;
const timestamp = '2026-07-24T00:00:00.000Z';

function backendDeploymentInput(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    mode: 'backend-deployment',
    target: 'staging',
    receiptRunId: '1001',
    acceptedSourceSha: sourceSha,
    acceptedValidationRunId: '1002',
    selectedBackendComponents: ['gateway', 'router'],
    backendReleaseSetId: releaseSetId,
    deployedComponentDigests: [
      { component: 'gateway', digestSha256: 'd'.repeat(64) },
      { component: 'router', digestSha256: 'e'.repeat(64) },
    ],
    supportedFrontendApiContractRange: { minInclusive: '1.0.0', maxInclusive: '2.0.0' },
    smokeResult: {
      status: 'passed',
      completedAt: timestamp,
      checks: [{ name: 'https://staging.seams.sh/readyz', status: 200 }],
    },
    createdAt: timestamp,
    ...overrides,
  };
}

test('backend deployment receipt is content-addressed, immutable, and self-verifying', async () => {
  const module = await receiptModule;
  const receipt = module.createBackendCoordinationReceipt(backendDeploymentInput());

  expect(receipt).toMatchObject({
    schemaVersion: 1,
    kind: 'backend-coordination-receipt',
    mode: 'backend-deployment',
    target: 'staging',
    receiptRunId: '1001',
    acceptedSourceSha: sourceSha,
    activeBackendSourceSha: sourceSha,
    activeBackendReceiptRunId: '1001',
    backendReleaseSetId: releaseSetId,
  });
  expect(receipt.receiptId).toBe(`bcr_${receipt.receiptDigestSha256}`);
  expect(Object.isFrozen(receipt)).toBe(true);
  expect(Object.isFrozen(receipt.deployedComponentDigests)).toBe(true);
  expect(module.parseBackendCoordinationReceipt(receipt)).toEqual(receipt);
});

test('frontend-only no-op receipt carries forward the active backend identity', async () => {
  const module = await receiptModule;
  const activeReceipt = module.createBackendCoordinationReceipt(backendDeploymentInput());
  const noOpReceipt = module.createBackendCoordinationReceipt({
    mode: 'frontend-only-no-op',
    target: 'staging',
    receiptRunId: '2001',
    acceptedSourceSha: 'f'.repeat(40),
    acceptedValidationRunId: '2002',
    selectedBackendComponents: [],
    previousActiveReceipt: activeReceipt,
    createdAt: timestamp,
  });

  expect(noOpReceipt.mode).toBe('frontend-only-no-op');
  expect(noOpReceipt.selectedBackendComponents).toEqual([]);
  expect(noOpReceipt.activeBackendSourceSha).toBe(sourceSha);
  expect(noOpReceipt.activeBackendReceiptRunId).toBe(activeReceipt.receiptRunId);
  expect(noOpReceipt.backendReleaseSetId).toBe(activeReceipt.backendReleaseSetId);
  expect(noOpReceipt.deployedComponentDigests).toEqual(activeReceipt.deployedComponentDigests);
  expect(noOpReceipt.supportedFrontendApiContractRange).toEqual(
    activeReceipt.supportedFrontendApiContractRange,
  );
});

test('receipt parsing rejects tampering, non-canonical arrays, and unknown fields', async () => {
  const module = await receiptModule;
  const receipt = module.createBackendCoordinationReceipt(backendDeploymentInput());

  expect(() =>
    module.parseBackendCoordinationReceipt({
      ...receipt,
      createdAt: '2026-07-24T00:00:01.000Z',
    }),
  ).toThrow('digest mismatch');
  expect(() =>
    module.createBackendCoordinationReceipt(
      backendDeploymentInput({ selectedBackendComponents: ['router', 'gateway'] }),
    ),
  ).toThrow('unique and sorted');
  expect(() => module.parseBackendCoordinationReceipt({ ...receipt, legacyReceipt: true })).toThrow(
    'fields are invalid',
  );
});

test('receipt creation rejects invalid deployment and no-op semantics', async () => {
  const module = await receiptModule;
  const activeReceipt = module.createBackendCoordinationReceipt(backendDeploymentInput());

  expect(() =>
    module.createBackendCoordinationReceipt(
      backendDeploymentInput({
        selectedBackendComponents: [],
        deployedComponentDigests: [],
      }),
    ),
  ).toThrow('must select at least one backend component');
  expect(() =>
    module.createBackendCoordinationReceipt({
      mode: 'frontend-only-no-op',
      target: 'production',
      receiptRunId: '2001',
      acceptedSourceSha: 'f'.repeat(40),
      acceptedValidationRunId: '2002',
      selectedBackendComponents: [],
      previousActiveReceipt: activeReceipt,
      createdAt: timestamp,
    }),
  ).toThrow('target does not match');
});

test('receipt identity matching verifies the accepted deployment boundary', async () => {
  const module = await receiptModule;
  const receipt = module.createBackendCoordinationReceipt(backendDeploymentInput());

  expect(
    module.assertBackendCoordinationReceiptMatches(receipt, {
      target: 'staging',
      acceptedSourceSha: sourceSha,
      acceptedValidationRunId: '1002',
      receiptRunId: '1001',
    }),
  ).toEqual(receipt);
  expect(() =>
    module.assertBackendCoordinationReceiptMatches(receipt, {
      target: 'staging',
      acceptedSourceSha: sourceSha,
      acceptedValidationRunId: '9999',
      receiptRunId: '1001',
    }),
  ).toThrow('does not match expected deployment identity');
});

test('frontend API compatibility is checked against the active backend receipt range', async () => {
  const module = await receiptModule;
  const receipt = module.createBackendCoordinationReceipt(backendDeploymentInput());

  expect(
    module.assertFrontendApiCompatibleWithBackendReceipt(receipt, {
      gatewayApiContractVersion: '2.0.0',
    }),
  ).toMatchObject({
    receipt,
    compatibility: {
      gatewayApiContractVersion: '2.0.0',
      supportedFrontendApiContractRange: { minInclusive: '1.0.0', maxInclusive: '2.0.0' },
    },
  });
  expect(() =>
    module.assertFrontendApiCompatibleWithBackendReceipt(receipt, {
      gatewayApiContractVersion: '2.0.1',
    }),
  ).toThrow('outside supported range');
});
