import { expect, test } from '@playwright/test';
import {
  VAULT_OPERATION_KINDS,
  buildCapabilityOperationEnvelope,
  buildVaultOperationRef,
  canonicalCapabilityOperationFingerprintPreimageV1,
  computeCapabilityOperationFingerprintDigest,
  parseCapabilityId,
  parseCapabilityOperationEnvelope,
  parseCapabilityOperationId,
  parseOperationDigestSet,
  parseTenantId,
  type AuthorizationParseResult,
  type CapabilityId,
  type CapabilityOperationId,
  type TenantId,
} from '@shared/authorization';
import { parseDigestB64u, type DigestB64u } from '@shared/utils/canonicalPrimitives';

const LANE_DIGEST = 'AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE';
const INTENT_DIGEST = 'AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI';
const DISPLAY_DIGEST = 'AwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwM';

function requireParsed<T>(result: AuthorizationParseResult<T>): T {
  if (!result.ok) throw new Error(result.error.message);
  return result.value;
}

function operationDigests(
  input: {
    readonly laneDigest?: string;
    readonly intentDigest?: string;
    readonly displayDigest?: string;
  } = {},
): {
  readonly laneDigest: DigestB64u;
  readonly intentDigest: DigestB64u;
  readonly displayDigest: DigestB64u;
} {
  return {
    laneDigest: parseDigestB64u(input.laneDigest ?? LANE_DIGEST),
    intentDigest: parseDigestB64u(input.intentDigest ?? INTENT_DIGEST),
    displayDigest: parseDigestB64u(input.displayDigest ?? DISPLAY_DIGEST),
  };
}

function validRawEnvelope(): Record<string, unknown> {
  return {
    tenantId: 'tenant-1',
    capabilityId: 'capability-1',
    operationId: 'operation-1',
    operation: {
      capabilityKind: 'vault_access',
      operationKind: 'vault.proxy_use',
    },
    digests: {
      laneDigest: LANE_DIGEST,
      intentDigest: INTENT_DIGEST,
      displayDigest: DISPLAY_DIGEST,
    },
  };
}

function buildVaultEnvelope(
  input: {
    readonly tenantId?: TenantId;
    readonly capabilityId?: CapabilityId;
    readonly operationId?: CapabilityOperationId;
    readonly digests?: ReturnType<typeof operationDigests>;
  } = {},
) {
  return buildCapabilityOperationEnvelope({
    tenantId: input.tenantId ?? requireParsed(parseTenantId('tenant-1')),
    capabilityId: input.capabilityId ?? requireParsed(parseCapabilityId('capability-1')),
    operationId: input.operationId ?? requireParsed(parseCapabilityOperationId('operation-1')),
    operation: buildVaultOperationRef(VAULT_OPERATION_KINDS.proxyUse),
    digests: input.digests ?? operationDigests(),
  });
}

test('authorization operation fingerprint pins its versioned canonical preimage and digest', async () => {
  const envelope = buildVaultEnvelope();
  expect(canonicalCapabilityOperationFingerprintPreimageV1(envelope)).toBe(
    'seams:authorization:capability-operation-fingerprint:v1|{"capabilityId":"capability-1","digests":{"displayDigest":"AwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwM","intentDigest":"AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI","laneDigest":"AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE"},"operation":{"capabilityKind":"vault_access","operationKind":"vault.proxy_use"},"operationId":"operation-1","tenantId":"tenant-1"}',
  );
  await expect(computeCapabilityOperationFingerprintDigest(envelope)).resolves.toBe(
    'hKhf6zecZUMhSkBKctQmEb31cb-tI6wCe9r3aRg4rls',
  );
});

test('authorization operation fingerprint changes with exact operation semantics', async () => {
  const original = await computeCapabilityOperationFingerprintDigest(buildVaultEnvelope());
  const changedOperationId = await computeCapabilityOperationFingerprintDigest(
    buildVaultEnvelope({
      operationId: requireParsed(parseCapabilityOperationId('operation-2')),
    }),
  );
  const changedIntent = await computeCapabilityOperationFingerprintDigest(
    buildVaultEnvelope({
      digests: operationDigests({
        intentDigest: 'BAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQ',
      }),
    }),
  );

  expect(changedOperationId).not.toBe(original);
  expect(changedIntent).not.toBe(original);
  expect(changedIntent).not.toBe(changedOperationId);
});

test('authorization operation envelope parser normalizes one exact boundary shape', () => {
  const parsed = parseCapabilityOperationEnvelope(validRawEnvelope());
  expect(parsed.ok).toBe(true);
  if (!parsed.ok) return;
  expect(parsed.value).toMatchObject({
    tenantId: 'tenant-1',
    capabilityId: 'capability-1',
    operationId: 'operation-1',
    operation: {
      capabilityKind: 'vault_access',
      operationKind: 'vault.proxy_use',
    },
    digests: {
      laneDigest: LANE_DIGEST,
      intentDigest: INTENT_DIGEST,
      displayDigest: DISPLAY_DIGEST,
    },
  });
});

test('authorization operation envelope rejects mismatched operations and authorization fields', () => {
  const mismatchedOperation = validRawEnvelope();
  mismatchedOperation.operation = {
    capabilityKind: 'vault_access',
    operationKind: 'near.sign_transaction',
  };
  expect(parseCapabilityOperationEnvelope(mismatchedOperation)).toMatchObject({
    ok: false,
    error: { code: 'invalid' },
  });

  const authorizationCoupled = validRawEnvelope();
  authorizationCoupled.grantId = 'grant-1';
  expect(parseCapabilityOperationEnvelope(authorizationCoupled)).toEqual({
    ok: false,
    error: {
      code: 'invalid',
      message:
        'capability operation envelope must contain exact identity, operation, and digest fields',
    },
  });
});

test('operation digest parsing rejects noncanonical and partial digest sets', () => {
  expect(
    parseOperationDigestSet({
      laneDigest: 'raw-digest',
      intentDigest: INTENT_DIGEST,
      displayDigest: DISPLAY_DIGEST,
    }),
  ).toEqual({
    ok: false,
    error: {
      code: 'invalid',
      message: 'laneDigest must be a canonical 32-byte base64url digest',
    },
  });
  expect(
    parseOperationDigestSet({
      laneDigest: LANE_DIGEST,
      intentDigest: INTENT_DIGEST,
    }),
  ).toMatchObject({
    ok: false,
    error: { code: 'invalid' },
  });
});
