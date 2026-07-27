import { base64UrlEncode } from '../utils/base64';
import type { DigestB64u } from '../utils/canonicalPrimitives';
import { parseDigestB64u } from '../utils/canonicalPrimitives';
import { alphabetizeStringify, sha256BytesUtf8 } from '../utils/digests';
import {
  type AuthorizationParseResult,
  type CapabilityId,
  type CapabilityOperationId,
  type CapabilityOperationRef,
  type PrincipalId,
  type TenantId,
  parseCapabilityId,
  parseCapabilityOperationId,
  parseCapabilityOperationRef,
  parsePrincipalId,
  parseTenantId,
} from './capabilityKinds';

const CAPABILITY_OPERATION_FINGERPRINT_DOMAIN_V1 =
  'seams:authorization:capability-operation-fingerprint:v1';

declare const capabilityOperationFingerprintDigestBrand: unique symbol;

export type CapabilityOperationFingerprintDigest = DigestB64u & {
  readonly [capabilityOperationFingerprintDigestBrand]: true;
};

export type OperationDigestSet = {
  readonly laneDigest: DigestB64u;
  readonly intentDigest: DigestB64u;
  readonly displayDigest: DigestB64u;
};

type CapabilityOperationEnvelopeFields<
  TOperation extends CapabilityOperationRef = CapabilityOperationRef,
> = {
  readonly tenantId: TenantId;
  readonly principalId: PrincipalId;
  readonly capabilityId: CapabilityId;
  readonly operationId: CapabilityOperationId;
  readonly operation: TOperation;
  readonly digests: OperationDigestSet;
};

class CapabilityOperationEnvelopeProof<
  TOperation extends CapabilityOperationRef = CapabilityOperationRef,
> {
  readonly tenantId: TenantId;
  readonly principalId: PrincipalId;
  readonly capabilityId: CapabilityId;
  readonly operationId: CapabilityOperationId;
  readonly operation: TOperation;
  readonly digests: OperationDigestSet;

  private retainProof(): true {
    return true;
  }

  constructor(fields: CapabilityOperationEnvelopeFields<TOperation>) {
    void this.retainProof();
    this.tenantId = fields.tenantId;
    this.principalId = fields.principalId;
    this.capabilityId = fields.capabilityId;
    this.operationId = fields.operationId;
    this.operation = fields.operation;
    this.digests = fields.digests;
  }
}

export type CapabilityOperationEnvelope<
  TOperation extends CapabilityOperationRef = CapabilityOperationRef,
> = CapabilityOperationEnvelopeProof<TOperation>;

export function buildCapabilityOperationEnvelope<TOperation extends CapabilityOperationRef>(
  fields: CapabilityOperationEnvelopeFields<TOperation>,
): CapabilityOperationEnvelope<TOperation> {
  return new CapabilityOperationEnvelopeProof({
    tenantId: fields.tenantId,
    principalId: fields.principalId,
    capabilityId: fields.capabilityId,
    operationId: fields.operationId,
    operation: fields.operation,
    digests: {
      laneDigest: fields.digests.laneDigest,
      intentDigest: fields.digests.intentDigest,
      displayDigest: fields.digests.displayDigest,
    },
  });
}

export function parseCapabilityOperationEnvelope(
  raw: unknown,
): AuthorizationParseResult<CapabilityOperationEnvelope> {
  if (
    !isExactRecord(raw, [
      'tenantId',
      'principalId',
      'capabilityId',
      'operationId',
      'operation',
      'digests',
    ])
  ) {
    return invalidResult(
      'capability operation envelope must contain exact identity, operation, and digest fields',
    );
  }
  const tenantId = parseTenantId(raw.tenantId);
  if (!tenantId.ok) return tenantId;
  const principalId = parsePrincipalId(raw.principalId);
  if (!principalId.ok) return principalId;
  const capabilityId = parseCapabilityId(raw.capabilityId);
  if (!capabilityId.ok) return capabilityId;
  const operationId = parseCapabilityOperationId(raw.operationId);
  if (!operationId.ok) return operationId;
  const operation = parseCapabilityOperationRef(raw.operation);
  if (!operation.ok) return operation;
  const digests = parseOperationDigestSet(raw.digests);
  if (!digests.ok) return digests;
  return {
    ok: true,
    value: buildCapabilityOperationEnvelope({
      tenantId: tenantId.value,
      principalId: principalId.value,
      capabilityId: capabilityId.value,
      operationId: operationId.value,
      operation: operation.value,
      digests: digests.value,
    }),
  };
}

export function parseOperationDigestSet(
  raw: unknown,
): AuthorizationParseResult<OperationDigestSet> {
  if (!isExactRecord(raw, ['laneDigest', 'intentDigest', 'displayDigest'])) {
    return invalidResult(
      'operation digests must contain exact laneDigest, intentDigest, and displayDigest fields',
    );
  }
  const laneDigest = parseDigest(raw.laneDigest, 'laneDigest');
  if (!laneDigest.ok) return laneDigest;
  const intentDigest = parseDigest(raw.intentDigest, 'intentDigest');
  if (!intentDigest.ok) return intentDigest;
  const displayDigest = parseDigest(raw.displayDigest, 'displayDigest');
  if (!displayDigest.ok) return displayDigest;
  return {
    ok: true,
    value: {
      laneDigest: laneDigest.value,
      intentDigest: intentDigest.value,
      displayDigest: displayDigest.value,
    },
  };
}

export function canonicalCapabilityOperationFingerprintPreimageV1(
  envelope: CapabilityOperationEnvelope,
): string {
  return `${CAPABILITY_OPERATION_FINGERPRINT_DOMAIN_V1}|${alphabetizeStringify({
    tenantId: envelope.tenantId,
    principalId: envelope.principalId,
    capabilityId: envelope.capabilityId,
    operationId: envelope.operationId,
    operation: envelope.operation,
    digests: envelope.digests,
  })}`;
}

export async function computeCapabilityOperationFingerprintDigest(
  envelope: CapabilityOperationEnvelope,
): Promise<CapabilityOperationFingerprintDigest> {
  const digest = base64UrlEncode(
    await sha256BytesUtf8(canonicalCapabilityOperationFingerprintPreimageV1(envelope)),
  );
  return parseCapabilityOperationFingerprintDigest(digest);
}

export function parseCapabilityOperationFingerprintDigest(
  value: unknown,
): CapabilityOperationFingerprintDigest {
  return parseDigestB64u(value) as CapabilityOperationFingerprintDigest;
}

function parseDigest(
  value: unknown,
  fieldName: keyof OperationDigestSet,
): AuthorizationParseResult<DigestB64u> {
  try {
    return { ok: true, value: parseDigestB64u(value) };
  } catch {
    return invalidResult(`${fieldName} must be a canonical 32-byte base64url digest`);
  }
}

function isExactRecord(
  value: unknown,
  expectedKeys: readonly string[],
): value is Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
  const keys = Object.keys(value);
  return keys.length === expectedKeys.length && keys.every((key) => expectedKeys.includes(key));
}

function invalidResult<T>(message: string): AuthorizationParseResult<T> {
  return {
    ok: false,
    error: {
      code: 'invalid',
      message,
    },
  };
}
