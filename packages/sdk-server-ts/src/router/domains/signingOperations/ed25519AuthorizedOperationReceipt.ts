import { parseDigestB64u } from '@shared/utils/canonicalPrimitives';
import { parseCapabilityOperationFingerprintDigest } from '@shared/authorization/operationFingerprint';
import { isPlainObject } from '@shared/utils/validation';

export type Ed25519OperationKind =
  | 'near.sign_transaction'
  | 'near.sign_delegate_action'
  | 'near.sign_nep413_message';

export type Ed25519ReusableAuthorizedOperationReceipt = {
  readonly kind: 'reusable_wallet_session_authorized_operation_v1';
  readonly authorized_operation_id: string;
  readonly operation_id: string;
  readonly capability_kind: 'near_ed25519_mpc_signing';
  readonly operation_kind: Ed25519OperationKind;
  readonly lane_digest_b64u: string;
  readonly intent_digest_b64u: string;
  readonly display_digest_b64u: string;
  readonly operation_fingerprint_digest: string;
};

export function requireEd25519OperationKind(value: unknown): Ed25519OperationKind {
  if (
    value !== 'near.sign_transaction' &&
    value !== 'near.sign_delegate_action' &&
    value !== 'near.sign_nep413_message'
  ) {
    throw new Error('authorized_operation.operation_kind is invalid');
  }
  return value;
}

export function requireAuthorizedOperationReceiptString(
  record: Record<string, unknown>,
  name: string,
): string {
  const field = typeof record[name] === 'string' ? record[name].trim() : '';
  if (!field) throw new Error(`authorized_operation.${name} is required`);
  return field;
}

export function requireExactAuthorizedOperationReceiptFields(
  record: Record<string, unknown>,
  branchFields: readonly string[] = [],
): void {
  const expected = [
    'capability_kind',
    'display_digest_b64u',
    'intent_digest_b64u',
    'kind',
    'lane_digest_b64u',
    'operation_fingerprint_digest',
    'operation_id',
    'operation_kind',
    'authorized_operation_id',
    ...branchFields,
  ].sort();
  const actual = Object.keys(record).sort();
  if (
    actual.length !== expected.length ||
    actual.some((field, index) => field !== expected[index])
  ) {
    throw new Error('authorized_operation has invalid fields');
  }
}

export function parseEd25519ReusableAuthorizedOperationReceipt(
  value: unknown,
): Ed25519ReusableAuthorizedOperationReceipt {
  const record = isPlainObject(value) ? value : null;
  if (!record || record.kind !== 'reusable_wallet_session_authorized_operation_v1') {
    throw new Error('Ed25519 reusable Wallet Session authorized operation is required');
  }
  requireExactAuthorizedOperationReceiptFields(record);
  const capabilityKind = requireAuthorizedOperationReceiptString(record, 'capability_kind');
  if (capabilityKind !== 'near_ed25519_mpc_signing') {
    throw new Error('authorized_operation.capability_kind is invalid');
  }
  const operationKind = requireEd25519OperationKind(
    requireAuthorizedOperationReceiptString(record, 'operation_kind'),
  );
  const laneDigest = requireAuthorizedOperationReceiptString(record, 'lane_digest_b64u');
  const intentDigest = requireAuthorizedOperationReceiptString(record, 'intent_digest_b64u');
  const displayDigest = requireAuthorizedOperationReceiptString(record, 'display_digest_b64u');
  parseDigestB64u(laneDigest);
  parseDigestB64u(intentDigest);
  parseDigestB64u(displayDigest);
  const fingerprint = requireAuthorizedOperationReceiptString(
    record,
    'operation_fingerprint_digest',
  );
  parseCapabilityOperationFingerprintDigest(fingerprint);
  return {
    kind: 'reusable_wallet_session_authorized_operation_v1',
    authorized_operation_id: requireAuthorizedOperationReceiptString(
      record,
      'authorized_operation_id',
    ),
    operation_id: requireAuthorizedOperationReceiptString(record, 'operation_id'),
    capability_kind: 'near_ed25519_mpc_signing',
    operation_kind: operationKind,
    lane_digest_b64u: laneDigest,
    intent_digest_b64u: intentDigest,
    display_digest_b64u: displayDigest,
    operation_fingerprint_digest: fingerprint,
  };
}
