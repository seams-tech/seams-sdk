import {
  parseMpcMaterialActivationRef,
  type MpcMaterialActivationRef,
} from './domainIds';

export type RouterAbNormalSigningAuthorizationWire =
  | {
      readonly kind: 'reusable_wallet_session';
      readonly wallet_session_id: string;
    }
  | {
      readonly kind: 'operation_step_up';
      readonly evidence_set_digest?: never;
      readonly wallet_session_id?: never;
    };

export type RouterAbMpcMaterialActivationRefWire = {
  readonly kind: 'mpc_material_activation_ref';
  readonly activation_id: string;
  readonly capability: string;
  readonly material_owner: string;
  readonly key_binding: string;
  readonly lifecycle_binding: string;
  readonly signing_worker: string;
};

export type RouterAbEd25519OperationStepUpPreparationV1Wire = {
  readonly wallet_id: string;
  readonly operation_kind:
    | 'near.sign_transaction'
    | 'near.sign_delegate_action'
    | 'near.sign_nep413_message';
  readonly operation_id: string;
  readonly request_id: string;
  readonly account_id: string;
  readonly material_activation: RouterAbMpcMaterialActivationRefWire;
  readonly signing_worker_id: string;
  readonly near_account_id: string;
  readonly signer_slot: number;
  readonly participant_ids: readonly [number, number];
  readonly expires_at_ms: number;
};

export type RouterAbEd25519OwnerOperationAuthorizationDecisionV1Wire =
  | {
      readonly kind: 'authorized';
      readonly operation: {
        readonly kind: 'authorized_operation';
        readonly operation_id: string;
        readonly authorized_operation_id: string;
        readonly operation_fingerprint_digest: string;
      };
      readonly source: {
        readonly kind: 'reusable_wallet_session';
        readonly wallet_session_id: string;
        readonly quota_id: string;
      };
    }
  | {
      readonly kind: 'step_up_required';
      readonly reason:
        | 'wallet_session_missing'
        | 'wallet_session_expired'
        | 'wallet_session_exhausted'
        | 'wallet_session_ended'
        | 'wallet_session_superseded';
      readonly step_up: RouterAbEd25519OperationStepUpPreparationV1Wire;
    }
  | {
      readonly kind: 'denied';
      readonly denial: {
        readonly code:
          | 'invalid_identity'
          | 'invalid_authority'
          | 'invalid_operation'
          | 'inactive_material'
          | 'replayed_step_up'
          | 'authorization_unavailable';
        readonly message: string;
      };
    };

function requireRecord(value: unknown, label: string): Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error(`${label} must be an object`);
  }
  return value as Record<string, unknown>;
}

function requireExactFields(
  record: Record<string, unknown>,
  expectedFields: readonly string[],
  label: string,
): void {
  const actualFields = Object.keys(record).sort();
  const expected = [...expectedFields].sort();
  if (
    actualFields.length !== expected.length ||
    actualFields.some((field, index) => field !== expected[index])
  ) {
    throw new Error(`${label} has invalid fields`);
  }
}

function requireAsciiString(value: unknown, label: string): string {
  if (typeof value !== 'string' || value.trim() !== value || !value) {
    throw new Error(`${label} is required`);
  }
  if (!/^[\x20-\x7e]+$/.test(value)) {
    throw new Error(`${label} must be printable ASCII`);
  }
  return value;
}

export function parseRouterAbNormalSigningAuthorization(
  value: unknown,
): RouterAbNormalSigningAuthorizationWire {
  const authorization = requireRecord(value, 'authorization');
  switch (authorization.kind) {
    case 'reusable_wallet_session':
      requireExactFields(
        authorization,
        ['kind', 'wallet_session_id'],
        'authorization',
      );
      return {
        kind: 'reusable_wallet_session',
        wallet_session_id: requireAsciiString(
          authorization.wallet_session_id,
          'authorization.wallet_session_id',
        ),
      };
    case 'operation_step_up':
      requireExactFields(authorization, ['kind'], 'authorization');
      return { kind: 'operation_step_up' };
    default:
      throw new Error('authorization.kind is not supported');
  }
}

export function parseRouterAbMpcMaterialActivationRef(
  value: unknown,
): RouterAbMpcMaterialActivationRefWire {
  const activation = requireRecord(value, 'material_activation');
  requireExactFields(
    activation,
    [
      'kind',
      'activation_id',
      'capability',
      'material_owner',
      'key_binding',
      'lifecycle_binding',
      'signing_worker',
    ],
    'material_activation',
  );
  if (activation.kind !== 'mpc_material_activation_ref') {
    throw new Error('material_activation.kind is not supported');
  }
  return {
    kind: 'mpc_material_activation_ref',
    activation_id: requireAsciiString(
      activation.activation_id,
      'material_activation.activation_id',
    ),
    capability: requireAsciiString(activation.capability, 'material_activation.capability'),
    material_owner: requireAsciiString(
      activation.material_owner,
      'material_activation.material_owner',
    ),
    key_binding: requireAsciiString(activation.key_binding, 'material_activation.key_binding'),
    lifecycle_binding: requireAsciiString(
      activation.lifecycle_binding,
      'material_activation.lifecycle_binding',
    ),
    signing_worker: requireAsciiString(
      activation.signing_worker,
      'material_activation.signing_worker',
    ),
  };
}

export function routerAbMpcMaterialActivationRefToWire(input: {
  readonly kind: 'mpc_material_activation_ref';
  readonly activationId: string;
  readonly capability: string;
  readonly materialOwner: string;
  readonly keyBinding: string;
  readonly lifecycleBinding: string;
  readonly signingWorker: string;
}): RouterAbMpcMaterialActivationRefWire {
  return parseRouterAbMpcMaterialActivationRef({
    kind: input.kind,
    activation_id: input.activationId,
    capability: input.capability,
    material_owner: input.materialOwner,
    key_binding: input.keyBinding,
    lifecycle_binding: input.lifecycleBinding,
    signing_worker: input.signingWorker,
  });
}

export function routerAbMpcMaterialActivationRefFromWire(
  value: unknown,
): MpcMaterialActivationRef {
  const wire = parseRouterAbMpcMaterialActivationRef(value);
  const parsed = parseMpcMaterialActivationRef({
    kind: wire.kind,
    activationId: wire.activation_id,
    capability: wire.capability,
    materialOwner: wire.material_owner,
    keyBinding: wire.key_binding,
    lifecycleBinding: wire.lifecycle_binding,
    signingWorker: wire.signing_worker,
  });
  if (!parsed.ok) {
    throw new Error(`material_activation is invalid: ${parsed.error.message}`);
  }
  return parsed.value;
}

function asciiBytes(value: string): Uint8Array {
  return new TextEncoder().encode(value);
}

function appendLen32(out: number[], value: string): void {
  const bytes = asciiBytes(value);
  const length = bytes.length >>> 0;
  out.push((length >>> 24) & 0xff, (length >>> 16) & 0xff, (length >>> 8) & 0xff, length & 0xff);
  out.push(...bytes);
}

export function canonicalRouterAbNormalSigningAuthorizationBytes(
  value: RouterAbNormalSigningAuthorizationWire,
): Uint8Array {
  const authorization = parseRouterAbNormalSigningAuthorization(value);
  const out: number[] = [];
  appendLen32(out, authorization.kind);
  switch (authorization.kind) {
    case 'reusable_wallet_session':
      appendLen32(out, authorization.wallet_session_id);
      break;
    case 'operation_step_up':
      break;
  }
  return new Uint8Array(out);
}

export function canonicalRouterAbMpcMaterialActivationRefBytes(
  value: RouterAbMpcMaterialActivationRefWire,
): Uint8Array {
  const activation = parseRouterAbMpcMaterialActivationRef(value);
  const out: number[] = [];
  appendLen32(out, activation.kind);
  appendLen32(out, activation.activation_id);
  appendLen32(out, activation.capability);
  appendLen32(out, activation.material_owner);
  appendLen32(out, activation.key_binding);
  appendLen32(out, activation.lifecycle_binding);
  appendLen32(out, activation.signing_worker);
  return new Uint8Array(out);
}

export function sameRouterAbMpcMaterialActivationRef(
  left: RouterAbMpcMaterialActivationRefWire,
  right: RouterAbMpcMaterialActivationRefWire,
): boolean {
  return (
    left.kind === right.kind &&
    left.activation_id === right.activation_id &&
    left.capability === right.capability &&
    left.material_owner === right.material_owner &&
    left.key_binding === right.key_binding &&
    left.lifecycle_binding === right.lifecycle_binding &&
    left.signing_worker === right.signing_worker
  );
}
