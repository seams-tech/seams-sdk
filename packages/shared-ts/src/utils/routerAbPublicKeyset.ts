export const ROUTER_AB_PUBLIC_KEYSET_VERSION_V2 = 'router_ab_keyset_v2' as const;
export const ROUTER_AB_PUBLIC_KEYSET_WELL_KNOWN_PATH_V2 = '/.well-known/router-ab/keyset' as const;
export const ROUTER_AB_PUBLIC_KEYSET_PATH_V2 = '/v2/router-ab/keyset' as const;

export type RouterAbSignerRoleV1 = 'signer_a' | 'signer_b';

export type RouterAbSignerEnvelopeHpkePublicKeyV1 = {
  role: RouterAbSignerRoleV1;
  key_epoch: string;
  public_key: string;
};

export type RouterAbSignerEnvelopeHpkePublicKeySetV1 = {
  deriver_a: RouterAbSignerEnvelopeHpkePublicKeyV1;
  deriver_b: RouterAbSignerEnvelopeHpkePublicKeyV1;
};

export type RouterAbSignerEnvelopeHpkeCurrentPublicKeySetV1 = {
  current: RouterAbSignerEnvelopeHpkePublicKeySetV1;
  previous?: never;
  previous_retire_at_ms?: never;
};

export type RouterAbSignerEnvelopeHpkeRotatingPublicKeySetV1 = {
  current: RouterAbSignerEnvelopeHpkePublicKeySetV1;
  previous: RouterAbSignerEnvelopeHpkePublicKeySetV1;
  previous_retire_at_ms: number;
};

export type RouterAbSignerEnvelopeHpkeRotationPublicKeySetV1 =
  | RouterAbSignerEnvelopeHpkeCurrentPublicKeySetV1
  | RouterAbSignerEnvelopeHpkeRotatingPublicKeySetV1;

export type RouterAbSignerPeerVerifyingKeyHexV1 = {
  role: RouterAbSignerRoleV1;
  verifying_key_hex: string;
};

export type RouterAbSignerPeerVerifyingKeyHexSetV1 = {
  deriver_a: RouterAbSignerPeerVerifyingKeyHexV1;
  deriver_b: RouterAbSignerPeerVerifyingKeyHexV1;
};

export type RouterAbPublicHpkeKeyDescriptorV1 = {
  key_epoch: string;
  public_key: string;
};

export type RouterAbPublicKeysetV2 = {
  keyset_version: typeof ROUTER_AB_PUBLIC_KEYSET_VERSION_V2;
  signer_envelope_hpke: RouterAbSignerEnvelopeHpkeRotationPublicKeySetV1;
  signer_peer_verifying_keys: RouterAbSignerPeerVerifyingKeyHexSetV1;
  signing_worker_server_output_hpke: RouterAbPublicHpkeKeyDescriptorV1;
};

function requireRecord(value: unknown, label: string): Record<string, unknown> {
  if (value && typeof value === 'object' && !Array.isArray(value)) {
    return value as Record<string, unknown>;
  }
  throw new Error(`${label} must be an object`);
}

function requireExactKeys(
  record: Record<string, unknown>,
  allowedKeys: readonly string[],
  label: string,
): void {
  const allowed = new Set(allowedKeys);
  for (const key of Object.keys(record)) {
    if (!allowed.has(key)) {
      throw new Error(`${label}.${key} is not supported`);
    }
  }
}

function requireNonEmptyString(value: unknown, label: string): string {
  const normalized = String(value || '').trim();
  if (!normalized) throw new Error(`${label} is required`);
  return normalized;
}

function requirePositiveInteger(value: unknown, label: string): number {
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed <= 0) {
    throw new Error(`${label} must be a positive integer`);
  }
  return parsed;
}

function requireSignerRole(value: unknown, label: string): RouterAbSignerRoleV1 {
  const role = requireNonEmptyString(value, label);
  switch (role) {
    case 'signer_a':
    case 'signer_b':
      return role;
    default:
      throw new Error(`${label} must be signer_a or signer_b`);
  }
}

function requireLowerHex(value: unknown, label: string, byteLength: number): string {
  const hex = requireNonEmptyString(value, label);
  if (!new RegExp(`^[0-9a-f]{${byteLength * 2}}$`).test(hex)) {
    throw new Error(`${label} must be ${byteLength} lowercase-hex bytes`);
  }
  return hex;
}

function requireHpkePublicKey(value: unknown, label: string): string {
  const publicKey = requireNonEmptyString(value, label);
  if (!/^x25519:[0-9a-f]{64}$/.test(publicKey)) {
    throw new Error(`${label} must use x25519:<64 lowercase hex chars> encoding`);
  }
  return publicKey;
}

function parseSignerEnvelopeHpkePublicKey(
  value: unknown,
  label: string,
): RouterAbSignerEnvelopeHpkePublicKeyV1 {
  const record = requireRecord(value, label);
  requireExactKeys(record, ['role', 'key_epoch', 'public_key'], label);
  return {
    role: requireSignerRole(record.role, `${label}.role`),
    key_epoch: requireNonEmptyString(record.key_epoch, `${label}.key_epoch`),
    public_key: requireHpkePublicKey(record.public_key, `${label}.public_key`),
  };
}

function parseSignerEnvelopeHpkePublicKeySet(
  value: unknown,
  label: string,
): RouterAbSignerEnvelopeHpkePublicKeySetV1 {
  const record = requireRecord(value, label);
  requireExactKeys(record, ['deriver_a', 'deriver_b'], label);
  const deriverA = parseSignerEnvelopeHpkePublicKey(record.deriver_a, `${label}.deriver_a`);
  const deriverB = parseSignerEnvelopeHpkePublicKey(record.deriver_b, `${label}.deriver_b`);
  if (deriverA.role !== 'signer_a') {
    throw new Error(`${label}.deriver_a.role must be signer_a`);
  }
  if (deriverB.role !== 'signer_b') {
    throw new Error(`${label}.deriver_b.role must be signer_b`);
  }
  return {
    deriver_a: deriverA,
    deriver_b: deriverB,
  };
}

function requireRotatedSignerEnvelopeHpkeKey(
  label: string,
  current: RouterAbSignerEnvelopeHpkePublicKeyV1,
  previous: RouterAbSignerEnvelopeHpkePublicKeyV1,
): void {
  if (current.role !== previous.role) {
    throw new Error(`${label}.previous.role must match current role`);
  }
  if (current.key_epoch === previous.key_epoch) {
    throw new Error(`${label}.previous.key_epoch must differ from current key_epoch`);
  }
  if (current.public_key === previous.public_key) {
    throw new Error(`${label}.previous.public_key must differ from current public_key`);
  }
}

function parseSignerEnvelopeHpkeRotationPublicKeySet(
  value: unknown,
  label: string,
): RouterAbSignerEnvelopeHpkeRotationPublicKeySetV1 {
  const record = requireRecord(value, label);
  const hasPrevious = 'previous' in record || 'previous_retire_at_ms' in record;
  requireExactKeys(
    record,
    hasPrevious ? ['current', 'previous', 'previous_retire_at_ms'] : ['current'],
    label,
  );
  const current = parseSignerEnvelopeHpkePublicKeySet(record.current, `${label}.current`);
  if (!hasPrevious) {
    return { current };
  }
  const previous = parseSignerEnvelopeHpkePublicKeySet(record.previous, `${label}.previous`);
  requireRotatedSignerEnvelopeHpkeKey(
    `${label}.deriver_a`,
    current.deriver_a,
    previous.deriver_a,
  );
  requireRotatedSignerEnvelopeHpkeKey(
    `${label}.deriver_b`,
    current.deriver_b,
    previous.deriver_b,
  );
  return {
    current,
    previous,
    previous_retire_at_ms: requirePositiveInteger(
      record.previous_retire_at_ms,
      `${label}.previous_retire_at_ms`,
    ),
  };
}

function hasPreviousSignerEnvelopeHpkeKeySet(
  keyset: RouterAbSignerEnvelopeHpkeRotationPublicKeySetV1,
): keyset is RouterAbSignerEnvelopeHpkeRotatingPublicKeySetV1 {
  return keyset.previous !== undefined && keyset.previous_retire_at_ms !== undefined;
}

function parseSignerPeerVerifyingKey(
  value: unknown,
  label: string,
): RouterAbSignerPeerVerifyingKeyHexV1 {
  const record = requireRecord(value, label);
  requireExactKeys(record, ['role', 'verifying_key_hex'], label);
  return {
    role: requireSignerRole(record.role, `${label}.role`),
    verifying_key_hex: requireLowerHex(record.verifying_key_hex, `${label}.verifying_key_hex`, 32),
  };
}

function parseSignerPeerVerifyingKeySet(
  value: unknown,
  label: string,
): RouterAbSignerPeerVerifyingKeyHexSetV1 {
  const record = requireRecord(value, label);
  requireExactKeys(record, ['deriver_a', 'deriver_b'], label);
  const deriverA = parseSignerPeerVerifyingKey(record.deriver_a, `${label}.deriver_a`);
  const deriverB = parseSignerPeerVerifyingKey(record.deriver_b, `${label}.deriver_b`);
  if (deriverA.role !== 'signer_a') {
    throw new Error(`${label}.deriver_a.role must be signer_a`);
  }
  if (deriverB.role !== 'signer_b') {
    throw new Error(`${label}.deriver_b.role must be signer_b`);
  }
  return {
    deriver_a: deriverA,
    deriver_b: deriverB,
  };
}

function parsePublicHpkeKeyDescriptor(
  value: unknown,
  label: string,
): RouterAbPublicHpkeKeyDescriptorV1 {
  const record = requireRecord(value, label);
  requireExactKeys(record, ['key_epoch', 'public_key'], label);
  return {
    key_epoch: requireNonEmptyString(record.key_epoch, `${label}.key_epoch`),
    public_key: requireHpkePublicKey(record.public_key, `${label}.public_key`),
  };
}

export function parseRouterAbPublicKeysetV2(value: unknown): RouterAbPublicKeysetV2 {
  const record = requireRecord(value, 'Router A/B public keyset');
  requireExactKeys(
    record,
    [
      'keyset_version',
      'signer_envelope_hpke',
      'signer_peer_verifying_keys',
      'signing_worker_server_output_hpke',
    ],
    'Router A/B public keyset',
  );
  const keysetVersion = requireNonEmptyString(record.keyset_version, 'keyset_version');
  if (keysetVersion !== ROUTER_AB_PUBLIC_KEYSET_VERSION_V2) {
    throw new Error(`Unsupported Router A/B public keyset version: ${keysetVersion}`);
  }
  return {
    keyset_version: ROUTER_AB_PUBLIC_KEYSET_VERSION_V2,
    signer_envelope_hpke: parseSignerEnvelopeHpkeRotationPublicKeySet(
      record.signer_envelope_hpke,
      'signer_envelope_hpke',
    ),
    signer_peer_verifying_keys: parseSignerPeerVerifyingKeySet(
      record.signer_peer_verifying_keys,
      'signer_peer_verifying_keys',
    ),
    signing_worker_server_output_hpke: parsePublicHpkeKeyDescriptor(
      record.signing_worker_server_output_hpke,
      'signing_worker_server_output_hpke',
    ),
  };
}

export function selectRouterAbSignerEnvelopeHpkeKeyForEpoch(args: {
  keyset: RouterAbSignerEnvelopeHpkeRotationPublicKeySetV1;
  role: RouterAbSignerRoleV1;
  keyEpoch: string;
  nowMs: number;
}): RouterAbSignerEnvelopeHpkePublicKeyV1 {
  const keyEpoch = requireNonEmptyString(args.keyEpoch, 'keyEpoch');
  const nowMs = requirePositiveInteger(args.nowMs, 'nowMs');
  const current = selectSignerEnvelopeHpkeKey(args.keyset.current, args.role, 'current');
  if (current.key_epoch === keyEpoch) return current;
  if (hasPreviousSignerEnvelopeHpkeKeySet(args.keyset)) {
    const previous = selectSignerEnvelopeHpkeKey(args.keyset.previous, args.role, 'previous');
    if (previous.key_epoch === keyEpoch) {
      if (nowMs <= args.keyset.previous_retire_at_ms) return previous;
      throw new Error('previous signer-envelope HPKE key epoch is retired');
    }
  }
  throw new Error('signer-envelope HPKE key epoch is not in the current or previous keyset');
}

function selectSignerEnvelopeHpkeKey(
  keyset: RouterAbSignerEnvelopeHpkePublicKeySetV1,
  role: RouterAbSignerRoleV1,
  label: string,
): RouterAbSignerEnvelopeHpkePublicKeyV1 {
  switch (role) {
    case 'signer_a':
      return keyset.deriver_a;
    case 'signer_b':
      return keyset.deriver_b;
    default:
      throw new Error(`${label}.role must be signer_a or signer_b`);
  }
}
