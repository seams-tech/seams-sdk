export const ROUTER_AB_PUBLIC_KEYSET_VERSION_V1 = 'router_ab_keyset_v1' as const;
export const ROUTER_AB_PUBLIC_KEYSET_WELL_KNOWN_PATH_V1 = '/.well-known/router-ab/keyset' as const;
export const ROUTER_AB_PUBLIC_KEYSET_PATH_V1 = '/v1/router-ab/keyset' as const;

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

export type RouterAbPublicKeysetV1 = {
  keyset_version: typeof ROUTER_AB_PUBLIC_KEYSET_VERSION_V1;
  route_profile: string;
  signer_envelope_hpke: RouterAbSignerEnvelopeHpkePublicKeySetV1;
  signer_peer_verifying_keys: RouterAbSignerPeerVerifyingKeyHexSetV1;
  signing_worker_server_output_hpke: RouterAbPublicHpkeKeyDescriptorV1;
};

function requireRecord(value: unknown, label: string): Record<string, unknown> {
  if (value && typeof value === 'object' && !Array.isArray(value)) {
    return value as Record<string, unknown>;
  }
  throw new Error(`${label} must be an object`);
}

function requireNonEmptyString(value: unknown, label: string): string {
  const normalized = String(value || '').trim();
  if (!normalized) throw new Error(`${label} is required`);
  return normalized;
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

function parseSignerPeerVerifyingKey(
  value: unknown,
  label: string,
): RouterAbSignerPeerVerifyingKeyHexV1 {
  const record = requireRecord(value, label);
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
  return {
    key_epoch: requireNonEmptyString(record.key_epoch, `${label}.key_epoch`),
    public_key: requireHpkePublicKey(record.public_key, `${label}.public_key`),
  };
}

export function parseRouterAbPublicKeysetV1(value: unknown): RouterAbPublicKeysetV1 {
  const record = requireRecord(value, 'Router A/B public keyset');
  const keysetVersion = requireNonEmptyString(record.keyset_version, 'keyset_version');
  if (keysetVersion !== ROUTER_AB_PUBLIC_KEYSET_VERSION_V1) {
    throw new Error(`Unsupported Router A/B public keyset version: ${keysetVersion}`);
  }
  return {
    keyset_version: ROUTER_AB_PUBLIC_KEYSET_VERSION_V1,
    route_profile: requireNonEmptyString(record.route_profile, 'route_profile'),
    signer_envelope_hpke: parseSignerEnvelopeHpkePublicKeySet(
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
