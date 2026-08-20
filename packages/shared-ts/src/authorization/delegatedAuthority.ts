import type { AuthorizationParseResult } from './capabilityKinds';

export type DelegatedWalletPermissionV1 =
  | 'sign'
  | 'export_keys'
  | 'link_devices'
  | 'revoke_devices';

export const FULL_OWNER_PERMISSIONS = Object.freeze([
  'export_keys',
  'link_devices',
  'revoke_devices',
  'sign',
] as const) satisfies readonly DelegatedWalletPermissionV1[];

export const SIGNING_ONLY_PERMISSIONS = Object.freeze([
  'sign',
] as const) satisfies readonly DelegatedWalletPermissionV1[];

const DELEGATED_WALLET_PERMISSION_VALUES: readonly DelegatedWalletPermissionV1[] = [
  'export_keys',
  'link_devices',
  'revoke_devices',
  'sign',
];
const DELEGATED_WALLET_PERMISSION_VALUE_SET = new Set<string>(DELEGATED_WALLET_PERMISSION_VALUES);

type CanonicalPermissionTuple = readonly [
  DelegatedWalletPermissionV1,
  ...DelegatedWalletPermissionV1[],
];

const canonicalPermissionSetBrand: unique symbol = Symbol('canonicalPermissionSetBrand');

class CanonicalDelegatedWalletPermissionSetProof extends Array<DelegatedWalletPermissionV1> {
  readonly [canonicalPermissionSetBrand] = true as const;

  private constructor(permissions: CanonicalPermissionTuple) {
    super(...permissions);
    Object.freeze(this);
  }

  static create(permissions: CanonicalPermissionTuple): CanonicalDelegatedWalletPermissionSetProof {
    return new CanonicalDelegatedWalletPermissionSetProof(permissions);
  }

  static get [Symbol.species](): ArrayConstructor {
    return Array;
  }
}

/** A canonical permission set can only be obtained from a boundary parser or builder. */
export type CanonicalDelegatedWalletPermissionSetV1 = CanonicalDelegatedWalletPermissionSetProof;

export type DelegatedWalletAuthorityV1 = {
  readonly kind: 'delegated_wallet_authority_v1';
  readonly permissions: CanonicalDelegatedWalletPermissionSetV1;
};

export function isDelegatedWalletPermissionV1(
  value: unknown,
): value is DelegatedWalletPermissionV1 {
  return typeof value === 'string' && DELEGATED_WALLET_PERMISSION_VALUE_SET.has(value);
}

export function parseDelegatedWalletPermissionSetV1(
  raw: unknown,
): AuthorizationParseResult<CanonicalDelegatedWalletPermissionSetV1> {
  if (!Array.isArray(raw)) {
    return invalidPermissionResult(
      raw == null
        ? 'delegated wallet permissions are required'
        : 'delegated wallet permissions must be an array',
    );
  }
  if (raw.length === 0) {
    return invalidPermissionResult('delegated wallet permissions must be non-empty');
  }

  const permissions: DelegatedWalletPermissionV1[] = [];
  const seen = new Set<DelegatedWalletPermissionV1>();
  for (const value of raw) {
    if (!isDelegatedWalletPermissionV1(value)) {
      return invalidPermissionResult('delegated wallet permission is unsupported');
    }
    if (seen.has(value)) {
      return invalidPermissionResult(`delegated wallet permission ${value} is duplicated`);
    }
    seen.add(value);
    permissions.push(value);
  }

  permissions.sort(compareDelegatedWalletPermissions);
  return {
    ok: true,
    value: CanonicalDelegatedWalletPermissionSetProof.create(
      toNonEmptyPermissionTuple(permissions),
    ),
  };
}

export function buildDelegatedWalletAuthorityV1(input: {
  readonly permissions: CanonicalDelegatedWalletPermissionSetV1;
}): DelegatedWalletAuthorityV1 {
  return {
    kind: 'delegated_wallet_authority_v1',
    permissions: input.permissions,
  };
}

export function parseDelegatedWalletAuthorityV1(
  raw: unknown,
): AuthorizationParseResult<DelegatedWalletAuthorityV1> {
  if (!isExactAuthorityRecord(raw)) {
    return invalidAuthorityResult(
      'delegated wallet authority must contain exactly kind and permissions',
    );
  }
  if (raw.kind !== 'delegated_wallet_authority_v1') {
    return invalidAuthorityResult('delegated wallet authority kind is unsupported');
  }
  const permissions = parseDelegatedWalletPermissionSetV1(raw.permissions);
  if (!permissions.ok) return permissions;
  return {
    ok: true,
    value: buildDelegatedWalletAuthorityV1({ permissions: permissions.value }),
  };
}

export function buildFullOwnerPermissionsV1(): CanonicalDelegatedWalletPermissionSetV1 {
  return buildPresetPermissionSet(FULL_OWNER_PERMISSIONS);
}

export function buildSigningOnlyPermissionsV1(): CanonicalDelegatedWalletPermissionSetV1 {
  return buildPresetPermissionSet(SIGNING_ONLY_PERMISSIONS);
}

export function buildFullOwnerDelegatedWalletAuthorityV1(): DelegatedWalletAuthorityV1 {
  return buildDelegatedWalletAuthorityV1({ permissions: buildFullOwnerPermissionsV1() });
}

export function buildSigningOnlyDelegatedWalletAuthorityV1(): DelegatedWalletAuthorityV1 {
  return buildDelegatedWalletAuthorityV1({ permissions: buildSigningOnlyPermissionsV1() });
}

export function hasDelegatedWalletPermissionV1(
  authority: DelegatedWalletAuthorityV1,
  permission: DelegatedWalletPermissionV1,
): boolean {
  return authority.permissions.includes(permission);
}

export function delegatedWalletPermissionNamesV1(
  authority: DelegatedWalletAuthorityV1,
): readonly DelegatedWalletPermissionV1[] {
  return Object.freeze([...authority.permissions]);
}

export function sameDelegatedWalletAuthorityV1(
  left: DelegatedWalletAuthorityV1,
  right: DelegatedWalletAuthorityV1,
): boolean {
  if (left.kind !== right.kind || left.permissions.length !== right.permissions.length) {
    return false;
  }
  for (let index = 0; index < left.permissions.length; index += 1) {
    if (left.permissions[index] !== right.permissions[index]) return false;
  }
  return true;
}

export function validateDelegatedWalletAuthorityAttenuationV1(input: {
  readonly parent: DelegatedWalletAuthorityV1;
  readonly child: DelegatedWalletAuthorityV1;
}): AuthorizationParseResult<true> {
  for (const permission of input.child.permissions) {
    if (!input.parent.permissions.includes(permission)) {
      return {
        ok: false,
        error: {
          code: 'invalid',
          message: `delegated authority cannot grant ${permission} outside its parent authority`,
        },
      };
    }
  }
  return { ok: true, value: true };
}

export function assertDelegatedWalletAuthorityAttenuationV1(input: {
  readonly parent: DelegatedWalletAuthorityV1;
  readonly child: DelegatedWalletAuthorityV1;
}): void {
  const result = validateDelegatedWalletAuthorityAttenuationV1(input);
  if (!result.ok) throw new Error(result.error.message);
}

function buildPresetPermissionSet(
  permissions: readonly DelegatedWalletPermissionV1[],
): CanonicalDelegatedWalletPermissionSetV1 {
  const parsed = parseDelegatedWalletPermissionSetV1(permissions);
  if (!parsed.ok) throw new Error(parsed.error.message);
  return parsed.value;
}

function compareDelegatedWalletPermissions(
  left: DelegatedWalletPermissionV1,
  right: DelegatedWalletPermissionV1,
): number {
  return left < right ? -1 : left > right ? 1 : 0;
}

function toNonEmptyPermissionTuple(
  permissions: readonly DelegatedWalletPermissionV1[],
): CanonicalPermissionTuple {
  const [first, ...remaining] = permissions;
  if (!first) throw new Error('delegated wallet permissions must be non-empty');
  return [first, ...remaining];
}

function isExactAuthorityRecord(
  value: unknown,
): value is { readonly kind: unknown; readonly permissions: unknown } {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return false;
  const keys = Object.keys(value);
  return keys.length === 2 && keys.includes('kind') && keys.includes('permissions');
}

function invalidPermissionResult<T>(message: string): AuthorizationParseResult<T> {
  return { ok: false, error: { code: 'invalid', message } };
}

function invalidAuthorityResult<T>(message: string): AuthorizationParseResult<T> {
  return { ok: false, error: { code: 'invalid', message } };
}
