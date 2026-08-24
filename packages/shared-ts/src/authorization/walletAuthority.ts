import { base64UrlDecode, base64UrlEncode } from '../utils/base64';
import { parseDigestB64u, type DigestB64u } from '../utils/canonicalPrimitives';
import { sha256Bytes } from '../utils/digests';
import {
  parseDelegatedWalletPermissionSetV1,
  type CanonicalDelegatedWalletPermissionSetV1,
} from './delegatedAuthority';
import {
  parseDeviceId,
  type AuthorizationParseResult,
  type DeviceId,
} from './capabilityKinds';
import {
  buildExactAdministeredSignerManifestV1,
  parseExactAdministeredSignerManifestV1,
  type ExactAdministeredEd25519SignerV1,
  type ExactAdministeredEcdsaSignerV1,
  type ExactAdministeredSignerManifestV1,
} from '../device-linking/delegatedActivationPlan';
import {
  parseLinkDeviceSessionId,
  parseLinkedDeviceEnrollmentId,
  parseMpcMaterialActivationRef,
  parseWalletAuthorityId,
  parseWalletId,
  type LinkDeviceSessionId,
  type LinkedDeviceEnrollmentId,
  type MpcMaterialActivationRef,
  type WalletAuthorityId,
  type WalletId,
} from '../utils/domainIds';

const SIGNER_ACTIVATION_SET_DOMAIN = 'seams/wallet-signer-activation-set/v1';
const WALLET_AUTHORITY_DOMAIN = 'seams/wallet-authority/v1';
const TEXT_ENCODER = new TextEncoder();

export type WalletAuthorityPrincipalV1 = {
  readonly kind: 'owner_device';
  readonly deviceId: DeviceId;
};

export type WalletAuthorityProvenanceV1 =
  | {
      readonly kind: 'wallet_registration';
      readonly enrollmentId?: never;
      readonly sourceAuthorityId?: never;
      readonly linkSessionId?: never;
    }
  | {
      readonly kind: 'device_link';
      readonly enrollmentId: LinkedDeviceEnrollmentId;
      readonly sourceAuthorityId: WalletAuthorityId;
      readonly linkSessionId: LinkDeviceSessionId;
    };

export type WalletEd25519SignerActivationV1 = {
  readonly kind: 'wallet_ed25519_signer_activation_v1';
  readonly signer: ExactAdministeredEd25519SignerV1;
  readonly materialActivation: MpcMaterialActivationRef;
};

export type WalletEcdsaSignerActivationV1 = {
  readonly kind: 'wallet_ecdsa_signer_activation_v1';
  readonly signer: ExactAdministeredEcdsaSignerV1;
  readonly materialActivation: MpcMaterialActivationRef;
};

export type WalletSignerActivationSetV1 =
  | {
      readonly kind: 'wallet_signer_activation_set_v1';
      readonly keyFamilies: readonly ['ed25519'];
      readonly ed25519: WalletEd25519SignerActivationV1;
      readonly ecdsa?: never;
    }
  | {
      readonly kind: 'wallet_signer_activation_set_v1';
      readonly keyFamilies: readonly ['ecdsa_secp256k1'];
      readonly ed25519?: never;
      readonly ecdsa: WalletEcdsaSignerActivationV1;
    }
  | {
      readonly kind: 'wallet_signer_activation_set_v1';
      readonly keyFamilies: readonly ['ed25519', 'ecdsa_secp256k1'];
      readonly ed25519: WalletEd25519SignerActivationV1;
      readonly ecdsa: WalletEcdsaSignerActivationV1;
    };

export type WalletSignerActivationMaterialsV1 =
  | {
      readonly keyFamilies: readonly ['ed25519'];
      readonly ed25519: MpcMaterialActivationRef;
      readonly ecdsa?: never;
    }
  | {
      readonly keyFamilies: readonly ['ecdsa_secp256k1'];
      readonly ed25519?: never;
      readonly ecdsa: MpcMaterialActivationRef;
    }
  | {
      readonly keyFamilies: readonly ['ed25519', 'ecdsa_secp256k1'];
      readonly ed25519: MpcMaterialActivationRef;
      readonly ecdsa: MpcMaterialActivationRef;
    };

export type WalletSignerActivationSetBuilderInputV1 = {
  readonly manifest: ExactAdministeredSignerManifestV1;
  readonly materialActivations: WalletSignerActivationMaterialsV1;
};

export type WalletAuthorityCommonV1 = {
  readonly kind: 'wallet_authority_v1';
  readonly authorityId: WalletAuthorityId;
  readonly walletId: WalletId;
  readonly principal: WalletAuthorityPrincipalV1;
  readonly provenance: WalletAuthorityProvenanceV1;
  readonly permissions: CanonicalDelegatedWalletPermissionSetV1;
  readonly signerActivations: WalletSignerActivationSetV1;
  readonly signerActivationSetDigestB64u: DigestB64u;
  readonly authorityDigestB64u: DigestB64u;
  readonly revocationEpoch: number;
  readonly createdAtMs: number;
  readonly updatedAtMs: number;
};

export type WalletAuthorityV1 = WalletAuthorityCommonV1 &
  (
    | {
        readonly state: 'pending_local_install';
        readonly localInstallPackageSetDigestB64u: DigestB64u;
        readonly activatedAtMs?: never;
        readonly revokedAtMs?: never;
      }
    | {
        readonly state: 'active';
        readonly localInstallPackageSetDigestB64u?: never;
        readonly activatedAtMs: number;
        readonly revokedAtMs?: never;
      }
    | {
        readonly state: 'revoked';
        readonly localInstallPackageSetDigestB64u?: never;
        readonly activatedAtMs: number;
        readonly revokedAtMs: number;
      }
  );

export type PendingWalletAuthorityV1 = Extract<
  WalletAuthorityV1,
  { readonly state: 'pending_local_install' }
>;
export type ActiveWalletAuthorityV1 = Extract<WalletAuthorityV1, { readonly state: 'active' }>;
export type RevokedWalletAuthorityV1 = Extract<WalletAuthorityV1, { readonly state: 'revoked' }>;

export type Ed25519WalletSignerActivationSetV1 = Extract<
  WalletSignerActivationSetV1,
  { readonly keyFamilies: readonly ['ed25519'] }
>;
export type EcdsaWalletSignerActivationSetV1 = Extract<
  WalletSignerActivationSetV1,
  { readonly keyFamilies: readonly ['ecdsa_secp256k1'] }
>;
export type CombinedWalletSignerActivationSetV1 = Extract<
  WalletSignerActivationSetV1,
  { readonly keyFamilies: readonly ['ed25519', 'ecdsa_secp256k1'] }
>;

export type ActiveEd25519WalletAuthorityV1 = Omit<
  ActiveWalletAuthorityV1,
  'signerActivations'
> & {
  readonly signerActivations: Ed25519WalletSignerActivationSetV1;
};
export type ActiveEcdsaWalletAuthorityV1 = Omit<ActiveWalletAuthorityV1, 'signerActivations'> & {
  readonly signerActivations: EcdsaWalletSignerActivationSetV1;
};
export type ActiveCombinedWalletAuthorityV1 = Omit<
  ActiveWalletAuthorityV1,
  'signerActivations'
> & {
  readonly signerActivations: CombinedWalletSignerActivationSetV1;
};

export function isCombinedWalletSignerActivationSetV1(
  value: WalletSignerActivationSetV1,
): value is CombinedWalletSignerActivationSetV1 {
  return isBothFamilyActivationSet(value);
}

export function isActiveEcdsaWalletAuthorityV1(
  value: ActiveWalletAuthorityV1,
): value is ActiveEcdsaWalletAuthorityV1 {
  return isEcdsaOnlyActivationSet(value.signerActivations);
}

export function buildWalletEd25519SignerActivationV1(input: {
  readonly signer: ExactAdministeredEd25519SignerV1;
  readonly materialActivation: MpcMaterialActivationRef;
}): WalletEd25519SignerActivationV1 {
  return {
    kind: 'wallet_ed25519_signer_activation_v1',
    signer: input.signer,
    materialActivation: input.materialActivation,
  };
}

export function buildWalletEcdsaSignerActivationV1(input: {
  readonly signer: ExactAdministeredEcdsaSignerV1;
  readonly materialActivation: MpcMaterialActivationRef;
}): WalletEcdsaSignerActivationV1 {
  return {
    kind: 'wallet_ecdsa_signer_activation_v1',
    signer: input.signer,
    materialActivation: input.materialActivation,
  };
}

export function buildWalletSignerActivationSetV1(
  input: WalletSignerActivationSetBuilderInputV1,
): WalletSignerActivationSetV1 {
  const manifest = parseExactAdministeredSignerManifestV1(input.manifest);
  const materials = normalizeWalletSignerActivationMaterials(input.materialActivations);
  if (!sameFamilies(manifest.keyFamilies, materials.keyFamilies)) {
    throw new Error('wallet signer activation materials must match the signer manifest families');
  }

  if (isEd25519OnlyManifest(manifest)) {
    if (!isEd25519OnlyMaterials(materials)) {
      throw new Error('Ed25519 signer activation requires one Ed25519 material activation');
    }
    return {
      kind: 'wallet_signer_activation_set_v1',
      keyFamilies: ['ed25519'],
      ed25519: buildWalletEd25519SignerActivationV1({
        signer: manifest.signers[0],
        materialActivation: materials.ed25519,
      }),
    };
  }
  if (isEcdsaOnlyManifest(manifest)) {
    if (!isEcdsaOnlyMaterials(materials)) {
      throw new Error('ECDSA signer activation requires one ECDSA material activation');
    }
    return {
      kind: 'wallet_signer_activation_set_v1',
      keyFamilies: ['ecdsa_secp256k1'],
      ecdsa: buildWalletEcdsaSignerActivationV1({
        signer: manifest.signers[0],
        materialActivation: materials.ecdsa,
      }),
    };
  }
  if (!isBothFamilyManifest(manifest) || !isBothFamilyMaterials(materials)) {
    throw new Error('wallet signer activation set has unsupported families');
  }
  if (materials.ed25519.activationId === materials.ecdsa.activationId) {
    throw new Error('wallet signer activation references must be distinct');
  }
  return {
    kind: 'wallet_signer_activation_set_v1',
    keyFamilies: ['ed25519', 'ecdsa_secp256k1'],
    ed25519: buildWalletEd25519SignerActivationV1({
      signer: manifest.signers[0],
      materialActivation: materials.ed25519,
    }),
    ecdsa: buildWalletEcdsaSignerActivationV1({
      signer: manifest.signers[1],
      materialActivation: materials.ecdsa,
    }),
  };
}

export function parseWalletSignerActivationSetV1(
  raw: unknown,
): AuthorizationParseResult<WalletSignerActivationSetV1> {
  try {
    const record = requireRecord(raw, 'WalletSignerActivationSetV1');
    if (record.kind !== 'wallet_signer_activation_set_v1') {
      return invalidResult('wallet signer activation set kind is unsupported');
    }
    if (!Object.prototype.hasOwnProperty.call(record, 'keyFamilies')) {
      return invalidResult('WalletSignerActivationSetV1.keyFamilies is required');
    }
    const families = parseFamilies(record.keyFamilies, 'WalletSignerActivationSetV1.keyFamilies');
    if (families.length === 1 && families[0] === 'ed25519') {
      exactFields(record, ['kind', 'keyFamilies', 'ed25519'], 'WalletSignerActivationSetV1');
      const activation = parseEd25519Activation(record.ed25519, 'ed25519');
      return {
        ok: true,
        value: {
          kind: 'wallet_signer_activation_set_v1',
          keyFamilies: ['ed25519'],
          ed25519: activation,
        },
      };
    }
    if (families.length === 1 && families[0] === 'ecdsa_secp256k1') {
      exactFields(record, ['kind', 'keyFamilies', 'ecdsa'], 'WalletSignerActivationSetV1');
      const activation = parseEcdsaActivation(record.ecdsa, 'ecdsa');
      return {
        ok: true,
        value: {
          kind: 'wallet_signer_activation_set_v1',
          keyFamilies: ['ecdsa_secp256k1'],
          ecdsa: activation,
        },
      };
    }
    exactFields(record, ['kind', 'keyFamilies', 'ed25519', 'ecdsa'], 'WalletSignerActivationSetV1');
    const ed25519 = parseEd25519Activation(record.ed25519, 'ed25519');
    const ecdsa = parseEcdsaActivation(record.ecdsa, 'ecdsa');
    if (ed25519.materialActivation.activationId === ecdsa.materialActivation.activationId) {
      return invalidResult('wallet signer activation references must be distinct');
    }
    return {
      ok: true,
      value: {
        kind: 'wallet_signer_activation_set_v1',
        keyFamilies: ['ed25519', 'ecdsa_secp256k1'],
        ed25519,
        ecdsa,
      },
    };
  } catch (error) {
    return invalidResult(errorMessage(error, 'wallet signer activation set is invalid'));
  }
}

export function encodeWalletSignerActivationSetV1(value: WalletSignerActivationSetV1): Uint8Array {
  const parts: Uint8Array[] = [
    text(SIGNER_ACTIVATION_SET_DOMAIN, 'domain'),
    text(value.kind, 'kind'),
    u32(value.keyFamilies.length, 'keyFamilies'),
  ];
  for (const family of value.keyFamilies) parts.push(text(family, 'keyFamilies.item'));
  if (isEd25519OnlyActivationSet(value) || isBothFamilyActivationSet(value)) {
    parts.push(lp32(encodeEd25519Activation(value.ed25519), 'ed25519'));
  }
  if (isEcdsaOnlyActivationSet(value) || isBothFamilyActivationSet(value)) {
    parts.push(lp32(encodeEcdsaActivation(value.ecdsa), 'ecdsa'));
  }
  return concat(parts);
}

export async function computeWalletSignerActivationSetDigestB64u(
  value: WalletSignerActivationSetV1,
): Promise<DigestB64u> {
  return parseDigestB64u(base64UrlEncode(await sha256Bytes(encodeWalletSignerActivationSetV1(value))));
}

export function parseWalletSignerActivationSetDigestB64u(raw: unknown): DigestB64u {
  try {
    return parseDigestB64u(raw);
  } catch (error) {
    throw new Error(errorMessage(error, 'wallet signer activation set digest is invalid'));
  }
}

export function buildWalletAuthorityV1(input: WalletAuthorityV1): WalletAuthorityV1 {
  validateWalletAuthorityV1(input);
  switch (input.state) {
    case 'pending_local_install':
      return buildPendingWalletAuthorityV1(input);
    case 'active':
      return buildActiveWalletAuthorityV1(input);
    case 'revoked':
      return buildRevokedWalletAuthorityV1(input);
  }
}

export function buildPendingWalletAuthorityV1(input: PendingWalletAuthorityV1): PendingWalletAuthorityV1 {
  validateWalletAuthorityV1(input);
  return {
    kind: 'wallet_authority_v1',
    authorityId: input.authorityId,
    walletId: input.walletId,
    principal: input.principal,
    provenance: input.provenance,
    permissions: input.permissions,
    signerActivations: input.signerActivations,
    signerActivationSetDigestB64u: input.signerActivationSetDigestB64u,
    authorityDigestB64u: input.authorityDigestB64u,
    revocationEpoch: input.revocationEpoch,
    createdAtMs: input.createdAtMs,
    updatedAtMs: input.updatedAtMs,
    state: 'pending_local_install',
    localInstallPackageSetDigestB64u: input.localInstallPackageSetDigestB64u,
  };
}

export function buildActiveWalletAuthorityV1(input: ActiveWalletAuthorityV1): ActiveWalletAuthorityV1 {
  validateWalletAuthorityV1(input);
  return {
    kind: 'wallet_authority_v1',
    authorityId: input.authorityId,
    walletId: input.walletId,
    principal: input.principal,
    provenance: input.provenance,
    permissions: input.permissions,
    signerActivations: input.signerActivations,
    signerActivationSetDigestB64u: input.signerActivationSetDigestB64u,
    authorityDigestB64u: input.authorityDigestB64u,
    revocationEpoch: input.revocationEpoch,
    createdAtMs: input.createdAtMs,
    updatedAtMs: input.updatedAtMs,
    state: 'active',
    activatedAtMs: input.activatedAtMs,
  };
}

export async function replaceActiveWalletAuthorityEd25519MaterialActivationV1(input: {
  readonly authority: ActiveWalletAuthorityV1;
  readonly materialActivation: MpcMaterialActivationRef;
  readonly updatedAtMs: number;
}): Promise<ActiveWalletAuthorityV1> {
  const current = input.authority.signerActivations;
  if (!current.ed25519) {
    throw new Error('active Wallet Authority has no Ed25519 material activation to replace');
  }
  const signerActivations = current.ecdsa
    ? buildWalletSignerActivationSetV1({
        manifest: buildExactAdministeredSignerManifestV1([
          current.ed25519.signer,
          current.ecdsa.signer,
        ]),
        materialActivations: {
          keyFamilies: ['ed25519', 'ecdsa_secp256k1'],
          ed25519: input.materialActivation,
          ecdsa: current.ecdsa.materialActivation,
        },
      })
    : buildWalletSignerActivationSetV1({
        manifest: buildExactAdministeredSignerManifestV1([current.ed25519.signer]),
        materialActivations: {
          keyFamilies: ['ed25519'],
          ed25519: input.materialActivation,
        },
      });
  const signerActivationSetDigestB64u =
    await computeWalletSignerActivationSetDigestB64u(signerActivations);
  const draft: ActiveWalletAuthorityV1 = {
    kind: input.authority.kind,
    authorityId: input.authority.authorityId,
    walletId: input.authority.walletId,
    principal: input.authority.principal,
    provenance: input.authority.provenance,
    permissions: input.authority.permissions,
    signerActivations,
    signerActivationSetDigestB64u,
    authorityDigestB64u: input.authority.authorityDigestB64u,
    revocationEpoch: input.authority.revocationEpoch,
    createdAtMs: input.authority.createdAtMs,
    updatedAtMs: Math.max(input.authority.updatedAtMs, input.updatedAtMs),
    state: 'active',
    activatedAtMs: input.authority.activatedAtMs,
  };
  return buildActiveWalletAuthorityV1({
    kind: draft.kind,
    authorityId: draft.authorityId,
    walletId: draft.walletId,
    principal: draft.principal,
    provenance: draft.provenance,
    permissions: draft.permissions,
    signerActivations: draft.signerActivations,
    signerActivationSetDigestB64u: draft.signerActivationSetDigestB64u,
    authorityDigestB64u: await computeWalletAuthorityDigestB64u(draft),
    revocationEpoch: draft.revocationEpoch,
    createdAtMs: draft.createdAtMs,
    updatedAtMs: draft.updatedAtMs,
    state: draft.state,
    activatedAtMs: draft.activatedAtMs,
  });
}

export function buildActiveCombinedWalletAuthorityV1(
  input: ActiveCombinedWalletAuthorityV1,
): ActiveCombinedWalletAuthorityV1 {
  validateWalletAuthorityV1(input);
  return {
    kind: 'wallet_authority_v1',
    authorityId: input.authorityId,
    walletId: input.walletId,
    principal: input.principal,
    provenance: input.provenance,
    permissions: input.permissions,
    signerActivations: input.signerActivations,
    signerActivationSetDigestB64u: input.signerActivationSetDigestB64u,
    authorityDigestB64u: input.authorityDigestB64u,
    revocationEpoch: input.revocationEpoch,
    createdAtMs: input.createdAtMs,
    updatedAtMs: input.updatedAtMs,
    state: 'active',
    activatedAtMs: input.activatedAtMs,
  };
}

export function buildRevokedWalletAuthorityV1(input: RevokedWalletAuthorityV1): RevokedWalletAuthorityV1 {
  validateWalletAuthorityV1(input);
  return {
    kind: 'wallet_authority_v1',
    authorityId: input.authorityId,
    walletId: input.walletId,
    principal: input.principal,
    provenance: input.provenance,
    permissions: input.permissions,
    signerActivations: input.signerActivations,
    signerActivationSetDigestB64u: input.signerActivationSetDigestB64u,
    authorityDigestB64u: input.authorityDigestB64u,
    revocationEpoch: input.revocationEpoch,
    createdAtMs: input.createdAtMs,
    updatedAtMs: input.updatedAtMs,
    state: 'revoked',
    activatedAtMs: input.activatedAtMs,
    revokedAtMs: input.revokedAtMs,
  };
}

export function parseWalletAuthorityV1(raw: unknown): AuthorizationParseResult<WalletAuthorityV1> {
  try {
    const record = requireRecord(raw, 'WalletAuthorityV1');
    const common = parseWalletAuthorityCommon(record);
    switch (record.state) {
      case 'pending_local_install': {
        exactFields(record, [
          'kind',
          'authorityId',
          'walletId',
          'principal',
          'provenance',
          'permissions',
          'signerActivations',
          'signerActivationSetDigestB64u',
          'authorityDigestB64u',
          'revocationEpoch',
          'createdAtMs',
          'updatedAtMs',
          'state',
          'localInstallPackageSetDigestB64u',
        ], 'WalletAuthorityV1');
        return {
          ok: true,
          value: buildPendingWalletAuthorityV1({
            kind: 'wallet_authority_v1',
            authorityId: common.authorityId,
            walletId: common.walletId,
            principal: common.principal,
            provenance: common.provenance,
            permissions: common.permissions,
            signerActivations: common.signerActivations,
            signerActivationSetDigestB64u: common.signerActivationSetDigestB64u,
            authorityDigestB64u: common.authorityDigestB64u,
            revocationEpoch: common.revocationEpoch,
            createdAtMs: common.createdAtMs,
            updatedAtMs: common.updatedAtMs,
            state: 'pending_local_install',
            localInstallPackageSetDigestB64u: parseDigestField(
              record.localInstallPackageSetDigestB64u,
              'localInstallPackageSetDigestB64u',
            ),
          }),
        };
      }
      case 'active': {
        exactFields(record, [
          'kind',
          'authorityId',
          'walletId',
          'principal',
          'provenance',
          'permissions',
          'signerActivations',
          'signerActivationSetDigestB64u',
          'authorityDigestB64u',
          'revocationEpoch',
          'createdAtMs',
          'updatedAtMs',
          'state',
          'activatedAtMs',
        ], 'WalletAuthorityV1');
        return {
          ok: true,
          value: buildActiveWalletAuthorityV1({
            kind: 'wallet_authority_v1',
            authorityId: common.authorityId,
            walletId: common.walletId,
            principal: common.principal,
            provenance: common.provenance,
            permissions: common.permissions,
            signerActivations: common.signerActivations,
            signerActivationSetDigestB64u: common.signerActivationSetDigestB64u,
            authorityDigestB64u: common.authorityDigestB64u,
            revocationEpoch: common.revocationEpoch,
            createdAtMs: common.createdAtMs,
            updatedAtMs: common.updatedAtMs,
            state: 'active',
            activatedAtMs: parseSafeInteger(record.activatedAtMs, 'activatedAtMs'),
          }),
        };
      }
      case 'revoked': {
        exactFields(record, [
          'kind',
          'authorityId',
          'walletId',
          'principal',
          'provenance',
          'permissions',
          'signerActivations',
          'signerActivationSetDigestB64u',
          'authorityDigestB64u',
          'revocationEpoch',
          'createdAtMs',
          'updatedAtMs',
          'state',
          'activatedAtMs',
          'revokedAtMs',
        ], 'WalletAuthorityV1');
        return {
          ok: true,
          value: buildRevokedWalletAuthorityV1({
            kind: 'wallet_authority_v1',
            authorityId: common.authorityId,
            walletId: common.walletId,
            principal: common.principal,
            provenance: common.provenance,
            permissions: common.permissions,
            signerActivations: common.signerActivations,
            signerActivationSetDigestB64u: common.signerActivationSetDigestB64u,
            authorityDigestB64u: common.authorityDigestB64u,
            revocationEpoch: common.revocationEpoch,
            createdAtMs: common.createdAtMs,
            updatedAtMs: common.updatedAtMs,
            state: 'revoked',
            activatedAtMs: parseSafeInteger(record.activatedAtMs, 'activatedAtMs'),
            revokedAtMs: parseSafeInteger(record.revokedAtMs, 'revokedAtMs'),
          }),
        };
      }
      default:
        return invalidResult('WalletAuthorityV1.state is unsupported');
    }
  } catch (error) {
    return invalidResult(errorMessage(error, 'wallet authority is invalid'));
  }
}

export function encodeWalletAuthorityV1(value: WalletAuthorityV1): Uint8Array {
  const parts: Uint8Array[] = [
    text(WALLET_AUTHORITY_DOMAIN, 'domain'),
    text(value.kind, 'kind'),
    text(value.authorityId, 'authorityId'),
    text(value.walletId, 'walletId'),
    lp32(encodePrincipal(value.principal), 'principal'),
    lp32(encodeProvenance(value.provenance), 'provenance'),
    lp32(encodePermissions(value.permissions), 'permissions'),
    rawDigest(value.signerActivationSetDigestB64u, 'signerActivationSetDigestB64u'),
    text(value.state, 'state'),
    u64(value.revocationEpoch, 'revocationEpoch'),
  ];
  return concat(parts);
}

export async function computeWalletAuthorityDigestB64u(
  value: WalletAuthorityV1,
): Promise<DigestB64u> {
  return parseDigestB64u(base64UrlEncode(await sha256Bytes(encodeWalletAuthorityV1(value))));
}

export function parseWalletAuthorityDigestB64u(raw: unknown): DigestB64u {
  try {
    return parseDigestB64u(raw);
  } catch (error) {
    throw new Error(errorMessage(error, 'wallet authority digest is invalid'));
  }
}

export async function walletAuthorityDigestsMatchV1(value: WalletAuthorityV1): Promise<boolean> {
  const activationDigest = await computeWalletSignerActivationSetDigestB64u(value.signerActivations);
  if (activationDigest !== value.signerActivationSetDigestB64u) return false;
  const authorityDigest = await computeWalletAuthorityDigestB64u(value);
  return authorityDigest === value.authorityDigestB64u;
}

function parseWalletAuthorityCommon(record: Record<string, unknown>): Omit<
  WalletAuthorityCommonV1,
  'kind'
> {
  const kind = record.kind;
  if (kind !== 'wallet_authority_v1') throw new Error('WalletAuthorityV1.kind is unsupported');
  const authorityId = requireParsed(parseWalletAuthorityId(record.authorityId), 'authorityId');
  const walletId = requireParsed(parseWalletId(record.walletId), 'walletId');
  const principal = parsePrincipal(record.principal);
  const provenance = parseProvenance(record.provenance);
  const permissions = requireParsed(
    parseDelegatedWalletPermissionSetV1(record.permissions),
    'permissions',
  );
  const signerActivations = requireParsed(
    parseWalletSignerActivationSetV1(record.signerActivations),
    'signerActivations',
  );
  const signerActivationSetDigestB64u = parseDigestField(
    record.signerActivationSetDigestB64u,
    'signerActivationSetDigestB64u',
  );
  const authorityDigestB64u = parseDigestField(record.authorityDigestB64u, 'authorityDigestB64u');
  const revocationEpoch = parseSafeInteger(record.revocationEpoch, 'revocationEpoch');
  const createdAtMs = parseSafeInteger(record.createdAtMs, 'createdAtMs');
  const updatedAtMs = parseSafeInteger(record.updatedAtMs, 'updatedAtMs');
  validateSignerActivationsForWallet(signerActivations, walletId);
  return {
    authorityId,
    walletId,
    principal,
    provenance,
    permissions,
    signerActivations,
    signerActivationSetDigestB64u,
    authorityDigestB64u,
    revocationEpoch,
    createdAtMs,
    updatedAtMs,
  };
}

function validateWalletAuthorityV1(value: WalletAuthorityV1): void {
  if (value.kind !== 'wallet_authority_v1') throw new Error('wallet authority kind is unsupported');
  if (!Number.isSafeInteger(value.revocationEpoch) || value.revocationEpoch < 0) {
    throw new Error('wallet authority revocationEpoch must be a non-negative safe integer');
  }
  validateTimestamp(value.createdAtMs, 'createdAtMs');
  validateTimestamp(value.updatedAtMs, 'updatedAtMs');
  if (value.updatedAtMs < value.createdAtMs) {
    throw new Error('wallet authority updatedAtMs cannot precede createdAtMs');
  }
  parseDigestField(value.signerActivationSetDigestB64u, 'signerActivationSetDigestB64u');
  parseDigestField(value.authorityDigestB64u, 'authorityDigestB64u');
  validateSignerActivationsForWallet(value.signerActivations, value.walletId);
  validateProvenance(value.provenance);
  switch (value.state) {
    case 'pending_local_install':
      parseDigestField(value.localInstallPackageSetDigestB64u, 'localInstallPackageSetDigestB64u');
      break;
    case 'active':
      validateTimestamp(value.activatedAtMs, 'activatedAtMs');
      break;
    case 'revoked':
      validateTimestamp(value.activatedAtMs, 'activatedAtMs');
      validateTimestamp(value.revokedAtMs, 'revokedAtMs');
      if (value.revokedAtMs < value.activatedAtMs) {
        throw new Error('revokedAtMs cannot precede activatedAtMs');
      }
      break;
  }
}

function parsePrincipal(raw: unknown): WalletAuthorityPrincipalV1 {
  const record = exactRecord(raw, ['kind', 'deviceId'], 'WalletAuthorityPrincipalV1');
  if (record.kind !== 'owner_device') throw new Error('wallet authority principal kind is unsupported');
  return {
    kind: 'owner_device',
    deviceId: requireParsed(parseDeviceId(record.deviceId), 'deviceId'),
  };
}

function parseProvenance(raw: unknown): WalletAuthorityProvenanceV1 {
  const record = requireRecord(raw, 'WalletAuthorityProvenanceV1');
  switch (record.kind) {
    case 'wallet_registration':
      exactFields(record, ['kind'], 'WalletAuthorityProvenanceV1');
      return { kind: 'wallet_registration' };
    case 'device_link':
      exactFields(
        record,
        ['kind', 'enrollmentId', 'sourceAuthorityId', 'linkSessionId'],
        'WalletAuthorityProvenanceV1',
      );
      return {
        kind: 'device_link',
        enrollmentId: requireParsed(
          parseLinkedDeviceEnrollmentId(record.enrollmentId),
          'enrollmentId',
        ),
        sourceAuthorityId: requireParsed(
          parseWalletAuthorityId(record.sourceAuthorityId),
          'sourceAuthorityId',
        ),
        linkSessionId: requireParsed(parseLinkDeviceSessionId(record.linkSessionId), 'linkSessionId'),
      };
    default:
      throw new Error('wallet authority provenance kind is unsupported');
  }
}

function validateProvenance(value: WalletAuthorityProvenanceV1): void {
  switch (value.kind) {
    case 'wallet_registration':
      return;
    case 'device_link':
      if (!value.enrollmentId || !value.sourceAuthorityId || !value.linkSessionId) {
        throw new Error('device-link provenance requires every audit identity');
      }
      return;
  }
}

function validateSignerActivationsForWallet(
  value: WalletSignerActivationSetV1,
  walletId: WalletId,
): void {
  if (isEd25519OnlyActivationSet(value)) {
    if (value.ed25519.signer.walletId !== walletId) {
      throw new Error('Ed25519 signer activation uses a different wallet id');
    }
    return;
  }
  if (isEcdsaOnlyActivationSet(value)) {
    if (value.ecdsa.signer.walletId !== walletId) {
      throw new Error('ECDSA signer activation uses a different wallet id');
    }
    return;
  }
  if (isBothFamilyActivationSet(value)) {
    if (
      value.ed25519.signer.walletId !== walletId ||
      value.ecdsa.signer.walletId !== walletId
    ) {
      throw new Error('signer activations must use the authority wallet id');
    }
    return;
  }
  throw new Error('wallet signer activation families are unsupported');
}

function parseEd25519Activation(
  raw: unknown,
  label: string,
): WalletEd25519SignerActivationV1 {
  const record = exactRecord(raw, ['kind', 'signer', 'materialActivation'], label);
  if (record.kind !== 'wallet_ed25519_signer_activation_v1') {
    throw new Error(`${label}.kind is invalid`);
  }
  const manifest = parseManifestForSigner(record.signer, 'ed25519', `${label}.signer`);
  if (!isEd25519OnlyManifest(manifest)) throw new Error(`${label}.signer is not Ed25519`);
  return buildWalletEd25519SignerActivationV1({
    signer: manifest.signers[0],
    materialActivation: requireParsed(
      parseMpcMaterialActivationRef(record.materialActivation),
      `${label}.materialActivation`,
    ),
  });
}

function parseEcdsaActivation(raw: unknown, label: string): WalletEcdsaSignerActivationV1 {
  const record = exactRecord(raw, ['kind', 'signer', 'materialActivation'], label);
  if (record.kind !== 'wallet_ecdsa_signer_activation_v1') {
    throw new Error(`${label}.kind is invalid`);
  }
  const manifest = parseManifestForSigner(record.signer, 'ecdsa_secp256k1', `${label}.signer`);
  if (!isEcdsaOnlyManifest(manifest)) throw new Error(`${label}.signer is not ECDSA`);
  return buildWalletEcdsaSignerActivationV1({
    signer: manifest.signers[0],
    materialActivation: requireParsed(
      parseMpcMaterialActivationRef(record.materialActivation),
      `${label}.materialActivation`,
    ),
  });
}

function parseManifestForSigner(
  raw: unknown,
  family: 'ed25519' | 'ecdsa_secp256k1',
  label: string,
): ExactAdministeredSignerManifestV1 {
  return parseExactAdministeredSignerManifestV1({
    kind: 'exact_administered_signer_manifest_v1',
    keyFamilies: [family],
    signers: [raw],
  });
}

function encodeEd25519Activation(value: WalletEd25519SignerActivationV1): Uint8Array {
  return concat([
    text(value.kind, 'ed25519.kind'),
    lp32(encodeEd25519Signer(value.signer), 'ed25519.signer'),
    lp32(encodeMaterialActivation(value.materialActivation), 'ed25519.materialActivation'),
  ]);
}

function encodeEcdsaActivation(value: WalletEcdsaSignerActivationV1): Uint8Array {
  return concat([
    text(value.kind, 'ecdsa.kind'),
    lp32(encodeEcdsaSigner(value.signer), 'ecdsa.signer'),
    lp32(encodeMaterialActivation(value.materialActivation), 'ecdsa.materialActivation'),
  ]);
}

function encodeEd25519Signer(value: ExactAdministeredEd25519SignerV1): Uint8Array {
  return concat([
    text(value.kind, 'ed25519.signer.kind'),
    text(value.keyFamily, 'ed25519.signer.keyFamily'),
    text(value.walletId, 'ed25519.signer.walletId'),
    text(value.walletKeyId, 'ed25519.signer.walletKeyId'),
    lp32(rawPublicKey(value.registeredPublicKeyB64u, 'ed25519.signer.registeredPublicKeyB64u'), 'ed25519.signer.registeredPublicKeyB64u'),
  ]);
}

function encodeEcdsaSigner(value: ExactAdministeredEcdsaSignerV1): Uint8Array {
  return concat([
    text(value.kind, 'ecdsa.signer.kind'),
    text(value.keyFamily, 'ecdsa.signer.keyFamily'),
    text(value.walletId, 'ecdsa.signer.walletId'),
    text(value.walletKeyId, 'ecdsa.signer.walletKeyId'),
    lp32(rawPublicKey(value.thresholdPublicKey33B64u, 'ecdsa.signer.thresholdPublicKey33B64u'), 'ecdsa.signer.thresholdPublicKey33B64u'),
    text(value.evmAddress, 'ecdsa.signer.evmAddress'),
  ]);
}

function encodeMaterialActivation(value: MpcMaterialActivationRef): Uint8Array {
  return concat([
    text(value.kind, 'materialActivation.kind'),
    text(value.activationId, 'materialActivation.activationId'),
    text(value.capability, 'materialActivation.capability'),
    text(value.materialOwner, 'materialActivation.materialOwner'),
    text(value.keyBinding, 'materialActivation.keyBinding'),
    text(value.lifecycleBinding, 'materialActivation.lifecycleBinding'),
    text(value.signingWorker, 'materialActivation.signingWorker'),
  ]);
}

function encodePrincipal(value: WalletAuthorityPrincipalV1): Uint8Array {
  return concat([text(value.kind, 'principal.kind'), text(value.deviceId, 'principal.deviceId')]);
}

function encodeProvenance(value: WalletAuthorityProvenanceV1): Uint8Array {
  if (value.kind === 'wallet_registration') return text(value.kind, 'provenance.kind');
  return concat([
    text(value.kind, 'provenance.kind'),
    text(value.enrollmentId, 'provenance.enrollmentId'),
    text(value.sourceAuthorityId, 'provenance.sourceAuthorityId'),
    text(value.linkSessionId, 'provenance.linkSessionId'),
  ]);
}

function encodePermissions(value: CanonicalDelegatedWalletPermissionSetV1): Uint8Array {
  const parts: Uint8Array[] = [u32(value.length, 'permissions')];
  for (const permission of value) parts.push(lp32(text(permission, 'permissions.item'), 'permissions.item'));
  return concat(parts);
}

function requireRecord(value: unknown, label: string): Record<string, unknown> {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error(`${label} must be an object`);
  }
  return value as Record<string, unknown>;
}

function exactRecord(
  value: unknown,
  fields: readonly string[],
  label: string,
): Record<string, unknown> {
  const record = requireRecord(value, label);
  exactFields(record, fields, label);
  return record;
}

function exactFields(record: Record<string, unknown>, fields: readonly string[], label: string): void {
  const expected = new Set(fields);
  const actual = Object.keys(record);
  if (actual.length !== fields.length) throw new Error(`${label} contains unexpected fields`);
  for (const field of actual) {
    if (!expected.has(field)) throw new Error(`${label}.${field} is not allowed`);
  }
  for (const field of fields) {
    if (!Object.prototype.hasOwnProperty.call(record, field)) {
      throw new Error(`${label}.${field} is required`);
    }
  }
}

function parseFamilies(
  raw: unknown,
  label: string,
): WalletSignerActivationSetV1['keyFamilies'] {
  if (!Array.isArray(raw)) throw new Error(`${label} must be an array`);
  if (raw.length === 1 && raw[0] === 'ed25519') return ['ed25519'];
  if (raw.length === 1 && raw[0] === 'ecdsa_secp256k1') return ['ecdsa_secp256k1'];
  if (raw.length === 2 && raw[0] === 'ed25519' && raw[1] === 'ecdsa_secp256k1') {
    return ['ed25519', 'ecdsa_secp256k1'];
  }
  throw new Error(`${label} must use canonical family order`);
}

function sameFamilies(
  left: readonly string[],
  right: readonly string[],
): boolean {
  if (left.length !== right.length) return false;
  for (let index = 0; index < left.length; index += 1) {
    if (left[index] !== right[index]) return false;
  }
  return true;
}

function isEd25519OnlyManifest(
  value: ExactAdministeredSignerManifestV1,
): value is Extract<ExactAdministeredSignerManifestV1, { readonly keyFamilies: readonly ['ed25519'] }> {
  return value.keyFamilies.length === 1 && value.keyFamilies[0] === 'ed25519';
}

function isEcdsaOnlyManifest(
  value: ExactAdministeredSignerManifestV1,
): value is Extract<
  ExactAdministeredSignerManifestV1,
  { readonly keyFamilies: readonly ['ecdsa_secp256k1'] }
> {
  return value.keyFamilies.length === 1 && value.keyFamilies[0] === 'ecdsa_secp256k1';
}

function isBothFamilyManifest(
  value: ExactAdministeredSignerManifestV1,
): value is Extract<
  ExactAdministeredSignerManifestV1,
  { readonly keyFamilies: readonly ['ed25519', 'ecdsa_secp256k1'] }
> {
  return value.keyFamilies.length === 2;
}

function isEd25519OnlyMaterials(
  value: WalletSignerActivationMaterialsV1,
): value is Extract<WalletSignerActivationMaterialsV1, { readonly keyFamilies: readonly ['ed25519'] }> {
  return value.keyFamilies.length === 1 && value.keyFamilies[0] === 'ed25519';
}

function isEcdsaOnlyMaterials(
  value: WalletSignerActivationMaterialsV1,
): value is Extract<
  WalletSignerActivationMaterialsV1,
  { readonly keyFamilies: readonly ['ecdsa_secp256k1'] }
> {
  return value.keyFamilies.length === 1 && value.keyFamilies[0] === 'ecdsa_secp256k1';
}

function isBothFamilyMaterials(
  value: WalletSignerActivationMaterialsV1,
): value is Extract<
  WalletSignerActivationMaterialsV1,
  { readonly keyFamilies: readonly ['ed25519', 'ecdsa_secp256k1'] }
> {
  return value.keyFamilies.length === 2;
}

function normalizeWalletSignerActivationMaterials(
  value: WalletSignerActivationMaterialsV1,
): WalletSignerActivationMaterialsV1 {
  if (isEd25519OnlyMaterials(value)) {
    return {
      keyFamilies: ['ed25519'],
      ed25519: requireParsed(
        parseMpcMaterialActivationRef(value.ed25519),
        'materialActivations.ed25519',
      ),
    };
  }
  if (isEcdsaOnlyMaterials(value)) {
    return {
      keyFamilies: ['ecdsa_secp256k1'],
      ecdsa: requireParsed(
        parseMpcMaterialActivationRef(value.ecdsa),
        'materialActivations.ecdsa',
      ),
    };
  }
  if (isBothFamilyMaterials(value)) {
    return {
      keyFamilies: ['ed25519', 'ecdsa_secp256k1'],
      ed25519: requireParsed(
        parseMpcMaterialActivationRef(value.ed25519),
        'materialActivations.ed25519',
      ),
      ecdsa: requireParsed(
        parseMpcMaterialActivationRef(value.ecdsa),
        'materialActivations.ecdsa',
      ),
    };
  }
  throw new Error('wallet signer activation materials are unsupported');
}

function isEd25519OnlyActivationSet(
  value: WalletSignerActivationSetV1,
): value is Extract<WalletSignerActivationSetV1, { readonly keyFamilies: readonly ['ed25519'] }> {
  return value.keyFamilies.length === 1 && value.keyFamilies[0] === 'ed25519';
}

function isEcdsaOnlyActivationSet(
  value: WalletSignerActivationSetV1,
): value is Extract<
  WalletSignerActivationSetV1,
  { readonly keyFamilies: readonly ['ecdsa_secp256k1'] }
> {
  return value.keyFamilies.length === 1 && value.keyFamilies[0] === 'ecdsa_secp256k1';
}

function isBothFamilyActivationSet(
  value: WalletSignerActivationSetV1,
): value is Extract<
  WalletSignerActivationSetV1,
  { readonly keyFamilies: readonly ['ed25519', 'ecdsa_secp256k1'] }
> {
  return value.keyFamilies.length === 2;
}

function parseDigestField(raw: unknown, label: string): DigestB64u {
  try {
    return parseDigestB64u(raw);
  } catch (error) {
    throw new Error(`${label} ${errorMessage(error, 'is invalid')}`);
  }
}

function rawDigest(value: DigestB64u, label: string): Uint8Array {
  try {
    const digest = parseDigestB64u(value);
    return base64UrlDecode(digest);
  } catch (error) {
    throw new Error(`${label} ${errorMessage(error, 'is invalid')}`);
  }
}

function rawPublicKey(value: string, label: string): Uint8Array {
  try {
    const decoded = base64UrlDecode(value);
    if (decoded.length === 0 || base64UrlEncode(decoded) !== value) {
      throw new Error('must be canonical base64url');
    }
    return decoded;
  } catch (error) {
    throw new Error(`${label} ${errorMessage(error, 'is invalid')}`);
  }
}

function concat(parts: readonly Uint8Array[]): Uint8Array {
  let length = 0;
  for (const part of parts) length += part.length;
  const output = new Uint8Array(length);
  let offset = 0;
  for (const part of parts) {
    output.set(part, offset);
    offset += part.length;
  }
  return output;
}

function u32(value: number, label: string): Uint8Array {
  if (!Number.isSafeInteger(value) || value < 0 || value > 0xffffffff) {
    throw new Error(`${label} must be a non-negative u32`);
  }
  return Uint8Array.from([
    (value >>> 24) & 0xff,
    (value >>> 16) & 0xff,
    (value >>> 8) & 0xff,
    value & 0xff,
  ]);
}

function u64(value: number, label: string): Uint8Array {
  if (!Number.isSafeInteger(value) || value < 0) {
    throw new Error(`${label} must be a non-negative safe integer`);
  }
  let remaining = BigInt(value);
  const output = new Uint8Array(8);
  for (let index = 7; index >= 0; index -= 1) {
    output[index] = Number(remaining & 0xffn);
    remaining >>= 8n;
  }
  return output;
}

function lp32(value: Uint8Array, label: string): Uint8Array {
  return concat([u32(value.length, `${label}.length`), value]);
}

function text(value: string, label: string): Uint8Array {
  if (typeof value !== 'string') throw new Error(`${label} must be a string`);
  return lp32(TEXT_ENCODER.encode(value), label);
}

function parseSafeInteger(raw: unknown, label: string): number {
  if (typeof raw !== 'number' || !Number.isSafeInteger(raw) || raw < 0) {
    throw new Error(`${label} must be a non-negative safe integer`);
  }
  return raw;
}

function validateTimestamp(value: number, label: string): void {
  if (!Number.isSafeInteger(value) || value < 0) {
    throw new Error(`${label} must be a non-negative safe integer`);
  }
}

function requireParsed<T>(
  result: AuthorizationParseResult<T> | { readonly ok: true; readonly value: T } | { readonly ok: false; readonly error: { readonly message: string } },
  label: string,
): T {
  if (result.ok) return result.value;
  throw new Error(`${label} ${result.error.message}`);
}

function invalidResult<T>(message: string): AuthorizationParseResult<T> {
  return { ok: false, error: { code: 'invalid', message } };
}

function errorMessage(error: unknown, fallback: string): string {
  return error instanceof Error ? error.message : fallback;
}
