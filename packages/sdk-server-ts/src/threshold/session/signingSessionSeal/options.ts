import { base64UrlDecode } from '@shared/utils/encoders';
import {
  SIGNING_SESSION_SEAL_ALG,
  SIGNING_SESSION_SEAL_GROUP_ID,
} from '@shared/utils/signingSessionSeal';
import { toOptionalTrimmedString } from '@shared/utils/validation';
import {
  parseSigningSessionSealKeyVersion,
  type SigningSessionSealKeyVersion,
} from '../../../core/keyMaterialBrands';
import {
  createSigningSessionSealShamir3PassCipherAdapter,
  type SigningSessionSealShamir3PassRootConfig,
} from './crypto/cipher';
import { createSigningSessionSealRoutesOptions } from './routesOptions';

export type CreateSigningSessionSealOptionsInput = {
  readonly rootSecretB64u: string;
  readonly currentKeyVersion: unknown;
  readonly acceptedWarmKeyVersions?: readonly unknown[];
};

function parseKeyVersion(value: unknown, label: string): SigningSessionSealKeyVersion {
  const parsed = toOptionalTrimmedString(value);
  if (!parsed) throw new Error(`${label} is required`);
  return parseSigningSessionSealKeyVersion(parsed);
}

function parseRootSecret32(value: unknown): Uint8Array {
  const encoded = toOptionalTrimmedString(value);
  if (!encoded) throw new Error('SIGNING_SESSION_SEAL_ROOT_SECRET_B64U is required');
  const rootSecret32 = base64UrlDecode(encoded);
  if (rootSecret32.length !== 32) {
    rootSecret32.fill(0);
    throw new Error('SIGNING_SESSION_SEAL_ROOT_SECRET_B64U must decode to exactly 32 bytes');
  }
  return rootSecret32;
}

export function parseSigningSessionSealRootConfig(
  input: CreateSigningSessionSealOptionsInput,
): SigningSessionSealShamir3PassRootConfig {
  const currentKeyVersion = parseKeyVersion(input.currentKeyVersion, 'currentKeyVersion');
  const acceptedWarmKeyVersions = (input.acceptedWarmKeyVersions ?? [currentKeyVersion]).map(
    (value, index) => parseKeyVersion(value, `acceptedWarmKeyVersions[${index}]`),
  );
  return {
    kind: 'shamir3pass_root_v2',
    rootSecret32: parseRootSecret32(input.rootSecretB64u),
    currentKeyVersion,
    acceptedWarmKeyVersions,
    protocol: {
      algorithm: SIGNING_SESSION_SEAL_ALG,
      groupId: SIGNING_SESSION_SEAL_GROUP_ID,
    },
  };
}

export function createSigningSessionSealOptions(input: CreateSigningSessionSealOptionsInput) {
  const config = parseSigningSessionSealRootConfig(input);
  return createSigningSessionSealRoutesOptions({
    cipher: createSigningSessionSealShamir3PassCipherAdapter({ config }),
    capabilities: {
      mode: 'sealed_refresh_v1',
      protocol: config.protocol,
      currentKeyVersion: config.currentKeyVersion,
    },
    logger: console,
  });
}
