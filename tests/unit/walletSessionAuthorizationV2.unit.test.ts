import { expect, test } from '@playwright/test';
import {
  buildActiveWalletAuthorityV1,
  buildWalletSignerActivationSetV1,
  computeWalletAuthorityDigestB64u,
  computeWalletSignerActivationSetDigestB64u,
  type ActiveWalletAuthorityV1,
} from '@shared/authorization/walletAuthority';
import { buildFullOwnerPermissionsV1 } from '@shared/authorization/delegatedAuthority';
import { parseDeviceId } from '@shared/authorization/capabilityKinds';
import { parseExactAdministeredSignerManifestV1 } from '@shared/device-linking/delegatedActivationPlan';
import {
  parseMpcWalletSigningQuotaId,
  parsePrincipalId,
  parseReusableWalletSessionMintId,
  parseTenantId,
  parseWalletSessionAuthorizationId,
  parseWalletSessionId,
} from '@shared/authorization/capabilityKinds';
import {
  parseWalletAuthMethodId,
  parseWalletAuthorityId,
  parseWalletId,
  type WalletAuthMethodId,
  type WalletAuthorityId,
} from '@shared/utils/domainIds';
import { base64UrlEncode } from '@shared/utils/base64';
import { parseDigestB64u, type DigestB64u } from '@shared/utils/canonicalPrimitives';
import { buildMpcMaterialActivationRefFixture } from './helpers/ecdsaMaterialRef.fixtures';
import {
  buildWalletSessionAuthorizationV2,
  buildWalletSessionCapabilitySubjectsV1,
  parseWalletSessionAuthorizationV2,
  walletSessionAuthorizationV2RecordsEqual,
  type WalletSessionAuthorizationV2,
  type WalletSessionCapabilitySubjectV1,
} from '../../packages/wallet-server/src/authorization/domain';

type SignerFamily = 'ed25519' | 'ecdsa_secp256k1' | 'both';

function required<T>(
  result:
    | { readonly ok: true; readonly value: T }
    | { readonly ok: false; readonly error: { readonly message: string } },
): T {
  if (result.ok) return result.value;
  throw new Error(result.error.message);
}

function buildSignerManifest(
  family: SignerFamily,
  walletId: string,
  label: string,
): ReturnType<typeof parseExactAdministeredSignerManifestV1> {
  const ed25519 = {
    kind: 'exact_administered_ed25519_signer_v1' as const,
    keyFamily: 'ed25519' as const,
    walletId,
    walletKeyId: `wallet-key:v2-${label}-ed25519`,
    registeredPublicKeyB64u: base64UrlEncode(new Uint8Array(32).fill(3)),
  };
  const ecdsa = {
    kind: 'exact_administered_ecdsa_signer_v1' as const,
    keyFamily: 'ecdsa_secp256k1' as const,
    walletId,
    walletKeyId: `wallet-key:v2-${label}-ecdsa`,
    thresholdPublicKey33B64u: base64UrlEncode(new Uint8Array([2, ...new Uint8Array(32).fill(4)])),
    evmAddress: `0x${'1'.repeat(40)}`,
  };
  switch (family) {
    case 'ed25519':
      return parseExactAdministeredSignerManifestV1({
        kind: 'exact_administered_signer_manifest_v1',
        keyFamilies: ['ed25519'],
        signers: [ed25519],
      });
    case 'ecdsa_secp256k1':
      return parseExactAdministeredSignerManifestV1({
        kind: 'exact_administered_signer_manifest_v1',
        keyFamilies: ['ecdsa_secp256k1'],
        signers: [ecdsa],
      });
    case 'both':
      return parseExactAdministeredSignerManifestV1({
        kind: 'exact_administered_signer_manifest_v1',
        keyFamilies: ['ed25519', 'ecdsa_secp256k1'],
        signers: [ed25519, ecdsa],
      });
  }
}

function buildSignerActivations(
  family: SignerFamily,
  walletId: string,
  label: string,
) {
  const manifest = buildSignerManifest(family, walletId, label);
  switch (family) {
    case 'ed25519':
      return buildWalletSignerActivationSetV1({
        manifest,
        materialActivations: {
          keyFamilies: ['ed25519'],
          ed25519: buildMpcMaterialActivationRefFixture(`v2-${label}-ed25519`),
        },
      });
    case 'ecdsa_secp256k1':
      return buildWalletSignerActivationSetV1({
        manifest,
        materialActivations: {
          keyFamilies: ['ecdsa_secp256k1'],
          ecdsa: buildMpcMaterialActivationRefFixture(`v2-${label}-ecdsa`),
        },
      });
    case 'both':
      return buildWalletSignerActivationSetV1({
        manifest,
        materialActivations: {
          keyFamilies: ['ed25519', 'ecdsa_secp256k1'],
          ed25519: buildMpcMaterialActivationRefFixture(`v2-${label}-ed25519`),
          ecdsa: buildMpcMaterialActivationRefFixture(`v2-${label}-ecdsa`),
        },
      });
  }
}

async function buildAuthority(family: SignerFamily): Promise<ActiveWalletAuthorityV1> {
  const label = family.replace('_', '-');
  const walletId = required(parseWalletId(`wallet:v2-${label}`));
  const authorityId = required(parseWalletAuthorityId(`authority:v2-${label}`));
  const deviceId = required(parseDeviceId(`device:v2-${label}`));
  const signerActivations = buildSignerActivations(family, String(walletId), label);
  const signerActivationSetDigestB64u = parseDigestB64u(
    await computeWalletSignerActivationSetDigestB64u(signerActivations),
  );
  const draft = buildActiveWalletAuthorityV1({
    kind: 'wallet_authority_v1',
    authorityId,
    walletId,
    principal: { kind: 'owner_device', deviceId },
    provenance: { kind: 'wallet_registration' },
    permissions: buildFullOwnerPermissionsV1(),
    signerActivations,
    signerActivationSetDigestB64u,
    authorityDigestB64u: parseDigestB64u(base64UrlEncode(new Uint8Array(32).fill(8))),
    revocationEpoch: 0,
    createdAtMs: 100,
    updatedAtMs: 200,
    state: 'active',
    activatedAtMs: 200,
  });
  return buildActiveWalletAuthorityV1({
    kind: draft.kind,
    authorityId: draft.authorityId,
    walletId: draft.walletId,
    principal: draft.principal,
    provenance: draft.provenance,
    permissions: draft.permissions,
    signerActivations: draft.signerActivations,
    signerActivationSetDigestB64u: draft.signerActivationSetDigestB64u,
    authorityDigestB64u: parseDigestB64u(await computeWalletAuthorityDigestB64u(draft)),
    revocationEpoch: draft.revocationEpoch,
    createdAtMs: draft.createdAtMs,
    updatedAtMs: draft.updatedAtMs,
    state: draft.state,
    activatedAtMs: draft.activatedAtMs,
  });
}

function buildSession(
  authority: ActiveWalletAuthorityV1,
  walletAuthMethodId: WalletAuthMethodId,
  capabilitySubjects: readonly [WalletSessionCapabilitySubjectV1, ...WalletSessionCapabilitySubjectV1[]],
): WalletSessionAuthorizationV2 {
  return buildWalletSessionAuthorizationV2({
    tenantId: required(parseTenantId('tenant:v2-session')),
    principalId: required(parsePrincipalId('principal:v2-session')),
    walletId: authority.walletId,
    authorityId: authority.authorityId,
    walletAuthMethodId,
    authorityDigestB64u: authority.authorityDigestB64u,
    authorityRevocationEpoch: authority.revocationEpoch,
    mintId: required(parseReusableWalletSessionMintId('mint:v2-session')),
    authorizationId: required(parseWalletSessionAuthorizationId('authorization:v2-session')),
    walletSessionId: required(parseWalletSessionId('wallet-session:v2-session')),
    quotaId: required(parseMpcWalletSigningQuotaId('quota:v2-session')),
    capabilitySubjects,
    createdAtMs: 300,
    expiresAtMs: 400,
  });
}

function rebuildWithProvenance(
  session: WalletSessionAuthorizationV2,
  authorityId: WalletAuthorityId,
  walletAuthMethodId: WalletAuthMethodId,
  authorityDigestB64u: DigestB64u,
  authorityRevocationEpoch: number,
): WalletSessionAuthorizationV2 {
  return buildWalletSessionAuthorizationV2({
    tenantId: session.tenantId,
    principalId: session.principalId,
    walletId: session.walletId,
    authorityId,
    walletAuthMethodId,
    authorityDigestB64u,
    authorityRevocationEpoch,
    mintId: session.mintId,
    authorizationId: session.authorizationId,
    walletSessionId: session.walletSessionId,
    quotaId: session.quotaId,
    capabilitySubjects: session.capabilitySubjects,
    createdAtMs: session.createdAtMs,
    expiresAtMs: session.expiresAtMs,
  });
}

function signerFamilies(
  subjects: readonly WalletSessionCapabilitySubjectV1[],
): string[] {
  const families: string[] = [];
  for (const subject of subjects) {
    if (subject.kind === 'sign') families.push(subject.keyFamily);
  }
  return families;
}

test('constructs and parses an exact V2 Wallet Session authorization', async () => {
  const authority = await buildAuthority('ed25519');
  const methodId = required(parseWalletAuthMethodId('passkey:v2-session:original'));
  const subjects = buildWalletSessionCapabilitySubjectsV1(authority);
  const session = buildSession(authority, methodId, subjects);
  const parsed = parseWalletSessionAuthorizationV2(JSON.parse(JSON.stringify(session)));

  expect(parsed.kind).toBe('wallet_session_authorization_v2');
  expect(parsed.capabilitySubjects).toEqual(subjects);
  expect(walletSessionAuthorizationV2RecordsEqual(session, parsed)).toBe(true);
});

test('rejects empty and malformed capability subjects at the parser boundary', async () => {
  const authority = await buildAuthority('ed25519');
  const methodId = required(parseWalletAuthMethodId('passkey:v2-session:malformed'));
  const session = buildSession(
    authority,
    methodId,
    buildWalletSessionCapabilitySubjectsV1(authority),
  );
  const emptySubjects = JSON.parse(JSON.stringify(session));
  emptySubjects.capabilitySubjects = [];
  expect(() => parseWalletSessionAuthorizationV2(emptySubjects)).toThrow(
    /capability subjects must be non-empty/,
  );

  const malformedSigner = JSON.parse(JSON.stringify(session));
  malformedSigner.capabilitySubjects[0].materialActivation = {
    kind: 'mpc_material_activation_ref',
  };
  expect(() => parseWalletSessionAuthorizationV2(malformedSigner)).toThrow(
    /mpcMaterialActivationRef has invalid fields/,
  );
});

test('rejects authority, method, digest, and epoch drift during exact replay comparison', async () => {
  const authority = await buildAuthority('ed25519');
  const methodId = required(parseWalletAuthMethodId('passkey:v2-session:drift'));
  const session = buildSession(
    authority,
    methodId,
    buildWalletSessionCapabilitySubjectsV1(authority),
  );
  const otherAuthorityId = required(parseWalletAuthorityId('authority:v2-session:other'));
  const otherMethodId = required(parseWalletAuthMethodId('passkey:v2-session:other'));
  const otherDigest = parseDigestB64u(base64UrlEncode(new Uint8Array(32).fill(13)));
  const candidates = [
    rebuildWithProvenance(session, otherAuthorityId, methodId, session.authorityDigestB64u, 0),
    rebuildWithProvenance(session, session.authorityId, otherMethodId, session.authorityDigestB64u, 0),
    rebuildWithProvenance(session, session.authorityId, methodId, otherDigest, 0),
    rebuildWithProvenance(session, session.authorityId, methodId, session.authorityDigestB64u, 1),
  ];

  for (const candidate of candidates) {
    expect(walletSessionAuthorizationV2RecordsEqual(session, candidate)).toBe(false);
  }
});

test('emits exhaustive signer-family subjects for Ed25519, ECDSA, and both', async () => {
  const ed25519Authority = await buildAuthority('ed25519');
  const ecdsaAuthority = await buildAuthority('ecdsa_secp256k1');
  const bothAuthority = await buildAuthority('both');

  expect(signerFamilies(buildWalletSessionCapabilitySubjectsV1(ed25519Authority))).toEqual([
    'ed25519',
  ]);
  expect(signerFamilies(buildWalletSessionCapabilitySubjectsV1(ecdsaAuthority))).toEqual([
    'ecdsa_secp256k1',
  ]);
  expect(signerFamilies(buildWalletSessionCapabilitySubjectsV1(bothAuthority))).toEqual([
    'ed25519',
    'ecdsa_secp256k1',
  ]);
});
