import {
  buildFullOwnerPermissionsV1,
  buildSigningOnlyDelegatedWalletAuthorityV1,
  type CanonicalDelegatedWalletPermissionSetV1,
} from '../../../packages/shared-ts/src/authorization/delegatedAuthority';
import {
  buildActiveWalletAuthorityV1,
  computeWalletAuthorityDigestB64u,
  computeWalletSignerActivationSetDigestB64u,
  buildRevokedWalletAuthorityV1,
  buildWalletSignerActivationSetV1,
  type ActiveWalletAuthorityV1,
  type RevokedWalletAuthorityV1,
} from '../../../packages/shared-ts/src/authorization/walletAuthority';
import {
  buildActiveWalletSessionQuota,
  buildWalletSessionAuthorizationV2,
  buildWalletSessionCapabilitySubjectsV1,
  projectActiveWalletSession,
  type IssuedWalletSessionAuthorizationV2,
} from '../../../packages/wallet-server/src/authorization/domain';
import {
  parseDeviceId,
  parseMpcWalletSigningQuotaId,
  parsePrincipalId,
  parseReusableWalletSessionMintId,
  parseTenantId,
  parseWalletSessionAuthorizationId,
  parseWalletSessionId,
} from '../../../packages/shared-ts/src/authorization/capabilityKinds';
import { base64UrlEncode } from '../../../packages/shared-ts/src/utils/base64';
import { parseDigestB64u } from '../../../packages/shared-ts/src/utils/canonicalPrimitives';
import {
  buildWalletAuthMethodRecordV2,
  type WalletAuthMethodRecordV2,
} from '../../../packages/shared-ts/src/utils/registrationIntent';
import {
  parseLinkedDeviceEnrollmentId,
  parseLinkDeviceSessionId,
  parseMpcMaterialActivationRef,
  parseWalletAuthMethodId,
  parseWalletAuthorityId,
  parseWalletId,
  parseWalletRecoveryOperationId,
  parseWebAuthnCredentialIdB64u,
  parseWebAuthnRpId,
  type MpcMaterialActivationRef,
} from '../../../packages/shared-ts/src/utils/domainIds';
import { parseExactAdministeredSignerManifestV1 } from '../../../packages/shared-ts/src/device-linking/delegatedActivationPlan';
import type { ExactAdministeredEcdsaSignerV1 } from '../../../packages/shared-ts/src/device-linking/delegatedActivationPlan';
import { parseWalletSessionOperationCredentialV1 } from '../../../packages/shared-ts/src/device-linking/parsers';
import type {
  ActiveWalletSessionV1,
  WalletSessionOperationCredentialV1,
} from '../../../packages/shared-ts/src/device-linking/contracts';
import type { WalletSelectionRecordV1 } from '../../../packages/wallet/src/core/indexedDB/passkeyClientDB.types';
import { buildMpcMaterialActivationRefFixture } from './ecdsaMaterialRef.fixtures';

const MANAGEMENT_DIGEST = parseDigestB64u(base64UrlEncode(new Uint8Array(32).fill(33)));

type ActivePasskeyWalletAuthMethodRecordV2 = Extract<
  WalletAuthMethodRecordV2,
  { readonly kind: 'passkey'; readonly status: 'active' }
>;

type RevokedPasskeyWalletAuthMethodRecordV2 = Extract<
  WalletAuthMethodRecordV2,
  { readonly kind: 'passkey'; readonly status: 'revoked' }
>;

function required<T>(
  result:
    | { readonly ok: true; readonly value: T }
    | { readonly ok: false; readonly error: { readonly message: string } },
): T {
  if (!result.ok) throw new Error(result.error.message);
  return result.value;
}

/**
 * The identity a founding authority is built under.
 *
 * One coherent value rather than four independent overrides: a fixture whose
 * wallet came from the caller but whose authority id came from the label would
 * be an authority for a wallet it does not belong to, and every test using it
 * would be asserting against a state the production stores cannot hold.
 *
 * Canonical encodings stay inside the factory. A caller supplies names; the
 * factory decides what a valid credential id looks like.
 */
export type LinkedDeviceManagementAuthorityIdentityV1 = {
  readonly walletId: string;
  readonly authorityId: string;
  readonly walletAuthMethodId: string;
  readonly rpId: string;
};

export type LinkedDeviceManagementAuthorityFixture = {
  readonly authority: ActiveWalletAuthorityV1;
  readonly authMethod: ActivePasskeyWalletAuthMethodRecordV2;
  readonly selection: WalletSelectionRecordV1;
  readonly issuedSession: IssuedWalletSessionAuthorizationV2;
  readonly activeWalletSession: ActiveWalletSessionV1;
  readonly operationCredential: WalletSessionOperationCredentialV1;
};

export async function buildLinkedDeviceManagementAuthorityFixture(input: {
  readonly label: string;
  readonly permissions: CanonicalDelegatedWalletPermissionSetV1;
  readonly provenance: 'wallet_registration' | 'device_link' | 'wallet_recovery';
  readonly keyFamily?: 'ed25519' | 'ecdsa_secp256k1';
  readonly materialActivation?: MpcMaterialActivationRef;
  readonly sourceAuthorityId?: ActiveWalletAuthorityV1['authorityId'];
  readonly identity?: LinkedDeviceManagementAuthorityIdentityV1;
  readonly expiresAtMs?: number;
  readonly tenantId?: string;
  readonly principalId?: string;
  readonly ecdsaSigner?: Pick<
    ExactAdministeredEcdsaSignerV1,
    'walletKeyId' | 'thresholdPublicKey33B64u' | 'evmAddress'
  >;
}): Promise<LinkedDeviceManagementAuthorityFixture> {
  const walletId = required(parseWalletId(input.identity?.walletId ?? 'wallet:management'));
  const authorityId = required(
    parseWalletAuthorityId(input.identity?.authorityId ?? `authority:management-${input.label}`),
  );
  const deviceId = required(parseDeviceId(`device:management-${input.label}`));
  const keyFamily = input.keyFamily ?? 'ed25519';
  const manifest =
    keyFamily === 'ed25519'
      ? parseExactAdministeredSignerManifestV1({
          kind: 'exact_administered_signer_manifest_v1',
          keyFamilies: ['ed25519'],
          signers: [
            {
              kind: 'exact_administered_ed25519_signer_v1',
              keyFamily: 'ed25519',
              walletId: String(walletId),
              walletKeyId: `wallet-key:management-${input.label}`,
              registeredPublicKeyB64u: base64UrlEncode(new Uint8Array(32).fill(34)),
            },
          ],
        })
      : parseExactAdministeredSignerManifestV1({
          kind: 'exact_administered_signer_manifest_v1',
          keyFamilies: ['ecdsa_secp256k1'],
          signers: [
            {
              kind: 'exact_administered_ecdsa_signer_v1',
              keyFamily: 'ecdsa_secp256k1',
              walletId: String(walletId),
              walletKeyId: input.ecdsaSigner?.walletKeyId ?? `wallet-key:management-${input.label}`,
              thresholdPublicKey33B64u:
                input.ecdsaSigner?.thresholdPublicKey33B64u ??
                base64UrlEncode(new Uint8Array([2, ...new Uint8Array(32).fill(38)])),
              evmAddress: input.ecdsaSigner?.evmAddress ?? `0x${'1'.repeat(40)}`,
            },
          ],
        });
  const signerActivations =
    keyFamily === 'ed25519'
      ? buildWalletSignerActivationSetV1({
          manifest,
          materialActivations: {
            keyFamilies: ['ed25519'],
            ed25519:
              input.materialActivation ??
              buildMpcMaterialActivationRefFixture(`management-${input.label}`),
          },
        })
      : buildWalletSignerActivationSetV1({
          manifest,
          materialActivations: {
            keyFamilies: ['ecdsa_secp256k1'],
            ecdsa:
              input.materialActivation ??
              buildMpcMaterialActivationRefFixture(`management-${input.label}`),
          },
        });
  const provenance =
    input.provenance === 'wallet_registration'
      ? ({ kind: 'wallet_registration' } as const)
      : input.provenance === 'device_link'
        ? {
            kind: 'device_link' as const,
            enrollmentId: required(
              parseLinkedDeviceEnrollmentId(`enrollment:management-${input.label}`),
            ),
            sourceAuthorityId:
              input.sourceAuthorityId ??
              required(parseWalletAuthorityId('authority:management-owner')),
            linkSessionId: required(
              parseLinkDeviceSessionId(`link-session:management-${input.label}`),
            ),
          }
        : {
            kind: 'wallet_recovery' as const,
            recoveryOperationId: required(
              parseWalletRecoveryOperationId(`wallet-recovery-operation:${input.label}`),
            ),
            continuityAuthorityId:
              input.sourceAuthorityId ??
              required(parseWalletAuthorityId('authority:management-owner')),
          };
  /* Canonical, not placeholder. Every server path that reads an authority
     recomputes both digests and refuses a record whose stored values disagree,
     so a fixture with a stand-in digest describes a row production would treat
     as corrupt. The authority digest covers the activation digest, so they are
     computed in that order. */
  const signerActivationSetDigestB64u =
    await computeWalletSignerActivationSetDigestB64u(signerActivations);
  const authorityWithoutDigest = buildActiveWalletAuthorityV1({
    kind: 'wallet_authority_v1',
    authorityId,
    walletId,
    principal: { kind: 'owner_device', deviceId },
    provenance,
    permissions: input.permissions,
    signerActivations,
    signerActivationSetDigestB64u,
    authorityDigestB64u: MANAGEMENT_DIGEST,
    revocationEpoch: 0,
    createdAtMs: 100,
    updatedAtMs: 200,
    state: 'active',
    activatedAtMs: 200,
  });
  const authority = buildActiveWalletAuthorityV1({
    ...authorityWithoutDigest,
    authorityDigestB64u: await computeWalletAuthorityDigestB64u(authorityWithoutDigest),
  });
  const rpId = required(parseWebAuthnRpId(input.identity?.rpId ?? 'management.example.test'));
  const credentialIdB64u = required(
    parseWebAuthnCredentialIdB64u(
      base64UrlEncode(new Uint8Array(32).fill(input.label === 'owner' ? 35 : 36)),
    ),
  );
  const authMethodId = required(
    parseWalletAuthMethodId(
      input.identity?.walletAuthMethodId ?? `auth-method:management-${input.label}`,
    ),
  );
  const authMethod = buildActivePasskeyWalletAuthMethodRecord({
    version: 'wallet_auth_method_v2',
    walletAuthMethodId: authMethodId,
    walletId,
    walletAuthorityId: authorityId,
    kind: 'passkey',
    status: 'active',
    rpId,
    credentialIdB64u,
    credentialPublicKeyB64u: base64UrlEncode(new Uint8Array(65).fill(37)),
    counter: 0,
    createdAtMs: 100,
    updatedAtMs: 200,
    activatedAtMs: 200,
  });
  const tenantId = required(parseTenantId(input.tenantId ?? 'tenant:management'));
  const principalId = required(
    parsePrincipalId(input.principalId ?? `principal:management-${input.label}`),
  );
  const walletSessionId = required(
    parseWalletSessionId(`wallet-session:management-${input.label}`),
  );
  const authorizationId = required(
    parseWalletSessionAuthorizationId(`authorization:management-${input.label}`),
  );
  const quotaId = required(parseMpcWalletSigningQuotaId(`wallet-quota:management-${input.label}`));
  const mintId = required(
    parseReusableWalletSessionMintId(`wallet-mint:management-${input.label}`),
  );
  const expiresAtMs = input.expiresAtMs ?? 10_000;
  const session = buildWalletSessionAuthorizationV2({
    tenantId,
    principalId,
    walletId,
    authorityId,
    walletAuthMethodId: authMethodId,
    authorityDigestB64u: authority.authorityDigestB64u,
    authorityRevocationEpoch: authority.revocationEpoch,
    mintId,
    authorizationId,
    walletSessionId,
    quotaId,
    capabilitySubjects: buildWalletSessionCapabilitySubjectsV1(authority),
    createdAtMs: 300,
    expiresAtMs,
  });
  const issuedSession = {
    session,
    quota: buildActiveWalletSessionQuota({
      tenantId,
      principalId,
      walletSessionId,
      quotaId,
      remainingUses: 10,
      expiresAtMs,
    }),
  };
  return {
    authority,
    authMethod,
    selection: {
      kind: 'wallet_selection_v1',
      walletId,
      walletAuthMethodId: authMethodId,
      lockGeneration: 0,
      lockState: 'unlocked',
      updatedAtMs: 200,
    },
    issuedSession,
    activeWalletSession: projectActiveWalletSession(issuedSession),
    operationCredential: parseWalletSessionOperationCredentialV1({
      kind: 'opaque_wallet_session_operation_credential_v1',
      token: `wst_${base64UrlEncode(new Uint8Array(32).fill((input.label.length % 254) + 1))}`,
      walletSessionId,
    }),
  };
}

export async function extendFixtureAuthorityWithEcdsaSigner(
  authority: ActiveWalletAuthorityV1,
): Promise<ActiveWalletAuthorityV1> {
  if (authority.signerActivations.keyFamilies.length !== 1 || !authority.signerActivations.ed25519) {
    throw new Error('fixture authority must begin with one Ed25519 signer');
  }
  const ecdsaSigner = {
    kind: 'exact_administered_ecdsa_signer_v1' as const,
    keyFamily: 'ecdsa_secp256k1' as const,
    walletId: authority.walletId,
    walletKeyId: `wallet-key:management-deferred-ecdsa:${authority.walletId}`,
    thresholdPublicKey33B64u: base64UrlEncode(
      new Uint8Array([2, ...new Uint8Array(32).fill(48)]),
    ),
    evmAddress: `0x${'2'.repeat(40)}`,
  };
  const manifest = parseExactAdministeredSignerManifestV1({
    kind: 'exact_administered_signer_manifest_v1',
    keyFamilies: ['ed25519', 'ecdsa_secp256k1'],
    signers: [authority.signerActivations.ed25519.signer, ecdsaSigner],
  });
  const signerActivations = buildWalletSignerActivationSetV1({
    manifest,
    materialActivations: {
      keyFamilies: ['ed25519', 'ecdsa_secp256k1'],
      ed25519: authority.signerActivations.ed25519.materialActivation,
      ecdsa: buildMpcMaterialActivationRefFixture(
        `management-deferred-ecdsa-${authority.walletId}`,
      ),
    },
  });
  const signerActivationSetDigestB64u =
    await computeWalletSignerActivationSetDigestB64u(signerActivations);
  const draft = buildActiveWalletAuthorityV1({
    kind: authority.kind,
    authorityId: authority.authorityId,
    walletId: authority.walletId,
    principal: authority.principal,
    provenance: authority.provenance,
    permissions: authority.permissions,
    signerActivations,
    signerActivationSetDigestB64u,
    authorityDigestB64u: authority.authorityDigestB64u,
    revocationEpoch: authority.revocationEpoch,
    createdAtMs: authority.createdAtMs,
    updatedAtMs: authority.updatedAtMs + 1,
    state: authority.state,
    activatedAtMs: authority.activatedAtMs,
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
    authorityDigestB64u: await computeWalletAuthorityDigestB64u(draft),
    revocationEpoch: draft.revocationEpoch,
    createdAtMs: draft.createdAtMs,
    updatedAtMs: draft.updatedAtMs,
    state: draft.state,
    activatedAtMs: draft.activatedAtMs,
  });
}

export function buildRevokedLinkedDeviceAuthorityV1(
  authority: ActiveWalletAuthorityV1,
  revokedAtMs: number,
): RevokedWalletAuthorityV1 {
  return buildRevokedWalletAuthorityV1({
    kind: authority.kind,
    authorityId: authority.authorityId,
    walletId: authority.walletId,
    principal: authority.principal,
    provenance: authority.provenance,
    permissions: authority.permissions,
    signerActivations: authority.signerActivations,
    signerActivationSetDigestB64u: authority.signerActivationSetDigestB64u,
    authorityDigestB64u: authority.authorityDigestB64u,
    revocationEpoch: authority.revocationEpoch + 1,
    createdAtMs: authority.createdAtMs,
    updatedAtMs: revokedAtMs,
    state: 'revoked',
    activatedAtMs: authority.activatedAtMs,
    revokedAtMs,
  });
}

export function buildRevokedLinkedDeviceAuthMethodV1(
  authMethod: ActivePasskeyWalletAuthMethodRecordV2,
  revokedAtMs: number,
): RevokedPasskeyWalletAuthMethodRecordV2 {
  return buildRevokedPasskeyWalletAuthMethodRecord({
    version: 'wallet_auth_method_v2',
    walletAuthMethodId: authMethod.walletAuthMethodId,
    walletId: authMethod.walletId,
    walletAuthorityId: authMethod.walletAuthorityId,
    kind: 'passkey',
    status: 'revoked',
    rpId: authMethod.rpId,
    credentialIdB64u: authMethod.credentialIdB64u,
    credentialPublicKeyB64u: authMethod.credentialPublicKeyB64u,
    counter: authMethod.counter,
    createdAtMs: authMethod.createdAtMs,
    updatedAtMs: revokedAtMs,
    activatedAtMs: authMethod.activatedAtMs,
    revokedAtMs,
  });
}

function buildActivePasskeyWalletAuthMethodRecord(
  input: ActivePasskeyWalletAuthMethodRecordV2,
): ActivePasskeyWalletAuthMethodRecordV2 {
  const record = buildWalletAuthMethodRecordV2(input);
  if (record.kind !== 'passkey' || record.status !== 'active') {
    throw new Error('active Passkey fixture unexpectedly changed branch');
  }
  return record;
}

function buildRevokedPasskeyWalletAuthMethodRecord(
  input: RevokedPasskeyWalletAuthMethodRecordV2,
): RevokedPasskeyWalletAuthMethodRecordV2 {
  const record = buildWalletAuthMethodRecordV2(input);
  if (record.kind !== 'passkey' || record.status !== 'revoked') {
    throw new Error('revoked Passkey fixture unexpectedly changed branch');
  }
  return record;
}

export function fullOwnerPermissionsForManagementFixture(): CanonicalDelegatedWalletPermissionSetV1 {
  return buildFullOwnerPermissionsV1();
}

export function linkedDevicePermissionsForManagementFixture(): CanonicalDelegatedWalletPermissionSetV1 {
  return buildSigningOnlyDelegatedWalletAuthorityV1().permissions;
}

export function parseManagementMaterialActivationRef(raw: string): MpcMaterialActivationRef {
  return required(parseMpcMaterialActivationRef(raw));
}
