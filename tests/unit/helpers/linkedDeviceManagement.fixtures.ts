import {
  buildFullOwnerPermissionsV1,
  buildSigningOnlyDelegatedWalletAuthorityV1,
  type CanonicalDelegatedWalletPermissionSetV1,
} from '../../../packages/shared-ts/src/authorization/delegatedAuthority';
import {
  buildActiveWalletAuthorityV1,
  buildRevokedWalletAuthorityV1,
  buildWalletSignerActivationSetV1,
  type ActiveWalletAuthorityV1,
  type RevokedWalletAuthorityV1,
} from '../../../packages/shared-ts/src/authorization/walletAuthority';
import {
  buildActiveWalletSessionQuota,
  buildWalletSessionAuthorizationV2,
  buildWalletSessionCapabilitySubjectsV1,
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
  parseWebAuthnCredentialIdB64u,
  parseWebAuthnRpId,
} from '../../../packages/shared-ts/src/utils/domainIds';
import { parseExactAdministeredSignerManifestV1 } from '../../../packages/shared-ts/src/device-linking/delegatedActivationPlan';
import { buildMpcMaterialActivationRefFixture } from './ecdsaMaterialRef.fixtures';

const MANAGEMENT_DIGEST = parseDigestB64u(base64UrlEncode(new Uint8Array(32).fill(33)));

function required<T>(
  result:
    | { readonly ok: true; readonly value: T }
    | { readonly ok: false; readonly error: { readonly message: string } },
): T {
  if (!result.ok) throw new Error(result.error.message);
  return result.value;
}

export type LinkedDeviceManagementAuthorityFixture = {
  readonly authority: ActiveWalletAuthorityV1;
  readonly authMethod: Extract<WalletAuthMethodRecordV2, { readonly status: 'active' }>;
  readonly issuedSession: IssuedWalletSessionAuthorizationV2;
};

export async function buildLinkedDeviceManagementAuthorityFixture(input: {
  readonly label: string;
  readonly permissions: CanonicalDelegatedWalletPermissionSetV1;
  readonly provenance: 'wallet_registration' | 'device_link';
  readonly keyFamily?: 'ed25519' | 'ecdsa_secp256k1';
  readonly sourceAuthorityId?: ActiveWalletAuthorityV1['authorityId'];
}): Promise<LinkedDeviceManagementAuthorityFixture> {
  const walletId = required(parseWalletId('wallet:management'));
  const authorityId = required(parseWalletAuthorityId(`authority:management-${input.label}`));
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
              walletKeyId: `wallet-key:management-${input.label}`,
              thresholdPublicKey33B64u: base64UrlEncode(
                new Uint8Array([2, ...new Uint8Array(32).fill(38)]),
              ),
              evmAddress: `0x${'1'.repeat(40)}`,
            },
          ],
        });
  const signerActivations =
    keyFamily === 'ed25519'
      ? buildWalletSignerActivationSetV1({
          manifest,
          materialActivations: {
            keyFamilies: ['ed25519'],
            ed25519: buildMpcMaterialActivationRefFixture(`management-${input.label}`),
          },
        })
      : buildWalletSignerActivationSetV1({
          manifest,
          materialActivations: {
            keyFamilies: ['ecdsa_secp256k1'],
            ecdsa: buildMpcMaterialActivationRefFixture(`management-${input.label}`),
          },
        });
  const provenance =
    input.provenance === 'wallet_registration'
      ? ({ kind: 'wallet_registration' } as const)
      : {
          kind: 'device_link' as const,
          enrollmentId: required(
            parseLinkedDeviceEnrollmentId(`enrollment:management-${input.label}`),
          ),
          sourceAuthorityId:
            input.sourceAuthorityId ?? required(parseWalletAuthorityId('authority:management-owner')),
          linkSessionId: required(
            parseLinkDeviceSessionId(`link-session:management-${input.label}`),
          ),
        };
  const authority = buildActiveWalletAuthorityV1({
    kind: 'wallet_authority_v1',
    authorityId,
    walletId,
    principal: { kind: 'owner_device', deviceId },
    provenance,
    permissions: input.permissions,
    signerActivations,
    signerActivationSetDigestB64u: MANAGEMENT_DIGEST,
    authorityDigestB64u: MANAGEMENT_DIGEST,
    revocationEpoch: 0,
    createdAtMs: 100,
    updatedAtMs: 200,
    state: 'active',
    activatedAtMs: 200,
  });
  const rpId = required(parseWebAuthnRpId('management.example.test'));
  const credentialIdB64u = required(
    parseWebAuthnCredentialIdB64u(
      base64UrlEncode(new Uint8Array(32).fill(input.label === 'owner' ? 35 : 36)),
    ),
  );
  const authMethodId = required(parseWalletAuthMethodId(`auth-method:management-${input.label}`));
  const authMethod = buildWalletAuthMethodRecordV2({
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
  const tenantId = required(parseTenantId('tenant:management'));
  const principalId = required(parsePrincipalId(`principal:management-${input.label}`));
  const walletSessionId = required(parseWalletSessionId(`wallet-session:management-${input.label}`));
  const authorizationId = required(
    parseWalletSessionAuthorizationId(`authorization:management-${input.label}`),
  );
  const quotaId = required(parseMpcWalletSigningQuotaId(`wallet-quota:management-${input.label}`));
  const mintId = required(parseReusableWalletSessionMintId(`wallet-mint:management-${input.label}`));
  const session = buildWalletSessionAuthorizationV2({
    tenantId,
    principalId,
    walletId,
    authorityId,
    walletAuthMethodId: authMethodId,
    authorityDigestB64u: MANAGEMENT_DIGEST,
    authorityRevocationEpoch: authority.revocationEpoch,
    mintId,
    authorizationId,
    walletSessionId,
    quotaId,
    capabilitySubjects: buildWalletSessionCapabilitySubjectsV1(authority),
    createdAtMs: 300,
    expiresAtMs: 10_000,
  });
  return {
    authority,
    authMethod,
    issuedSession: {
      session,
      quota: buildActiveWalletSessionQuota({
        tenantId,
        principalId,
        walletSessionId,
        quotaId,
        remainingUses: 10,
        expiresAtMs: 10_000,
      }),
    },
  };
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
  authMethod: Extract<WalletAuthMethodRecordV2, { readonly status: 'active' }>,
  revokedAtMs: number,
): Extract<WalletAuthMethodRecordV2, { readonly status: 'revoked' }> {
  return buildWalletAuthMethodRecordV2({
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

export function fullOwnerPermissionsForManagementFixture(): CanonicalDelegatedWalletPermissionSetV1 {
  return buildFullOwnerPermissionsV1();
}

export function linkedDevicePermissionsForManagementFixture(): CanonicalDelegatedWalletPermissionSetV1 {
  return buildSigningOnlyDelegatedWalletAuthorityV1().permissions;
}

export function parseManagementMaterialActivationRef(raw: string) {
  return required(parseMpcMaterialActivationRef(raw));
}
