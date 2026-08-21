import { expect, test } from '@playwright/test';
import {
  EVM_ECDSA_MPC_OPERATION_KINDS,
  NEAR_ED25519_MPC_OPERATION_KINDS,
  parseDeviceId,
  parseMpcWalletSigningQuotaId,
  parsePrincipalId,
  parseReusableWalletSessionMintId,
  parseTenantId,
  parseWalletSessionAuthorizationId,
  parseWalletSessionId,
} from '@shared/authorization/capabilityKinds';
import { buildFullOwnerPermissionsV1 } from '@shared/authorization/delegatedAuthority';
import {
  buildActiveWalletAuthorityV1,
  buildWalletSignerActivationSetV1,
  computeWalletAuthorityDigestB64u,
  computeWalletSignerActivationSetDigestB64u,
  type ActiveWalletAuthorityV1,
} from '@shared/authorization/walletAuthority';
import { parseExactAdministeredSignerManifestV1 } from '@shared/device-linking/delegatedActivationPlan';
import {
  parseWalletAuthMethodId,
  parseWalletAuthorityId,
  parseWalletId,
  parseWebAuthnCredentialIdB64u,
  parseWebAuthnRpId,
  type WalletAuthMethodId,
  type WalletId,
} from '@shared/utils/domainIds';
import { base64UrlEncode } from '@shared/utils/base64';
import { parseDigestB64u, type DigestB64u } from '@shared/utils/canonicalPrimitives';
import {
  buildWalletAuthMethodRecordV2,
  type WalletAuthMethodRecordV2,
} from '@shared/utils/registrationIntent';
import {
  buildWalletSessionAuthorizationV2,
  buildWalletSessionCapabilitySubjectsV1,
  type WalletSessionAuthorizationV2,
} from '../../packages/wallet-server/src/authorization/domain';
import {
  resolveWalletSessionAuthorizationV2Admission,
  type WalletSessionAuthorizationV2RequestedOperation,
} from '../../packages/wallet-server/src/router/domains/signingOperations/walletExecutionAdmission';
import { buildMpcMaterialActivationRefFixture } from './helpers/ecdsaMaterialRef.fixtures';

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
  walletId: WalletId,
  label: string,
): ReturnType<typeof parseExactAdministeredSignerManifestV1> {
  const ed25519 = {
    kind: 'exact_administered_ed25519_signer_v1' as const,
    keyFamily: 'ed25519' as const,
    walletId,
    walletKeyId: `wallet-key:admission-${label}-ed25519`,
    registeredPublicKeyB64u: base64UrlEncode(new Uint8Array(32).fill(3)),
  };
  const ecdsa = {
    kind: 'exact_administered_ecdsa_signer_v1' as const,
    keyFamily: 'ecdsa_secp256k1' as const,
    walletId,
    walletKeyId: `wallet-key:admission-${label}-ecdsa`,
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

function buildSignerActivations(family: SignerFamily, walletId: WalletId, label: string) {
  const manifest = buildSignerManifest(family, walletId, label);
  const materialOwner = String(walletId);
  switch (family) {
    case 'ed25519':
      return buildWalletSignerActivationSetV1({
        manifest,
        materialActivations: {
          keyFamilies: ['ed25519'],
          ed25519: buildMpcMaterialActivationRefFixture(
            `admission-${label}-ed25519`,
            materialOwner,
          ),
        },
      });
    case 'ecdsa_secp256k1':
      return buildWalletSignerActivationSetV1({
        manifest,
        materialActivations: {
          keyFamilies: ['ecdsa_secp256k1'],
          ecdsa: buildMpcMaterialActivationRefFixture(`admission-${label}-ecdsa`, materialOwner),
        },
      });
    case 'both':
      return buildWalletSignerActivationSetV1({
        manifest,
        materialActivations: {
          keyFamilies: ['ed25519', 'ecdsa_secp256k1'],
          ed25519: buildMpcMaterialActivationRefFixture(
            `admission-${label}-ed25519`,
            materialOwner,
          ),
          ecdsa: buildMpcMaterialActivationRefFixture(`admission-${label}-ecdsa`, materialOwner),
        },
      });
  }
}

async function buildAuthority(
  family: SignerFamily,
  label: string,
): Promise<ActiveWalletAuthorityV1> {
  const walletId = required(parseWalletId(`wallet:admission-${label}`));
  const authorityId = required(parseWalletAuthorityId(`authority:admission-${label}`));
  const deviceId = required(parseDeviceId(`device:admission-${label}`));
  const signerActivations = buildSignerActivations(family, walletId, label);
  const signerActivationSetDigestB64u =
    await computeWalletSignerActivationSetDigestB64u(signerActivations);
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
    updatedAtMs: 100,
    state: 'active',
    activatedAtMs: 100,
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

function buildAuthMethod(
  authority: ActiveWalletAuthorityV1,
  label: string,
  status: 'active' | 'revoked',
): WalletAuthMethodRecordV2 {
  const walletAuthMethodId = required(parseWalletAuthMethodId(`passkey:admission-${label}`));
  const rpId = required(parseWebAuthnRpId('wallet.example.test'));
  const credentialIdB64u = required(parseWebAuthnCredentialIdB64u(`credential:admission-${label}`));
  const common = {
    version: 'wallet_auth_method_v2' as const,
    walletAuthMethodId,
    walletId: authority.walletId,
    walletAuthorityId: authority.authorityId,
    kind: 'passkey' as const,
    rpId,
    credentialIdB64u,
    credentialPublicKeyB64u: base64UrlEncode(new Uint8Array(32).fill(6)),
    counter: 0,
    createdAtMs: 200,
    updatedAtMs: 200,
  };
  if (status === 'active') {
    return buildWalletAuthMethodRecordV2({
      ...common,
      status: 'active',
      activatedAtMs: 200,
    });
  }
  return buildWalletAuthMethodRecordV2({
    ...common,
    status: 'revoked',
    activatedAtMs: 200,
    revokedAtMs: 300,
  });
}

function buildSession(input: {
  readonly authority: ActiveWalletAuthorityV1;
  readonly authMethodId: WalletAuthMethodId;
  readonly label: string;
  readonly capabilitySubjects: WalletSessionAuthorizationV2['capabilitySubjects'];
  readonly authorityDigestB64u: DigestB64u;
  readonly authorityRevocationEpoch: number;
  readonly expiresAtMs: number;
}): WalletSessionAuthorizationV2 {
  return buildWalletSessionAuthorizationV2({
    tenantId: required(parseTenantId(`tenant:admission-${input.label}`)),
    principalId: required(parsePrincipalId(`principal:admission-${input.label}`)),
    walletId: input.authority.walletId,
    authorityId: input.authority.authorityId,
    walletAuthMethodId: input.authMethodId,
    authorityDigestB64u: input.authorityDigestB64u,
    authorityRevocationEpoch: input.authorityRevocationEpoch,
    mintId: required(parseReusableWalletSessionMintId(`mint:admission-${input.label}`)),
    authorizationId: required(
      parseWalletSessionAuthorizationId(`authorization:admission-${input.label}`),
    ),
    walletSessionId: required(parseWalletSessionId(`wallet-session:admission-${input.label}`)),
    quotaId: required(parseMpcWalletSigningQuotaId(`quota:admission-${input.label}`)),
    capabilitySubjects: input.capabilitySubjects,
    createdAtMs: 300,
    expiresAtMs: input.expiresAtMs,
  });
}

function buildOperation(
  authority: ActiveWalletAuthorityV1,
  label: string,
  keyFamily: 'ed25519' | 'ecdsa_secp256k1',
  operationKind:
    | (typeof NEAR_ED25519_MPC_OPERATION_KINDS)[keyof typeof NEAR_ED25519_MPC_OPERATION_KINDS]
    | (typeof EVM_ECDSA_MPC_OPERATION_KINDS)[keyof typeof EVM_ECDSA_MPC_OPERATION_KINDS],
): WalletSessionAuthorizationV2RequestedOperation {
  const identity = {
    tenantId: required(parseTenantId(`tenant:admission-${label}`)),
    principalId: required(parsePrincipalId(`principal:admission-${label}`)),
    walletId: authority.walletId,
  };
  if (keyFamily === 'ed25519') {
    if (
      operationKind !== NEAR_ED25519_MPC_OPERATION_KINDS.signTransaction &&
      operationKind !== NEAR_ED25519_MPC_OPERATION_KINDS.signDelegateAction &&
      operationKind !== NEAR_ED25519_MPC_OPERATION_KINDS.signNep413Message &&
      operationKind !== NEAR_ED25519_MPC_OPERATION_KINDS.exportKey
    ) {
      throw new Error('Ed25519 operation kind is invalid');
    }
    return { ...identity, keyFamily, operationKind };
  }
  if (
    operationKind !== EVM_ECDSA_MPC_OPERATION_KINDS.signTransaction &&
    operationKind !== EVM_ECDSA_MPC_OPERATION_KINDS.exportKey
  ) {
    throw new Error('ECDSA operation kind is invalid');
  }
  return { ...identity, keyFamily, operationKind };
}

test('admits exact Ed25519 and ECDSA Wallet Session V2 provenance', async () => {
  const authority = await buildAuthority('both', 'valid');
  const authMethod = buildAuthMethod(authority, 'valid', 'active');
  const session = buildSession({
    authority,
    authMethodId: authMethod.walletAuthMethodId,
    label: 'valid',
    capabilitySubjects: buildWalletSessionCapabilitySubjectsV1(authority),
    authorityDigestB64u: authority.authorityDigestB64u,
    authorityRevocationEpoch: authority.revocationEpoch,
    expiresAtMs: 1_000,
  });

  const edAdmission = resolveWalletSessionAuthorizationV2Admission({
    authorization: session,
    authority,
    authMethod,
    operation: buildOperation(
      authority,
      'valid',
      'ed25519',
      NEAR_ED25519_MPC_OPERATION_KINDS.signTransaction,
    ),
    retiredAtMs: null,
    nowMs: 500,
  });
  const ecdsaAdmission = resolveWalletSessionAuthorizationV2Admission({
    authorization: session,
    authority,
    authMethod,
    operation: buildOperation(
      authority,
      'valid',
      'ecdsa_secp256k1',
      EVM_ECDSA_MPC_OPERATION_KINDS.exportKey,
    ),
    retiredAtMs: null,
    nowMs: 500,
  });

  if (!edAdmission.ok || !ecdsaAdmission.ok) {
    throw new Error('valid signer admission was refused');
  }
  expect(edAdmission.keyFamily).toBe('ed25519');
  expect(edAdmission.operationKind).toBe(NEAR_ED25519_MPC_OPERATION_KINDS.signTransaction);
  expect(ecdsaAdmission.keyFamily).toBe('ecdsa_secp256k1');
  expect(ecdsaAdmission.operationKind).toBe(EVM_ECDSA_MPC_OPERATION_KINDS.exportKey);
  expect(edAdmission.walletKeyId).toBe(authority.signerActivations.ed25519.signer.walletKeyId);
  expect(ecdsaAdmission.walletKeyId).toBe(authority.signerActivations.ecdsa.signer.walletKeyId);
});

test('rejects provenance drift, retirement, expiry, subject drift, and missing signer family', async () => {
  const authority = await buildAuthority('both', 'reject');
  const authMethod = buildAuthMethod(authority, 'reject', 'active');
  const subjects = buildWalletSessionCapabilitySubjectsV1(authority);
  const operation = buildOperation(
    authority,
    'reject',
    'ed25519',
    NEAR_ED25519_MPC_OPERATION_KINDS.signTransaction,
  );
  const digestDrift = buildSession({
    authority,
    authMethodId: authMethod.walletAuthMethodId,
    label: 'reject',
    capabilitySubjects: subjects,
    authorityDigestB64u: parseDigestB64u(base64UrlEncode(new Uint8Array(32).fill(9))),
    authorityRevocationEpoch: authority.revocationEpoch,
    expiresAtMs: 1_000,
  });
  const epochDrift = buildSession({
    authority,
    authMethodId: authMethod.walletAuthMethodId,
    label: 'reject',
    capabilitySubjects: subjects,
    authorityDigestB64u: authority.authorityDigestB64u,
    authorityRevocationEpoch: authority.revocationEpoch + 1,
    expiresAtMs: 1_000,
  });
  const expired = buildSession({
    authority,
    authMethodId: authMethod.walletAuthMethodId,
    label: 'reject',
    capabilitySubjects: subjects,
    authorityDigestB64u: authority.authorityDigestB64u,
    authorityRevocationEpoch: authority.revocationEpoch,
    expiresAtMs: 500,
  });
  const foreignAuthority = await buildAuthority('both', 'foreign-subject');
  const subjectDrift = buildSession({
    authority,
    authMethodId: authMethod.walletAuthMethodId,
    label: 'reject',
    capabilitySubjects: buildWalletSessionCapabilitySubjectsV1(foreignAuthority),
    authorityDigestB64u: authority.authorityDigestB64u,
    authorityRevocationEpoch: authority.revocationEpoch,
    expiresAtMs: 1_000,
  });

  expect(
    resolveWalletSessionAuthorizationV2Admission({
      authorization: digestDrift,
      authority,
      authMethod,
      operation,
      retiredAtMs: null,
      nowMs: 500,
    }),
  ).toEqual({ ok: false, error: 'authority_digest_mismatch' });
  expect(
    resolveWalletSessionAuthorizationV2Admission({
      authorization: epochDrift,
      authority,
      authMethod,
      operation,
      retiredAtMs: null,
      nowMs: 500,
    }),
  ).toEqual({ ok: false, error: 'authority_revocation_epoch_mismatch' });
  expect(
    resolveWalletSessionAuthorizationV2Admission({
      authorization: expired,
      authority,
      authMethod,
      operation,
      retiredAtMs: null,
      nowMs: 500,
    }),
  ).toEqual({ ok: false, error: 'authorization_expired' });
  expect(
    resolveWalletSessionAuthorizationV2Admission({
      authorization: subjectDrift,
      authority,
      authMethod,
      operation,
      retiredAtMs: null,
      nowMs: 500,
    }),
  ).toEqual({ ok: false, error: 'capability_subject_mismatch' });
  expect(
    resolveWalletSessionAuthorizationV2Admission({
      authorization: buildSession({
        authority,
        authMethodId: authMethod.walletAuthMethodId,
        label: 'reject',
        capabilitySubjects: subjects,
        authorityDigestB64u: authority.authorityDigestB64u,
        authorityRevocationEpoch: authority.revocationEpoch,
        expiresAtMs: 1_000,
      }),
      authority,
      authMethod: buildAuthMethod(authority, 'reject', 'revoked'),
      operation,
      retiredAtMs: null,
      nowMs: 500,
    }),
  ).toEqual({ ok: false, error: 'auth_method_inactive' });

  const edOnlyAuthority = await buildAuthority('ed25519', 'missing-family');
  const edOnlyMethod = buildAuthMethod(edOnlyAuthority, 'missing-family', 'active');
  const edOnlySession = buildSession({
    authority: edOnlyAuthority,
    authMethodId: edOnlyMethod.walletAuthMethodId,
    label: 'missing-family',
    capabilitySubjects: buildWalletSessionCapabilitySubjectsV1(edOnlyAuthority),
    authorityDigestB64u: edOnlyAuthority.authorityDigestB64u,
    authorityRevocationEpoch: edOnlyAuthority.revocationEpoch,
    expiresAtMs: 1_000,
  });
  expect(
    resolveWalletSessionAuthorizationV2Admission({
      authorization: edOnlySession,
      authority: edOnlyAuthority,
      authMethod: edOnlyMethod,
      operation: buildOperation(
        edOnlyAuthority,
        'missing-family',
        'ecdsa_secp256k1',
        EVM_ECDSA_MPC_OPERATION_KINDS.signTransaction,
      ),
      retiredAtMs: null,
      nowMs: 500,
    }),
  ).toEqual({ ok: false, error: 'signer_family_mismatch' });
});
