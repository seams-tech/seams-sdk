import {
  buildActiveWalletAuthorityV1,
  buildWalletSignerActivationSetV1,
} from '@shared/authorization/walletAuthority';
import { buildFullOwnerPermissionsV1 } from '@shared/authorization/delegatedAuthority';
import {
  parseDeviceId,
  parsePrincipalId,
  parseTenantId,
  parseWalletSessionId,
} from '@shared/authorization/capabilityKinds';
import { parseExactAdministeredSignerManifestV1 } from '@shared/device-linking/delegatedActivationPlan';
import { parseDigestB64u, type DigestB64u } from '@shared/utils/canonicalPrimitives';
import { parseWalletAuthorityId } from '@shared/utils/domainIds';
import { buildWalletAuthMethodRecordV2 } from '@shared/utils/registrationIntent';
import {
  isEmailOtpWalletAuthAuthority,
  isPasskeyWalletAuthAuthority,
} from '@shared/utils/walletAuthAuthority';
import { parseWalletSessionOperationCredentialV1 } from '@shared/device-linking/parsers';
import { projectActiveWalletSession } from '../../../packages/wallet-server/src/authorization/domain';
import {
  buildExactEvmFamilyWalletSessionAuthorization,
  type ExactEvmFamilyWalletSessionAuthorization,
} from '@/core/signingEngine/session/material/ecdsaSigningCapability';
import type { ExactEcdsaSealedRuntime } from '@/core/signingEngine/session/material/ecdsaSealedRuntime';
import type { CanonicalEvmFamilyEcdsaSigningCapability } from '@/core/signingEngine/session/material/ecdsaSigningCapability';
import { canonicalEcdsaSealedRuntimeFixture } from './ecdsaOperationStepUp.fixtures';
import { buildExactWalletSessionAuthorizationFixture } from './exactWalletSessionAuthorization.fixtures';
import { buildEmailOtpEcdsaWalletSessionFixture } from './linkedDeviceManagement.fixtures';

function required<T>(
  result:
    | { readonly ok: true; readonly value: T }
    | { readonly ok: false; readonly error: { readonly message: string } },
): T {
  if (!result.ok) throw new Error(result.error.message);
  return result.value;
}

function authorityDigest(value: string): DigestB64u {
  return parseDigestB64u(value);
}

export async function buildExactPasskeyEvmFamilyWalletSessionAuthorizationFixture(input: {
  readonly label: string;
  readonly walletSessionLabel: string;
  readonly authorizationLabel: string;
  readonly quotaLabel: string;
}): Promise<ExactEvmFamilyWalletSessionAuthorization> {
  return buildExactPasskeyEvmFamilyWalletSessionAuthorizationFromRuntimeFixture({
    ...input,
    canonicalRuntime: await canonicalEcdsaSealedRuntimeFixture('passkey'),
  });
}

export function buildExactPasskeyEvmFamilyWalletSessionAuthorizationFromRuntimeFixture(input: {
  readonly label: string;
  readonly walletSessionLabel: string;
  readonly authorizationLabel: string;
  readonly quotaLabel: string;
  readonly canonicalRuntime: Awaited<ReturnType<typeof canonicalEcdsaSealedRuntimeFixture>>;
}): ExactEvmFamilyWalletSessionAuthorization {
  const { fixture, runtime } = input.canonicalRuntime;
  if (!isPasskeyWalletAuthAuthority(fixture.authority)) {
    throw new Error('[fixture] exact Passkey authorization requires a Passkey authority');
  }
  const walletId = fixture.manifest.signer.walletId;
  const materialActivation = fixture.manifest.activation.materialActivation;
  const signerManifest = parseExactAdministeredSignerManifestV1({
    kind: 'exact_administered_signer_manifest_v1',
    keyFamilies: ['ecdsa_secp256k1'],
    signers: [
      {
        kind: 'exact_administered_ecdsa_signer_v1',
        keyFamily: 'ecdsa_secp256k1',
        walletId,
        walletKeyId: `wallet-key:exact-session-${input.label}`,
        thresholdPublicKey33B64u: fixture.capability.material.publicFacts.groupPublicKey33B64u,
        evmAddress: fixture.capability.material.publicFacts.ethereumAddress,
      },
    ],
  });
  const signerActivations = buildWalletSignerActivationSetV1({
    manifest: signerManifest,
    materialActivations: {
      keyFamilies: ['ecdsa_secp256k1'],
      ecdsa: materialActivation,
    },
  });
  const bindingDigest = authorityDigest(String(fixture.manifest.signer.authority.authorityDigest));
  const authorityId = required(parseWalletAuthorityId(`authority:exact-session-${input.label}`));
  const authority = buildActiveWalletAuthorityV1({
    kind: 'wallet_authority_v1',
    authorityId,
    walletId,
    principal: {
      kind: 'owner_device',
      deviceId: required(parseDeviceId(`device:exact-session-${input.label}`)),
    },
    provenance: { kind: 'wallet_registration' },
    permissions: buildFullOwnerPermissionsV1(),
    signerActivations,
    signerActivationSetDigestB64u: bindingDigest,
    authorityDigestB64u: bindingDigest,
    revocationEpoch: 0,
    createdAtMs: 100,
    updatedAtMs: 200,
    state: 'active',
    activatedAtMs: 200,
  });
  const authMethod = buildWalletAuthMethodRecordV2({
    version: 'wallet_auth_method_v2',
    walletAuthMethodId: fixture.authority.bindingId,
    walletId,
    walletAuthorityId: authorityId,
    kind: 'passkey',
    status: 'active',
    rpId: fixture.authority.verifier.rpId,
    credentialIdB64u: fixture.authority.factor.credentialIdB64u,
    credentialPublicKeyB64u: 'fixture-public-key',
    counter: 0,
    createdAtMs: 100,
    updatedAtMs: 200,
    activatedAtMs: 200,
  });
  if (authMethod.kind !== 'passkey' || authMethod.status !== 'active') {
    throw new Error('[fixture] exact Passkey auth method has the wrong branch');
  }
  const nowMs = Date.now();
  const issued = buildExactWalletSessionAuthorizationFixture({
    label: input.label,
    walletSessionLabel: input.walletSessionLabel,
    authorizationLabel: input.authorizationLabel,
    quotaLabel: input.quotaLabel,
    mintLabel: input.walletSessionLabel,
    tenantId: required(parseTenantId('tenant:exact-session')),
    principalId: required(parsePrincipalId('principal:exact-session')),
    authority,
    walletAuthMethodId: authMethod.walletAuthMethodId,
    issuedAtMs: nowMs - 1_000,
    expiresAtMs: nowMs + 60_000,
    remainingUses: 5,
  });
  const selection = {
    kind: 'wallet_selection_v1',
    walletId,
    walletAuthMethodId: authMethod.walletAuthMethodId,
    lockGeneration: 0,
    lockState: 'unlocked',
    updatedAtMs: 200,
  } as const;
  const walletSessionId = required(
    parseWalletSessionId(`wallet-session:${input.walletSessionLabel}`),
  );
  return buildExactEvmFamilyWalletSessionAuthorization({
    capability: fixture.capability,
    selected: {
      kind: 'resolved',
      selection,
      authMethod,
      authority,
      signerMaterials: [],
      exportRoot: null,
    },
    session: projectActiveWalletSession(issued),
    operationCredential: parseWalletSessionOperationCredentialV1({
      kind: 'opaque_wallet_session_operation_credential_v1',
      token: `wst_${'A'.repeat(42)}${input.walletSessionLabel.length % 10}`,
      walletSessionId,
    }),
    runtime,
    nowMs,
  });
}

export async function buildExactEmailOtpEvmFamilyWalletSessionAuthorizationFixture(input: {
  readonly capability: CanonicalEvmFamilyEcdsaSigningCapability;
  readonly runtime: ExactEcdsaSealedRuntime;
  readonly label: string;
}): Promise<ExactEvmFamilyWalletSessionAuthorization> {
  if (input.runtime.authBinding.kind !== 'email_otp') {
    throw new Error('[fixture] exact Email OTP authorization requires an Email OTP runtime');
  }
  if (!isEmailOtpWalletAuthAuthority(input.capability.authority)) {
    throw new Error('[fixture] exact Email OTP authorization requires an Email OTP capability');
  }
  const factor = input.capability.authority;
  const walletSessionFixture = await buildEmailOtpEcdsaWalletSessionFixture({
    label: input.label,
    walletId: String(input.capability.manifest.signer.walletId),
    walletAuthMethodId: String(factor.bindingId),
    materialActivation: input.runtime.materialActivation,
    providerUserId: String(factor.factor.providerUserId),
    emailHashHex: String(factor.verifier.emailHashHex),
    expiresAtMs: input.runtime.expiresAtMs,
  });
  const selectedAuthority = buildActiveWalletAuthorityV1({
    kind: walletSessionFixture.authority.kind,
    authorityId: walletSessionFixture.authority.authorityId,
    walletId: walletSessionFixture.authority.walletId,
    principal: walletSessionFixture.authority.principal,
    provenance: walletSessionFixture.authority.provenance,
    permissions: walletSessionFixture.authority.permissions,
    signerActivations: walletSessionFixture.authority.signerActivations,
    signerActivationSetDigestB64u: walletSessionFixture.authority.signerActivationSetDigestB64u,
    authorityDigestB64u: authorityDigest(
      String(input.capability.manifest.signer.authority.authorityDigest),
    ),
    revocationEpoch: walletSessionFixture.authority.revocationEpoch,
    createdAtMs: walletSessionFixture.authority.createdAtMs,
    updatedAtMs: walletSessionFixture.authority.updatedAtMs,
    state: 'active',
    activatedAtMs: walletSessionFixture.authority.activatedAtMs,
  });
  const nowMs = Math.max(0, Math.min(Date.now(), input.runtime.expiresAtMs - 1));
  const issued = buildExactWalletSessionAuthorizationFixture({
    label: input.label,
    tenantId: required(parseTenantId('tenant:exact-session')),
    principalId: required(parsePrincipalId('principal:exact-session')),
    authority: selectedAuthority,
    walletAuthMethodId: walletSessionFixture.authMethod.walletAuthMethodId,
    issuedAtMs: Math.max(0, nowMs - 1_000),
    expiresAtMs: input.runtime.expiresAtMs,
    remainingUses: Math.max(1, input.runtime.remainingUses),
  });
  const session = projectActiveWalletSession(issued);
  const operationCredential = parseWalletSessionOperationCredentialV1({
    kind: 'opaque_wallet_session_operation_credential_v1',
    token: `wst_${'E'.repeat(43)}`,
    walletSessionId: issued.session.walletSessionId,
  });
  return buildExactEvmFamilyWalletSessionAuthorization({
    capability: input.capability,
    selected: {
      kind: 'resolved',
      selection: walletSessionFixture.selection,
      authMethod: walletSessionFixture.authMethod,
      authority: selectedAuthority,
      signerMaterials: [],
      exportRoot: null,
    },
    session,
    operationCredential,
    runtime: input.runtime,
    nowMs,
  });
}
