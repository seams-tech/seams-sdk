import {
  buildSigningOnlyPermissionsV1,
  buildActiveWalletAuthorityV1,
  buildWalletSignerActivationSetV1,
  computeWalletAuthorityDigestB64u,
  computeWalletSignerActivationSetDigestB64u,
} from '@shared/authorization';
import type {
  ActiveWalletSessionV1,
  WalletSessionOperationCredentialV1,
} from '@shared/device-linking';
import { parseActiveWalletSessionV1 } from '@shared/device-linking/parsers';
import {
  parseExactAdministeredSignerManifestV1,
  type ExactAdministeredSignerManifestV1,
} from '@shared/device-linking/delegatedActivationPlan';
import {
  parseLinkedDeviceEnrollmentId,
  parseLinkDeviceSessionId,
  parseWalletAuthorityId,
  parseWalletId,
  parseWalletRecoveryOperationId,
  parseWebAuthnCredentialIdB64u,
  parseWebAuthnRpId,
  parseThresholdEd25519SessionId,
  parseRootShareEpoch,
  type MpcMaterialActivationRef,
  type WalletAuthMethodId,
  type WalletAuthorityId,
  type WalletId,
} from '@shared/utils/domainIds';
import {
  parseDeviceId as parseAuthorizationDeviceId,
  parseMpcWalletSigningQuotaId,
  parsePrincipalId,
  parseWalletSessionMintId,
  parseTenantId,
  parseWalletSessionAuthorizationId,
  parseWalletSessionId,
} from '@shared/authorization/capabilityKinds';
import { base64UrlEncode } from '@shared/utils/base64';
import { parseDigestB64u, type DigestB64u } from '@shared/utils/canonicalPrimitives';
import { parseSecp256k1CompressedPublicKeyB64u } from '@shared/passkey-custody/primitives';
import {
  buildWalletAuthMethodRecordV2,
  nearEd25519SigningKeyIdFromString,
  type WalletAuthMethodRecordV2,
} from '@shared/utils/registrationIntent';
import {
  buildEmailOtpWalletAuthAuthority,
  buildPasskeyWalletAuthAuthority,
  type EmailOtpWalletAuthAuthority,
  type PasskeyWalletAuthAuthority,
} from '@shared/utils/walletAuthAuthority';
import { routerAbMpcMaterialActivationRefToWire } from '@shared/utils/routerAbNormalSigningIdentity';
import type { RouterAbEcdsaDerivationNormalSigningStateV1 } from '@shared/utils/routerAbEcdsaDerivation';
import type {
  RouterAbEd25519YaoActivationPublicReceiptV1,
  RouterAbEd25519YaoApplicationBindingFactsV1,
  RouterAbEd25519YaoCeremonyBindingV1,
} from '@shared/utils/routerAbEd25519Yao';
import {
  buildWalletSessionAuthorizationV2,
  buildWalletSessionCapabilitySubjectsV1,
} from '../../../packages/wallet-server/src/authorization/domain';
import { toAccountId } from '../../../packages/wallet/src/core/types/accountIds';
import type {
  WalletAuthorityLinkedMaterialTargetFactorV1,
  WalletAuthorityLinkedSignerMaterialRecordV1,
} from '../../../packages/wallet/src/core/indexedDB/passkeyClientDB.types';
import { parseEcdsaThresholdKeyId } from '../../../packages/wallet/src/core/signingEngine/session/keyMaterialBrands';
import { sealWalletAuthorityLinkedSignerMaterialV1 } from '../../../packages/wallet/src/core/indexedDB/linkedAuthoritySignerMaterial';
import { toRpId } from '../../../packages/wallet/src/core/signingEngine/session/identity/evmFamilyEcdsaIdentity';
import type { Ed25519YaoPublicCapabilityLaneReferenceV1 } from '../../../packages/wallet/src/core/signingEngine/threshold/ed25519/yaoPublicCapabilityReferences';
import type { ActiveNearEd25519WalletSessionStatus } from '../../../packages/wallet/src/core/signingEngine/session/material/nearEd25519YaoSigningPreparation';
import type { PasskeyWalletUnlockEd25519Session } from '../../../packages/wallet/src/core/rpcClients/near/rpcCalls';
import type { WebAuthnAuthenticationCredential } from '../../../packages/wallet/src/core/types/webauthn';
import { buildMpcMaterialActivationRefFixture } from './ecdsaMaterialRef.fixtures';

type LinkedEd25519Material = Extract<
  WalletAuthorityLinkedSignerMaterialRecordV1,
  { readonly keyFamily: 'ed25519' }
>;
type LinkedEcdsaMaterial = Extract<
  WalletAuthorityLinkedSignerMaterialRecordV1,
  { readonly keyFamily: 'ecdsa_secp256k1' }
>;

export function buildLinkedDeviceActiveWalletSessionFixture(input: {
  readonly source: ActiveWalletSessionV1;
  readonly authMethodId: ActiveWalletSessionV1['authMethodId'];
  readonly authorizationId: ActiveWalletSessionV1['authorizationId'];
  readonly quotaId: ActiveWalletSessionV1['quotaId'];
  readonly authorityDigestB64u: ActiveWalletSessionV1['authorityDigestB64u'];
  readonly authorityRevocationEpoch: number;
}): ActiveWalletSessionV1 {
  return parseActiveWalletSessionV1({
    kind: 'active_wallet_session_v1',
    walletId: input.source.walletId,
    authorityId: input.source.authorityId,
    authMethodId: input.authMethodId,
    authorizationId: input.authorizationId,
    quotaId: input.quotaId,
    authorityDigestB64u: input.authorityDigestB64u,
    authorityRevocationEpoch: input.authorityRevocationEpoch,
    capabilitySubjects: input.source.capabilitySubjects,
    issuedAtMs: input.source.issuedAtMs,
    expiresAtMs: input.source.expiresAtMs,
  });
}

function required<T>(
  result:
    | { readonly ok: true; readonly value: T }
    | { readonly ok: false; readonly error: { readonly message: string } },
): T {
  if (!result.ok) throw new Error(result.error.message);
  return result.value;
}

function bytes(length: number, seed: number): number[] {
  return Array.from({ length }, (_, index) => (seed + index) % 256);
}

function digest(seed: number): DigestB64u {
  return parseDigestB64u(base64UrlEncode(new Uint8Array(bytes(32, seed))));
}

function secpPublicKey(seed: number): ReturnType<typeof parseSecp256k1CompressedPublicKeyB64u> {
  return parseSecp256k1CompressedPublicKeyB64u(
    base64UrlEncode(new Uint8Array([2, ...bytes(32, seed)])),
  );
}

function id<T>(
  parser: (
    value: string,
  ) =>
    | { readonly ok: true; readonly value: T }
    | { readonly ok: false; readonly error: { readonly message: string } },
  value: string,
): T {
  return required(parser(value));
}

function buildCombinedSignerManifest(walletId: WalletId): ExactAdministeredSignerManifestV1 {
  return parseExactAdministeredSignerManifestV1({
    kind: 'exact_administered_signer_manifest_v1',
    keyFamilies: ['ed25519', 'ecdsa_secp256k1'],
    signers: [
      {
        kind: 'exact_administered_ed25519_signer_v1',
        keyFamily: 'ed25519',
        walletId: String(walletId),
        walletKeyId: 'wallet-key:linked-runtime-ed25519',
        registeredPublicKeyB64u: base64UrlEncode(new Uint8Array(bytes(32, 31))),
      },
      {
        kind: 'exact_administered_ecdsa_signer_v1',
        keyFamily: 'ecdsa_secp256k1',
        walletId: String(walletId),
        walletKeyId: 'wallet-key:linked-runtime-ecdsa',
        thresholdPublicKey33B64u: base64UrlEncode(new Uint8Array([2, ...bytes(32, 41)])),
        evmAddress: '0x1111111111111111111111111111111111111111',
      },
    ],
  });
}

function buildEd25519Binding(
  walletId: WalletId,
  materialActivation: MpcMaterialActivationRef,
): RouterAbEd25519YaoCeremonyBindingV1 {
  const wireActivation = routerAbMpcMaterialActivationRefToWire(materialActivation);
  return {
    lifecycle: {
      lifecycle_id: 'lifecycle:linked-runtime',
      work_kind: 'registration_prepare',
      primitive_request_kind: 'registration',
      root_share_epoch: 'epoch:linked-runtime',
      account_id: String(walletId),
      session_id: 'threshold-ed25519:linked-runtime',
      signer_set_id: 'signer-set:linked-runtime',
      selected_server_id: String(materialActivation.signingWorker),
    },
    operation: 'registration',
    session_id: bytes(32, 51),
    stable_key_context_binding: bytes(32, 52),
    material_activation: wireActivation,
  };
}

function buildEd25519Receipt(
  materialActivation: MpcMaterialActivationRef,
): RouterAbEd25519YaoActivationPublicReceiptV1 {
  return {
    transcript: bytes(32, 61),
    registered_public_key: bytes(32, 62),
    joined_client_commitment: bytes(32, 63),
    joined_signing_worker_commitment: bytes(32, 64),
    signing_worker_verifying_share: bytes(32, 65),
    state_epoch: 1,
    material_activation: routerAbMpcMaterialActivationRefToWire(materialActivation),
  };
}

function buildEd25519PublicFacts(
  walletId: WalletId,
  materialActivation: MpcMaterialActivationRef,
): Extract<
  WalletAuthorityLinkedSignerMaterialRecordV1,
  { readonly keyFamily: 'ed25519' }
>['publicFacts'] {
  const targetBinding = buildEd25519Binding(walletId, materialActivation);
  const applicationBinding: RouterAbEd25519YaoApplicationBindingFactsV1 = {
    wallet_id: String(walletId),
    near_ed25519_signing_key_id: 'near-ed25519-key:linked-runtime',
    signing_root_id: 'signing-root:linked-runtime',
    key_creation_signer_slot: 1,
  };
  return {
    keyFamily: 'ed25519',
    participantIds: [1, 2],
    targetBinding,
    applicationBinding,
    activationReceipt: buildEd25519Receipt(materialActivation),
  };
}

function buildEcdsaReceipt(
  materialActivation: MpcMaterialActivationRef,
): Extract<
  WalletAuthorityLinkedSignerMaterialRecordV1,
  { readonly keyFamily: 'ecdsa_secp256k1' }
>['publicFacts']['activationReceipt'] {
  const thresholdPublicKey33B64u = secpPublicKey(41);
  const thresholdEthereumAddress20B64u = base64UrlEncode(new Uint8Array(20).fill(0x11));
  const sourceActivation = buildMpcMaterialActivationRefFixture(
    'linked-runtime-source',
    'wallet:linked-runtime-source',
    'worker:linked-runtime',
  );
  const sourceBinding = {
    linkSessionId: id(parseLinkDeviceSessionId, 'link-session:linked-runtime'),
    enrollmentId: id(parseLinkedDeviceEnrollmentId, 'enrollment:linked-runtime'),
    sourceAuthorityId: id(parseWalletAuthorityId, 'authority:linked-runtime-source'),
    source: {
      activation: sourceActivation,
      clientPublicKey33B64u: secpPublicKey(71),
      relayerPublicKey33B64u: secpPublicKey(72),
      thresholdPublicKey33B64u,
      thresholdEthereumAddress20B64u,
    },
    target: {
      activation: materialActivation,
      targetDeviceId: id(parseAuthorizationDeviceId, 'device:linked-runtime'),
      targetFactorVerificationDigestB64u: digest(75),
      clientRecipientPublicKeyB64u: secpPublicKey(76),
      signingWorkerRecipientPublicKeyB64u: secpPublicKey(77),
    },
    targetClientPublicKey33B64u: secpPublicKey(78),
  };
  const normalSigning: RouterAbEcdsaDerivationNormalSigningStateV1 = {
    kind: 'router_ab_ecdsa_derivation_normal_signing_v1',
    scope: {
      wallet_id: 'wallet:linked-runtime',
      ecdsa_threshold_key_id: 'ecdsa-threshold-key:linked-runtime',
      signing_root_id: 'signing-root:linked-runtime-source',
      signing_root_version: 'v1',
      context: { application_binding_digest_b64u: digest(79) },
      public_identity: {
        context_binding_b64u: base64UrlEncode(new Uint8Array(bytes(32, 80))),
        derivation_client_share_public_key33_b64u: sourceBinding.source.clientPublicKey33B64u,
        server_public_key33_b64u: sourceBinding.source.relayerPublicKey33B64u,
        threshold_public_key33_b64u: thresholdPublicKey33B64u,
        ethereum_address20_b64u: thresholdEthereumAddress20B64u,
        client_share_retry_counter: 0,
        server_share_retry_counter: 0,
      },
      material_activation: routerAbMpcMaterialActivationRefToWire(materialActivation),
      signing_worker: {
        server_id: String(materialActivation.signingWorker),
        key_epoch: 'epoch:linked-runtime',
        recipient_encryption_key: base64UrlEncode(new Uint8Array(bytes(32, 81))),
      },
      activation_epoch: required(parseRootShareEpoch('epoch:linked-runtime')),
    },
  };
  return {
    state: 'inactive',
    binding: sourceBinding,
    sourceDerivation: {
      applicationBindingDigestB64u: digest(79),
      clientShareRetryCounter: 0,
      ecdsaThresholdKeyId: parseEcdsaThresholdKeyId('ecdsa-threshold-key:linked-runtime'),
      sourceNormalSigning: normalSigning,
    },
    targetRelayerPublicKey33B64u: sourceBinding.source.relayerPublicKey33B64u,
    thresholdPublicKey33B64u,
    thresholdEthereumAddress20B64u,
    normalSigning,
  };
}

function buildTargetFactor(
  walletAuthMethodId: WalletAuthMethodId,
  rpId: string,
  credentialIdB64u: string,
  verificationDigest: DigestB64u,
): WalletAuthorityLinkedMaterialTargetFactorV1 {
  return {
    kind: 'passkey',
    walletAuthMethodId,
    verificationDigestB64u: verificationDigest,
    rpId,
    credentialIdB64u,
  };
}

type SealSignerMaterialArgs = {
  readonly walletId: WalletId;
  readonly authorityId: WalletAuthorityId;
  readonly walletAuthMethodId: WalletAuthMethodId;
  readonly packageSetDigestB64u: DigestB64u;
  readonly targetFactor: WalletAuthorityLinkedMaterialTargetFactorV1;
  readonly materialActivation: MpcMaterialActivationRef;
  readonly factorSecret: Uint8Array;
} & (
  | {
      readonly keyFamily: 'ed25519';
      readonly publicFacts: LinkedEd25519Material['publicFacts'];
    }
  | {
      readonly keyFamily: 'ecdsa_secp256k1';
      readonly publicFacts: LinkedEcdsaMaterial['publicFacts'];
    }
);

async function sealSignerMaterial(
  args: SealSignerMaterialArgs,
): Promise<WalletAuthorityLinkedSignerMaterialRecordV1> {
  const sealed = await sealWalletAuthorityLinkedSignerMaterialV1({
    factorSecret: args.factorSecret,
    aad: {
      authorityId: args.authorityId,
      walletId: args.walletId,
      walletAuthMethodId: args.walletAuthMethodId,
      packageSetDigestB64u: args.packageSetDigestB64u,
      targetFactor: args.targetFactor,
      materialActivation: args.materialActivation,
      keyFamily: args.keyFamily,
    },
    material: new Uint8Array(bytes(32, args.keyFamily === 'ed25519' ? 81 : 91)),
  });
  const common = {
    kind: 'wallet_authority_linked_signer_material_v1' as const,
    authorityId: args.authorityId,
    walletAuthMethodId: args.walletAuthMethodId,
    activationId: args.materialActivation.activationId,
    materialActivation: args.materialActivation,
    sealedMaterialB64u: sealed.sealedMaterialB64u,
    sealedMaterialDigestB64u: sealed.sealedMaterialDigestB64u,
    packageSetDigestB64u: args.packageSetDigestB64u,
    targetFactor: args.targetFactor,
  };
  if (args.keyFamily === 'ed25519') {
    if (args.publicFacts.keyFamily !== 'ed25519') {
      throw new Error('linked Ed25519 fixture facts have the wrong family');
    }
    return { ...common, keyFamily: 'ed25519', publicFacts: args.publicFacts };
  }
  if (args.publicFacts.keyFamily !== 'ecdsa_secp256k1') {
    throw new Error('linked ECDSA fixture facts have the wrong family');
  }
  return {
    ...common,
    keyFamily: 'ecdsa_secp256k1',
    ecdsaThresholdKeyId: args.publicFacts.ecdsaThresholdKeyId,
    publicFacts: args.publicFacts,
  };
}

export type LinkedDeviceUnlockRuntimeFixture = {
  readonly walletId: WalletId;
  readonly authority: ReturnType<typeof buildActiveWalletAuthorityV1>;
  readonly authMethod: Extract<WalletAuthMethodRecordV2, { kind: 'passkey'; status: 'active' }>;
  readonly factorAuthority: PasskeyWalletAuthAuthority;
  readonly selection: {
    readonly kind: 'wallet_selection_v1';
    readonly walletId: WalletId;
    readonly walletAuthMethodId: WalletAuthMethodId;
    readonly lockGeneration: number;
    readonly lockState: 'unlocked';
    readonly updatedAtMs: number;
  };
  readonly signerMaterials: readonly WalletAuthorityLinkedSignerMaterialRecordV1[];
  readonly activeWalletSession: ActiveWalletSessionV1;
  readonly operationCredential: WalletSessionOperationCredentialV1;
  readonly ed25519Session: PasskeyWalletUnlockEd25519Session;
  readonly credential: WebAuthnAuthenticationCredential;
};

export type LinkedDeviceEmailOtpUnlockRuntimeFixture = Omit<
  LinkedDeviceUnlockRuntimeFixture,
  | 'authMethod'
  | 'factorAuthority'
  | 'selection'
  | 'signerMaterials'
  | 'activeWalletSession'
  | 'credential'
> & {
  readonly authMethod: Extract<
    WalletAuthMethodRecordV2,
    { readonly kind: 'email_otp'; readonly status: 'active' }
  >;
  readonly factorAuthority: EmailOtpWalletAuthAuthority;
  readonly selection: {
    readonly kind: 'wallet_selection_v1';
    readonly walletId: WalletId;
    readonly walletAuthMethodId: WalletAuthMethodId;
    readonly lockGeneration: number;
    readonly lockState: 'unlocked';
    readonly updatedAtMs: number;
  };
  readonly signerMaterials: readonly WalletAuthorityLinkedSignerMaterialRecordV1[];
  readonly activeWalletSession: ActiveWalletSessionV1;
  readonly providerIdentity: {
    readonly provider: 'email';
    readonly providerSubjectId: string;
  };
  readonly factorSecret32: Uint8Array;
};

export function buildLinkedDeviceEd25519YaoCapabilityLaneFixture(
  fixture: LinkedDeviceUnlockRuntimeFixture,
): Ed25519YaoPublicCapabilityLaneReferenceV1 {
  const activation = fixture.authority.signerActivations.ed25519;
  if (!activation) throw new Error('linked runtime fixture is missing Ed25519 activation');
  return {
    walletId: fixture.walletId,
    nearAccountId: toAccountId(fixture.ed25519Session.nearAccountId),
    thresholdSessionId: fixture.ed25519Session.thresholdSessionId,
    runtimePolicyScope: fixture.ed25519Session.runtimePolicyScope,
    materialActivation: activation.materialActivation,
    auth: {
      kind: 'passkey',
      rpId: toRpId(String(fixture.authMethod.rpId)),
      credentialIdB64u: fixture.authMethod.credentialIdB64u,
    },
    nearEd25519SigningKeyId: nearEd25519SigningKeyIdFromString(
      fixture.ed25519Session.nearEd25519SigningKeyId,
    ),
    signerSlot: 1,
  };
}

export function buildLinkedDeviceActiveNearSessionStatusFixture(
  fixture: Pick<LinkedDeviceUnlockRuntimeFixture, 'activeWalletSession' | 'operationCredential'>,
): ActiveNearEd25519WalletSessionStatus {
  return {
    status: 'active',
    walletSessionId: fixture.operationCredential.walletSessionId,
    quotaId: fixture.activeWalletSession.quotaId,
    remainingUses: 10,
    expiresAtMs: fixture.activeWalletSession.expiresAtMs,
    quotaLifecycle: 'active',
    authorization: fixture.activeWalletSession,
  };
}

export async function buildLinkedDeviceUnlockRuntimeFixture(): Promise<LinkedDeviceUnlockRuntimeFixture> {
  const walletId = required(parseWalletId('wallet:linked-runtime'));
  const authorityId = required(parseWalletAuthorityId('authority:linked-runtime'));
  const rpId = required(parseWebAuthnRpId('wallet.example.test'));
  const credentialIdB64u = base64UrlEncode(new Uint8Array(bytes(32, 21)));
  const credentialId = required(parseWebAuthnCredentialIdB64u(credentialIdB64u));
  const factorAuthority = buildPasskeyWalletAuthAuthority({
    walletId,
    rpId,
    credentialIdB64u: credentialId,
  });
  const walletAuthMethodId = factorAuthority.bindingId;
  const deviceId = required(parseAuthorizationDeviceId('device:linked-runtime'));
  const packageSetDigestB64u = digest(11);
  const materialActivationEd25519 = buildMpcMaterialActivationRefFixture(
    'linked-runtime-ed25519',
    String(walletId),
    'worker:linked-runtime',
  );
  const materialActivationEcdsa = buildMpcMaterialActivationRefFixture(
    'linked-runtime-ecdsa',
    String(walletId),
    'worker:linked-runtime',
  );
  const signerActivations = buildWalletSignerActivationSetV1({
    manifest: buildCombinedSignerManifest(walletId),
    materialActivations: {
      keyFamilies: ['ed25519', 'ecdsa_secp256k1'],
      ed25519: materialActivationEd25519,
      ecdsa: materialActivationEcdsa,
    },
  });
  const signerActivationSetDigestB64u =
    await computeWalletSignerActivationSetDigestB64u(signerActivations);
  const authorityDraft = {
    kind: 'wallet_authority_v1',
    authorityId,
    walletId,
    principal: { kind: 'owner_device', deviceId },
    provenance: {
      kind: 'device_link',
      enrollmentId: required(parseLinkedDeviceEnrollmentId('enrollment:linked-runtime')),
      sourceAuthorityId: required(parseWalletAuthorityId('authority:linked-runtime-source')),
      linkSessionId: required(parseLinkDeviceSessionId('link-session:linked-runtime')),
    },
    permissions: buildSigningOnlyPermissionsV1(),
    signerActivations,
    signerActivationSetDigestB64u,
    authorityDigestB64u: digest(12),
    revocationEpoch: 0,
    createdAtMs: 100,
    updatedAtMs: 200,
    state: 'active',
    activatedAtMs: 200,
  } as const;
  const authority = buildActiveWalletAuthorityV1({
    ...authorityDraft,
    authorityDigestB64u: await computeWalletAuthorityDigestB64u(authorityDraft),
  });
  const authMethod = buildWalletAuthMethodRecordV2({
    version: 'wallet_auth_method_v2',
    walletAuthMethodId,
    walletId,
    walletAuthorityId: authorityId,
    kind: 'passkey',
    status: 'active',
    rpId,
    credentialIdB64u: credentialId,
    credentialPublicKeyB64u: base64UrlEncode(new Uint8Array(bytes(65, 22))),
    counter: 0,
    createdAtMs: 100,
    updatedAtMs: 200,
    activatedAtMs: 200,
  });
  if (authMethod.kind !== 'passkey' || authMethod.status !== 'active') {
    throw new Error('linked runtime auth-method fixture has the wrong branch');
  }
  const targetFactor = buildTargetFactor(walletAuthMethodId, rpId, credentialId, digest(13));
  const factorSecret = new Uint8Array(bytes(32, 101));
  const signerMaterials = [
    await sealSignerMaterial({
      walletId,
      authorityId,
      walletAuthMethodId,
      packageSetDigestB64u,
      targetFactor,
      materialActivation: materialActivationEd25519,
      keyFamily: 'ed25519',
      publicFacts: buildEd25519PublicFacts(walletId, materialActivationEd25519),
      factorSecret,
    }),
    await sealSignerMaterial({
      walletId,
      authorityId,
      walletAuthMethodId,
      packageSetDigestB64u,
      targetFactor,
      materialActivation: materialActivationEcdsa,
      keyFamily: 'ecdsa_secp256k1',
      publicFacts: {
        keyFamily: 'ecdsa_secp256k1',
        ecdsaThresholdKeyId: parseEcdsaThresholdKeyId('ecdsa-threshold-key:linked-runtime'),
        activationReceipt: buildEcdsaReceipt(materialActivationEcdsa),
      },
      factorSecret,
    }),
  ] as const;
  const tenantId = required(parseTenantId('tenant:linked-runtime'));
  const principalId = required(parsePrincipalId('principal:linked-runtime'));
  const mintId = required(parseWalletSessionMintId('wallet-mint:linked-runtime'));
  const authorizationId = required(
    parseWalletSessionAuthorizationId('authorization:linked-runtime'),
  );
  const walletSessionId = required(parseWalletSessionId('wallet-session:linked-runtime'));
  const quotaId = required(parseMpcWalletSigningQuotaId('wallet-quota:linked-runtime'));
  const issuedSession = buildWalletSessionAuthorizationV2({
    tenantId,
    principalId,
    walletId,
    authorityId,
    walletAuthMethodId,
    authorityDigestB64u: authority.authorityDigestB64u,
    authorityRevocationEpoch: 0,
    mintId,
    authorizationId,
    walletSessionId,
    quotaId,
    capabilitySubjects: buildWalletSessionCapabilitySubjectsV1(authority),
    createdAtMs: 300,
    expiresAtMs: Date.now() + 60_000,
  });
  const activeWalletSession: ActiveWalletSessionV1 = {
    kind: 'active_wallet_session_v1',
    walletId,
    authorityId,
    authMethodId: walletAuthMethodId,
    authorizationId,
    quotaId,
    authorityDigestB64u: authority.authorityDigestB64u,
    authorityRevocationEpoch: 0,
    capabilitySubjects: issuedSession.capabilitySubjects,
    issuedAtMs: issuedSession.createdAtMs,
    expiresAtMs: issuedSession.expiresAtMs,
  };
  const operationCredential = {
    kind: 'opaque_wallet_session_operation_credential_v1' as const,
    token: `wst_${'A'.repeat(43)}`,
    walletSessionId,
  };
  const thresholdSessionId = required(
    parseThresholdEd25519SessionId('threshold-ed25519:linked-runtime'),
  );
  const ed25519Session: PasskeyWalletUnlockEd25519Session = {
    walletId: String(walletId),
    nearAccountId: 'linked-runtime.testnet',
    nearEd25519SigningKeyId: 'near-ed25519-key:linked-runtime',
    relayerKeyId: 'worker:linked-runtime',
    participantIds: [1, 2],
    thresholdSessionId,
    authorizationId,
    walletSessionId,
    quotaId,
    expiresAtMs: activeWalletSession.expiresAtMs,
    remainingUses: 10,
    runtimePolicyScope: {
      orgId: 'org:linked-runtime',
      projectId: 'project:linked-runtime',
      envId: 'test',
      signingRootVersion: 'epoch:linked-runtime',
    },
    routerAbNormalSigning: {
      kind: 'router_ab_ed25519_normal_signing_v1',
      signingWorkerId: 'worker:linked-runtime',
    },
    sessionKind: 'issued_exact_wallet_session',
    operationCredential,
  };
  const factorSecretB64u = base64UrlEncode(factorSecret);
  factorSecret.fill(0);
  return {
    walletId,
    authority,
    authMethod,
    factorAuthority,
    selection: {
      kind: 'wallet_selection_v1',
      walletId,
      walletAuthMethodId,
      lockGeneration: 0,
      lockState: 'unlocked',
      updatedAtMs: 200,
    },
    signerMaterials,
    activeWalletSession,
    operationCredential,
    ed25519Session,
    credential: {
      id: credentialId,
      rawId: credentialId,
      type: 'public-key',
      authenticatorAttachment: undefined,
      response: {
        clientDataJSON: 'client-data',
        authenticatorData: 'authenticator-data',
        signature: 'signature',
        userHandle: undefined,
      },
      clientExtensionResults: {
        prf: { results: { first: factorSecretB64u, second: undefined } },
      },
    },
  };
}

export async function buildWalletRecoveryAuthorityFixture(
  fixture: Pick<LinkedDeviceUnlockRuntimeFixture, 'authority'>,
): Promise<LinkedDeviceUnlockRuntimeFixture['authority']> {
  const draft = buildActiveWalletAuthorityV1({
    kind: fixture.authority.kind,
    authorityId: fixture.authority.authorityId,
    walletId: fixture.authority.walletId,
    principal: fixture.authority.principal,
    provenance: {
      kind: 'wallet_recovery',
      recoveryOperationId: required(
        parseWalletRecoveryOperationId('wallet-recovery:linked-runtime'),
      ),
      continuityAuthorityId: fixture.authority.authorityId,
    },
    permissions: fixture.authority.permissions,
    signerActivations: fixture.authority.signerActivations,
    signerActivationSetDigestB64u: fixture.authority.signerActivationSetDigestB64u,
    authorityDigestB64u: fixture.authority.authorityDigestB64u,
    revocationEpoch: fixture.authority.revocationEpoch,
    createdAtMs: fixture.authority.createdAtMs,
    updatedAtMs: fixture.authority.updatedAtMs,
    state: fixture.authority.state,
    activatedAtMs: fixture.authority.activatedAtMs,
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

export async function buildLinkedDeviceEmailOtpUnlockRuntimeFixture(): Promise<LinkedDeviceEmailOtpUnlockRuntimeFixture> {
  const passkeyFixture = await buildLinkedDeviceUnlockRuntimeFixture();
  const runtimeFixture = {
    walletId: passkeyFixture.walletId,
    authority: passkeyFixture.authority,
    operationCredential: passkeyFixture.operationCredential,
    ed25519Session: passkeyFixture.ed25519Session,
  };
  const emailHashHex = 'a'.repeat(64);
  const providerIdentity = {
    provider: 'email' as const,
    providerSubjectId: 'linked-runtime@example.test',
  };
  const factorAuthority = buildEmailOtpWalletAuthAuthority({
    walletId: passkeyFixture.walletId,
    provider: providerIdentity.provider,
    providerUserId: providerIdentity.providerSubjectId,
    emailHashHex,
  });
  const authMethod = buildWalletAuthMethodRecordV2({
    version: 'wallet_auth_method_v2',
    walletAuthMethodId: factorAuthority.bindingId,
    walletId: passkeyFixture.walletId,
    walletAuthorityId: passkeyFixture.authority.authorityId,
    kind: 'email_otp',
    status: 'active',
    emailHashHex,
    registrationAuthorityId: providerIdentity.providerSubjectId,
    createdAtMs: 100,
    updatedAtMs: 200,
    activatedAtMs: 200,
  });
  if (authMethod.kind !== 'email_otp' || authMethod.status !== 'active') {
    throw new Error('linked Email OTP runtime auth-method fixture has the wrong branch');
  }
  const targetFactor: WalletAuthorityLinkedMaterialTargetFactorV1 = {
    kind: 'email_otp',
    walletAuthMethodId: authMethod.walletAuthMethodId,
    verificationDigestB64u: digest(14),
    emailHashHex,
    registrationAuthorityId: authMethod.registrationAuthorityId,
  };
  const factorSecret32 = new Uint8Array(bytes(32, 101));
  const signerMaterials = await Promise.all(
    passkeyFixture.signerMaterials.map(async (material) => {
      if (material.keyFamily === 'ed25519') {
        return await sealSignerMaterial({
          walletId: passkeyFixture.walletId,
          authorityId: passkeyFixture.authority.authorityId,
          walletAuthMethodId: authMethod.walletAuthMethodId,
          packageSetDigestB64u: material.packageSetDigestB64u,
          targetFactor,
          materialActivation: material.materialActivation,
          keyFamily: 'ed25519',
          publicFacts: material.publicFacts,
          factorSecret: factorSecret32,
        });
      }
      return await sealSignerMaterial({
        walletId: passkeyFixture.walletId,
        authorityId: passkeyFixture.authority.authorityId,
        walletAuthMethodId: authMethod.walletAuthMethodId,
        packageSetDigestB64u: material.packageSetDigestB64u,
        targetFactor,
        materialActivation: material.materialActivation,
        keyFamily: 'ecdsa_secp256k1',
        publicFacts: material.publicFacts,
        factorSecret: factorSecret32,
      });
    }),
  );
  const activeWalletSession = buildLinkedDeviceActiveWalletSessionFixture({
    source: passkeyFixture.activeWalletSession,
    authMethodId: authMethod.walletAuthMethodId,
    authorizationId: passkeyFixture.activeWalletSession.authorizationId,
    quotaId: passkeyFixture.activeWalletSession.quotaId,
    authorityDigestB64u: passkeyFixture.authority.authorityDigestB64u,
    authorityRevocationEpoch: passkeyFixture.authority.revocationEpoch,
  });
  return {
    ...runtimeFixture,
    authMethod,
    factorAuthority,
    selection: {
      kind: 'wallet_selection_v1',
      walletId: passkeyFixture.walletId,
      walletAuthMethodId: authMethod.walletAuthMethodId,
      lockGeneration: 0,
      lockState: 'unlocked',
      updatedAtMs: 200,
    },
    signerMaterials,
    activeWalletSession,
    providerIdentity,
    factorSecret32,
  };
}
