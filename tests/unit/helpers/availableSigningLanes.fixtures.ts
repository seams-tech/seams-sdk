import {
  readAvailableSigningLanes,
  type AvailableSigningLanes,
  type ConcreteAvailableEd25519SigningLane,
  type ConcreteAvailableEcdsaSigningLane,
} from '@/core/signingEngine/session/availability/availableSigningLanes';
import {
  thresholdEcdsaChainTargetFromChainFamily,
  thresholdEcdsaChainTargetKey,
  toWalletId,
  type ThresholdEcdsaChainTarget,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import { toAccountId } from '@/core/types/accountIds';
import {
  buildExactEcdsaDirectCapabilityRuntime,
  buildExactEvmFamilyWalletSessionAuthorization,
  type CanonicalEvmFamilyEcdsaSigningCapability,
  type ExactEvmFamilyWalletSessionAuthorization,
} from '@/core/signingEngine/session/material/ecdsaSigningCapability';
import {
  parseDeviceId,
  parsePrincipalId,
  parseTenantId,
} from '@shared/authorization/capabilityKinds';
import {
  buildActiveWalletAuthorityV1,
  buildWalletSignerActivationSetV1,
} from '@shared/authorization/walletAuthority';
import { buildSigningOnlyPermissionsV1 } from '@shared/authorization/delegatedAuthority';
import { parseExactAdministeredSignerManifestV1 } from '@shared/device-linking/delegatedActivationPlan';
import { parseWalletSessionOperationCredentialV1 } from '@shared/device-linking/parsers';
import { base64UrlEncode } from '@shared/utils/base64';
import { parseDigestB64u } from '@shared/utils/canonicalPrimitives';
import { parseWalletAuthorityId } from '@shared/utils/domainIds';
import { parseEcdsaRoleLocalPersistedMaterialRef } from '@/core/signingEngine/session/keyMaterialBrands';
import { buildWalletAuthAuthorityRefForAuthorityFixture } from './ecdsaMaterialRef.fixtures';
import {
  parseRootShareEpoch,
  parseThresholdEcdsaSessionId,
  parseThresholdEd25519SessionId,
  type MpcMaterialActivationRef,
  type RootShareEpoch,
} from '@shared/utils/domainIds';
import { nearEd25519SigningKeyIdFromString } from '@shared/utils/registrationIntent';
import {
  buildBaseEvmFamilyEcdsaKeyIdentity,
  buildPasskeyEcdsaAuthBinding,
  buildResolvedEvmFamilyEcdsaKey,
  buildVerifiedEcdsaPublicFacts,
  deriveEvmFamilySigningKeySlotId,
  toRpId,
  type EvmFamilyEcdsaKeyHandle,
  type EvmFamilyEcdsaKeyIdentity,
  type VerifiedEcdsaPublicFacts,
} from '@/core/signingEngine/session/identity/evmFamilyEcdsaIdentity';
import type { SigningSessionSealedStoreRecord } from '@/core/signingEngine/session/persistence/sealedSessionStore';
import {
  ROUTER_AB_ED25519_NORMAL_SIGNING_STATE_KIND,
  type RouterAbEd25519NormalSigningState,
} from '@shared/utils/signingSessionSeal';
import {
  ROUTER_AB_ECDSA_DERIVATION_NORMAL_SIGNING_STATE_KIND_V1,
  type RouterAbEcdsaDerivationNormalSigningStateV1,
} from '@shared/utils/routerAbEcdsaDerivation';
import { buildMpcMaterialActivationRefFixture } from './ecdsaMaterialRef.fixtures';
import { routerAbMpcMaterialActivationRefToWire } from '@shared/utils/routerAbNormalSigningIdentity';
import { ecdsaCapabilityActivationLookupFixture } from './ecdsaCapabilityManifest.fixtures';
import { buildPersistedEcdsaRoleLocalMaterial } from '@/core/signingEngine/session/material/ecdsaRoleLocalMaterialResolver';
import {
  buildEmailOtpWalletAuthAuthority,
  buildPasskeyWalletAuthAuthority,
  isEmailOtpWalletAuthAuthority,
  isPasskeyWalletAuthAuthority,
  type WalletAuthAuthority,
} from '@shared/utils/walletAuthAuthority';
import { buildWalletAuthMethodRecordV2 } from '@shared/utils/registrationIntent';
import {
  buildActiveNearEd25519WalletSessionAuthorization,
  type ActiveNearEd25519WalletSessionStatus,
  type ExactNearEd25519WalletSessionAuthorization,
} from '@/core/signingEngine/session/material/nearEd25519YaoSigningPreparation';
import type {
  ExactEcdsaCapabilityRuntime,
  ExactEcdsaSealedRuntime,
} from '@/core/signingEngine/session/material/ecdsaSealedRuntime';
import type { OwnerLaneScope } from '@/core/signingEngine/session/identity/signingLaneAuthBinding';
import { projectActiveWalletSession } from '../../../packages/wallet-server/src/authorization/domain';
import { buildExactWalletSessionAuthorizationFixture } from './exactWalletSessionAuthorization.fixtures';

export const AVAILABLE_LANES_WALLET_ID = 'alice.testnet';
export const AVAILABLE_LANES_ED25519_WALLET_ID = toWalletId('frost-vermillion-k7p9m2');
export const AVAILABLE_LANES_ED25519_NEAR_ACCOUNT_ID = toAccountId('alice.testnet');
export const AVAILABLE_LANES_ED25519_KEY_SCOPE_ID = nearEd25519SigningKeyIdFromString(
  'scope-frost-vermillion-k7p9m2',
);
export const AVAILABLE_LANES_ECDSA_RP_ID = 'wallet.example.localhost';
export const AVAILABLE_LANES_ECDSA_SIGNING_KEY_SLOT_ID = deriveEvmFamilySigningKeySlotId({
  walletId: AVAILABLE_LANES_WALLET_ID,
  signingRootId: 'sr-test:dev',
  signingRootVersion: 'default',
});
export const AVAILABLE_LANES_PASSKEY_CREDENTIAL_ID = 'credential-available-lanes';
export const AVAILABLE_LANES_EXPIRES_AT_MS = 2_000_000_000_000;
export const AVAILABLE_LANES_ECDSA_PUBLIC_KEY_B64U = 'AgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';
export const AVAILABLE_LANES_ECDSA_KEY_HANDLE =
  'ederivation-key-available-lane-test' as EvmFamilyEcdsaKeyHandle;
export const AVAILABLE_LANES_ROOT_SHARE_EPOCH = fixtureRootShareEpoch(
  'available-lanes-root-epoch-1',
);
export const AVAILABLE_LANES_ECDSA_TARGET = thresholdEcdsaChainTargetFromChainFamily({
  chain: 'evm',
  chainId: 5042002,
  networkSlug: 'arc-testnet',
});
export const AVAILABLE_LANES_TEMPO_TARGET = thresholdEcdsaChainTargetFromChainFamily({
  chain: 'tempo',
  chainId: 42431,
  networkSlug: 'tempo-moderato',
});

export function runtimeEd25519RouterAbNormalSigningState(): RouterAbEd25519NormalSigningState {
  return {
    kind: ROUTER_AB_ED25519_NORMAL_SIGNING_STATE_KIND,
    signingWorkerId: 'signing-worker-available-lanes',
  };
}

function hexAddressToBase64Url(address: string): string {
  return Buffer.from(address.replace(/^0x/i, ''), 'hex').toString('base64url');
}

export function runtimeEcdsaRouterAbNormalSigningState(args: {
  key: ReturnType<typeof buildBaseEvmFamilyEcdsaKeyIdentity>;
  thresholdSessionId: string;
  thresholdEcdsaPublicKeyB64u: string;
  thresholdOwnerAddress: string;
}): RouterAbEcdsaDerivationNormalSigningStateV1 {
  return {
    kind: ROUTER_AB_ECDSA_DERIVATION_NORMAL_SIGNING_STATE_KIND_V1,
    scope: {
      wallet_id: args.key.walletId,
      ecdsa_threshold_key_id: args.key.ecdsaThresholdKeyId,
      signing_root_id: args.key.signingRootId,
      signing_root_version: args.key.signingRootVersion,
      context: {
        application_binding_digest_b64u: 'BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc',
      },
      public_identity: {
        context_binding_b64u: 'AQ',
        derivation_client_share_public_key33_b64u: args.thresholdEcdsaPublicKeyB64u,
        server_public_key33_b64u: args.thresholdEcdsaPublicKeyB64u,
        threshold_public_key33_b64u: args.thresholdEcdsaPublicKeyB64u,
        ethereum_address20_b64u: hexAddressToBase64Url(args.thresholdOwnerAddress),
        client_share_retry_counter: 0,
        server_share_retry_counter: 0,
      },
      material_activation: routerAbMpcMaterialActivationRefToWire(
        buildMpcMaterialActivationRefFixture(
          `available-lanes:${args.key.walletId}:${args.key.ecdsaThresholdKeyId}:${AVAILABLE_LANES_ROOT_SHARE_EPOCH}`,
          args.key.walletId,
        ),
      ),
      signing_worker: {
        server_id: 'signing-worker-available-lanes',
        key_epoch: 'epoch-available-lanes',
        recipient_encryption_key:
          'x25519:1111111111111111111111111111111111111111111111111111111111111111',
      },
      activation_epoch: AVAILABLE_LANES_ROOT_SHARE_EPOCH,
    },
  };
}

/** Brands a fixture root-share epoch via the production parser. */
function fixtureRootShareEpoch(value: string): RootShareEpoch {
  const parsed = parseRootShareEpoch(value);
  if (!parsed.ok) {
    throw new Error(`invalid fixture activation epoch: ${value}`);
  }
  return parsed.value;
}

function requireAvailableLaneId<T>(result: { ok: true; value: T } | { ok: false }): T {
  if (!result.ok) throw new Error('available-lane fixture id is invalid');
  return result.value;
}

function requireTwoParticipantIds(value: readonly number[]): readonly [number, number] {
  const [first, second] = value;
  if (
    value.length !== 2 ||
    first === undefined ||
    second === undefined ||
    !Number.isSafeInteger(first) ||
    !Number.isSafeInteger(second) ||
    first < 1 ||
    second < 1 ||
    first === second
  ) {
    throw new Error('available-lane ECDSA fixture requires two distinct participants');
  }
  return [first, second];
}

function buildAvailableLaneEcdsaRuntime(args: {
  common: Omit<ExactEcdsaSealedRuntime, 'authBinding'>;
  authBinding: ExactEcdsaSealedRuntime['authBinding'];
}): ExactEcdsaSealedRuntime {
  switch (args.authBinding.kind) {
    case 'passkey':
      return { ...args.common, authBinding: args.authBinding };
    case 'email_otp':
      return { ...args.common, authBinding: args.authBinding };
  }
  args.authBinding satisfies never;
  throw new Error('available-lane ECDSA fixture has an unsupported auth binding');
}

export function availableLaneEd25519Authorization(args: {
  walletId: string;
  identitySeed: string;
  authMethod: 'email_otp' | 'passkey';
  expiresAtMs?: number;
  materialActivation?: MpcMaterialActivationRef;
}): ExactNearEd25519WalletSessionAuthorization {
  const walletId = toWalletId(args.walletId);
  const materialActivation =
    args.materialActivation ??
    buildMpcMaterialActivationRefFixture(
      `available-lane-ed25519:${args.identitySeed}`,
      args.walletId,
    );
  let factorAuthority: WalletAuthAuthority;
  const authorityId = requireAvailableLaneId(
    parseWalletAuthorityId(`available-lane-authority:${args.identitySeed}`),
  );
  const signerManifest = parseExactAdministeredSignerManifestV1({
    kind: 'exact_administered_signer_manifest_v1',
    keyFamilies: ['ed25519'],
    signers: [
      {
        kind: 'exact_administered_ed25519_signer_v1',
        keyFamily: 'ed25519',
        walletId,
        walletKeyId: `wallet-key:available-lane-${args.identitySeed}`,
        registeredPublicKeyB64u: base64UrlEncode(new Uint8Array(32).fill(7)),
      },
    ],
  });
  const signerActivations = buildWalletSignerActivationSetV1({
    manifest: signerManifest,
    materialActivations: {
      keyFamilies: ['ed25519'],
      ed25519: materialActivation,
    },
  });
  const authorityDigest = parseDigestB64u(base64UrlEncode(new Uint8Array(32).fill(8)));
  const authority = buildActiveWalletAuthorityV1({
    kind: 'wallet_authority_v1',
    authorityId,
    walletId,
    principal: {
      kind: 'owner_device',
      deviceId: requireAvailableLaneId(parseDeviceId(`device:available-lane-${args.identitySeed}`)),
    },
    provenance: { kind: 'wallet_registration' },
    permissions: buildSigningOnlyPermissionsV1(),
    signerActivations,
    signerActivationSetDigestB64u: authorityDigest,
    authorityDigestB64u: authorityDigest,
    revocationEpoch: 0,
    createdAtMs: 0,
    updatedAtMs: 1,
    state: 'active',
    activatedAtMs: 1,
  });
  let authMethod: ReturnType<typeof buildWalletAuthMethodRecordV2>;
  if (args.authMethod === 'passkey') {
    const passkeyAuthority = buildPasskeyWalletAuthAuthority({
      walletId,
      rpId: AVAILABLE_LANES_ECDSA_RP_ID,
      credentialIdB64u: AVAILABLE_LANES_PASSKEY_CREDENTIAL_ID,
    });
    factorAuthority = passkeyAuthority;
    authMethod = buildWalletAuthMethodRecordV2({
      version: 'wallet_auth_method_v2',
      walletAuthMethodId: passkeyAuthority.bindingId,
      walletId,
      walletAuthorityId: authorityId,
      kind: 'passkey',
      status: 'active',
      rpId: passkeyAuthority.verifier.rpId,
      credentialIdB64u: passkeyAuthority.factor.credentialIdB64u,
      credentialPublicKeyB64u: base64UrlEncode(new Uint8Array(65).fill(9)),
      counter: 0,
      createdAtMs: 0,
      updatedAtMs: 1,
      activatedAtMs: 1,
    });
  } else {
    const emailOtpAuthority = buildEmailOtpWalletAuthAuthority({
      walletId,
      provider: 'google',
      providerUserId: 'google:available-lanes',
      emailHashHex: 'available-lanes-email-hash',
    });
    factorAuthority = emailOtpAuthority;
    authMethod = buildWalletAuthMethodRecordV2({
      version: 'wallet_auth_method_v2',
      walletAuthMethodId: emailOtpAuthority.bindingId,
      walletId,
      walletAuthorityId: authorityId,
      kind: 'email_otp',
      status: 'active',
      emailHashHex: emailOtpAuthority.verifier.emailHashHex,
      registrationAuthorityId: `registration:available-lane-${args.identitySeed}`,
      createdAtMs: 0,
      updatedAtMs: 1,
      activatedAtMs: 1,
    });
  }
  if (authMethod.status !== 'active') {
    throw new Error('available-lane exact auth method fixture is not active');
  }
  const expiresAtMs = args.expiresAtMs ?? AVAILABLE_LANES_EXPIRES_AT_MS;
  const issuedAtMs = Math.max(0, Math.min(100, expiresAtMs - 1));
  const issued = buildExactWalletSessionAuthorizationFixture({
    label: `available-lane-${args.identitySeed}`,
    tenantId: requireAvailableLaneId(parseTenantId('tenant:available-lanes')),
    principalId: requireAvailableLaneId(parsePrincipalId('principal:available-lanes')),
    authority,
    walletAuthMethodId: authMethod.walletAuthMethodId,
    issuedAtMs,
    expiresAtMs,
    remainingUses: 3,
  });
  const session = projectActiveWalletSession(issued);
  const walletSessionId = issued.session.walletSessionId;
  const operationCredential = parseWalletSessionOperationCredentialV1({
    kind: 'opaque_wallet_session_operation_credential_v1',
    token: `wst_${'A'.repeat(43)}`,
    walletSessionId,
  });
  const status: ActiveNearEd25519WalletSessionStatus = {
    status: 'active',
    walletSessionId,
    quotaId: session.quotaId,
    remainingUses: 3,
    expiresAtMs,
    quotaLifecycle: 'active',
    authorization: session,
  };
  return buildActiveNearEd25519WalletSessionAuthorization({
    selectedAuthority: authority,
    selectedAuthMethod: authMethod,
    selectedFactorAuthority: factorAuthority,
    session,
    operationCredential,
    status,
    nowMs: Math.min(Date.now(), Math.max(0, expiresAtMs - 1)),
  });
}

export function authorizedPasskeyEd25519AvailableLane(args: {
  authorization: ExactNearEd25519WalletSessionAuthorization;
  materialActivation: MpcMaterialActivationRef;
  signerSlot?: number;
}): Extract<ConcreteAvailableEd25519SigningLane, { authorizationState: 'authorized' }> {
  return {
    auth: {
      kind: 'passkey',
      rpId: toRpId(AVAILABLE_LANES_ECDSA_RP_ID),
      credentialIdB64u: AVAILABLE_LANES_PASSKEY_CREDENTIAL_ID,
    },
    curve: 'ed25519',
    chain: 'near',
    materialActivation: args.materialActivation,
    walletId: args.authorization.session.walletId,
    nearAccountId: AVAILABLE_LANES_ED25519_NEAR_ACCOUNT_ID,
    nearEd25519SigningKeyId: AVAILABLE_LANES_ED25519_KEY_SCOPE_ID,
    signerSlot: args.signerSlot ?? 1,
    thresholdSessionId: requireAvailableLaneId(
      parseThresholdEd25519SessionId('available-lane-threshold-ed25519:fixture'),
    ),
    state: 'ready',
    source: 'durable_sealed_record',
    authorizationState: 'authorized',
    authorization: args.authorization,
  };
}

export function availableEd25519Inventory(args: {
  primary: Extract<ConcreteAvailableEd25519SigningLane, { authorizationState: 'authorized' }>;
  candidates: ConcreteAvailableEd25519SigningLane[];
}): AvailableSigningLanes {
  return {
    walletId: args.primary.walletId,
    generation: 1,
    ecdsa: {
      targets: [],
      lanesByTarget: {},
      candidatesByTarget: {},
    },
    lanes: { ed25519: { near: args.primary } },
    candidates: { ed25519: { near: args.candidates } },
  };
}

// Active ECDSA lanes carry the exact V2 session, operation credential, and
// sealed-runtime facts that production admission reconciles.
function availableLaneEcdsaAuthorization(args: {
  capability: CanonicalEvmFamilyEcdsaSigningCapability;
  key: EvmFamilyEcdsaKeyIdentity;
  publicFacts: VerifiedEcdsaPublicFacts;
  chainTarget: ThresholdEcdsaChainTarget;
  identitySeed: string;
  authMethod: 'email_otp' | 'passkey';
  remainingUses: number;
  expiresAtMs: number;
  runtimeKind: 'sealed_session' | 'direct_capability';
}): ExactEvmFamilyWalletSessionAuthorization {
  const walletId = args.capability.manifest.signer.walletId;
  const authorityId = requireAvailableLaneId(
    parseWalletAuthorityId(`available-lane-ecdsa-authority:${args.identitySeed}`),
  );
  const signerManifest = parseExactAdministeredSignerManifestV1({
    kind: 'exact_administered_signer_manifest_v1',
    keyFamilies: ['ecdsa_secp256k1'],
    signers: [
      {
        kind: 'exact_administered_ecdsa_signer_v1',
        keyFamily: 'ecdsa_secp256k1',
        walletId,
        walletKeyId: `wallet-key:available-lane-ecdsa-${args.identitySeed}`,
        thresholdPublicKey33B64u: args.publicFacts.publicKeyB64u,
        evmAddress: args.publicFacts.thresholdOwnerAddress,
      },
    ],
  });
  const signerActivations = buildWalletSignerActivationSetV1({
    manifest: signerManifest,
    materialActivations: {
      keyFamilies: ['ecdsa_secp256k1'],
      ecdsa: args.capability.manifest.activation.materialActivation,
    },
  });
  const authority = buildActiveWalletAuthorityV1({
    kind: 'wallet_authority_v1',
    authorityId,
    walletId,
    principal: {
      kind: 'owner_device',
      deviceId: requireAvailableLaneId(
        parseDeviceId(`device:available-lane-ecdsa-${args.identitySeed}`),
      ),
    },
    provenance: { kind: 'wallet_registration' },
    permissions: buildSigningOnlyPermissionsV1(),
    signerActivations,
    signerActivationSetDigestB64u: parseDigestB64u(base64UrlEncode(new Uint8Array(32).fill(14))),
    authorityDigestB64u: parseDigestB64u(
      String(args.capability.manifest.signer.authority.authorityDigest),
    ),
    revocationEpoch: 0,
    createdAtMs: 0,
    updatedAtMs: 1,
    state: 'active',
    activatedAtMs: 1,
  });
  const factorAuthority = args.capability.authority;
  let selectedAuthMethod: ReturnType<typeof buildWalletAuthMethodRecordV2>;
  let authBinding: ExactEvmFamilyWalletSessionAuthorization['runtime']['authBinding'];
  if (isPasskeyWalletAuthAuthority(factorAuthority)) {
    const passkeyAuthority = factorAuthority;
    selectedAuthMethod = buildWalletAuthMethodRecordV2({
      version: 'wallet_auth_method_v2',
      walletAuthMethodId: passkeyAuthority.bindingId,
      walletId,
      walletAuthorityId: authorityId,
      kind: 'passkey',
      status: 'active',
      rpId: passkeyAuthority.verifier.rpId,
      credentialIdB64u: passkeyAuthority.factor.credentialIdB64u,
      credentialPublicKeyB64u: base64UrlEncode(new Uint8Array(65).fill(15)),
      counter: 0,
      createdAtMs: 0,
      updatedAtMs: 1,
      activatedAtMs: 1,
    });
    authBinding = {
      kind: 'passkey',
      rpId: String(passkeyAuthority.verifier.rpId),
      credentialIdB64u: passkeyAuthority.factor.credentialIdB64u,
    };
  } else {
    if (!isEmailOtpWalletAuthAuthority(factorAuthority)) {
      throw new Error('available-lane ECDSA authority fixture has an unsupported factor');
    }
    const emailOtpAuthority = factorAuthority;
    selectedAuthMethod = buildWalletAuthMethodRecordV2({
      version: 'wallet_auth_method_v2',
      walletAuthMethodId: emailOtpAuthority.bindingId,
      walletId,
      walletAuthorityId: authorityId,
      kind: 'email_otp',
      status: 'active',
      emailHashHex: emailOtpAuthority.verifier.emailHashHex,
      registrationAuthorityId: `registration:available-lane-ecdsa-${args.identitySeed}`,
      createdAtMs: 0,
      updatedAtMs: 1,
      activatedAtMs: 1,
    });
    authBinding = {
      kind: 'email_otp',
      providerSubjectId: String(emailOtpAuthority.factor.providerUserId),
      emailHashHex: emailOtpAuthority.verifier.emailHashHex,
      emailOtpAuthority,
    };
  }
  if (selectedAuthMethod.status !== 'active') {
    throw new Error('available-lane exact ECDSA auth method fixture is not active');
  }
  const issued = buildExactWalletSessionAuthorizationFixture({
    label: `available-lane-ecdsa-${args.identitySeed}`,
    tenantId: requireAvailableLaneId(parseTenantId('tenant:available-lanes')),
    principalId: requireAvailableLaneId(parsePrincipalId('principal:available-lanes')),
    authority,
    walletAuthMethodId: selectedAuthMethod.walletAuthMethodId,
    issuedAtMs: Math.max(0, Math.min(100, args.expiresAtMs - 1)),
    expiresAtMs: args.expiresAtMs,
    remainingUses: args.remainingUses,
  });
  const session = projectActiveWalletSession(issued);
  const operationCredential = parseWalletSessionOperationCredentialV1({
    kind: 'opaque_wallet_session_operation_credential_v1',
    token: `wst_${'B'.repeat(43)}`,
    walletSessionId: issued.session.walletSessionId,
  });
  const durable = args.capability.manifest.durableMaterial;
  const participantIds = requireTwoParticipantIds(args.publicFacts.participantIds);
  const roleLocalMaterialRef = parseEcdsaRoleLocalPersistedMaterialRef({
    kind: 'ecdsa_role_local_persisted_material_ref_v1',
    durableMaterialRef: durable.durableMaterialRef,
    bindingDigest: durable.bindingDigest,
    materialActivation: durable.materialActivation,
  });
  const capabilityRuntime: ExactEcdsaCapabilityRuntime = {
    kind: 'exact_ecdsa_capability_runtime_v1',
    walletId,
    chainTarget: args.chainTarget,
    materialActivation: durable.materialActivation,
    normalSigning: durable.routerAbEcdsaDerivationNormalSigning,
    relayerUrl: 'https://relay.example.test',
    relayerKeyId: String(durable.roleLocalBinding.relayerKeyId),
    clientVerifyingPublicKey33B64u: durable.roleLocalBinding.clientVerifyingPublicKey33B64u,
    participantIds,
    ecdsaThresholdKeyId: String(args.key.ecdsaThresholdKeyId),
    thresholdEcdsaPublicKeyB64u: String(args.publicFacts.publicKeyB64u),
    keyHandle: String(args.publicFacts.keyHandle),
    runtimePolicyScope: durable.runtimePolicyScope,
    roleLocalMaterialRef,
  };
  const runtime =
    args.runtimeKind === 'direct_capability'
      ? buildExactEcdsaDirectCapabilityRuntime({
          runtime: capabilityRuntime,
          authority: factorAuthority,
          status: {
            status: 'active',
            walletSessionId: operationCredential.walletSessionId,
            quotaId: session.quotaId,
            expiresAtMs: args.expiresAtMs,
            remainingUses: args.remainingUses,
          },
        })
      : buildAvailableLaneEcdsaRuntime({
          common: {
            kind: 'exact_ecdsa_sealed_runtime_v1' as const,
            walletId,
            chainTarget: args.chainTarget,
            materialActivation: durable.materialActivation,
            normalSigning: durable.routerAbEcdsaDerivationNormalSigning,
            relayerUrl: 'https://relay.example.test',
            relayerKeyId: String(durable.roleLocalBinding.relayerKeyId),
            clientVerifyingPublicKey33B64u: durable.roleLocalBinding.clientVerifyingPublicKey33B64u,
            participantIds,
            ecdsaThresholdKeyId: String(args.key.ecdsaThresholdKeyId),
            thresholdEcdsaPublicKeyB64u: String(args.publicFacts.publicKeyB64u),
            keyHandle: String(args.publicFacts.keyHandle),
            runtimePolicyScope: durable.runtimePolicyScope,
            roleLocalMaterialRef,
            expiresAtMs: args.expiresAtMs,
            remainingUses: args.remainingUses,
            sealedRecord: {
              storeKey: `available-lane-ecdsa:${args.identitySeed}`,
              thresholdSessionId: requireAvailableLaneId(
                parseThresholdEcdsaSessionId(`available-lane-threshold-ecdsa:${args.identitySeed}`),
              ),
              authMethod: args.authMethod,
            },
          },
          authBinding,
        });
  return buildExactEvmFamilyWalletSessionAuthorization({
    capability: args.capability,
    selected: {
      kind: 'resolved',
      selection: {
        kind: 'wallet_selection_v1',
        walletId,
        walletAuthMethodId: selectedAuthMethod.walletAuthMethodId,
        lockGeneration: 0,
        lockState: 'unlocked',
        updatedAtMs: 1,
      },
      authMethod: selectedAuthMethod,
      authority,
      signerMaterials: [],
      exportRoot: null,
    },
    session,
    operationCredential,
    runtime,
    nowMs: Math.min(Date.now(), Math.max(0, args.expiresAtMs - 1)),
  });
}

export function canonicalEcdsaAvailableLane(args: {
  walletId?: string;
  chainTarget: ThresholdEcdsaChainTarget;
  thresholdOwnerAddress: string;
  authMethod?: 'email_otp' | 'passkey';
  state?: 'ready' | 'deferred' | 'expired' | 'exhausted';
  ecdsaThresholdKeyId?: string;
  keyHandle?: EvmFamilyEcdsaKeyHandle;
  remainingUses?: number;
  expiresAtMs?: number;
  updatedAtMs?: number;
  runtimeKind?: 'sealed_session' | 'direct_capability';
}): Extract<ConcreteAvailableEcdsaSigningLane, { source: 'canonical_capability' }> {
  const keyId = args.ecdsaThresholdKeyId || 'shared-ecdsa-key';
  const walletId = args.walletId || AVAILABLE_LANES_WALLET_ID;
  const authMethod = args.authMethod || 'passkey';
  const thresholdOwnerAddress = args.thresholdOwnerAddress;
  const key = buildBaseEvmFamilyEcdsaKeyIdentity({
    walletId,
    ecdsaThresholdKeyId: keyId,
    signingRootId: 'sr-test:dev',
    signingRootVersion: 'default',
    participantIds: [1, 2],
    thresholdOwnerAddress,
  });
  const keyHandle = args.keyHandle || (`ederivation-key-${keyId}` as EvmFamilyEcdsaKeyHandle);
  const factor =
    authMethod === 'email_otp'
      ? buildEmailOtpWalletAuthAuthority({
          walletId,
          provider: 'google',
          providerUserId: 'google:available-lanes',
          emailHashHex: 'available-lanes-email-hash',
        })
      : buildPasskeyWalletAuthAuthority({
          walletId,
          rpId: AVAILABLE_LANES_ECDSA_RP_ID,
          credentialIdB64u: AVAILABLE_LANES_PASSKEY_CREDENTIAL_ID,
        });
  const factorRef = buildWalletAuthAuthorityRefForAuthorityFixture(factor);
  const manifest = ecdsaCapabilityActivationLookupFixture({
    authority: factorRef,
    walletId: toWalletId(walletId),
    chainTarget: args.chainTarget,
    keyHandle,
    signingRootId: String(key.signingRootId),
    signingRootVersion: String(key.signingRootVersion),
    ecdsaThresholdKeyId: keyId,
    thresholdOwnerAddress,
  }).manifest;
  const capability = {
    kind: 'canonical_evm_family_ecdsa_signing_capability' as const,
    authority: factor,
    manifest,
    material: buildPersistedEcdsaRoleLocalMaterial({
      authority: manifest.signer.authority,
      materialActivation: manifest.activation.materialActivation,
      publicFacts: manifest.durableMaterial.roleLocalPublicFacts,
    }),
  };
  const materialActivation = manifest.activation.materialActivation;
  const publicFacts = manifest.signer.registeredPublicFacts;
  const authorization = availableLaneEcdsaAuthorization({
    capability,
    key,
    publicFacts,
    chainTarget: args.chainTarget,
    identitySeed: `${keyId}:${thresholdEcdsaChainTargetKey(args.chainTarget)}`,
    authMethod,
    remainingUses: args.remainingUses ?? 3,
    expiresAtMs: args.expiresAtMs ?? AVAILABLE_LANES_EXPIRES_AT_MS,
    runtimeKind: args.runtimeKind ?? 'sealed_session',
  });
  const base = {
    capability,
    key,
    materialActivation,
    publicFacts,
    curve: 'ecdsa' as const,
    chainTarget: args.chainTarget,
    source: 'canonical_capability' as const,
    state: args.state ?? 'ready',
    authorization,
    remainingUses: args.remainingUses ?? 3,
    expiresAtMs: args.expiresAtMs ?? AVAILABLE_LANES_EXPIRES_AT_MS,
    updatedAtMs: args.updatedAtMs ?? 700,
  };
  return authMethod === 'email_otp'
    ? {
        ...base,
        auth: { kind: 'email_otp', providerSubjectId: 'google:available-lanes' },
      }
    : {
        ...base,
        auth: {
          kind: 'passkey',
          rpId: toRpId(AVAILABLE_LANES_ECDSA_RP_ID),
          credentialIdB64u: AVAILABLE_LANES_PASSKEY_CREDENTIAL_ID,
        },
        resolvedKey: buildResolvedEvmFamilyEcdsaKey({
          walletId: key.walletId,
          publicFacts,
          authBinding: buildPasskeyEcdsaAuthBinding({
            rpId: AVAILABLE_LANES_ECDSA_RP_ID,
            credentialIdB64u: AVAILABLE_LANES_PASSKEY_CREDENTIAL_ID,
          }),
        }),
      };
}

export function authorizationRequiredCanonicalEcdsaAvailableLane(
  args: Parameters<typeof canonicalEcdsaAvailableLane>[0],
): Extract<ConcreteAvailableEcdsaSigningLane, { source: 'canonical_capability' }> {
  const authorized = canonicalEcdsaAvailableLane(args);
  const base = {
    capability: authorized.capability,
    key: authorized.key,
    materialActivation: authorized.materialActivation,
    publicFacts: authorized.publicFacts,
    curve: 'ecdsa' as const,
    chainTarget: authorized.chainTarget,
    source: 'canonical_capability' as const,
    state: 'deferred' as const,
  };
  if (authorized.auth.kind === 'email_otp') {
    return {
      ...base,
      auth: authorized.auth,
    };
  }
  if (!authorized.resolvedKey) {
    throw new Error('canonical passkey ECDSA lane fixture is missing its resolved key');
  }
  return {
    ...base,
    auth: authorized.auth,
    resolvedKey: authorized.resolvedKey,
  };
}

export function canonicalEcdsaOwnerLaneScopeFixture(
  lane: Extract<ConcreteAvailableEcdsaSigningLane, { source: 'canonical_capability' }>,
): OwnerLaneScope {
  const authorityRef = buildWalletAuthAuthorityRefForAuthorityFixture(lane.capability.authority);
  if (lane.auth.kind === 'passkey') {
    return {
      auth: lane.auth,
      keyFamily: 'ecdsa',
    };
  }
  return {
    auth: lane.auth,
    ownerAuthority: {
      walletAuthMethodId: authorityRef.walletAuthMethodId,
      authorityDigest: authorityRef.authorityDigest,
    },
  };
}

export async function readAvailableLanesFixture(args: {
  walletId?: string;
  sealedRecords?: SigningSessionSealedStoreRecord[];
  ecdsaChainTargets?: [ThresholdEcdsaChainTarget, ...ThresholdEcdsaChainTarget[]];
  canonicalEcdsaLanes?: ConcreteAvailableEcdsaSigningLane[];
}) {
  return await readAvailableSigningLanes(
    {
      walletId: toWalletId(args.walletId || AVAILABLE_LANES_WALLET_ID),
      ecdsaChainTargets: args.ecdsaChainTargets || [AVAILABLE_LANES_ECDSA_TARGET],
    },
    {
      listSealedRecordsForWallet: async ({ filter }) =>
        (args.sealedRecords || []).filter((record) => {
          if (record.curve !== filter.curve) return false;
          if (filter.authMethod && record.authMethod !== filter.authMethod) return false;
          return true;
        }),
      listCanonicalEcdsaLanesForWallet: async () => args.canonicalEcdsaLanes || [],
    },
  );
}
