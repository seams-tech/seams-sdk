import {
  readAvailableSigningLanes,
  type ConcreteAvailableEcdsaSigningLane,
} from '@/core/signingEngine/session/availability/availableSigningLanes';
import {
  thresholdEcdsaChainTargetFromChainFamily,
  thresholdEcdsaChainTargetKey,
  toWalletId,
  type ThresholdEcdsaChainTarget,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import { toAccountId } from '@/core/types/accountIds';
import type { ActiveEvmFamilyWalletSessionAuthorization } from '@/core/signingEngine/session/material/ecdsaSigningCapability';
import {
  parseMpcWalletSigningQuotaId,
  parseWalletSessionAuthorizationId,
  parseWalletSessionId,
} from '@shared/authorization/capabilityKinds';
import {
  WALLET_SESSION_AUTHORIZATION_RECORD_VERSION,
  type ActiveWalletSessionAuthorizationProjection,
} from '@/core/indexedDB/seamsWalletDB/walletSessionAuthorizationStore';
import { buildWalletAuthAuthorityRefFixture } from './ecdsaMaterialRef.fixtures';
import {
  parseRootShareEpoch,
  parseThresholdEcdsaSessionId,
  parseThresholdEd25519SessionId,
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
} from '@shared/utils/walletAuthAuthority';

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

export function availableLaneEd25519Authorization(args: {
  walletId: string;
  identitySeed: string;
  authMethod: 'email_otp' | 'passkey';
  expiresAtMs?: number;
}): ActiveWalletSessionAuthorizationProjection {
  return {
    recordVersion: WALLET_SESSION_AUTHORIZATION_RECORD_VERSION,
    walletId: toWalletId(args.walletId),
    walletSessionId: requireAvailableLaneId(
      parseWalletSessionId(`available-lane-wallet-session:${args.identitySeed}`),
    ),
    quotaId: requireAvailableLaneId(
      parseMpcWalletSigningQuotaId(`available-lane-quota:${args.identitySeed}`),
    ),
    authMethod: args.authMethod,
    authority: buildWalletAuthAuthorityRefFixture({ walletId: args.walletId }),
    expiresAtMs: args.expiresAtMs ?? AVAILABLE_LANES_EXPIRES_AT_MS,
    status: 'active',
    walletSessionTokens: {
      kind: 'near_ed25519',
      ed25519: {
        authorizationId: requireAvailableLaneId(
          parseWalletSessionAuthorizationId(`available-lane-authorization:${args.identitySeed}`),
        ),
        walletSessionToken: `fixture-wallet-session-jwt:${args.identitySeed}` as never,
        thresholdSessionId: requireAvailableLaneId(
          parseThresholdEd25519SessionId(`available-lane-threshold-ed25519:${args.identitySeed}`),
        ),
      },
    },
  };
}

// Active reusable Wallet Session authorization for a runtime ECDSA lane.
// Runtime state a durable record never carries, so the fixture supplies it.
function availableLaneEcdsaAuthorization(args: {
  walletId: string;
  identitySeed: string;
  authMethod: 'email_otp' | 'passkey';
  remainingUses: number;
  expiresAtMs: number;
}): ActiveEvmFamilyWalletSessionAuthorization {
  const walletSessionId = requireAvailableLaneId(
    parseWalletSessionId(`available-lane-wallet-session:${args.identitySeed}`),
  );
  const quotaId = requireAvailableLaneId(
    parseMpcWalletSigningQuotaId(`available-lane-quota:${args.identitySeed}`),
  );
  return {
    kind: 'active_reusable_wallet_session_authorization',
    projection: {
      recordVersion: WALLET_SESSION_AUTHORIZATION_RECORD_VERSION,
      walletId: toWalletId(args.walletId),
      walletSessionId,
      quotaId,
      authMethod: args.authMethod,
      authority: buildWalletAuthAuthorityRefFixture({ walletId: args.walletId }),
      expiresAtMs: args.expiresAtMs,
      status: 'active',
      walletSessionTokens: {
        kind: 'evm_family_ecdsa',
        ecdsa: {
          authorizationId: requireAvailableLaneId(
            parseWalletSessionAuthorizationId(`available-lane-authorization:${args.identitySeed}`),
          ),
          walletSessionToken: `fixture-wallet-session-jwt:${args.identitySeed}` as never,
          thresholdSessionId: requireAvailableLaneId(
            parseThresholdEcdsaSessionId(`available-lane-threshold-ecdsa:${args.identitySeed}`),
          ),
        },
      },
    },
    status: {
      walletSessionId,
      quotaId,
      status: 'active',
      remainingUses: args.remainingUses,
      expiresAtMs: args.expiresAtMs,
    },
  };
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
}): ConcreteAvailableEcdsaSigningLane {
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
  const manifest = ecdsaCapabilityActivationLookupFixture({
    authority: buildWalletAuthAuthorityRefFixture({ walletId }),
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
    authority:
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
          }),
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
    walletId,
    identitySeed: `${keyId}:${thresholdEcdsaChainTargetKey(args.chainTarget)}`,
    authMethod,
    remainingUses: args.remainingUses ?? 3,
    expiresAtMs: args.expiresAtMs ?? AVAILABLE_LANES_EXPIRES_AT_MS,
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
): ConcreteAvailableEcdsaSigningLane {
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
