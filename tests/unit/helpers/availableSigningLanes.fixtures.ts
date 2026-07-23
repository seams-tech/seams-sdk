import {
  readAvailableSigningLanes,
  runtimeEcdsaRecordAdvisoryKey,
  type AvailableLaneStateAdvisory,
  type AvailableSigningLanesRuntimeEcdsaRecord,
  type AvailableSigningLanesRuntimeEd25519Record,
} from '@/core/signingEngine/session/availability/availableSigningLanes';
import {
  thresholdEcdsaChainTargetFromChainFamily,
  thresholdEcdsaChainTargetKey,
  toWalletId,
  type ThresholdEcdsaChainTarget,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import { toAccountId } from '@/core/types/accountIds';
import { parseRootShareEpoch, type RootShareEpoch } from '@shared/utils/domainIds';
import { nearEd25519SigningKeyIdFromString } from '@shared/utils/registrationIntent';
import {
  buildBaseEvmFamilyEcdsaKeyIdentity,
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
  ROUTER_AB_ECDSA_DERIVATION_KEY_SCOPE_V1,
  ROUTER_AB_ECDSA_DERIVATION_NORMAL_SIGNING_STATE_KIND_V1,
  type RouterAbEcdsaDerivationNormalSigningStateV1,
} from '@shared/utils/routerAbEcdsaDerivation';

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
      wallet_key_id: args.key.evmFamilySigningKeySlotId,
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

export function runtimeEcdsaAvailableLaneRecord(args: {
  chainTarget: ThresholdEcdsaChainTarget;
  thresholdSessionId: string;
  signingGrantId: string;
  thresholdOwnerAddress: string;
  authMethod?: 'email_otp' | 'passkey';
  ecdsaThresholdKeyId?: string;
  keyHandle?: EvmFamilyEcdsaKeyHandle;
  remainingUses?: number;
  expiresAtMs?: number;
  updatedAtMs?: number;
}): AvailableSigningLanesRuntimeEcdsaRecord {
  const keyId = args.ecdsaThresholdKeyId || 'shared-ecdsa-key';
  const thresholdOwnerAddress = args.thresholdOwnerAddress;
  const evmFamilySigningKeySlotId = deriveEvmFamilySigningKeySlotId({
    walletId: AVAILABLE_LANES_WALLET_ID,
    signingRootId: 'sr-test:dev',
    signingRootVersion: 'default',
  });
  const key = buildBaseEvmFamilyEcdsaKeyIdentity({
    walletId: AVAILABLE_LANES_WALLET_ID,
    evmFamilySigningKeySlotId,
    ecdsaThresholdKeyId: keyId,
    signingRootId: 'sr-test:dev',
    signingRootVersion: 'default',
    participantIds: [1, 2],
    thresholdOwnerAddress,
  });
  const base = {
    key,
    routerAbEcdsaDerivationNormalSigning: runtimeEcdsaRouterAbNormalSigningState({
      key,
      thresholdSessionId: args.thresholdSessionId,
      thresholdEcdsaPublicKeyB64u: AVAILABLE_LANES_ECDSA_PUBLIC_KEY_B64U,
      thresholdOwnerAddress,
    }),
    keyHandle: args.keyHandle || (`ederivation-key-${keyId}` as EvmFamilyEcdsaKeyHandle),
    thresholdEcdsaPublicKeyB64u: AVAILABLE_LANES_ECDSA_PUBLIC_KEY_B64U,
    curve: 'ecdsa',
    chainTarget: args.chainTarget,
    thresholdSessionId: args.thresholdSessionId,
    signingGrantId: args.signingGrantId,
    remainingUses: args.remainingUses ?? 3,
    expiresAtMs: args.expiresAtMs ?? AVAILABLE_LANES_EXPIRES_AT_MS,
    updatedAtMs: args.updatedAtMs ?? 700,
  } as const;
  return (args.authMethod || 'passkey') === 'email_otp'
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
      };
}

export async function readAvailableLanesFixture(args: {
  sealedRecords?: SigningSessionSealedStoreRecord[];
  ecdsaChainTargets?: [ThresholdEcdsaChainTarget, ...ThresholdEcdsaChainTarget[]];
  runtimeEcdsaRecords?: AvailableSigningLanesRuntimeEcdsaRecord[];
  runtimeEd25519Records?: AvailableSigningLanesRuntimeEd25519Record[];
  warmEcdsaAdvisories?: Map<string, AvailableLaneStateAdvisory>;
  warmStatusAdvisories?: Map<string, AvailableLaneStateAdvisory>;
}) {
  return await readAvailableSigningLanes(
    {
      walletId: AVAILABLE_LANES_WALLET_ID,
      ecdsaChainTargets: args.ecdsaChainTargets || [AVAILABLE_LANES_ECDSA_TARGET],
    },
    {
      listSealedRecordsForWallet: async ({ filter }) =>
        (args.sealedRecords || []).filter((record) => {
          if (record.curve !== filter.curve) return false;
          if (filter.authMethod && record.authMethod !== filter.authMethod) return false;
          if (filter.curve !== 'ecdsa') return true;
          return (
            Boolean(record.ecdsaRestore?.chainTarget) &&
            thresholdEcdsaChainTargetKey(record.ecdsaRestore!.chainTarget) ===
              thresholdEcdsaChainTargetKey(filter.chainTarget)
          );
        }),
      listEcdsaSealedRecordsForWallet: async ({ filter }) =>
        (args.sealedRecords || []).filter((record) => {
          if (record.curve !== 'ecdsa') return false;
          if (filter.authMethod && record.authMethod !== filter.authMethod) return false;
          return Boolean(record.ecdsaRestore?.chainTarget);
        }),
      listRuntimeEcdsaLanesForWallet: async () => args.runtimeEcdsaRecords || [],
      listRuntimeEd25519RecordsForWallet: async () => args.runtimeEd25519Records || [],
      readEcdsaWarmStatusAdvisoriesForRecords: async (records) => {
        const advisories = new Map<string, AvailableLaneStateAdvisory | null>();
        for (const record of records) {
          const advisoryKey = runtimeEcdsaRecordAdvisoryKey(record);
          if (!advisoryKey) continue;
          advisories.set(
            advisoryKey,
            args.warmEcdsaAdvisories?.get(advisoryKey) ||
              args.warmStatusAdvisories?.get(record.thresholdSessionId) ||
              null,
          );
        }
        return advisories;
      },
      readWarmStatusAdvisoriesForSessions: async (sessionIds) => {
        const advisories = new Map<string, AvailableLaneStateAdvisory | null>();
        for (const sessionId of sessionIds) {
          advisories.set(sessionId, args.warmStatusAdvisories?.get(sessionId) || null);
        }
        return advisories;
      },
    },
  );
}
