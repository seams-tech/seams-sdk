import {
  readAvailableSigningLanes,
  runtimeEcdsaRecordClaimKey,
  type AvailableSigningLanesRuntimeClaim,
  type AvailableSigningLanesRuntimeEcdsaRecord,
  type AvailableSigningLanesRuntimeEd25519Record,
} from '@/core/signingEngine/session/availability/availableSigningLanes';
import {
  thresholdEcdsaChainTargetFromChainFamily,
  thresholdEcdsaChainTargetKey,
  type ThresholdEcdsaChainTarget,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import {
  buildBaseEvmFamilyEcdsaKeyIdentity,
  type EvmFamilyEcdsaKeyHandle,
} from '@/core/signingEngine/session/identity/evmFamilyEcdsaIdentity';
import {
  buildCurrentSealedSessionRecord,
  type SigningSessionSealedStoreRecord,
} from '@/core/signingEngine/session/persistence/sealedSessionStore';
import {
  ROUTER_AB_ED25519_NORMAL_SIGNING_STATE_KIND,
  type RouterAbEd25519NormalSigningState,
  type SealedSigningSessionEcdsaRestoreMetadata,
} from '@shared/utils/signingSessionSeal';
import {
  ROUTER_AB_ECDSA_HSS_KEY_SCOPE_V1,
  ROUTER_AB_ECDSA_HSS_NORMAL_SIGNING_STATE_KIND_V1,
  type RouterAbEcdsaHssNormalSigningStateV1,
} from '@shared/utils/routerAbEcdsaHss';
import {
  ROUTER_AB_ECDSA_HSS_WALLET_SESSION_JWT_KIND,
  THRESHOLD_ECDSA_SESSION_AUTH_TOKEN_KIND,
} from '@shared/utils/sessionTokens';

export const AVAILABLE_LANES_WALLET_ID = 'alice.testnet';
export const AVAILABLE_LANES_ECDSA_RP_ID = 'wallet.example.localhost';
export const AVAILABLE_LANES_EXPIRES_AT_MS = 2_000_000_000_000;
export const AVAILABLE_LANES_ECDSA_PUBLIC_KEY_B64U =
  'AgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';
export const AVAILABLE_LANES_ECDSA_KEY_HANDLE =
  'ehss-key-available-lane-test' as EvmFamilyEcdsaKeyHandle;
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
}): RouterAbEcdsaHssNormalSigningStateV1 {
  return {
    kind: ROUTER_AB_ECDSA_HSS_NORMAL_SIGNING_STATE_KIND_V1,
    scope: {
      context: {
        wallet_id: args.key.walletId,
        rp_id: args.key.rpId,
        key_scope: ROUTER_AB_ECDSA_HSS_KEY_SCOPE_V1,
        ecdsa_threshold_key_id: args.key.ecdsaThresholdKeyId,
        signing_root_id: args.key.signingRootId,
        signing_root_version: args.key.signingRootVersion,
        key_purpose: 'evm-family-signing',
        key_version: 'available-lanes-test',
      },
      public_identity: {
        context_binding_b64u: 'AQ',
        client_public_key33_b64u: args.thresholdEcdsaPublicKeyB64u,
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
      activation_epoch: args.thresholdSessionId,
    },
  };
}

function unsignedJwt(payload: Record<string, unknown>): string {
  const header = Buffer.from(JSON.stringify({ alg: 'none', typ: 'JWT' })).toString('base64url');
  const body = Buffer.from(JSON.stringify(payload)).toString('base64url');
  return `${header}.${body}.`;
}

export function thresholdEcdsaSessionJwtFixture(args: {
  thresholdSessionId: string;
  signingGrantId: string;
  keyHandle: string;
  chainTarget?: ThresholdEcdsaChainTarget;
  kind?:
    | typeof ROUTER_AB_ECDSA_HSS_WALLET_SESSION_JWT_KIND
    | typeof THRESHOLD_ECDSA_SESSION_AUTH_TOKEN_KIND;
}): string {
  return unsignedJwt({
    kind: args.kind || ROUTER_AB_ECDSA_HSS_WALLET_SESSION_JWT_KIND,
    sub: AVAILABLE_LANES_WALLET_ID,
    walletId: AVAILABLE_LANES_WALLET_ID,
    keyHandle: args.keyHandle,
    keyScope: 'evm-family',
    ...(args.chainTarget ? { chainTarget: args.chainTarget } : {}),
    thresholdSessionId: args.thresholdSessionId,
    signingGrantId: args.signingGrantId,
  });
}

export function sealedEcdsaAvailableLaneRecord(args: {
  authMethod?: 'email_otp' | 'passkey';
  signingGrantId: string;
  thresholdSessionId: string;
  updatedAtMs: number;
  restoreMetadata?: 'valid' | 'missing' | 'missing_rp_id';
  chainTarget?: ThresholdEcdsaChainTarget;
  ecdsaThresholdKeyId?: string;
  keyHandle?: string;
  participantIds?: number[];
  ethereumAddress?: string;
  remainingUses?: number;
  expiresAtMs?: number;
  sessionKind?: 'cookie' | 'jwt';
}): SigningSessionSealedStoreRecord {
  const issuedAtMs = Date.now();
  const authMethod = args.authMethod || 'passkey';
  const chainTarget = args.chainTarget || AVAILABLE_LANES_ECDSA_TARGET;
  const sessionKind = args.sessionKind || 'cookie';
  const restoreMetadata = args.restoreMetadata || 'valid';
  const keyHandle = args.keyHandle || AVAILABLE_LANES_ECDSA_KEY_HANDLE;
  const ecdsaThresholdKeyId = args.ecdsaThresholdKeyId || 'ek-passkey';
  const validEcdsaRestore: SealedSigningSessionEcdsaRestoreMetadata = {
    chainTarget,
    rpId: AVAILABLE_LANES_ECDSA_RP_ID,
    sessionKind,
    ...(sessionKind === 'jwt'
      ? {
          walletSessionJwt: thresholdEcdsaSessionJwtFixture({
            thresholdSessionId: args.thresholdSessionId,
            signingGrantId: args.signingGrantId,
            chainTarget,
            keyHandle,
          }),
        }
      : {}),
    ecdsaThresholdKeyId,
    keyHandle,
    thresholdEcdsaPublicKeyB64u: AVAILABLE_LANES_ECDSA_PUBLIC_KEY_B64U,
    ethereumAddress: args.ethereumAddress || `0x${'AB'.repeat(20)}`,
    relayerKeyId: 'relayer-key',
    clientVerifyingShareB64u: 'client-verifying-share',
    participantIds: args.participantIds || [1, 2],
    runtimePolicyScope: {
      orgId: 'org-test',
      projectId: 'sr-test',
      envId: 'dev',
      signingRootVersion: 'default',
    },
  };
  if (restoreMetadata !== 'valid') {
    return {
      storeKey: `${authMethod}:${args.signingGrantId}:${args.thresholdSessionId}:${args.updatedAtMs}:ecdsa`,
      curve: 'ecdsa',
      authMethod,
      walletId: AVAILABLE_LANES_WALLET_ID,
      signingGrantId: args.signingGrantId,
      thresholdSessionId: args.thresholdSessionId,
      thresholdSessionIds: { ecdsa: args.thresholdSessionId },
      sealedSecretB64u: 'sealed',
      relayerUrl: 'https://relay.example.test',
      keyVersion: 'seal-key-v1',
      shamirPrimeB64u: 'shamir-prime',
      ecdsaRestore:
        restoreMetadata === 'missing'
          ? {
              chainTarget,
              sessionKind: 'cookie',
              ecdsaThresholdKeyId,
            }
          : {
              ...validEcdsaRestore,
              rpId: undefined,
            },
      issuedAtMs,
      expiresAtMs: args.expiresAtMs ?? issuedAtMs + 60_000,
      remainingUses: args.remainingUses ?? 1,
      updatedAtMs: args.updatedAtMs,
    } as unknown as SigningSessionSealedStoreRecord;
  }
  const record = buildCurrentSealedSessionRecord({
    curve: 'ecdsa',
    authMethod,
    walletId: AVAILABLE_LANES_WALLET_ID,
    signingGrantId: args.signingGrantId,
    thresholdSessionId: args.thresholdSessionId,
    thresholdSessionIds: { ecdsa: args.thresholdSessionId },
    sealedSecretB64u: 'sealed',
    relayerUrl: 'https://relay.example.test',
    keyVersion: 'seal-key-v1',
    shamirPrimeB64u: 'shamir-prime',
    ecdsaRestore: validEcdsaRestore,
    issuedAtMs,
    expiresAtMs: args.expiresAtMs ?? issuedAtMs + 60_000,
    remainingUses: args.remainingUses ?? 1,
    updatedAtMs: args.updatedAtMs,
  });
  if (!record) {
    throw new Error(`failed to build ECDSA sealed fixture ${args.thresholdSessionId}`);
  }
  return record;
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
  const key = buildBaseEvmFamilyEcdsaKeyIdentity({
    walletId: AVAILABLE_LANES_WALLET_ID,
    rpId: AVAILABLE_LANES_ECDSA_RP_ID,
    ecdsaThresholdKeyId: keyId,
    signingRootId: 'sr-test:dev',
    signingRootVersion: 'default',
    participantIds: [1, 2],
    thresholdOwnerAddress,
  });
  const base = {
    key,
    routerAbEcdsaHssNormalSigning: runtimeEcdsaRouterAbNormalSigningState({
      key,
      thresholdSessionId: args.thresholdSessionId,
      thresholdEcdsaPublicKeyB64u: AVAILABLE_LANES_ECDSA_PUBLIC_KEY_B64U,
      thresholdOwnerAddress,
    }),
    keyHandle: args.keyHandle || (`ehss-key-${keyId}` as EvmFamilyEcdsaKeyHandle),
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
    ? { ...base, authMethod: 'email_otp' }
    : { ...base, authMethod: 'passkey' };
}

export async function readAvailableLanesFixture(args: {
  sealedRecords?: SigningSessionSealedStoreRecord[];
  ecdsaChainTargets?: [ThresholdEcdsaChainTarget, ...ThresholdEcdsaChainTarget[]];
  runtimeEcdsaRecords?: AvailableSigningLanesRuntimeEcdsaRecord[];
  runtimeEd25519Records?: AvailableSigningLanesRuntimeEd25519Record[];
  runtimeEcdsaClaims?: Map<string, AvailableSigningLanesRuntimeClaim>;
  runtimeClaims?: Map<string, AvailableSigningLanesRuntimeClaim>;
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
      listRuntimeEd25519RecordsForAccount: async () => args.runtimeEd25519Records || [],
      readRuntimeEcdsaClaimsForRecords: async (records) => {
        const claims = new Map<string, AvailableSigningLanesRuntimeClaim | null>();
        for (const record of records) {
          const claimKey = runtimeEcdsaRecordClaimKey(record);
          if (!claimKey) continue;
          claims.set(
            claimKey,
            args.runtimeEcdsaClaims?.get(claimKey) ||
              args.runtimeClaims?.get(record.thresholdSessionId) ||
              null,
          );
        }
        return claims;
      },
      readRuntimeClaimsForSessions: async (sessionIds) => {
        const claims = new Map<string, AvailableSigningLanesRuntimeClaim | null>();
        for (const sessionId of sessionIds) {
          claims.set(sessionId, args.runtimeClaims?.get(sessionId) || null);
        }
        return claims;
      },
    },
  );
}
